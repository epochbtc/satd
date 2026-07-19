//! BIP 352 silent payments — the **scan-key watch** (Tier 2, convenience) mode.
//!
//! Register a `(scan_secret b_scan, spend_pubkey B_spend)` target on a `Watch`
//! stream; the node runs the ECDH match and pushes a `SilentPaymentMatched` for
//! every output paying you. From each match's public tweak `T` and counter `k`
//! this example re-derives the output's **full spending key offline** — the node
//! never holds spend authority. `b_scan` is disclosed to the node (it is a watch
//! credential, not a spend key): the operator learns *which* outputs are yours,
//! but can never spend them.
//!
//! The recommended zero-custody alternative — where `b_scan` never leaves the
//! device — is the tweaks-firehose scan in `sp_light_scan.rs`.
//!
//! Requires the default `bitcoin` feature.
//!
//! ```sh
//! cargo run -p satd-events-client --example sp_wallet -- http://127.0.0.1:50051
//! ```

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use satd_events_client::{Event, SilentPaymentTarget, StreamClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    // Your wallet's silent-payment keys. Replace these demo scalars with your
    // own. `b_scan` is disclosed to the node; `b_spend` stays here and is what
    // makes the derived keys spendable — it is never sent.
    let secp = Secp256k1::new();
    let b_scan = SecretKey::from_slice(&[0x11; 32])?;
    let b_spend = SecretKey::from_slice(&[0x22; 32])?;
    let spend_pubkey = PublicKey::from_secret_key(&secp, &b_spend);

    let target = SilentPaymentTarget {
        scan_secret: b_scan.secret_bytes(),
        spend_pubkey: spend_pubkey.serialize(),
        labels: vec![0], // include label 0 to also catch your own change
    };
    println!("watching scan key {}", hex(&target.scan_pubkey()?));

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    let (watch, mut events) = client.watch().await?;
    watch.add_silent_payments([target]).await?;

    while let Some(event) = events.message().await? {
        if let Event::SilentPaymentMatched {
            txid, vout, output_pubkey, amount, tweak, k, label, confirmed, ..
        } = event
        {
            // Re-derive the full spending key offline from T, k, and (for a
            // labelled/change output) the label m the node reported.
            let spend_key = derive_spend_key(&secp, &b_scan, &b_spend, &tweak, k, label)?;
            // Sanity-check: its public key must equal the matched output key.
            let derived = PublicKey::from_secret_key(&secp, &spend_key)
                .x_only_public_key()
                .0
                .serialize();
            let ok = derived == output_pubkey.as_slice();
            println!(
                "paid {} sat at {}:{} ({}) — spend key {} [{}]",
                amount,
                hex(&txid),
                vout,
                if confirmed { "confirmed" } else { "mempool" },
                hex(&spend_key.secret_bytes()),
                if ok { "verified" } else { "MISMATCH" },
            );
        }
    }
    Ok(())
}

/// BIP 352 receiver derivation: the spending key for output counter `k` is
/// `d = b_spend + t_k (mod n)`, where `t_k = hash_BIP0352/SharedSecret(b_scan·T ‖ k)`.
///
/// For a **labelled** output (the node reports `label = Some(m)` — e.g. `m = 0`
/// for your own change), the receiver also added the label tweak
/// `label_m = hash_BIP0352/Label(b_scan ‖ ser32(m))`, so the spending key is
/// `d = b_spend + t_k + label_m (mod n)`. Omitting it — a common copy-paste
/// mistake — yields a key that does NOT control the output, so the change is
/// unspendable; the self-check in `main` prints `MISMATCH` when this happens.
fn derive_spend_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    b_scan: &SecretKey,
    b_spend: &SecretKey,
    tweak: &[u8],
    k: u32,
    label: Option<u32>,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let t = PublicKey::from_slice(tweak)?;
    // ecdh = b_scan · T
    let ecdh = t.mul_tweak(secp, &Scalar::from_be_bytes(b_scan.secret_bytes())?)?;
    let mut msg = ecdh.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = tagged_hash(b"BIP0352/SharedSecret", &msg);
    let mut d = b_spend.add_tweak(&Scalar::from_be_bytes(t_k)?)?;
    if let Some(m) = label {
        // label_m = hash_BIP0352/Label(ser256(b_scan) ‖ ser32(m))
        let mut lbuf = b_scan.secret_bytes().to_vec();
        lbuf.extend_from_slice(&m.to_be_bytes());
        let label_m = tagged_hash(b"BIP0352/Label", &lbuf);
        d = d.add_tweak(&Scalar::from_be_bytes(label_m)?)?;
    }
    Ok(d)
}

/// BIP 340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine, sha256};
    let th = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(th.as_ref());
    eng.input(th.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
