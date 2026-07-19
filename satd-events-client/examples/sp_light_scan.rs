//! BIP 352 silent payments — the **client-side scan** (Tier 1, zero-custody)
//! mode, the recommended one.
//!
//! Subscribe to the `tweaks` firehose and do the ECDH locally: for each block,
//! the node sends only the public tweak `T` of every silent-payment-eligible
//! transaction, and this client derives its own candidate output key
//! `P_k = B_spend + hash(b_scan·T ‖ k)·G` — so **the scan key never leaves the
//! device**. Contrast `sp_wallet.rs`, where you hand the node `b_scan` and it
//! matches for you.
//!
//! A candidate `P_k` is *yours* iff its taproot output actually appears on-chain.
//! The tweaks stream deliberately carries only tweaks, so a full wallet confirms
//! membership against the block's taproot outputs from its own chain access
//! (a `getblock`, or a BIP 157 compact-filter test of the candidate script) —
//! that lookup is the wallet's, not the events SDK's. This example derives and
//! prints the candidates (and, for `k = 0`, the spending key you would hold),
//! which is the whole cryptographic core of a light-client scanner.
//!
//! The `tweaks` category requires the node's tweak index (`silentpaymentindex=1`)
//! and is not part of the default category set — request it explicitly.
//!
//! Requires the default `bitcoin` feature.
//!
//! ```sh
//! cargo run -p satd-events-client --example sp_light_scan -- http://127.0.0.1:50051
//! ```

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use satd_events_client::{Categories, Event, StreamClient, SubscribeOptions};

/// How many outputs per transaction to probe (`k = 0..N`). A real scanner keeps
/// going until a `k` misses; a couple is plenty to illustrate.
const PROBE_K: u32 = 2;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    // Your keys never leave this process. `b_spend` is public-derived once.
    let secp = Secp256k1::new();
    let b_scan = SecretKey::from_slice(&[0x11; 32])?;
    let b_spend = SecretKey::from_slice(&[0x22; 32])?;
    let spend_pubkey = PublicKey::from_secret_key(&secp, &b_spend);

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    // Request ONLY the tweaks category (bit 8, explicit — not in the default).
    let mut events = client
        .subscribe(SubscribeOptions {
            categories: Categories::TWEAKS,
            ..Default::default()
        })
        .await?;

    while let Some(event) = events.message().await? {
        if let Event::BlockTweaks { height, entries, .. } = event {
            for entry in &entries {
                for k in 0..PROBE_K {
                    let (output_key, spend_key) =
                        derive_candidate(&secp, &b_scan, &spend_pubkey, &b_spend, &entry.tweak, k)?;
                    // Candidate P2TR scriptPubKey the wallet would look for on-chain.
                    println!(
                        "block {height} tweak {} k={k}: candidate output key {}{}",
                        &hex(&entry.tweak)[..12],
                        hex(&output_key),
                        match spend_key {
                            Some(sk) => format!(" (spend key {})", hex(&sk)),
                            None => String::new(),
                        },
                    );
                }
            }
        }
    }
    Ok(())
}

/// Derive the candidate output key `P_k = B_spend + t_k·G` and, for the change
/// path this wallet controls, the corresponding spending key `d = b_spend + t_k`.
/// `t_k = hash_BIP0352/SharedSecret(b_scan·T ‖ k)`.
#[allow(clippy::type_complexity)]
fn derive_candidate(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    b_scan: &SecretKey,
    spend_pubkey: &PublicKey,
    b_spend: &SecretKey,
    tweak: &[u8],
    k: u32,
) -> Result<([u8; 32], Option<[u8; 32]>), Box<dyn std::error::Error>> {
    let t = PublicKey::from_slice(tweak)?;
    let ecdh = t.mul_tweak(secp, &Scalar::from_be_bytes(b_scan.secret_bytes())?)?;
    let mut msg = ecdh.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = Scalar::from_be_bytes(tagged_hash(b"BIP0352/SharedSecret", &msg))?;

    // P_k = B_spend + t_k·G
    let p_k = spend_pubkey.add_exp_tweak(secp, &t_k)?;
    let output_key = p_k.x_only_public_key().0.serialize();
    // d = b_spend + t_k (spendable because we also hold b_spend).
    let spend_key = b_spend.add_tweak(&t_k).ok().map(|sk| sk.secret_bytes());
    Ok((output_key, spend_key))
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
