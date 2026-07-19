//! BIP 352 silent payments — the **client-side scan** (Tier 1, zero-custody)
//! mode, the recommended one.
//!
//! Subscribe to the `tweaks` firehose and do the ECDH locally: for each block,
//! the node sends only the public tweak `T` of every silent-payment-eligible
//! transaction, and this client derives its own candidate output keys locally —
//! so **the scan key never leaves the device**. Contrast `sp_wallet.rs`, where
//! you hand the node `b_scan` and it matches for you.
//!
//! For each tweak and output counter `k` the scanner derives the unlabelled
//! candidate `P_k = B_spend + hash(b_scan·T ‖ k)·G` **and**, for each label `m`
//! the receiver uses (BIP 352 §5; include `0` to catch your own change), the
//! labelled candidate `P_k + label_m·G`. A candidate is *yours* iff its taproot
//! output actually appears on-chain: the tweaks stream deliberately carries only
//! tweaks, so a full wallet confirms membership against the block's taproot
//! outputs from its own chain access (a `getblock`, or a BIP 157 compact-filter
//! test of the candidate script) — that lookup is the wallet's, not the events
//! SDK's. This example derives and prints the candidate output keys and the
//! *candidate* spending key you would hold if a candidate proves to be on-chain,
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

/// Receiver labels to also scan for (BIP 352 §5). Include `0` to catch your own
/// change; a label-less receiver leaves this empty. Each label yields an extra
/// candidate per `k`.
const LABELS: &[u32] = &[0];

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
                    let candidates =
                        derive_candidates(&secp, &b_scan, &spend_pubkey, &b_spend, &entry.tweak, k, LABELS)?;
                    for c in candidates {
                        let lbl = match c.label {
                            Some(m) => format!(" label={m}"),
                            None => String::new(),
                        };
                        // The scriptPubKey a wallet would look for on-chain is the
                        // P2TR wrapping `output_key`; the spend key is a *candidate*
                        // until that output is confirmed present.
                        println!(
                            "block {height} tweak {}.. k={k}{lbl}: candidate output key {} \
                             (candidate spend key {})",
                            &hex(&entry.tweak)[..12],
                            hex(&c.output_key),
                            hex(&c.spend_key),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// One candidate output the wallet could own for a given tweak and counter `k`.
struct Candidate {
    /// The label `m` this candidate assumes (`None` = unlabelled), if any.
    label: Option<u32>,
    /// 32-byte x-only taproot output key to look for on-chain.
    output_key: [u8; 32],
    /// The spending key the wallet would hold *if* `output_key` is on-chain.
    spend_key: [u8; 32],
}

/// Derive every candidate output key this wallet could own for tweak `T` at
/// counter `k`: the unlabelled `P_k = B_spend + t_k·G`, plus one per configured
/// label `m` — `P_k + label_m·G`. Each carries the spending key the wallet would
/// hold (`b_spend + t_k [+ label_m]`), so a labelled/change output is not missed.
/// `t_k = hash_BIP0352/SharedSecret(b_scan·T ‖ k)` and
/// `label_m = hash_BIP0352/Label(ser256(b_scan) ‖ ser32(m))`.
fn derive_candidates(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    b_scan: &SecretKey,
    spend_pubkey: &PublicKey,
    b_spend: &SecretKey,
    tweak: &[u8],
    k: u32,
    labels: &[u32],
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let t = PublicKey::from_slice(tweak)?;
    let ecdh = t.mul_tweak(secp, &Scalar::from_be_bytes(b_scan.secret_bytes())?)?;
    let mut msg = ecdh.serialize().to_vec();
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = Scalar::from_be_bytes(tagged_hash(b"BIP0352/SharedSecret", &msg))?;

    // Unlabelled: P_k = B_spend + t_k·G, spend = b_spend + t_k.
    let p_k = spend_pubkey.add_exp_tweak(secp, &t_k)?;
    let mut out = vec![Candidate {
        label: None,
        output_key: p_k.x_only_public_key().0.serialize(),
        spend_key: b_spend.add_tweak(&t_k)?.secret_bytes(),
    }];

    // Labelled: P_k + label_m·G, spend = b_spend + t_k + label_m.
    for &m in labels {
        let mut lbuf = b_scan.secret_bytes().to_vec();
        lbuf.extend_from_slice(&m.to_be_bytes());
        let label_m = Scalar::from_be_bytes(tagged_hash(b"BIP0352/Label", &lbuf))?;
        let p_k_m = p_k.add_exp_tweak(secp, &label_m)?;
        let spend = b_spend.add_tweak(&t_k)?.add_tweak(&label_m)?;
        out.push(Candidate {
            label: Some(m),
            output_key: p_k_m.x_only_public_key().0.serialize(),
            spend_key: spend.secret_bytes(),
        });
    }
    Ok(out)
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
