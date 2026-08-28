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
//! output actually appears in the transaction. When the tweak event carries the
//! transaction's taproot outputs (`entry.taproot_outputs`), this example
//! confirms the match **in-band** — comparing each derived key against the
//! carried outputs, no `getblock`/`getrawtransaction` needed. Otherwise it falls
//! back to printing the candidate key for the wallet to look up against the
//! block from its own chain access.
//!
//! The `tweaks` category requires the node's tweak index (`silentpaymentindex=1`)
//! and is not part of the default category set — request it explicitly.
//!
//! This example sets `mempool_tweaks` (Tier 1.5), so it scans each payment at
//! **mempool admission** as well as at confirmation — mempool-latency detection
//! with the scan key still on the device. A `MempoolTweak` **always** carries
//! `taproot_outputs` (there is no block to fall back to, and fetching an
//! unconfirmed tx races eviction); it also sets `tweak_outputs`, so the confirmed
//! `BlockTweaks` entries carry them too — both paths confirm the match in-band.
//! A mempool hit and its later confirmed hit share a txid, so a real scanner
//! dedups on `entry.txid`.
//!
//! **Resume is durable, and the SDK owns the hard part.** The scan runs under
//! [`ResilientSubscription`] with a [`FileCursorStore`], which persists each
//! block's cursor **commit-on-poll**: the write happens when this loop comes back
//! for the next event — that is, only once the block it belongs to has been
//! scanned. A crash mid-block replays that block instead of skipping it. Getting
//! this backwards is how a scanner silently loses a payment: persist the cursor of
//! an event you have not finished processing and a restart resumes past it. (The
//! opposite slip — persisting one event *behind* — only costs a rescan, and is a
//! real bug in a shipped wallet: cake-tech/cake_wallet#3574.) Do not hand-roll it;
//! the safe side of that trade is already implemented here.
//!
//! **Cold sync.** Give a start height as the third argument and, when the cursor
//! file is empty, the scan begins there — taproot activation (709632 on mainnet)
//! for a fresh wallet, which the server replays in one unclamped, backpressured
//! subscription. Once the file holds a cursor it wins, so the argument is a seed
//! for the first run only and is harmless to leave in place.
//!
//! Requires the default `bitcoin` feature.
//!
//! ```sh
//! cargo run -p satd-events-client --example sp_light_scan -- \
//!     http://127.0.0.1:50051 /tmp/satd-sp.cursor 709632
//! ```

use std::sync::Arc;

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use satd_events_client::{
    display_hex, Categories, Cursor, Event, FileCursorStore, ResilientConfig, StreamClient,
    SubscribeOptions, TweakEntry,
};

/// How many outputs per transaction to probe (`k = 0..N`). A real scanner keeps
/// going until a `k` misses; a couple is plenty to illustrate.
const PROBE_K: u32 = 2;

/// Receiver labels to also scan for (BIP 352 §5). Include `0` to catch your own
/// change; a label-less receiver leaves this empty. Each label yields an extra
/// candidate per `k`.
const LABELS: &[u32] = &[0];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let cursor_path = args.next().unwrap_or_else(|| "/tmp/satd-sp.cursor".into());
    // First height to scan on a cold start. A cursor names the last height
    // already *done*, so anchoring at `h - 1` makes `h` itself the first block
    // replayed — pass 709632 (mainnet taproot activation) and block 709632 is
    // scanned, not skipped.
    let from_height: Option<u32> = match args.next() {
        Some(h) => Some(h.parse::<u32>()?.saturating_sub(1)),
        None => None,
    };

    // Your keys never leave this process. `b_spend` is public-derived once.
    let secp = Secp256k1::new();
    let b_scan = SecretKey::from_slice(&[0x11; 32])?;
    let b_spend = SecretKey::from_slice(&[0x22; 32])?;
    let spend_pubkey = PublicKey::from_secret_key(&secp, &b_spend);

    let client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    // Request ONLY the tweaks category (bit 8, explicit — not in the default),
    // opt into mempool-time tweaks so payments surface at admission too, and set
    // `tweak_outputs` so confirmed `BlockTweaks` entries carry the transaction's
    // taproot outputs as well. With that, both streams confirm a match in-band —
    // no block/tx fetch. (A `MempoolTweak` carries its outputs regardless; drop
    // `tweak_outputs` and the block path falls back to the candidate key below.)
    let opts = SubscribeOptions {
        categories: Categories::TWEAKS,
        mempool_tweaks: true,
        tweak_outputs: true,
        // Seed only: the persisted cursor wins whenever the store has one, so
        // this anchor is used on a first run and never again.
        from_cursor: from_height.map(|height| Cursor {
            height,
            ..Default::default()
        }),
        ..Default::default()
    };
    // The file-backed store is what makes a restart resume rather than rescan
    // from scratch, and commit-on-poll is what makes it resume *safely*.
    let mut sub = client.resilient_subscribe(
        opts,
        ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(cursor_path))),
    );

    // `next()` reconnects and replays underneath, and commits the previous
    // event's cursor on the way in. It returns `Err` only on a permanent failure.
    loop {
        match sub.next().await? {
            // Confirmed: one entry per SP-eligible tx in the connected block.
            Event::BlockTweaks { height, entries, .. } => {
                for entry in &entries {
                    scan_entry(&secp, &b_scan, &spend_pubkey, &b_spend, entry, &format!("block {height}"))?;
                }
            }
            // Mempool (Tier 1.5): one accepted-but-unconfirmed tx. Same scan;
            // dedup against the later BlockTweaks hit on `entry.txid`.
            Event::MempoolTweak { entry } => {
                scan_entry(&secp, &b_scan, &spend_pubkey, &b_spend, &entry, "mempool")?;
            }
            // Tweak replay is unclamped, so a scanner should never see this. If it
            // ever does, blocks went unscanned — for a wallet that is missed money,
            // not a warning. Stop rather than continue with a hole in the history.
            Event::ReplayGap { resume_height, first_height } => {
                return Err(format!(
                    "replay gap: blocks ({resume_height}, {first_height}) were never scanned; \
                     rescan that range before trusting this wallet's balance"
                )
                .into());
            }
            _ => {}
        }
    }
}

/// Run the client-side scan over one tweak entry, printing each candidate. Shared
/// by the confirmed (`BlockTweaks`) and mempool (`MempoolTweak`) paths — the
/// cryptography is identical; only `where_` (the log prefix) differs.
fn scan_entry(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    b_scan: &SecretKey,
    spend_pubkey: &PublicKey,
    b_spend: &SecretKey,
    entry: &TweakEntry,
    where_: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for k in 0..PROBE_K {
        let candidates =
            derive_candidates(secp, b_scan, spend_pubkey, b_spend, &entry.tweak, k, LABELS)?;
        for c in candidates {
            let lbl = match c.label {
                Some(m) => format!(" label={m}"),
                None => String::new(),
            };
            // If the event carries the tx's taproot outputs (always for a
            // MempoolTweak; for BlockTweaks when `tweak_outputs` was set), confirm
            // the match in-band: a candidate is ours iff its key is one of them.
            if let Some(o) = entry
                .taproot_outputs
                .iter()
                .find(|o| o.output_pubkey.as_slice() == c.output_key.as_slice())
            {
                println!(
                    "{where_} tx {} k={k}{lbl}: ✓ MATCH — output vout={} value={} sats is yours \
                     (spend key {})",
                    display_hex(&entry.txid),
                    o.vout,
                    o.value,
                    hex(&c.spend_key),
                );
            } else if entry.taproot_outputs.is_empty() {
                // No outputs in the event (a lean BlockTweaks with tweak_outputs
                // off). Fall back to the candidate key for the wallet to look up
                // against the block from its own chain access.
                println!(
                    "{where_} tx {} tweak {}.. k={k}{lbl}: candidate output key {} \
                     — confirm against the block (candidate spend key {})",
                    display_hex(&entry.txid),
                    &hex(&entry.tweak)[..12],
                    hex(&c.output_key),
                    hex(&c.spend_key),
                );
            }
            // else: outputs present but this candidate is not among them — not
            // ours at this k; a real scanner stops probing once a k misses.
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
