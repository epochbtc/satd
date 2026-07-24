//! Envelope-shaped JSON for a [`WatchMatch`].
//!
//! Watch matches are delivered per subscriber over an mpsc channel rather than
//! on the shared event bus, and the proto types carry no `serde` derive, so
//! their JSON is rendered by hand. It lives here rather than in a carrier so
//! the WebSocket/SSE firehose and the alert webhook dispatcher emit **the same
//! bytes** for the same match — a receiver that handles one handles the other.
//!
//! The shape mirrors a `NodeEvent`: a `body` tagged by `category`, plus a
//! `cursor` on confirmed matches.

use serde_json::json;

use super::watch::WatchMatch;

/// Hand-rolled JSON for a watch match (the proto has no `serde` derive). The
/// shape mirrors a `NodeEvent`: a `body` tagged by `category`, plus a
/// `cursor` on confirmed matches. `descriptor_matches` is the descriptor
/// attribution for a `ScriptMatched` (empty otherwise / for a direct watch).
pub fn watch_match_json(
    m: &WatchMatch,
    descriptor_matches: &[(std::sync::Arc<str>, u32, u32)],
    include_raw_tx: bool,
) -> serde_json::Value {
    use bitcoin::hashes::Hash;
    match m {
        WatchMatch::OutpointSpent {
            outpoint,
            spending_txid,
            spending_vin,
            confirmed,
            height,
        } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "outpoint_spent",
                "outpoint_txid": hex::encode(outpoint.txid.as_raw_hash().to_byte_array()),
                "outpoint_vout": outpoint.vout,
                "spending_txid": hex::encode(spending_txid.as_raw_hash().to_byte_array()),
                "spending_vin": spending_vin,
                "confirmed": confirmed,
            }
        }),
        WatchMatch::ScriptMatched {
            scripthash,
            txid,
            is_output,
            index,
            confirmed,
            height,
            amount,
            raw_tx,
        } => {
            // Hex of the full tx when this stream opted in (SetWatchOptions) and
            // the match carried it; `null` otherwise. Mirrors the gRPC gate.
            let raw_tx_hex = if include_raw_tx {
                raw_tx.as_ref().map(hex::encode)
            } else {
                None
            };
            json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "script_matched",
                "scripthash": hex::encode(scripthash),
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "is_output": is_output,
                "index": index,
                "confirmed": confirmed,
                // Matched value (sats): funded output value or spent-prevout
                // value. `has_amount = false` marks "not retained at this tier"
                // (mempool spend under `streamprevoutmeta = hash`).
                "amount": amount.unwrap_or(0),
                "has_amount": amount.is_some(),
                // Full serialized tx (hex) when opted in; null otherwise.
                "raw_tx": raw_tx_hex,
                // Empty array for a directly-watched script; one entry per
                // descriptor whose window holds this scripthash.
                "descriptor_matches": descriptor_matches
                    .iter()
                    .map(|(d, branch, index)| json!({
                        "descriptor": d.as_ref(),
                        "branch": branch,
                        "derivation_index": index,
                    }))
                    .collect::<Vec<_>>(),
            }
            })
        }
        WatchMatch::TxidMatched {
            txid,
            confirmed,
            height,
        } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "txid_matched",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "confirmed": confirmed,
            }
        }),
        WatchMatch::TxidReplaced {
            txid,
            replacing_txid,
        } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_replaced",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "replacing_txid": hex::encode(replacing_txid.as_raw_hash().to_byte_array()),
            }
        }),
        WatchMatch::TxidEvicted { txid, reason } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_evicted",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "reason": reason.as_str(),
            }
        }),
        WatchMatch::TxidUnconfirmed { txid, prev_height } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_unconfirmed",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "prev_height": prev_height,
            }
        }),
        WatchMatch::TxidDepthReached {
            txid,
            depth,
            height,
        } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": json!({ "height": height, "tx_index": 0, "mempool_seq": 0 }),
            "body": {
                "category": "txid_depth_reached",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "depth": depth,
                "height": height,
            }
        }),
        WatchMatch::TxidFinalized {
            txid,
            depth,
            height,
        } => json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": json!({ "height": height, "tx_index": 0, "mempool_seq": 0 }),
            "body": {
                "category": "txid_finalized",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "depth": depth,
                "height": height,
            }
        }),
        WatchMatch::PrefixMatched(pm) => {
            let (masked, bits) = pm.prefix;
            let nbytes = (bits as usize).div_ceil(8).min(4);
            json!({
                "schema_version": super::SCHEMA_VERSION,
                "cursor": pm.height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
                "body": {
                    "category": "prefix_matched",
                    "prefix": hex::encode(&masked.to_be_bytes()[..nbytes]),
                    "bits": bits,
                    "raw_tx": hex::encode(pm.raw_tx.as_ref()),
                    "confirmed": pm.confirmed,
                    "height": pm.height,
                    "matched_prevouts": pm.matched_prevouts.iter().map(|m| json!({
                        "outpoint_txid": hex::encode(m.outpoint.txid.as_raw_hash().to_byte_array()),
                        "outpoint_vout": m.outpoint.vout,
                        "script_pubkey": hex::encode(m.script_pubkey.as_bytes()),
                        // `amount` is null when the value was not retained
                        // (streamprevoutmeta below `amount`); `has_amount`
                        // mirrors the gRPC SpentPrevout bool so a JSON client can
                        // distinguish "not retained" from a genuine 0-sat prevout
                        // without relying on the null-vs-0 encoding.
                        "amount": m.amount,
                        "has_amount": m.amount.is_some(),
                    })).collect::<Vec<_>>(),
                }
            })
        }
        WatchMatch::SilentPaymentMatched {
            scan_pubkey,
            txid,
            vout,
            output_pubkey,
            amount,
            tweak,
            k,
            label,
            confirmed,
            height,
            raw_tx,
        } => {
            let raw_tx_hex = if include_raw_tx {
                raw_tx.as_ref().map(hex::encode)
            } else {
                None
            };
            json!({
            "schema_version": super::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "silent_payment_matched",
                "scan_pubkey": hex::encode(scan_pubkey),
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "vout": vout,
                "output_pubkey": hex::encode(output_pubkey.serialize()),
                "amount": amount,
                // 33-byte public tweak T; with `k` (and the label, if any) a
                // light client re-derives the output key offline from b_scan.
                "tweak": hex::encode(tweak.serialize()),
                "k": k,
                "has_label": label.is_some(),
                "label": label.unwrap_or(0),
                "confirmed": confirmed,
                "height": height,
                "raw_tx": raw_tx_hex,
            }
            })
        }
    }
}
