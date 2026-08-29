//! `blockchain.tweaks.subscribe` — the BIP 352 tweak stream light wallets
//! already speak.
//!
//! This is not a request/response method. The JSON-RPC `result` carries the
//! **first** height only; every further height arrives as an unsolicited
//! `blockchain.tweaks.subscribe` notification on the same connection, and
//! `{"message":"done"}` ends the chunk. A client that treats the call as an
//! ordinary RPC reads one block and believes it finished a scan.
//!
//! The shape is the de-facto one, fixed by the clients that consume it (Cake
//! Wallet, [kiss-bdk]) rather than by a spec:
//!
//! ```json
//! {"850000": {"<txid>": {"tweak": "<33-byte hex>",
//!                        "output_pubkeys": {"<vout>": ["<x-only hex>", <sats>]}}}}
//! ```
//!
//! Params are `[start_height, count, historical_mode]`. `count` is a height
//! count, not a transaction count; `historical_mode = false` (Cake's default)
//! asks for **cut-through** — omit taproot outputs already spent, and omit
//! transactions with nothing left — which is what makes a phone's balance scan
//! affordable. A wallet restoring transaction history must pass `true`.
//!
//! The scan is client-side: the node serves public per-transaction tweaks and
//! never sees a scan key. Sparrow's silent-payment path talks to a different
//! method (`blockchain.silentpayments.subscribe`, which uploads a scan key);
//! satd does not implement that one, and this is not it.
//!
//! [kiss-bdk]: https://github.com/kkdao/kiss-bdk

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::OutPoint;
use node::chain::state::ChainState;
use node::index::silent_payments::{SpBlockRow, SpIndex, SpIndexError};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;

use crate::error::JsonRpcError;
use crate::state::ElectrumState;

/// Method name, used for the notification envelope as well as dispatch.
pub const METHOD: &str = "blockchain.tweaks.subscribe";

/// Wall-clock budget for one subscribe chunk. When it elapses the server sends
/// `{"message":"done"}` at a height boundary and returns to the connection loop;
/// the client resubscribes from the next unscanned height. Bounding the chunk
/// keeps one scan from monopolising a connection's notification channel for the
/// length of a taproot-era cold sync, and gives clients a natural checkpoint —
/// the same reason Cake's own server chunks by height count.
pub const CHUNK_BUDGET: Duration = Duration::from_secs(60);

/// Heights read per blocking hop. Each height costs one index read plus one
/// block read, so this bounds how long a blocking thread is held while still
/// amortising the hop.
pub const HEIGHTS_PER_HOP: u32 = 16;

/// Pre-activation heights collapsed into a single notification. Nothing below
/// taproot activation can carry a silent payment, so those heights are empty by
/// construction — but a client restoring from an old height still needs to see
/// progress, and Cake reads the **last key** of the map as its progress marker.
/// One notification per empty height would mean ~700k lines on mainnet.
pub const EMPTY_WAVE_HEIGHTS: u32 = 1024;

/// A parsed `blockchain.tweaks.subscribe` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TweakReq {
    /// First height to serve.
    pub start: u32,
    /// How many heights the client asked for (at least 1).
    pub count: u32,
    /// Cake's `historicalMode`. `false` (the default, and what Cake sends)
    /// means cut through spent outputs.
    pub historical: bool,
}

impl TweakReq {
    /// Whether spent taproot outputs should be cut through.
    pub fn cut_through(&self) -> bool {
        !self.historical
    }

    /// Inclusive last height to serve, clamped to `tip`. `None` when `start` is
    /// already above the tip — there is nothing to stream.
    pub fn last_height(&self, tip: u32) -> Option<u32> {
        if self.start > tip {
            return None;
        }
        Some(self.start.saturating_add(self.count.saturating_sub(1)).min(tip))
    }
}

/// Parse `[start_height, count?, historical_mode?]`.
///
/// `count` defaults to 1 (Cake's one-height probe is `[0, 1, false]`) and
/// `historical_mode` to `false`, matching what the clients send when they omit
/// them.
pub fn parse_req(params: &Value) -> Result<TweakReq, JsonRpcError> {
    let arr = match params {
        Value::Array(a) if !a.is_empty() => a,
        _ => {
            return Err(JsonRpcError::invalid_params(
                "blockchain.tweaks.subscribe takes [start_height, count, historical_mode]",
            ));
        }
    };
    let start = u32_param(arr.first(), "start_height")?;
    let count = match arr.get(1) {
        None | Some(Value::Null) => 1,
        v => u32_param(v, "count")?.max(1),
    };
    let historical = match arr.get(2) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(JsonRpcError::invalid_params("historical_mode must be a boolean"));
        }
    };
    Ok(TweakReq { start, count, historical })
}

fn u32_param(v: Option<&Value>, name: &str) -> Result<u32, JsonRpcError> {
    v.and_then(Value::as_u64)
        .filter(|n| *n <= u64::from(u32::MAX))
        .map(|n| n as u32)
        .ok_or_else(|| JsonRpcError::invalid_params(format!("{name} must be a height")))
}

/// Everything the stream needs, in owned handles: the spawned task outlives the
/// dispatch call that started it, so it cannot borrow the connection's state.
#[derive(Clone)]
pub struct TweakSource {
    pub chain: Arc<ChainState>,
    pub index: Arc<dyn SpIndex>,
}

impl TweakSource {
    /// Take the handles out of the connection state, refusing when this node
    /// cannot serve the method: no index, or an index still backfilling.
    ///
    /// Refusing an incomplete index is deliberate. A partial index answers the
    /// heights it has not reached with silence, and silence is indistinguishable
    /// from "no payments in this block" — the one failure a scanning client
    /// cannot detect. The streaming API refuses a tweak replay for the same
    /// reason.
    pub fn from_state(state: &ElectrumState) -> Result<Self, JsonRpcError> {
        let index = state
            .sp_index
            .clone()
            .ok_or_else(|| index_unavailable(&SpIndexError::Disabled))?;
        if !index.is_complete() {
            return Err(index_unavailable(&SpIndexError::Incomplete));
        }
        Ok(Self { chain: state.chain.clone(), index })
    }

    /// Taproot activation on this network — the lowest height that can carry a
    /// row, and so the point below which every height is empty by construction.
    pub fn activation_height(&self) -> u32 {
        self.index.activation_height()
    }
}

/// One height's map, `{"<height>": {<txid>: {...}}}`, as the result and every
/// notification carry it.
///
/// A height with no eligible transactions — including one below taproot
/// activation or above the tip — is `{"<height>": {}}`. That is a real answer,
/// not an error: it is how a client's progress marker advances across barren
/// stretches of chain.
pub fn height_map(src: &TweakSource, height: u32, cut_through: bool) -> Result<Value, JsonRpcError> {
    let row = match src.index.tweaks_at(height) {
        Ok(row) => row,
        Err(SpIndexError::NotFound(_)) => {
            // Below activation or above the tip, absence *is* the answer: those
            // heights carry no row by construction, and `{"<h>": {}}` is how a
            // client's progress marker crosses them.
            //
            // Inside `[activation, tip]` it is a hole, not an answer.
            // `from_state` already refused an incomplete index, so the way to
            // get here is a reorg: the disconnect drops each disconnected
            // height's row, and the replacement branch is written back one
            // block per batch, leaving a window where these heights have no
            // row. Answering `{}` there would tell the client "no payments at
            // this height" and advance its marker past a block that is about to
            // be replaced by one that may well pay it — the silent skip this
            // whole surface exists to avoid. Refuse in-band instead, exactly as
            // the streaming pager does for the same case.
            if height >= src.activation_height() && height <= src.chain.tip_height() {
                return Err(JsonRpcError::internal(format!(
                    "silent-payment index has no row for height {height} \
                     (a reorg is in flight); re-request this height"
                )));
            }
            return Ok(empty_heights(height, height));
        }
        Err(e) => return Err(index_unavailable(&e)),
    };
    Ok(json!({ height.to_string(): txs_object(src, &row, cut_through)? }))
}

/// The `{txid: {tweak, output_pubkeys}}` half of a height map.
fn txs_object(
    src: &TweakSource,
    row: &SpBlockRow,
    cut_through: bool,
) -> Result<Value, JsonRpcError> {
    if row.entries.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    // The wire format always carries each transaction's taproot outputs — that
    // is what lets a client confirm a match without fetching the block, and the
    // measured difference between this stream and a bare tweak list. The lean
    // index stores none, so they are re-derived here from the block the row
    // itself names (never a height→hash lookup, which is last-writer-wins).
    let Some(block) = src.chain.get_block(&row.block_hash) else {
        // Pruned or otherwise unreadable. Serving tweak-only entries would look
        // like transactions with no outputs, which a client reads as "not mine";
        // an error is the honest answer.
        return Err(JsonRpcError::internal(format!(
            "block {} is not available locally; cannot serve its tweak outputs",
            row.block_hash
        )));
    };
    let wanted: HashSet<bitcoin::Txid> = row.entries.iter().map(|e| e.txid).collect();
    let chain = src.chain.clone();
    // `has_coin`, not `get_coin`: this runs once per taproot output of every
    // eligible transaction the scan touches, and `get_coin` would promote each
    // historical coin it reads into the clean LRU that block connection depends
    // on.
    let unspent = move |op: &OutPoint| chain.has_coin(op);
    let by_txid = node::sp_serve::taproot_outputs_by_txid(&block, &wanted);

    let mut out = Map::new();
    for e in &row.entries {
        let outs = match by_txid.get(&e.txid) {
            // Nothing left unspent: every taproot output of this transaction is
            // already spent, so there is no coin to find at any k. Drop the
            // whole entry — never trim a surviving one, which would cut a BIP
            // 352 scanner's k walk short (see `node::sp_serve::any_unspent`).
            Some(o) if cut_through && !node::sp_serve::any_unspent(e.txid, o, &unspent) => {
                continue;
            }
            Some(o) => o,
            // Absent: the block does not contain this transaction, which is a
            // reorg race against the row rather than evidence about spentness.
            // Serving the height anyway would advance the client's progress
            // marker past a payment it never saw, so refuse the height in-band
            // and let the client re-request it against the replacement block —
            // the same call the unreadable-block case makes above.
            None => {
                return Err(JsonRpcError::internal(format!(
                    "block {} no longer carries transaction {}; re-request this height",
                    row.block_hash, e.txid
                )));
            }
        };
        let mut pubkeys = Map::new();
        for o in outs {
            pubkeys.insert(
                o.vout.to_string(),
                json!([hex::encode(o.output_key), o.value]),
            );
        }
        out.insert(
            e.txid.to_string(),
            json!({ "tweak": hex::encode(e.tweak.serialize()), "output_pubkeys": pubkeys }),
        );
    }
    Ok(Value::Object(out))
}

/// `{"h": {}, "h+1": {}, …}` — one map covering an inclusive empty range.
pub fn empty_heights(first: u32, last: u32) -> Value {
    let mut m = Map::new();
    for h in first..=last {
        m.insert(h.to_string(), Value::Object(Map::new()));
    }
    Value::Object(m)
}

/// Inclusive end of the pre-activation wave starting at `start`, or `None` when
/// taproot is already active there (always the case on regtest and signet).
pub fn pre_activation_wave_end(start: u32, last: u32, activation: u32) -> Option<u32> {
    if start >= activation {
        return None;
    }
    let cap = start.saturating_add(EMPTY_WAVE_HEIGHTS.saturating_sub(1));
    Some(
        last.min(activation.saturating_sub(1))
            .min(cap)
            .min(same_decimal_width_end(start)),
    )
}

/// The largest height with the same number of decimal digits as `h` (9, 99,
/// 999, ...).
///
/// A wave is one JSON object keyed by height, and `serde_json::Map` is a
/// `BTreeMap` here — `preserve_order` is not enabled — so keys serialize in
/// **lexicographic** order, not numeric. A wave spanning 1..=1024 therefore ends
/// with the key `"999"`, not `"1024"`, and a client that reads the map's last
/// key as its progress marker resumes at 1000 and re-requests everything above
/// it. Keeping a wave inside one digit width makes the two orders agree, so the
/// last key is always the highest height in the wave.
fn same_decimal_width_end(h: u32) -> u32 {
    let mut bound: u64 = 9;
    while bound < u64::from(h) {
        bound = bound * 10 + 9;
    }
    bound.min(u64::from(u32::MAX)) as u32
}

/// The JSON line for one notification carrying `map`.
pub fn notification_line(map: &Value) -> String {
    json!({ "jsonrpc": "2.0", "method": METHOD, "params": [map] }).to_string()
}

/// The end-of-chunk marker. Clients resubscribe from the next unscanned height
/// when they see it; a client that never receives it waits forever.
pub fn done_line() -> String {
    notification_line(&json!({ "message": "done" }))
}

/// Map an index state to the JSON-RPC error a client sees. Refusing is
/// deliberate: a partial index would answer a scan with silence at exactly the
/// heights it has not indexed, and the client cannot tell that from "no payments
/// here".
fn index_unavailable(e: &SpIndexError) -> JsonRpcError {
    JsonRpcError::bad_request(format!("blockchain.tweaks.subscribe unavailable: {e}"))
}

/// Advance the stream cursor by `by`, or `None` when that would pass `last`.
///
/// In `u64` on purpose. `h.saturating_add(..)` looks equivalent and is not: at
/// `h == u32::MAX` it saturates back to `u32::MAX`, so the loop guard
/// `h <= last` stays true forever and one request naming height 4294967295
/// spins out the entire chunk budget re-serving a single empty height.
/// Saturation is the wrong operator for a cursor that must be able to leave its
/// own range.
fn advance(h: u32, by: u32, last: u32) -> Option<u32> {
    let next = u64::from(h) + u64::from(by);
    (next <= u64::from(last)).then_some(next as u32)
}

/// Stream heights `[from, last]` as notifications, then `{"message":"done"}`.
///
/// Runs as its own task so a taproot-era scan never blocks the connection's
/// request loop, and stops early on three conditions: the client disconnected
/// (the notification channel closes), the chunk budget elapsed, or a read
/// failed. All three end with `done` if the channel still accepts it, because a
/// client that never sees `done` waits forever rather than resubscribing.
///
/// Reads run on the blocking pool in hops of [`HEIGHTS_PER_HOP`] heights: each
/// height is an index read plus a block read, and the notification channel's
/// capacity provides backpressure, so a slow client throttles the reads instead
/// of making the node buffer a cold sync.
pub async fn stream_chunk(
    src: TweakSource,
    from: u32,
    last: u32,
    cut_through: bool,
    activation: u32,
    notify_tx: mpsc::Sender<String>,
    budget: Duration,
) {
    let started = Instant::now();
    let mut h = from;
    while h <= last {
        if started.elapsed() >= budget {
            break;
        }
        // Nothing below taproot activation can carry a payment, so those heights
        // are empty by construction. Collapse a wave of them into one
        // notification: a client restoring from an old height still needs its
        // progress marker to move (it reads the map's last key), but one line
        // per height would be ~700k lines on mainnet.
        if let Some(end) = pre_activation_wave_end(h, last, activation) {
            if notify_tx.send(notification_line(&empty_heights(h, end))).await.is_err() {
                return;
            }
            let Some(next) = advance(end, 1, last) else { break };
            h = next;
            continue;
        }

        let hop_end = h.saturating_add(HEIGHTS_PER_HOP - 1).min(last);
        let src_hop = src.clone();
        let lines = tokio::task::spawn_blocking(move || {
            let mut lines = Vec::with_capacity((hop_end - h + 1) as usize);
            for hh in h..=hop_end {
                match height_map(&src_hop, hh, cut_through) {
                    Ok(map) => lines.push(notification_line(&map)),
                    // Stop at the first failure rather than skipping the height:
                    // a hole a client cannot see is a payment it never scans.
                    Err(e) => {
                        tracing::warn!(height = hh, error = %e.message, "tweak stream ended early");
                        break;
                    }
                }
            }
            lines
        })
        .await
        .unwrap_or_default();

        let served = lines.len() as u32;
        for line in lines {
            if notify_tx.send(line).await.is_err() {
                return;
            }
        }
        if served == 0 {
            break;
        }
        let Some(next) = advance(h, served, last) else { break };
        h = next;
    }
    // Best-effort: the client may already be gone.
    let _ = notify_tx.send(done_line()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cake_probe_params() {
        let req = parse_req(&json!([0, 1, false])).expect("probe parses");
        assert_eq!(req, TweakReq { start: 0, count: 1, historical: false });
        assert!(req.cut_through(), "historicalMode=false means cut through");
    }

    #[test]
    fn count_and_mode_default_when_omitted() {
        let req = parse_req(&json!([850_000])).expect("start alone parses");
        assert_eq!(req.count, 1, "one height, like Cake's getTweaks probe");
        assert!(!req.historical);
    }

    #[test]
    fn zero_count_is_one_height_not_none() {
        // A zero count would otherwise mean "serve nothing", and the client
        // would wait for a stream that never starts.
        assert_eq!(parse_req(&json!([5, 0, false])).expect("parses").count, 1);
    }

    #[test]
    fn rejects_missing_or_malformed_params() {
        assert!(parse_req(&json!([])).is_err());
        assert!(parse_req(&json!(["850000"])).is_err(), "height must be numeric");
        assert!(parse_req(&json!([1, 1, "yes"])).is_err(), "mode must be boolean");
        assert!(parse_req(&json!([-1])).is_err(), "negative height is not a height");
    }

    #[test]
    fn last_height_clamps_to_tip_and_stops_above_it() {
        let req = TweakReq { start: 100, count: 50, historical: false };
        assert_eq!(req.last_height(120), Some(120), "clamped to tip");
        assert_eq!(req.last_height(1_000), Some(149), "start + count - 1");
        assert_eq!(TweakReq { start: 200, count: 1, historical: false }.last_height(120), None);
    }

    #[test]
    fn empty_heights_map_carries_every_key_in_order() {
        let m = empty_heights(7, 9);
        let obj = m.as_object().expect("object");
        assert_eq!(obj.len(), 3);
        // The last key is what a client reads as progress, so the range must be
        // complete rather than just its endpoints — and the *serialized* last
        // key must be the highest height, which is a claim about key order, not
        // just membership.
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["7", "8", "9"]);
        assert!(obj["8"].as_object().expect("height object").is_empty());
    }

    #[test]
    fn a_wave_never_straddles_a_decimal_width_so_its_last_key_is_its_highest() {
        // `serde_json::Map` is a BTreeMap: keys come out lexicographically. Left
        // unbounded, a 1..=1024 wave would serialize with "999" last and a
        // client would resume at 1000, re-requesting 1000..=1024 forever after
        // every restore. Each wave stays inside one digit width instead.
        for (start, activation) in [(1u32, 709_632u32), (10, 709_632), (995, 709_632)] {
            let end = pre_activation_wave_end(start, 1_000_000, activation).expect("wave");
            let m = empty_heights(start, end);
            let obj = m.as_object().expect("object");
            let last_key = obj.keys().next_back().expect("non-empty");
            assert_eq!(
                last_key.parse::<u32>().expect("numeric key"),
                end,
                "wave {start}..={end} must serialize with its highest height last"
            );
        }
        assert_eq!(same_decimal_width_end(0), 9);
        assert_eq!(same_decimal_width_end(9), 9);
        assert_eq!(same_decimal_width_end(10), 99);
        assert_eq!(same_decimal_width_end(1_000), 9_999);
        assert_eq!(same_decimal_width_end(u32::MAX), u32::MAX);
    }

    #[test]
    fn the_cursor_can_leave_its_range_at_u32_max() {
        // `saturating_add` cannot: at u32::MAX it returns u32::MAX, the loop
        // guard `h <= last` stays true, and a request naming height 4294967295
        // spins the whole chunk budget re-serving one empty height.
        assert_eq!(advance(5, 3, 10), Some(8));
        assert_eq!(advance(9, 1, 10), Some(10), "landing exactly on last is fine");
        assert_eq!(advance(10, 1, 10), None, "one past last ends the chunk");
        assert_eq!(advance(u32::MAX, 1, u32::MAX), None, "no fixed point at the ceiling");
    }

    #[test]
    fn pre_activation_wave_is_bounded_and_stops_at_activation() {
        // Below activation: one wave, capped at EMPTY_WAVE_HEIGHTS and at the
        // decimal-width boundary that keeps the map's last key its highest.
        assert_eq!(pre_activation_wave_end(0, 1_000_000, 709_632), Some(9));
        assert_eq!(pre_activation_wave_end(1_000, 1_000_000, 709_632), Some(2_023));
        // The wave never crosses activation, so the first real height is served
        // from the index rather than swallowed as "empty".
        assert_eq!(pre_activation_wave_end(709_000, 1_000_000, 709_632), Some(709_631));
        // Requested range ends first.
        assert_eq!(pre_activation_wave_end(10, 42, 709_632), Some(42));
        // At or above activation there is no empty wave at all (regtest/signet
        // activate at 0, so this is their only path).
        assert_eq!(pre_activation_wave_end(709_632, 1_000_000, 709_632), None);
        assert_eq!(pre_activation_wave_end(0, 10, 0), None);
    }

    #[test]
    fn notification_and_done_lines_match_the_client_shape() {
        let line = notification_line(&empty_heights(3, 3));
        let v: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["method"], METHOD);
        // Clients read `params.last`, so the map must be the single param.
        assert_eq!(v["params"].as_array().expect("array").len(), 1);
        assert!(v["params"][0]["3"].is_object());

        let done: Value = serde_json::from_str(&done_line()).expect("valid JSON");
        assert_eq!(done["method"], METHOD);
        assert_eq!(done["params"][0]["message"], "done");
    }
}
