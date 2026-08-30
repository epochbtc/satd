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
use tokio::sync::{mpsc, Semaphore};

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

/// Concurrent silent-payment block scans allowed across the whole node.
///
/// A tweak read is the heaviest thing this surface does — a block read out of
/// the flat files plus, under cut-through, one UTXO lookup per taproot output in
/// it — and it is reachable by any unauthenticated client. `block_in_place` and
/// `spawn_blocking` keep that work off the async reactor, but neither *bounds*
/// it: the per-request timeout cannot interrupt a synchronous body, so without
/// a cap a client pipelining subscribes decides how much of the machine to
/// occupy. This is the cap. It is deliberately global rather than
/// per-connection, because the resource being protected is the node's storage
/// bandwidth, not any one connection's fairness.
///
/// The streaming half waits for a permit (it is already asynchronous and
/// chunked, so backpressure is free); the synchronous first height refuses
/// instead, because blocking there would hold the connection's request slot for
/// exactly as long as waiting would have.
static SP_READ_SLOTS: std::sync::LazyLock<Semaphore> = std::sync::LazyLock::new(|| {
    let cores = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    Semaphore::new(cores.div_ceil(2).clamp(2, 8))
});

/// Try to claim a scan slot without waiting. `None` means the node is already
/// running as many silent-payment scans as it will.
pub fn try_claim_scan_slot() -> Option<tokio::sync::SemaphorePermit<'static>> {
    SP_READ_SLOTS.try_acquire().ok()
}

/// The refusal a client gets when every scan slot is taken. Deliberately says
/// what to do about it: this is transient, and a wallet that retries succeeds.
pub fn scan_slots_busy() -> JsonRpcError {
    JsonRpcError::bad_request(
        "blockchain.tweaks.subscribe: this node is already running as many \
         silent-payment scans as it will; retry shortly",
    )
}

/// Most heights one subscribe will serve, whatever `count` asks for.
///
/// The de-facto reference server (`cake-tech/blockstream-electrs`) clamps
/// `count` to 1000 the same way, and both known clients ask for the entire
/// remaining chain in a single call — Cake sends `count = tip - syncHeight + 1`.
/// Clamping is therefore the expected behaviour, not a satd restriction.
///
/// It also settles what `{"message":"done"}` means. The two clients read the
/// sentinel differently: Cake treats it as "this chunk ended, resubscribe from
/// the last height key", while kiss-bdk treats it as "the range I requested was
/// fully served" and stops (kkdao/kiss-bdk#10). Those readings only agree if the
/// server always finishes the range it accepted before saying `done` — so satd
/// bounds the range up front rather than truncating an accepted one part-way.
pub const MAX_CHUNK_HEIGHTS: u32 = 1000;

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

    /// Inclusive last height to serve, clamped to `tip` and to
    /// [`MAX_CHUNK_HEIGHTS`]. `None` when `start` is already above the tip —
    /// there is nothing to stream.
    ///
    /// The height cap is what lets `done` mean the same thing to both clients:
    /// satd only ever accepts a range it intends to finish, so a client that
    /// reads the sentinel as "the requested range was served" is not misled.
    /// A client wanting more resubscribes, which is what both already do.
    pub fn last_height(&self, tip: u32) -> Option<u32> {
        if self.start > tip {
            return None;
        }
        let capped = self.count.min(MAX_CHUNK_HEIGHTS);
        Some(self.start.saturating_add(capped.saturating_sub(1)).min(tip))
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
    /// The tip when this request began, frozen.
    ///
    /// Deliberately *not* re-read from the chain per height. A reorg lowers the
    /// live tip below heights this source already promised to serve, and a
    /// liveness check would then classify their dropped rows as "above the tip,
    /// no row by construction" — the exact silent skip the row-miss guard
    /// exists to stop. See [`absence_is_an_answer`].
    pub tip_at_start: u32,
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
        Ok(Self {
            chain: state.chain.clone(),
            index,
            tip_at_start: state.chain.tip_height(),
        })
    }

    /// Taproot activation on this network — the lowest height that can carry a
    /// row, and so the point below which every height is empty by construction.
    pub fn activation_height(&self) -> u32 {
        self.index.activation_height()
    }
}

/// Whether a missing index row at `height` is a legitimate answer rather than a
/// hole.
///
/// Below taproot activation, and above the tip this request started from, there
/// is no row *by construction*, and `{"<h>": {}}` is the honest reply — it is
/// how a client's progress marker crosses barren stretches. Anywhere inside
/// `[activation, tip_at_start]` a complete index must have a row, so a miss
/// means the rows are moving under us: a reorg drops every disconnected
/// height's row in one batch and writes the replacement branch back one block
/// per batch. Replying `{}` there says "no payments at this height" about a
/// block that is about to be replaced by one that may well pay the client, and
/// the client's marker moves past it for good.
///
/// `tip_at_start` must be the tip frozen when the request began, **never** the
/// live tip. `perform_reorg` commits the disconnect batch — dropping those rows
/// — and only then lowers the in-memory tip to the fork point, so for the whole
/// reconnect leg the rowless heights sit *above* the live tip. Against a live
/// tip this predicate would call each of them "above the tip, empty by
/// construction" and serve `{}`, which is precisely the silent skip it is here
/// to prevent; against the frozen tip they are inside the promised range and
/// refuse in-band. The guarded window is the long one, not the microseconds
/// between the batch commit and the tip write.
///
/// A named predicate rather than an inline comparison because it is the whole
/// of the difference between a served scan and a silently short one, and an
/// inline `&&` is not something a test can fail on.
fn absence_is_an_answer(height: u32, activation: u32, tip_at_start: u32) -> bool {
    height < activation || height > tip_at_start
}

/// One height's map, `{"<height>": {<txid>: {...}}}`, as the result and every
/// notification carry it.
///
/// A height with no eligible transactions — including one below taproot
/// activation or above the tip this request started from — is
/// `{"<height>": {}}`. That is a real answer,
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
            // Inside `[activation, tip_at_start]` it is a hole, not an answer.
            // `from_state` already refused an incomplete index, so the way to
            // get here is a reorg: the disconnect drops each disconnected
            // height's row, and the replacement branch is written back one
            // block per batch, leaving a window where these heights have no
            // row. Answering `{}` there would tell the client "no payments at
            // this height" and advance its marker past a block that is about to
            // be replaced by one that may well pay it — the silent skip this
            // whole surface exists to avoid. Refuse in-band instead, exactly as
            // the streaming pager does for the same case.
            //
            // The tip here is frozen at subscribe time on purpose: during a
            // reorg's reconnect leg the live tip sits *below* these heights,
            // which would send them down the "above the tip" arm and serve `{}`.
            if !absence_is_an_answer(height, src.activation_height(), src.tip_at_start) {
                // `bad_request`, not `internal`: `internal` sends a fixed
                // `"internal error"` and keeps the detail in the log, which
                // would make this "refuse in-band" in name only. The text is
                // composed here from a height and carries nothing about the
                // node's filesystem, so it is safe to put on the wire — and a
                // client that is told to re-request the height can act on it.
                return Err(JsonRpcError::bad_request(format!(
                    "silent-payment index has no row for height {height} \
                     (a reorg is in flight); re-request this height"
                )));
            }
            return Ok(empty_heights(height, height));
        }
        Err(e) => return Err(index_unavailable(&e)),
    };
    Ok(json!({ height.to_string(): txs_object(src, &row, cut_through, height)? }))
}

/// The `{txid: {tweak, output_pubkeys}}` half of a height map.
fn txs_object(
    src: &TweakSource,
    row: &SpBlockRow,
    cut_through: bool,
    height: u32,
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
        return Err(JsonRpcError::bad_request(format!(
            "block {} is not available locally; cannot serve its tweak outputs",
            row.block_hash
        )));
    };
    let wanted: HashSet<bitcoin::Txid> = row.entries.iter().map(|e| e.txid).collect();
    // Spentness is read one output at a time against the live UTXO set, so a
    // connect or a reorg landing mid-evaluation gives a mixed view: some outputs
    // judged against the old chain, some against the new. That matters because
    // "every output spent" *drops the entry*, so a mixed view can drop an entry
    // that is unspent in the chain we end up on -- a scanner then never sees the
    // coin, which is the same silent miss the row-hole guard above exists to
    // stop.
    //
    // The tip moves on every connect and every disconnect, and nothing else
    // changes the UTXO set, so an unchanged tip across the evaluation is proof
    // the set held still. Check it after rather than locking: block connection
    // is the last thing a consumption surface should be able to block, and on a
    // node not reorging this costs two atomic reads and never fires.
    let tip_before = src.chain.tip_snapshot();
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

    // Only cut-through consults the UTXO set; a historical request built this
    // map from the block alone and nothing under it can have moved.
    if cut_through && src.chain.tip_snapshot() != tip_before {
        return Err(JsonRpcError::bad_request(format!(
            "the chain advanced while height {} was being cut through; \
             re-request this height",
            height,
        )));
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
///
/// Only sent once the whole accepted range has been served — see
/// [`incomplete_line`].
pub fn done_line() -> String {
    notification_line(&json!({ "message": "done" }))
}

/// End-of-stream marker for a range that was **not** served in full.
///
/// `done` cannot be used here. kiss-bdk reads it as "the requested range was
/// fully served" and stops (kkdao/kiss-bdk#10), so sending it after an early
/// break would tell that client every undelivered height had been scanned and
/// found empty — the silent skip the rest of this module is built to prevent.
/// Cake reads any `{"message": ...}` as end-of-chunk and resubscribes from the
/// last height key it saw, so it is unaffected either way.
///
/// The message names the last height actually served, so a client that does
/// look at it can resume exactly.
pub fn incomplete_line(served_through: u32, reason: &str) -> String {
    let resume = u64::from(served_through) + 1;
    notification_line(&json!({
        "message": format!("incomplete: {reason}; resume from height {resume}")
    }))
}

/// Map an index state to the JSON-RPC error a client sees. Refusing is
/// deliberate: a partial index would answer a scan with silence at exactly the
/// heights it has not indexed, and the client cannot tell that from "no payments
/// here".
fn index_unavailable(e: &SpIndexError) -> JsonRpcError {
    match e {
        // `Storage` wraps a stringified backend error, and RocksDB's routinely
        // embed absolute paths. `bad_request` keeps its message on the wire, so
        // routing this one there would hand the datadir layout to any
        // unauthenticated Electrum client. `internal` logs the detail and sends
        // a fixed `"internal error"`.
        SpIndexError::Storage(_) => JsonRpcError::internal(format!(
            "blockchain.tweaks.subscribe unavailable: {e}"
        )),
        // These two are satd's own text and name the option an operator has to
        // change, so they are worth putting in front of the user.
        SpIndexError::Disabled | SpIndexError::Incomplete | SpIndexError::NotFound(_) => {
            JsonRpcError::bad_request(format!("blockchain.tweaks.subscribe unavailable: {e}"))
        }
    }
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
    // Highest height actually delivered by this task, and — if the loop stopped
    // before reaching `last` — why. The end marker depends on the difference:
    // `done` claims the accepted range was served, and one client believes it.
    let mut served_through: Option<u32> = None;
    let mut cut_short: Option<&str> = None;
    while h <= last {
        if started.elapsed() >= budget {
            cut_short = Some("chunk budget elapsed");
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
            served_through = Some(end);
            let Some(next) = advance(end, 1, last) else { break };
            h = next;
            continue;
        }

        let hop_end = h.saturating_add(HEIGHTS_PER_HOP - 1).min(last);
        let src_hop = src.clone();
        // Aborting this task -- which is what a disconnect does -- cannot stop a
        // `spawn_blocking` closure that has already started, so without a check
        // inside it a client that connects, subscribes and drops repeats a full
        // 16-height scan of block reads and UTXO lookups per cycle, detached
        // from any connection limit. The channel closes when the connection
        // goes, so poll it between heights and stop at the next boundary.
        let hop_tx = notify_tx.clone();
        // Wait rather than refuse: this task already owns its chunk, and the
        // client is holding a connection open for it.
        let permit = SP_READ_SLOTS.acquire().await;
        let lines = tokio::task::spawn_blocking(move || {
            let mut lines = Vec::with_capacity((hop_end - h + 1) as usize);
            for hh in h..=hop_end {
                if hop_tx.is_closed() {
                    break;
                }
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
        drop(permit);

        let served = lines.len() as u32;
        for line in lines {
            if notify_tx.send(line).await.is_err() {
                return;
            }
        }
        if served == 0 {
            // The hop could not read the height it started on. `height_map`
            // already refused rather than skipping it, so stopping here leaves
            // the client short of `last` — which the end marker must say.
            cut_short = Some("a height could not be read");
            break;
        }
        served_through = Some(h.saturating_add(served - 1));
        let Some(next) = advance(h, served, last) else { break };
        h = next;
    }

    // `from - 1` is the height the synchronous half of the subscribe already
    // answered, so it is the floor for "how far this client got".
    let served_through = served_through.unwrap_or(from.saturating_sub(1));
    let end = match cut_short {
        None => done_line(),
        Some(reason) => incomplete_line(served_through, reason),
    };
    // Best-effort: the client may already be gone.
    let _ = notify_tx.send(end).await;
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
    fn scan_slots_are_finite_and_refuse_rather_than_queue() {
        // The cap is the only thing bounding how much storage work an
        // unauthenticated client can start: `block_in_place` keeps the reads off
        // the reactor, but nothing interrupts them once running and the
        // per-request timeout cannot fire during a synchronous body.
        let mut held = Vec::new();
        while let Some(p) = try_claim_scan_slot() {
            held.push(p);
            assert!(held.len() <= 64, "the semaphore must be finite");
        }
        assert!(held.len() >= 2, "at least two concurrent scans, got {}", held.len());

        // Exhausted: a further claim fails instead of waiting, and the refusal
        // tells the client it is transient.
        assert!(try_claim_scan_slot().is_none(), "must refuse once full");
        let err = scan_slots_busy();
        assert_eq!(err.code, 1, "in-band refusal, not a transport error");
        assert!(err.message.contains("retry"), "must say it is transient: {}", err.message);

        // Releasing one frees exactly one.
        held.pop();
        let regained = try_claim_scan_slot();
        assert!(regained.is_some(), "a released slot is reusable");
        drop(regained);
        drop(held);
    }

    #[test]
    fn an_accepted_range_never_exceeds_the_chunk_cap() {
        // Both clients ask for the whole remaining chain in one call -- Cake
        // sends `count = tip - syncHeight + 1`. Serving only part of an accepted
        // range and then saying `done` tells kiss-bdk the rest was scanned and
        // empty, so the range satd accepts has to be one it will finish.
        let huge = TweakReq { start: 800_000, count: u32::MAX, historical: false };
        assert_eq!(
            huge.last_height(900_000),
            Some(800_000 + MAX_CHUNK_HEIGHTS - 1),
            "a whole-chain request is capped, not accepted in full",
        );

        // The tip still wins when it is the tighter bound.
        let past_tip = TweakReq { start: 899_990, count: u32::MAX, historical: false };
        assert_eq!(past_tip.last_height(900_000), Some(900_000), "clamped to the tip");

        // Under the cap nothing changes.
        let small = TweakReq { start: 100, count: 5, historical: false };
        assert_eq!(small.last_height(900_000), Some(104));

        // The cap is a height count, so the boundary case serves exactly it.
        let exact = TweakReq { start: 0, count: MAX_CHUNK_HEIGHTS, historical: false };
        assert_eq!(exact.last_height(900_000), Some(MAX_CHUNK_HEIGHTS - 1));
    }

    #[test]
    fn a_truncated_stream_does_not_end_with_done() {
        // `done` is not a neutral "stream over": kiss-bdk reads it as "the range
        // I asked for was fully served" and stops. Anything short of `last` has
        // to end with a marker that does not carry that claim, naming where to
        // resume.
        let line = incomplete_line(899_998, "chunk budget elapsed");
        let v: Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(v["method"], METHOD, "same notification envelope as a height");
        let msg = v["params"][0]["message"].as_str().expect("message");
        assert!(!msg.contains("done"), "must not read as completion, got {msg:?}");
        assert!(msg.contains("899999"), "names the resume height, got {msg:?}");

        // And the completion marker still says exactly `done`, which is the
        // string the clients match on.
        let d: Value = serde_json::from_str(&done_line()).expect("valid JSON");
        assert_eq!(d["params"][0]["message"], "done");
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
    fn a_missing_row_is_an_answer_only_outside_the_served_range() {
        // Outside [activation, tip]: no row exists by construction, so an empty
        // map is the honest reply and the client's marker advances.
        assert!(absence_is_an_answer(0, 709_632, 900_000), "below activation");
        assert!(absence_is_an_answer(709_631, 709_632, 900_000), "one below activation");
        assert!(absence_is_an_answer(900_001, 709_632, 900_000), "one above the tip");
        assert!(absence_is_an_answer(u32::MAX, 709_632, 900_000), "far above the tip");

        // Inside it: a complete index must have a row, so a miss is a reorg
        // window. Answering `{}` here is the silent skip -- the client records
        // the height as scanned and never revisits the block that replaces it.
        assert!(!absence_is_an_answer(709_632, 709_632, 900_000), "activation itself");
        assert!(!absence_is_an_answer(800_000, 709_632, 900_000), "mid-range");
        assert!(!absence_is_an_answer(900_000, 709_632, 900_000), "the tip itself");

        // Regtest and signet activate at 0, so every height at or below the tip
        // is inside the range and no height is "below activation".
        assert!(!absence_is_an_answer(0, 0, 10), "regtest genesis is in range");
        assert!(absence_is_an_answer(11, 0, 10), "still an answer above the tip");
    }

    #[test]
    fn a_reorg_window_is_a_hole_even_though_the_live_tip_dropped_below_it() {
        // The case this predicate exists for, and the one it got wrong while it
        // read the live tip.
        //
        // A subscription starts at tip 900_000. A 3-block reorg lands:
        // `perform_reorg` commits the disconnect batch — dropping the rows for
        // 899_998..=900_000 — and only then lowers the in-memory tip to 899_997.
        // The replacement branch is written back one block per batch, so for the
        // whole reconnect leg those three heights have no row *and* sit above
        // the live tip.
        //
        // Fed the live tip, every one of them takes the "above the tip, empty by
        // construction" arm and is served as `{}`. The client reads the map's
        // last key, records 900_000 as scanned, resumes at 900_001, and never
        // scans the three replacement blocks. Fed the tip frozen at subscribe,
        // they are inside the promised range and refuse in-band.
        const ACT: u32 = 709_632;
        const TIP_AT_START: u32 = 900_000;
        const LIVE_TIP_MID_REORG: u32 = 899_997;

        for h in [899_998, 899_999, 900_000] {
            assert!(
                !absence_is_an_answer(h, ACT, TIP_AT_START),
                "height {h} was promised by this subscription; a dropped row there is a hole",
            );
            assert!(
                absence_is_an_answer(h, ACT, LIVE_TIP_MID_REORG),
                "height {h} against the live tip is the silent skip — this asserts the \
                 wrong-input behaviour so the frozen-tip requirement cannot be quietly undone",
            );
        }

        // Above the promise it stays an answer, reorg or not: that is the
        // caught-up wallet polling one past the tip.
        assert!(absence_is_an_answer(900_001, ACT, TIP_AT_START), "one past the promise");
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
