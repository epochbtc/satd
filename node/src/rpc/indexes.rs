//! Operator-facing RPCs for the indexes family. M7 ships
//! `getindexinfo` and the four backfill control RPCs
//! (`backfillindex`, `pauseindex`, `resumeindex`, `cancelindex`).
//!
//! `getindexinfo` returns a wrapping shape (`{"address": {...},
//! ...}`) matching `ADDRESS_INDEX.md` §"Status reporting" so future
//! indexes (txindex, blockfilter) can join under sibling keys without
//! breaking consumers.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use serde_json::{Value, json};

use crate::chain::state::ChainState;
use crate::index::address::{
    BackfillCommand, BackfillError, BackfillHandle, cursor::BackfillState, preflight_disk,
    render_status,
};
use crate::storage::Store;

/// `getindexinfo` → `{"address": {...}, "basic block filter index": {...}}`
/// per `ADDRESS_INDEX.md` §"Status reporting":
///
/// ```text
/// {
///   "address": {
///     "synced": <bool>,
///     "best_block_height": <chain tip height>,
///     "backfill": { ... }
///   },
///   "basic block filter index": {  // only when block-filter-index feature is on
///     "synced": <bool>,
///     "best_block_height": <chain tip height>
///   }
/// }
/// ```
///
/// `backfill` is omitted when no backfill state has ever been
/// recorded for this datadir (cursor is fully idle), keeping the
/// response slim for the common "no backfill needed" case.
///
/// The Bitcoin Core-shaped key `"basic block filter index"` (with the
/// spaces and the lowercase wording) keeps existing tooling that polls
/// `getindexinfo` to wait for filter readiness happy. Backfill
/// progress for the filter index is deferred to a follow-up PR; the
/// `synced` field reads the `block_filter_index.complete` marker
/// directly so a fresh-from-genesis sync with `--blockfilterindex=basic`
/// reports `synced: true` once it reaches the chain tip.
pub fn get_index_info(
    backfill: Option<&Arc<BackfillHandle>>,
    chain: &Arc<ChainState>,
    address_enabled: bool,
    best_block_height: u32,
    #[cfg(feature = "block-filter-index")] block_filter_index_enabled: bool,
) -> Value {
    let report = render_status(backfill.map(|h| h.as_ref()), address_enabled);
    let mut address = serde_json::Map::new();
    address.insert("synced".into(), json!(report.synced));
    address.insert("best_block_height".into(), json!(best_block_height));

    // Emit backfill substructure when there's anything to report.
    // For a brand-new datadir with no backfill ever started, we still
    // emit it (with `active: false`) so clients can probe a stable
    // shape without conditional handling.
    let cursor_state = backfill
        .map(|h| h.cursor().state)
        .unwrap_or(BackfillState::Idle);
    let active = matches!(
        cursor_state,
        BackfillState::Running | BackfillState::Paused
    );
    let estimated_remaining_seconds = estimate_remaining_seconds(&report);
    let mut bf = serde_json::Map::new();
    bf.insert("active".into(), json!(active));
    bf.insert("state".into(), json!(cursor_state.label()));
    bf.insert("pass".into(), json!(report.pass));
    bf.insert("cursor_height".into(), json!(report.cursor_height));
    bf.insert("snapshot_height".into(), json!(report.snapshot_height));
    bf.insert(
        "estimated_remaining_seconds".into(),
        json!(estimated_remaining_seconds),
    );
    // Surface the persisted last-error message when the cursor is in
    // Failed state so operators can see *why* the backfill stopped
    // without grepping the log. Cleared automatically on the next
    // state transition (see `BackfillHandle::persist`).
    if cursor_state == BackfillState::Failed
        && let Some(msg) = chain.store_ref().read_backfill_last_error()
    {
        bf.insert("last_error".into(), json!(msg));
    }
    address.insert("backfill".into(), Value::Object(bf));

    // outpoint_spend completeness — exposed under the address-index
    // sibling because outpoint_spend rides the same on-disk lifecycle
    // (populated by connect_block / cleared by clear_chainstate /
    // stamped complete by backfill mark_completed). Operators reading
    // this field see whether `/tx/:txid/outspend/...` and
    // `gettxspendingprevout` (confirmed-side) can be trusted to
    // distinguish "unspent" from "we don't know" (round-3 H2).
    let mut outpoint_spend = serde_json::Map::new();
    outpoint_spend.insert(
        "complete".into(),
        json!(chain.store_ref().outpoint_spend_complete()),
    );
    address.insert("outpoint_spend".into(), Value::Object(outpoint_spend));

    let mut top = serde_json::Map::new();
    top.insert("address".into(), Value::Object(address));

    // BIP 158 filter index sibling. `block_filter_index_enabled` is
    // the runtime config bit (`--blockfilterindex=basic`); `synced`
    // reads the on-disk completeness marker. Both must be true for
    // the BIP 157 P2P service and `getblockfilter` RPC to actually
    // return data.
    #[cfg(feature = "block-filter-index")]
    {
        let synced = block_filter_index_enabled
            && chain.store_ref().block_filter_index_complete();
        let mut bfi = serde_json::Map::new();
        bfi.insert("synced".into(), json!(synced));
        bfi.insert("best_block_height".into(), json!(best_block_height));
        top.insert("basic block filter index".into(), Value::Object(bfi));
    }
    Value::Object(top)
}

/// Estimate seconds-to-completion from elapsed time and progress
/// ratio. Returns 0 when no estimate is available (idle, just
/// started, or no snapshot height yet).
fn estimate_remaining_seconds(report: &crate::index::address::backfill::StatusReport) -> u64 {
    if report.progress_ratio <= 0.0 || report.progress_ratio >= 1.0 {
        return 0;
    }
    if report.started_at_unix == 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now <= report.started_at_unix {
        return 0;
    }
    let elapsed = now - report.started_at_unix;
    let remaining_ratio = 1.0 - report.progress_ratio;
    ((elapsed as f64) * (remaining_ratio / report.progress_ratio)) as u64
}

/// `backfillindex address` → trigger a deferred backfill for the
/// address-history index. Two-pass walk over every block from genesis
/// to the chain tip, populating the address-index CFs that pre-date
/// the operator turning the index on.
///
/// All synchronous setup — disk pre-flight, temp-CF creation, anchor
/// persistence — happens inside this handler before returning
/// `started: true`. That closes the duplicate-RPC race: a second
/// caller arriving between the first's `try_send` and the supervisor
/// spawning the runner now sees the persisted `Running` state and
/// gets the standard "already in progress" response.
///
/// `Failed` is treated as a non-terminal recovery state (lenient
/// contract): a fresh `backfillindex` after a failed run starts over.
pub fn backfill_index(
    backfill: Option<&Arc<BackfillHandle>>,
    cmd_tx: Option<&tokio::sync::mpsc::Sender<BackfillCommand>>,
    chain: &Arc<ChainState>,
    address_index_enabled: bool,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    if !address_index_enabled {
        return Err((
            -8,
            "address index is disabled (--addressindex=0); enable it before requesting a backfill"
                .into(),
        ));
    }
    let h = backfill.ok_or((-32603, "backfill handle not initialized".to_string()))?;
    let tx = cmd_tx.ok_or((
        -32603,
        "backfill supervisor not running — restart the daemon to wire it".to_string(),
    ))?;

    let cur = h.cursor();
    match cur.state {
        BackfillState::Running | BackfillState::Paused => Ok(in_progress_response(&cur)),
        BackfillState::Completed => Ok(json!({
            "started": false,
            "reason": "backfill already completed for this datadir",
            "state": cur.state.label(),
            "snapshot_height": cur.snapshot_height,
        })),
        BackfillState::Idle
        | BackfillState::Cancelled
        | BackfillState::Rejected
        | BackfillState::Failed => start_fresh(h, tx, chain, &cur),
    }
}

fn in_progress_response(cur: &crate::index::address::cursor::BackfillCursor) -> Value {
    json!({
        "started": false,
        "reason": "backfill already in progress",
        "state": cur.state.label(),
        "pass": cur.pass,
        "cursor_height": cur.cursor_height,
        "snapshot_height": cur.snapshot_height,
    })
}

/// Synchronous fresh-start path. Runs pre-flight, snapshots the chain
/// tip, creates the temp CF, and atomically persists `Running` via
/// `handle.start()` — so a duplicate RPC arriving between this and
/// the supervisor spawn sees `Running` and falls into the "already
/// running" branch.
fn start_fresh(
    h: &Arc<BackfillHandle>,
    tx: &tokio::sync::mpsc::Sender<BackfillCommand>,
    chain: &Arc<ChainState>,
    prev: &crate::index::address::cursor::BackfillCursor,
) -> Result<Value, (i32, String)> {
    preflight_disk(chain).map_err(map_backfill_err)?;

    // Atomic snapshot of (hash, height) so the persisted anchor and
    // its height match exactly — see review-3 finding #1.
    let (tip_hash, tip_height) = chain.tip_snapshot();
    let store = chain.store_ref();

    // Empty chain (genesis only): no walk needed. Mark Completed
    // synchronously without spawning a runner. This still creates +
    // drops the temp CF so the durable state matches the "just ran a
    // backfill" path (operators can rely on `getindexinfo.synced`).
    if tip_height == 0 {
        store
            .create_backfill_temp_cf()
            .map_err(|e| (-32603, format!("create temp CF: {}", e)))?;
        h.reset_flags();
        h.start(store.as_ref(), 0, tip_hash.to_byte_array())
            .map_err(map_backfill_err)?;
        h.mark_completed(store.as_ref()).map_err(map_backfill_err)?;
        store
            .drop_backfill_temp_cf()
            .map_err(|e| (-32603, format!("drop temp CF: {}", e)))?;
        return Ok(json!({
            "started": true,
            "completed": true,
            "reason": "empty chain — nothing to walk",
            "previous_state": prev.state.label(),
        }));
    }

    // Reserve a permit on the supervisor channel BEFORE persisting
    // Running. Otherwise a `try_send` failure (channel full or
    // receiver dropped) would leave the cursor stuck Running with no
    // runner alive to advance it — review-2 finding #5.
    let permit = match tx.try_reserve() {
        Ok(p) => p,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            // Channel size 1 + the supervisor processes one Start at
            // a time. A full channel means a Start is already queued
            // — treat as an in-progress duplicate rather than failing
            // the operator.
            return Ok(json!({
                "started": false,
                "reason": "another backfill start is already queued",
                "state": prev.state.label(),
            }));
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            return Err((
                -32603,
                "backfill supervisor channel closed; restart the daemon".to_string(),
            ));
        }
    };

    store
        .create_backfill_temp_cf()
        .map_err(|e| (-32603, format!("create temp CF: {}", e)))?;
    h.reset_flags();

    // start() atomically transitions Idle/Cancelled/Rejected/Failed/
    // Completed → Running. If a concurrent caller raced ahead and
    // already set Running, we get AlreadyRunning back — surface that
    // as the standard "already in progress" wire shape rather than a
    // generic -32603. The reserved permit is dropped (no command sent)
    // — that's fine because the winning caller already enqueued one.
    match h.start(store.as_ref(), tip_height, tip_hash.to_byte_array()) {
        Ok(()) => {}
        Err(BackfillError::AlreadyRunning(_)) => {
            // Lost the race; current cursor reflects the winner.
            drop(permit);
            return Ok(in_progress_response(&h.cursor()));
        }
        Err(e) => {
            drop(permit);
            return Err(map_backfill_err(e));
        }
    }

    // Send via the reserved permit — infallible; closes the dispatch
    // gap that `try_send` had between persisting Running and the
    // supervisor receiving the command.
    permit.send(BackfillCommand::Start);
    Ok(json!({
        "started": true,
        "previous_state": prev.state.label(),
        "snapshot_height": tip_height,
    }))
}

fn map_backfill_err(e: BackfillError) -> (i32, String) {
    match e {
        BackfillError::InsufficientDisk { have, need } => (
            -8,
            format!(
                "insufficient free disk for backfill: have {} bytes, need {} bytes (~80 GB)",
                have, need
            ),
        ),
        BackfillError::AddressIndexDisabled => (
            -8,
            "address index is disabled; enable --addressindex=1 first".into(),
        ),
        other => (-32603, format!("backfill setup failed: {}", other)),
    }
}

/// Per ADDRESS_INDEX.md, `pause`/`resume`/`cancel` only make sense
/// while a backfill is in progress (state `running` or `paused`).
/// In M7 scaffolding mode, no backfill task ever runs, so flipping
/// the atomic flags would silently mismatch the persisted state and
/// confuse operators ("paused: true, state: idle"). Treat any
/// invocation while idle as an explicit no-op with a -8 error so the
/// command surface is honest.
fn require_active_backfill(handle: &Arc<BackfillHandle>) -> Result<(), (i32, String)> {
    use crate::index::address::cursor::BackfillState;
    let state = handle.cursor().state;
    match state {
        BackfillState::Running | BackfillState::Paused => Ok(()),
        _ => Err((
            -8,
            format!(
                "no backfill is in progress (state: {}); pause/resume/cancel apply only to running or paused backfills",
                state.label()
            ),
        )),
    }
}

pub fn pause_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    let h = backfill.ok_or((-32603, "backfill handle not initialized".to_string()))?;
    require_active_backfill(h)?;
    h.pause();
    Ok(json!({"paused": true, "state": h.cursor().state.label()}))
}

pub fn resume_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    let h = backfill.ok_or((-32603, "backfill handle not initialized".to_string()))?;
    require_active_backfill(h)?;
    h.resume();
    Ok(json!({"resumed": true, "state": h.cursor().state.label()}))
}

pub fn cancel_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    let h = backfill.ok_or((-32603, "backfill handle not initialized".to_string()))?;
    require_active_backfill(h)?;
    h.cancel();
    Ok(json!({"cancelled": true, "state": h.cursor().state.label()}))
}
