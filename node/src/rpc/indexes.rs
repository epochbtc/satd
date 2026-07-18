//! Operator-facing RPCs for the indexes family: `getindexinfo` and
//! the four backfill control RPCs (`backfillindex`, `pauseindex`,
//! `resumeindex`, `cancelindex`).
//!
//! `getindexinfo` returns a wrapping shape (`{"address": {...}, ...}`)
//! so future indexes (txindex, blockfilter) join under sibling keys
//! without breaking consumers. The exact JSON layout is documented on
//! `getindexinfo` below and locked by `STABILITY_POLICY.md` Tier 2.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use serde_json::{Value, json};

use crate::chain::state::ChainState;
use crate::index::address::{
    BackfillCommand, BackfillError, BackfillHandle, cursor::BackfillState, preflight_disk,
    render_status,
};
#[cfg(feature = "block-filter-index")]
use crate::index::filter;
use crate::index::silent_payments;
use crate::storage::Store;

/// `getindexinfo` → `{"address": {...}, "basic block filter index": {...}}`:
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
#[allow(clippy::too_many_arguments)]
pub fn get_index_info(
    backfill: Option<&Arc<BackfillHandle>>,
    chain: &Arc<ChainState>,
    address_enabled: bool,
    best_block_height: u32,
    sp_index_enabled: bool,
    sp_backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")] block_filter_index_enabled: bool,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<&Arc<filter::BackfillHandle>>,
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
    let active = matches!(cursor_state, BackfillState::Running | BackfillState::Paused);
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
    // reads the on-disk completeness marker AND requires no backfill
    // to be mid-flight. Both must be true for the BIP 157 P2P service
    // and `getblockfilter` RPC to actually return data.
    #[cfg(feature = "block-filter-index")]
    {
        let filter_complete = chain.store_ref().block_filter_index_complete();
        let report = filter::render_status(
            filter_backfill.map(|h| h.as_ref()),
            block_filter_index_enabled,
            filter_complete,
        );
        let mut bfi = serde_json::Map::new();
        bfi.insert("synced".into(), json!(report.synced));
        bfi.insert("best_block_height".into(), json!(best_block_height));

        // Emit the backfill substructure even when no backfill has run
        // (Idle), matching the address-index shape so clients can probe
        // the field unconditionally.
        let cursor_state = filter_backfill
            .map(|h| h.cursor().state)
            .unwrap_or(filter::cursor::BackfillState::Idle);
        let active = matches!(
            cursor_state,
            filter::cursor::BackfillState::Running | filter::cursor::BackfillState::Paused
        );
        let estimated_remaining_seconds = estimate_filter_remaining_seconds(&report);
        let mut bf = serde_json::Map::new();
        bf.insert("active".into(), json!(active));
        bf.insert("state".into(), json!(cursor_state.label()));
        bf.insert("cursor_height".into(), json!(report.cursor_height));
        bf.insert("snapshot_height".into(), json!(report.snapshot_height));
        bf.insert(
            "estimated_remaining_seconds".into(),
            json!(estimated_remaining_seconds),
        );
        if cursor_state == filter::cursor::BackfillState::Failed
            && let Some(msg) = chain.store_ref().read_filter_backfill_last_error()
        {
            bf.insert("last_error".into(), json!(msg));
        }
        bfi.insert("backfill".into(), Value::Object(bf));
        top.insert("basic block filter index".into(), Value::Object(bfi));
    }

    // BIP 352 silent-payment tweak index sibling. `sp_index_enabled` is
    // the runtime config bit (`--silentpaymentindex=1`); `synced` reads
    // the on-disk completeness marker AND requires no backfill to be
    // mid-flight. Both must be true before the tweak-serving surfaces
    // (streaming `tweaks` category / `getsilentpaymentblockdata`, PR-5)
    // return data.
    {
        let sp_complete = chain.store_ref().silent_payment_index_complete();
        let report = silent_payments::render_status(
            sp_backfill.map(|h| h.as_ref()),
            sp_index_enabled,
            sp_complete,
        );
        let mut spi = serde_json::Map::new();
        spi.insert("synced".into(), json!(report.synced));
        spi.insert("best_block_height".into(), json!(best_block_height));

        let cursor_state = sp_backfill
            .map(|h| h.cursor().state)
            .unwrap_or(silent_payments::BackfillState::Idle);
        let active = matches!(
            cursor_state,
            silent_payments::BackfillState::Running | silent_payments::BackfillState::Paused
        );
        let estimated_remaining_seconds = estimate_sp_remaining_seconds(&report);
        let mut bf = serde_json::Map::new();
        bf.insert("active".into(), json!(active));
        bf.insert("state".into(), json!(cursor_state.label()));
        bf.insert("cursor_height".into(), json!(report.cursor_height));
        bf.insert("snapshot_height".into(), json!(report.snapshot_height));
        bf.insert(
            "estimated_remaining_seconds".into(),
            json!(estimated_remaining_seconds),
        );
        if cursor_state == silent_payments::BackfillState::Failed
            && let Some(msg) = chain.store_ref().read_sp_backfill_last_error()
        {
            bf.insert("last_error".into(), json!(msg));
        }
        spi.insert("backfill".into(), Value::Object(bf));
        top.insert("silentpayments".into(), Value::Object(spi));
    }
    Value::Object(top)
}

/// ETA estimator for the single-pass filter backfill. Same shape as
/// `estimate_remaining_seconds` for the address-index but reads the
/// linear `progress_ratio` (no two-pass weighting).
#[cfg(feature = "block-filter-index")]
fn estimate_filter_remaining_seconds(report: &filter::StatusReport) -> u64 {
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

/// ETA estimator for the single-pass SP-index backfill. Same shape as the
/// filter estimator — reads the linear `progress_ratio`.
fn estimate_sp_remaining_seconds(report: &silent_payments::StatusReport) -> u64 {
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
#[allow(clippy::too_many_arguments)]
pub fn backfill_index(
    backfill: Option<&Arc<BackfillHandle>>,
    cmd_tx: Option<&tokio::sync::mpsc::Sender<BackfillCommand>>,
    chain: &Arc<ChainState>,
    address_index_enabled: bool,
    target: &str,
    sp_backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    sp_cmd_tx: Option<&tokio::sync::mpsc::Sender<silent_payments::BackfillCommand>>,
    sp_index_enabled: bool,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<&Arc<filter::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")] filter_cmd_tx: Option<
        &tokio::sync::mpsc::Sender<filter::BackfillCommand>,
    >,
    #[cfg(feature = "block-filter-index")] block_filter_index_enabled: bool,
) -> Result<Value, (i32, String)> {
    #[cfg(feature = "block-filter-index")]
    if target == "blockfilter" {
        return backfill_index_filter(
            filter_backfill,
            filter_cmd_tx,
            chain,
            block_filter_index_enabled,
        );
    }
    if target == "silentpayment" {
        return backfill_index_sp(sp_backfill, sp_cmd_tx, chain, sp_index_enabled);
    }
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

/// `pause`/`resume`/`cancel` only make sense while a backfill is in
/// progress (state `running` or `paused`). When no backfill task is
/// running, flipping the atomic flags would silently mismatch the
/// persisted state and confuse operators ("paused: true, state: idle").
/// Treat any invocation while idle as an explicit no-op with a -8 error
/// so the command surface is honest.
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
    sp_backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<&Arc<filter::BackfillHandle>>,
) -> Result<Value, (i32, String)> {
    #[cfg(feature = "block-filter-index")]
    if target == "blockfilter" {
        let h = filter_backfill
            .ok_or((-32603, "filter backfill handle not initialized".to_string()))?;
        require_active_filter_backfill(h)?;
        h.pause();
        return Ok(json!({"paused": true, "state": h.cursor().state.label()}));
    }
    if target == "silentpayment" {
        let h = sp_backfill.ok_or((-32603, "SP backfill handle not initialized".to_string()))?;
        require_active_sp_backfill(h)?;
        h.pause();
        return Ok(json!({"paused": true, "state": h.cursor().state.label()}));
    }
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
    sp_backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<&Arc<filter::BackfillHandle>>,
) -> Result<Value, (i32, String)> {
    #[cfg(feature = "block-filter-index")]
    if target == "blockfilter" {
        let h = filter_backfill
            .ok_or((-32603, "filter backfill handle not initialized".to_string()))?;
        require_active_filter_backfill(h)?;
        h.resume();
        return Ok(json!({"resumed": true, "state": h.cursor().state.label()}));
    }
    if target == "silentpayment" {
        let h = sp_backfill.ok_or((-32603, "SP backfill handle not initialized".to_string()))?;
        require_active_sp_backfill(h)?;
        h.resume();
        return Ok(json!({"resumed": true, "state": h.cursor().state.label()}));
    }
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
    sp_backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<&Arc<filter::BackfillHandle>>,
) -> Result<Value, (i32, String)> {
    #[cfg(feature = "block-filter-index")]
    if target == "blockfilter" {
        let h = filter_backfill
            .ok_or((-32603, "filter backfill handle not initialized".to_string()))?;
        require_active_filter_backfill(h)?;
        h.cancel();
        return Ok(json!({"cancelled": true, "state": h.cursor().state.label()}));
    }
    if target == "silentpayment" {
        let h = sp_backfill.ok_or((-32603, "SP backfill handle not initialized".to_string()))?;
        require_active_sp_backfill(h)?;
        h.cancel();
        return Ok(json!({"cancelled": true, "state": h.cursor().state.label()}));
    }
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    let h = backfill.ok_or((-32603, "backfill handle not initialized".to_string()))?;
    require_active_backfill(h)?;
    h.cancel();
    Ok(json!({"cancelled": true, "state": h.cursor().state.label()}))
}

/// Mirror of `require_active_backfill` for the filter-index family.
#[cfg(feature = "block-filter-index")]
fn require_active_filter_backfill(
    handle: &Arc<filter::BackfillHandle>,
) -> Result<(), (i32, String)> {
    use filter::cursor::BackfillState;
    let state = handle.cursor().state;
    match state {
        BackfillState::Running | BackfillState::Paused => Ok(()),
        _ => Err((
            -8,
            format!(
                "no filter backfill is in progress (state: {}); pause/resume/cancel apply only to running or paused backfills",
                state.label()
            ),
        )),
    }
}

/// Filter-index `backfillindex blockfilter` handler. Single-pass walk
/// from genesis → tip; the synchronous setup runs `preflight_disk`,
/// captures the active-chain anchor, and atomically persists `Running`
/// before signalling the supervisor.
#[cfg(feature = "block-filter-index")]
fn backfill_index_filter(
    backfill: Option<&Arc<filter::BackfillHandle>>,
    cmd_tx: Option<&tokio::sync::mpsc::Sender<filter::BackfillCommand>>,
    chain: &Arc<ChainState>,
    block_filter_index_enabled: bool,
) -> Result<Value, (i32, String)> {
    use filter::cursor::BackfillState as FState;
    if !block_filter_index_enabled {
        return Err((
            -8,
            "block filter index is disabled (--blockfilterindex=0); enable it before requesting a backfill"
                .into(),
        ));
    }
    let h = backfill.ok_or((-32603, "filter backfill handle not initialized".to_string()))?;
    let tx = cmd_tx.ok_or((
        -32603,
        "filter backfill supervisor not running — restart the daemon to wire it".to_string(),
    ))?;

    let cur = h.cursor();
    match cur.state {
        FState::Running | FState::Paused => Ok(filter_in_progress_response(&cur)),
        FState::Completed => Ok(json!({
            "started": false,
            "reason": "filter backfill already completed for this datadir",
            "state": cur.state.label(),
            "snapshot_height": cur.snapshot_height,
        })),
        FState::Idle | FState::Cancelled | FState::Rejected | FState::Failed => {
            filter_start_fresh(h, tx, chain, &cur)
        }
    }
}

#[cfg(feature = "block-filter-index")]
fn filter_in_progress_response(cur: &filter::cursor::BackfillCursor) -> Value {
    json!({
        "started": false,
        "reason": "filter backfill already in progress",
        "state": cur.state.label(),
        "cursor_height": cur.cursor_height,
        "snapshot_height": cur.snapshot_height,
    })
}

#[cfg(feature = "block-filter-index")]
fn filter_start_fresh(
    h: &Arc<filter::BackfillHandle>,
    tx: &tokio::sync::mpsc::Sender<filter::BackfillCommand>,
    chain: &Arc<ChainState>,
    prev: &filter::cursor::BackfillCursor,
) -> Result<Value, (i32, String)> {
    filter::preflight_disk(chain).map_err(map_filter_backfill_err)?;

    let (tip_hash, tip_height) = chain.tip_snapshot();
    let store = chain.store_ref();

    // Empty chain (genesis only): walk a one-element snapshot
    // synchronously rather than spawning a runner. The runner has its
    // own genesis emit branch so the synchronous shortcut just stamps
    // the marker and Completes.
    if tip_height == 0 {
        h.reset_flags();
        h.start(store.as_ref(), 0, tip_hash.to_byte_array())
            .map_err(map_filter_backfill_err)?;
        // Stamp filter row 0 inline — the runner walks 1..=tip, so an
        // empty chain (height 0) skips the loop entirely. Emit genesis
        // here so `getblockfilter <genesis>` works on an empty
        // backfill chain.
        let block = chain.get_block(&tip_hash).ok_or_else(|| {
            (
                -32603,
                format!("missing genesis block data for {}", tip_hash),
            )
        })?;
        let cfg = filter::FilterIndexConfig {
            enabled: true,
            peer_serve: false,
        };
        let prev_map: std::collections::HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf> =
            std::collections::HashMap::new();
        let mut batch = crate::storage::StoreBatch::default();
        if let Some((row, header_row)) = filter::build_filter_row_pair(
            &cfg,
            0,
            &block,
            &prev_map,
            &filter::emit::GENESIS_PREV_FILTER_HEADER,
        )
        .map_err(|e| (-32603, format!("genesis filter emit: {e}")))?
        {
            batch.filter_puts.push(row);
            batch.filter_header_puts.push(header_row);
        }
        store
            .write_batch_mode(batch, crate::storage::WriteMode::Normal)
            .map_err(|e| (-32603, format!("write genesis filter row: {e}")))?;
        h.mark_completed(store.as_ref())
            .map_err(map_filter_backfill_err)?;
        return Ok(json!({
            "started": true,
            "completed": true,
            "reason": "empty chain — only genesis filter stamped",
            "previous_state": prev.state.label(),
        }));
    }

    let permit = match tx.try_reserve() {
        Ok(p) => p,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            return Ok(json!({
                "started": false,
                "reason": "another filter backfill start is already queued",
                "state": prev.state.label(),
            }));
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            return Err((
                -32603,
                "filter backfill supervisor channel closed; restart the daemon".to_string(),
            ));
        }
    };

    h.reset_flags();
    match h.start(store.as_ref(), tip_height, tip_hash.to_byte_array()) {
        Ok(()) => {}
        Err(filter::BackfillError::AlreadyRunning(_)) => {
            drop(permit);
            return Ok(filter_in_progress_response(&h.cursor()));
        }
        Err(e) => {
            drop(permit);
            return Err(map_filter_backfill_err(e));
        }
    }
    permit.send(filter::BackfillCommand::Start);
    Ok(json!({
        "started": true,
        "previous_state": prev.state.label(),
        "snapshot_height": tip_height,
    }))
}

#[cfg(feature = "block-filter-index")]
fn map_filter_backfill_err(e: filter::BackfillError) -> (i32, String) {
    use filter::BackfillError as E;
    match e {
        E::FilterIndexDisabled => (
            -8,
            "block filter index is disabled; enable --blockfilterindex=basic first".into(),
        ),
        other => (-32603, format!("filter backfill setup failed: {}", other)),
    }
}

/// Mirror of `require_active_backfill` for the SP-index family.
fn require_active_sp_backfill(
    handle: &Arc<silent_payments::BackfillHandle>,
) -> Result<(), (i32, String)> {
    use silent_payments::BackfillState;
    let state = handle.cursor().state;
    match state {
        BackfillState::Running | BackfillState::Paused => Ok(()),
        _ => Err((
            -8,
            format!(
                "no SP backfill is in progress (state: {}); pause/resume/cancel apply only to running or paused backfills",
                state.label()
            ),
        )),
    }
}

/// SP-index `backfillindex silentpayment` handler. Single-pass walk from
/// taproot activation → tip; the synchronous setup runs `preflight_disk`,
/// captures the active-chain anchor, and atomically persists `Running`
/// before signalling the supervisor. Same lifecycle as the filter
/// handler.
fn backfill_index_sp(
    backfill: Option<&Arc<silent_payments::BackfillHandle>>,
    cmd_tx: Option<&tokio::sync::mpsc::Sender<silent_payments::BackfillCommand>>,
    chain: &Arc<ChainState>,
    sp_index_enabled: bool,
) -> Result<Value, (i32, String)> {
    use silent_payments::BackfillState as SState;
    if !sp_index_enabled {
        return Err((
            -8,
            "silent-payment index is disabled (--silentpaymentindex=0); enable it before requesting a backfill"
                .into(),
        ));
    }
    let h = backfill.ok_or((-32603, "SP backfill handle not initialized".to_string()))?;
    let tx = cmd_tx.ok_or((
        -32603,
        "SP backfill supervisor not running — restart the daemon to wire it".to_string(),
    ))?;

    let cur = h.cursor();
    match cur.state {
        SState::Running | SState::Paused => Ok(sp_in_progress_response(&cur)),
        // The on-disk completeness marker — not the cursor state — is the
        // source of truth for "the index is whole." The marker is cleared
        // independently of the cursor (e.g. a run with `--silentpaymentindex=0`
        // invalidates it on every connect while leaving the cursor `Completed`),
        // so refuse a re-backfill only when the index is *genuinely* complete.
        // Otherwise fall through to a fresh walk that refills the holes —
        // `start()` accepts `Completed → Running` and re-walks from activation.
        SState::Completed if chain.store_ref().silent_payment_index_complete() => Ok(json!({
            "started": false,
            "reason": "SP backfill already completed for this datadir",
            "state": cur.state.label(),
            "snapshot_height": cur.snapshot_height,
        })),
        SState::Idle
        | SState::Cancelled
        | SState::Rejected
        | SState::Failed
        | SState::Completed => sp_start_fresh(h, tx, chain, &cur),
    }
}

fn sp_in_progress_response(cur: &silent_payments::BackfillCursor) -> Value {
    json!({
        "started": false,
        "reason": "SP backfill already in progress",
        "state": cur.state.label(),
        "cursor_height": cur.cursor_height,
        "snapshot_height": cur.snapshot_height,
    })
}

fn sp_start_fresh(
    h: &Arc<silent_payments::BackfillHandle>,
    tx: &tokio::sync::mpsc::Sender<silent_payments::BackfillCommand>,
    chain: &Arc<ChainState>,
    prev: &silent_payments::BackfillCursor,
) -> Result<Value, (i32, String)> {
    silent_payments::preflight_disk(chain).map_err(map_sp_backfill_err)?;

    let (tip_hash, tip_height) = chain.tip_snapshot();
    let store = chain.store_ref();

    // Chain at (or before) taproot activation: no SP-eligible blocks
    // exist yet, so there's nothing to walk. Stamp the completeness
    // marker synchronously and Complete without spawning a runner — the
    // marker means "no holes below the tip", which is trivially true when
    // there are no eligible blocks. A later block connect above activation
    // is handled by the live emit path (which keeps the index whole).
    let walk_start = crate::validation::script::activation_heights(chain.network)
        .taproot
        .max(1);
    if tip_height < walk_start {
        h.reset_flags();
        h.start(store.as_ref(), tip_height, tip_hash.to_byte_array())
            .map_err(map_sp_backfill_err)?;
        h.mark_completed(store.as_ref())
            .map_err(map_sp_backfill_err)?;
        return Ok(json!({
            "started": true,
            "completed": true,
            "reason": "chain has not reached taproot activation — no eligible blocks",
            "previous_state": prev.state.label(),
        }));
    }

    let permit = match tx.try_reserve() {
        Ok(p) => p,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            return Ok(json!({
                "started": false,
                "reason": "another SP backfill start is already queued",
                "state": prev.state.label(),
            }));
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            return Err((
                -32603,
                "SP backfill supervisor channel closed; restart the daemon".to_string(),
            ));
        }
    };

    h.reset_flags();
    match h.start(store.as_ref(), tip_height, tip_hash.to_byte_array()) {
        Ok(()) => {}
        Err(silent_payments::BackfillError::AlreadyRunning(_)) => {
            drop(permit);
            return Ok(sp_in_progress_response(&h.cursor()));
        }
        Err(e) => {
            drop(permit);
            return Err(map_sp_backfill_err(e));
        }
    }
    permit.send(silent_payments::BackfillCommand::Start);
    Ok(json!({
        "started": true,
        "previous_state": prev.state.label(),
        "snapshot_height": tip_height,
    }))
}

fn map_sp_backfill_err(e: silent_payments::BackfillError) -> (i32, String) {
    use silent_payments::BackfillError as E;
    match e {
        E::SilentPaymentIndexDisabled => (
            -8,
            "silent-payment index is disabled; enable --silentpaymentindex=1 first".into(),
        ),
        other => (-32603, format!("SP backfill setup failed: {}", other)),
    }
}

/// `getblockfilter <blockhash> [filtertype]` — Bitcoin-Core-compatible
/// RPC. Returns `{filter: hex, header: hex}` for the basic filter at
/// the block.
///
/// Errors:
/// - `RPC_INVALID_ADDRESS_OR_KEY` (-5) when the block hash is unknown.
/// - `RPC_INVALID_PARAMETER` (-8) when `filtertype` is not `"basic"`.
/// - `RPC_MISC_ERROR` (-1) when the index is disabled or not synced.
#[cfg(feature = "block-filter-index")]
pub fn get_block_filter(
    chain: &Arc<ChainState>,
    filter_index: Option<&Arc<dyn node_filter_index::FilterIndex>>,
    block_hash_hex: &str,
    filter_type_str: Option<&str>,
) -> Result<Value, (i32, String)> {
    use bitcoin::BlockHash;
    use bitcoin::hashes::{Hash, hex::FromHex};
    use node_filter_index::FILTER_TYPE_BASIC;

    let filter_type = match filter_type_str {
        None | Some("basic") => FILTER_TYPE_BASIC,
        Some(other) => return Err((-8, format!("unknown filter type '{other}'"))),
    };

    let raw = <[u8; 32]>::from_hex(block_hash_hex)
        .map_err(|e| (-5, format!("blockhash must be hex of length 64: {e}")))?;
    // Bitcoin block hashes are display-reversed; the wire-format we
    // deserialize from the user's hex IS the consensus byte order.
    // `BlockHash::from_byte_array` takes consensus bytes — but the
    // user typed the display form. Reverse it.
    let mut consensus = raw;
    consensus.reverse();
    let block_hash =
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(consensus));

    let entry = chain
        .get_block_index(&block_hash)
        .ok_or_else(|| (-5, "block not found".to_string()))?;
    let height = entry.height;

    // Active-chain check (review 2026-05-04 H2): the filter index is
    // height-keyed, so resolving a stale/fork/header-only block hash
    // through `get_block_index` and then reading by height would
    // return the active block's filter under the wrong hash. Reject
    // any hash that isn't the active chain at its claimed height.
    match chain.get_block_hash_by_height(height) {
        Some(active) if active == block_hash => {}
        _ => {
            return Err((
                -5,
                "filter not found for non-active block".to_string(),
            ));
        }
    }

    let idx = filter_index.ok_or_else(|| {
        (
            -1,
            "block filter index not initialized in this build".to_string(),
        )
    })?;

    let filter_bytes = idx
        .filter_at(filter_type, height)
        .map_err(map_filter_index_err)?;
    let header_bytes = idx
        .header_at(filter_type, height)
        .map_err(map_filter_index_err)?;

    // Re-check the active-chain mapping after the index reads to
    // prevent a concurrent reorg from interleaving a filter from one
    // block with the active-chain hash of another. If the height
    // mapping changed under us, surface as not-found rather than
    // returning stale data.
    match chain.get_block_hash_by_height(height) {
        Some(active) if active == block_hash => {}
        _ => {
            return Err((
                -5,
                "filter not found: concurrent reorg displaced the requested block"
                    .to_string(),
            ));
        }
    }

    // Header byte order (review 2026-05-04 M2): Bitcoin Core's RPC
    // convention for uint256-shaped fields is the display/reversed
    // hex encoding, which is what `FilterHeader::to_string()` /
    // `Display` produces. Returning `hex::encode(header_bytes)`
    // would emit the internal/wire byte order (reversed relative to
    // Core).
    let header_display =
        bitcoin::bip158::FilterHeader::from_byte_array(header_bytes).to_string();

    Ok(json!({
        "filter": hex::encode(filter_bytes),
        "header": header_display,
    }))
}

#[cfg(feature = "block-filter-index")]
fn map_filter_index_err(e: node_filter_index::IndexError) -> (i32, String) {
    use node_filter_index::IndexError;
    match e {
        IndexError::Disabled => (-1, "block filter index is disabled".to_string()),
        IndexError::Incomplete => (-1, "block filter index is not synced".to_string()),
        IndexError::NotFound(h) => (-5, format!("filter not found at height {h}")),
        IndexError::InvalidRange { .. } => (-8, "invalid filter range".to_string()),
        IndexError::Storage(s) => (-1, format!("filter storage error: {s}")),
    }
}

/// `getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` — the
/// JSON-RPC fallback for the streaming `tweaks` category. Serves the same
/// per-block BIP 352 tweak data the firehose does (§3.5), so scripts, the
/// reference-implementation differential, and integrators not yet on an SDK
/// can scan without a stream.
///
/// - `verbosity 0` (default): `{ block_hash, height, tweaks: ["<33B hex>", …] }`.
/// - `verbosity 1`: `tweaks` entries become `{ txid, tweak, max_value }`.
/// - `dust_limit` (sats, default 0) drops entries whose stored max taproot
///   output value is below the floor, on either verbosity.
///
/// Errors (per the design's serving-gate contract):
/// - `-5` (`RPC_INVALID_ADDRESS_OR_KEY`): unknown or non-active block.
/// - `-8` (`RPC_INVALID_PARAMETER`): the index is disabled, or `verbosity` is
///   out of range.
/// - `-1` (`RPC_MISC_ERROR`): the block is not yet indexed at that height (row
///   absent — the height-by-height scanner cannot proceed past a missing row,
///   but unlike BIP 157 it cannot silently miss its own outputs either).
pub fn get_silent_payment_block_data(
    chain: &Arc<ChainState>,
    block_hash_hex: &str,
    verbosity: Option<u32>,
    dust_limit: Option<u64>,
) -> Result<Value, (i32, String)> {
    use bitcoin::BlockHash;
    use bitcoin::hashes::hex::FromHex;
    use node_sp_index::{SpIndex, SpIndexError};

    let verbosity = verbosity.unwrap_or(0);
    if verbosity > 1 {
        return Err((-8, format!("verbosity must be 0 or 1, got {verbosity}")));
    }
    let dust_limit = dust_limit.unwrap_or(0);

    let raw = <[u8; 32]>::from_hex(block_hash_hex)
        .map_err(|e| (-5, format!("blockhash must be hex of length 64: {e}")))?;
    // The user typed the display (reversed) form; `from_byte_array` wants
    // consensus byte order. Reverse before constructing the hash.
    let mut consensus = raw;
    consensus.reverse();
    let block_hash =
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(consensus));

    let entry = chain
        .get_block_index(&block_hash)
        .ok_or_else(|| (-5, "block not found".to_string()))?;
    let height = entry.height;

    // Active-chain check: the tweak index is height-keyed, so a stale/fork/
    // header-only hash must not resolve to the active block's row.
    match chain.get_block_hash_by_height(height) {
        Some(active) if active == block_hash => {}
        _ => {
            return Err((-5, "tweak data not found for non-active block".to_string()));
        }
    }

    let row = chain.tweaks_at(height).map_err(|e| match e {
        SpIndexError::Disabled => (-8, "silent payment index is disabled".to_string()),
        SpIndexError::Incomplete => (
            -1,
            "silent payment index is not synced to this height yet".to_string(),
        ),
        SpIndexError::NotFound(h) => (
            -1,
            format!("silent payment tweak data not yet indexed at height {h}"),
        ),
        SpIndexError::Storage(s) => (-1, format!("silent payment index storage error: {s}")),
    })?;

    // The row is self-authenticating (§3.2): confirm it describes the block we
    // resolved, guarding against a concurrent reorg between the height lookup
    // and the index read.
    if row.block_hash != block_hash {
        return Err((
            -5,
            "tweak data not found: concurrent reorg displaced the requested block".to_string(),
        ));
    }

    let mut tweaks: Vec<Value> = Vec::with_capacity(row.entries.len());
    for e in &row.entries {
        if dust_limit != 0 && e.max_taproot_value.to_sat() < dust_limit {
            continue;
        }
        let tweak_hex = hex::encode(e.tweak.serialize());
        if verbosity == 0 {
            tweaks.push(json!(tweak_hex));
        } else {
            tweaks.push(json!({
                "txid": e.txid.to_string(),
                "tweak": tweak_hex,
                "max_value": e.max_taproot_value.to_sat(),
            }));
        }
    }

    Ok(json!({
        "block_hash": block_hash.to_string(),
        "height": height,
        "tweaks": tweaks,
    }))
}
