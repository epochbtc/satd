//! Operator-facing RPCs for the indexes family. M7 ships
//! `getindexinfo` and the four backfill control RPCs
//! (`backfillindex`, `pauseindex`, `resumeindex`, `cancelindex`).
//!
//! `getindexinfo` returns a wrapping shape (`{"address": {...},
//! ...}`) matching `ADDRESS_INDEX.md` §"Status reporting" so future
//! indexes (txindex, blockfilter) can join under sibling keys without
//! breaking consumers.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::index::address::{BackfillCommand, BackfillHandle, cursor::BackfillState, render_status};

/// `getindexinfo` → `{"address": {...}, ...}` per
/// `ADDRESS_INDEX.md` §"Status reporting":
///
/// ```text
/// {
///   "address": {
///     "synced": <bool>,
///     "best_block_height": <chain tip height>,
///     "backfill": {
///       "active": <bool>,
///       "pass": <1 or 2>,
///       "cursor_height": <u32>,
///       "snapshot_height": <u32>,
///       "estimated_remaining_seconds": <u64>
///     }
///   }
/// }
/// ```
///
/// `backfill` is omitted when no backfill state has ever been
/// recorded for this datadir (cursor is fully idle), keeping the
/// response slim for the common "no backfill needed" case.
pub fn get_index_info(
    backfill: Option<&Arc<BackfillHandle>>,
    address_enabled: bool,
    best_block_height: u32,
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
    bf.insert("pass".into(), json!(report.pass));
    bf.insert("cursor_height".into(), json!(report.cursor_height));
    bf.insert("snapshot_height".into(), json!(report.snapshot_height));
    bf.insert(
        "estimated_remaining_seconds".into(),
        json!(estimated_remaining_seconds),
    );
    address.insert("backfill".into(), Value::Object(bf));

    json!({ "address": Value::Object(address) })
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
/// the operator turning the index on. Idempotent on the wire: a call
/// while a backfill is already running returns the live state, not an
/// error. A call after Completed reports the cached completion.
pub fn backfill_index(
    backfill: Option<&Arc<BackfillHandle>>,
    cmd_tx: Option<&tokio::sync::mpsc::Sender<BackfillCommand>>,
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
        BackfillState::Running | BackfillState::Paused => Ok(json!({
            "started": false,
            "reason": "backfill already in progress",
            "state": cur.state.label(),
            "pass": cur.pass,
            "cursor_height": cur.cursor_height,
            "snapshot_height": cur.snapshot_height,
        })),
        BackfillState::Completed => Ok(json!({
            "started": false,
            "reason": "backfill already completed for this datadir",
            "state": cur.state.label(),
            "snapshot_height": cur.snapshot_height,
        })),
        BackfillState::Idle | BackfillState::Cancelled | BackfillState::Rejected => {
            // Reset pause/cancel flags so a prior cancel doesn't leak
            // into the new run. The supervisor will spawn a fresh
            // runner that calls `start()` to persist Running state.
            h.reset_flags();
            tx.try_send(BackfillCommand::Start).map_err(|e| {
                (
                    -32603,
                    format!("failed to dispatch backfill start: {}", e),
                )
            })?;
            Ok(json!({
                "started": true,
                "previous_state": cur.state.label(),
            }))
        }
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
