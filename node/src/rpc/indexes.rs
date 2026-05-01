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

use crate::index::address::{BackfillHandle, cursor::BackfillState, render_status};

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
/// address-history index. M7 scaffolding: returns the current state
/// so operators can confirm the index is wired; actual two-pass
/// execution lights up when AssumeUTXO lands and the snapshot
/// height is known.
pub fn backfill_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    match backfill {
        Some(h) => {
            // No-op for now: with AssumeUTXO not in the tree, every
            // block already populated the index from `connect_block`.
            // We expose the intent so the wire surface is stable.
            Ok(json!({
                "started": false,
                "reason": "AssumeUTXO is not in the tree; every block was already indexed at connect_block time. Backfill is a no-op for this datadir.",
                "state": h.cursor().state.label(),
            }))
        }
        None => Err((-32603, "backfill handle not initialized".to_string())),
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
