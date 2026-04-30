//! Operator-facing RPCs for the indexes family. M7 ships
//! `getindexinfo` and the four backfill control RPCs
//! (`backfillindex`, `pauseindex`, `resumeindex`, `cancelindex`).
//!
//! `getindexinfo` returns a wrapping shape (`{"address": {...},
//! ...}`) so future indexes (txindex, blockfilter) can join under
//! sibling keys without breaking consumers — see
//! `ADDRESS_INDEX.md` §"Operator RPCs / `getindexinfo`".

use std::sync::Arc;

use serde_json::{Value, json};

use crate::index::address::{BackfillHandle, render_status};

/// `getindexinfo` → `{"address": {...}, ...}`. Builds the per-index
/// `synced` / `state` / `progress_ratio` fields from the live
/// backfill cursor (or the idle defaults if no cursor exists yet).
pub fn get_index_info(
    backfill: Option<&Arc<BackfillHandle>>,
    address_enabled: bool,
) -> Value {
    let report = render_status(backfill.map(|h| h.as_ref()), address_enabled);
    json!({
        "address": {
            "synced": report.synced,
            "enabled": report.enabled,
            "state": report.state,
            "pass": report.pass,
            "cursor_height": report.cursor_height,
            "snapshot_height": report.snapshot_height,
            "started_at_unix": report.started_at_unix,
            "progress_ratio": report.progress_ratio,
        },
    })
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
