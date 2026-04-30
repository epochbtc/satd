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

pub fn pause_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    if let Some(h) = backfill {
        h.pause();
        Ok(json!({"paused": true, "state": h.cursor().state.label()}))
    } else {
        Err((-32603, "backfill handle not initialized".to_string()))
    }
}

pub fn resume_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    if let Some(h) = backfill {
        h.resume();
        Ok(json!({"resumed": true, "state": h.cursor().state.label()}))
    } else {
        Err((-32603, "backfill handle not initialized".to_string()))
    }
}

pub fn cancel_index(
    backfill: Option<&Arc<BackfillHandle>>,
    target: &str,
) -> Result<Value, (i32, String)> {
    if target != "address" {
        return Err((-8, format!("unknown index target '{}'", target)));
    }
    if let Some(h) = backfill {
        h.cancel();
        Ok(json!({"cancelled": true, "state": h.cursor().state.label()}))
    } else {
        Err((-32603, "backfill handle not initialized".to_string()))
    }
}
