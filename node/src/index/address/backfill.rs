//! Deferred address-history backfill — the AssumeUTXO mitigation
//! described in `ADDRESS_INDEX.md` §"Backfill". Two-pass walk over
//! every block from genesis to the snapshot height, populating the
//! `addr_funding` / `addr_spending` CFs that AssumeUTXO bypassed.
//!
//! Status: scaffolding (M7). The state machine, persistent cursor,
//! and operator RPCs are wired so the feature is testable and
//! observable. Actual two-pass execution lights up when AssumeUTXO
//! itself lands — running it without AssumeUTXO is a no-op since
//! every block already has its rows from `connect_block`.
//!
//! Pass 1 (genesis → snapshot_height): for each block, write
//! `addr_funding` rows and write `(prev_outpoint) → scripthash` to
//! a temp CF (`addr_backfill_outpoint_to_scripthash`).
//!
//! Pass 2 (genesis → snapshot_height): for each input, look up
//! scripthash in the temp CF and write the matching `addr_spending`
//! row.
//!
//! On Completed: drop the temp CF; clear cursor.
//!
//! Concurrency: live `connect_block` writes ranges > current_tip;
//! the backfill writes ranges ≤ snapshot_height. Disjoint key
//! spaces — RocksDB MVCC handles concurrent readers, concurrent
//! disjoint-key writes are safe.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::index::address::cursor::{BackfillCursor, BackfillState};

/// Shared handle so RPCs can drive the task without a tokio
/// `oneshot` per command. Each control RPC sets a flag; the task
/// observes it on its next batch boundary.
#[derive(Clone)]
pub struct BackfillHandle {
    inner: Arc<BackfillInner>,
}

struct BackfillInner {
    /// Persistent cursor as last-known to the in-memory shared state.
    /// Updated atomically by the running task; read by RPCs.
    cursor: Mutex<BackfillCursor>,
    /// Operator-set pause request. The task checks it on each batch.
    paused: AtomicBool,
    /// Operator-set cancel request. The task checks it on each batch.
    cancelled: AtomicBool,
}

impl BackfillHandle {
    pub fn new(initial: BackfillCursor) -> Self {
        Self {
            inner: Arc::new(BackfillInner {
                cursor: Mutex::new(initial),
                paused: AtomicBool::new(false),
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    /// Snapshot the in-memory cursor for `getindexinfo`. Cheap;
    /// holds the mutex only long enough to clone.
    pub fn cursor(&self) -> BackfillCursor {
        self.inner.cursor.lock().unwrap().clone()
    }

    /// Update the in-memory cursor. Called by the running task on
    /// each batch boundary, and by `main.rs` on startup when
    /// re-reading persisted state.
    pub fn set_cursor(&self, cursor: BackfillCursor) {
        *self.inner.cursor.lock().unwrap() = cursor;
    }

    /// Operator request: pause at the next batch boundary. Idempotent.
    pub fn pause(&self) {
        self.inner.paused.store(true, Ordering::SeqCst);
    }

    /// Operator request: resume paused backfill. The task is expected
    /// to pick this up between sleep cycles.
    pub fn resume(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
    }

    /// Operator request: cancel at the next batch boundary. The task
    /// flushes its cursor and exits; the temp CF is dropped.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.inner.paused.load(Ordering::SeqCst)
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }
}

/// Pre-flight: refuse to start a backfill if free disk is below this
/// threshold. The temp CF can grow to ~56 GB on mainnet; require
/// 80 GB headroom so the disk doesn't fill mid-backfill.
pub const PREFLIGHT_REQUIRED_FREE_BYTES: u64 = 80 * 1_073_741_824;

/// Build the snapshot reported by `getindexinfo`. Folds the live
/// cursor + AssumeUTXO availability into a single struct that the
/// RPC handler json-renders. Used by both the operator-RPC and (in
/// future) the Electrum/Esplora `serverinfo` surface.
pub fn render_status(handle: Option<&BackfillHandle>, address_enabled: bool) -> StatusReport {
    let cursor = handle.map(|h| h.cursor()).unwrap_or_else(BackfillCursor::idle);
    let synced = matches!(
        cursor.state,
        BackfillState::Idle | BackfillState::Completed
    ) && address_enabled;
    StatusReport {
        synced,
        enabled: address_enabled,
        state: cursor.state.label().to_string(),
        pass: cursor.pass,
        cursor_height: cursor.cursor_height,
        snapshot_height: cursor.snapshot_height,
        started_at_unix: cursor.started_at_unix,
        progress_ratio: cursor.progress_ratio(),
    }
}

/// Serializable shape returned by `getindexinfo` under the `address`
/// key. The wrapping envelope (`{"address": …, "txindex": …}`) is
/// constructed in `rpc/indexes.rs` per `ADDRESS_INDEX.md` §"RPC".
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusReport {
    pub synced: bool,
    pub enabled: bool,
    pub state: String,
    pub pass: u8,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    pub progress_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backfill_status_idle_when_no_handle() {
        let report = render_status(None, true);
        assert_eq!(report.state, "idle");
        assert_eq!(report.cursor_height, 0);
        assert_eq!(report.snapshot_height, 0);
        assert_eq!(report.progress_ratio, 0.0);
        assert!(report.synced, "idle + enabled = synced");
    }

    #[test]
    fn test_backfill_status_disabled_not_synced() {
        let report = render_status(None, false);
        assert!(!report.synced);
        assert!(!report.enabled);
    }

    #[test]
    fn test_backfill_handle_pause_resume_cancel_flags() {
        let h = BackfillHandle::new(BackfillCursor::idle());
        assert!(!h.is_paused());
        assert!(!h.is_cancelled());

        h.pause();
        assert!(h.is_paused());

        h.resume();
        assert!(!h.is_paused());

        h.cancel();
        assert!(h.is_cancelled());
    }

    #[test]
    fn test_backfill_progress_pass1() {
        let cursor = BackfillCursor {
            state: BackfillState::Running,
            pass: 1,
            cursor_height: 100,
            snapshot_height: 1000,
            started_at_unix: 0,
        };
        // Pass 1 at height 100 of a 1000-block snapshot = 100/2000 = 0.05.
        assert!((cursor.progress_ratio() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn test_backfill_progress_pass2() {
        let cursor = BackfillCursor {
            state: BackfillState::Running,
            pass: 2,
            cursor_height: 500,
            snapshot_height: 1000,
            started_at_unix: 0,
        };
        // Pass 2 at height 500 of a 1000-block snapshot = (1000+500)/2000 = 0.75.
        assert!((cursor.progress_ratio() - 0.75).abs() < 1e-9);
    }
}
