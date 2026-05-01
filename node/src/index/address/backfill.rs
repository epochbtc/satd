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
use crate::storage::{BackfillCursorWrite, Store, StoreBatch, StoreError, WriteMode};

#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    #[error("backfill already in progress (state: {0})")]
    AlreadyRunning(&'static str),
    #[error("backfill already completed for this datadir")]
    AlreadyCompleted,
    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: &'static str, to: &'static str },
    #[error("pre-flight: insufficient free disk ({have} bytes < {need} bytes required)")]
    InsufficientDisk { have: u64, need: u64 },
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("chain state: {0}")]
    Chain(String),
    #[error("cancelled by operator")]
    Cancelled,
    #[error("shutdown requested")]
    Shutdown,
    #[error("temp CF lookup miss for outpoint {0}: backfill data may be corrupt")]
    TempCfMiss(bitcoin::OutPoint),
    #[error("reorg invalidated the backfill snapshot at height {height}: {detail}")]
    ReorgInvalidated { height: u32, detail: String },
    #[error("address index is disabled (--addressindex=0); refusing to run backfill")]
    AddressIndexDisabled,
}

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
        // Initialize the in-memory pause flag from the persisted state
        // so a `Paused` cursor stays paused across restart. Without
        // this init, an operator who paused before shutdown would see
        // the runner auto-resume on next start (see review finding
        // #10 — sticky-paused contract).
        let paused_initial = matches!(initial.state, BackfillState::Paused);
        Self {
            inner: Arc::new(BackfillInner {
                cursor: Mutex::new(initial),
                paused: AtomicBool::new(paused_initial),
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    /// Snapshot the in-memory cursor for `getindexinfo`. Cheap;
    /// holds the mutex only long enough to clone.
    pub fn cursor(&self) -> BackfillCursor {
        *self.inner.cursor.lock().unwrap()
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

    /// Reset the pause/cancel flags. Called by the supervisor before
    /// spawning a fresh runner so an earlier `cancel`/`pause` doesn't
    /// leak across runs.
    pub fn reset_flags(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
        self.inner.cancelled.store(false, Ordering::SeqCst);
    }

    /// Persist a metadata-only cursor advance via a no-row StoreBatch.
    /// Used for state transitions (start, advance_to_pass_2, mark_*)
    /// where the cursor changes without a corresponding addr-CF write.
    /// Clears the persisted `last_error` blob — every transition out
    /// of `Failed` (or out of any state, for that matter) replaces the
    /// stale error context with a fresh empty slot.
    fn persist(&self, store: &dyn Store, new: BackfillCursor) -> Result<(), BackfillError> {
        let batch = StoreBatch {
            backfill_cursor_advance: Some(BackfillCursorWrite {
                state: new.state,
                pass: new.pass,
                cursor_height: new.cursor_height,
                snapshot_height: new.snapshot_height,
                started_at_unix: new.started_at_unix,
                snapshot_tip_hash: new.snapshot_tip_hash,
            }),
            ..Default::default()
        };
        // Force WriteMode::Normal for cursor transitions so a
        // BulkLoad-mode chain (mid-IBD) can't lose Completed/Failed/
        // Cancelled writes on a kill -9. Pairs with the runner's
        // per-batch Normal writes (review-2 #4 / review-3 #4).
        store.write_batch_mode(batch, WriteMode::Normal)?;
        // Best-effort clear; non-fatal if the underlying store doesn't
        // support it (in-memory test stores).
        let _ = store.write_backfill_last_error("");
        self.set_cursor(new);
        Ok(())
    }

    /// Begin a fresh backfill. Cursor transitions
    /// Idle/Cancelled/Rejected/Failed/Completed → Running(pass=1, h=0,
    /// snapshot_height). Errors if a backfill is already Running or
    /// Paused. `Failed` is treated as a non-terminal recovery state:
    /// a fresh start clears the persisted last-error and runs from
    /// scratch (the lenient-failed contract). The caller is expected
    /// to have created the temp CF first.
    pub fn start(
        &self,
        store: &dyn Store,
        snapshot_height: u32,
        snapshot_tip_hash: [u8; 32],
    ) -> Result<(), BackfillError> {
        let cur = self.cursor();
        match cur.state {
            BackfillState::Running => {
                return Err(BackfillError::AlreadyRunning("running"));
            }
            BackfillState::Paused => {
                return Err(BackfillError::AlreadyRunning("paused"));
            }
            BackfillState::Idle
            | BackfillState::Cancelled
            | BackfillState::Rejected
            | BackfillState::Failed
            | BackfillState::Completed => {}
        }
        let started_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Running,
                pass: 1,
                cursor_height: 0,
                snapshot_height,
                started_at_unix,
                snapshot_tip_hash,
            },
        )
    }

    /// Atomic pass-1 → pass-2 transition. Caller must have just persisted
    /// the final pass-1 row batch (cursor_height = snapshot_height).
    pub fn advance_to_pass_2(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if cur.state != BackfillState::Running || cur.pass != 1 {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "running pass=2",
            });
        }
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Running,
                pass: 2,
                cursor_height: 0,
                ..cur
            },
        )
    }

    /// Mark Completed. Caller drops the temp CF after this returns Ok.
    pub fn mark_completed(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if cur.state != BackfillState::Running {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "completed",
            });
        }
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Completed,
                ..cur
            },
        )
    }

    /// Mark Cancelled. Caller drops the temp CF after this returns Ok.
    pub fn mark_cancelled(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if !matches!(
            cur.state,
            BackfillState::Running | BackfillState::Paused
        ) {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "cancelled",
            });
        }
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Cancelled,
                ..cur
            },
        )
    }

    /// Mark Failed with a persisted operator-readable error message.
    /// Used by the runner when an unrecoverable error occurs (missing
    /// block, reorg invalidation, temp CF miss, storage error).
    /// `Failed` is non-terminal at the RPC layer: a fresh
    /// `backfillindex` clears it and starts over.
    ///
    /// Cursor positional fields (pass/cursor_height/snapshot_height)
    /// are preserved for diagnostics — operators may want to see how
    /// far the failed run got. The persisted last-error is written
    /// AFTER the cursor advance so a crash between the two doesn't
    /// leave a stale error attached to a non-Failed cursor.
    pub fn mark_failed(
        &self,
        store: &dyn Store,
        err_msg: &str,
    ) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if !matches!(
            cur.state,
            BackfillState::Running | BackfillState::Paused
        ) {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "failed",
            });
        }
        // Persist cursor first (this also clears any prior last-error
        // via `persist`'s blanket clear), then write the new one.
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Failed,
                ..cur
            },
        )?;
        // Best-effort: if the message can't be persisted (e.g. in-mem
        // store), the state still reflects Failed — operators just
        // won't get the error context.
        let _ = store.write_backfill_last_error(err_msg);
        Ok(())
    }

    /// Move Running→Paused for `getindexinfo` reporting consistency.
    /// The runner observes `is_paused()` between batches; this method
    /// also persists the state byte so a restart while paused stays
    /// paused. Idempotent if already Paused.
    pub fn mark_paused(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        match cur.state {
            BackfillState::Paused => Ok(()),
            BackfillState::Running => self.persist(
                store,
                BackfillCursor {
                    state: BackfillState::Paused,
                    ..cur
                },
            ),
            _ => Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "paused",
            }),
        }
    }

    /// Paused→Running on resume. Idempotent if already Running.
    pub fn mark_running(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        match cur.state {
            BackfillState::Running => Ok(()),
            BackfillState::Paused => self.persist(
                store,
                BackfillCursor {
                    state: BackfillState::Running,
                    ..cur
                },
            ),
            _ => Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "running",
            }),
        }
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
            snapshot_tip_hash: [0u8; 32],
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
            snapshot_tip_hash: [0u8; 32],
        };
        // Pass 2 at height 500 of a 1000-block snapshot = (1000+500)/2000 = 0.75.
        assert!((cursor.progress_ratio() - 0.75).abs() < 1e-9);
    }
}
