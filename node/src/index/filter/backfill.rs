//! Deferred BIP 158 filter-index backfill — runtime state machine
//! and operator-facing handle.
//!
//! Single-pass walk over every block from genesis to the snapshot
//! height taken at task start, populating `cf_filter` and
//! `cf_filter_header`. Unlike the address-index backfill (which needs
//! a temp CF to resolve prev-output scripthashes for spending rows),
//! the filter backfill reads `UndoData` directly to recover the spent
//! prev-output scripts the BIP 158 SCRIPT_FILTER input set requires.
//! No temp CF, no second pass.
//!
//! Concurrency: live `connect_block` writes ranges > current_tip; the
//! backfill writes ranges ≤ snapshot_height. Disjoint key spaces —
//! RocksDB MVCC handles concurrent readers, concurrent disjoint-key
//! writes are safe. Mirrors the same property the address-index
//! backfill relies on (`ADDRESS_INDEX.md` §"Concurrency").

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use node_filter_index::cursor::{BackfillCursor, BackfillState};

use crate::storage::{FilterBackfillCursorWrite, Store, StoreBatch, StoreError, WriteMode};

#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    #[error("filter backfill already in progress (state: {0})")]
    AlreadyRunning(&'static str),
    #[error("filter backfill already completed for this datadir")]
    AlreadyCompleted,
    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("chain state: {0}")]
    Chain(String),
    #[error("cancelled by operator")]
    Cancelled,
    #[error("shutdown requested")]
    Shutdown,
    #[error(
        "missing undo data for block at height {0}; \
             cannot reconstruct prev-output scripts for filter"
    )]
    MissingUndo(u32),
    #[error("reorg invalidated the backfill snapshot at height {height}: {detail}")]
    ReorgInvalidated { height: u32, detail: String },
    #[error(
        "block filter index is disabled (--blockfilterindex=0); \
             refusing to run backfill"
    )]
    FilterIndexDisabled,
}

/// Shared handle so RPCs can drive the task without a tokio
/// `oneshot` per command. Each control RPC sets a flag; the task
/// observes it on its next batch boundary. Mirrors
/// `crate::index::address::BackfillHandle` exactly except for the
/// single-pass cursor shape and the namespace.
#[derive(Clone)]
pub struct BackfillHandle {
    inner: Arc<BackfillInner>,
}

struct BackfillInner {
    cursor: Mutex<BackfillCursor>,
    paused: AtomicBool,
    cancelled: AtomicBool,
}

impl BackfillHandle {
    pub fn new(initial: BackfillCursor) -> Self {
        // Initialize the in-memory pause flag from persisted state so a
        // `Paused` cursor stays paused across restart.
        let paused_initial = matches!(initial.state, BackfillState::Paused);
        Self {
            inner: Arc::new(BackfillInner {
                cursor: Mutex::new(initial),
                paused: AtomicBool::new(paused_initial),
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    pub fn cursor(&self) -> BackfillCursor {
        *self.inner.cursor.lock().unwrap()
    }

    pub fn set_cursor(&self, cursor: BackfillCursor) {
        *self.inner.cursor.lock().unwrap() = cursor;
    }

    pub fn pause(&self) {
        self.inner.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
    }

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

    fn persist(&self, store: &dyn Store, new: BackfillCursor) -> Result<(), BackfillError> {
        let batch = StoreBatch {
            filter_backfill_cursor_advance: Some(FilterBackfillCursorWrite {
                state: new.state,
                cursor_height: new.cursor_height,
                snapshot_height: new.snapshot_height,
                started_at_unix: new.started_at_unix,
                snapshot_tip_hash: new.snapshot_tip_hash,
            }),
            ..Default::default()
        };
        // Force WriteMode::Normal for cursor transitions so a
        // BulkLoad-mode chain (mid-IBD) can't lose Completed/Failed/
        // Cancelled writes on a kill -9.
        store.write_batch_mode(batch, WriteMode::Normal)?;
        // Best-effort clear of last_error on every transition; this
        // keeps stale error context from leaking past a fresh start.
        let _ = store.write_filter_backfill_last_error("");
        self.set_cursor(new);
        Ok(())
    }

    /// Begin a fresh backfill. Cursor transitions
    /// Idle/Cancelled/Rejected/Failed/Completed → Running.
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
                cursor_height: 0,
                snapshot_height,
                started_at_unix,
                snapshot_tip_hash,
            },
        )
    }

    /// Mark Completed. Stamps the `block_filter_index.complete` marker
    /// before advancing the cursor so a crash between the two replays
    /// idempotently on next start (see address-index `mark_completed`
    /// for the same ordering rationale).
    pub fn mark_completed(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if cur.state != BackfillState::Running {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "completed",
            });
        }
        store.mark_block_filter_index_complete()?;
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Completed,
                ..cur
            },
        )?;
        Ok(())
    }

    pub fn mark_cancelled(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if !matches!(cur.state, BackfillState::Running | BackfillState::Paused) {
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
    pub fn mark_failed(&self, store: &dyn Store, err_msg: &str) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if !matches!(cur.state, BackfillState::Running | BackfillState::Paused) {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "failed",
            });
        }
        self.persist(
            store,
            BackfillCursor {
                state: BackfillState::Failed,
                ..cur
            },
        )?;
        let _ = store.write_filter_backfill_last_error(err_msg);
        Ok(())
    }

    /// Move Running→Paused. Idempotent if already Paused.
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
/// threshold. Filter blobs at mainnet tip total ~6 GB; require 10 GB
/// headroom to absorb compaction churn and continued IBD writes.
pub const PREFLIGHT_REQUIRED_FREE_BYTES: u64 = 10 * 1_073_741_824;

/// Build the snapshot reported by `getindexinfo`'s `basic block filter
/// index` sibling. Same shape as the address-index `render_status`,
/// minus the `pass` field that the single-pass walk doesn't need.
pub fn render_status(
    handle: Option<&BackfillHandle>,
    filter_enabled: bool,
    filter_complete: bool,
) -> StatusReport {
    let cursor = handle
        .map(|h| h.cursor())
        .unwrap_or_else(BackfillCursor::idle);
    // `synced` is true when the index is enabled AND the on-disk
    // completeness marker is set AND no backfill is mid-flight. Same
    // shape as address-index status reporting.
    let bf_quiet = matches!(cursor.state, BackfillState::Idle | BackfillState::Completed);
    let synced = filter_enabled && filter_complete && bf_quiet;
    StatusReport {
        synced,
        enabled: filter_enabled,
        state: cursor.state.label().to_string(),
        cursor_height: cursor.cursor_height,
        snapshot_height: cursor.snapshot_height,
        started_at_unix: cursor.started_at_unix,
        progress_ratio: cursor.progress_ratio(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusReport {
    pub synced: bool,
    pub enabled: bool,
    pub state: String,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    pub progress_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_idle_when_no_handle_and_complete() {
        let report = render_status(None, true, true);
        assert!(report.synced);
        assert!(report.enabled);
        assert_eq!(report.state, "idle");
    }

    #[test]
    fn test_status_disabled_not_synced() {
        let report = render_status(None, false, true);
        assert!(!report.synced);
        assert!(!report.enabled);
    }

    #[test]
    fn test_status_incomplete_not_synced() {
        let report = render_status(None, true, false);
        assert!(!report.synced);
        assert!(report.enabled);
    }

    #[test]
    fn test_status_running_not_synced_even_when_marker_true() {
        let h = BackfillHandle::new(BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 100,
            snapshot_height: 1000,
            started_at_unix: 1,
            snapshot_tip_hash: [0u8; 32],
        });
        let report = render_status(Some(&h), true, true);
        assert!(!report.synced);
    }

    #[test]
    fn test_handle_pause_resume_cancel_flags() {
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
    fn test_handle_paused_initial_state_initializes_atomic() {
        let cur = BackfillCursor {
            state: BackfillState::Paused,
            cursor_height: 50,
            snapshot_height: 500,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        };
        let h = BackfillHandle::new(cur);
        assert!(
            h.is_paused(),
            "Paused cursor must initialize the atomic to true"
        );
    }

    #[test]
    fn test_progress_ratio_partway() {
        let h = BackfillHandle::new(BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 250,
            snapshot_height: 1000,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        });
        let report = render_status(Some(&h), true, false);
        assert!((report.progress_ratio - 0.25).abs() < 1e-9);
    }
}
