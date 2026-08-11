//! Deferred BIP 352 silent-payment-index backfill — runtime state
//! machine and operator-facing handle.
//!
//! Single-pass walk over every block from **taproot activation** to the
//! snapshot height taken at task start, populating `cf_sp_tweaks`. Below
//! taproot activation no BIP 352 output can exist (§3.2), so the walk
//! starts there rather than at genesis. Like the filter-index backfill
//! (and unlike the address-index one) it needs no temp CF: the runner
//! reads `UndoData` directly to recover the spent prev-output scripts BIP
//! 352 input classification requires, so it is a single forward walk.
//!
//! Unlike the filter index, SP tweak rows do **not** chain — each row is
//! self-authenticating (it embeds the hash of the block it describes) and
//! independent of its neighbours. So there is no tail-catch-up phase: the
//! rows live `connect_block` emitted for heights above the snapshot while
//! the backfill was running are already correct and complete.
//!
//! Concurrency: live `connect_block` writes rows for heights >
//! current_tip; the backfill writes rows for heights ≤ snapshot_height.
//! Disjoint key spaces — RocksDB MVCC handles concurrent readers, and
//! concurrent disjoint-key writes are safe. Same property the filter /
//! address backfills rely on.

use parking_lot::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use node_sp_index::cursor::{BackfillCursor, BackfillState};

use crate::index::stint::{StintGuard, StintMeter};
use crate::storage::{SpBackfillCursorWrite, Store, StoreBatch, StoreError, WriteMode};

#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    #[error("SP-index backfill already in progress (state: {0})")]
    AlreadyRunning(&'static str),
    #[error("SP-index backfill already completed for this datadir")]
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
    #[error("tweak emit at height {height}: {detail}")]
    Emit { height: u32, detail: String },
    #[error("cancelled by operator")]
    Cancelled,
    #[error("shutdown requested")]
    Shutdown,
    #[error(
        "missing undo data for block at height {0}; \
             cannot reconstruct prev-output scripts for tweak classification"
    )]
    MissingUndo(u32),
    #[error("reorg invalidated the backfill snapshot at height {height}: {detail}")]
    ReorgInvalidated { height: u32, detail: String },
    #[error(
        "silent-payment index is disabled (--silentpaymentindex=0); \
             refusing to run backfill"
    )]
    SilentPaymentIndexDisabled,
}

/// Shared handle so RPCs can drive the task without a tokio `oneshot`
/// per command. Each control RPC sets a flag; the task observes it on its
/// next batch boundary. Mirrors `crate::index::filter::BackfillHandle`
/// exactly except for the namespace.
#[derive(Clone)]
pub struct BackfillHandle {
    inner: Arc<BackfillInner>,
}

struct BackfillInner {
    cursor: Mutex<BackfillCursor>,
    paused: AtomicBool,
    cancelled: AtomicBool,
    /// Rate meter for `estimated_remaining_seconds`. In-memory only, and
    /// anchored by the runner rather than by `start()`, so idle time
    /// (paused, or the daemon simply not running) is never extrapolated
    /// as work — see `crate::index::stint` and #546.
    stint: Arc<StintMeter>,
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
                stint: Arc::new(StintMeter::new()),
            }),
        }
    }

    /// Anchor a working stint at `ratio_now`. The returned guard clears
    /// the anchor on drop, so no runner exit path — including an
    /// unwinding panic — can leave the meter aging while nothing walks.
    pub fn begin_stint(&self, ratio_now: f64) -> StintGuard {
        StintGuard::new(self.inner.stint.clone(), ratio_now)
    }

    /// Re-anchor after a pause. Discards the pre-pause stint so the
    /// paused span is not counted as working time.
    pub fn reanchor_stint(&self, ratio_now: f64) {
        self.inner.stint.begin(ratio_now);
    }

    /// Stop the clock while paused. Idempotent.
    pub fn end_stint(&self) {
        self.inner.stint.end();
    }

    /// Seconds of work remaining at the rate measured over the current
    /// stint; `None` when no runner is walking or the stint is too young
    /// to have measured anything.
    pub fn estimated_remaining_secs(&self, ratio_now: f64) -> Option<u64> {
        self.inner.stint.estimate_remaining_secs(ratio_now)
    }

    pub fn cursor(&self) -> BackfillCursor {
        *self.inner.cursor.lock()
    }

    pub fn set_cursor(&self, cursor: BackfillCursor) {
        *self.inner.cursor.lock() = cursor;
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
            sp_backfill_cursor_advance: Some(SpBackfillCursorWrite {
                state: new.state,
                cursor_height: new.cursor_height,
                snapshot_height: new.snapshot_height,
                started_at_unix: new.started_at_unix,
                snapshot_tip_hash: new.snapshot_tip_hash,
            }),
            ..Default::default()
        };
        // Force WriteMode::Normal for cursor transitions so a BulkLoad-mode
        // chain (mid-IBD) can't lose Completed/Failed/Cancelled writes on
        // a kill -9.
        store.write_batch_mode(batch, WriteMode::Normal)?;
        // Best-effort clear of last_error on every transition; this keeps
        // stale error context from leaking past a fresh start.
        let _ = store.write_sp_backfill_last_error("");
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

    /// Mark Completed. Stamps the `sp_index.complete` marker before
    /// advancing the cursor so a crash between the two replays
    /// idempotently on next start (see the filter-index `mark_completed`
    /// for the same ordering rationale).
    pub fn mark_completed(&self, store: &dyn Store) -> Result<(), BackfillError> {
        let cur = self.cursor();
        if cur.state != BackfillState::Running {
            return Err(BackfillError::InvalidTransition {
                from: cur.state.label(),
                to: "completed",
            });
        }
        store.mark_silent_payment_index_complete()?;
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
        let _ = store.write_sp_backfill_last_error(err_msg);
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
/// threshold. SP tweak rows at mainnet tip total ~3.9 GB; require 6 GB
/// headroom to absorb compaction churn and continued IBD writes.
pub const PREFLIGHT_REQUIRED_FREE_BYTES: u64 = 6 * 1_073_741_824;

/// Build the snapshot reported by `getindexinfo`'s `silent payment index`
/// sibling. Same shape as the filter-index `render_status`, except that
/// progress is measured from `walk_start` (taproot activation) rather than
/// from genesis — the filter index walks the whole chain, this one does
/// not. Pass `super::walk_start(network)`.
pub fn render_status(
    handle: Option<&BackfillHandle>,
    sp_enabled: bool,
    sp_complete: bool,
    walk_start: u32,
) -> StatusReport {
    let cursor = handle
        .map(|h| h.cursor())
        .unwrap_or_else(BackfillCursor::idle);
    // `synced` is true when the index is enabled AND the on-disk
    // completeness marker is set AND no backfill is mid-flight. Same
    // shape as filter-index status reporting.
    let bf_quiet = matches!(cursor.state, BackfillState::Idle | BackfillState::Completed);
    let synced = sp_enabled && sp_complete && bf_quiet;
    let progress_ratio = cursor.progress_ratio(walk_start);
    StatusReport {
        synced,
        enabled: sp_enabled,
        state: cursor.state.label().to_string(),
        cursor_height: cursor.cursor_height,
        snapshot_height: cursor.snapshot_height,
        started_at_unix: cursor.started_at_unix,
        progress_ratio,
        estimated_remaining_seconds: estimate_remaining_seconds(
            handle,
            sp_enabled,
            &cursor,
            progress_ratio,
        ),
    }
}

/// ETA for the `getindexinfo` sibling, in seconds; 0 means "no estimate".
///
/// Two independent gates, both required. The state/enabled gate (#532)
/// keeps a paused, failed or cancelled cursor from serving a number at
/// all — its `progress_ratio` is frozen, so anything derived from it ages
/// without bound. The stint gate (#546) is what makes the number itself
/// mean something: it is measured over the span the runner has actually
/// been walking, so a resume after a pause, or a restart after downtime,
/// re-measures instead of extrapolating the idle time.
fn estimate_remaining_seconds(
    handle: Option<&BackfillHandle>,
    sp_enabled: bool,
    cursor: &BackfillCursor,
    progress_ratio: f64,
) -> u64 {
    if !sp_enabled || cursor.state != BackfillState::Running {
        return 0;
    }
    handle
        .and_then(|h| h.estimated_remaining_secs(progress_ratio))
        .unwrap_or(0)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusReport {
    pub synced: bool,
    pub enabled: bool,
    pub state: String,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    /// When the backfill was *first* started, carried forward across
    /// pause/resume/restart. Reported for operator context only — the ETA
    /// deliberately does not derive from it (#546).
    pub started_at_unix: u64,
    pub progress_ratio: f64,
    /// Seconds of work remaining at the rate measured over the runner's
    /// current stint; 0 when no estimate can be justified.
    pub estimated_remaining_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_idle_when_no_handle_and_complete() {
        let report = render_status(None, true, true, 1);
        assert!(report.synced);
        assert!(report.enabled);
        assert_eq!(report.state, "idle");
    }

    #[test]
    fn status_disabled_not_synced() {
        let report = render_status(None, false, true, 1);
        assert!(!report.synced);
        assert!(!report.enabled);
    }

    #[test]
    fn status_incomplete_not_synced() {
        let report = render_status(None, true, false, 1);
        assert!(!report.synced);
        assert!(report.enabled);
    }

    #[test]
    fn status_running_not_synced_even_when_marker_true() {
        let h = BackfillHandle::new(BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 100,
            snapshot_height: 1000,
            started_at_unix: 1,
            snapshot_tip_hash: [0u8; 32],
        });
        let report = render_status(Some(&h), true, true, 1);
        assert!(!report.synced);
    }

    #[test]
    fn handle_pause_resume_cancel_flags() {
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
    fn handle_paused_initial_state_initializes_atomic() {
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
    fn progress_ratio_partway() {
        let h = BackfillHandle::new(BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 250,
            snapshot_height: 1000,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        });
        let report = render_status(Some(&h), true, false, 1);
        assert!((report.progress_ratio - 0.25).abs() < 1e-9);
    }

    fn running_at(cursor_height: u32, snapshot_height: u32) -> BackfillCursor {
        BackfillCursor {
            state: BackfillState::Running,
            cursor_height,
            snapshot_height,
            // Deliberately ancient: an hour into 1970. The whole point of
            // #546 is that this field no longer feeds the ETA, so a
            // reintroduction of the old formula would show up here as an
            // estimate measured in decades.
            started_at_unix: 3600,
            snapshot_tip_hash: [0u8; 32],
        }
    }

    /// The ETA comes from the stint the runner is in, not from
    /// `started_at_unix`.
    #[test]
    fn eta_is_measured_over_the_runners_stint() {
        let h = BackfillHandle::new(running_at(250, 1000));
        // No runner walking yet: nothing to estimate from.
        assert_eq!(
            render_status(Some(&h), true, false, 1).estimated_remaining_seconds,
            0
        );

        // A runner that started an hour ago at 5% and is now at 25%: 0.20
        // of the walk per hour, 0.75 left => ~3h45m.
        h.inner
            .stint
            .begin_backdated(0.05, std::time::Duration::from_secs(3600));
        let eta = render_status(Some(&h), true, false, 1).estimated_remaining_seconds;
        assert!(
            (13_300..=13_700).contains(&eta),
            "expected ~13500s, got {eta}"
        );
    }

    /// The regression guard from #532, kept: a backfill that is not
    /// running reports no ETA even if a stint anchor is somehow still
    /// around. `progress_ratio` freezes in these states, so anything
    /// derived from it ages without bound.
    #[test]
    fn eta_is_zero_for_non_running_states() {
        for state in [
            BackfillState::Failed,
            BackfillState::Paused,
            BackfillState::Cancelled,
            BackfillState::Completed,
            BackfillState::Idle,
            BackfillState::Rejected,
        ] {
            let h = BackfillHandle::new(BackfillCursor {
                state,
                ..running_at(250, 1000)
            });
            h.inner
                .stint
                .begin_backdated(0.05, std::time::Duration::from_secs(3600));
            assert_eq!(
                render_status(Some(&h), true, false, 1).estimated_remaining_seconds,
                0,
                "state {:?} must not report an ETA",
                state.label()
            );
        }
    }

    /// A disabled index reports no ETA regardless of cursor state — the
    /// runner refuses to run at all, so there is nothing to estimate.
    #[test]
    fn eta_is_zero_when_the_index_is_disabled() {
        let h = BackfillHandle::new(running_at(250, 1000));
        h.inner
            .stint
            .begin_backdated(0.05, std::time::Duration::from_secs(3600));
        assert_eq!(
            render_status(Some(&h), false, false, 1).estimated_remaining_seconds,
            0
        );
    }

    /// `render_status` must carry the walk-start offset through to the
    /// report, not just to the cursor: the reported ratio is what feeds the
    /// `getindexinfo` ETA and the Prometheus gauge.
    #[test]
    fn progress_ratio_reported_from_walk_start_on_mainnet_shape() {
        let h = BackfillHandle::new(BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 709_863,
            snapshot_height: 961_595,
            started_at_unix: 1,
            snapshot_tip_hash: [0u8; 32],
        });
        let report = render_status(Some(&h), true, false, 709_632);
        assert!(
            report.progress_ratio < 0.01,
            "231 blocks past activation is ~0% of the walk, got {}",
            report.progress_ratio
        );
    }
}
