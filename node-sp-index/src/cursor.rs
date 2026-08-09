//! Persistent cursor for the deferred silent-payment-index backfill.
//!
//! Byte-compatible with the filter-index backfill conventions
//! (`node-filter-index/src/cursor.rs`): single-pass, no temp CF and no
//! `pass` field — the runner reads block + undo data directly per height
//! to recover the spent prev-output scripts BIP 352 input classification
//! needs. Stored in `CF_METADATA` so a `kill -9` mid-backfill resumes
//! cleanly. Each 1000-block batch writes the new rows + the cursor
//! advance in one RocksDB WriteBatch, so a half-advanced cursor
//! inconsistent with persisted rows is never observable.
//!
//! Key shapes (all in `CF_METADATA`):
//! - `spindex.backfill.state`            → 1 byte
//! - `spindex.backfill.cursor_height`    → 4 bytes BE
//! - `spindex.backfill.snapshot_height`  → 4 bytes BE
//! - `spindex.backfill.started_at`       → 8 bytes BE (unix seconds)
//! - `spindex.backfill.snapshot_hash`    → 32 bytes (anchor blockhash)
//! - `spindex.backfill.last_error`       → UTF-8 (truncated)
//! - `sp_index.complete`                 → 1 byte marker (backfill done /
//!   from-genesis sync caught up); the read trait's `is_complete()` gate.

use serde::{Deserialize, Serialize};

pub const META_KEY_STATE: &[u8] = b"spindex.backfill.state";
pub const META_KEY_CURSOR_HEIGHT: &[u8] = b"spindex.backfill.cursor_height";
pub const META_KEY_SNAPSHOT_HEIGHT: &[u8] = b"spindex.backfill.snapshot_height";
pub const META_KEY_STARTED_AT: &[u8] = b"spindex.backfill.started_at";
/// Active-chain anchor: hash of the block at `snapshot_height` at the
/// moment `start()` was called. The runner verifies on resume (and
/// periodically during the run) that this hash is still on the active
/// chain — if not, a reorg has invalidated the snapshot and the run must
/// abort rather than write rows for blocks the chain no longer includes.
pub const META_KEY_SNAPSHOT_HASH: &[u8] = b"spindex.backfill.snapshot_hash";
/// Operator-readable error message persisted alongside `State::Failed`.
pub const META_KEY_LAST_ERROR: &[u8] = b"spindex.backfill.last_error";
/// Completeness marker: index has no holes from taproot activation to the
/// snapshot/tip. Backing store for `SpIndex::is_complete()`.
pub const META_KEY_COMPLETE: &[u8] = b"sp_index.complete";

/// Maximum length (bytes) of the persisted last-error message.
pub const LAST_ERROR_MAX_BYTES: usize = 1024;

/// Lifecycle state of the backfill task. Persisted as a single byte in
/// metadata so a restart can pick up where it left off. Wire-byte values
/// match `node_filter_index::cursor::BackfillState` so an operator
/// inspecting the raw metadata CF reads the same labels across index
/// families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BackfillState {
    /// No backfill has ever been started for this datadir.
    Idle = 0,
    /// Backfill is running (or was running before a clean shutdown).
    Running = 1,
    /// Operator paused via `pauseindex`. Sticky across restart.
    Paused = 2,
    /// Backfill finished successfully.
    Completed = 3,
    /// Operator cancelled via `cancelindex`.
    Cancelled = 4,
    /// Pre-flight rejection (e.g. insufficient disk).
    Rejected = 5,
    /// The runner exited with an unrecoverable error (missing block/undo
    /// data, reorg invalidation, storage error). Last error is in
    /// `META_KEY_LAST_ERROR`. A fresh `backfillindex` clears and restarts.
    Failed = 6,
}

impl BackfillState {
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Running,
            2 => Self::Paused,
            3 => Self::Completed,
            4 => Self::Cancelled,
            5 => Self::Rejected,
            6 => Self::Failed,
            _ => Self::Idle,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

/// Snapshot of the persisted backfill cursor for `getindexinfo`.
/// `last_error` is loaded out-of-band by the storage layer (the cursor is
/// `Copy`).
#[derive(Debug, Clone, Copy)]
pub struct BackfillCursor {
    pub state: BackfillState,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    /// Hash of the active-chain block at `snapshot_height` at `start()`
    /// time. All-zero on `Idle`. Used on resume to detect reorgs that
    /// invalidated the original snapshot.
    pub snapshot_tip_hash: [u8; 32],
}

impl BackfillCursor {
    pub fn idle() -> Self {
        Self {
            state: BackfillState::Idle,
            cursor_height: 0,
            snapshot_height: 0,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        }
    }

    /// Progress toward the snapshot height. Single-pass walk over
    /// `[walk_start, snapshot_height]`, so total work is
    /// `snapshot_height - walk_start + 1` blocks, **not** `snapshot_height`:
    /// the walk begins at taproot activation because no block below it can
    /// carry a tweak row (§3.2). `cursor_height` is the last height with a
    /// stamped row.
    ///
    /// `walk_start` must be the same value the runner walks from
    /// (`node::index::silent_payments::walk_start` for the chain's
    /// network). Passing 0 measures from genesis and overstates progress on
    /// any chain whose taproot activation is above genesis. On mainnet that
    /// put the gauge at 0.738 from the *first* stamped block onward (a fresh
    /// cursor persists 0, so it read 0.0 until then and jumped), and left it
    /// unable to report below that floor for the rest of the run. The ETA
    /// derived from it was optimistic by a factor that grows as the walk
    /// gets shorter — roughly 4x over most of a mainnet run, far worse in
    /// the first percent.
    ///
    /// Returns 0.0 when there is nothing to walk: the idle cursor (no
    /// snapshot taken) and a chain that has not yet reached activation.
    pub fn progress_ratio(&self, walk_start: u32) -> f64 {
        if self.snapshot_height == 0 || self.snapshot_height < walk_start {
            return 0.0;
        }
        // Both ends inclusive, matching the runner's `walk_start..=snapshot`
        // loop: the span is `snapshot_height - walk_start + 1` blocks. That
        // matters at the edge — the runner's own guard is
        // `walk_start > snapshot_height`, so a snapshot sitting exactly ON
        // the walk start is one block of work that does get walked and
        // completed, not a zero-width span. Counting inclusively is what
        // keeps a completed cursor at exactly 1.0 for every span width.
        let total = (self.snapshot_height - walk_start) as f64 + 1.0;
        let done = if self.cursor_height < walk_start {
            // Fresh cursor: `start()` persists 0, which is below `walk_start`
            // on any chain with a non-genesis activation. Nothing stamped yet.
            0.0
        } else {
            (self.cursor_height - walk_start) as f64 + 1.0
        };
        (done / total).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_byte_roundtrip() {
        for s in [
            BackfillState::Idle,
            BackfillState::Running,
            BackfillState::Paused,
            BackfillState::Completed,
            BackfillState::Cancelled,
            BackfillState::Rejected,
            BackfillState::Failed,
        ] {
            assert_eq!(BackfillState::from_byte(s.as_byte()), s);
        }
    }

    #[test]
    fn state_unknown_byte_falls_back_to_idle() {
        assert_eq!(BackfillState::from_byte(0xff), BackfillState::Idle);
    }

    #[test]
    fn state_bytes_match_filter_index_labels() {
        // Cross-family stability: an operator reads the same byte→label
        // mapping in the metadata CF for both index families.
        assert_eq!(BackfillState::Idle.as_byte(), 0);
        assert_eq!(BackfillState::Running.as_byte(), 1);
        assert_eq!(BackfillState::Completed.as_byte(), 3);
        assert_eq!(BackfillState::Failed.as_byte(), 6);
    }

    fn running_at(cursor_height: u32, snapshot_height: u32) -> BackfillCursor {
        BackfillCursor {
            state: BackfillState::Running,
            cursor_height,
            snapshot_height,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        }
    }

    #[test]
    fn progress_ratio_edges() {
        assert_eq!(BackfillCursor::idle().progress_ratio(1), 0.0);
        // walk_start is floored at 1 in production, and with an inclusive
        // span that makes the arithmetic land on the intuitive value:
        // heights 1..=1000 is 1000 blocks, done through 250 is 250 of them.
        let c = running_at(250, 1000);
        assert!((c.progress_ratio(1) - 0.25).abs() < 1e-9);
        let over = BackfillCursor {
            cursor_height: 5_000,
            ..c
        };
        assert_eq!(over.progress_ratio(1), 1.0);
    }

    /// The regression this function exists for: with taproot activation as
    /// the origin, mainnet must open at 0.0 and not at `activation / tip`.
    #[test]
    fn progress_ratio_measures_from_walk_start_not_genesis() {
        const ACTIVATION: u32 = 709_632;
        const TIP: u32 = 961_595;

        // The cursor observed on the dogfood mainnet node moments after
        // the backfill started: 231 blocks past activation, i.e. 0.09% of
        // the 251_964-block walk.
        let fresh = running_at(709_863, TIP);
        let ratio = fresh.progress_ratio(ACTIVATION);
        assert!(
            ratio < 0.01,
            "a just-started mainnet backfill must read ~0.0, got {ratio}"
        );
        // Measuring from genesis instead is what produced the 0.738 floor —
        // asserted on the same cursor so a regression reads as intent rather
        // than a bare number change.
        assert!(
            (fresh.progress_ratio(0) - 0.738_214).abs() < 1e-5,
            "genesis-origin value should reproduce the reported 0.738"
        );

        // Halfway through the *eligible* span, not through the chain.
        let half = running_at(ACTIVATION + (TIP - ACTIVATION) / 2, TIP);
        assert!((half.progress_ratio(ACTIVATION) - 0.5).abs() < 1e-5);

        // Completion is exactly 1.0 — the cursor lands on the snapshot.
        assert_eq!(running_at(TIP, TIP).progress_ratio(ACTIVATION), 1.0);
    }

    #[test]
    fn progress_ratio_nothing_to_walk_is_zero() {
        // Idle cursor: no snapshot taken.
        assert_eq!(BackfillCursor::idle().progress_ratio(709_632), 0.0);
        // Chain not yet past activation — the runner returns without walking
        // (its guard is `walk_start > snapshot_height`).
        assert_eq!(running_at(0, 500).progress_ratio(709_632), 0.0);
    }

    /// A snapshot sitting exactly on the walk start is NOT a zero-width span:
    /// the runner's guard is `>`, so it walks that one block and completes.
    /// Reporting 0.0 for a completed backfill is the same fencepost error
    /// this function was fixed for, one step further out.
    #[test]
    fn progress_ratio_single_block_span_completes_at_one() {
        let r = running_at(1_000, 1_000).progress_ratio(1_000);
        assert!(r.is_finite(), "must not divide by zero");
        assert_eq!(r, 1.0, "one-block walk, cursor on the snapshot => complete");

        // Same span before that block is stamped (fresh cursor persists 0).
        assert_eq!(running_at(0, 1_000).progress_ratio(1_000), 0.0);
    }

    #[test]
    fn progress_ratio_cursor_below_walk_start_floors_at_zero() {
        // Shouldn't arise (the runner never persists a cursor below the
        // walk start) but must not underflow the u32 subtraction if it does.
        assert_eq!(running_at(100, 1_000).progress_ratio(500), 0.0);
    }
}
