//! Persistent cursor for the deferred BIP 158 filter-index backfill.
//!
//! Mirrors the address-index cursor (`node-index/src/cursor.rs`) but
//! single-pass: there is no temp CF and no `pass` field — the runner
//! reads block + undo data directly per height to recover the spent
//! prev-output scripts (BIP 158 SCRIPT_FILTER input set).
//!
//! Stored in `CF_METADATA` so a `kill -9` mid-backfill can be resumed
//! cleanly on the next start. Each batch (1000 blocks) writes the new
//! filter rows + cursor advance in **one** RocksDB WriteBatch — atomicity
//! guarantees we never observe a half-advanced cursor inconsistent with
//! the rows we've persisted.
//!
//! Key shapes (all in CF_METADATA):
//! - `filterindex.backfill.state`            → 1 byte
//! - `filterindex.backfill.cursor_height`    → 4 bytes BE
//! - `filterindex.backfill.snapshot_height`  → 4 bytes BE
//! - `filterindex.backfill.started_at`       → 8 bytes BE (unix seconds)
//! - `filterindex.backfill.snapshot_hash`    → 32 bytes (anchor blockhash)
//! - `filterindex.backfill.last_error`       → UTF-8 (truncated)

use serde::{Deserialize, Serialize};

pub const META_KEY_STATE: &[u8] = b"filterindex.backfill.state";
pub const META_KEY_CURSOR_HEIGHT: &[u8] = b"filterindex.backfill.cursor_height";
pub const META_KEY_SNAPSHOT_HEIGHT: &[u8] = b"filterindex.backfill.snapshot_height";
pub const META_KEY_STARTED_AT: &[u8] = b"filterindex.backfill.started_at";
/// Active-chain anchor: hash of the block at `snapshot_height` at the
/// moment `start()` was called. The runner verifies on resume (and
/// periodically during the run) that this hash is still on the active
/// chain — if not, a reorg has invalidated the snapshot and the run
/// must abort with `ReorgInvalidated → Failed` rather than write rows
/// for blocks the chain no longer includes. 32 bytes raw.
pub const META_KEY_SNAPSHOT_HASH: &[u8] = b"filterindex.backfill.snapshot_hash";
/// Operator-readable error message persisted alongside `State::Failed`.
/// Cleared on the next state transition. UTF-8 string, bounded length
/// (truncated by the writer if pathological).
pub const META_KEY_LAST_ERROR: &[u8] = b"filterindex.backfill.last_error";

/// Lifecycle state of the backfill task. Persisted as a single byte
/// in metadata so a restart can pick up where it left off.
///
/// Wire-byte values match `node_index::cursor::BackfillState` so an
/// operator inspecting the raw metadata CF reads the same labels for
/// both index families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BackfillState {
    /// No backfill has ever been started for this datadir.
    Idle = 0,
    /// Backfill is running (or was running before a clean shutdown).
    Running = 1,
    /// Operator paused via `pauseindex`. Sticky across restart — the
    /// runner is not auto-respawned; operator must `resumeindex`.
    Paused = 2,
    /// Backfill finished successfully.
    Completed = 3,
    /// Operator cancelled via `cancelindex`.
    Cancelled = 4,
    /// Pre-flight rejection (e.g. insufficient disk). No persistent
    /// state to clean up.
    Rejected = 5,
    /// The runner exited with an unrecoverable error (missing block,
    /// reorg invalidation, missing undo data, storage error). The last
    /// error message is persisted in `META_KEY_LAST_ERROR`. Treated as
    /// a non-terminal recovery state by the RPC: a fresh
    /// `backfillindex` clears it and starts over.
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

/// Maximum length (bytes) of the persisted last-error message. Kept
/// short so a pathological producer can't bloat the metadata CF.
pub const LAST_ERROR_MAX_BYTES: usize = 1024;

/// Snapshot of the persisted backfill cursor for `getindexinfo`.
/// `last_error` is loaded out-of-band by the storage layer (since the
/// cursor is `Copy`); see `Store::read_filter_backfill_last_error`.
#[derive(Debug, Clone, Copy)]
pub struct BackfillCursor {
    pub state: BackfillState,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    /// Hash of the active-chain block at `snapshot_height` at
    /// `start()` time. All-zero on `Idle` (no run yet). Used on resume
    /// to detect reorgs that invalidated the original snapshot.
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

    /// Progress percent toward the snapshot height. Single-pass walk:
    /// total work is `snapshot_height` blocks; `cursor_height` is the
    /// last height that has a stamped row.
    pub fn progress_ratio(&self) -> f64 {
        if self.snapshot_height == 0 {
            return 0.0;
        }
        (self.cursor_height as f64 / self.snapshot_height as f64).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_byte_roundtrip() {
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
    fn test_state_unknown_byte_falls_back_to_idle() {
        assert_eq!(BackfillState::from_byte(0xff), BackfillState::Idle);
    }

    #[test]
    fn test_progress_ratio_no_snapshot_height_is_zero() {
        let c = BackfillCursor::idle();
        assert_eq!(c.progress_ratio(), 0.0);
    }

    #[test]
    fn test_progress_ratio_partway() {
        let c = BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 250,
            snapshot_height: 1000,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        };
        assert!((c.progress_ratio() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_progress_ratio_clamps_to_unit() {
        // Defensive — runner shouldn't allow this, but the helper must
        // not return >1.0 even if the persisted cursor went rogue.
        let c = BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 5_000,
            snapshot_height: 1_000,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        };
        assert_eq!(c.progress_ratio(), 1.0);
    }
}
