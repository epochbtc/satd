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

    /// Progress toward the snapshot height. Single-pass walk: total work
    /// is `snapshot_height` blocks; `cursor_height` is the last height
    /// with a stamped row.
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

    #[test]
    fn progress_ratio_edges() {
        assert_eq!(BackfillCursor::idle().progress_ratio(), 0.0);
        let c = BackfillCursor {
            state: BackfillState::Running,
            cursor_height: 250,
            snapshot_height: 1000,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        };
        assert!((c.progress_ratio() - 0.25).abs() < 1e-9);
        let over = BackfillCursor {
            cursor_height: 5_000,
            snapshot_height: 1_000,
            ..c
        };
        assert_eq!(over.progress_ratio(), 1.0);
    }
}
