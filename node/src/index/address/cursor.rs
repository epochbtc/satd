//! Persistent cursor for the deferred address-index backfill.
//!
//! Stored in `CF_METADATA` so a `kill -9` mid-backfill can be
//! resumed cleanly on the next start. Each batch (1000 blocks)
//! writes the new rows + cursor advance in **one** RocksDB
//! WriteBatch — atomicity guarantees we never observe a "half-
//! advanced cursor" inconsistent with the rows we've persisted.
//!
//! Key shapes (all in CF_METADATA):
//! - `addrindex.backfill.pass`            → 1 byte (1 or 2)
//! - `addrindex.backfill.cursor_height`   → 4 bytes BE
//! - `addrindex.backfill.snapshot_height` → 4 bytes BE
//! - `addrindex.backfill.started_at`      → 8 bytes BE (unix seconds)

use serde::{Deserialize, Serialize};

pub const META_KEY_PASS: &[u8] = b"addrindex.backfill.pass";
pub const META_KEY_CURSOR_HEIGHT: &[u8] = b"addrindex.backfill.cursor_height";
pub const META_KEY_SNAPSHOT_HEIGHT: &[u8] = b"addrindex.backfill.snapshot_height";
pub const META_KEY_STARTED_AT: &[u8] = b"addrindex.backfill.started_at";
pub const META_KEY_STATE: &[u8] = b"addrindex.backfill.state";
/// Active-chain anchor: hash of the block at `snapshot_height` at the
/// moment `start()` was called. The runner verifies on resume (and
/// periodically during the run) that this hash is still on the active
/// chain — if not, a reorg has invalidated the snapshot and the run
/// must abort with `ReorgInvalidated → Failed` rather than write rows
/// for blocks the chain no longer includes. 32 bytes raw.
pub const META_KEY_SNAPSHOT_HASH: &[u8] = b"addrindex.backfill.snapshot_hash";
/// Operator-readable error message persisted alongside `State::Failed`.
/// Cleared on the next state transition. UTF-8 string, bounded length
/// (truncated by the writer if pathological).
pub const META_KEY_LAST_ERROR: &[u8] = b"addrindex.backfill.last_error";

/// Lifecycle state of the backfill task. Persisted as a single byte
/// in metadata so a restart can pick up where it left off.
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
    /// Backfill finished successfully; temp CF dropped.
    Completed = 3,
    /// Operator cancelled via `cancelindex`. Temp CF dropped.
    Cancelled = 4,
    /// Pre-flight rejection (e.g. insufficient disk). No persistent
    /// state to clean up.
    Rejected = 5,
    /// The runner exited with an unrecoverable error (missing block,
    /// reorg invalidation, temp CF miss, storage error). The last
    /// error message is persisted in `META_KEY_LAST_ERROR`. Treated
    /// as a non-terminal recovery state by the RPC: a fresh
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
/// cursor is `Copy`); see `Store::read_backfill_last_error`.
#[derive(Debug, Clone, Copy)]
pub struct BackfillCursor {
    pub state: BackfillState,
    pub pass: u8,
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
            pass: 0,
            cursor_height: 0,
            snapshot_height: 0,
            started_at_unix: 0,
            snapshot_tip_hash: [0u8; 32],
        }
    }

    /// Progress percent toward the snapshot height. Each pass covers
    /// `snapshot_height` blocks; the second pass advances from 0 to
    /// `snapshot_height` again — so total work is `2 * snapshot_height`.
    /// Returns 0..=1.0; 0 if there is no snapshot height yet.
    pub fn progress_ratio(&self) -> f64 {
        if self.snapshot_height == 0 {
            return 0.0;
        }
        let total = 2 * self.snapshot_height as u64;
        let done = match self.pass {
            1 => self.cursor_height as u64,
            2 => self.snapshot_height as u64 + self.cursor_height as u64,
            _ => 0,
        };
        (done as f64 / total as f64).clamp(0.0, 1.0)
    }
}
