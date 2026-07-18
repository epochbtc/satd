//! The `SpIndex` trait — read-side surface for the tweak index.
//!
//! Consumed by the serving surfaces (the `getsilentpaymentblockdata`
//! RPC, the streaming `tweaks` category replay) and by the D4
//! rescan fast path. Intentionally minimal: fetch one block's row, and
//! ask whether the index is complete.
//!
//! `is_complete()` is the gate the deep-replay exemption and the rescan
//! fast path both consult: when `false`, callers fall back to recompute
//! (rescan) or refuse the unclamped replay, because a partial index can't
//! be treated as authoritative.

use crate::keys::SpBlockRow;
use crate::types::SpIndexError;

pub trait SpIndex: Send + Sync {
    /// The tweak row for the block at `height`. `Err(NotFound)` when no
    /// row exists (below taproot activation, above tip, or a
    /// not-yet-backfilled range); `Err(Disabled)`/`Err(Incomplete)` per
    /// the runtime state. The returned row carries the block hash it
    /// describes (§3.2), so callers verify identity without a height→hash
    /// lookup.
    fn tweaks_at(&self, height: u32) -> Result<SpBlockRow, SpIndexError>;

    /// Completeness gate. Reads `sp_index.complete` from the metadata CF.
    /// The rescan fast path and the tweaks-only deep-replay exemption
    /// both require this to be `true`.
    fn is_complete(&self) -> bool;
}
