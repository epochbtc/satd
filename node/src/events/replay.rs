//! Block-index access for durable cursor replay.
//!
//! The streaming event sinks (e.g. the gRPC `Subscribe` RPC) resume a
//! client from a durable [`Cursor`](super::Cursor) by replaying confirmed
//! history forward from the block store, then joining the live broadcast.
//! That replay needs read-only access to the active chain: the current
//! tip height and the block hash at a height. This trait is the narrow
//! seam the sinks depend on, so the `satd-events` crate does not have to
//! depend on the full [`ChainState`](crate::chain::state::ChainState)
//! surface.
//!
//! The implementation is **read-only and off the consensus hot path**:
//! replay reads blocks the node already holds and never blocks, locks, or
//! backpressures block connection.

use bitcoin::BlockHash;

/// Read-only block-index access for confirmed cursor replay.
///
/// Implemented by [`ChainState`](crate::chain::state::ChainState). All
/// methods describe the **active chain** only; a height beyond the tip or
/// a pruned/missing block returns `None`.
pub trait BlockCursorSource: Send + Sync {
    /// Current active-chain tip height.
    fn current_tip_height(&self) -> u32;

    /// Active-chain block hash at `height`, or `None` if the height is
    /// beyond the tip or the block is unavailable (pruned).
    fn block_hash_at(&self, height: u32) -> Option<BlockHash>;
}

impl BlockCursorSource for crate::chain::state::ChainState {
    fn current_tip_height(&self) -> u32 {
        // Inherent method on ChainState; no clash since the trait method
        // has a distinct name.
        self.tip_height()
    }

    fn block_hash_at(&self, height: u32) -> Option<BlockHash> {
        self.get_block_hash_by_height(height)
    }
}
