//! Chain event broadcast — analogue of `MempoolEvent` for chain-tip
//! transitions. The address-index subscription notifier (M5) fans
//! these into per-scripthash status updates; future watchtower /
//! observability tools subscribe to the same channel.

use bitcoin::BlockHash;
use serde::Serialize;

/// Capacity of the chain-event broadcast channel.
///
/// A reorg is the largest burst the chain produces in one go: one `Reorg`
/// marker, one `BlockDisconnected` per block it unwinds and one
/// `BlockConnected` per block it connects, all sent back to back under the
/// accept lock. At the old capacity of 64 a reorg of more than about 30
/// blocks could overrun the ring before the event-bus bridge drained it, and
/// the bridge dropped the overflow with only a log line, so a streaming or
/// ZMQ subscriber silently missed blocks. 1024 covers a reorg of 500 blocks
/// with room to spare; `ChainEvent` is 76 bytes, so the ring holds 76 KiB.
/// Lagged consumers still see `RecvError::Lagged` and resync from chain
/// state — same contract as the mempool channel.
pub const CHAIN_EVENT_BROADCAST_CAPACITY: usize = 1024;

/// Chain-tip transition. A reorg emits one `Reorg` marker (fork point and
/// new tip) followed by one `BlockDisconnected` per disconnected block and
/// one `BlockConnected` per reconnected block (in chain order). The `Reorg`
/// marker is a first-class, in-process ground-truth signal — a ZMQ/header
/// sidecar can only *infer* a reorg by diffing headers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainEvent {
    BlockConnected {
        hash: BlockHash,
        height: u32,
    },
    BlockDisconnected {
        hash: BlockHash,
        height: u32,
    },
    /// A reorg replaced the active tip. Emitted once, before the
    /// per-block disconnect/connect sequence, so a client has an explicit
    /// fork-point marker rather than having to reconstruct one.
    Reorg {
        /// Height of the tip being abandoned.
        from_height: u32,
        /// Hash of the tip being abandoned.
        old_tip: BlockHash,
        /// Height of the new active tip.
        to_height: u32,
        /// Hash of the new active tip.
        new_tip: BlockHash,
    },
}

impl ChainEvent {
    /// The block hash this event concerns. For a [`ChainEvent::Reorg`]
    /// this is the **new** tip (the resulting active-chain head).
    pub fn hash(&self) -> &BlockHash {
        match self {
            ChainEvent::BlockConnected { hash, .. }
            | ChainEvent::BlockDisconnected { hash, .. } => hash,
            ChainEvent::Reorg { new_tip, .. } => new_tip,
        }
    }

    /// The height this event concerns. For a [`ChainEvent::Reorg`] this is
    /// the **new** tip height.
    pub fn height(&self) -> u32 {
        match self {
            ChainEvent::BlockConnected { height, .. }
            | ChainEvent::BlockDisconnected { height, .. } => *height,
            ChainEvent::Reorg { to_height, .. } => *to_height,
        }
    }
}
