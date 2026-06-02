//! Chain event broadcast — analogue of `MempoolEvent` for chain-tip
//! transitions. The address-index subscription notifier (M5) fans
//! these into per-scripthash status updates; future watchtower /
//! observability tools subscribe to the same channel.

use bitcoin::BlockHash;
use serde::Serialize;

/// Capacity of the chain-event broadcast channel. Sized so a slow
/// consumer can pause for a few seconds at typical block cadence
/// (~10 min mainnet, ~10 s regtest under stress) without missing
/// events. Lagged consumers see `RecvError::Lagged` and resync from
/// chain state — same contract as the mempool channel.
pub const CHAIN_EVENT_BROADCAST_CAPACITY: usize = 64;

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
