//! Chain event broadcast — analogue of `MempoolEvent` for chain-tip
//! transitions. The address-index subscription notifier (M5) fans
//! these into per-scripthash status updates; future watchtower /
//! observability tools subscribe to the same channel.

use bitcoin::BlockHash;

/// Capacity of the chain-event broadcast channel. Sized so a slow
/// consumer can pause for a few seconds at typical block cadence
/// (~10 min mainnet, ~10 s regtest under stress) without missing
/// events. Lagged consumers see `RecvError::Lagged` and resync from
/// chain state — same contract as the mempool channel.
pub const CHAIN_EVENT_BROADCAST_CAPACITY: usize = 64;

/// Chain-tip transition. A reorg emits one `BlockDisconnected` per
/// disconnected block followed by one `BlockConnected` per
/// reconnected block (in chain order).
#[derive(Debug, Clone)]
pub enum ChainEvent {
    BlockConnected {
        hash: BlockHash,
        height: u32,
    },
    BlockDisconnected {
        hash: BlockHash,
        height: u32,
    },
}

impl ChainEvent {
    pub fn hash(&self) -> &BlockHash {
        match self {
            ChainEvent::BlockConnected { hash, .. }
            | ChainEvent::BlockDisconnected { hash, .. } => hash,
        }
    }

    pub fn height(&self) -> u32 {
        match self {
            ChainEvent::BlockConnected { height, .. }
            | ChainEvent::BlockDisconnected { height, .. } => *height,
        }
    }
}
