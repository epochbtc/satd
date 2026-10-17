//! Which peer sent a stored block, so a block that fails when it connects
//! later can be charged to its sender: Core's `mapBlockSource`
//! (`net_processing.cpp`), read in `BlockChecked`.
//!
//! During initial block download a block is stored when it arrives and
//! judged only when the connector reaches it, by which point the peer it came
//! from is no longer in hand. Without this, a block that fails a consensus
//! rule at connect is marked invalid and its sender is never charged, so it
//! can keep feeding the node.
//!
//! Bounded by insertion order. An entry is taken when its block's verdict is
//! known, or pushed out by newer ones; a block judged after its entry was
//! pushed out is just not attributed, as in Core when the source has gone.

use std::collections::{HashMap, VecDeque};

use bitcoin::BlockHash;

use crate::net::peer::PeerId;

/// Room for every block in flight and stored ahead of the connector at the
/// default download window, with headroom.
pub const DEFAULT_CAPACITY: usize = 16_384;

pub struct BlockSources {
    by_hash: HashMap<BlockHash, PeerId>,
    order: VecDeque<BlockHash>,
    capacity: usize,
}

impl BlockSources {
    pub fn new(capacity: usize) -> Self {
        Self { by_hash: HashMap::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    /// Record that `peer` sent `hash`. A block already recorded keeps its
    /// first sender, as Core's `mapBlockSource.emplace` does.
    pub fn record(&mut self, hash: BlockHash, peer: PeerId) {
        if self.by_hash.contains_key(&hash) {
            return;
        }
        while self.by_hash.len() >= self.capacity {
            let Some(old) = self.order.pop_front() else { break };
            self.by_hash.remove(&old);
        }
        self.by_hash.insert(hash, peer);
        self.order.push_back(hash);
    }

    /// The peer that sent `hash`, forgetting it. `order` keeps the hash
    /// until it reaches the front, where a pop of a hash no longer in
    /// `by_hash` frees nothing; the queue is at most `capacity` plus the
    /// entries taken since.
    pub fn take(&mut self, hash: &BlockHash) -> Option<PeerId> {
        let peer = self.by_hash.remove(hash);
        if peer.is_some() && self.order.len() > 2 * self.capacity {
            self.order.retain(|h| self.by_hash.contains_key(h));
        }
        peer
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_hash.len()
    }
}

impl Default for BlockSources {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn h(b: u8) -> BlockHash {
        BlockHash::from_byte_array([b; 32])
    }

    #[test]
    fn the_first_sender_is_kept_and_taken_once() {
        let mut s = BlockSources::new(4);
        s.record(h(1), 7);
        s.record(h(1), 8);
        assert_eq!(s.take(&h(1)), Some(7));
        assert_eq!(s.take(&h(1)), None);
    }

    #[test]
    fn the_oldest_entry_makes_room() {
        let mut s = BlockSources::new(2);
        s.record(h(1), 1);
        s.record(h(2), 2);
        s.record(h(3), 3);
        assert_eq!(s.len(), 2);
        assert_eq!(s.take(&h(1)), None, "pushed out");
        assert_eq!(s.take(&h(2)), Some(2));
        assert_eq!(s.take(&h(3)), Some(3));
    }

    /// Taking entries does not let the order queue grow without bound.
    #[test]
    fn taken_entries_do_not_accumulate() {
        let mut s = BlockSources::new(4);
        for i in 0..200u8 {
            s.record(h(i), u64::from(i));
            assert_eq!(s.take(&h(i)), Some(u64::from(i)));
        }
        assert!(s.order.len() <= 2 * 4 + 1, "order queue is {}", s.order.len());
        assert_eq!(s.len(), 0);
    }
}
