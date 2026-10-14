//! Blocks that arrived before their parent, kept until the parent connects.
//!
//! Bitcoin Core keeps no such block. `AcceptBlockHeader` refuses a block
//! whose parent has no index entry as `prev-blk-not-found`
//! (`validation.cpp:4216`), and the block is gone. satd answers a block
//! `inv` with a `getdata` as well as a `getheaders` (`handle_inv`), so a
//! block it asked for can arrive before the parent it is still learning
//! about. Keeping that block saves fetching it a second time once the parent
//! connects.
//!
//! This holds the blocks and bounds them; the block processor decides what
//! to offer (only a block the node asked for) and takes a block back out when
//! its parent becomes the tip. A block is kept only if:
//!
//! - its header meets its own target and that target is within the
//!   network's proof-of-work limit, Core's `CheckProofOfWork`, which Core's
//!   `AcceptBlockHeader` runs before it looks for the parent
//!   (`validation.cpp:4206`);
//! - its serialized size is at most Core's `MAX_BLOCK_SERIALIZED_SIZE`
//!   (`consensus/consensus.h:13`), which no valid block exceeds.
//!
//! The buffer holds at most [`MAX_ORPHAN_BLOCKS_PER_PEER`] blocks from one
//! peer, [`MAX_ORPHAN_BLOCKS`] blocks and [`MAX_ORPHAN_BLOCK_BYTES`]
//! serialized bytes in all. When a new block needs room, the sender's own
//! oldest block goes first if the sender is at its share, then the oldest
//! block of all. A block is dropped after [`ORPHAN_BLOCK_EXPIRY`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bitcoin::{Block, BlockHash, Network};

use crate::net::peer::PeerId;

/// Core's `MAX_BLOCK_SERIALIZED_SIZE` (`consensus/consensus.h:13`). A block's
/// serialized size never exceeds its weight, so a valid block is never
/// larger.
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 4_000_000;

/// Blocks kept from one peer.
pub const MAX_ORPHAN_BLOCKS_PER_PEER: usize = 4;

/// Blocks kept in all.
pub const MAX_ORPHAN_BLOCKS: usize = 64;

/// Serialized bytes kept in all: eight blocks of the largest size.
pub const MAX_ORPHAN_BLOCK_BYTES: usize = 8 * MAX_BLOCK_SERIALIZED_SIZE;

/// How long a block is kept. By then the headers the node asked for have
/// made the block's own header known, and the ordinary missing-block fetch
/// gets it again if the parent connects later.
pub const ORPHAN_BLOCK_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// The bounds a buffer enforces. [`OrphanBlocks::new`] uses the constants
/// above; tests use smaller ones.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_peer: usize,
    pub blocks: usize,
    pub bytes: usize,
    pub expiry: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_peer: MAX_ORPHAN_BLOCKS_PER_PEER,
            blocks: MAX_ORPHAN_BLOCKS,
            bytes: MAX_ORPHAN_BLOCK_BYTES,
            expiry: ORPHAN_BLOCK_EXPIRY,
        }
    }
}

struct Orphan {
    hash: BlockHash,
    block: Block,
    from: PeerId,
    size: usize,
    since: Instant,
}

/// Blocks waiting for a parent the node has no index entry for, oldest first.
pub struct OrphanBlocks {
    waiting: VecDeque<Orphan>,
    bytes: usize,
    limits: Limits,
}

impl Default for OrphanBlocks {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanBlocks {
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    pub fn with_limits(limits: Limits) -> Self {
        Self { waiting: VecDeque::new(), bytes: 0, limits }
    }

    /// Blocks waiting.
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Serialized bytes waiting.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether the block with this hash is waiting.
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.waiting.iter().any(|o| o.hash == *hash)
    }

    /// Keep `block`, received from `from`, until its parent connects.
    /// Returns whether it is waiting afterwards; a copy of a block that is
    /// already waiting counts as waiting and is not kept twice.
    pub fn insert(&mut self, from: PeerId, block: Block, network: Network, now: Instant) -> bool {
        if crate::validation::pow::check_proof_of_work_bounded(&block.header, network).is_err() {
            return false;
        }
        let size = block.total_size();
        if size > MAX_BLOCK_SERIALIZED_SIZE || size > self.limits.bytes {
            return false;
        }
        let hash = block.block_hash();
        self.expire(now);
        if self.contains(&hash) {
            return true;
        }
        if self.limits.per_peer == 0 || self.limits.blocks == 0 {
            return false;
        }
        if self.waiting.iter().filter(|o| o.from == from).count() >= self.limits.per_peer
            && let Some(oldest) = self.waiting.iter().position(|o| o.from == from)
        {
            self.remove_at(oldest);
        }
        while !self.waiting.is_empty()
            && (self.waiting.len() >= self.limits.blocks || self.bytes + size > self.limits.bytes)
        {
            self.remove_at(0);
        }
        self.bytes += size;
        self.waiting.push_back(Orphan { hash, block, from, size, since: now });
        true
    }

    /// Remove and return the oldest waiting block whose parent is `parent`.
    pub fn take_child_of(&mut self, parent: &BlockHash) -> Option<Block> {
        let at = self.waiting.iter().position(|o| o.block.header.prev_blockhash == *parent)?;
        Some(self.remove_at(at).block)
    }

    /// Drop every block that has waited [`Limits::expiry`] or longer.
    pub fn expire(&mut self, now: Instant) {
        let expiry = self.limits.expiry;
        self.waiting.retain(|o| now.saturating_duration_since(o.since) < expiry);
        self.bytes = self.waiting.iter().map(|o| o.size).sum();
    }

    fn remove_at(&mut self, at: usize) -> Orphan {
        let orphan = self.waiting.remove(at).expect("index in range");
        self.bytes -= orphan.size;
        orphan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    /// A regtest block on `prev` whose coinbase carries `pad` extra bytes,
    /// with its header ground to meet (or, without `pow`, to miss) the
    /// regtest target.
    fn block_on(prev: BlockHash, salt: u32, pad: usize, pow: bool) -> Block {
        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::script::Builder::new()
                    .push_int(1)
                    .push_int(i64::from(salt))
                    .into_script(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x6a; pad]),
            }],
        };
        let mut block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_707_200_000 + salt,
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root().expect("one transaction");
        let target = block.header.target();
        while block.header.validate_pow(target).is_ok() != pow {
            block.header.nonce += 1;
        }
        block
    }

    fn prev(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn small(limits: Limits) -> OrphanBlocks {
        OrphanBlocks::with_limits(limits)
    }

    const ROOMY: Limits = Limits {
        per_peer: 100,
        blocks: 100,
        bytes: 100 * MAX_BLOCK_SERIALIZED_SIZE,
        expiry: Duration::from_secs(300),
    };

    #[test]
    fn a_block_with_valid_proof_of_work_is_kept_and_returned_to_its_parent() {
        let mut buf = OrphanBlocks::new();
        let b = block_on(prev(1), 1, 0, true);
        let now = Instant::now();
        assert!(buf.insert(7, b.clone(), Network::Regtest, now));
        assert_eq!((buf.len(), buf.bytes()), (1, b.total_size()));
        assert!(buf.take_child_of(&prev(2)).is_none(), "only to its own parent");
        assert_eq!(buf.take_child_of(&prev(1)).map(|b| b.block_hash()), Some(b.block_hash()));
        assert_eq!((buf.len(), buf.bytes()), (0, 0), "its bytes are released");
    }

    /// Core's `CheckProofOfWork` (`pow.cpp`): the hash meets the header's
    /// target, and the target is within powLimit.
    #[test]
    fn a_block_without_proof_of_work_within_the_limit_is_not_kept() {
        let mut buf = OrphanBlocks::new();
        let now = Instant::now();
        let misses = block_on(prev(1), 2, 0, false);
        assert!(!buf.insert(7, misses, Network::Regtest, now), "the hash misses its target");

        // A target above regtest's powLimit (0x207fffff), which almost every
        // hash meets.
        let mut easy = block_on(prev(1), 3, 0, true);
        easy.header.bits = bitcoin::CompactTarget::from_consensus(0x2100_ffff);
        assert!(easy.header.validate_pow(easy.header.target()).is_ok(), "fixture: meets its own target");
        assert!(!buf.insert(7, easy, Network::Regtest, now), "the target is above powLimit");

        // The same rule on mainnet, where regtest's work is far too little.
        let regtest_work = block_on(prev(1), 4, 0, true);
        assert!(!buf.insert(7, regtest_work.clone(), Network::Bitcoin, now));
        assert!(buf.is_empty());
        assert!(buf.insert(7, regtest_work, Network::Regtest, now), "but it is enough on regtest");
    }

    #[test]
    fn a_block_over_the_serialized_size_limit_is_not_kept() {
        let mut buf = OrphanBlocks::new();
        let now = Instant::now();
        let over = block_on(prev(1), 5, MAX_BLOCK_SERIALIZED_SIZE, true);
        assert!(over.total_size() > MAX_BLOCK_SERIALIZED_SIZE, "fixture: over the limit");
        assert!(!buf.insert(7, over, Network::Regtest, now));
        assert!(buf.is_empty());

        let at = block_on(prev(1), 6, MAX_BLOCK_SERIALIZED_SIZE - 200, true);
        assert!(at.total_size() <= MAX_BLOCK_SERIALIZED_SIZE, "fixture: within the limit");
        assert!(buf.insert(7, at, Network::Regtest, now), "a block within the limit is kept");
    }

    /// One peer cannot take more than its share: past it, its own oldest
    /// block goes, and blocks from other peers stay.
    #[test]
    fn one_peer_keeps_at_most_its_share_and_loses_its_oldest_first() {
        let mut buf = small(Limits { per_peer: 2, ..ROOMY });
        let now = Instant::now();
        let other = block_on(prev(9), 9, 0, true);
        assert!(buf.insert(8, other.clone(), Network::Regtest, now));
        let mine: Vec<Block> = (1..=3).map(|i| block_on(prev(i), 10 + u32::from(i), 0, true)).collect();
        for b in &mine {
            assert!(buf.insert(7, b.clone(), Network::Regtest, now));
        }
        assert_eq!(buf.len(), 3, "two from peer 7, one from peer 8");
        assert!(!buf.contains(&mine[0].block_hash()), "peer 7's oldest went");
        assert!(buf.contains(&mine[1].block_hash()) && buf.contains(&mine[2].block_hash()));
        assert!(buf.contains(&other.block_hash()), "the other peer's block stays");
    }

    #[test]
    fn the_byte_cap_drops_the_oldest_blocks_first() {
        let probe = block_on(prev(1), 20, 1_000, true).total_size();
        let mut buf = small(Limits { bytes: 3 * probe, ..ROOMY });
        let now = Instant::now();
        let blocks: Vec<Block> = (1..=4).map(|i| block_on(prev(i), 20 + u32::from(i), 1_000, true)).collect();
        for (peer, b) in blocks.iter().enumerate() {
            assert_eq!(b.total_size(), probe, "fixture: equal sizes");
            assert!(buf.insert(peer as PeerId, b.clone(), Network::Regtest, now));
            assert!(buf.bytes() <= 3 * probe, "never over the byte cap");
        }
        assert_eq!(buf.len(), 3);
        assert!(!buf.contains(&blocks[0].block_hash()), "the oldest went");
        assert!(blocks[1..].iter().all(|b| buf.contains(&b.block_hash())));
    }

    #[test]
    fn the_block_cap_drops_the_oldest_blocks_first() {
        let mut buf = small(Limits { blocks: 2, ..ROOMY });
        let now = Instant::now();
        let blocks: Vec<Block> = (1..=3).map(|i| block_on(prev(i), 30 + u32::from(i), 0, true)).collect();
        for (peer, b) in blocks.iter().enumerate() {
            assert!(buf.insert(peer as PeerId, b.clone(), Network::Regtest, now));
        }
        assert_eq!(buf.len(), 2);
        assert!(!buf.contains(&blocks[0].block_hash()), "the oldest went");
    }

    #[test]
    fn a_block_is_dropped_once_it_has_waited_the_expiry() {
        let mut buf = small(Limits { expiry: Duration::from_secs(60), ..ROOMY });
        let start = Instant::now();
        let old = block_on(prev(1), 40, 0, true);
        let young = block_on(prev(2), 41, 0, true);
        assert!(buf.insert(7, old.clone(), Network::Regtest, start));
        assert!(buf.insert(8, young.clone(), Network::Regtest, start + Duration::from_secs(30)));

        buf.expire(start + Duration::from_secs(59));
        assert_eq!(buf.len(), 2, "nothing has waited a minute yet");
        buf.expire(start + Duration::from_secs(60));
        assert!(!buf.contains(&old.block_hash()), "the first block expired");
        assert!(buf.contains(&young.block_hash()), "the second has not");
        assert_eq!(buf.bytes(), young.total_size());
    }

    /// Two blocks on the same parent both wait; a copy of one that is already
    /// waiting is not kept twice.
    #[test]
    fn siblings_both_wait_and_a_second_copy_is_not_kept_twice() {
        let mut buf = OrphanBlocks::new();
        let now = Instant::now();
        let a = block_on(prev(1), 50, 0, true);
        let b = block_on(prev(1), 51, 0, true);
        assert!(buf.insert(7, a.clone(), Network::Regtest, now));
        assert!(buf.insert(8, b.clone(), Network::Regtest, now));
        assert!(buf.insert(9, a.clone(), Network::Regtest, now), "already waiting");
        assert_eq!((buf.len(), buf.bytes()), (2, a.total_size() + b.total_size()));
        assert_eq!(buf.take_child_of(&prev(1)).map(|x| x.block_hash()), Some(a.block_hash()), "oldest first");
        assert_eq!(buf.take_child_of(&prev(1)).map(|x| x.block_hash()), Some(b.block_hash()));
        assert!(buf.is_empty());
    }

    /// The default bounds always leave room for one block of the largest
    /// valid size, and one peer can never fill the buffer on its own.
    #[test]
    fn the_default_bounds_fit_a_full_size_block_and_cap_each_peer_below_the_total() {
        let l = Limits::default();
        assert!(l.bytes >= MAX_BLOCK_SERIALIZED_SIZE);
        assert!(l.per_peer * MAX_BLOCK_SERIALIZED_SIZE < l.bytes);
        assert!(l.per_peer < l.blocks);
    }
}
