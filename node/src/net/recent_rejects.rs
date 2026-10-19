//! Core's recent-rejects filters (`TxDownloadManagerImpl`,
//! `m_lazy_recent_rejects` and `m_lazy_recent_rejects_reconsiderable`):
//! the hashes of transactions the mempool refused since the tip last moved,
//! so the same transaction is not downloaded and validated again, scripts
//! and all, each time another peer announces it.
//!
//! Core keeps each in a `CRollingBloomFilter` of 120000 entries at a
//! 1-in-a-million false-positive rate. Here each is a bounded set of salted
//! 64-bit hashes of the 32-byte txid or wtxid: the same capacity in about
//! 2 MB, with a far lower false-positive rate, oldest entries forgotten
//! first. Both are cleared when the active tip changes, as Core's
//! `ActiveTipChange` resets them: a block can make a refused transaction
//! acceptable.

use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};

use bitcoin::BlockHash;

/// Core's capacity for each filter.
pub const RECENT_REJECTS_CAPACITY: usize = 120_000;

/// One filter: a FIFO-bounded set of salted 64-bit keys.
#[derive(Debug)]
struct Filter {
    keys: HashSet<u64>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl Filter {
    fn new(capacity: usize) -> Self {
        Self { keys: HashSet::new(), order: VecDeque::new(), capacity }
    }

    fn insert(&mut self, key: u64) {
        if !self.keys.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.order.len() > self.capacity
            && let Some(old) = self.order.pop_front()
        {
            self.keys.remove(&old);
        }
    }

    fn contains(&self, key: u64) -> bool {
        self.keys.contains(&key)
    }

    fn clear(&mut self) {
        self.keys.clear();
        self.order.clear();
    }
}

/// Which filter a refusal goes to, per Core's `MempoolRejectedTx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// `m_lazy_recent_rejects`: not downloaded again.
    Rejected,
    /// `m_lazy_recent_rejects_reconsiderable` (`TX_RECONSIDERABLE`, a fee
    /// failure): not downloaded again on its own, though it may still enter
    /// with a child that pays for it.
    Reconsiderable,
}

/// Both filters, and the tip they were filled under.
#[derive(Debug)]
pub struct RecentRejects {
    salt: std::collections::hash_map::RandomState,
    rejected: Filter,
    reconsiderable: Filter,
    tip: Option<BlockHash>,
}

impl RecentRejects {
    pub fn new() -> Self {
        Self::with_capacity(RECENT_REJECTS_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            salt: std::collections::hash_map::RandomState::new(),
            rejected: Filter::new(capacity),
            reconsiderable: Filter::new(capacity),
            tip: None,
        }
    }

    fn key(&self, hash: &[u8; 32]) -> u64 {
        let mut h = self.salt.build_hasher();
        h.write(hash);
        h.finish()
    }

    /// Forget everything when the tip has moved since the last call.
    fn sync_tip(&mut self, tip: BlockHash) {
        if self.tip != Some(tip) {
            self.rejected.clear();
            self.reconsiderable.clear();
            self.tip = Some(tip);
        }
    }

    /// Record `hash` (a txid or a wtxid) as refused under `tip`.
    pub fn insert(&mut self, tip: BlockHash, hash: &[u8; 32], kind: Rejection) {
        self.sync_tip(tip);
        let key = self.key(hash);
        match kind {
            Rejection::Rejected => self.rejected.insert(key),
            Rejection::Reconsiderable => self.reconsiderable.insert(key),
        }
    }

    /// Record `hashes` as refused only if the verdict was reached under the
    /// tip that is current: `judged_at` is the tip the transaction was
    /// validated against, `tip` the tip now. A verdict about a tip that has
    /// since moved is dropped rather than recorded under the new one.
    pub fn insert_if_tip(&mut self, judged_at: BlockHash, tip: BlockHash, hashes: &[[u8; 32]], kind: Rejection) {
        if judged_at != tip {
            return;
        }
        for hash in hashes {
            self.insert(tip, hash, kind);
        }
    }

    /// Whether `hash` was refused under `tip`: by the main filter, or with
    /// `include_reconsiderable` also by the fee filter (Core's
    /// `AlreadyHaveTx(gtxid, include_reconsiderable)`).
    pub fn contains(&mut self, tip: BlockHash, hash: &[u8; 32], include_reconsiderable: bool) -> bool {
        self.sync_tip(tip);
        let key = self.key(hash);
        self.rejected.contains(key) || (include_reconsiderable && self.reconsiderable.contains(key))
    }

    /// Whether `hash` is in the fee filter alone (Core's
    /// `RecentRejectsReconsiderableFilter().contains`).
    pub fn contains_reconsiderable(&mut self, tip: BlockHash, hash: &[u8; 32]) -> bool {
        self.sync_tip(tip);
        let key = self.key(hash);
        self.reconsiderable.contains(key)
    }
}

/// Core's `GetPackageHash` (`policy/packages.cpp`): the SHA256 of the
/// members' wtxids, sorted as numbers (by their bytes from the last), each
/// written in its own byte order. A failed package is remembered by it in
/// the fee filter, so the same pairing is not tried again.
pub fn package_hash(wtxids: &[bitcoin::Wtxid]) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine, sha256};
    let mut sorted: Vec<[u8; 32]> = wtxids.iter().map(|w| w.to_byte_array()).collect();
    sorted.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    let mut engine = sha256::Hash::engine();
    for w in &sorted {
        engine.input(w);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

impl Default for RecentRejects {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn tip(b: u8) -> BlockHash {
        BlockHash::from_byte_array([b; 32])
    }

    /// What Core's `txpackage_tests.cpp` checks of `GetPackageHash`: the
    /// order the wtxids come in does not matter, and they are sorted as
    /// their hex strings read (the bytes from the last), not by the byte
    /// array, where these two would sort the other way round.
    #[test]
    fn the_package_hash_sorts_the_wtxids_as_numbers() {
        use bitcoin::hashes::{sha256, HashEngine};
        // As numbers, `low` < `high`, though `low`'s first byte is larger.
        let mut low = [0u8; 32];
        low[0] = 0xff;
        low[31] = 0x01;
        let mut high = [0u8; 32];
        high[31] = 0x02;
        let (lw, hw) = (bitcoin::Wtxid::from_byte_array(low), bitcoin::Wtxid::from_byte_array(high));
        let mut engine = sha256::Hash::engine();
        engine.input(&low);
        engine.input(&high);
        let expected = sha256::Hash::from_engine(engine).to_byte_array();
        assert_eq!(package_hash(&[hw, lw]), expected);
        assert_eq!(package_hash(&[lw, hw]), expected);
    }

    #[test]
    fn the_fee_filter_is_asked_alone() {
        let mut r = RecentRejects::new();
        r.insert(tip(1), &[7; 32], Rejection::Reconsiderable);
        r.insert(tip(1), &[8; 32], Rejection::Rejected);
        assert!(r.contains_reconsiderable(tip(1), &[7; 32]));
        assert!(!r.contains_reconsiderable(tip(1), &[8; 32]));
    }

    #[test]
    fn a_hash_is_remembered_until_the_tip_moves() {
        let mut r = RecentRejects::new();
        r.insert(tip(1), &[7; 32], Rejection::Rejected);
        assert!(r.contains(tip(1), &[7; 32], false));
        assert!(!r.contains(tip(1), &[8; 32], true));
        assert!(!r.contains(tip(2), &[7; 32], true), "a new tip forgets it");
        assert!(!r.contains(tip(1), &[7; 32], true), "and going back does not restore it");
    }

    #[test]
    fn a_fee_refusal_counts_only_where_reconsiderable_ones_are_asked_for() {
        let mut r = RecentRejects::new();
        r.insert(tip(1), &[7; 32], Rejection::Reconsiderable);
        assert!(r.contains(tip(1), &[7; 32], true));
        assert!(!r.contains(tip(1), &[7; 32], false));
    }

    #[test]
    fn a_verdict_about_a_former_tip_is_not_recorded() {
        let mut r = RecentRejects::new();
        r.insert_if_tip(tip(1), tip(2), &[[7; 32]], Rejection::Rejected);
        assert!(!r.contains(tip(2), &[7; 32], true));
        r.insert_if_tip(tip(2), tip(2), &[[7; 32]], Rejection::Rejected);
        assert!(r.contains(tip(2), &[7; 32], true));
    }

    #[test]
    fn the_oldest_entry_goes_first_at_capacity() {
        let mut r = RecentRejects::with_capacity(2);
        for b in 1..=3u8 {
            r.insert(tip(1), &[b; 32], Rejection::Rejected);
        }
        assert!(!r.contains(tip(1), &[1; 32], false));
        assert!(r.contains(tip(1), &[2; 32], false) && r.contains(tip(1), &[3; 32], false));
    }
}
