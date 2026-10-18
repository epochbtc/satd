//! Core's `-assumevalid` decision: whether a block's scripts are verified
//! when it connects.
//!
//! Core skips script verification for a block only when all of these hold
//! (`ConnectBlock`, `validation.cpp`):
//!
//! 1. the assumevalid block is in the block index;
//! 2. the block is an ancestor of it (`GetAncestor(nHeight) == pindex`);
//! 3. the block is an ancestor of the best header;
//! 4. the best header has at least the network's minimum chain work;
//! 5. the best header is more than two weeks of equivalent proof of work
//!    beyond the block (`GetBlockProofEquivalentTime`).
//!
//! satd used to skip every block at or below the assumevalid block's
//! *height*, whatever chain it was on and however little work stood on top
//! of it. A side-chain block connected by a reorg skipped its scripts too.
//!
//! Core answers 2 and 3 with its skip list. satd's block index has none, so
//! [`AvAncestry`] keeps the assumevalid block's ancestor at each height,
//! built once by walking parent hashes down from it. It also caches whether
//! the assumevalid block is an ancestor of the best header, refreshed by
//! walking only the part of the chain above the last best header checked.
//! Given 2, condition 3 holds exactly when the assumevalid block is on the
//! best-header chain, or when the block lies below the point where the two
//! chains fork. satd checks only the first: if the best header is on another
//! branch, every block is verified. That is stricter than Core, never looser.

use bitcoin::BlockHash;

use crate::storage::blockindex::{BlockIndexEntry, sub_u256, work_for_bits};

/// Why a block's scripts are verified: Core's `script_check_reason`. `None`
/// means they are skipped.
pub type ScriptCheckReason = Option<&'static str>;

pub const ALWAYS_VERIFY: &str = "assumevalid=0 (always verify)";
pub const NOT_IN_HEADERS: &str = "assumevalid hash not in headers";
pub const ABOVE_AV_HEIGHT: &str = "block height above assumevalid height";
pub const NOT_IN_AV_CHAIN: &str = "block not in assumevalid chain";
pub const NOT_IN_BEST_HEADER_CHAIN: &str = "block not in best header chain";
pub const BELOW_MIN_CHAINWORK: &str = "best header chainwork below minimumchainwork";
pub const TOO_RECENT: &str = "block too recent relative to best header";
/// satd's `-assumevalid=all`: a block newer than `-assumevalidage`.
pub const NEWER_THAN_AGE: &str = "block newer than -assumevalidage";

/// Core's `TWO_WEEKS_IN_SECONDS` over `nPowTargetSpacing` (600 s): the
/// two-week bound in blocks' worth of the best header's proof.
const TWO_WEEKS_IN_SECONDS: u128 = 60 * 60 * 24 * 7 * 2;
const POW_TARGET_SPACING: u128 = 600;

/// Cached ancestry for the assumevalid decision. Lives behind a mutex in
/// `ChainState`.
#[derive(Default)]
pub struct AvAncestry {
    /// The assumevalid block's ancestor at each height, index = height, with
    /// the assumevalid hash it was built for. Dropped once blocks above that
    /// height are being connected, and rebuilt if a reorg below it needs it.
    av_chain: Option<(BlockHash, Vec<BlockHash>)>,
    /// `(best header, its height, assumevalid block is its ancestor)` for the
    /// last best header checked.
    on_best: Option<(BlockHash, u32, bool)>,
    /// The last reason logged, `None` before the first. Core's is an
    /// `std::optional<const char*>` that starts empty, so the first decision
    /// is always logged, a skip included.
    last_logged: Option<ScriptCheckReason>,
}

impl AvAncestry {
    /// Whether `hash` at `height` is an ancestor of (or is) the assumevalid
    /// block `av`, at `av_height`. Builds the ancestor table on first use;
    /// a gap in the parent chain answers `false` and caches nothing.
    pub fn is_av_ancestor<G>(
        &mut self,
        av: &BlockHash,
        av_height: u32,
        hash: &BlockHash,
        height: u32,
        get: G,
    ) -> bool
    where
        G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
    {
        if height > av_height {
            // Past the assumevalid block: the table is no longer needed.
            self.av_chain = None;
            return false;
        }
        if self.av_chain.as_ref().is_none_or(|(built_for, _)| built_for != av) {
            let Some(chain) = ancestors_down_to(av, av_height, 0, &get) else {
                return false;
            };
            self.av_chain = Some((*av, chain));
        }
        self.av_chain
            .as_ref()
            .and_then(|(_, chain)| chain.get(height as usize))
            .is_some_and(|h| h == hash)
    }

    /// Whether the assumevalid block `av` at `av_height` is an ancestor of
    /// (or is) the best header `best` at `best_height`. Walks from `best`
    /// down to the last best header checked when that one was on the
    /// assumevalid chain and `best` descends from it, and down to
    /// `av_height` otherwise.
    pub fn av_on_best_chain<G>(
        &mut self,
        av: &BlockHash,
        av_height: u32,
        best: &BlockHash,
        best_height: u32,
        get: G,
    ) -> bool
    where
        G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
    {
        if best_height < av_height {
            return false;
        }
        if let Some((cached, _, ok)) = self.on_best
            && cached == *best
        {
            return ok;
        }
        // The last best header checked was on the assumevalid chain: if this
        // one descends from it, so is this one.
        if let Some((prev, prev_height, true)) = self.on_best
            && prev_height <= best_height
            && ancestor_at(best, best_height, prev_height, &get) == Some(prev)
        {
            self.on_best = Some((*best, best_height, true));
            return true;
        }
        let ok = ancestor_at(best, best_height, av_height, &get) == Some(*av);
        self.on_best = Some((*best, best_height, ok));
        ok
    }

    /// Record `reason` for `height`/`hash`, logging Core's line when it
    /// differs from the last one logged.
    pub fn log_reason(&mut self, height: u32, hash: &BlockHash, reason: ScriptCheckReason) {
        if self.last_logged == Some(reason) {
            return;
        }
        match reason {
            Some(r) => tracing::info!("Enabling script verification at block #{height} ({hash}): {r}."),
            None => tracing::info!("Disabling script verification at block #{height} ({hash})."),
        }
        self.last_logged = Some(reason);
    }
}

/// The ancestor of `from` (at `from_height`) at `height`, by walking parent
/// hashes. `None` if `height > from_height` or the walk hits a missing entry.
fn ancestor_at<G>(from: &BlockHash, from_height: u32, height: u32, get: &G) -> Option<BlockHash>
where
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    if height > from_height {
        return None;
    }
    let mut cur = *from;
    for _ in height..from_height {
        cur = get(&cur)?.header.prev_blockhash;
    }
    Some(cur)
}

/// `from` and its ancestors down to `floor`, indexed by height (entries
/// below `floor` are zero hashes). `None` on a missing entry.
fn ancestors_down_to<G>(from: &BlockHash, from_height: u32, floor: u32, get: &G) -> Option<Vec<BlockHash>>
where
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    use bitcoin::hashes::Hash as _;
    let mut chain = vec![BlockHash::all_zeros(); from_height as usize + 1];
    let mut cur = *from;
    for h in (floor..=from_height).rev() {
        chain[h as usize] = cur;
        if h > floor {
            cur = get(&cur)?.header.prev_blockhash;
        }
    }
    Some(chain)
}

/// Core's `GetBlockProofEquivalentTime(best, block, best) > TWO_WEEKS`:
/// whether the work on top of `block_work` up to `best_work` is worth more
/// than two weeks of blocks at the best header's difficulty
/// (`best_bits`).
///
/// Core computes `(best - block) * 600 / GetBlockProof(best)` and verifies
/// when that is at most two weeks. Here the comparison is made without the
/// division: skip iff `(best - block) * 600 >= (TWO_WEEKS + 1) * proof`. The
/// operands are taken as `u128`; a difference too large for that is far
/// beyond two weeks, and a proof too large for it never happens on a real
/// network, so that case verifies.
pub fn more_than_two_weeks_on_top(
    best_work: &[u8; 32],
    block_work: &[u8; 32],
    best_bits: bitcoin::pow::CompactTarget,
) -> bool {
    proof_equivalent_time_at_least(best_work, block_work, best_bits, TWO_WEEKS_IN_SECONDS + 1)
}

/// Core's `GetBlockProofEquivalentTime(best, block, best) >= secs`, with
/// Core's integer division: whether the work on top of `block_work` up to
/// `best_work` is worth at least `secs` of blocks at the best header's
/// difficulty. Compared without the division, as
/// `(best - block) * 600 >= secs * proof`. Work at or below the block's is
/// never worth `secs > 0`.
pub fn proof_equivalent_time_at_least(
    best_work: &[u8; 32],
    block_work: &[u8; 32],
    best_bits: bitcoin::pow::CompactTarget,
    secs: u128,
) -> bool {
    if crate::chain::state::compare_u256(best_work, block_work) <= 0 {
        return false;
    }
    let diff = sub_u256(best_work, block_work);
    let proof = work_for_bits(best_bits);
    let (Some(diff), Some(proof)) = (low_u128(&diff), low_u128(&proof)) else {
        // A difference beyond 2^128 is far more than two weeks; a proof
        // beyond it is not a real network. Distinguish the two.
        return low_u128(&diff).is_none() && low_u128(&proof).is_some();
    };
    match (diff.checked_mul(POW_TARGET_SPACING), proof.checked_mul(secs)) {
        (Some(lhs), Some(rhs)) => lhs >= rhs,
        // `diff * 600` overflowed: the difference is far beyond two weeks.
        (None, _) => true,
        (Some(_), None) => false,
    }
}

/// `v` as a `u128` when its high 16 bytes are zero.
fn low_u128(v: &[u8; 32]) -> Option<u128> {
    if v[..16].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(v[16..].try_into().expect("16 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::pow::CompactTarget;

    fn u256(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&v.to_be_bytes());
        out
    }

    /// Regtest proof is 2 per block, so two weeks is 2016 blocks of work: a
    /// difference of 4032 is exactly two weeks and is verified (Core's
    /// `<=`); one more unit of work and the block is skipped.
    #[test]
    fn the_two_week_bound_is_cores_inclusive_one() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        assert_eq!(work_for_bits(bits), u256(2));
        let block = u256(1000);
        assert!(!more_than_two_weeks_on_top(&u256(1000 + 4032), &block, bits));
        // 4033 * 600 / 2 = 1_209_900, past two weeks once floored to seconds.
        assert!(more_than_two_weeks_on_top(&u256(1000 + 4033), &block, bits));
        assert!(!more_than_two_weeks_on_top(&block, &block, bits));
        assert!(!more_than_two_weeks_on_top(&u256(10), &block, bits), "best below block");
    }

    /// A fake block index: `chain` is a list of (hash byte, parent byte, height).
    fn index(chain: &[(u8, u8, u32)]) -> std::collections::HashMap<BlockHash, BlockIndexEntry> {
        use bitcoin::hashes::Hash as _;
        let h = |b: u8| BlockHash::from_byte_array([b; 32]);
        chain
            .iter()
            .map(|&(id, parent, height)| {
                let mut header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
                header.prev_blockhash = h(parent);
                (
                    h(id),
                    BlockIndexEntry {
                        header,
                        height,
                        status: crate::storage::blockindex::BlockStatus::HeaderOnly,
                        num_tx: 0,
                        file_number: 0,
                        data_pos: 0,
                        chainwork: [0; 32],
                    },
                )
            })
            .collect()
    }

    fn hash(b: u8) -> BlockHash {
        use bitcoin::hashes::Hash as _;
        BlockHash::from_byte_array([b; 32])
    }

    /// Main chain 1..=10 (ids 1..=10), a branch forking at 3: ids 23..=29 at
    /// heights 4..=10. The assumevalid block is 5.
    fn fixture() -> std::collections::HashMap<BlockHash, BlockIndexEntry> {
        let mut chain: Vec<(u8, u8, u32)> = (1..=10u8).map(|i| (i, i - 1, u32::from(i) - 1)).collect();
        chain.push((23, 3, 3));
        chain.extend((24..=29u8).map(|i| (i, i - 1, u32::from(i) - 20)));
        index(&chain)
    }

    #[test]
    fn ancestry_of_the_assumevalid_block() {
        let idx = fixture();
        let get = |h: &BlockHash| idx.get(h).cloned();
        let mut a = AvAncestry::default();
        // Id 5 sits at height 4.
        assert!(a.is_av_ancestor(&hash(5), 4, &hash(2), 1, get));
        assert!(a.is_av_ancestor(&hash(5), 4, &hash(5), 4, get));
        assert!(!a.is_av_ancestor(&hash(5), 4, &hash(23), 3, get), "branch block at height 3");
        assert!(!a.is_av_ancestor(&hash(5), 4, &hash(6), 5, get), "above the AV height");
    }

    #[test]
    fn the_assumevalid_block_on_the_best_header_chain() {
        let idx = fixture();
        let get = |h: &BlockHash| idx.get(h).cloned();
        let mut a = AvAncestry::default();
        assert!(a.av_on_best_chain(&hash(5), 4, &hash(8), 7, get));
        // A descendant of the last best header: the short walk.
        assert!(a.av_on_best_chain(&hash(5), 4, &hash(10), 9, get));
        // The branch: not on it, and the cache follows the new best header.
        assert!(!a.av_on_best_chain(&hash(5), 4, &hash(29), 9, get));
        assert!(!a.av_on_best_chain(&hash(5), 4, &hash(29), 9, get));
        // Back on the main chain.
        assert!(a.av_on_best_chain(&hash(5), 4, &hash(9), 8, get));
        // A best header below the AV height cannot carry it.
        assert!(!a.av_on_best_chain(&hash(5), 4, &hash(3), 2, get));
    }

    /// A gap in the index answers "not an ancestor" and is not cached: once
    /// the entry is there, the answer is right.
    #[test]
    fn a_gap_in_the_index_is_not_cached() {
        let mut idx = fixture();
        let missing = idx.remove(&hash(3)).unwrap();
        let mut a = AvAncestry::default();
        assert!(!a.is_av_ancestor(&hash(5), 4, &hash(2), 1, |h: &BlockHash| idx.get(h).cloned()));
        idx.insert(hash(3), missing);
        assert!(a.is_av_ancestor(&hash(5), 4, &hash(2), 1, |h: &BlockHash| idx.get(h).cloned()));
    }

    /// The first decision is logged even when it is a skip, and a decision
    /// is logged again only when it changes (Core's
    /// `m_last_script_check_reason_logged`, an empty `std::optional` at
    /// first). `feature_assumevalid.py` expects "Disabling script
    /// verification at block #1".
    #[test]
    fn the_first_decision_is_logged_whatever_it_is() {
        let mut a = AvAncestry::default();
        assert_eq!(a.last_logged, None);
        a.log_reason(1, &hash(1), None);
        assert_eq!(a.last_logged, Some(None), "a first skip is logged");
        a.log_reason(2, &hash(2), Some(TOO_RECENT));
        assert_eq!(a.last_logged, Some(Some(TOO_RECENT)));
    }

    /// `BlockRequestAllowed`'s bound: 30 days at 600 s a block is 4320
    /// blocks of the best header's work, and Core refuses at exactly that.
    #[test]
    fn thirty_days_of_work_is_cores_inclusive_bound() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let proof = u128::from_be_bytes(work_for_bits(bits)[16..].try_into().unwrap());
        let block = u256(1000);
        let month = 30 * 24 * 60 * 60;
        assert!(proof_equivalent_time_at_least(&u256(1000 + 4320 * proof), &block, bits, month));
        assert!(!proof_equivalent_time_at_least(&u256(1000 + 4320 * proof - 1), &block, bits, month));
        assert!(!proof_equivalent_time_at_least(&block, &u256(1000 + 4320 * proof), bits, month), "less work on top");
    }

    #[test]
    fn a_difference_beyond_u128_is_more_than_two_weeks() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut big = [0u8; 32];
        big[0] = 1;
        assert!(more_than_two_weeks_on_top(&big, &u256(0), bits));
    }
}
