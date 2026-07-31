//! Chain selection for `-reindex-chainstate`.
//!
//! `-reindex-chainstate` clears the UTXO set and undo data but keeps the block
//! index, then replays the chain to rebuild the chainstate. The question that
//! has repeatedly gone wrong is *which* chain it replays.
//!
//! The obvious answer — walk the height→hash index, height 1, 2, 3, … — is the
//! wrong one. That index is derived state. It names the active chain, and it
//! has been observed polluted with a fork block in production (#322, and the
//! `bad-cb-height` reindex loop that followed it). A replay that trusts it will
//! happily connect a block from one branch and then continue with another on
//! top of it: `bad-txns-inputs-missingorspent` if the two happen to conflict,
//! and a silently corrupt UTXO set if they do not.
//!
//! So the plan is derived from the block index itself, which is
//! self-authenticating in the ways that matter here — every entry carries the
//! block header, and a header names its parent by hash. Selection recomputes
//! cumulative chainwork from those headers rather than trusting the stored
//! `chainwork` and `height` fields, so a damaged index cannot misdirect the
//! replay through them either.
//!
//! The sibling planner for `-reindex` (which has no block index to work from
//! and scans the flat files instead) lives in
//! `ChainState::plan_reindex_chain`. Same shape, different input.

use std::collections::HashMap;

use bitcoin::BlockHash;

use crate::storage::Store;
use crate::storage::blockindex::{BlockStatus, add_u256, work_for_bits};

/// The chain a chainstate reindex will replay: `hashes[h]` is the block to
/// connect at height `h`, with `hashes[0]` the genesis block.
pub struct ReplayPlan {
    hashes: Vec<BlockHash>,
}

impl ReplayPlan {
    /// The block to connect at `height`, or `None` past the plan's tip.
    pub fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.hashes.get(height as usize).copied()
    }

    /// Height of the selected tip. Zero for a genesis-only index.
    pub fn tip_height(&self) -> u32 {
        // A plan always contains genesis, so the subtraction cannot wrap.
        (self.hashes.len() as u32).saturating_sub(1)
    }

    /// The selected tip's hash.
    pub fn tip_hash(&self) -> BlockHash {
        // Same invariant: `hashes` is never empty.
        self.hashes[self.hashes.len() - 1]
    }
}

/// One replayable block index entry, reduced to what selection needs.
struct Node {
    prev: BlockHash,
    bits: bitcoin::pow::CompactTarget,
    /// Memoized result of the ancestry walk:
    ///   * `None` — not resolved yet
    ///   * `Some(None)` — not connectable (some ancestor is missing, header-only,
    ///     invalid or pruned)
    ///   * `Some(Some(work))` — connectable, with cumulative chainwork measured
    ///     from genesis (genesis contributing zero, a constant offset shared by
    ///     every candidate)
    resolved: Option<Option<[u8; 32]>>,
}

/// Build the replay plan by selecting the most-work fully-connectable branch in
/// the block index.
///
/// Only `DataStored`/`Valid` entries are eligible: a `HeaderOnly` block has no
/// data to replay, and `Invalid`/`Pruned` must not be replayed at all. Because
/// eligibility is checked on every ancestor, excluding a block automatically
/// excludes its descendants — an `invalidateblock` still holds across a
/// chainstate reindex.
///
/// On an exact chainwork tie `incumbent` — the block the chainstate was already
/// at — wins, so a reindex never switches a node onto an equal-work sibling it
/// had already declined. That is the rule `find_best_valid_tip` implements on
/// the live path by returning the active tip. Remaining ties fall back to the
/// lowest block hash: `for_each_block_index` has no defined iteration order, so
/// unlike the flat-file planner there is no meaningful "first seen" to prefer,
/// and hash order at least makes the choice deterministic across runs.
///
/// Memory at the current mainnet height (~950k eligible blocks, which hashbrown
/// rounds up to 2^21 buckets): `nodes` is ~220 MB, plus ~33 MB each for `all`,
/// the ancestry `stack`, the reversed path and the returned `hashes` — roughly
/// **350 MB peak**. All of it is dropped before the caller enters BulkLoad and
/// starts filling the coin cache.
pub fn plan_replay_from_block_index(
    store: &dyn Store,
    genesis: BlockHash,
    incumbent: Option<BlockHash>,
) -> Result<ReplayPlan, crate::storage::StoreError> {
    let mut nodes: HashMap<BlockHash, Node> = HashMap::new();
    let mut all: Vec<BlockHash> = Vec::new();
    store.for_each_block_index(&mut |hash, entry| {
        if !matches!(entry.status, BlockStatus::DataStored | BlockStatus::Valid) {
            return;
        }
        // Selection is driven by `bits`, so `bits` has to be backed by work
        // that was actually done. A corrupted header — in a damaged index, or
        // one rebuilt from a damaged flat file — can otherwise claim an
        // astronomical target and win every comparison. Re-deriving the hash
        // and checking it against the claimed target makes forged work
        // impossible: a harder claimed target the block does not meet is
        // rejected outright, and an easier one only lowers its own score.
        if crate::validation::pow::check_proof_of_work(&entry.header).is_err() {
            tracing::warn!(
                block = %hash,
                "reindex: block index entry fails proof of work; excluding it from chain selection"
            );
            return;
        }
        all.push(hash);
        nodes.insert(
            hash,
            Node {
                prev: entry.header.prev_blockhash,
                bits: entry.header.bits,
                resolved: None,
            },
        );
    })?;
    // Deterministic tie-breaks and a deterministic walk order regardless of how
    // the backend enumerated the index.
    all.sort_unstable();

    // Resolve each block's ancestry to genesis, memoizing so the whole pass is
    // linear in the number of blocks rather than quadratic in chain length.
    let node_count = nodes.len();
    for start in &all {
        if nodes.get(start).is_some_and(|n| n.resolved.is_some()) {
            continue;
        }
        let mut stack: Vec<BlockHash> = Vec::new();
        let mut cursor = *start;
        let base = loop {
            if cursor == genesis {
                break Some([0u8; 32]);
            }
            match nodes.get(&cursor) {
                // Ancestry leaves the replayable set: this branch cannot be
                // replayed, and neither can anything descending from it.
                None => break None,
                Some(n) => match n.resolved {
                    Some(known) => break known,
                    None => {
                        // A prev-hash chain cannot cycle (that would need a hash
                        // preimage), but a damaged index should not be able to
                        // hang startup either.
                        if stack.len() > node_count {
                            break None;
                        }
                        stack.push(cursor);
                        cursor = n.prev;
                    }
                },
            }
        };
        let mut acc = base;
        while let Some(hash) = stack.pop() {
            if let Some(node) = nodes.get_mut(&hash) {
                acc = acc.map(|w| add_u256(&w, &work_for_bits(node.bits)));
                node.resolved = Some(acc);
            }
        }
    }

    // Most work wins; ties by hash. `all` is sorted, so scanning it and taking
    // strictly-greater work leaves the lowest hash of an equal-work set.
    let mut best: Option<(BlockHash, [u8; 32])> = None;
    for hash in &all {
        let Some(Some(work)) = nodes.get(hash).and_then(|n| n.resolved) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some((best_hash, best_work)) => {
                match crate::chain::state::compare_u256(&work, best_work) {
                    1 => true,
                    // Exact tie: the branch the node was already on wins, and
                    // never loses to a later candidate. Same rule as
                    // `find_best_valid_tip`, which returns the active tip
                    // rather than switching on equal work.
                    0 => Some(*hash) == incumbent && Some(*best_hash) != incumbent,
                    _ => false,
                }
            }
        };
        if better {
            best = Some((*hash, work));
        }
    }

    // Walk back to genesis through parent pointers, then reverse.
    let mut hashes = vec![genesis];
    if let Some((tip, _)) = best {
        let mut path = Vec::new();
        let mut cursor = tip;
        while cursor != genesis {
            path.push(cursor);
            match nodes.get(&cursor) {
                Some(n) => cursor = n.prev,
                // Unreachable: `tip` resolved, so every ancestor is present.
                None => break,
            }
        }
        path.reverse();
        hashes.extend(path);
    }
    Ok(ReplayPlan { hashes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::BlockIndexEntry;
    use crate::storage::db::InMemoryStore;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;

    // Both targets must be cheap to mine, since every synthetic header below is
    // ground until it satisfies its own claimed target — the planner now
    // rejects entries whose PoW does not back their `bits`.
    const EASY: u32 = 0x207fffff; // regtest floor
    const HARDER: u32 = 0x201fffff; // a quarter of EASY's target => 4x the work

    fn h(n: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([n; 32]))
    }

    /// Insert a block index entry. `height` and `chainwork` are deliberately
    /// callers' choice — the planner recomputes both from headers, and the
    /// tests below feed it wrong values to prove it.
    fn put(
        store: &InMemoryStore,
        hash: BlockHash,
        prev: BlockHash,
        bits: u32,
        status: BlockStatus,
        stored_height: u32,
        stored_work: [u8; 32],
    ) {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x20000000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
            ),
            time: 0,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        };
        // Grind until the header actually meets the target it claims. The
        // planner excludes entries whose PoW does not back their `bits`, which
        // is what stops a corrupted header from claiming astronomical work, so
        // the fixtures have to be honestly mined.
        let mut nonce = 0u32;
        loop {
            header.nonce = nonce;
            if crate::validation::pow::check_proof_of_work(&header).is_ok() {
                break;
            }
            nonce = nonce.checked_add(1).expect("failed to mine test header");
        }
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            hash,
            BlockIndexEntry {
                header,
                height: stored_height,
                status,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: stored_work,
            },
        ));
        store.write_batch(batch).unwrap();
    }

    fn chain(store: &InMemoryStore, spec: &[(BlockHash, BlockHash, u32, BlockStatus)]) {
        for (hash, prev, bits, status) in spec {
            put(store, *hash, *prev, *bits, *status, 0, [0u8; 32]);
        }
    }

    /// Selection is by recomputed cumulative chainwork, so a single block at a
    /// harder target (4x the work) beats two at an easy one. Picking by depth —
    /// or by walking the height→hash index — would replay the wrong branch.
    #[test]
    fn picks_most_work_not_deepest() {
        let store = InMemoryStore::new();
        let (genesis, deep1, deep2, heavy) = (h(0), h(1), h(2), h(3));
        chain(&store, &[
            (deep1, genesis, EASY, BlockStatus::Valid),
            (deep2, deep1, EASY, BlockStatus::Valid),
            (heavy, genesis, HARDER, BlockStatus::Valid),
        ]);

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_height(), 1);
        assert_eq!(plan.tip_hash(), heavy);
        assert_eq!(plan.hash_at(0), Some(genesis));
        assert_eq!(plan.hash_at(1), Some(heavy));
        assert_eq!(plan.hash_at(2), None);
    }

    /// The stored `height` and `chainwork` fields are derived state like the
    /// height→hash index, and a damaged index can carry wrong ones. The planner
    /// recomputes from headers, so lies in those fields cannot misdirect it.
    #[test]
    fn ignores_stored_height_and_chainwork_fields() {
        let store = InMemoryStore::new();
        let (genesis, a, b, liar) = (h(0), h(1), h(2), h(3));
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            (b, a, EASY, BlockStatus::Valid),
        ]);
        // A one-block branch claiming enormous chainwork and an absurd height.
        put(&store, liar, genesis, EASY, BlockStatus::Valid, 9_999, [0xffu8; 32]);

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(
            plan.tip_hash(),
            b,
            "the real two-block branch must win over a forged chainwork field"
        );
        assert_eq!(plan.tip_height(), 2);
    }

    /// An `invalidateblock` must survive a chainstate reindex: the invalid
    /// block is not replayable, and neither is anything descending from it.
    #[test]
    fn invalid_block_excludes_its_descendants() {
        let store = InMemoryStore::new();
        let (genesis, a, bad, after_bad, side) = (h(0), h(1), h(2), h(3), h(4));
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            // Longer, but rooted in an invalidated block.
            (bad, a, EASY, BlockStatus::Invalid),
            (after_bad, bad, EASY, BlockStatus::Valid),
            (side, a, EASY, BlockStatus::Valid),
        ]);

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_hash(), side);
        assert_eq!(plan.tip_height(), 2);
    }

    /// A branch whose ancestry has a hole (a header-only block, no data to
    /// replay) is not connectable, so a shorter fully-present branch wins.
    #[test]
    fn header_only_gap_makes_a_branch_unconnectable() {
        let store = InMemoryStore::new();
        let (genesis, a, gap, past_gap, short) = (h(0), h(1), h(2), h(3), h(4));
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            (gap, a, EASY, BlockStatus::HeaderOnly),
            (past_gap, gap, EASY, BlockStatus::Valid),
            (short, a, EASY, BlockStatus::Valid),
        ]);

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_hash(), short);
        assert_eq!(plan.tip_height(), 2);
    }

    /// Equal-work branches resolve to the lowest block hash. The block index
    /// has no defined iteration order, so the choice has to come from the data
    /// itself or the replay is nondeterministic across runs.
    #[test]
    fn equal_work_tie_breaks_by_hash_deterministically() {
        let (genesis, a, low, high) = (h(0), h(1), h(2), h(9));
        for _ in 0..8 {
            let store = InMemoryStore::new();
            // Insert in the "wrong" order too; the result must not depend on it.
            chain(&store, &[
                (a, genesis, EASY, BlockStatus::Valid),
                (high, a, EASY, BlockStatus::Valid),
                (low, a, EASY, BlockStatus::Valid),
            ]);
            let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
            assert_eq!(plan.tip_hash(), low);
        }
    }

    /// On an exact chainwork tie the incumbent — the chain the node was already
    /// on — wins, regardless of hash order. Without this a node holding a
    /// fully-received equal-work stale sibling at its tip would, on a coin
    /// flip, rebuild its chainstate onto the orphan.
    #[test]
    fn incumbent_wins_an_exact_tie() {
        let (genesis, a, low, high) = (h(0), h(1), h(2), h(9));
        // `high` is the incumbent even though `low` sorts first, so hash order
        // and incumbent order disagree and only the incumbent rule can win.
        let store = InMemoryStore::new();
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            (low, a, EASY, BlockStatus::Valid),
            (high, a, EASY, BlockStatus::Valid),
        ]);
        let plan = plan_replay_from_block_index(&store, genesis, Some(high)).unwrap();
        assert_eq!(
            plan.tip_hash(),
            high,
            "an equal-work sibling must not displace the chain the node was on"
        );
        // And with no incumbent the deterministic hash rule still applies.
        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_hash(), low);
    }

    /// A header whose `bits` claims work it did not do must not be able to buy
    /// the selection. `bits` is the only input to the work calculation, and a
    /// corrupt index or flat file can produce a well-formed header claiming an
    /// astronomical target — which would otherwise out-score the honest chain
    /// and be replayed as the active one.
    #[test]
    fn forged_work_without_proof_is_excluded() {
        let store = InMemoryStore::new();
        let (genesis, a, b, forger) = (h(0), h(1), h(2), h(3));
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            (b, a, EASY, BlockStatus::Valid),
        ]);
        // Claims a target ~2^32 times harder than the honest chain's, with a
        // nonce that does not meet it — the shape a flipped exponent byte
        // produces. `chain()` mines; this deliberately does not.
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            forger,
            BlockIndexEntry {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(0x20000000),
                    prev_blockhash: genesis,
                    merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                    ),
                    time: 0,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 0,
                },
                height: 1,
                status: BlockStatus::Valid,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            },
        ));
        store.write_batch(batch).unwrap();

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(
            plan.tip_hash(),
            b,
            "a header claiming unearned work must not win selection"
        );
    }

    /// A block whose parent is absent from the index entirely is unreachable
    /// from genesis and must not be selected.
    #[test]
    fn orphan_strand_is_not_selected() {
        let store = InMemoryStore::new();
        let (genesis, a, orphan_root, x, y) = (h(0), h(1), h(100), h(101), h(102));
        chain(&store, &[
            (a, genesis, EASY, BlockStatus::Valid),
            // orphan_root's parent (h(99)) is not in the index.
            (orphan_root, h(99), EASY, BlockStatus::Valid),
            (x, orphan_root, EASY, BlockStatus::Valid),
            (y, x, EASY, BlockStatus::Valid),
        ]);

        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_hash(), a);
        assert_eq!(plan.tip_height(), 1);
    }

    /// Degenerate input: an index with nothing but genesis plans a no-op
    /// replay rather than panicking or selecting nothing.
    #[test]
    fn genesis_only_index_plans_an_empty_replay() {
        let store = InMemoryStore::new();
        let genesis = h(0);
        let plan = plan_replay_from_block_index(&store, genesis, None).unwrap();
        assert_eq!(plan.tip_height(), 0);
        assert_eq!(plan.tip_hash(), genesis);
        assert_eq!(plan.hash_at(1), None);
    }
}
