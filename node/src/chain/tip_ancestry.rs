//! Audit of the tip's ancestry: every recent ancestor must be a block this
//! chainstate actually connected.
//!
//! `BlockStatus::Valid` is written in exactly one place — `connect_block` —
//! and nothing ever downgrades it. `disconnect_block` writes no status at all,
//! and `accept_block` returns `Duplicate` before reaching its side-chain
//! `DataStored` write for any entry that is not `HeaderOnly`. So a `DataStored`
//! entry has never been connected in this chainstate, and a `DataStored`
//! *ancestor of the tip* means the tip is standing on blocks whose UTXO deltas
//! were never applied.
//!
//! That is not hypothetical. On a synced mainnet node the persisted tip was
//! eight blocks above the last block it had actually connected: the tip read
//! `Valid`, its eight ancestors read `DataStored`, and the ancestor below them
//! read `Valid` again. Every output created in that eight-block window was
//! absent from the UTXO set. The node reported a healthy synced tip on a real
//! canonical block, `getblockchaininfo` was self-consistent, and `/healthz`
//! stayed green for five and a half hours. Nothing detected it; what finally
//! surfaced it was the next block happening to spend one of the dropped
//! outputs, which wedged the connector on
//! `bad-txns-inputs-missingorspent`. Had it not, the node would have served
//! wrong `gettxout` answers indefinitely.
//!
//! This pass is the detector that was missing. It answers wrong rather than
//! not at all: a node that fails it is refusing to serve, not quietly serving
//! a truncated UTXO set.
//!
//! ## What it does not do
//!
//! It does not repair. The remedy for a hole is to replay the missing blocks,
//! which means connecting them — real validation work with real coin writes,
//! not the derived-state rewrite that [`crate::chain::height_index_repair`]
//! performs. Detecting reliably and refusing loudly is the whole job here.
//!
//! ## Distinguishing a hole from an unvalidated floor
//!
//! An AssumeUTXO node legitimately has unvalidated ancestors: everything below
//! the snapshot base reads `DataStored`/`HeaderOnly` until the background
//! chainstate works through it. That must not be mistaken for damage.
//!
//! The discriminator needs no snapshot plumbing, because the two shapes differ
//! structurally. Unvalidated history is a *floor* — one contiguous run of
//! non-`Valid` ancestors extending down from some point, with nothing
//! connected beneath it. A hole has connected blocks on **both** sides. So:
//!
//! > a non-`Valid` ancestor is a fault if and only if some ancestor beneath it
//! > within the window is `Valid`.
//!
//! Anything below the lowest `Valid` ancestor is reported as a floor and is
//! not a fault. When the window is too short to see a `Valid` block beneath an
//! unvalidated run, the run is classified as a floor — the conservative
//! direction, since the cost of a false floor is a missed detection while the
//! cost of a false hole is refusing to start a healthy node.
//!
//! The snapshot base itself is the one block the structural rule cannot
//! classify, because it sits at the *top* of the unvalidated run rather than
//! inside it: right after `loadtxoutset` the base is the tip, with nothing
//! connected above it to make it a hole and nothing connected below it to make
//! it a floor. Its coins are present — streamed in wholesale — so the caller
//! passes it in and it counts as connected until the background chainstate
//! writes `Valid` over it.

use bitcoin::BlockHash;

use crate::storage::Store;
use crate::storage::blockindex::BlockStatus;

/// How many ancestors below the tip to check.
///
/// This class of damage is created at the tip, by the interaction of block
/// connection with reorgs and cache flushes, so a bounded window near the tip
/// is where it can be. Below that, `Valid` is what every ancestor reads
/// whether or not its coins are intact, so walking further buys no detection —
/// only cost.
///
/// One retarget period. At one block-index point lookup per height, served
/// from the block cache and the in-memory overlay, the whole pass is
/// microseconds-per-block against a startup that is already doing far more.
pub const DEFAULT_ANCESTRY_WINDOW: u32 = 2016;

/// An ancestor of the tip that this chainstate never connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnconnectedAncestor {
    pub height: u32,
    pub hash: BlockHash,
    pub status: BlockStatus,
}

/// Why the ancestry walk stopped before exhausting its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkBreak {
    /// An ancestor named by a parent pointer has no block-index entry. The
    /// chain of parent pointers is broken.
    MissingEntry { height: u32, hash: BlockHash },
    /// An ancestor's entry reports a height that disagrees with the walk.
    HeightMismatch {
        expected: u32,
        found: u32,
        hash: BlockHash,
    },
}

/// Result of one ancestry audit.
#[derive(Debug, Clone, Default)]
pub struct TipAncestryAudit {
    /// Ancestors inspected, including the tip itself.
    pub blocks_checked: u32,
    /// Lowest height the walk reached.
    pub lowest_height: u32,
    /// Ancestors never connected in this chainstate that have a connected
    /// ancestor beneath them. Each one is a block whose UTXO delta is missing
    /// from a chain the node is presenting as active.
    pub holes: Vec<UnconnectedAncestor>,
    /// The contiguous run of never-connected ancestors at the bottom of the
    /// walk, with nothing connected beneath it. The ordinary shape of an
    /// AssumeUTXO snapshot's unvalidated history; not a fault.
    pub unvalidated_floor: Vec<UnconnectedAncestor>,
    /// Set when the walk stopped early.
    pub broken: Option<WalkBreak>,
    pub elapsed_ms: u64,
}

impl TipAncestryAudit {
    /// True when the tip stands on a fully connected chain, as far as the
    /// window can see.
    pub fn is_intact(&self) -> bool {
        self.holes.is_empty() && self.broken.is_none()
    }
}

/// Walk `window` ancestors down from the tip and classify every one that this
/// chainstate never connected.
///
/// `tip_hash` must be the block at `tip_height`. `snapshot_base` is the
/// AssumeUTXO base block when a background chainstate is attached, and counts
/// as connected — see the module docs.
pub fn audit_tip_ancestry(
    store: &dyn Store,
    tip_hash: BlockHash,
    tip_height: u32,
    window: u32,
    snapshot_base: Option<BlockHash>,
) -> TipAncestryAudit {
    let started = std::time::Instant::now();
    let mut audit = TipAncestryAudit {
        lowest_height: tip_height,
        ..Default::default()
    };

    // Walk down from the tip by parent pointer. The active chain is the tip's
    // ancestry by definition, so no height-index row is consulted — the same
    // discipline `height_index_repair` applies, and for the same reason: the
    // height index is exactly the state that has been observed to lie.
    let mut chain: Vec<UnconnectedAncestor> = Vec::new();
    let mut cursor_hash = tip_hash;
    let mut cursor_height = tip_height;
    let stop_height = tip_height.saturating_sub(window.saturating_sub(1));

    loop {
        let Some(entry) = store.get_block_index(&cursor_hash) else {
            audit.broken = Some(WalkBreak::MissingEntry {
                height: cursor_height,
                hash: cursor_hash,
            });
            break;
        };
        if entry.height != cursor_height {
            audit.broken = Some(WalkBreak::HeightMismatch {
                expected: cursor_height,
                found: entry.height,
                hash: cursor_hash,
            });
            break;
        }

        chain.push(UnconnectedAncestor {
            height: cursor_height,
            hash: cursor_hash,
            status: entry.status,
        });
        audit.blocks_checked += 1;
        audit.lowest_height = cursor_height;

        if cursor_height == 0 || cursor_height == stop_height {
            break;
        }
        cursor_hash = entry.header.prev_blockhash;
        cursor_height -= 1;
    }

    // `chain` is ordered tip-first, so the LAST connected element is the
    // lowest-height one. Everything non-`Valid` above it is a hole; everything
    // below it is the unvalidated floor.
    //
    // `Pruned` counts as connected: pruning removes block data from a block
    // that was connected, and keeps its header. It never applies to a block
    // whose coins were not written. The snapshot base counts too — its coins
    // are present without this chainstate having connected it.
    let connected = |a: &UnconnectedAncestor| {
        matches!(a.status, BlockStatus::Valid | BlockStatus::Pruned)
            || snapshot_base == Some(a.hash)
    };

    match chain.iter().rposition(&connected) {
        Some(floor_idx) => {
            audit.holes = chain[..floor_idx]
                .iter()
                .filter(|a| !connected(a))
                .cloned()
                .collect();
            audit.unvalidated_floor = chain[floor_idx + 1..].to_vec();
        }
        None => {
            // Nothing in the window was connected here, so there is no
            // connected block beneath anything and the floor rule would excuse
            // the entire window. The tip itself is the exception that cannot
            // be excused: a node serving a tip it never connected is broken
            // whatever the reason, so report it as a hole and leave the rest
            // as floor.
            if let Some(tip) = chain.first() {
                audit.holes.push(tip.clone());
                audit.unvalidated_floor = chain[1..].to_vec();
            }
        }
    }

    // The walk runs tip-first; report ascending, which is how heights read.
    audit.holes.sort_unstable_by_key(|a| a.height);
    audit
        .unvalidated_floor
        .sort_unstable_by_key(|a| a.height);

    audit.elapsed_ms = started.elapsed().as_millis() as u64;
    audit
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    use crate::storage::StoreBatch;
    use crate::storage::blockindex::BlockIndexEntry;
    use crate::storage::db::InMemoryStore;

    fn header_with(prev: BlockHash, nonce: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
            ),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce,
        }
    }

    /// Build a linear chain of `n` blocks (heights 0..n-1) all `Valid`, and
    /// return their hashes indexed by height.
    fn chain_of(store: &InMemoryStore, n: u32) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let mut prev = BlockHash::from_byte_array([0u8; 32]);
        let mut batch = StoreBatch::default();
        for h in 0..n {
            let header = header_with(prev, h);
            let hash = header.block_hash();
            batch.block_index_puts.push((
                hash,
                BlockIndexEntry {
                    header,
                    height: h,
                    status: BlockStatus::Valid,
                    num_tx: 1,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                },
            ));
            hashes.push(hash);
            prev = hash;
        }
        store.write_batch(batch).unwrap();
        hashes
    }

    fn set_status(store: &InMemoryStore, hash: BlockHash, status: BlockStatus) {
        let mut entry = store.get_block_index(&hash).unwrap();
        entry.status = status;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        store.write_batch(batch).unwrap();
    }

    #[test]
    fn clean_chain_is_intact() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);
        assert!(audit.is_intact());
        assert!(audit.holes.is_empty());
        assert!(audit.unvalidated_floor.is_empty());
        assert_eq!(audit.blocks_checked, 50);
        assert_eq!(audit.lowest_height, 0);
    }

    /// The mainnet incident, in miniature: a run of never-connected ancestors
    /// with a connected block on both sides.
    #[test]
    fn datastored_run_below_a_valid_tip_is_a_hole() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[40..=47] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);

        assert!(!audit.is_intact());
        let heights: Vec<u32> = audit.holes.iter().map(|a| a.height).collect();
        assert_eq!(heights, (40..=47).collect::<Vec<_>>());
        assert!(audit.unvalidated_floor.is_empty());
    }

    /// An AssumeUTXO node: everything below the snapshot base is unvalidated,
    /// with nothing connected beneath. Not a fault.
    #[test]
    fn unvalidated_history_below_the_tip_is_a_floor_not_a_hole() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[0..40] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);

        assert!(audit.is_intact(), "unvalidated history must not fail the audit");
        assert!(audit.holes.is_empty());
        assert_eq!(audit.unvalidated_floor.len(), 40);
    }

    /// A hole ABOVE an unvalidated floor is still a hole: the floor excuses
    /// only what is beneath the lowest connected block.
    #[test]
    fn hole_above_a_floor_is_still_reported() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[0..30] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        for hash in &hashes[40..=44] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);

        assert!(!audit.is_intact());
        let heights: Vec<u32> = audit.holes.iter().map(|a| a.height).collect();
        assert_eq!(heights, (40..=44).collect::<Vec<_>>());
        assert_eq!(audit.unvalidated_floor.len(), 30);
    }

    /// A window too short to reach a connected block beneath an unvalidated
    /// run classifies it as a floor. Conservative: a false floor misses a
    /// detection, a false hole refuses to start a healthy node.
    #[test]
    fn short_window_prefers_floor_over_hole() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[40..=47] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        // Window covers 49..=45 only, so height 39 (Valid) is never seen.
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 5, None);

        assert!(audit.is_intact());
        assert_eq!(audit.blocks_checked, 5);
        assert_eq!(audit.lowest_height, 45);
        assert_eq!(audit.unvalidated_floor.len(), 3);
    }

    /// A tip that was never connected fails even with no connected block
    /// anywhere in the window to compare against.
    #[test]
    fn unconnected_tip_fails_with_no_valid_block_in_window() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[0..50] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);

        assert!(!audit.is_intact());
        assert_eq!(audit.holes.len(), 1);
        assert_eq!(audit.holes[0].height, 49);
    }

    /// `Pruned` blocks were connected; their data was removed afterwards.
    #[test]
    fn pruned_ancestors_count_as_connected() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[10..40] {
            set_status(&store, *hash, BlockStatus::Pruned);
        }
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);
        assert!(audit.is_intact());
        assert!(audit.unvalidated_floor.is_empty());
    }

    /// An `Invalid` ancestor of the active tip is a hole: `invalidate_block`
    /// is supposed to have driven a reorg away from it.
    #[test]
    fn invalid_ancestor_is_a_hole() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        set_status(&store, hashes[45], BlockStatus::Invalid);
        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);

        assert!(!audit.is_intact());
        assert_eq!(audit.holes.len(), 1);
        assert_eq!(audit.holes[0].status, BlockStatus::Invalid);
    }

    #[test]
    fn broken_parent_pointer_is_reported() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        // Point 45's parent at a block that does not exist.
        let mut entry = store.get_block_index(&hashes[45]).unwrap();
        entry.header.prev_blockhash = BlockHash::from_byte_array([0xab; 32]);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hashes[45], entry));
        store.write_batch(batch).unwrap();

        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);
        assert!(!audit.is_intact());
        assert!(matches!(
            audit.broken,
            Some(WalkBreak::MissingEntry { height: 44, .. })
        ));
    }

    #[test]
    fn height_disagreement_stops_the_walk() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        let mut entry = store.get_block_index(&hashes[45]).unwrap();
        entry.height = 999;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hashes[45], entry));
        store.write_batch(batch).unwrap();

        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);
        assert!(!audit.is_intact());
        assert!(matches!(
            audit.broken,
            Some(WalkBreak::HeightMismatch {
                expected: 45,
                found: 999,
                ..
            })
        ));
    }

    /// Immediately after `loadtxoutset` the tip IS the snapshot base, whose
    /// entry is still `DataStored` and which has nothing connected above or
    /// below it. Without the exemption this is the "no connected block in the
    /// window" case and the node refuses to start.
    #[test]
    fn snapshot_base_as_tip_is_not_a_hole() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[0..=49] {
            set_status(&store, *hash, BlockStatus::HeaderOnly);
        }
        set_status(&store, hashes[49], BlockStatus::DataStored);

        // Perturbation: without the base passed in, this same state fails.
        let without = audit_tip_ancestry(&store, hashes[49], 49, 2016, None);
        assert!(!without.is_intact());

        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, Some(hashes[49]));
        assert!(audit.is_intact());
        assert!(audit.holes.is_empty());
        assert_eq!(audit.unvalidated_floor.len(), 49);
    }

    /// The exemption covers exactly one block. A hole above the base is still
    /// a hole.
    #[test]
    fn snapshot_base_does_not_excuse_a_hole_above_it() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 50);
        for hash in &hashes[0..40] {
            set_status(&store, *hash, BlockStatus::HeaderOnly);
        }
        // Base at 40, still unvalidated; live chain connected 41..=49 on top,
        // except for a run that never connected.
        set_status(&store, hashes[40], BlockStatus::DataStored);
        for hash in &hashes[45..=47] {
            set_status(&store, *hash, BlockStatus::DataStored);
        }

        let audit = audit_tip_ancestry(&store, hashes[49], 49, 2016, Some(hashes[40]));
        assert!(!audit.is_intact());
        let heights: Vec<u32> = audit.holes.iter().map(|a| a.height).collect();
        assert_eq!(heights, vec![45, 46, 47]);
        assert_eq!(audit.unvalidated_floor.len(), 40);
    }

    /// Genesis terminates the walk without a break.
    #[test]
    fn walk_stops_at_genesis() {
        let store = InMemoryStore::new();
        let hashes = chain_of(&store, 3);
        let audit = audit_tip_ancestry(&store, hashes[2], 2, 2016, None);
        assert!(audit.is_intact());
        assert_eq!(audit.blocks_checked, 3);
        assert_eq!(audit.lowest_height, 0);
        assert!(audit.broken.is_none());
    }
}
