//! Audit and repair of the height→hash index.
//!
//! The height index is *derived* state: for every height at or below the
//! tip there must be exactly one row, and its value is recoverable from the
//! block index alone by following parent pointers. Nothing about it is
//! authoritative, which is what makes repairing it in place safe — and what
//! makes leaving it damaged unnecessary.
//!
//! Rows have gone missing for real. A reorg used to emit a remove for the
//! displaced block at height H and a put for the replacement at height H into
//! the same coalesced write batch, and every batch applies its puts before
//! its removes, so the remove annihilated a row that should have survived.
//! That defect is fixed at the source; this module exists because the damage
//! it already did is invisible and persistent. Two heights in the middle of a
//! healthy active chain on a synced mainnet node answered `getblockhash` with
//! `-8: Block height out of range`, and the only cure was a full reindex.
//!
//! A missing row is not merely cosmetic: `median_time_past` resolves its
//! eleven-block window through this index on the connect path, and MTP gates
//! BIP 113 locktimes and BIP 68 sequence locks.
//!
//! ## What this does and does not touch
//!
//! Every gap is derived from the tip's ancestry, never from a neighbouring
//! index row — the active chain is the tip's ancestry by definition, so no
//! row this module distrusts is ever consulted as an anchor.
//!
//! It only **adds rows for heights that have none**. A height whose row is
//! present but *wrong* is left alone. That is a different failure (the
//! `accept_header` clobber of #322, since fixed) and repairing it means
//! adjudicating between competing blocks by chainwork rather than reading a
//! parent pointer — a decision this pass is deliberately not equipped to
//! make. Silently overwriting a row the node believes in would be a worse
//! failure than the gap.
//!
//! ## Cost
//!
//! One sequential scan of the height index — the cheap direction, versus a
//! point lookup per height. On a clean node it allocates a presence bitmap,
//! finds nothing, and writes nothing.
//!
//! When there is damage, the walk adds one block-index read per height between
//! the tip and the *lowest* gap. That is set by where the damage reaches, not
//! by how much of it there is: a thousand gaps clustered under the tip are
//! cheaper to repair than one gap near genesis.

use std::collections::{HashMap, HashSet};

use bitcoin::BlockHash;

use crate::storage::blockindex::BlockStatus;
use crate::storage::{HeightHashScanStats, Store, StoreBatch, StoreError};

/// Refuse to allocate a presence map for an implausible tip height. The tip
/// height is read from the chainstate, so a corrupt value must not be able to
/// turn a startup audit into a multi-gigabyte allocation. Ten million blocks
/// is roughly two centuries of mainnet.
const MAX_PLAUSIBLE_TIP_HEIGHT: u32 = 10_000_000;

/// Above this share of the heights at or below the tip being absent, the pass
/// reports and does nothing.
///
/// This is a **cost** guard, and saying so is the point: it used to be an
/// absolute count of a thousand gaps, which bounded neither cost nor risk.
///
/// Not cost, because the walk is one block-index read per height between the
/// tip and the *lowest* gap — a single gap far down costs more than ten
/// thousand clustered near the tip, and a count guard waves the first through
/// and stops the second. Not risk, because safety here is enforced per height
/// and does not consult this number at all: a row is written only for a block
/// the walk reached along the tip's own ancestry whose status is `Valid` or
/// `Pruned`, so a chainstate that has not validated its history writes nothing
/// however this is set.
///
/// What a threshold can still usefully decide is whether the operation is a
/// repair at all. Half the range absent is a rebuild, and a pass that runs on
/// every start should not quietly undertake one. Real damage sits nowhere near
/// that line: a node on a reorg-heavy chain accumulated 3009 gaps confined to
/// its top 10k heights — two percent of the range, one sub-second walk — and
/// the old count declined it on every restart while logging that an AssumeUTXO
/// snapshot the node had never loaded was the likely cause.
const MAX_MISSING_PERCENT: usize = 50;

/// Result of one audit pass.
#[derive(Debug, Clone, Default)]
pub struct HeightIndexAudit {
    /// Rows seen during the scan, including any above the tip.
    pub rows_scanned: u64,
    /// Heights at or below the tip with no row at all.
    pub missing: Vec<u32>,
    /// Heights whose row this pass rederived and wrote.
    pub repaired: Vec<u32>,
    /// Heights that are missing and could not be rederived. Each is left
    /// untouched; the block index does not contain enough to rebuild them,
    /// which means the damage is not the shape this pass understands.
    pub unrepairable: Vec<u32>,
    /// Heights whose present row disagrees with the tip's ancestry, within
    /// the range the walk covered. Reported, never overwritten: correcting one
    /// means adjudicating between branches by chainwork, which this pass does
    /// not do.
    pub mismatched: Vec<u32>,
    /// Heights whose block this node has not validated in this chainstate.
    /// Normal while an AssumeUTXO snapshot's history is still being verified
    /// in the background — the validator writes these rows itself. Reported
    /// separately from `unrepairable` because it is not a fault.
    pub pending_validation: Vec<u32>,
    /// Corrupt rows surfaced by the scan.
    pub scan_stats: HeightHashScanStats,
    /// Set when the missing share exceeded [`MAX_MISSING_PERCENT`] and the
    /// pass declined to write anything. `missing` is still populated, so the
    /// condition is reported rather than hidden.
    pub skipped_bulk: bool,
    /// The tip the audit ran against — the top of the range `missing` was
    /// computed over. Carried so a caller can report a gap count in
    /// proportion without redoing the arithmetic.
    pub tip_height: u32,
    pub elapsed_secs: u64,
}

impl HeightIndexAudit {
    /// True when the index is intact — the overwhelmingly common case, and
    /// the one where the caller should stay quiet.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.mismatched.is_empty()
            && self.scan_stats.skipped_bad_key == 0
            && self.scan_stats.skipped_bad_value == 0
    }
}

/// Scan the height index for gaps at or below `tip_height` and rederive
/// whatever can be rederived from the block index.
///
/// `tip_hash` must be the block at `tip_height`; it is the one anchor the
/// caller can supply that needs no lookup, and it covers the case where the
/// tip's own row is the missing one.
pub fn audit_and_repair_height_index(
    store: &dyn Store,
    tip_hash: BlockHash,
    tip_height: u32,
) -> Result<HeightIndexAudit, StoreError> {
    let started = std::time::Instant::now();

    if tip_height > MAX_PLAUSIBLE_TIP_HEIGHT {
        return Err(StoreError::Database(format!(
            "refusing height-index audit at implausible tip height {tip_height}"
        )));
    }

    // Presence bitmap over 0..=tip_height. One byte per height is ~1 MB at
    // mainnet scale, which is cheaper than the alternative of a point lookup
    // per height and far cheaper than being wrong about a gap.
    let mut present = vec![false; tip_height as usize + 1];
    let mut rows_scanned: u64 = 0;
    let scan_stats = store.for_each_height_hash(&mut |height, _hash| {
        rows_scanned += 1;
        if height <= tip_height {
            present[height as usize] = true;
        }
    })?;

    let missing: Vec<u32> = present
        .iter()
        .enumerate()
        .filter(|(_, seen)| !**seen)
        .map(|(h, _)| h as u32)
        .collect();

    let mut audit = HeightIndexAudit {
        rows_scanned,
        missing: missing.clone(),
        scan_stats,
        tip_height,
        ..Default::default()
    };

    if missing.is_empty() {
        audit.elapsed_secs = started.elapsed().as_secs();
        return Ok(audit);
    }

    // Proportional, never an absolute count — see `MAX_MISSING_PERCENT` for
    // why a count measures neither the cost nor the risk it appeared to.
    let heights_in_range = tip_height as usize + 1;
    if missing.len() * 100 > heights_in_range * MAX_MISSING_PERCENT {
        audit.skipped_bulk = true;
        audit.elapsed_secs = started.elapsed().as_secs();
        return Ok(audit);
    }

    // Derive every gap from the TIP'S ANCESTRY, not from neighbouring index
    // rows.
    //
    // An earlier version anchored each gap on the row one height above it and
    // read that block's parent pointer. That was wrong in two ways, both
    // demonstrated by the regression tests below. It trusted rows this very
    // module declares untrustworthy, so a fork block whose divergence point
    // was the gap itself satisfied every guard; and across a run of
    // consecutive gaps the corroborating check ran only at the bottom, so a
    // run could be written and only then discovered to be on the wrong branch.
    //
    // Walking down from the tip removes the whole class: the active chain IS
    // the tip's ancestry, by definition. No anchor row is consulted, so no
    // anchor row can be wrong.
    //
    // Cost is one block-index read per height between the tip and the lowest
    // gap, paid only when there is damage.
    let lowest = missing[0];
    let missing_set: HashSet<u32> = missing.iter().copied().collect();
    let mut derived: HashMap<u32, (BlockHash, BlockStatus)> = HashMap::new();

    let mut cursor_hash = tip_hash;
    let mut cursor_height = tip_height;
    loop {
        let Some(entry) = store.get_block_index(&cursor_hash) else {
            // The chain of parent pointers is broken. Everything at or below
            // here stays a gap rather than being guessed at.
            break;
        };
        if entry.height != cursor_height {
            // The index disagrees with the walk. Refuse to derive anything
            // further rather than trust a block that misreports its height.
            break;
        }
        if missing_set.contains(&cursor_height) {
            derived.insert(cursor_height, (cursor_hash, entry.status));
        } else if store
            .get_block_hash_by_height(cursor_height)
            .is_some_and(|row| row != cursor_hash)
        {
            // Present, but naming a block that is not the tip's ancestor at
            // this height. Surfacing it costs one lookup per walked height and
            // turns a silent #322-class pollution into something an operator
            // can see.
            audit.mismatched.push(cursor_height);
        }
        if cursor_height == lowest {
            break;
        }
        cursor_hash = entry.header.prev_blockhash;
        cursor_height -= 1;
    }

    let mut puts: Vec<(u32, BlockHash)> = Vec::new();
    for &h in &missing {
        match derived.get(&h) {
            // Never reached by the walk.
            None => audit.unrepairable.push(h),
            Some((hash, status)) => match status {
                // Connected in this chainstate. `Pruned` blocks keep their
                // header, which is all a height row needs.
                BlockStatus::Valid | BlockStatus::Pruned => puts.push((h, *hash)),
                // Downloaded or headers-only but never validated here. This is
                // the ordinary state of an AssumeUTXO snapshot's history while
                // background validation is still working through it, so the
                // rows are legitimately absent and the validator will write
                // them itself. Not an error.
                BlockStatus::DataStored | BlockStatus::HeaderOnly => {
                    audit.pending_validation.push(h)
                }
                BlockStatus::Invalid => audit.unrepairable.push(h),
            },
        }
    }

    audit.unrepairable.sort_unstable();
    audit.pending_validation.sort_unstable();
    audit.mismatched.sort_unstable();

    if !puts.is_empty() {
        audit.repaired = puts.iter().map(|(h, _)| *h).collect();
        audit.repaired.sort_unstable();
        let batch = StoreBatch {
            // Puts only. This pass never removes a row, so it cannot itself
            // reproduce the defect it is cleaning up after.
            height_hash_puts: puts,
            ..Default::default()
        };
        store.write_batch(batch)?;
        // The repair is worth nothing if it evaporates on the next crash, and
        // this only runs when there was real damage.
        store.flush_durable()?;
    }

    audit.elapsed_secs = started.elapsed().as_secs();
    Ok(audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    use crate::storage::blockindex::BlockIndexEntry;
    use crate::storage::db::InMemoryStore;

    fn entry(header: bitcoin::block::Header, height: u32, status: BlockStatus) -> BlockIndexEntry {
        BlockIndexEntry {
            header,
            height,
            status,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        }
    }

    fn header_with(prev: BlockHash, nonce: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
            ),
            time: 1_000 + nonce,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce,
        }
    }

    /// Builds a linear chain of `n` blocks (heights 0..n-1) in the block
    /// index and the height index, returning the hashes by height.
    fn seed_chain(store: &InMemoryStore, n: u32) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let mut prev = BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0u8; 32],
        ));
        let mut batch = StoreBatch::default();
        for height in 0..n {
            let header = header_with(prev, height);
            let hash = header.block_hash();
            batch
                .block_index_puts
                .push((hash, entry(header, height, BlockStatus::Valid)));
            batch.height_hash_puts.push((height, hash));
            hashes.push(hash);
            prev = hash;
        }
        store.write_batch(batch).unwrap();
        hashes
    }

    fn punch_gap(store: &InMemoryStore, height: u32) {
        let batch = StoreBatch {
            height_hash_removes: vec![height],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();
    }

    fn punch_gaps(store: &InMemoryStore, heights: std::ops::Range<u32>) {
        let batch = StoreBatch {
            height_hash_removes: heights.collect(),
            ..Default::default()
        };
        store.write_batch(batch).unwrap();
    }

    #[test]
    fn a_clean_index_is_left_alone() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        let audit =
            audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert!(audit.is_clean());
        assert!(audit.repaired.is_empty());
        assert_eq!(audit.rows_scanned, 20);
    }

    #[test]
    fn an_isolated_gap_is_rederived_from_the_block_above() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 7);
        assert_eq!(store.get_block_hash_by_height(7), None);

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.missing, vec![7]);
        assert_eq!(audit.repaired, vec![7]);
        assert!(audit.unrepairable.is_empty());
        assert_eq!(store.get_block_hash_by_height(7), Some(hashes[7]));
    }

    /// The shape actually seen in production: two unrelated single-height
    /// gaps far apart on one chain.
    #[test]
    fn two_far_apart_gaps_are_both_repaired() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 200);
        punch_gap(&store, 12);
        punch_gap(&store, 173);

        let audit = audit_and_repair_height_index(&store, hashes[199], 199).unwrap();
        assert_eq!(audit.missing, vec![12, 173]);
        assert_eq!(audit.repaired, vec![12, 173]);
        assert_eq!(store.get_block_hash_by_height(12), Some(hashes[12]));
        assert_eq!(store.get_block_hash_by_height(173), Some(hashes[173]));
    }

    /// Consecutive gaps: resolving descending means each one has a rebuilt
    /// height above it to anchor on.
    #[test]
    fn a_run_of_consecutive_gaps_resolves_top_down() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 30);
        for h in 10..=14 {
            punch_gap(&store, h);
        }

        let audit = audit_and_repair_height_index(&store, hashes[29], 29).unwrap();
        assert_eq!(audit.missing, vec![10, 11, 12, 13, 14]);
        assert_eq!(audit.repaired, vec![10, 11, 12, 13, 14]);
        assert!(audit.unrepairable.is_empty());
        for h in 10..=14u32 {
            assert_eq!(
                store.get_block_hash_by_height(h),
                Some(hashes[h as usize]),
                "height {h}"
            );
        }
    }

    /// The tip's own row has no height above it to derive from, so it comes
    /// from the caller-supplied anchor.
    #[test]
    fn a_missing_tip_row_is_filled_from_the_supplied_tip_hash() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 19);

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.repaired, vec![19]);
        assert_eq!(store.get_block_hash_by_height(19), Some(hashes[19]));
    }

    /// A row that is present but WRONG is not this pass's business. It must
    /// be reported as neither missing nor repaired, and left exactly as it
    /// was — overwriting it needs chainwork adjudication.
    #[test]
    fn a_wrong_but_present_row_is_left_untouched() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        let bogus = BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0xAB; 32],
        ));
        let batch = StoreBatch {
            height_hash_puts: vec![(8, bogus)],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert!(audit.is_clean(), "a wrong row is not a gap");
        assert!(audit.repaired.is_empty());
        assert_eq!(store.get_block_hash_by_height(8), Some(bogus));
    }

    /// Heights above the tip are not the audit's concern — headers can run
    /// ahead of blocks during IBD and those rows legitimately exist.
    #[test]
    fn rows_above_the_tip_are_scanned_but_never_treated_as_gaps() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 30);
        // Pretend the connected tip is only 19 while headers reach 29.
        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert!(audit.is_clean());
        assert_eq!(audit.rows_scanned, 30, "all rows are visited");
        assert!(audit.missing.is_empty());
    }

    /// REGRESSION: a fork whose divergence point IS the gap.
    ///
    /// The original anchor-based derivation read the parent pointer of the row
    /// one height up. A fork block sharing the active block's parent satisfied
    /// every guard — same height, status Valid, and its parent link matched the
    /// row below — so the FORK was written at the gap. Deriving from the tip's
    /// ancestry makes the fork unreachable.
    #[test]
    fn a_fork_diverging_at_the_gap_does_not_win() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);

        // F8 is a sibling of A8: same parent A7, same height 8.
        let f8 = header_with(hashes[7], 9008);
        let f8h = f8.block_hash();
        let f9 = header_with(f8h, 9009);
        let f9h = f9.block_hash();

        let batch = StoreBatch {
            block_index_puts: vec![
                (f8h, entry(f8, 8, BlockStatus::Valid)),
                (f9h, entry(f9, 9, BlockStatus::Valid)),
            ],
            height_hash_puts: vec![(9, f9h)],   // present-but-wrong anchor
            height_hash_removes: vec![8],        // the gap
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.missing, vec![8]);
        assert_eq!(audit.repaired, vec![8]);
        assert_eq!(
            store.get_block_hash_by_height(8),
            Some(hashes[8]),
            "the fork block must never be written at the gap"
        );
        // The polluted anchor row is surfaced, not silently trusted.
        assert_eq!(audit.mismatched, vec![9]);
    }

    /// REGRESSION: a run of consecutive gaps must never write fork rows.
    ///
    /// The original derivation corroborated only the bottom of a run, but
    /// queued every height above it first and wrote the queue unconditionally
    /// — so it could prove the branch wrong and persist it anyway.
    #[test]
    fn a_run_of_gaps_never_writes_fork_rows() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 30);

        // Fork attaches at A6, so the bottom link check at h=8 must fail.
        let f8 = header_with(hashes[6], 8008);
        let f8h = f8.block_hash();
        let f9 = header_with(f8h, 8009);
        let f9h = f9.block_hash();
        let f10 = header_with(f9h, 8010);
        let f10h = f10.block_hash();
        let f11 = header_with(f10h, 8011);
        let f11h = f11.block_hash();

        let batch = StoreBatch {
            block_index_puts: vec![
                (f8h, entry(f8, 8, BlockStatus::Valid)),
                (f9h, entry(f9, 9, BlockStatus::Valid)),
                (f10h, entry(f10, 10, BlockStatus::Valid)),
                (f11h, entry(f11, 11, BlockStatus::Valid)),
            ],
            height_hash_puts: vec![(11, f11h)],
            height_hash_removes: vec![8, 9, 10],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[29], 29).unwrap();
        assert_eq!(audit.repaired, vec![8, 9, 10], "all three, from the tip");
        for h in [8usize, 9, 10] {
            assert_eq!(
                store.get_block_hash_by_height(h as u32),
                Some(hashes[h]),
                "height {h}: a run of gaps must not persist rows from a fork"
            );
        }
    }

    /// Wholesale absence is not this pass's damage. An index that has to be
    /// *built* rather than repaired is a reindex, and a pass that runs on
    /// every start does not undertake one unasked. Report and decline.
    #[test]
    fn wholesale_absence_is_reported_and_not_repaired() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 2_000);
        punch_gaps(&store, 0..1_500);

        let audit = audit_and_repair_height_index(&store, hashes[1_999], 1_999).unwrap();
        assert!(audit.skipped_bulk, "must decline en-masse rewriting");
        assert_eq!(audit.missing.len(), 1_500, "but still report the condition");
        assert!(audit.repaired.is_empty());
        assert_eq!(
            store.get_block_hash_by_height(0),
            None,
            "nothing may be written when the pass declines"
        );
    }

    /// The threshold is a *share* of the range, not a count of gaps.
    ///
    /// Both halves punch exactly 3000 gaps and reach opposite verdicts, which
    /// is the whole claim: 30% of a long chain is damage worth repairing, 75%
    /// of a short one is a rebuild. An absolute count — the thousand-gap
    /// constant this replaced — cannot tell them apart, and got the first one
    /// wrong on a real node for months, declining a sub-second repair on every
    /// restart because a chain that reorgs often had accumulated 3009 gaps.
    #[test]
    fn the_skip_threshold_is_proportional_not_an_absolute_count() {
        // 3000 gaps in 10_000 heights: 30%, repairable.
        let long = InMemoryStore::new();
        let long_hashes = seed_chain(&long, 10_000);
        punch_gaps(&long, 6_500..9_500);

        let audit = audit_and_repair_height_index(&long, long_hashes[9_999], 9_999).unwrap();
        assert!(
            !audit.skipped_bulk,
            "3000 gaps in 10k heights is damage, not a rebuild"
        );
        assert_eq!(audit.repaired.len(), 3_000);
        assert!(audit.unrepairable.is_empty());
        assert!(audit.mismatched.is_empty());
        for h in [6_500usize, 8_000, 9_499] {
            assert_eq!(
                long.get_block_hash_by_height(h as u32),
                Some(long_hashes[h]),
                "height {h}"
            );
        }

        // The same 3000 gaps in 4_000 heights: 75%, declined.
        let short = InMemoryStore::new();
        let short_hashes = seed_chain(&short, 4_000);
        punch_gaps(&short, 500..3_500);

        let audit = audit_and_repair_height_index(&short, short_hashes[3_999], 3_999).unwrap();
        assert!(
            audit.skipped_bulk,
            "the identical gap count is a rebuild on a short chain"
        );
        assert!(audit.repaired.is_empty());
        assert_eq!(short.get_block_hash_by_height(500), None);
    }

    /// Safety does not ride on the skip threshold, and must not start to.
    ///
    /// A long run of unvalidated history sits well under the share that would
    /// trip the guard, so the pass proceeds and reaches every one of those
    /// heights — and still writes nothing, because the decision is made per
    /// height on `BlockStatus`. That is what makes it safe to let the guard
    /// pass thousands of gaps through.
    #[test]
    fn bulk_unvalidated_history_is_never_written_however_the_guard_is_set() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 2_000);
        punch_gaps(&store, 1_800..1_900);

        // Same headers — only the status changes, so the walk still traverses
        // them and the refusal has to come from the status check alone.
        let mut demote = StoreBatch::default();
        for h in 1_800..1_900usize {
            let header = header_with(hashes[h - 1], h as u32);
            demote
                .block_index_puts
                .push((hashes[h], entry(header, h as u32, BlockStatus::DataStored)));
        }
        store.write_batch(demote).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[1_999], 1_999).unwrap();
        assert!(!audit.skipped_bulk, "5% of the range does not trip the guard");
        assert_eq!(audit.pending_validation.len(), 100);
        assert!(audit.repaired.is_empty(), "not one row may be written");
        assert!(audit.unrepairable.is_empty(), "unvalidated is not a fault");
        for h in [1_800u32, 1_850, 1_899] {
            assert_eq!(store.get_block_hash_by_height(h), None, "height {h}");
        }
    }

    /// An implausible tip height must not turn a startup audit into a
    /// multi-gigabyte allocation.
    #[test]
    fn an_implausible_tip_height_is_refused_before_allocating() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 5);
        let err = audit_and_repair_height_index(&store, hashes[4], u32::MAX).unwrap_err();
        assert!(
            format!("{err}").contains("implausible tip height"),
            "got {err}"
        );
    }

    /// A block this node has a header or bytes for but never validated is
    /// not a fault — it is the ordinary state of an AssumeUTXO snapshot's
    /// history mid-validation. Report it apart from real damage so the
    /// operator is not told to `-reindex` a healthy node.
    #[test]
    fn an_unvalidated_block_is_pending_not_unrepairable() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 7);

        let header = header_with(hashes[6], 7);
        let batch = StoreBatch {
            block_index_puts: vec![(hashes[7], entry(header, 7, BlockStatus::DataStored))],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.pending_validation, vec![7]);
        assert!(audit.unrepairable.is_empty(), "not a fault");
        assert!(audit.repaired.is_empty());
        assert_eq!(store.get_block_hash_by_height(7), None);
    }

    /// A pruned block keeps its header, which is all a height row needs. A
    /// pruned node must still be repairable — it cannot act on advice to
    /// `-reindex`.
    #[test]
    fn a_pruned_block_is_still_repairable() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 7);

        let header = header_with(hashes[6], 7);
        let batch = StoreBatch {
            block_index_puts: vec![(hashes[7], entry(header, 7, BlockStatus::Pruned))],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.repaired, vec![7]);
        assert_eq!(store.get_block_hash_by_height(7), Some(hashes[7]));
    }

    /// A broken parent chain stops the walk. Everything at or below the break
    /// stays a gap rather than being guessed at.
    #[test]
    fn a_broken_parent_chain_leaves_the_rest_unrepairable() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 5);

        // Sever the chain at height 10 by pointing its entry at a parent the
        // index does not know.
        let unknown = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xCD; 32]),
        );
        let severed = header_with(unknown, 10);
        let batch = StoreBatch {
            block_index_puts: vec![(hashes[10], entry(severed, 10, BlockStatus::Valid))],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.missing, vec![5]);
        assert_eq!(audit.unrepairable, vec![5], "the walk cannot reach it");
        assert!(audit.repaired.is_empty());
        assert_eq!(store.get_block_hash_by_height(5), None);
    }

    /// A block that misreports its own height stops the walk rather than
    /// being trusted.
    #[test]
    fn a_block_misreporting_its_height_stops_the_walk() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        punch_gap(&store, 5);

        let header = header_with(hashes[9], 10);
        let batch = StoreBatch {
            block_index_puts: vec![(hashes[10], entry(header, 4_242, BlockStatus::Valid))],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.unrepairable, vec![5]);
        assert!(audit.repaired.is_empty());
    }

    /// A present row that names something other than the tip's ancestor is
    /// reported but never rewritten — the CHANGELOG says "reported", so it
    /// has to actually be reported.
    #[test]
    fn a_row_disagreeing_with_the_tips_ancestry_is_reported_not_overwritten() {
        let store = InMemoryStore::new();
        let hashes = seed_chain(&store, 20);
        let bogus = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xAB; 32]),
        );
        // A gap low down so the walk covers height 12, plus a polluted row.
        punch_gap(&store, 3);
        let batch = StoreBatch {
            height_hash_puts: vec![(12, bogus)],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let audit = audit_and_repair_height_index(&store, hashes[19], 19).unwrap();
        assert_eq!(audit.mismatched, vec![12], "must be surfaced");
        assert!(!audit.is_clean());
        assert_eq!(
            store.get_block_hash_by_height(12),
            Some(bogus),
            "reported, never overwritten"
        );
        assert_eq!(audit.repaired, vec![3], "the real gap is still fixed");
    }
}
