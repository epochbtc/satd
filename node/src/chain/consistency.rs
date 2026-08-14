//! Whole-chainstate consistency check: does the UTXO set actually agree with
//! the blocks the node says are on the active chain?
//!
//! [`crate::chain::tip_ancestry`] answers a narrower question — were these
//! blocks connected at all — from the block index alone, cheaply enough to run
//! on every startup. This module answers the question that matters and cannot
//! be answered cheaply: it reads the blocks back and recomputes what their
//! coins imply, so it catches damage that leaves every status reading `Valid`.
//!
//! It exists because reasoning did not settle the mainnet incident behind #567
//! and reading the on-disk artifacts did. Four independent artifacts —
//! `coins`, `height_hash`, `undo`, `chain_tx` — each said something the others
//! did not, and the fourth reversed the conclusion drawn from the first three.
//! An assertion that "the tip is fine" is worth very little; an assertion that
//! names the outpoint, the height and the artifact is worth a great deal. So
//! every check here reports *what* disagreed rather than a boolean.
//!
//! Two uses:
//!
//! - As a test oracle. A scenario test that reorgs, flushes and then asks this
//!   for a clean report is checking the property that was actually violated,
//!   not a proxy for it.
//! - As the basis for an offline audit of a suspect datadir, which is how the
//!   incident was diagnosed in the first place — by hand, with a throwaway
//!   read-only RocksDB reader.
//!
//! ## Cost
//!
//! One block read plus a coin lookup per output and per input, over the
//! window. Not something to run on a hot path.

use std::collections::HashSet;

use bitcoin::{BlockHash, OutPoint, Txid};

use crate::chain::state::ChainState;
use crate::chain::tip_ancestry::{DEFAULT_ANCESTRY_WINDOW, TipAncestryAudit};

/// What a consistency pass found. Every field names the specific thing that
/// disagreed; none of them is a summary.
#[derive(Debug, Clone, Default)]
pub struct ChainstateReport {
    pub blocks_checked: u32,
    pub lowest_height: u32,
    /// The cheap structural check, run first — a hole here explains
    /// everything below it, so read this before anything else.
    pub ancestry: TipAncestryAudit,
    /// Outputs the walked blocks created and did not themselves spend, which
    /// are absent from the UTXO set. This is the shape of the mainnet loss.
    pub missing_coins: Vec<OutPoint>,
    /// Outputs the walked blocks spent that are still in the UTXO set — a
    /// double-spendable coin.
    pub unspent_spends: Vec<OutPoint>,
    /// Heights whose `height_hash` row does not name the tip's ancestor there.
    pub height_mismatches: Vec<u32>,
    /// Transactions whose `tx_index` row names a block other than the one that
    /// contains them. A reorg that re-mines a transaction produces exactly
    /// this when the batch layer resolves a put and a remove by apply order
    /// rather than by which came last.
    pub tx_index_wrong: Vec<(Txid, BlockHash)>,
    /// Transactions in the walked blocks with no `tx_index` row at all.
    ///
    /// Whether this is a fault depends on [`Self::txindex_expected`]: only a
    /// store that runs the index *and* whose index is known complete should
    /// have a row for every transaction. Counted rather than listed because on
    /// a node without a complete index it is every transaction in the window.
    pub tx_index_absent: usize,
    /// Whether every walked transaction should have a `tx_index` row —
    /// `has_txindex() && tx_index_complete()`.
    ///
    /// Both halves are load-bearing. Without the first, absent rows are the
    /// correct state and judging them as faults calls a healthy node damaged.
    /// Without the second, so is flipping `-txindex=1` onto a datadir synced
    /// without it: the flag is now on, the historical rows were never written,
    /// and every block in the window legitimately lacks one. This mirrors the
    /// `chain_tx` check below, which gates on its own backfill marker for
    /// exactly the same reason.
    ///
    /// The completeness marker does not weaken the fault it exists to catch:
    /// it is cleared only by connecting a block with the index off, never by
    /// row loss, so a complete-but-corrupted index still fails the verdict.
    pub txindex_expected: bool,
    /// The store runs `-txindex` but its index is known incomplete, so absent
    /// rows could not be judged either way.
    ///
    /// Reported rather than silently dropped: "not checked" and "checked and
    /// clean" are different answers, and a diagnostic that conflates them is
    /// how the audit came to print `consistent` about an index it had never
    /// actually looked at.
    pub txindex_incomplete: bool,
    /// Blocks whose cumulative transaction count is absent, or disagrees with
    /// `parent + num_tx`.
    pub chain_tx_faults: Vec<(u32, BlockHash)>,
    /// Blocks in the ancestry whose data could not be read back, and which
    /// were expected to be readable. Blocks the node has deliberately pruned
    /// are counted in [`Self::pruned`] instead — see there.
    pub unreadable: Vec<BlockHash>,
    /// Blocks in the window whose data this node pruned. Not a fault: the
    /// deletion was deliberate and the block is marked `Pruned` in the index.
    ///
    /// Counted separately because it still suppresses the coin verdicts that
    /// depend on having read the block — a pruned block contributes neither
    /// its creates nor its spends — but it must not make a healthy pruned node
    /// report INCONSISTENT. At the default window a `-prune=550` node has no
    /// data for most of the range, so folding these into `unreadable` failed
    /// every such node and then advised `-reindex-chainstate`, which a pruned
    /// node refuses outright.
    pub pruned: usize,
}

impl ChainstateReport {
    /// True when nothing disagreed.
    ///
    /// `tx_index_absent` counts only when [`Self::txindex_expected`] — the
    /// store both runs the index and has a complete one. On any other store
    /// absent rows are the correct state, and treating them as damage calls a
    /// healthy node broken; see that field.
    pub fn is_consistent(&self) -> bool {
        !(self.txindex_expected && self.tx_index_absent > 0)
            && self.ancestry.is_intact()
            && self.missing_coins.is_empty()
            && self.unspent_spends.is_empty()
            && self.height_mismatches.is_empty()
            && self.tx_index_wrong.is_empty()
            && self.chain_tx_faults.is_empty()
            && self.unreadable.is_empty()
    }

    /// A short operator-facing summary of what disagreed. Empty when
    /// consistent.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.ancestry.is_intact() {
            parts.push(format!(
                "{} ancestor(s) never connected",
                self.ancestry.holes.len()
            ));
        }
        if !self.missing_coins.is_empty() {
            parts.push(format!("{} coin(s) missing", self.missing_coins.len()));
        }
        if !self.unspent_spends.is_empty() {
            parts.push(format!(
                "{} spent coin(s) still present",
                self.unspent_spends.len()
            ));
        }
        if !self.height_mismatches.is_empty() {
            parts.push(format!(
                "{} height row(s) wrong",
                self.height_mismatches.len()
            ));
        }
        if !self.tx_index_wrong.is_empty() {
            parts.push(format!(
                "{} txindex row(s) wrong",
                self.tx_index_wrong.len()
            ));
        }
        if !self.chain_tx_faults.is_empty() {
            parts.push(format!("{} chain_tx row(s) wrong", self.chain_tx_faults.len()));
        }
        if !self.unreadable.is_empty() {
            parts.push(format!("{} block(s) unreadable", self.unreadable.len()));
        }
        if self.txindex_expected && self.tx_index_absent > 0 {
            parts.push(format!("{} txindex row(s) absent", self.tx_index_absent));
        }
        parts.join("; ")
    }
}

impl ChainState {
    /// Read the last `window` blocks of the active chain back and check the
    /// UTXO set, height index, txindex and cumulative counts against them.
    ///
    /// Expensive by design — see the module docs.
    pub fn verify_chainstate(&self, window: u32) -> ChainstateReport {
        // One acquisition. Reading hash and height separately lets a block
        // connect in between, after which `tip_hash` is the old tip paired
        // with the new height: the ancestry walk records a height mismatch
        // immediately, and every height row in the coin walk is off by one —
        // up to a full window of spurious faults on a healthy node.
        let (tip_hash, tip_height) = self.tip_snapshot();

        let ancestry = crate::chain::tip_ancestry::audit_tip_ancestry(
            &**self.store_ref(),
            tip_hash,
            tip_height,
            window,
            self.background().map(|bg| bg.snapshot_height()),
        );

        let mut report = ChainstateReport {
            lowest_height: tip_height,
            ancestry,
            // Ask the datadir, not the caller. `has_txindex()` alone is just
            // the flag the store was opened with, and the node's own default
            // (off) disagrees with what an auditor would naturally assume.
            // `tx_index_complete()` is persisted in the datadir and maintained
            // atomically with the batches that would invalidate it, so it is
            // the half that cannot be got wrong from outside.
            txindex_expected: crate::storage::Store::has_txindex(&**self.store_ref())
                && crate::storage::Store::tx_index_complete(&**self.store_ref()),
            txindex_incomplete: crate::storage::Store::has_txindex(&**self.store_ref())
                && !crate::storage::Store::tx_index_complete(&**self.store_ref()),
            ..Default::default()
        };

        // Walk the ancestry by parent pointer, newest first, collecting what
        // each block creates and spends. Never consult the height index for
        // navigation — it is one of the things under test.
        // Keyed by height: a block that could not be read only invalidates
        // verdicts at or below its own height (see the coin checks below).
        let mut created: Vec<(u32, OutPoint)> = Vec::new();
        let mut spent: HashSet<OutPoint> = HashSet::new();
        let mut unread_ceiling: Option<u32> = None;
        let mut cursor = tip_hash;
        let mut height = tip_height;
        let stop = tip_height.saturating_sub(window.saturating_sub(1));

        loop {
            let Some(entry) = self.get_block_index(&cursor) else {
                break;
            };

            if self.get_block_hash_by_height(height) != Some(cursor) {
                report.height_mismatches.push(height);
            }

            // `chain_tx[b]` is written as `chain_tx[parent] + num_tx`. It is
            // what proved the mainnet blocks HAD connected, after the status
            // and undo artifacts both said they had not.
            //
            // Only when the rows are all supposed to be there. `chain_tx` is a
            // backfilled column family: opening a datadir that predates it
            // creates it empty and marks the backfill incomplete, and the fill
            // only runs while the node runs. Auditing a copy taken before that
            // happened would otherwise report a full window of faults on a
            // datadir whose UTXO set is perfect.
            let parent_hash = entry.header.prev_blockhash;
            if crate::storage::Store::chain_tx_backfill_complete(&**self.store_ref()) {
                match self.cumulative_tx_count(&cursor) {
                    Some(mine) => {
                        // Checked: `theirs` comes off disk, from the artifact
                        // under audit. A corrupt row near u64::MAX would panic
                        // in debug and wrap in release — and a wrap could land
                        // on `mine` and hide the very fault being looked for.
                        if let Some(theirs) = self.cumulative_tx_count(&parent_hash)
                            && theirs
                                .checked_add(entry.num_tx as u64)
                                .is_none_or(|expected| mine != expected)
                        {
                            report.chain_tx_faults.push((height, cursor));
                        }
                    }
                    None if height > 0 => report.chain_tx_faults.push((height, cursor)),
                    None => {}
                }
            }

            match self.get_block(&cursor) {
                Some(block) => {
                    for tx in &block.txdata {
                        let txid = tx.compute_txid();
                        match self.get_tx_location(&txid) {
                            Some(loc) if loc != cursor => {
                                report.tx_index_wrong.push((txid, loc));
                            }
                            Some(_) => {}
                            None => report.tx_index_absent += 1,
                        }
                        if !tx.is_coinbase() {
                            for input in &tx.input {
                                spent.insert(input.previous_output);
                            }
                        }
                        // Only outputs that actually enter the UTXO set count
                        // as created. Two exclusions, both mirroring
                        // `connect_block`:
                        //
                        // - Unspendable outputs (OP_RETURN, or a script over
                        //   the size limit) are never written. Every
                        //   post-segwit coinbase carries the
                        //   witness-commitment OP_RETURN, so without this
                        //   every block contributes at least one phantom
                        //   missing coin — and far more in practice:
                        //   `connect_block` puts unspendables at ~24% of all
                        //   outputs at height 840000. A default-window run on
                        //   mainnet would have reported millions of them and
                        //   called a healthy node corrupt.
                        // - The genesis coinbase, which Core does not add to
                        //   the UTXO set and satd matches.
                        if height > 0 {
                            for (vout, output) in tx.output.iter().enumerate() {
                                if crate::chain::connect::is_unspendable(
                                    &output.script_pubkey,
                                ) {
                                    continue;
                                }
                                created.push((
                                    height,
                                    OutPoint {
                                        txid,
                                        vout: vout as u32,
                                    },
                                ));
                            }
                        }
                    }
                }
                None => {
                    // A pruned block is *supposed* to be unreadable. Counting
                    // it as a fault fails every healthy pruned node, at the
                    // default window for most of the range. It still blocks
                    // the coin verdicts below, because it contributes neither
                    // its creates nor its spends — but it is not damage.
                    if entry.status == crate::storage::blockindex::BlockStatus::Pruned {
                        report.pruned += 1;
                    } else {
                        report.unreadable.push(cursor);
                    }
                    unread_ceiling = Some(unread_ceiling.map_or(height, |h: u32| h.max(height)));
                }
            }

            report.blocks_checked += 1;
            report.lowest_height = height;
            if height == 0 || height == stop {
                break;
            }
            cursor = parent_hash;
            height -= 1;
        }

        // An output created and not spent inside the window must be present.
        // That is only sound where the *spends* are fully known: a block we
        // could not read contributes neither its creates nor its spends, so a
        // coin it spent still looks created-and-unspent and would be reported
        // missing. A pruned node has no data for most of a default window and
        // would otherwise be told it had lost thousands of coins.
        //
        // But the walk is newest-first, and a coin created at height H can
        // only be spent at a height >= H. So for every create strictly above
        // the highest unreadable block, the spend set is complete and the
        // verdict is sound. Only creates at or below that ceiling are dropped.
        // Withholding the whole window instead — as this did — means one
        // truncated block anywhere in it hides every missing coin above it,
        // which is precisely the pair of defects this node has already seen:
        // repair the one bad block, re-run, get "consistent", and the UTXO
        // hole the tool exists to find is never reported.
        for (h, op) in &created {
            if unread_ceiling.is_some_and(|ceiling| *h <= ceiling) {
                continue;
            }
            if spent.contains(op) {
                continue;
            }
            if self.get_coin(op).is_none() {
                report.missing_coins.push(*op);
            }
        }
        // Every spend must have removed its coin, wherever the coin came from.
        //
        // Unconditional: `spent` is populated only from blocks that WERE read,
        // and the coin those blocks spent had to be gone regardless of what
        // any unreadable block contained. The only way an unreadable block
        // could make this wrong is by re-creating the same outpoint, which is
        // a BIP30 duplicate and impossible above height 227931. So the
        // double-spendable-coin detector stays live on a pruned node, where
        // the previous blanket suppression disabled it permanently.
        for op in &spent {
            if self.get_coin(op).is_some() {
                report.unspent_spends.push(*op);
            }
        }

        report.missing_coins.sort_unstable();
        report.unspent_spends.sort_unstable();
        report.height_mismatches.sort_unstable();
        report.chain_tx_faults.sort_unstable();
        report
    }

    /// [`Self::verify_chainstate`] over the default ancestry window.
    pub fn verify_chainstate_default(&self) -> ChainstateReport {
        self.verify_chainstate(DEFAULT_ANCESTRY_WINDOW)
    }
}
