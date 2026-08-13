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
    /// Informational: this is the correct state when `-txindex` is off, so it
    /// is counted rather than treated as a fault.
    pub tx_index_absent: usize,
    /// Blocks whose cumulative transaction count is absent, or disagrees with
    /// `parent + num_tx`.
    pub chain_tx_faults: Vec<(u32, BlockHash)>,
    /// Blocks in the ancestry whose data could not be read back.
    pub unreadable: Vec<BlockHash>,
}

impl ChainstateReport {
    /// True when nothing disagreed. `tx_index_absent` is excluded — see its
    /// docs.
    pub fn is_consistent(&self) -> bool {
        self.ancestry.is_intact()
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
        parts.join("; ")
    }
}

impl ChainState {
    /// Read the last `window` blocks of the active chain back and check the
    /// UTXO set, height index, txindex and cumulative counts against them.
    ///
    /// Expensive by design — see the module docs.
    pub fn verify_chainstate(&self, window: u32) -> ChainstateReport {
        let tip_hash = self.tip_hash();
        let tip_height = self.tip_height();

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
            ..Default::default()
        };

        // Walk the ancestry by parent pointer, newest first, collecting what
        // each block creates and spends. Never consult the height index for
        // navigation — it is one of the things under test.
        let mut created: Vec<OutPoint> = Vec::new();
        let mut spent: HashSet<OutPoint> = HashSet::new();
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
            let parent_hash = entry.header.prev_blockhash;
            match self.cumulative_tx_count(&cursor) {
                Some(mine) => {
                    if let Some(theirs) = self.cumulative_tx_count(&parent_hash)
                        && mine != theirs + entry.num_tx as u64
                    {
                        report.chain_tx_faults.push((height, cursor));
                    }
                }
                None if height > 0 => report.chain_tx_faults.push((height, cursor)),
                None => {}
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
                                created.push(OutPoint {
                                    txid,
                                    vout: vout as u32,
                                });
                            }
                        }
                    }
                }
                None => report.unreadable.push(cursor),
            }

            report.blocks_checked += 1;
            report.lowest_height = height;
            if height == 0 || height == stop {
                break;
            }
            cursor = parent_hash;
            height -= 1;
        }

        // An output created and spent inside the window must be gone; one
        // created and not spent must be present. Provably exhaustive over
        // the window without needing to know anything about the chain below
        // it — but only if every block in it was read. A block we could not
        // read contributes neither its creates nor its spends, so a coin it
        // spent still looks created-and-unspent and would be reported
        // missing. Not hypothetical: a pruned node has no block data for
        // most of a 2016-block window, and would otherwise be told it had
        // lost thousands of coins. Withhold the coin verdicts rather than
        // emit ones we know are unsound; `unreadable` is itself reported,
        // so nothing is hidden.
        if report.unreadable.is_empty() {
            for op in &created {
                if spent.contains(op) {
                    continue;
                }
                if self.get_coin(op).is_none() {
                    report.missing_coins.push(*op);
                }
            }
            // Every spend must have removed its coin, wherever the coin came from.
            for op in &spent {
                if self.get_coin(op).is_some() {
                    report.unspent_spends.push(*op);
                }
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
