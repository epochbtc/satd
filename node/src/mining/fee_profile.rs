//! Per-block fee profile: what each transaction in a block paid, priced
//! from the block's undo data.
//!
//! One walk over a block and the coins it spent gives `(fee, weight)` for
//! every non-coinbase transaction. Two readers use it:
//!
//! * `getblockstats`, for its fee fields and Core's `feerate_percentiles`.
//! * The fee estimator's per-block hurdle ([`BlockFeeProfile::hurdle`]), the
//!   rate a transaction had to pay to get into this block.
//!
//! ## Why undo data
//!
//! Connecting a block removes the coins its inputs spend, so the live UTXO
//! set cannot price a block that is already connected. Undo data holds those
//! coins, one per non-coinbase input in connect order, and covers parents in
//! the same block too: an in-block CPFP child is priced like any other
//! transaction. Undo rows outlive pruning (they live in the chainstate, not
//! in the block files), but the block itself is still needed for the weights,
//! so a pruned node can profile only the blocks it still stores.

use bitcoin::{Block, OutPoint, Transaction};

use crate::storage::undo::UndoData;

/// One priced non-coinbase transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFee {
    /// Fee in satoshis.
    pub fee: u64,
    /// BIP 141 weight in weight units.
    pub weight: u64,
}

/// The fee profile of one block: every non-coinbase transaction that could
/// be priced, in block order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockFeeProfile {
    pub txs: Vec<TxFee>,
}

/// Why a block could not be profiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeeProfileError {
    /// The undo row does not hold one coin per non-coinbase input. That is
    /// corruption, not a missing prevout: a misaligned cursor would pair
    /// inputs with the wrong coins, so no figure from the block can be
    /// trusted.
    #[error(
        "undo data is inconsistent with the block: {coins} spent coins for {inputs} non-coinbase inputs"
    )]
    UndoMismatch { coins: usize, inputs: usize },
}

/// Core's `getblockstats` percentiles: the 10th, 25th, 50th, 75th and 90th
/// weight unit, as `(numerator, denominator)`.
const CORE_PERCENTILES: [(u64, u64); 5] = [(1, 10), (1, 4), (1, 2), (3, 4), (9, 10)];

/// The hurdle percentile: the 10th weight unit.
const HURDLE_PERCENTILE: (u64, u64) = (1, 10);

impl BlockFeeProfile {
    /// Profile `block` from its undo data. Every non-coinbase transaction is
    /// priced; the undo row must hold exactly one coin per non-coinbase
    /// input, or the block is refused with [`FeeProfileError::UndoMismatch`].
    pub fn from_undo(block: &Block, undo: &UndoData) -> Result<Self, FeeProfileError> {
        let inputs: usize = block
            .txdata
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| tx.input.len())
            .sum();
        let coins = undo.spent_coins.len();
        if coins != inputs {
            return Err(FeeProfileError::UndoMismatch { coins, inputs });
        }
        let mut spent = undo.spent_coins.iter().map(|c| c.amount);
        Ok(Self::price(block, |_| spent.next()))
    }

    /// Profile `block` by looking each prevout up with `prevout_value`. A
    /// transaction with a prevout it cannot find, or whose outputs exceed its
    /// inputs, is left out. For a block with no undo row, which has never
    /// connected and whose coins are therefore still in the live set.
    pub fn from_lookup(block: &Block, prevout_value: impl FnMut(&OutPoint) -> Option<u64>) -> Self {
        Self::price(block, prevout_value)
    }

    fn price(block: &Block, mut prevout_value: impl FnMut(&OutPoint) -> Option<u64>) -> Self {
        let mut txs = Vec::with_capacity(block.txdata.len().saturating_sub(1));
        for tx in block.txdata.iter().filter(|tx| !tx.is_coinbase()) {
            if let Some(fee) = tx_fee(tx, &mut prevout_value) {
                txs.push(TxFee { fee, weight: tx.weight().to_wu() });
            }
        }
        BlockFeeProfile { txs }
    }

    /// Core's `getblockstats.feerate_percentiles`: the feerates, in sat/vB,
    /// at the 10th, 25th, 50th, 75th and 90th percentile weight unit of the
    /// block's non-coinbase transactions. Each transaction's rate is
    /// `fee * 4 / weight`, truncated, as Core computes it; the pairs are
    /// sorted by `(rate, weight)` and each percentile is the first rate at
    /// which the cumulative weight reaches that share of the total. All
    /// zeros for a block with no priced transaction.
    ///
    /// Core computes the thresholds in floating point (`total_weight / 10.0`
    /// and so on); `cumulative * den >= total * num` is the same comparison
    /// in integers, exact for every weight a block can hold.
    pub fn feerate_percentiles(&self) -> [u64; 5] {
        let rates: Vec<(u64, u64)> = self
            .txs
            .iter()
            .map(|t| (sat_per_vb_core(t.fee, t.weight), t.weight))
            .collect();
        weighted_percentiles(rates, CORE_PERCENTILES).unwrap_or([0; 5])
    }

    /// The block's hurdle: the 10th percentile weight unit of the
    /// individual feerates, in sat/kvB, over the transactions paying at
    /// least `min_relay_sat_per_kvb`. Rates are satd's policy unit
    /// ([`crate::mempool::policy::fee_rate_sat_per_kvb`], fee over virtual
    /// size), so the cut compares like with like against `-minrelaytxfee`.
    /// `None` when no transaction is left.
    pub fn hurdle(&self, min_relay_sat_per_kvb: u64) -> Option<u64> {
        let rates: Vec<(u64, u64)> = self
            .txs
            .iter()
            .map(|t| (crate::mempool::policy::fee_rate_sat_per_kvb(t.fee, t.weight), t.weight))
            .filter(|(rate, _)| *rate >= min_relay_sat_per_kvb)
            .collect();
        weighted_percentiles(rates, [HURDLE_PERCENTILE]).map(|[r]| r)
    }
}

/// A transaction's fee, or `None` when a prevout is missing or the outputs
/// exceed the inputs.
///
/// Asks for every input's prevout even after one is missing: the undo
/// cursor behind `prevout_value` is positional, and stopping early would
/// pair the next transaction's inputs with this one's coins.
fn tx_fee(tx: &Transaction, prevout_value: &mut impl FnMut(&OutPoint) -> Option<u64>) -> Option<u64> {
    let mut in_sum: Option<u64> = Some(0);
    for input in &tx.input {
        let value = prevout_value(&input.previous_output);
        in_sum = in_sum.zip(value).and_then(|(sum, v)| sum.checked_add(v));
    }
    let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    in_sum?.checked_sub(out_sum)
}

/// Core's feerate in `getblockstats`, sat/vB: `fee * 4 / weight`, truncated
/// (v32.1 `src/rpc/blockchain.cpp:2186`, `(txfee * WITNESS_SCALE_FACTOR) /
/// weight`, and `:2205` for `avgfeerate`). Zero for a zero weight, as in
/// Core.
pub fn sat_per_vb_core(fee: u64, weight: u64) -> u64 {
    if weight == 0 { 0 } else { fee.saturating_mul(4) / weight }
}

/// Core's `CalculatePercentilesByWeight` over `(rate, weight)` pairs: sort
/// by `(rate, weight)`, walk the cumulative weight, and take for each
/// percentile the first rate at which it reaches `total * num / den`.
/// `None` for no pairs.
fn weighted_percentiles<const K: usize>(
    mut scores: Vec<(u64, u64)>,
    percentiles: [(u64, u64); K],
) -> Option<[u64; K]> {
    if scores.is_empty() {
        return None;
    }
    scores.sort_unstable();
    let total: u128 = scores.iter().map(|&(_, w)| u128::from(w)).sum();
    let mut out = [0u64; K];
    let mut next = 0;
    let mut cumulative: u128 = 0;
    for &(rate, weight) in &scores {
        cumulative += u128::from(weight);
        while next < K {
            let (num, den) = percentiles[next];
            if cumulative * u128::from(den) < total * u128::from(num) {
                break;
            }
            out[next] = rate;
            next += 1;
        }
    }
    // The last pair brings the cumulative weight to the total, so every
    // percentile up to 100% is filled. Core still fills any left over with
    // the highest rate; so does this.
    let last = scores.last().map_or(0, |&(rate, _)| rate);
    for slot in out.iter_mut().skip(next) {
        *slot = last;
    }
    Some(out)
}

/// Core's `CalculateTruncatedMedian`: the middle value, or the integer mean
/// of the two middle values for an even count. Zero when empty.
pub fn truncated_median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let n = values.len();
    if n.is_multiple_of(2) {
        (values[n / 2 - 1] + values[n / 2]) / 2
    } else {
        values[n / 2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::coinview::Coin;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, ScriptBuf, Sequence, TxIn, TxMerkleNode, TxOut, Txid,
        Witness,
    };

    fn tx_spending(prevouts: &[OutPoint], out_value: u64, pad: usize) -> Transaction {
        Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: prevouts
                .iter()
                .map(|p| TxIn {
                    previous_output: *p,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from(vec![0x51; 1 + pad]),
            }],
        }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from(vec![0x51, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(50), script_pubkey: ScriptBuf::new() }],
        }
    }

    fn block(txs: Vec<Transaction>) -> Block {
        let mut txdata = vec![coinbase()];
        txdata.extend(txs);
        Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        }
    }

    fn op(n: u8) -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([n; 32]), vout: 0 }
    }

    fn coin(amount: u64) -> Coin {
        Coin {
            amount,
            script_pubkey: ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: 0,
        }
    }

    fn profile(pairs: &[(u64, u64)]) -> BlockFeeProfile {
        BlockFeeProfile { txs: pairs.iter().map(|&(fee, weight)| TxFee { fee, weight }).collect() }
    }

    #[test]
    fn from_undo_prices_every_non_coinbase_tx_in_block_order() {
        let parent = tx_spending(&[op(1)], 9_000, 0);
        let child = tx_spending(&[OutPoint { txid: parent.compute_txid(), vout: 0 }], 4_000, 0);
        let b = block(vec![parent.clone(), child.clone()]);
        // The child's coin is the parent's own output: undo data covers
        // in-block parents, so the CPFP child is priced.
        let undo = UndoData { spent_coins: vec![coin(10_000), coin(9_000)] };
        let p = BlockFeeProfile::from_undo(&b, &undo).unwrap();
        assert_eq!(
            p.txs,
            vec![
                TxFee { fee: 1_000, weight: parent.weight().to_wu() },
                TxFee { fee: 5_000, weight: child.weight().to_wu() },
            ]
        );
    }

    #[test]
    fn from_undo_refuses_an_undo_row_with_too_few_coins() {
        let b = block(vec![tx_spending(&[op(1), op(2)], 1, 0)]);
        let undo = UndoData { spent_coins: vec![coin(10)] };
        assert_eq!(
            BlockFeeProfile::from_undo(&b, &undo),
            Err(FeeProfileError::UndoMismatch { coins: 1, inputs: 2 })
        );
    }

    #[test]
    fn from_undo_refuses_an_undo_row_with_surplus_coins() {
        let b = block(vec![tx_spending(&[op(1)], 1, 0)]);
        let undo = UndoData { spent_coins: vec![coin(10), coin(10)] };
        assert_eq!(
            BlockFeeProfile::from_undo(&b, &undo),
            Err(FeeProfileError::UndoMismatch { coins: 2, inputs: 1 })
        );
    }

    /// A transaction left out (outputs above inputs) still consumes its
    /// coins, so the next transaction is priced from its own.
    #[test]
    fn a_skipped_tx_does_not_shift_the_undo_cursor() {
        let first = tx_spending(&[op(1), op(2)], 1_000, 0);
        let second = tx_spending(&[op(3)], 100, 0);
        let b = block(vec![first, second.clone()]);
        // First tx: 10 + 10 in, 1000 out -> unpriced. Second: 600 in, 100 out.
        let undo = UndoData { spent_coins: vec![coin(10), coin(10), coin(600)] };
        let p = BlockFeeProfile::from_undo(&b, &undo).unwrap();
        assert_eq!(p.txs, vec![TxFee { fee: 500, weight: second.weight().to_wu() }]);
    }

    /// An input sum that overflows leaves the transaction out without
    /// stopping the cursor.
    #[test]
    fn an_overflowing_input_sum_does_not_shift_the_undo_cursor() {
        let first = tx_spending(&[op(1), op(2), op(4)], 0, 0);
        let second = tx_spending(&[op(3)], 100, 0);
        let b = block(vec![first, second.clone()]);
        let undo = UndoData { spent_coins: vec![coin(u64::MAX), coin(1), coin(5), coin(600)] };
        let p = BlockFeeProfile::from_undo(&b, &undo).unwrap();
        assert_eq!(p.txs, vec![TxFee { fee: 500, weight: second.weight().to_wu() }]);
    }

    #[test]
    fn from_lookup_leaves_out_a_tx_with_a_missing_prevout() {
        let b = block(vec![tx_spending(&[op(1)], 1, 0), tx_spending(&[op(2)], 1, 0)]);
        let p = BlockFeeProfile::from_lookup(&b, |o| (o.txid == op(2).txid).then_some(11));
        assert_eq!(p.txs.len(), 1);
        assert_eq!(p.txs[0].fee, 10);
    }

    #[test]
    fn coinbase_only_block_has_zero_percentiles_and_no_hurdle() {
        let p = BlockFeeProfile::from_undo(&block(vec![]), &UndoData::default()).unwrap();
        assert!(p.txs.is_empty());
        assert_eq!(p.feerate_percentiles(), [0; 5]);
        assert_eq!(p.hurdle(0), None);
    }

    /// Hand-worked against Core's `CalculatePercentilesByWeight`. Rates
    /// (sat/vB) and weights: (1, 400), (2, 400), (5, 1200), (10, 2000).
    /// Total 4000; thresholds 400, 1000, 2000, 3000, 3600. Cumulative
    /// weights 400, 800, 2000, 4000.
    #[test]
    fn feerate_percentiles_are_weight_weighted_like_core() {
        let p = profile(&[(10 * 500, 2000), (100, 400), (5 * 300, 1200), (200, 400)]);
        assert_eq!(p.feerate_percentiles(), [1, 5, 5, 10, 10]);
    }

    /// An unweighted percentile would put the median at the second of four
    /// transactions. Weighting puts it on the one heavy transaction.
    #[test]
    fn one_heavy_tx_carries_the_weighted_median() {
        // Rates 1, 2, 3 (100 WU each) and 400 (3700 WU).
        let p = profile(&[(25, 100), (50, 100), (75, 100), (400 * 3_700 / 4, 3_700)]);
        assert_eq!(p.feerate_percentiles(), [400; 5]);
    }

    /// Core truncates `fee * 4 / weight`; rounding the virtual size up first,
    /// as satd's policy rate does, would give 1 here.
    #[test]
    fn feerate_percentiles_truncate_fee_times_four_over_weight() {
        // 7 sat over 13 WU: 28 / 13 = 2.15 -> 2. Over vsize 4: 1.75 -> 1.
        let p = profile(&[(7, 13)]);
        assert_eq!(p.feerate_percentiles(), [2; 5]);
    }

    /// Ties on rate are broken by weight, as `std::sort` on Core's
    /// `pair<CAmount, int64_t>` does; the order of equal-rate pairs does not
    /// move any percentile, but the threshold is the exact cumulative one:
    /// 10% of 1000 is reached at exactly 100.
    #[test]
    fn a_percentile_is_reached_at_an_exactly_equal_cumulative_weight() {
        let p = profile(&[(25, 100), (2 * 900 / 4, 900)]);
        // Rates: 1 (w 100), 2 (w 900). 10%: cumulative 100 >= 100 -> 1.
        assert_eq!(p.feerate_percentiles()[0], 1);
        assert_eq!(p.feerate_percentiles()[1], 2);
    }

    #[test]
    fn zero_fee_txs_count_toward_the_percentile_weight() {
        let p = profile(&[(0, 1_000), (0, 1_000), (4_000, 1_000)]);
        assert_eq!(p.feerate_percentiles(), [0, 0, 0, 16, 16]);
    }

    /// The hurdle drops transactions under min relay before taking the
    /// percentile, and works in sat/kvB.
    #[test]
    fn hurdle_drops_rates_below_min_relay() {
        // sat/kvB: 0 (w 4000), 500 (w 400), 2000 (w 400), 3000 (w 3200).
        let p = profile(&[(0, 4_000), (50, 400), (200, 400), (2_400, 3_200)]);
        // With a 1000 sat/kvB floor: 2000 (w 400) and 3000 (w 3200), total
        // 3600, 10% = 360 -> 2000.
        assert_eq!(p.hurdle(1_000), Some(2_000));
        // With no floor, the zero-fee weight is the bottom 10%.
        assert_eq!(p.hurdle(0), Some(0));
    }

    #[test]
    fn hurdle_keeps_a_rate_exactly_at_min_relay() {
        let p = profile(&[(100, 400)]); // 100 sat over 100 vB = 1000 sat/kvB
        assert_eq!(p.hurdle(1_000), Some(1_000));
        assert_eq!(p.hurdle(1_001), None);
    }

    #[test]
    fn hurdle_is_none_when_every_tx_is_under_min_relay() {
        let p = profile(&[(0, 400), (10, 400)]);
        assert_eq!(p.hurdle(1_000), None);
    }

    #[test]
    fn hurdle_is_the_tenth_weight_percentile_not_the_tenth_tx() {
        // Nine light high-rate transactions and one heavy low-rate one: an
        // unweighted p10 would land on a high rate.
        let mut pairs: Vec<(u64, u64)> = (0..9).map(|_| (1_000, 400)).collect(); // 10_000 sat/kvB
        pairs.push((4_000, 4_000)); // 4_000 sat/kvB
        assert_eq!(profile(&pairs).hurdle(1_000), Some(4_000));
    }

    #[test]
    fn truncated_median_matches_core() {
        assert_eq!(truncated_median(&mut []), 0);
        assert_eq!(truncated_median(&mut [7]), 7);
        assert_eq!(truncated_median(&mut [300, 100, 200]), 200);
        // Even count: integer mean of the two middle values, truncated.
        assert_eq!(truncated_median(&mut [100, 400, 201, 300]), 250);
        assert_eq!(truncated_median(&mut [1, 2]), 1);
    }
}
