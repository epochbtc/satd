//! Mempool-based smart fee estimation.
//!
//! Simulates the next N block templates from the current mempool snapshot.
//! For each simulated block we record the lowest admitted *ancestor
//! feerate* — that is the fee level a new tx needs to land in block k.
//! Ancestor feerate aggregation handles CPFP correctly: a low-fee parent
//! + high-fee child are admitted together at the child's pull rate.
//!
//! This complements the historical-block `FeeEstimator` in `fee.rs`:
//! historical data reacts to what miners *did* (slow to respond to sudden
//! congestion), while mempool simulation reacts to what's queued *now*.
//!
//! The simulator is intentionally a pure function over an owned snapshot
//! of `MempoolEntry`s — it does not hold any mempool locks while running.
//! Callers should `get_all_entries()` once and pass the Vec in.
//!
//! Output: per-block min feerate + confidence + a feerate histogram
//! suitable for callers that want to roll their own strategy.

use std::collections::{HashMap, HashSet};

use bitcoin::Txid;
use serde::Serialize;

use crate::mempool::pool::MempoolEntry;

/// Maximum block weight (4,000,000 WU per BIP 141).
pub const BLOCK_WEIGHT_LIMIT: u64 = 4_000_000;
/// Weight reserved for the coinbase — mirrors `mining/template.rs`.
/// Matches Bitcoin Core v30's `DEFAULT_BLOCK_RESERVED_WEIGHT` (8000 WU).
pub const COINBASE_WEIGHT_RESERVE: u64 = 8_000;
/// Usable weight per simulated block (block limit − coinbase reserve).
pub const USABLE_WEIGHT_PER_BLOCK: u64 = BLOCK_WEIGHT_LIMIT - COINBASE_WEIGHT_RESERVE;
/// BIP 141 sigop-cost cap per block.
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;
/// Bitcoin Core's per-ancestor sigop-cost cap (`MAX_PACKAGE_SIGOPS_COST`).
/// A package whose aggregate sigop cost exceeds this is skipped.
pub const MAX_PACKAGE_SIGOPS_COST: u64 = 80_000;
/// Below this block-0 weight we treat the mempool as "thin": short-term
/// targets collapse to the min-relay floor because there simply isn't
/// enough queue depth to draw an estimate from. 2 Mwu ≈ 500 kvB, matching
/// mempool.space's `blocks` gating.
pub const THIN_BLOCK_WEIGHT_THRESHOLD: u64 = 2_000_000;

/// Confidence of an estimated target feerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Target block fully packed in simulation; ancestor queue exceeds it.
    High,
    /// Target block partially packed; mempool too thin to fully fill it.
    Medium,
    /// Mempool had no usable data at this target; floor used.
    Low,
}

/// A single simulated block's summary.
#[derive(Debug, Clone, Serialize)]
pub struct SimBlock {
    /// Lowest ancestor-feerate admitted in this block (sat/kvB). Zero if
    /// the block is empty.
    pub min_feerate_sat_per_kvb: u64,
    /// Number of distinct transactions packed (ancestors + roots).
    pub tx_count: usize,
    /// Total weight used in this block (excludes coinbase reserve).
    pub weight: u64,
    /// Whether the block hit the weight ceiling (no more room to pack).
    pub filled: bool,
}

/// One bucket in the mempool feerate histogram.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct HistogramBucket {
    /// Inclusive lower bound of this bucket in sat/kvB.
    pub feerate_sat_per_kvb: u64,
    /// Sum of weights of entries whose *own* feerate falls in this bucket.
    pub weight: u64,
}

/// Result of a mempool simulation pass.
#[derive(Debug, Clone, Serialize)]
pub struct MempoolEstimate {
    pub sim_blocks: Vec<SimBlock>,
    pub histogram: Vec<HistogramBucket>,
    /// Total weight queued in the mempool at snapshot time.
    pub mempool_weight: u64,
}

/// Default histogram boundaries in sat/vB, converted to sat/kvB on use.
/// Chosen to span realistic mainnet fee regimes (1 → 1000 sat/vB).
const HISTOGRAM_BOUNDARIES_SAT_PER_VB: &[u64] = &[
    1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100, 150, 200, 300, 500, 1000,
];

/// Effective (post-prioritisation) fee of an entry, clamped at zero.
/// Saturating add: `fee_delta` may be an extreme value from a corrupt
/// persisted mempool, and must not overflow the i64 sum.
fn effective_fee(entry: &MempoolEntry) -> u64 {
    (entry.fee as i64).saturating_add(entry.fee_delta).max(0) as u64
}

/// Compute the set of in-mempool ancestor txids for `txid`, memoized.
///
/// Walks the input graph transitively. Only parents that are themselves
/// in the snapshot count — confirmed-parent inputs are ignored, matching
/// Core's ancestor-set semantics for fee estimation.
fn ancestor_set(
    txid: &Txid,
    entries: &HashMap<Txid, MempoolEntry>,
    memo: &mut HashMap<Txid, HashSet<Txid>>,
) -> HashSet<Txid> {
    if let Some(cached) = memo.get(txid) {
        return cached.clone();
    }
    let mut ancestors: HashSet<Txid> = HashSet::new();
    let Some(root) = entries.get(txid) else {
        memo.insert(*txid, ancestors.clone());
        return ancestors;
    };
    let mut queue: Vec<Txid> = root
        .tx
        .input
        .iter()
        .map(|i| i.previous_output.txid)
        .filter(|p| entries.contains_key(p))
        .collect();
    while let Some(parent) = queue.pop() {
        if !ancestors.insert(parent) {
            continue;
        }
        if let Some(parent_entry) = entries.get(&parent) {
            for input in &parent_entry.tx.input {
                let gp = input.previous_output.txid;
                if entries.contains_key(&gp) && !ancestors.contains(&gp) {
                    queue.push(gp);
                }
            }
        }
    }
    memo.insert(*txid, ancestors.clone());
    ancestors
}

/// Ancestor-aggregate (fee, weight) for `txid` — inclusive of self.
fn ancestor_aggregate(
    txid: &Txid,
    entries: &HashMap<Txid, MempoolEntry>,
    anc_memo: &mut HashMap<Txid, HashSet<Txid>>,
) -> (u64, u64) {
    let Some(root) = entries.get(txid) else {
        return (0, 0);
    };
    let mut fee = effective_fee(root);
    let mut weight = root.weight as u64;
    let anc = ancestor_set(txid, entries, anc_memo);
    for a in &anc {
        if let Some(e) = entries.get(a) {
            fee = fee.saturating_add(effective_fee(e));
            weight = weight.saturating_add(e.weight as u64);
        }
    }
    (fee, weight)
}

/// Simulate a single block from the remaining mempool.
///
/// Returns the block summary and the set of txids consumed (to remove
/// from `remaining` before simulating the next block).
///
/// Admission rules:
/// - Sort candidates by their *initial* ancestor feerate (descending).
/// - For each candidate, admit together with its in-mempool ancestors
///   that are not already in the block.
/// - Reject the package if its aggregate sigop cost exceeds
///   `MAX_PACKAGE_SIGOPS_COST`; if it would push the block past
///   `MAX_BLOCK_SIGOPS_COST`, skip and continue (later packages may fit).
/// - Record `min_feerate_sat_per_kvb` as the **marginal** feerate at
///   admission — (fee of not-yet-admitted ancestors + self) /
///   (weight of not-yet-admitted ancestors + self). This is the
///   dependencyRate clamp: a descendant whose ancestor was already
///   pulled in by a sibling only contributes its own weight and fees
///   to the block's floor, never claiming credit for the sibling's bump.
fn simulate_one_block(remaining: &HashMap<Txid, MempoolEntry>) -> (SimBlock, HashSet<Txid>) {
    let mut anc_memo: HashMap<Txid, HashSet<Txid>> = HashMap::with_capacity(remaining.len());
    let mut sorted: Vec<(Txid, u64)> = Vec::with_capacity(remaining.len());
    for txid in remaining.keys() {
        let (fee, weight) = ancestor_aggregate(txid, remaining, &mut anc_memo);
        if weight == 0 {
            continue;
        }
        let rate = crate::mempool::policy::fee_rate_sat_per_kvb(fee, weight);
        sorted.push((*txid, rate));
    }
    // Highest ancestor-feerate first.
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let mut included: HashSet<Txid> = HashSet::new();
    let mut used_weight: u64 = 0;
    let mut used_sigops: u64 = 0;
    let mut min_admitted_rate: u64 = 0;
    let mut filled = false;

    for (txid, _initial_rate) in sorted {
        if included.contains(&txid) {
            continue;
        }
        let mut group: Vec<Txid> = ancestor_set(&txid, remaining, &mut anc_memo)
            .into_iter()
            .filter(|t| !included.contains(t))
            .collect();
        group.push(txid);

        let mut group_fee: u64 = 0;
        let mut group_weight: u64 = 0;
        let mut group_sigops: u64 = 0;
        for t in &group {
            if let Some(e) = remaining.get(t) {
                group_fee = group_fee.saturating_add(effective_fee(e));
                group_weight = group_weight.saturating_add(e.weight as u64);
                group_sigops = group_sigops.saturating_add(e.sigop_cost);
            }
        }
        if group_weight == 0 {
            continue;
        }
        if group_sigops > MAX_PACKAGE_SIGOPS_COST {
            // Policy-invalid as a package — would be dropped by a miner.
            continue;
        }
        if used_weight.saturating_add(group_weight) > USABLE_WEIGHT_PER_BLOCK {
            filled = true;
            continue;
        }
        if used_sigops.saturating_add(group_sigops) > MAX_BLOCK_SIGOPS_COST {
            // Block-wide sigop cap reached for this package; skip and try
            // the next candidate (may be smaller in sigops).
            continue;
        }
        let marginal_rate = crate::mempool::policy::fee_rate_sat_per_kvb(group_fee, group_weight);
        used_weight += group_weight;
        used_sigops += group_sigops;
        min_admitted_rate = marginal_rate;
        for t in group {
            included.insert(t);
        }
        if used_weight >= USABLE_WEIGHT_PER_BLOCK || used_sigops >= MAX_BLOCK_SIGOPS_COST {
            filled = true;
            break;
        }
    }

    let block = SimBlock {
        min_feerate_sat_per_kvb: min_admitted_rate,
        tx_count: included.len(),
        weight: used_weight,
        filled,
    };
    (block, included)
}

/// Bucket entries by their own (not ancestor) feerate.
/// Bucket mempool entries by their own (not ancestor) feerate. Public
/// so `mempool::history` can reuse the same boundaries as the live
/// estimator without copying the bin math.
pub fn build_histogram(entries: &HashMap<Txid, MempoolEntry>) -> Vec<HistogramBucket> {
    let bounds_kvb: Vec<u64> = HISTOGRAM_BOUNDARIES_SAT_PER_VB
        .iter()
        .map(|v| v * 1000)
        .collect();
    let mut weights: Vec<u64> = vec![0; bounds_kvb.len()];
    for entry in entries.values() {
        let rate =
            crate::mempool::policy::fee_rate_sat_per_kvb(effective_fee(entry), entry.weight as u64);
        // Drop into the highest bucket whose boundary is ≤ rate.
        let mut idx: Option<usize> = None;
        for (i, b) in bounds_kvb.iter().enumerate() {
            if rate >= *b {
                idx = Some(i);
            } else {
                break;
            }
        }
        if let Some(i) = idx {
            weights[i] = weights[i].saturating_add(entry.weight as u64);
        }
    }
    bounds_kvb
        .into_iter()
        .zip(weights)
        .filter(|(_, w)| *w > 0)
        .map(|(feerate_sat_per_kvb, weight)| HistogramBucket {
            feerate_sat_per_kvb,
            weight,
        })
        .collect()
}

/// Run the full simulation: build histogram, simulate `n_blocks` blocks.
///
/// `snapshot` is taken by value so the caller releases the mempool lock
/// before we start work. `n_blocks` should be ≥ the largest target the
/// caller cares about (typically 25 is plenty).
pub fn estimate_from_mempool(
    snapshot: Vec<(Txid, MempoolEntry)>,
    n_blocks: usize,
) -> MempoolEstimate {
    let entries: HashMap<Txid, MempoolEntry> = snapshot.into_iter().collect();
    let mempool_weight: u64 = entries.values().map(|e| e.weight as u64).sum();
    let histogram = build_histogram(&entries);

    let mut remaining = entries;
    let mut sim_blocks: Vec<SimBlock> = Vec::with_capacity(n_blocks);
    for _ in 0..n_blocks {
        if remaining.is_empty() {
            sim_blocks.push(SimBlock {
                min_feerate_sat_per_kvb: 0,
                tx_count: 0,
                weight: 0,
                filled: false,
            });
            continue;
        }
        let (block, consumed) = simulate_one_block(&remaining);
        for txid in &consumed {
            remaining.remove(txid);
        }
        let was_filled = block.filled;
        let was_empty = block.tx_count == 0;
        sim_blocks.push(block);
        // If the block wasn't filled and produced nothing, further blocks
        // will also be empty — fill out with zeros for caller simplicity.
        if !was_filled && was_empty {
            while sim_blocks.len() < n_blocks {
                sim_blocks.push(SimBlock {
                    min_feerate_sat_per_kvb: 0,
                    tx_count: 0,
                    weight: 0,
                    filled: false,
                });
            }
            break;
        }
    }

    MempoolEstimate {
        sim_blocks,
        histogram,
        mempool_weight,
    }
}

/// Extract per-target estimated feerate with confidence.
///
/// `target` is a 1-indexed block number: target=1 means "land in next
/// block". For each target we look at `sim_blocks[target - 1]`.
///
/// - Fully-filled block → `High` confidence, min admitted rate.
/// - Partially-filled block → `Medium`, either the min admitted or the
///   caller's min-relay floor (whichever is higher).
/// - Empty simulated block → `Low`, floor to `floor_sat_per_kvb`.
///
/// If the first simulated block is "thin" (below
/// `THIN_BLOCK_WEIGHT_THRESHOLD`), short targets (1..=3) collapse to
/// the floor with `Low` confidence: in that regime the queue depth
/// doesn't carry enough signal to price above min-relay, so offering
/// anything else would mislead callers into overpaying.
pub fn target_estimate(
    estimate: &MempoolEstimate,
    target: u32,
    floor_sat_per_kvb: u64,
) -> (u64, Confidence) {
    if target <= 3 && is_thin_block(estimate) {
        return (floor_sat_per_kvb, Confidence::Low);
    }
    let idx = target.saturating_sub(1) as usize;
    let Some(block) = estimate.sim_blocks.get(idx) else {
        return (floor_sat_per_kvb, Confidence::Low);
    };
    if block.tx_count == 0 {
        return (floor_sat_per_kvb, Confidence::Low);
    }
    if block.filled {
        return (
            block.min_feerate_sat_per_kvb.max(floor_sat_per_kvb),
            Confidence::High,
        );
    }
    (
        block.min_feerate_sat_per_kvb.max(floor_sat_per_kvb),
        Confidence::Medium,
    )
}

/// True when the simulated next block is thinly filled — i.e., below
/// `THIN_BLOCK_WEIGHT_THRESHOLD` in weight. Indicates there is not
/// enough queue to derive a meaningful short-term premium over the
/// min-relay floor.
pub fn is_thin_block(estimate: &MempoolEstimate) -> bool {
    estimate
        .sim_blocks
        .first()
        .map(|b| b.weight < THIN_BLOCK_WEIGHT_THRESHOLD)
        .unwrap_or(true)
}

/// Economy feerate = min(2 × floor, hour_rate). Bounds a "cheapest
/// reasonable" suggestion so operators never undershoot by pulling
/// the hour rate down further than twice min-relay, and never
/// overshoot the hour rate on quiet days.
pub fn economy_feerate_sat_per_kvb(floor_sat_per_kvb: u64, hour_rate_sat_per_kvb: u64) -> u64 {
    let twice_floor = floor_sat_per_kvb.saturating_mul(2);
    hour_rate_sat_per_kvb
        .min(twice_floor)
        .max(floor_sat_per_kvb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    fn mk_tx(prevs: &[(Txid, u32)], n_out: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: prevs
                .iter()
                .map(|(txid, vout)| TxIn {
                    previous_output: OutPoint {
                        txid: *txid,
                        vout: *vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: (0..n_out)
                .map(|_| TxOut {
                    value: bitcoin::Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    fn mk_entry(tx: Transaction, fee: u64, weight: usize) -> MempoolEntry {
        mk_entry_with_sigops(tx, fee, weight, 0)
    }

    fn mk_entry_with_sigops(
        tx: Transaction,
        fee: u64,
        weight: usize,
        sigop_cost: u64,
    ) -> MempoolEntry {
        let fee_rate = crate::mempool::policy::fee_rate_sat_per_kvb(fee, weight as u64);
        MempoolEntry {
            tx,
            fee,
            weight,
            fee_rate,
            time: 0,
            fee_delta: 0,
            sigop_cost,
            prev_scripthashes: Vec::new(),
        }
    }

    fn random_txid(byte: u8) -> Txid {
        use bitcoin::hashes::Hash;
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
    }

    #[test]
    fn empty_mempool_yields_empty_blocks() {
        let est = estimate_from_mempool(Vec::new(), 3);
        assert_eq!(est.sim_blocks.len(), 3);
        for b in &est.sim_blocks {
            assert_eq!(b.tx_count, 0);
            assert_eq!(b.weight, 0);
            assert!(!b.filled);
        }
        assert!(est.histogram.is_empty());
        assert_eq!(est.mempool_weight, 0);

        let (rate, conf) = target_estimate(&est, 1, 1000);
        assert_eq!(rate, 1000);
        assert_eq!(conf, Confidence::Low);
    }

    #[test]
    fn single_tx_fills_nothing_medium_confidence() {
        // One fat tx whose weight is above the thin-block threshold so
        // short-target collapse does not kick in. Feerate 10_000 sat/kvB.
        let tx = mk_tx(&[], 1);
        let txid = tx.compute_txid();
        let weight = (THIN_BLOCK_WEIGHT_THRESHOLD as usize) + 1;
        // Fee for 10_000 sat/kvB measured per vbyte (fee = rate * vsize / 1000).
        let fee = crate::mempool::policy::weight_to_vsize(weight as u64) * 10_000 / 1_000;
        let entry = mk_entry(tx, fee, weight);
        let snap = vec![(txid, entry)];
        let est = estimate_from_mempool(snap, 3);
        let (rate, conf) = target_estimate(&est, 1, 1000);
        assert_eq!(rate, 10_000);
        assert_eq!(conf, Confidence::Medium);
        // Subsequent blocks are empty → Low.
        let (_, conf2) = target_estimate(&est, 2, 1000);
        assert_eq!(conf2, Confidence::Low);
    }

    #[test]
    fn histogram_buckets_by_own_feerate() {
        let tx_a = mk_tx(&[], 1);
        let tx_b = mk_tx(&[], 2);
        let ta = tx_a.compute_txid();
        let tb = tx_b.compute_txid();
        // 2 sat/vB (2000 sat/kvB) and 20 sat/vB (20000 sat/kvB). Weight 400 =
        // 100 vbytes, so fee/vsize gives the intended per-vbyte rate.
        let ea = mk_entry(tx_a, 200, 400); // 200 / 100 vB = 2000 sat/kvB
        let eb = mk_entry(tx_b, 2000, 400); // 2000 / 100 vB = 20000 sat/kvB
        let est = estimate_from_mempool(vec![(ta, ea), (tb, eb)], 1);
        let rates: Vec<u64> = est
            .histogram
            .iter()
            .map(|h| h.feerate_sat_per_kvb)
            .collect();
        // Expect buckets for 2 sat/vB (=2000) and 20 sat/vB (=20000).
        assert!(rates.contains(&2000));
        assert!(rates.contains(&20_000));
    }

    #[test]
    fn cpfp_lifts_parent_into_same_block() {
        // Parent: zero-fee. Child spends parent with high fee.
        // Without CPFP-aware ancestor feerate, parent would have feerate 0
        // and be sorted last. With ancestor-feerate sorting, the child's
        // high rate pulls the parent into the block alongside it.
        let parent = mk_tx(&[], 1);
        let parent_txid = parent.compute_txid();
        let child = mk_tx(&[(parent_txid, 0)], 1);
        let child_txid = child.compute_txid();

        let parent_entry = mk_entry(parent, 0, 400); // 0 sat/kvB on its own
        let child_entry = mk_entry(child, 2_000, 400); // 2000 / 100 vB = 20000 sat/kvB on its own
        let snap = vec![(parent_txid, parent_entry), (child_txid, child_entry)];
        let est = estimate_from_mempool(snap, 1);
        assert_eq!(est.sim_blocks[0].tx_count, 2, "CPFP must pull parent in");
        // Combined package: 2000 sat / 200 vB (800 wu) = 10000 sat/kvB.
        assert_eq!(est.sim_blocks[0].min_feerate_sat_per_kvb, 10_000);
    }

    #[test]
    fn weight_overflow_rolls_into_next_block() {
        // Two chunks each near half-block. First two fit; third spills.
        let w = (USABLE_WEIGHT_PER_BLOCK / 2) as usize;
        // Different prev-txids so the txs are independent (no ancestor
        // relationships) and sortable purely by own feerate.
        let t1 = mk_tx(&[(random_txid(1), 0)], 1);
        let t2 = mk_tx(&[(random_txid(2), 0)], 1);
        let t3 = mk_tx(&[(random_txid(3), 0)], 1);
        let id1 = t1.compute_txid();
        let id2 = t2.compute_txid();
        let id3 = t3.compute_txid();
        let e1 = mk_entry(t1, 10_000, w);
        let e2 = mk_entry(t2, 8_000, w);
        let e3 = mk_entry(t3, 5_000, w);
        let est = estimate_from_mempool(vec![(id1, e1), (id2, e2), (id3, e3)], 2);
        assert!(
            est.sim_blocks[0].filled,
            "block 1 should fill with 2 half-blocks"
        );
        assert_eq!(est.sim_blocks[0].tx_count, 2);
        // Block 2 has the leftover tx.
        assert_eq!(est.sim_blocks[1].tx_count, 1);
    }

    #[test]
    fn target_estimate_respects_floor() {
        // Non-thin mempool (weight above threshold) at 100 sat/kvB,
        // floor at 1000 → floor wins even though block is confident.
        let tx = mk_tx(&[], 1);
        let txid = tx.compute_txid();
        let weight = (THIN_BLOCK_WEIGHT_THRESHOLD as usize) + 1;
        // 100 sat/kvB measured per vbyte — still below the 1000 floor.
        let fee = crate::mempool::policy::weight_to_vsize(weight as u64) * 100 / 1_000;
        let entry = mk_entry(tx, fee, weight);
        let est = estimate_from_mempool(vec![(txid, entry)], 3);
        let (rate, conf) = target_estimate(&est, 1, 1000);
        assert_eq!(rate, 1000);
        assert_eq!(conf, Confidence::Medium);
    }

    // --- New: dependencyRate clamping, sigops budget, thin-block, economy ---

    #[test]
    fn dependency_rate_clamps_sibling_rate() {
        // Parent P (low), Child X (pays big fee), Child Y (modest).
        // Pre-fix: Y's ancestor rate = (P+Y)/(Pw+Yw) is medium because P
        // drags Y down — but after X admits P, Y's marginal rate is
        // just Y's own rate. We verify that min_admitted_rate reflects
        // the marginal rate at admission, not the stale ancestor-rate.
        let parent = mk_tx(&[], 2); // 2 outputs: one for X, one for Y
        let parent_id = parent.compute_txid();
        let child_x = mk_tx(&[(parent_id, 0)], 1);
        let x_id = child_x.compute_txid();
        let child_y = mk_tx(&[(parent_id, 1)], 1);
        let y_id = child_y.compute_txid();

        // (Rates are sat/kvB = per vbyte; 400 wu = 100 vB, 800 wu = 200 vB.)
        // P: 0 fee, 100 vB → 0 sat/kvB on its own.
        // X: 100_000 fee, 100 vB → 1_000_000 sat/kvB on its own.
        //    X's ancestor (P+X): 100k/200 vB = 500_000 sat/kvB.
        // Y: 1_000 fee, 100 vB → 10_000 sat/kvB on its own.
        //    Y's ancestor (P+Y): 1k/200 vB = 5_000 sat/kvB (drags low).
        // Sort: X first (500k), then Y (5k). X admits P+X.
        // Y's marginal at admission (P already in) = 1000/100 vB = 10_000.
        // Therefore min_admitted_rate must be 10_000, not 5_000.
        let p = mk_entry(parent, 0, 400);
        let ex = mk_entry(child_x, 100_000, 400);
        let ey = mk_entry(child_y, 1_000, 400);
        let snap = vec![(parent_id, p), (x_id, ex), (y_id, ey)];
        let est = estimate_from_mempool(snap, 1);
        assert_eq!(
            est.sim_blocks[0].tx_count, 3,
            "all three should be admitted"
        );
        assert_eq!(
            est.sim_blocks[0].min_feerate_sat_per_kvb, 10_000,
            "Y's marginal rate at admission — P already paid for"
        );
    }

    #[test]
    fn sigop_heavy_package_excluded() {
        // A tx with sigop_cost > MAX_PACKAGE_SIGOPS_COST is dropped as a
        // package candidate — even if its fee rate would otherwise admit.
        let fat_sigop_tx = mk_tx(&[(random_txid(9), 0)], 1);
        let fat_id = fat_sigop_tx.compute_txid();
        let fat_entry =
            mk_entry_with_sigops(fat_sigop_tx, 1_000_000, 400, MAX_PACKAGE_SIGOPS_COST + 1);

        // A normal high-rate tx that should still be admitted.
        let ok_tx = mk_tx(&[(random_txid(10), 0)], 1);
        let ok_id = ok_tx.compute_txid();
        let ok_entry = mk_entry(ok_tx, 2_000, 400);

        let snap = vec![(fat_id, fat_entry), (ok_id, ok_entry)];
        let est = estimate_from_mempool(snap, 1);
        assert_eq!(est.sim_blocks[0].tx_count, 1);
        // The admitted tx must be the ok one, not the sigop-heavy one.
        let expected_rate = crate::mempool::policy::fee_rate_sat_per_kvb(2_000, 400);
        assert_eq!(
            est.sim_blocks[0].min_feerate_sat_per_kvb, expected_rate,
            "sigop-heavy tx should not have set the floor"
        );
    }

    #[test]
    fn block_sigop_cap_skips_but_continues() {
        // Two txs each carry half the block sigop cap + a sliver over,
        // so two of them cannot coexist. The simulator should admit the
        // higher-rate one and skip (not stop at) the second — proving
        // the block-cap path is `continue`, not break.
        //
        // We put a third, smaller tx with 0 sigops behind the cap —
        // it must still be admitted after the block-cap skip.
        let half = MAX_BLOCK_SIGOPS_COST / 2 + 100;

        let t1 = mk_tx(&[(random_txid(21), 0)], 1);
        let id1 = t1.compute_txid();
        let e1 = mk_entry_with_sigops(t1, 100_000, 400, half);

        let t2 = mk_tx(&[(random_txid(22), 0)], 1);
        let id2 = t2.compute_txid();
        let e2 = mk_entry_with_sigops(t2, 90_000, 400, half);

        let t3 = mk_tx(&[(random_txid(23), 0)], 1);
        let id3 = t3.compute_txid();
        let e3 = mk_entry_with_sigops(t3, 1_000, 400, 0);

        let snap = vec![(id1, e1), (id2, e2), (id3, e3)];
        let est = estimate_from_mempool(snap, 1);
        // Admit t1 (sigops fit) + t3 (0 sigops). t2 skipped on block cap.
        assert_eq!(est.sim_blocks[0].tx_count, 2);
    }

    #[test]
    fn thin_block_collapses_short_targets_to_floor() {
        // A lone tx at 10_000 sat/kvB with weight just below the thin
        // threshold → block 0 is thin → short targets return (floor, Low).
        let tx = mk_tx(&[], 1);
        let txid = tx.compute_txid();
        let weight = (THIN_BLOCK_WEIGHT_THRESHOLD - 1) as usize;
        let fee = crate::mempool::policy::weight_to_vsize(weight as u64) * 10_000 / 1_000;
        let entry = mk_entry(tx, fee, weight);
        let est = estimate_from_mempool(vec![(txid, entry)], 6);
        assert!(is_thin_block(&est));
        let (rate1, conf1) = target_estimate(&est, 1, 1000);
        assert_eq!(rate1, 1000);
        assert_eq!(conf1, Confidence::Low);
        let (rate3, conf3) = target_estimate(&est, 3, 1000);
        assert_eq!(rate3, 1000);
        assert_eq!(conf3, Confidence::Low);
    }

    #[test]
    fn economy_feerate_clamps_between_floor_and_twice_floor() {
        let floor = 2_000u64;
        // Hour rate below floor → at least floor.
        assert_eq!(economy_feerate_sat_per_kvb(floor, 500), floor);
        // Hour rate between floor and 2× floor → equals hour rate.
        assert_eq!(economy_feerate_sat_per_kvb(floor, 3_000), 3_000);
        // Hour rate above 2× floor → clamped at 2× floor.
        assert_eq!(economy_feerate_sat_per_kvb(floor, 100_000), 2 * floor);
    }
}
