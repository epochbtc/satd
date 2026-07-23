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

use crate::mempool::fee::FeeEstimator;
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

impl Confidence {
    /// Lowercase wire string (`high`/`medium`/`low`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Which data source `estimatesmartfee` / `estimatefees` (and every other
/// fee surface) draws from.
///
/// - `Historical` (default for `estimatesmartfee`, for Bitcoin Core
///   compatibility): percentile of recent confirmed-block feerates.
/// - `Mempool`: simulate the next N block templates from the live mempool
///   and use the lowest admitted feerate. Responds faster to congestion.
/// - `Blend` (default everywhere else): mempool estimate when confidence
///   ≥ medium; fall back to historical, then the min-relay floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateMode {
    Historical,
    Mempool,
    Blend,
}

impl EstimateMode {
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s?.trim().to_ascii_lowercase().as_str() {
            "historical" | "conservative" | "economical" | "unset" => Some(Self::Historical),
            "mempool" => Some(Self::Mempool),
            "blend" => Some(Self::Blend),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Historical => "historical",
            Self::Mempool => "mempool",
            Self::Blend => "blend",
        }
    }
}

/// A single simulated block's summary.
#[derive(Debug, Clone, Serialize)]
pub struct SimBlock {
    /// Representative floor feerate to land in this block (sat/kvB). For a
    /// full block this is the robust, bottom-trimmed floor (see
    /// [`weighted_floor_rate`] / [`BLOCK_FLOOR_TRIM_PERCENT`]); for a partial
    /// block it is the plain cheapest admission. Zero if the block is empty.
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
/// - Each admission contributes its **marginal** feerate — (fee of
///   not-yet-admitted ancestors + self) / (weight of those) — paired with
///   its marginal weight. This is the dependencyRate clamp: a descendant
///   whose ancestor was already pulled in by a sibling only contributes its
///   own weight and fees, never claiming credit for the sibling's bump.
/// - `min_feerate_sat_per_kvb` is then the *robust* floor: the weight-
///   weighted [`BLOCK_FLOOR_TRIM_PERCENT`]-th percentile of admitted rates
///   (see [`weighted_floor_rate`]), not the absolute cheapest admission.
///   Trimming the bottom sliver of weight keeps one cheap tx slipping into
///   the tail of an otherwise-full block from dragging the next-block
///   estimate down to ~min-relay.
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
    // (marginal_rate, marginal_weight) for every admitted package, used to
    // compute the robust block floor once packing is done.
    let mut admissions: Vec<(u64, u64)> = Vec::new();
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
            // Block-wide sigop cap reached for this package; the block is at a
            // global capacity limit (like the weight-overflow branch above),
            // so mark it filled. Smaller-sigop candidates may still squeeze in,
            // so continue rather than break. Without this, a sigop-bound block
            // (weight-light but sigop-saturated) would report `filled == false`
            // and wrongly skip the robust floor trim / be labelled `Medium`.
            filled = true;
            continue;
        }
        let marginal_rate = crate::mempool::policy::fee_rate_sat_per_kvb(group_fee, group_weight);
        used_weight += group_weight;
        used_sigops += group_sigops;
        admissions.push((marginal_rate, group_weight));
        for t in group {
            included.insert(t);
        }
        if used_weight >= USABLE_WEIGHT_PER_BLOCK || used_sigops >= MAX_BLOCK_SIGOPS_COST {
            filled = true;
            break;
        }
    }

    // Only a *full* block has a real eviction margin to smooth. A partial
    // block admitted the entire remaining mempool, so its true floor is the
    // cheapest admission — anything at min-relay confirms — and trimming
    // would overcharge. So trim only when filled.
    let floor_trim = if filled { BLOCK_FLOOR_TRIM_PERCENT } else { 0 };
    let block = SimBlock {
        min_feerate_sat_per_kvb: weighted_floor_rate(&admissions, floor_trim),
        tx_count: included.len(),
        weight: used_weight,
        filled,
    };
    (block, included)
}

/// Fraction of admitted block weight (cheapest-first) trimmed before reading
/// the per-block floor feerate. Trimming the bottom sliver makes the floor
/// robust to a single cheap tx slipping into the tail of an otherwise-full
/// block — which would otherwise drag the next-block estimate down to
/// ~min-relay. 10% filters tail noise with a small conservative bias; on a
/// partial block (the whole mempool fits) the low rates still dominate, so
/// the floor correctly lands near the min-relay floor.
pub const BLOCK_FLOOR_TRIM_PERCENT: u64 = 10;

/// Weight-weighted, bottom-trimmed floor of `(rate, weight)` admissions: the
/// lowest rate `R` such that the cumulative weight of admissions with rate
/// `≤ R` reaches `trim_percent`% of the total. Equivalently, the cheapest
/// rate that survives trimming the bottom `trim_percent`% of weight.
///
/// `trim_percent == 0` reduces to the plain minimum admitted rate. A single
/// admission (or any whose weight alone exceeds the trim threshold) returns
/// its own rate, so small/chunky blocks are unaffected — only blocks with a
/// genuine cheap tail get smoothed.
fn weighted_floor_rate(admissions: &[(u64, u64)], trim_percent: u64) -> u64 {
    let total: u64 = admissions.iter().map(|(_, w)| *w).sum();
    if total == 0 {
        return 0;
    }
    let mut sorted: Vec<(u64, u64)> = admissions.to_vec();
    sorted.sort_by_key(|(rate, _)| *rate);
    let threshold = total.saturating_mul(trim_percent).div_ceil(100);
    let mut cum: u64 = 0;
    for (rate, weight) in &sorted {
        cum = cum.saturating_add(*weight);
        if cum >= threshold {
            return *rate;
        }
    }
    // threshold == total edge: return the heaviest (highest) rate seen.
    sorted.last().map(|(rate, _)| *rate).unwrap_or(0)
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

/// Extract the estimated feerate (with confidence) to confirm a tx
/// *within* `target` blocks.
///
/// `target` is a 1-indexed block number: target=1 means "land in the next
/// block". The estimate is the cheapest feerate that lands a tx in *any*
/// of the first `target` simulated blocks — i.e. the running minimum of
/// the per-block admission floors over `sim_blocks[0..target]`:
///
/// - Fully-filled block → `High` confidence, its min admitted rate.
/// - Partially-filled block → `Medium`, min admitted rate or floor.
/// - Empty simulated block → `Low`, floor (the queue clears by here, so
///   anything at min-relay confirms within `target`).
///
/// Taking the running minimum is what makes the estimate **monotonically
/// non-increasing** in `target`: confirming within N+k blocks can never
/// cost more than confirming within N. A single per-block floor is *not*
/// monotone — greedy packing under the weight/sigop caps can defer a
/// high-feerate package past block 1, leaving a later block with a higher
/// admission floor than an earlier one. Reading one block per target then
/// produces a nonsensical ladder (e.g. next-block < ~30-min). The running
/// minimum collapses that to the honest answer: if a cheap tx made it into
/// an early block, every deeper target is at least as cheap.
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
    let upto = target as usize;
    let mut best: Option<(u64, Confidence)> = None;
    for i in 0..upto {
        let Some(block) = estimate.sim_blocks.get(i) else {
            break;
        };
        let (rate, conf) = if block.tx_count == 0 {
            (floor_sat_per_kvb, Confidence::Low)
        } else if block.filled {
            (
                block.min_feerate_sat_per_kvb.max(floor_sat_per_kvb),
                Confidence::High,
            )
        } else {
            (
                block.min_feerate_sat_per_kvb.max(floor_sat_per_kvb),
                Confidence::Medium,
            )
        };
        // Keep the cheapest block in the window; its confidence is the
        // confidence of the block a tx at this rate would actually land in.
        if best.is_none_or(|(b, _)| rate < b) {
            best = Some((rate, conf));
        }
    }
    best.unwrap_or((floor_sat_per_kvb, Confidence::Low))
}

/// Clamp a set of `(target_blocks, rate_sat_per_kvb)` rows so the rate is
/// monotonically non-increasing as the confirmation target deepens.
///
/// [`target_estimate`] already guarantees this for a single estimator, but
/// the `estimatefees` / `estimatesmartfee` *blend* mode can source adjacent
/// targets from different estimators (mempool simulation vs. historical
/// percentile vs. the min-relay floor). Mixing sources can reintroduce an
/// inverted ladder, so this is the single belt-and-suspenders pass that
/// guarantees callers a sane High ≥ Medium ≥ Low ordering regardless of
/// where each tier's number came from. Mutates `rows` in place, clamping
/// each target down to the running minimum in ascending-target order;
/// confidence labels (held separately by the caller) are left untouched.
pub fn enforce_monotone_by_target(rows: &mut [(u32, u64)]) {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by_key(|&i| rows[i].0);
    let mut running_min = u64::MAX;
    for i in order {
        running_min = running_min.min(rows[i].1);
        rows[i].1 = running_min;
    }
}

/// Cap on how many blocks the mempool simulator runs, regardless of the
/// deepest requested target. Beyond a couple dozen blocks the mempool has
/// almost always drained (the sim early-exits on an empty block), so deeper
/// targets resolve through the historical fallback anyway. The cap bounds
/// cost for surfaces like Esplora `/fee-estimates` that ask out to 1008.
pub const MAX_SIM_DEPTH: usize = 25;

/// A single resolved per-target fee estimate (sat/kvB).
#[derive(Debug, Clone)]
pub struct TargetFee {
    pub target: u32,
    pub feerate_sat_per_kvb: u64,
    pub confidence: Confidence,
}

/// Fully-resolved smart-fee output shared by every surface (RPC, MCP,
/// Esplora, Electrum, TUI). This is the single source of truth: mode
/// selection, the monotonicity clamp, and the economy tier all happen here,
/// so no surface can drift or reintroduce an ordering/unit bug. All rates
/// are sat/kvB; each surface formats to its own wire unit.
#[derive(Debug, Clone)]
pub struct SmartFees {
    /// Per-target estimates in request order, clamped monotone by target.
    pub targets: Vec<TargetFee>,
    /// "Cheap but reasonable" economy rate (sat/kvB): the deepest target
    /// clamped into `[floor, 2×floor]` and never above the cheapest tier.
    pub economy_feerate_sat_per_kvb: u64,
    /// Mode actually used.
    pub mode: EstimateMode,
    /// Whether any target fell back off the mempool sim (to historical/floor).
    pub fallback: bool,
    /// Whether the simulated next block is thin (weak queue signal).
    pub thin_block: bool,
    /// Total mempool weight at snapshot time.
    pub mempool_weight: u64,
    /// Feerate histogram from the snapshot.
    pub histogram: Vec<HistogramBucket>,
}

/// Resolve one confirmation target against a prebuilt mempool simulation,
/// applying the mode policy. Returns `(sat/kvB, confidence, used_fallback)`.
///
/// This is the single definition of the blend policy: prefer the mempool
/// simulation when it is confident (High/Medium), else fall back to the
/// historical percentile estimator, else the min-relay floor.
pub fn resolve_target(
    mempool_est: &MempoolEstimate,
    fee_estimator: &FeeEstimator,
    target: u32,
    mode: EstimateMode,
    floor_sat_per_kvb: u64,
) -> (u64, Confidence, bool) {
    match mode {
        EstimateMode::Historical => match fee_estimator.estimate_fee(target) {
            Some(h) => (h, Confidence::Medium, false),
            None => (floor_sat_per_kvb, Confidence::Low, true),
        },
        EstimateMode::Mempool => {
            let (r, c) = target_estimate(mempool_est, target, floor_sat_per_kvb);
            (r, c, false)
        }
        EstimateMode::Blend => {
            let (mp_rate, mp_conf) = target_estimate(mempool_est, target, floor_sat_per_kvb);
            if matches!(mp_conf, Confidence::High | Confidence::Medium) {
                (mp_rate, mp_conf, false)
            } else if let Some(h) = fee_estimator.estimate_fee(target) {
                (h, Confidence::Medium, true)
            } else {
                (floor_sat_per_kvb, Confidence::Low, true)
            }
        }
    }
}

/// Compute smart fees for a set of confirmation targets — the unified entry
/// point behind every fee surface.
///
/// `snapshot` is an owned mempool snapshot (callers take it via
/// `Mempool::get_all_entries()` so no lock is held during simulation).
/// `floor_sat_per_kvb` is the min-relay floor (`min_fee_rate`, ≥ 1000).
pub fn smart_fees(
    snapshot: Vec<(Txid, MempoolEntry)>,
    fee_estimator: &FeeEstimator,
    targets: &[u32],
    mode: EstimateMode,
    floor_sat_per_kvb: u64,
) -> SmartFees {
    let max_target = targets.iter().copied().max().unwrap_or(24).max(1);
    let sim_depth = (max_target as usize).min(MAX_SIM_DEPTH);
    let mempool_est = estimate_from_mempool(snapshot, sim_depth);
    smart_fees_from_estimate(&mempool_est, fee_estimator, targets, mode, floor_sat_per_kvb)
}

/// `smart_fees` against a *prebuilt* mempool simulation, so callers on hot
/// public surfaces can reuse a cached `MempoolEstimate`
/// ([`FeeEstimator::cached_mempool_estimate`]) instead of cloning the whole
/// mempool and re-simulating on every request.
///
/// A `MempoolEstimate` simulated to any depth ≥ a target answers that target
/// identically (the per-block drain is the same regardless of total depth),
/// so a single estimate built to [`MAX_SIM_DEPTH`] serves every surface.
pub fn smart_fees_from_estimate(
    mempool_est: &MempoolEstimate,
    fee_estimator: &FeeEstimator,
    targets: &[u32],
    mode: EstimateMode,
    floor_sat_per_kvb: u64,
) -> SmartFees {
    let max_target = targets.iter().copied().max().unwrap_or(24).max(1);

    let mut fallback = false;
    let mut rows: Vec<(u32, u64, Confidence)> = Vec::with_capacity(targets.len());
    for &t in targets {
        let (rate, conf, fb) =
            resolve_target(mempool_est, fee_estimator, t, mode, floor_sat_per_kvb);
        fallback |= fb;
        rows.push((t, rate, conf));
    }

    // Clamp the assembled ladder to be monotone in target — belt-and-suspenders
    // against blend mixing estimators across adjacent targets. Confidence
    // labels are left as resolved.
    let mut clamped: Vec<(u32, u64)> = rows.iter().map(|(t, r, _)| (*t, *r)).collect();
    enforce_monotone_by_target(&mut clamped);
    for (row, (_, rate)) in rows.iter_mut().zip(clamped.iter()) {
        row.1 = *rate;
    }
    let lowest_tier = clamped.iter().map(|(_, r)| *r).min();

    // Economy: clamp the deepest target's rate into [floor, 2×floor], then
    // hold it at or below the cheapest displayed tier.
    let hour_rate = match mode {
        EstimateMode::Historical => fee_estimator
            .estimate_fee(max_target)
            .unwrap_or(floor_sat_per_kvb),
        _ => target_estimate(mempool_est, max_target, floor_sat_per_kvb).0,
    };
    let economy = economy_feerate_sat_per_kvb(floor_sat_per_kvb, hour_rate)
        .min(lowest_tier.unwrap_or(u64::MAX));

    SmartFees {
        targets: rows
            .into_iter()
            .map(|(target, feerate_sat_per_kvb, confidence)| TargetFee {
                target,
                feerate_sat_per_kvb,
                confidence,
            })
            .collect(),
        economy_feerate_sat_per_kvb: economy,
        mode,
        fallback,
        thin_block: is_thin_block(mempool_est),
        mempool_weight: mempool_est.mempool_weight,
        histogram: mempool_est.histogram.clone(),
    }
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
            prev_amounts: Vec::new(),
            prev_scripts: Vec::new(),
            sp_tweak: None,
            source: crate::mempool::pool::TxSource::Rpc,
            scope: crate::mempool::pool::QuarantineScope::acting(),
            quarantine_rule: None,
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
        // The block hit the global sigop cap, so it is reported as filled
        // (so it gets the robust floor trim / High confidence, not Medium).
        assert!(est.sim_blocks[0].filled, "sigop-bound block must be filled");
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

    /// Build a non-thin `MempoolEstimate` from explicit per-block
    /// (rate, filled, tx_count) triples, for exercising `target_estimate`
    /// directly without driving the whole simulator.
    fn estimate_from_blocks(blocks: &[(u64, bool, usize)]) -> MempoolEstimate {
        MempoolEstimate {
            sim_blocks: blocks
                .iter()
                .map(|&(rate, filled, txs)| SimBlock {
                    min_feerate_sat_per_kvb: rate,
                    tx_count: txs,
                    // Above the thin threshold so the short-target guard is off.
                    weight: THIN_BLOCK_WEIGHT_THRESHOLD + 1,
                    filled,
                })
                .collect(),
            histogram: Vec::new(),
            mempool_weight: THIN_BLOCK_WEIGHT_THRESHOLD + 1,
        }
    }

    #[test]
    fn target_estimate_is_monotone_when_sim_blocks_invert() {
        // A later block carries a HIGHER admission floor than an earlier
        // one — exactly the sigop/weight-deferral artifact that produced
        // the inverted "High 1.0 / Medium 6.0 / Low 4.2" TUI ladder.
        let est = estimate_from_blocks(&[
            (1_000, false, 5), // block 0: a cheap tail tx slipped in
            (5_000, false, 5), // block 1
            (6_000, false, 5), // block 2: inverted — above block 0
            (4_200, false, 5), // block 3
            (4_200, false, 5),
            (4_200, false, 5),
        ]);
        let (r1, _) = target_estimate(&est, 1, 1_000);
        let (r3, _) = target_estimate(&est, 3, 1_000);
        let (r6, _) = target_estimate(&est, 6, 1_000);
        assert!(
            r1 >= r3 && r3 >= r6,
            "tiers must be non-increasing: {r1} {r3} {r6}"
        );
        // The cheap block-0 tail honestly floors every deeper target: if a
        // 1.0 sat/vB tx confirms next block, it confirms within 3 and 6 too.
        assert_eq!((r1, r3, r6), (1_000, 1_000, 1_000));
    }

    #[test]
    fn target_estimate_preserves_descending_ladder() {
        // A clean drain (rates fall block over block) is already monotone;
        // the running minimum must leave it intact and keep confidence from
        // the block a tx would land in.
        let est = estimate_from_blocks(&[
            (50_000, true, 5),
            (30_000, true, 5),
            (20_000, false, 5),
            (10_000, false, 5),
            (10_000, false, 5),
            (8_000, false, 5),
        ]);
        let (r1, c1) = target_estimate(&est, 1, 1_000);
        let (r3, _) = target_estimate(&est, 3, 1_000);
        let (r6, _) = target_estimate(&est, 6, 1_000);
        assert_eq!((r1, c1), (50_000, Confidence::High));
        assert_eq!(r3, 20_000); // min(50k, 30k, 20k)
        assert_eq!(r6, 8_000);
        assert!(r1 >= r3 && r3 >= r6);
    }

    #[test]
    fn target_estimate_empty_block_in_window_floors_deeper_targets() {
        // Block 0 is a full, pricey block; block 1 is empty (queue clears).
        // Confirming within 2 blocks then costs only the floor.
        let est = estimate_from_blocks(&[(50_000, true, 5), (0, false, 0), (0, false, 0)]);
        let (r1, c1) = target_estimate(&est, 1, 1_000);
        let (r2, c2) = target_estimate(&est, 2, 1_000);
        assert_eq!((r1, c1), (50_000, Confidence::High));
        assert_eq!((r2, c2), (1_000, Confidence::Low));
    }

    #[test]
    fn enforce_monotone_by_target_clamps_inversions() {
        // Mixed-source ladder (as blend can emit): clamp deeper targets
        // down to the running minimum. Order of input rows is irrelevant —
        // clamping is by target value, not position.
        let mut rows = vec![(6u32, 4_200u64), (1, 1_000), (24, 8_000), (3, 6_000)];
        enforce_monotone_by_target(&mut rows);
        // Sort by target to read the resulting ladder.
        rows.sort_by_key(|r| r.0);
        let rates: Vec<u64> = rows.iter().map(|r| r.1).collect();
        // target 1 = 1_000; everything deeper clamped to ≤ that.
        assert_eq!(rates, vec![1_000, 1_000, 1_000, 1_000]);
    }

    #[test]
    fn enforce_monotone_by_target_keeps_healthy_ladder() {
        let mut rows = vec![(1u32, 50_000u64), (3, 30_000), (6, 20_000), (24, 5_000)];
        enforce_monotone_by_target(&mut rows);
        assert_eq!(
            rows,
            vec![(1, 50_000), (3, 30_000), (6, 20_000), (24, 5_000)]
        );
    }

    #[test]
    fn smart_fees_empty_mempool_no_history_floors_all_targets() {
        // Cold node: empty mempool + estimator with no samples. Every target
        // (and economy) collapses to the floor, monotone, with `fallback`.
        let est = FeeEstimator::new();
        let floor = 1_000;
        let sf = smart_fees(Vec::new(), &est, &[1, 3, 6, 12, 24], EstimateMode::Blend, floor);
        assert_eq!(sf.targets.len(), 5);
        assert!(sf.thin_block);
        assert!(sf.fallback);
        for tf in &sf.targets {
            assert_eq!(tf.feerate_sat_per_kvb, floor);
        }
        assert_eq!(sf.economy_feerate_sat_per_kvb, floor);
    }

    #[test]
    fn smart_fees_historical_is_monotone_and_economy_capped() {
        // Historical mode over a seeded estimator: percentile-by-target is
        // already monotone; economy stays at/below the cheapest tier.
        let est = FeeEstimator::new();
        // 100 samples 1..=100 (sat/kvB) → percentiles are well-defined.
        let rates: Vec<u64> = (1..=100).collect();
        est.record_block(&rates);
        let floor = 1; // keep the floor out of the way of the percentile values
        let sf = smart_fees(Vec::new(), &est, &[1, 3, 6, 12, 24], EstimateMode::Historical, floor);
        let vals: Vec<u64> = sf.targets.iter().map(|t| t.feerate_sat_per_kvb).collect();
        for w in vals.windows(2) {
            assert!(w[0] >= w[1], "historical ladder must be non-increasing: {vals:?}");
        }
        let lowest = *vals.iter().min().unwrap();
        assert!(sf.economy_feerate_sat_per_kvb <= lowest);
    }

    #[test]
    fn smart_fees_blend_clamps_inverted_history_fallback() {
        // Deep target falls back to a *higher* historical value than a
        // shallower mempool/floor target would imply; the clamp must keep the
        // assembled ladder non-increasing in target.
        let est = FeeEstimator::new();
        est.record_block(&[5_000; 50]); // historical ≈ 5_000 at every percentile
        let floor = 1_000;
        // Empty mempool → every target is thin/Low → blend falls to historical
        // (5_000) for all. That is flat (monotone) and a useful regression that
        // sources agree; assert non-increasing + economy cap.
        let sf = smart_fees(Vec::new(), &est, &[1, 3, 6], EstimateMode::Blend, floor);
        let vals: Vec<u64> = sf.targets.iter().map(|t| t.feerate_sat_per_kvb).collect();
        for w in vals.windows(2) {
            assert!(w[0] >= w[1], "blend ladder must be non-increasing: {vals:?}");
        }
        assert!(sf.economy_feerate_sat_per_kvb <= *vals.iter().min().unwrap());
    }

    #[test]
    fn weighted_floor_rate_p0_is_plain_min() {
        let adm = [(50_000u64, 1_000u64), (1_000, 100), (30_000, 1_000)];
        assert_eq!(weighted_floor_rate(&adm, 0), 1_000);
        assert_eq!(weighted_floor_rate(&[], 10), 0);
        assert_eq!(weighted_floor_rate(&[(7_000u64, 500u64)], 10), 7_000);
    }

    #[test]
    fn weighted_floor_rate_trims_small_cheap_tail() {
        // 99% of weight at 50_000, 1% at 1_000: P10 trims the cheap straggler,
        // P0 surfaces it.
        let adm = [(50_000u64, 9_900u64), (1_000, 100)];
        assert_eq!(weighted_floor_rate(&adm, 10), 50_000);
        assert_eq!(weighted_floor_rate(&adm, 0), 1_000);
    }

    #[test]
    fn weighted_floor_rate_keeps_cheap_when_backed_by_weight() {
        // A cheap rate backed by >10% of weight is real supply, not noise —
        // it must NOT be trimmed.
        let adm = [(50_000u64, 1_000u64), (1_000, 1_000)];
        assert_eq!(weighted_floor_rate(&adm, 10), 1_000);
    }

    #[test]
    fn full_block_floor_trims_cheap_tail() {
        // A full block packed with high-fee weight plus one cheap tx that
        // slips into the tail. The robust floor reports the competitive rate
        // (50 sat/vB), not the 1 sat/vB straggler — which a plain min would.
        let big_w = 1_300_000usize; // 3 of these ≈ 3.9 Mwu, just under the cap
        let mk_high = |seed: u8| {
            let tx = mk_tx(&[(random_txid(seed), 0)], 1);
            let id = tx.compute_txid();
            let fee = crate::mempool::policy::weight_to_vsize(big_w as u64) * 50; // 50 sat/vB
            (id, mk_entry(tx, fee, big_w))
        };
        let (h1, e1) = mk_high(1);
        let (h2, e2) = mk_high(2);
        let (h3, e3) = mk_high(3);
        let (h4, e4) = mk_high(4); // a 4th that won't fit → forces `filled`
        // One cheap tx (~1.3% of block weight) at 1 sat/vB.
        let cheap_w = 50_000usize;
        let ctx = mk_tx(&[(random_txid(9), 0)], 1);
        let cid = ctx.compute_txid();
        let cfee = crate::mempool::policy::weight_to_vsize(cheap_w as u64); // 1 sat/vB
        let centry = mk_entry(ctx, cfee, cheap_w);

        let est = estimate_from_mempool(
            vec![(h1, e1), (h2, e2), (h3, e3), (h4, e4), (cid, centry)],
            1,
        );
        let b0 = &est.sim_blocks[0];
        assert!(b0.filled, "block 0 should be full");
        assert_eq!(b0.min_feerate_sat_per_kvb, 50_000, "cheap 1% tail trimmed");
    }

    #[test]
    fn partial_block_floor_keeps_cheapest() {
        // When the whole mempool fits in one block (partial), the floor is the
        // genuine cheapest admission — trimming there would overcharge.
        let weight = (THIN_BLOCK_WEIGHT_THRESHOLD as usize) + 1; // non-thin, not full
        let big = mk_tx(&[(random_txid(1), 0)], 1);
        let bid = big.compute_txid();
        let bfee = crate::mempool::policy::weight_to_vsize(weight as u64) * 50;
        let cheap = mk_tx(&[(random_txid(2), 0)], 1);
        let cid = cheap.compute_txid();
        let cfee = crate::mempool::policy::weight_to_vsize(400); // tiny, 1 sat/vB
        let est = estimate_from_mempool(
            vec![(bid, mk_entry(big, bfee, weight)), (cid, mk_entry(cheap, cfee, 400))],
            1,
        );
        let b0 = &est.sim_blocks[0];
        assert!(!b0.filled, "block 0 should be partial (whole mempool fits)");
        assert_eq!(b0.min_feerate_sat_per_kvb, 1_000, "partial block keeps cheapest");
    }

    #[test]
    fn smart_fees_caps_simulation_depth() {
        // A very deep target must not blow up the sim; depth is capped and
        // deeper targets resolve through the (monotone) fallback path.
        let est = FeeEstimator::new();
        let sf = smart_fees(Vec::new(), &est, &[1, 1008], EstimateMode::Blend, 1_000);
        assert_eq!(sf.targets.len(), 2);
        assert!(sf.targets[0].feerate_sat_per_kvb >= sf.targets[1].feerate_sat_per_kvb);
    }
}
