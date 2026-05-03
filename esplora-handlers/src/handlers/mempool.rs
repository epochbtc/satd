//! Mempool + fee + root handlers (Esplora plan PR 7).
//!
//! Endpoints:
//! - `GET /`                 → small JSON with chain + mempool summary
//! - `GET /mempool`          → counts, vsize, fee total, fee histogram
//! - `GET /mempool/txids`    → array of mempool txids (no order guarantee)
//! - `GET /mempool/recent`   → up to 10 newest mempool txs (`{txid, fee, vsize, value}`)
//! - `GET /fee-estimates`    → map of confirmation target → feerate sat/vB
//!
//! Wire shapes match upstream Esplora: `/mempool`'s `fee_histogram` is
//! an array of `[feerate_sat_vb, vsize]` pairs, descending by feerate;
//! `/fee-estimates` is an object whose keys are target strings and
//! values are floating-point sat/vB. `/` is a small JSON envelope
//! (chain tip + mempool count) that mirrors blockstream.info's root.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use serde_json::Value;

use crate::error::EsploraResult;
use crate::state::EsploraState;

/// Confirmation targets exposed by `/fee-estimates`. Matches upstream
/// Esplora; downstream consumers (BDK, mempool.space SDK) iterate this
/// exact set so adding/removing keys is a wire-level break.
const FEE_TARGETS: &[u32] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 144,
    504, 1008,
];

/// Fee-rate buckets (sat/vB) used by `/mempool`'s fee_histogram. These
/// boundaries are dense at the bottom (where most mempool txs live) and
/// sparse at the top, matching upstream electrs's published shape.
const HISTOGRAM_BUCKETS_SAT_VB: &[f64] = &[
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0,
    100.0, 125.0, 150.0, 175.0, 200.0, 250.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0,
    1000.0, 1250.0, 1500.0, 1750.0, 2000.0, 3000.0, 4000.0,
];

const RECENT_LIMIT: usize = 10;

// ── JSON shapes ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct MempoolJson {
    pub count: u64,
    pub vsize: u64,
    pub total_fee: u64,
    /// Array of `[feerate_sat_vb, vsize_in_bucket]` pairs, ordered
    /// descending by feerate. Empty when the mempool is empty.
    pub fee_histogram: Vec<(f64, u64)>,
}

#[derive(Debug, Serialize)]
pub struct RecentTxJson {
    pub txid: String,
    pub fee: u64,
    pub vsize: u64,
    /// Total output value (sum of `vout[].value`) — matches upstream.
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct RootJson {
    pub chain_tip: ChainTipJson,
    pub mempool_count: u64,
}

#[derive(Debug, Serialize)]
pub struct ChainTipJson {
    pub hash: String,
    pub height: u32,
}

// ── Handlers ───────────────────────────────────────────────────────

pub async fn root(State(state): State<EsploraState>) -> Json<RootJson> {
    let count = state.mempool.get_all_entries().len() as u64;
    Json(RootJson {
        chain_tip: ChainTipJson {
            hash: state.chain.tip_hash().to_string(),
            height: state.chain.tip_height(),
        },
        mempool_count: count,
    })
}

pub async fn mempool_summary(
    State(state): State<EsploraState>,
) -> Json<MempoolJson> {
    let entries = state.mempool.get_all_entries();
    let count = entries.len() as u64;
    let mut vsize_total: u64 = 0;
    let mut fee_total: u64 = 0;
    // Per-tx (feerate_sat_vb, vsize). Used to bucket into histogram.
    let mut tx_rates: Vec<(f64, u64)> = Vec::with_capacity(entries.len());
    for (_, entry) in &entries {
        let vsize = vsize_of_weight(entry.weight as u64);
        vsize_total = vsize_total.saturating_add(vsize);
        fee_total = fee_total.saturating_add(entry.fee);
        // entry.fee_rate is sat/kvB; convert to sat/vB.
        let rate_sat_vb = (entry.fee_rate as f64) / 1000.0;
        tx_rates.push((rate_sat_vb, vsize));
    }
    let fee_histogram = build_fee_histogram(&tx_rates);
    Json(MempoolJson {
        count,
        vsize: vsize_total,
        total_fee: fee_total,
        fee_histogram,
    })
}

pub async fn mempool_txids(
    State(state): State<EsploraState>,
) -> Json<Vec<String>> {
    let entries = state.mempool.get_all_entries();
    Json(
        entries
            .into_iter()
            .map(|(txid, _)| txid.to_string())
            .collect(),
    )
}

pub async fn mempool_recent(
    State(state): State<EsploraState>,
) -> Json<Vec<RecentTxJson>> {
    let mut entries = state.mempool.get_all_entries();
    // Sort by `time` descending (newest first); take up to RECENT_LIMIT.
    entries.sort_by(|a, b| b.1.time.cmp(&a.1.time));
    entries.truncate(RECENT_LIMIT);
    Json(
        entries
            .into_iter()
            .map(|(txid, entry)| RecentTxJson {
                txid: txid.to_string(),
                fee: entry.fee,
                vsize: vsize_of_weight(entry.weight as u64),
                value: entry
                    .tx
                    .output
                    .iter()
                    .map(|o| o.value.to_sat())
                    .sum::<u64>(),
            })
            .collect(),
    )
}

pub async fn fee_estimates(
    State(state): State<EsploraState>,
) -> EsploraResult<Json<Value>> {
    let mut out = serde_json::Map::with_capacity(FEE_TARGETS.len());
    for target in FEE_TARGETS {
        // FeeEstimator returns sat/kvB; convert to sat/vB. When data
        // is insufficient (None) we fall back to 1.0 sat/vB so consumer
        // tooling always has a complete map. Upstream Esplora behaves
        // identically — its minimum is the network's relay floor.
        let rate = state
            .fee_estimator
            .estimate_fee(*target)
            .map(|sat_kvb| (sat_kvb as f64) / 1000.0)
            .unwrap_or(1.0);
        out.insert(target.to_string(), Value::from(rate));
    }
    Ok(Json(Value::Object(out)))
}

// ── Helpers ────────────────────────────────────────────────────────

/// Convert weight (WU) to vsize (vBytes). vsize = ceil(weight / 4).
fn vsize_of_weight(weight: u64) -> u64 {
    weight.div_ceil(4)
}

/// Bucket per-tx `(feerate_sat_vb, vsize)` pairs into the histogram
/// shape `/mempool` returns. Each bucket sums vsizes for all txs whose
/// feerate falls into the half-open range `[bucket_low, next_bucket)`,
/// or `[bucket_top, ∞)` for the topmost bucket. Empty buckets are
/// dropped. Result is descending by feerate.
fn build_fee_histogram(tx_rates: &[(f64, u64)]) -> Vec<(f64, u64)> {
    if tx_rates.is_empty() {
        return Vec::new();
    }
    let mut bucket_vsizes: HashMap<usize, u64> = HashMap::new();
    for (rate, vsize) in tx_rates {
        // Find highest bucket boundary <= rate.
        let mut idx = 0usize;
        for (i, &b) in HISTOGRAM_BUCKETS_SAT_VB.iter().enumerate() {
            if *rate >= b {
                idx = i;
            }
        }
        // Sub-1 sat/vB rates fall under the first bucket (1.0). The
        // histogram floor is 1.0 because below relay-floor txs would
        // be evicted before reaching the mempool.
        bucket_vsizes
            .entry(idx)
            .and_modify(|v| *v = v.saturating_add(*vsize))
            .or_insert(*vsize);
    }
    let mut out: Vec<(f64, u64)> = bucket_vsizes
        .into_iter()
        .map(|(idx, vsize)| (HISTOGRAM_BUCKETS_SAT_VB[idx], vsize))
        .collect();
    // Descending by feerate.
    out.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsize_rounds_up_for_odd_weight() {
        // weight 401 → vsize 101 (ceil(401/4) = 100.25 → 101).
        assert_eq!(vsize_of_weight(401), 101);
        assert_eq!(vsize_of_weight(400), 100);
        assert_eq!(vsize_of_weight(0), 0);
    }

    #[test]
    fn histogram_empty_for_empty_mempool() {
        assert!(build_fee_histogram(&[]).is_empty());
    }

    #[test]
    fn histogram_buckets_by_feerate() {
        // Two txs at 5 sat/vB → one bucket with summed vsize.
        let h = build_fee_histogram(&[(5.0, 200), (5.5, 300)]);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, 5.0);
        assert_eq!(h[0].1, 500);
    }

    #[test]
    fn histogram_descending_by_feerate() {
        let h = build_fee_histogram(&[(2.0, 100), (50.0, 300), (10.0, 200)]);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].0, 50.0);
        assert_eq!(h[1].0, 10.0);
        assert_eq!(h[2].0, 2.0);
    }

    #[test]
    fn histogram_floor_at_1_sat_vb() {
        // Sub-1.0 feerate (e.g. test mempool with manual entries) falls
        // under the lowest bucket (1.0).
        let h = build_fee_histogram(&[(0.5, 100)]);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, 1.0);
    }
}
