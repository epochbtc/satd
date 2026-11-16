//! `/fee-estimates` leaves out every target the node has no estimate for.

use node::mempool::estimate::{
    EstimateMode, MAX_SIM_DEPTH, estimate_from_mempool, smart_fees_from_estimate,
};
use node::mempool::fee::FeeEstimator;

use super::*;

fn map_for(fee_estimator: &FeeEstimator) -> serde_json::Map<String, Value> {
    // An empty mempool: no simulated block carries any transaction.
    let est = estimate_from_mempool(Vec::new(), MAX_SIM_DEPTH);
    let sf = smart_fees_from_estimate(
        &est,
        fee_estimator,
        None,
        FEE_TARGETS,
        EstimateMode::Blend,
        false,
        1_000,
    );
    fee_estimates_map(&sf)
}

/// No mempool signal and no confirmed-block fee history (IBD, a cold start):
/// there is no estimate for any target, so the object is empty instead of
/// every target reading the 1 sat/vB floor.
#[test]
fn fee_estimates_map_is_empty_without_a_fee_signal() {
    let map = map_for(&FeeEstimator::new());
    assert!(map.is_empty(), "no target has an estimate, got {map:?}");
}

/// With confirmed-block fee history every target has an estimate and is
/// listed, in sat/vB.
#[test]
fn fee_estimates_map_lists_every_target_with_an_estimate() {
    let fee_estimator = FeeEstimator::new();
    fee_estimator.record_block(&[5_000; 50]);
    let map = map_for(&fee_estimator);
    assert_eq!(map.len(), FEE_TARGETS.len(), "{map:?}");
    for t in FEE_TARGETS {
        assert_eq!(map[&t.to_string()], serde_json::json!(5.0), "target {t}");
    }
}

/// A healthy mempool side (the template percentile at 20 sat/vB) and no fee
/// history: targets 1 and 2 have an estimate from the mempool side and are
/// listed with the values every other fee surface reports; every deeper
/// target has no history, so it fell back to the floor and is left out. The
/// floored targets are the deepest ones, so the clamp never carried the floor
/// into a listed target.
#[test]
fn fee_estimates_map_keeps_mempool_targets_and_leaves_out_floored_ones() {
    let est = estimate_from_mempool(Vec::new(), MAX_SIM_DEPTH);
    let sf = smart_fees_from_estimate(
        &est,
        &FeeEstimator::new(),
        Some(20_000),
        FEE_TARGETS,
        EstimateMode::Blend,
        false,
        1_000,
    );
    let map = fee_estimates_map(&sf);
    assert_eq!(
        Value::Object(map.clone()),
        serde_json::json!({"1": 20.0, "2": 20.0})
    );
    for tf in &sf.targets {
        if let Some(v) = map.get(&tf.target.to_string()) {
            assert_eq!(*v, serde_json::json!(tf.feerate_sat_per_kvb as f64 / 1000.0));
        }
    }
}
