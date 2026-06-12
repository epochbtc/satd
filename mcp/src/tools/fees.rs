use crate::context::McpContext;
use node::mempool::estimate::{EstimateMode, smart_fees};
use serde_json::json;

/// Estimate fee rates for multiple confirmation targets.
///
/// Routes through the shared `smart_fees` resolver in blend mode, so the
/// numbers agree with the JSON-RPC `estimatefees`, the TUI fee panel, the
/// Esplora `/fee-estimates` endpoint and Electrum `blockchain.estimatefee`.
/// Rates are sat/kvB internally; we surface both BTC/kvB and sat/vB.
pub fn estimate_fee(ctx: &McpContext, targets: &[u32]) -> String {
    let floor_sat_per_kvb = ctx.mempool.min_fee_rate().max(1_000);
    let sf = smart_fees(
        ctx.mempool.get_all_entries(),
        &ctx.fee_estimator,
        targets,
        EstimateMode::Blend,
        floor_sat_per_kvb,
    );

    let estimates: Vec<_> = sf
        .targets
        .iter()
        .map(|tf| {
            json!({
                "target_blocks": tf.target,
                "fee_rate_btc_kvb": tf.feerate_sat_per_kvb as f64 / 100_000_000.0,
                "fee_rate_sat_vb": format!("{:.2}", tf.feerate_sat_per_kvb as f64 / 1000.0),
                "confidence": tf.confidence.as_str(),
            })
        })
        .collect();

    let result = json!({
        "estimates": estimates,
        "economy_fee_rate_sat_vb": format!("{:.2}", sf.economy_feerate_sat_per_kvb as f64 / 1000.0),
        "mode": sf.mode.as_str(),
        "mempool_thin": sf.thin_block,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
