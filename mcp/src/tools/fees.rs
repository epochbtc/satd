use crate::context::McpContext;
use node::mempool::estimate::{EstimateMode, near_rate, smart_fees};
use serde_json::json;

/// Estimate fee rates for multiple confirmation targets.
///
/// Routes through the shared `smart_fees` resolver in blend mode (the
/// default estimate), so the
/// numbers agree with the JSON-RPC `estimatefees`, the TUI fee panel, the
/// Esplora `/fee-estimates` endpoint and Electrum `blockchain.estimatefee`.
/// Rates are sat/kvB internally; we surface both BTC/kvB and sat/vB.
pub fn estimate_fee(ctx: &McpContext, targets: &[u32]) -> String {
    let floor_sat_per_kvb = ctx.mempool.fee_estimate_floor();
    let sf = smart_fees(
        // Fee-estimation surface (design §2.4): the template view, so a tx
        // quarantined `on template` can't inflate the quote — matching the
        // JSON-RPC estimatefees / Electrum / Esplora fee paths.
        ctx.mempool.get_template_entries(),
        &ctx.fee_estimator,
        near_rate(&ctx.mempool, &ctx.fee_estimator, false),
        targets,
        EstimateMode::Blend,
        false,
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

    let mut result = json!({
        "estimates": estimates,
        "mode": sf.mode.as_str(),
        "mempool_thin": sf.thin_block,
    });
    // Left out when there is no economy estimate (0 under a zero floor).
    if let Some(economy) = sf.economy_feerate_sat_per_kvb {
        result["economy_fee_rate_sat_vb"] = json!(format!("{:.2}", economy as f64 / 1000.0));
    }

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
