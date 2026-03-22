use crate::context::McpContext;
use serde_json::json;

/// Estimate fee rates for multiple confirmation targets.
pub fn estimate_fee(ctx: &McpContext, targets: &[u32]) -> String {
    let estimates: Vec<_> = targets
        .iter()
        .map(|&target| {
            let fee_rate_sat_kvb = ctx
                .fee_estimator
                .estimate_fee(target)
                .unwrap_or(1_000); // fallback: 1 sat/vB = 1000 sat/kvB
            let fee_rate_btc_kvb = fee_rate_sat_kvb as f64 / 100_000_000.0;
            let fee_rate_sat_vb = fee_rate_sat_kvb as f64 / 1000.0;
            json!({
                "target_blocks": target,
                "fee_rate_btc_kvb": fee_rate_btc_kvb,
                "fee_rate_sat_vb": format!("{:.2}", fee_rate_sat_vb),
            })
        })
        .collect();

    let result = json!({
        "estimates": estimates,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
