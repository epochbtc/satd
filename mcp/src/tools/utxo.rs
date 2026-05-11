use crate::context::McpContext;
use node::rpc::blockchain as rpc;
use serde_json::json;

/// Look up a single UTXO by txid and output index.
pub fn get_utxo(ctx: &McpContext, txid: &str, vout: u32) -> String {
    match rpc::get_tx_out(&ctx.chain_state, txid, vout) {
        // `rpc::get_tx_out` returns `Value::Null` for a missing or
        // spent outpoint (Core-compat). For the MCP surface we
        // re-shape that into the documented `{"error": ...}` form so
        // the LLM consumer sees a uniform error contract.
        Ok(serde_json::Value::Null) => json!({"error": "UTXO not found"}).to_string(),
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err(msg) => json!({"error": msg}).to_string(),
    }
}

/// Get UTXO set statistics: total outputs, value, and age distribution.
pub fn get_utxo_set_stats(ctx: &McpContext) -> String {
    let result = rpc::get_tx_out_set_info(&ctx.chain_state);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
