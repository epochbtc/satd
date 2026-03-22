use crate::context::McpContext;
use node::rpc::blockchain as rpc;

/// Look up a single UTXO by txid and output index.
pub fn get_utxo(ctx: &McpContext, txid: &str, vout: u32) -> String {
    let result = rpc::get_tx_out(&ctx.chain_state, txid, vout);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Get UTXO set statistics: total outputs, value, and age distribution.
pub fn get_utxo_set_stats(ctx: &McpContext) -> String {
    let result = rpc::get_tx_out_set_info(&ctx.chain_state);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
