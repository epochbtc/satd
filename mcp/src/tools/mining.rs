use crate::context::McpContext;
use node::rpc::mining as rpc;
use serde_json::json;

/// Get mining info: difficulty, network hashrate, chain height.
pub fn get_mining_info(ctx: &McpContext) -> String {
    let info = rpc::get_mining_info(&ctx.chain_state);
    let hashps = rpc::get_network_hash_ps(&ctx.chain_state, None, None);

    let result = json!({
        "mining_info": info,
        "network_hashrate": hashps,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Mine blocks to an address (regtest only).
pub fn generate_blocks(ctx: &McpContext, count: u32, address: &str) -> String {
    match rpc::generate_to_address(&ctx.chain_state, &ctx.mempool, count, address) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// Get a block template for mining.
pub fn get_block_template(ctx: &McpContext) -> String {
    let result = rpc::get_block_template(&ctx.chain_state, &ctx.mempool);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
