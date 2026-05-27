use crate::context::McpContext;
use node::rpc::blockchain as rpc;
use serde_json::json;

/// Resolve an identifier (hash or height string) to a block hash string.
fn resolve_hash(ctx: &McpContext, identifier: &str) -> Result<String, String> {
    if let Ok(height) = identifier.parse::<u32>() {
        match rpc::get_block_hash(&ctx.chain_state, height) {
            Ok(val) => Ok(val.as_str().unwrap_or_default().to_string()),
            Err(msg) => Err(msg),
        }
    } else {
        Ok(identifier.to_string())
    }
}

/// Retrieve a block by hash or height. Verbosity: "summary" (header+txids), "full" (decoded txs), "raw" (hex).
pub fn get_block(ctx: &McpContext, identifier: &str, verbosity: &str) -> String {
    let hash_str = match resolve_hash(ctx, identifier) {
        Ok(h) => h,
        Err(msg) => return json!({"error": msg}).to_string(),
    };

    let verbosity_int = match verbosity {
        "raw" => 0,
        "full" => 2,
        _ => 1, // "summary" default
    };

    match rpc::get_block(&ctx.chain_state, &hash_str, verbosity_int) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err(msg) => json!({"error": msg}).to_string(),
    }
}

/// Retrieve a block header by hash or height.
pub fn get_block_header(ctx: &McpContext, identifier: &str, raw: bool) -> String {
    let hash_str = match resolve_hash(ctx, identifier) {
        Ok(h) => h,
        Err(msg) => return json!({"error": msg}).to_string(),
    };

    match rpc::get_block_header(&ctx.chain_state, &hash_str, !raw) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err(msg) => json!({"error": msg}).to_string(),
    }
}

/// Get detailed statistics for a block: fee rates, sizes, tx counts, UTXO changes.
pub fn get_block_stats(ctx: &McpContext, identifier: &str) -> String {
    match rpc::get_block_stats(&ctx.chain_state, identifier) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err(msg) => json!({"error": msg}).to_string(),
    }
}

/// Get chain analysis: tips, tx rate over a window, and difficulty.
pub fn get_chain_info(ctx: &McpContext, window: u32) -> String {
    let tips = rpc::get_chain_tips(&ctx.chain_state);
    let tx_stats = rpc::get_chain_tx_stats(&ctx.chain_state, Some(window), None);
    let difficulty = rpc::get_difficulty(&ctx.chain_state);

    let result = json!({
        "chain_tips": tips,
        "tx_stats": tx_stats,
        "difficulty": difficulty,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Retrieve headers for a range of blocks (max 100).
pub fn search_block_range(ctx: &McpContext, start_height: u32, end_height: u32) -> String {
    let end = end_height.min(start_height + 99); // cap at 100 blocks
    let mut headers = Vec::new();

    for h in start_height..=end {
        match rpc::get_block_hash(&ctx.chain_state, h) {
            Ok(val) => {
                let hash_str = val.as_str().unwrap_or_default();
                match rpc::get_block_header(&ctx.chain_state, hash_str, true) {
                    Ok(header) => headers.push(header),
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }

    let result = json!({
        "start_height": start_height,
        "end_height": end,
        "count": headers.len(),
        "headers": headers,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
