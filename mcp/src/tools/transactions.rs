use crate::context::McpContext;
use node::rpc::rawtx;
use serde_json::json;

/// Look up a transaction by txid from both chain and mempool.
pub fn get_transaction(ctx: &McpContext, txid: &str, blockhash: Option<&str>) -> String {
    match rawtx::get_raw_transaction(&ctx.chain_state, &ctx.mempool, txid, true, blockhash) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// Parse a hex-encoded raw transaction into JSON.
pub fn decode_raw_transaction(hex_tx: &str) -> String {
    match rawtx::decode_raw_transaction(hex_tx) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// Decode a hex-encoded script into opcodes, type, and addresses.
pub fn decode_script(hex_script: &str) -> String {
    match rawtx::decode_script(hex_script) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}
