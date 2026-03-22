use crate::context::McpContext;
use node::rpc::{psbt, rawtx};
use serde_json::{Value, json};

/// Create an unsigned raw transaction from inputs and outputs.
pub fn create_transaction(inputs: &Value, outputs: &Value, locktime: Option<u32>) -> String {
    let input_slice = match inputs.as_array() {
        Some(arr) => arr.as_slice(),
        None => return json!({"error": "inputs must be an array"}).to_string(),
    };

    match rawtx::create_raw_transaction(input_slice, outputs, locktime) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// Sign a raw transaction with provided private keys.
pub fn sign_transaction(
    ctx: &McpContext,
    hex_tx: &str,
    private_keys: &[String],
    prevtxs: Option<&Value>,
    sighash: Option<&str>,
) -> String {
    let prevtxs_slice = prevtxs.and_then(|v| v.as_array()).map(|v| v.as_slice());

    match rawtx::sign_raw_transaction_with_key(
        &ctx.chain_state,
        hex_tx,
        private_keys,
        prevtxs_slice,
        sighash,
    ) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// Broadcast a signed raw transaction to the network.
pub fn send_transaction(ctx: &McpContext, hex_tx: &str) -> String {
    match rawtx::send_raw_transaction(&ctx.chain_state, &ctx.mempool, hex_tx) {
        Ok(result) => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string()),
        Err((code, msg)) => json!({"error": msg, "code": code}).to_string(),
    }
}

/// PSBT workflow operations.
pub fn psbt_workflow(ctx: &McpContext, action: &str, params: &Value) -> String {
    let result: Result<Value, String> = match action {
        "create" => {
            let empty_obj = Value::Object(Default::default());
            let inputs = params.get("inputs").and_then(|v| v.as_array());
            let outputs = params.get("outputs").unwrap_or(&empty_obj);
            let locktime = params
                .get("locktime")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            let input_slice = inputs.map(|v| v.as_slice()).unwrap_or(&[]);
            psbt::create_psbt(input_slice, outputs, locktime)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "decode" => {
            let psbt_b64 = params
                .get("psbt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            psbt::decode_psbt(psbt_b64)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "analyze" => {
            let psbt_b64 = params
                .get("psbt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            psbt::analyze_psbt(psbt_b64)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "combine" => {
            let psbts: Vec<String> = params
                .get("psbts")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            psbt::combine_psbt(&psbts)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "finalize" => {
            let psbt_b64 = params
                .get("psbt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let extract = params
                .get("extract")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            psbt::finalize_psbt(psbt_b64, extract)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "update" => {
            let psbt_b64 = params
                .get("psbt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            psbt::utxo_update_psbt(&ctx.chain_state, psbt_b64)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "convert" => {
            let hex_tx = params
                .get("hex_tx")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            psbt::convert_to_psbt(hex_tx)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        "join" => {
            let psbts: Vec<String> = params
                .get("psbts")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            psbt::join_psbts(&psbts)
                .map_err(|(code, msg)| format!("Error {}: {}", code, msg))
        }
        _ => Err(format!(
            "Unknown PSBT action: {}. Use: create, decode, analyze, combine, finalize, update, convert, join",
            action
        )),
    };

    match result {
        Ok(val) => serde_json::to_string_pretty(&val).unwrap_or_else(|_| "{}".to_string()),
        Err(msg) => json!({"error": msg}).to_string(),
    }
}
