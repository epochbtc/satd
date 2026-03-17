use crate::chain::state::ChainState;
use serde_json::Value;

/// Handle the `submitblock` RPC call.
/// Accepts a hex-encoded serialized block, validates it, and connects it to the chain.
/// Returns null on success, or a string describing the rejection reason.
pub fn submit_block(chain_state: &ChainState, hex_block: &str) -> Value {
    let block_bytes = match hex::decode(hex_block) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    let block: bitcoin::Block = match bitcoin::consensus::deserialize(&block_bytes) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    match chain_state.accept_block(block) {
        Ok(_) => Value::Null,
        Err(e) => Value::String(e.to_string()),
    }
}
