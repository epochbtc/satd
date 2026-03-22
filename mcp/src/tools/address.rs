use node::rpc::util;

/// Validate a Bitcoin address and return type, script, and witness info.
pub fn validate_address(address: &str) -> String {
    let result = util::validate_address(address);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
