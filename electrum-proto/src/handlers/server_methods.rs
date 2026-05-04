//! `server.*` method handlers.
//!
//! Static or near-static metadata endpoints: version negotiation,
//! ping, banner, donation address, feature dict, and the
//! always-empty-list `peers.subscribe`.

use serde_json::{Value, json};

use crate::PROTOCOL_VERSION;
use crate::error::JsonRpcError;
use crate::state::ElectrumState;

/// `server.version([client_name, protocol_version])` — returns
/// `[server_name, protocol_version]`. Per the Electrum spec, the
/// client may pass either a single string for `protocol_version` or a
/// `[min, max]` pair; we accept both and report a single supported
/// version. If the requested range excludes ours we error with
/// `code 1`.
pub fn version(_state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // Client name + protocol-version arg are both optional. We do
    // intersection logic only when we got a useful protocol-version.
    let arr = match &params {
        Value::Array(a) => a.clone(),
        _ => Vec::new(),
    };

    let _client_name = arr.first().and_then(|v| v.as_str()).unwrap_or("");
    let proto_arg = arr.get(1).cloned().unwrap_or(Value::Null);

    let supported = PROTOCOL_VERSION;
    // Per the Electrum spec, the client's protocol_version arg is
    // either a single string (the minimum version the client requires)
    // or an explicit `[min, max]` pair. In the single-string case
    // there is no upper bound — the server picks its own version
    // unconditionally as long as it's >= the client's min.
    let intersect_ok = match &proto_arg {
        Value::Null => true,
        Value::String(min) => !matches!(version_compare(supported, min), std::cmp::Ordering::Less),
        Value::Array(a) => {
            let min = a.first().and_then(|v| v.as_str()).unwrap_or(supported);
            let max = a.get(1).and_then(|v| v.as_str()).unwrap_or(supported);
            version_in_range(min, max, supported)
        }
        _ => true,
    };

    if !intersect_ok {
        return Err(JsonRpcError::new(
            1,
            format!("unsupported protocol version range; server speaks {supported}"),
        ));
    }

    let server_name = format!("satd/{}", env!("CARGO_PKG_VERSION"));
    Ok(json!([server_name, supported]))
}

/// `server.ping()` — returns `null`.
pub fn ping() -> Result<Value, JsonRpcError> {
    Ok(Value::Null)
}

/// `server.banner()` — returns the configured banner or a default
/// composed at request time.
pub fn banner(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let s = state.config.banner.clone().unwrap_or_else(|| {
        format!(
            "powered by satd {}\nhttps://github.com/epochbtc/satd",
            env!("CARGO_PKG_VERSION")
        )
    });
    Ok(Value::String(s))
}

/// `server.donation_address()` — returns the configured donation
/// address (empty string by default).
pub fn donation_address(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    Ok(Value::String(state.config.donation_address.clone()))
}

/// `server.features()` — small descriptor dict consumed by some
/// clients. We expose the honest minimum: hosts (empty), genesis hash,
/// supported protocol min/max (both = our PROTOCOL_VERSION since we
/// don't negotiate), and a server name. No pruning advertisement.
pub fn features(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let genesis_hash = state
        .chain
        .get_block_hash_by_height(0)
        .map(|h| h.to_string())
        .unwrap_or_default();
    Ok(json!({
        "genesis_hash": genesis_hash,
        "hosts": serde_json::Map::new(),
        "protocol_max": PROTOCOL_VERSION,
        "protocol_min": PROTOCOL_VERSION,
        "pruning": serde_json::Value::Null,
        "server_version": format!("satd/{}", env!("CARGO_PKG_VERSION")),
        "hash_function": "sha256",
    }))
}

/// `server.peers.subscribe()` — always returns `[]`. We're not part of
/// the Electrum-server peer mesh; future-work flag in the plan.
pub fn peers_subscribe() -> Result<Value, JsonRpcError> {
    Ok(Value::Array(Vec::new()))
}

/// Dotted-version comparison: `"1.4.5" < "1.5"` etc. Lexicographic on
/// numeric components.
fn version_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let parse =
        |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect() };
    parse(a).cmp(&parse(b))
}

fn version_in_range(min: &str, max: &str, ours: &str) -> bool {
    use std::cmp::Ordering::*;
    !matches!(version_compare(ours, min), Less) && !matches!(version_compare(ours, max), Greater)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_basic() {
        assert_eq!(version_compare("1.4.5", "1.4.5"), std::cmp::Ordering::Equal);
        assert_eq!(version_compare("1.4", "1.4.5"), std::cmp::Ordering::Less);
        assert_eq!(version_compare("1.5", "1.4.5"), std::cmp::Ordering::Greater);
        assert_eq!(version_compare("2.0", "1.99"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn version_in_range_inclusive() {
        assert!(version_in_range("1.0", "1.5", "1.4.5"));
        assert!(version_in_range("1.4.5", "1.4.5", "1.4.5"));
        assert!(!version_in_range("1.5", "2.0", "1.4.5"));
        assert!(!version_in_range("1.0", "1.3", "1.4.5"));
    }
}
