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
/// `[server_name, protocol_version]`. Per the Electrum spec (and
/// `romanz/electrs`'s implementation), the client may pass either a
/// single string for `protocol_version` (interpreted as a single
/// **exact** target version) or a `[min, max]` pair. The single-string
/// form is NOT a min-only — electrs's `check_between(version, single,
/// single)` rejects clients that don't match exactly. We mirror that
/// to keep the `server.version` contract identical.
pub fn version(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // Client name + protocol-version arg are both optional. We do
    // intersection logic only when we got a useful protocol-version.
    let arr = match &params {
        Value::Array(a) => a.clone(),
        _ => Vec::new(),
    };

    let _client_name = arr.first().and_then(|v| v.as_str()).unwrap_or("");
    let proto_arg = arr.get(1).cloned().unwrap_or(Value::Null);

    let supported = PROTOCOL_VERSION;
    // Spec / electrs:
    // - missing or null: accept; pick our supported version.
    // - single string: must match supported EXACTLY.
    // - [min, max] pair: supported must lie in [min, max].
    let intersect_ok = match &proto_arg {
        Value::Null => true,
        Value::String(exact) => version_in_range(exact, exact, supported),
        Value::Array(a) => {
            let min = a.first().and_then(|v| v.as_str()).unwrap_or(supported);
            let max = a.get(1).and_then(|v| v.as_str()).unwrap_or(supported);
            version_in_range(min, max, supported)
        }
        _ => true,
    };

    if !intersect_ok {
        return Err(JsonRpcError::bad_request(format!(
            "unsupported protocol version; server speaks {supported}"
        )));
    }

    Ok(json!([server_name(state), supported]))
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
/// clients. Mirrors `romanz/electrs`'s shape: genesis hash, supported
/// protocol min/max (both = our PROTOCOL_VERSION since we don't
/// negotiate), server name, and the `hosts` map populated with
/// `tcp_port` (and `ssl_port` when TLS is bound) so peer-discovery
/// clients can distinguish service ports.
pub fn features(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let genesis_hash = state
        .chain
        .get_block_hash_by_height(0)
        .map(|h| h.to_string())
        .unwrap_or_default();
    let mut host_entry = serde_json::Map::new();
    host_entry.insert("tcp_port".into(), json!(state.config.bind.port()));
    if let Some(tls) = state.config.tls_bind {
        host_entry.insert("ssl_port".into(), json!(tls.port()));
    }
    let mut hosts = serde_json::Map::new();
    // Use the bind host as the dictionary key. Real electrs
    // deployments key on the public hostname; here we only know the
    // bound socket, which is good enough for clients that round-trip
    // the structure (Sparrow, Electrum desktop) and don't validate
    // hostnames.
    hosts.insert(
        state.config.bind.ip().to_string(),
        Value::Object(host_entry),
    );
    Ok(json!({
        "genesis_hash": genesis_hash,
        "hosts": hosts,
        "protocol_max": PROTOCOL_VERSION,
        "protocol_min": PROTOCOL_VERSION,
        "pruning": serde_json::Value::Null,
        "server_version": server_name(state),
        "hash_function": "sha256",
        // Whether `blockchain.tweaks.subscribe` can actually be served on this
        // node right now. Deliberately the same test `TweakSource::from_state`
        // makes — index present AND complete — not merely "the operator turned
        // the index on". A node whose backfill is still running has the index
        // configured and refuses every subscribe, so reporting `true` there
        // would send a wallet to a backend that cannot answer it for hours.
        "tweaks": state.sp_index.as_ref().is_some_and(|i| i.is_complete()),
    }))
}

/// The name reported to clients, as `server.version`'s first element and
/// `server.features.server_version`.
///
/// Defaults to `satd-electrs-compatible/<version>`: identity first, then a
/// compatibility token, on the same principle that keeps `Mozilla` at the front
/// of every browser user-agent long after it stopped meaning anything about who
/// wrote the browser. The token is load-bearing rather than decorative --
/// Electrum's `server.version` carries no capability field, so clients feature-
/// detect by matching on this string, and Cake Wallet will not probe
/// `blockchain.tweaks.subscribe` at all unless it contains the substring
/// `electrs`. Spelling it `electrum` would read the same to a human and signal
/// nothing to the client.
///
/// It is a claim about the protocol satd speaks, not about the software it is:
/// the name leads with `satd`, and the P2P surface is untouched -- peers see
/// `node::USER_AGENT` (`/satd:<version>/`), which this cannot change.
///
/// An operator can override it with `electrumservername` -- to drop the
/// compatibility token, or to adopt a different one if another client gates on
/// a different string.
fn server_name(state: &ElectrumState) -> String {
    state
        .config
        .server_name
        .clone()
        .unwrap_or_else(|| format!("satd-electrs-compatible/{}", env!("CARGO_PKG_VERSION")))
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

    #[test]
    fn version_in_range_single_exact_match() {
        // Per electrs, single-string `protocol_version` is an exact
        // target — `check_between(ours, single, single)`. Our
        // PROTOCOL_VERSION is "1.4"; a client sending "1.4" passes,
        // a client sending "1.4.5" or "1.5" does not.
        assert!(version_in_range("1.4", "1.4", "1.4"));
        assert!(!version_in_range("1.4.5", "1.4.5", "1.4"));
        assert!(!version_in_range("1.5", "1.5", "1.4"));
    }
}
