use crate::net::manager::PeerManager;
use serde_json::{json, Value};

/// Build the `getnetworkinfo` response with live connection data.
pub fn get_network_info(peer_manager: &PeerManager) -> Value {
    let connections = peer_manager.connection_count();
    let onion_reachable = peer_manager.onion_routing_available();
    let randomize = peer_manager.proxy_randomize();
    let clearnet_proxy = peer_manager.proxy_addr().unwrap_or_default();
    let onion_proxy = peer_manager.onion_proxy_addr().unwrap_or_default();
    // proxy_randomize_credentials is only meaningful for a network that
    // actually routes through a proxy.
    let clearnet_randomize = randomize && !clearnet_proxy.is_empty();
    let onion_randomize = randomize && !onion_proxy.is_empty();
    let local_addresses: Vec<Value> = peer_manager
        .local_addresses()
        .into_iter()
        .map(|(address, port, score)| {
            json!({ "address": address, "port": port, "score": score })
        })
        .collect();

    json!({
        // Advertises Bitcoin Core wire-protocol vintage (Core v28).
        // Distinct from `subversion`, which carries satd's own
        // implementation version. Clients use `version` to gate
        // legacy compatibility adapters — `bitcoincore-rpc`
        // pre-`getblockchaininfo` switches softfork shape on
        // `version < 190000`, so anything advertising sub-0.19 here
        // breaks every Core-compat client.
        "version": 280000,
        "subversion": crate::USER_AGENT,
        "protocolversion": 70016,
        "localservices": "0000000000000409",
        "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": connections,
        "connections_in": 0,
        "connections_out": connections,
        "networks": [
            {
                "name": "ipv4",
                "limited": false,
                "reachable": true,
                "proxy": clearnet_proxy.clone(),
                "proxy_randomize_credentials": clearnet_randomize
            },
            {
                "name": "ipv6",
                "limited": false,
                "reachable": true,
                "proxy": clearnet_proxy,
                "proxy_randomize_credentials": clearnet_randomize
            },
            {
                "name": "onion",
                "limited": !onion_reachable,
                "reachable": onion_reachable,
                "proxy": onion_proxy,
                "proxy_randomize_credentials": onion_randomize
            }
        ],
        "relayfee": 0.00001000,
        "incrementalfee": 0.00001000,
        "localaddresses": local_addresses,
        "warnings": ""
    })
}
