use serde_json::{json, Value};

/// Build the `getnetworkinfo` response.
/// For M1, returns static stub data with zero connections.
pub fn get_network_info() -> Value {
    json!({
        "version": 10000,
        "subversion": "/btcd:0.1.0/",
        "protocolversion": 70016,
        "localservices": "0000000000000409",
        "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": 0,
        "connections_in": 0,
        "connections_out": 0,
        "networks": [
            {
                "name": "ipv4",
                "limited": false,
                "reachable": true,
                "proxy": "",
                "proxy_randomize_credentials": false
            },
            {
                "name": "ipv6",
                "limited": false,
                "reachable": true,
                "proxy": "",
                "proxy_randomize_credentials": false
            },
            {
                "name": "onion",
                "limited": true,
                "reachable": false,
                "proxy": "",
                "proxy_randomize_credentials": false
            }
        ],
        "relayfee": 0.00001000,
        "incrementalfee": 0.00001000,
        "localaddresses": [],
        "warnings": ""
    })
}
