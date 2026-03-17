use bitcoin::Network;
use serde_json::{json, Value};

/// Build the `getblockchaininfo` response for the current chain state.
/// For M1, this returns genesis-only stub data.
pub fn get_blockchain_info(network: Network, genesis_hash: &str) -> Value {
    let chain = match network {
        Network::Regtest => "regtest",
        Network::Testnet => "test",
        Network::Bitcoin => "main",
        _ => "main",
    };

    json!({
        "chain": chain,
        "blocks": 0,
        "headers": 0,
        "bestblockhash": genesis_hash,
        "difficulty": 4.656542373906925e-10_f64,
        "time": 1296688602_u64,
        "mediantime": 1296688602_u64,
        "verificationprogress": 1.0,
        "initialblockdownload": true,
        "chainwork": "0000000000000000000000000000000000000000000000000000000000000002",
        "size_on_disk": 293,
        "pruned": false,
        "warnings": ""
    })
}
