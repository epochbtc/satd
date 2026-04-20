use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::mining::template::create_template;
use crate::storage::blockindex::target_to_difficulty;
use serde_json::{json, Value};

/// Handle the `submitblock` RPC call.
pub fn submit_block(chain_state: &ChainState, mempool: &Mempool, hex_block: &str) -> Value {
    let block_bytes = match hex::decode(hex_block) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    let block: bitcoin::Block = match bitcoin::consensus::deserialize(&block_bytes) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    match chain_state.accept_block(&block) {
        Ok(_) => {
            mempool.remove_for_block(&block, chain_state.tip_height());
            Value::Null
        }
        Err(e) => Value::String(e.to_string()),
    }
}

/// Handle the `generatetoaddress` RPC call (regtest only).
pub fn generate_to_address(
    chain_state: &ChainState,
    mempool: &Mempool,
    nblocks: u32,
    address: &str,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generatetoaddress is only available in regtest mode".to_string()));
    }

    let hashes = crate::mining::miner::mine_blocks(chain_state, mempool, address, nblocks)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!(hashes))
}

/// Handle the `generateblock` RPC call (regtest only).
pub fn generate_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generateblock is only available in regtest mode".to_string()));
    }

    let block = crate::mining::miner::mine_block(chain_state, mempool, address)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!({ "hash": block.block_hash().to_string() }))
}

/// Handle the `getblocktemplate` RPC call.
pub fn get_block_template(chain_state: &ChainState, mempool: &Mempool) -> Value {
    let template = create_template(chain_state, mempool);

    let txs: Vec<Value> = template
        .transactions
        .iter()
        .map(|ttx| {
            let raw = bitcoin::consensus::serialize(&ttx.tx);
            json!({
                "data": hex::encode(&raw),
                "txid": ttx.tx.compute_txid().to_string(),
                "fee": ttx.fee,
                "weight": ttx.weight,
            })
        })
        .collect();

    // Compute target from compact bits
    let target = crate::storage::blockindex::target_from_compact(template.bits);
    let target_hex = hex::encode(target);

    json!({
        "version": template.version,
        "rules": ["csv", "segwit", "taproot"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": template.prev_hash.to_string(),
        "transactions": txs,
        "coinbaseaux": { "flags": "" },
        "coinbasevalue": template.coinbase_value,
        "target": format!("{:0>64}", target_hex),
        "mintime": template.cur_time,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "capabilities": ["proposal"],
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": template.cur_time,
        "bits": format!("{:08x}", template.bits.to_consensus()),
        "height": template.height,
        "default_witness_commitment": crate::mining::template::compute_witness_commitment_hex(&template.transactions),
        "longpollid": format!("{}{:x}", template.prev_hash, template.cur_time),
        "expires": 120,
    })
}

/// `getmininginfo` — return mining-related info.
pub fn get_mining_info(chain_state: &ChainState) -> Value {
    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();
    let difficulty = if let Some(entry) = chain_state.get_block_index(&tip_hash) {
        target_to_difficulty(entry.header.bits)
    } else {
        0.0
    };
    let hashps = get_network_hash_ps(chain_state, None, None);

    let chain = match chain_state.network {
        bitcoin::Network::Regtest => "regtest",
        bitcoin::Network::Testnet => "test",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Bitcoin => "main",
        _ => "main",
    };

    json!({
        "blocks": tip_height,
        "difficulty": difficulty,
        "networkhashps": hashps,
        "pooledtx": 0,
        "chain": chain,
        "warnings": "",
    })
}

/// `getnetworkhashps` — estimate network hash rate from recent blocks.
pub fn get_network_hash_ps(
    chain_state: &ChainState,
    nblocks: Option<u32>,
    height: Option<u32>,
) -> f64 {
    let tip_height = height.unwrap_or_else(|| chain_state.tip_height());
    let window = nblocks.unwrap_or(120).min(tip_height);

    if window == 0 {
        return 0.0;
    }

    let end_height = tip_height;
    let start_height = end_height.saturating_sub(window);

    let end_hash = match chain_state.get_block_hash_by_height(end_height) {
        Some(h) => h,
        None => return 0.0,
    };
    let start_hash = match chain_state.get_block_hash_by_height(start_height) {
        Some(h) => h,
        None => return 0.0,
    };

    let end_entry = match chain_state.get_block_index(&end_hash) {
        Some(e) => e,
        None => return 0.0,
    };
    let start_entry = match chain_state.get_block_index(&start_hash) {
        Some(e) => e,
        None => return 0.0,
    };

    let time_diff = end_entry.header.time.saturating_sub(start_entry.header.time) as f64;
    if time_diff == 0.0 {
        return 0.0;
    }

    // Estimate: difficulty * 2^32 / time_diff
    let difficulty = target_to_difficulty(end_entry.header.bits);
    difficulty * 4_294_967_296.0 / time_diff
}

/// `submitheader` — accept a block header.
pub fn submit_header(chain_state: &ChainState, hex_header: &str) -> Result<Value, String> {
    let header_bytes = hex::decode(hex_header).map_err(|_| "Invalid hex".to_string())?;
    let header: bitcoin::block::Header =
        bitcoin::consensus::deserialize(&header_bytes).map_err(|_| "Header decode failed".to_string())?;
    chain_state
        .accept_header(&header)
        .map_err(|e| e.to_string())?;
    Ok(Value::Null)
}
