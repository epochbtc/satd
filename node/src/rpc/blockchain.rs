use bitcoin::Network;
use bitcoin::consensus::serialize;
use serde_json::{json, Value};

use crate::chain::state::ChainState;
use crate::storage::blockindex::target_to_difficulty;

/// Build the `getblockchaininfo` response from real chain state.
pub fn get_blockchain_info(chain_state: &ChainState) -> Value {
    let chain = match chain_state.network {
        Network::Regtest => "regtest",
        Network::Testnet => "test",
        Network::Signet => "signet",
        Network::Bitcoin => "main",
        _ => "main",
    };

    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();

    let (difficulty, time, mediantime, chainwork) =
        if let Some(entry) = chain_state.get_block_index(&tip_hash) {
            let cw_hex = hex::encode(entry.chainwork);
            (
                target_to_difficulty(entry.header.bits),
                entry.header.time as u64,
                entry.header.time as u64, // simplified; proper MTP would need ancestor walk
                cw_hex,
            )
        } else {
            (0.0, 0u64, 0u64, "0".to_string())
        };

    json!({
        "chain": chain,
        "blocks": tip_height,
        "headers": tip_height,
        "bestblockhash": tip_hash.to_string(),
        "difficulty": difficulty,
        "time": time,
        "mediantime": mediantime,
        "verificationprogress": 1.0,
        "initialblockdownload": tip_height == 0,
        "chainwork": format!("{:0>64}", chainwork),
        "size_on_disk": 0,
        "pruned": false,
        "warnings": ""
    })
}

/// `getbestblockhash` — return the tip block hash.
pub fn get_best_block_hash(chain_state: &ChainState) -> Value {
    Value::String(chain_state.tip_hash().to_string())
}

/// `getblockcount` — return the height of the tip.
pub fn get_block_count(chain_state: &ChainState) -> Value {
    json!(chain_state.tip_height())
}

/// `getblockhash` — return the block hash at a given height.
pub fn get_block_hash(
    chain_state: &ChainState,
    height: u32,
) -> Result<Value, String> {
    if height > chain_state.tip_height() {
        return Err("Block height out of range".to_string());
    }
    match chain_state.get_block_hash_by_height(height) {
        Some(hash) => Ok(Value::String(hash.to_string())),
        None => Err("Block height out of range".to_string()),
    }
}

/// `getblock` — return block data at given verbosity.
/// verbosity 0: raw hex
/// verbosity 1 (default): JSON with header + txids
pub fn get_block(
    chain_state: &ChainState,
    hash_str: &str,
    verbosity: u32,
) -> Result<Value, String> {
    let hash: bitcoin::BlockHash = hash_str
        .parse()
        .map_err(|_| "Invalid block hash".to_string())?;

    let entry = chain_state
        .get_block_index(&hash)
        .ok_or("Block not found")?;

    if verbosity == 0 {
        let block = chain_state
            .get_block(&hash)
            .ok_or("Block data not available")?;
        let raw = serialize(&block);
        return Ok(Value::String(hex::encode(raw)));
    }

    // verbosity >= 1: JSON response
    let block = chain_state
        .get_block(&hash)
        .ok_or("Block data not available")?;

    let txids: Vec<String> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();

    let difficulty = target_to_difficulty(entry.header.bits);
    let chainwork_hex = hex::encode(entry.chainwork);
    let block_size = serialize(&block).len();

    let confirmations = if chain_state.tip_height() >= entry.height {
        chain_state.tip_height() - entry.height + 1
    } else {
        0
    };

    let prev_hash = if entry.height > 0 {
        Some(entry.header.prev_blockhash.to_string())
    } else {
        None
    };

    let next_hash = chain_state
        .get_block_hash_by_height(entry.height + 1)
        .map(|h| h.to_string());

    let mut result = json!({
        "hash": hash.to_string(),
        "confirmations": confirmations,
        "height": entry.height,
        "version": entry.header.version.to_consensus(),
        "versionHex": format!("{:08x}", entry.header.version.to_consensus()),
        "merkleroot": entry.header.merkle_root.to_string(),
        "tx": txids,
        "time": entry.header.time,
        "mediantime": entry.header.time,
        "nonce": entry.header.nonce,
        "bits": format!("{:08x}", entry.header.bits.to_consensus()),
        "difficulty": difficulty,
        "chainwork": format!("{:0>64}", chainwork_hex),
        "nTx": entry.num_tx,
        "size": block_size,
        "weight": block.weight().to_wu(),
    });

    if let Some(ph) = prev_hash {
        result["previousblockhash"] = Value::String(ph);
    }
    if let Some(nh) = next_hash {
        result["nextblockhash"] = Value::String(nh);
    }

    Ok(result)
}

/// `getblockheader` — return block header data.
/// verbose=false: hex-encoded 80-byte header
/// verbose=true (default): JSON
pub fn get_block_header(
    chain_state: &ChainState,
    hash_str: &str,
    verbose: bool,
) -> Result<Value, String> {
    let hash: bitcoin::BlockHash = hash_str
        .parse()
        .map_err(|_| "Invalid block hash".to_string())?;

    let entry = chain_state
        .get_block_index(&hash)
        .ok_or("Block not found")?;

    if !verbose {
        let raw = serialize(&entry.header);
        return Ok(Value::String(hex::encode(raw)));
    }

    let difficulty = target_to_difficulty(entry.header.bits);
    let chainwork_hex = hex::encode(entry.chainwork);

    let confirmations = if chain_state.tip_height() >= entry.height {
        chain_state.tip_height() - entry.height + 1
    } else {
        0
    };

    let prev_hash = if entry.height > 0 {
        Some(entry.header.prev_blockhash.to_string())
    } else {
        None
    };

    let next_hash = chain_state
        .get_block_hash_by_height(entry.height + 1)
        .map(|h| h.to_string());

    let mut result = json!({
        "hash": hash.to_string(),
        "confirmations": confirmations,
        "height": entry.height,
        "version": entry.header.version.to_consensus(),
        "versionHex": format!("{:08x}", entry.header.version.to_consensus()),
        "merkleroot": entry.header.merkle_root.to_string(),
        "time": entry.header.time,
        "mediantime": entry.header.time,
        "nonce": entry.header.nonce,
        "bits": format!("{:08x}", entry.header.bits.to_consensus()),
        "difficulty": difficulty,
        "chainwork": format!("{:0>64}", chainwork_hex),
        "nTx": entry.num_tx,
    });

    if let Some(ph) = prev_hash {
        result["previousblockhash"] = Value::String(ph);
    }
    if let Some(nh) = next_hash {
        result["nextblockhash"] = Value::String(nh);
    }

    Ok(result)
}

/// `gettxout` — query a single UTXO.
pub fn get_tx_out(
    chain_state: &ChainState,
    txid_str: &str,
    vout: u32,
) -> Result<Value, String> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| "Invalid txid".to_string())?;

    let outpoint = bitcoin::OutPoint { txid, vout };

    let coin = chain_state
        .get_coin(&outpoint)
        .ok_or("UTXO not found".to_string())?;

    let value_btc = coin.amount as f64 / 100_000_000.0;
    let confirmations = if chain_state.tip_height() >= coin.height {
        chain_state.tip_height() - coin.height + 1
    } else {
        0
    };

    Ok(json!({
        "bestblock": chain_state.tip_hash().to_string(),
        "confirmations": confirmations,
        "value": value_btc,
        "scriptPubKey": {
            "hex": hex::encode(coin.script_pubkey.as_bytes()),
        },
        "coinbase": coin.coinbase,
    }))
}

/// `gettxoutsetinfo` — return UTXO set statistics.
pub fn get_tx_out_set_info(chain_state: &ChainState) -> Value {
    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();
    let coin_count = chain_state.coin_count();

    json!({
        "height": tip_height,
        "bestblock": tip_hash.to_string(),
        "txouts": coin_count,
        "bogosize": coin_count * 50,
        "total_amount": 0.0,
        "hash_serialized_3": "",
    })
}
