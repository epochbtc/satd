use bitcoin::Network;
use bitcoin::consensus::serialize;
use serde_json::{json, Value};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::rpc::amounts::{annotate_units, default_unit, format_amount};
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

    // IBD heuristic: if tip is more than 24 hours behind wall clock, we're in IBD
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let is_ibd = time + 86400 < now;

    json!({
        "chain": chain,
        "blocks": tip_height,
        "headers": chain_state.headers_tip_height().max(tip_height),
        "bestblockhash": tip_hash.to_string(),
        "difficulty": difficulty,
        "time": time,
        "mediantime": mediantime,
        "verificationprogress": if is_ibd { time as f64 / now as f64 } else { 1.0 },
        "initialblockdownload": is_ibd,
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

    let unit = default_unit();
    let value = format_amount(coin.amount, unit);
    let confirmations = if chain_state.tip_height() >= coin.height {
        chain_state.tip_height() - coin.height + 1
    } else {
        0
    };

    let mut response = json!({
        "bestblock": chain_state.tip_hash().to_string(),
        "confirmations": confirmations,
        "value": value,
        "scriptPubKey": {
            "hex": hex::encode(coin.script_pubkey.as_bytes()),
        },
        "coinbase": coin.coinbase,
    });
    annotate_units(&mut response, unit);
    Ok(response)
}

/// `gettxoutsetinfo` — return UTXO set statistics.
pub fn get_tx_out_set_info(chain_state: &ChainState) -> Value {
    // Flush the UTXO cache so coin_count/coin_total_amount are accurate
    let _ = chain_state.flush_coin_cache();
    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();
    let coin_count = chain_state.coin_count();

    let total_sats = chain_state.coin_total_amount();
    let unit = default_unit();
    let total = format_amount(total_sats, unit);

    // Compute age distribution from height histogram
    // Buckets: <1h (6 blk), <1d (144), <1w (1008), <1mo (4320),
    //          <6mo (25920), <1y (51840), <3y (155520), 3y+
    let hist = chain_state.utxo_height_hist();
    let age_buckets = height_hist_to_age_buckets(&hist, tip_height);

    let mut response = json!({
        "height": tip_height,
        "bestblock": tip_hash.to_string(),
        "txouts": coin_count,
        "bogosize": coin_count * 50,
        "total_amount": total,
        "hash_serialized_3": "",
        "utxo_age_distribution": {
            "labels": ["<1h", "<1d", "<1w", "<1mo", "<6mo", "<1y", "<3y", "3y+"],
            "counts": age_buckets,
        },
    });
    annotate_units(&mut response, unit);
    response
}

/// Convert a height histogram (1000-block buckets) into 8 age-based buckets
/// relative to the current tip height.
fn height_hist_to_age_buckets(hist: &[u64], tip_height: u32) -> [u64; 8] {
    // Age thresholds in blocks (boundaries between buckets)
    let thresholds = [6u32, 144, 1008, 4320, 25920, 51840, 155520];
    let mut buckets = [0u64; 8];

    for (i, &count) in hist.iter().enumerate() {
        if count == 0 {
            continue;
        }
        // This histogram bucket covers heights [i*1000 .. (i+1)*1000)
        // Use the midpoint to estimate age
        let mid_height = i as u32 * 1000 + 500;
        let age = tip_height.saturating_sub(mid_height);

        let bucket = if age < thresholds[0] {
            0
        } else if age < thresholds[1] {
            1
        } else if age < thresholds[2] {
            2
        } else if age < thresholds[3] {
            3
        } else if age < thresholds[4] {
            4
        } else if age < thresholds[5] {
            5
        } else if age < thresholds[6] {
            6
        } else {
            7
        };
        buckets[bucket] += count;
    }
    buckets
}

/// `getdifficulty` — return current proof-of-work difficulty.
pub fn get_difficulty(chain_state: &ChainState) -> Value {
    let tip_hash = chain_state.tip_hash();
    if let Some(entry) = chain_state.get_block_index(&tip_hash) {
        json!(target_to_difficulty(entry.header.bits))
    } else {
        json!(0.0)
    }
}

/// `getblockstats` — return per-block statistics.
pub fn get_block_stats(
    chain_state: &ChainState,
    hash_or_height: &str,
) -> Result<Value, String> {
    // Parse as height or hash
    let hash = if let Ok(height) = hash_or_height.parse::<u32>() {
        chain_state
            .get_block_hash_by_height(height)
            .ok_or("Block height out of range")?
    } else {
        hash_or_height
            .parse()
            .map_err(|_| "Invalid block hash or height".to_string())?
    };

    let entry = chain_state
        .get_block_index(&hash)
        .ok_or("Block not found")?;
    let block = chain_state
        .get_block(&hash)
        .ok_or("Block data not available")?;

    let block_bytes = serialize(&block);
    let total_size = block_bytes.len();
    let total_weight = block.weight().to_wu();
    let num_txs = block.txdata.len();

    let mut total_fee: u64 = 0;
    let mut total_out: u64 = 0;
    let mut min_fee = u64::MAX;
    let mut max_fee = 0u64;
    let mut min_fee_rate = u64::MAX;
    let mut max_fee_rate = 0u64;
    let mut segwit_txs = 0u64;
    let mut utxo_increase: i64 = 0;

    for tx in &block.txdata {
        let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        total_out += out_sum;
        utxo_increase += tx.output.len() as i64;

        if tx.is_coinbase() {
            continue;
        }

        utxo_increase -= tx.input.len() as i64;

        // Compute fee from inputs
        let mut in_sum: u64 = 0;
        let mut inputs_found = true;
        for input in &tx.input {
            match chain_state.get_coin(&input.previous_output) {
                Some(coin) => in_sum += coin.amount,
                None => {
                    inputs_found = false;
                    break;
                }
            }
        }

        if inputs_found && in_sum >= out_sum {
            let fee = in_sum - out_sum;
            total_fee += fee;
            min_fee = min_fee.min(fee);
            max_fee = max_fee.max(fee);

            let w = tx.weight().to_wu();
            if w > 0 {
                let rate = fee * 1000 / w;
                min_fee_rate = min_fee_rate.min(rate);
                max_fee_rate = max_fee_rate.max(rate);
            }
        }

        if tx.input.iter().any(|i| !i.witness.is_empty()) {
            segwit_txs += 1;
        }
    }

    if min_fee == u64::MAX {
        min_fee = 0;
    }
    if min_fee_rate == u64::MAX {
        min_fee_rate = 0;
    }

    let avg_fee = if num_txs > 1 {
        total_fee / (num_txs as u64 - 1)
    } else {
        0
    };
    let avg_fee_rate = if total_weight > 0 && num_txs > 1 {
        total_fee * 1000 / total_weight
    } else {
        0
    };

    let subsidy = crate::chain::connect::block_subsidy(entry.height);

    Ok(json!({
        "avgfee": avg_fee,
        "avgfeerate": avg_fee_rate,
        "avgtxsize": if num_txs > 1 { total_size / num_txs } else { 0 },
        "blockhash": hash.to_string(),
        "height": entry.height,
        "ins": block.txdata.iter().skip(1).map(|tx| tx.input.len()).sum::<usize>(),
        "maxfee": max_fee,
        "maxfeerate": max_fee_rate,
        "maxtxsize": block.txdata.iter().map(|tx| serialize(tx).len()).max().unwrap_or(0),
        "medianfee": avg_fee, // simplified: use avg as median
        "mediantime": entry.header.time,
        "mediantxsize": if num_txs > 0 { total_size / num_txs } else { 0 },
        "minfee": min_fee,
        "minfeerate": min_fee_rate,
        "mintxsize": block.txdata.iter().map(|tx| serialize(tx).len()).min().unwrap_or(0),
        "outs": block.txdata.iter().map(|tx| tx.output.len()).sum::<usize>(),
        "subsidy": subsidy,
        "swtotal_size": 0,
        "swtotal_weight": 0,
        "swtxs": segwit_txs,
        "time": entry.header.time,
        "total_out": total_out,
        "total_size": total_size,
        "total_weight": total_weight,
        "totalfee": total_fee,
        "txs": num_txs,
        "utxo_increase": utxo_increase,
        "utxo_size_inc": utxo_increase * 50,
    }))
}

/// `getchaintips` — return chain tip info.
pub fn get_chain_tips(chain_state: &ChainState) -> Value {
    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();

    // Currently we only track the active chain tip
    json!([{
        "height": tip_height,
        "hash": tip_hash.to_string(),
        "branchlen": 0,
        "status": "active",
    }])
}

/// `getchaintxstats` — return tx rate statistics over a window.
pub fn get_chain_tx_stats(
    chain_state: &ChainState,
    nblocks: Option<u32>,
) -> Result<Value, String> {
    let tip_height = chain_state.tip_height();
    let window = nblocks.unwrap_or(30).min(tip_height);

    if window == 0 {
        return Err("Window must be > 0".to_string());
    }

    let tip_hash = chain_state.tip_hash();
    let tip_entry = chain_state
        .get_block_index(&tip_hash)
        .ok_or("Tip not found")?;

    let start_height = tip_height.saturating_sub(window);
    let start_hash = chain_state
        .get_block_hash_by_height(start_height)
        .ok_or("Start block not found")?;
    let start_entry = chain_state
        .get_block_index(&start_hash)
        .ok_or("Start block not found")?;

    // Count transactions in the window
    let mut tx_count: u64 = 0;
    for h in (start_height + 1)..=tip_height {
        if let Some(hash) = chain_state.get_block_hash_by_height(h)
            && let Some(entry) = chain_state.get_block_index(&hash) {
                tx_count += entry.num_tx as u64;
            }
    }

    let time_diff = tip_entry.header.time.saturating_sub(start_entry.header.time);
    let tx_rate = if time_diff > 0 {
        tx_count as f64 / time_diff as f64
    } else {
        0.0
    };

    Ok(json!({
        "time": tip_entry.header.time,
        "txcount": tx_count,
        "window_final_block_hash": tip_hash.to_string(),
        "window_final_block_height": tip_height,
        "window_block_count": window,
        "window_tx_count": tx_count,
        "window_interval": time_diff,
        "txrate": tx_rate,
    }))
}

/// `getmempoolancestors` — return in-mempool ancestors of a transaction.
pub fn get_mempool_ancestors(
    mempool: &Mempool,
    txid_str: &str,
    verbose: bool,
) -> Result<Value, String> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| "Invalid txid".to_string())?;

    let ancestors = mempool
        .get_ancestors(&txid)
        .ok_or("Transaction not in mempool")?;

    if verbose {
        let mut result = serde_json::Map::new();
        for anc_txid in &ancestors {
            if let Some(entry_json) = mempool.get_entry_verbose(anc_txid) {
                result.insert(anc_txid.to_string(), entry_json);
            }
        }
        Ok(Value::Object(result))
    } else {
        let txids: Vec<String> = ancestors.iter().map(|t| t.to_string()).collect();
        Ok(json!(txids))
    }
}

/// `getmempooldescendants` — return in-mempool descendants of a transaction.
pub fn get_mempool_descendants(
    mempool: &Mempool,
    txid_str: &str,
    verbose: bool,
) -> Result<Value, String> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| "Invalid txid".to_string())?;

    let descendants = mempool
        .get_descendants(&txid)
        .ok_or("Transaction not in mempool")?;

    if verbose {
        let mut result = serde_json::Map::new();
        for desc_txid in &descendants {
            if let Some(entry_json) = mempool.get_entry_verbose(desc_txid) {
                result.insert(desc_txid.to_string(), entry_json);
            }
        }
        Ok(Value::Object(result))
    } else {
        let txids: Vec<String> = descendants.iter().map(|t| t.to_string()).collect();
        Ok(json!(txids))
    }
}

/// `getmempoolentry` — return detailed info about a single mempool transaction.
pub fn get_mempool_entry(
    mempool: &Mempool,
    txid_str: &str,
) -> Result<Value, String> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| "Invalid txid".to_string())?;

    mempool
        .get_entry_verbose(&txid)
        .ok_or_else(|| "Transaction not in mempool".to_string())
}

/// `preciousblock` — mark a block as precious (prefer during reorg tie-breaking).
pub fn precious_block(_hash_str: &str) -> Result<Value, String> {
    // Stub: acknowledge but don't implement tie-breaking preference
    Ok(Value::Null)
}

/// `verifychain` — verify chain database integrity.
pub fn verify_chain(chain_state: &ChainState, check_level: u32, nblocks: u32) -> Value {
    let tip = chain_state.tip_height();
    let check_blocks = if nblocks == 0 { tip } else { nblocks.min(tip) };
    let start = tip.saturating_sub(check_blocks);

    let mut verified = 0u32;
    for h in start..=tip {
        if let Some(hash) = chain_state.get_block_hash_by_height(h)
            && chain_state.get_block_index(&hash).is_some() {
                verified += 1;
                if check_level >= 1 {
                    // Level 1+: verify block data exists
                    if chain_state.get_block(&hash).is_none() {
                        return json!(false);
                    }
                }
            }
    }

    let _ = verified; // suppress unused
    json!(true)
}

/// `savemempool` — serialize mempool to disk.
pub fn save_mempool() -> Value {
    // Stub: mempool persistence not yet implemented
    Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::{AssumeValid, ChainState};
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    fn make_cs() -> (ChainState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-rpc-bc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        4,
        )
        .unwrap();
        (cs, dir)
    }

    #[test]
    fn test_getblockchaininfo_genesis() {
        let (cs, dir) = make_cs();
        let info = get_blockchain_info(&cs);

        assert_eq!(info["chain"], "regtest");
        assert_eq!(info["blocks"], 0);

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(info["bestblockhash"], genesis.block_hash().to_string());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getbestblockhash() {
        let (cs, dir) = make_cs();
        let result = get_best_block_hash(&cs);

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(result, Value::String(genesis.block_hash().to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getblockcount() {
        let (cs, dir) = make_cs();
        let result = get_block_count(&cs);
        assert_eq!(result, json!(0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getblockhash() {
        let (cs, dir) = make_cs();
        let result = get_block_hash(&cs, 0).unwrap();

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(result, Value::String(genesis.block_hash().to_string()));

        // Height 1 should fail (out of range)
        let err = get_block_hash(&cs, 1);
        assert!(err.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getblock_hex() {
        let (cs, dir) = make_cs();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let hash_str = genesis.block_hash().to_string();

        let result = get_block(&cs, &hash_str, 0).unwrap();
        // Verbosity 0 returns a hex string
        let hex_str = result.as_str().unwrap();
        // Verify it's valid hex and can be decoded back to the genesis block
        let raw = hex::decode(hex_str).unwrap();
        let decoded: bitcoin::Block = bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(decoded.block_hash(), genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getblock_json() {
        let (cs, dir) = make_cs();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let hash_str = genesis.block_hash().to_string();

        let result = get_block(&cs, &hash_str, 1).unwrap();
        // Verbosity 1 returns JSON with height, hash, tx array
        assert_eq!(result["height"], 0);
        assert_eq!(result["hash"], hash_str);
        assert!(result["tx"].is_array());
        // Genesis block has exactly one transaction (the coinbase)
        assert_eq!(result["tx"].as_array().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_getblockheader() {
        let (cs, dir) = make_cs();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let hash_str = genesis.block_hash().to_string();

        let result = get_block_header(&cs, &hash_str, true).unwrap();
        assert_eq!(result["height"], 0);
        assert_eq!(result["hash"], hash_str);
        assert!(result["bits"].is_string());
        assert!(result["nonce"].is_number());
        assert!(result["merkleroot"].is_string());
        assert!(result["version"].is_number());
        assert!(result["confirmations"].as_u64().unwrap() >= 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
