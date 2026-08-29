use bitcoin::Network;
use bitcoin::consensus::serialize;
use serde_json::{json, Value};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::rpc::amounts::{annotate_units, default_unit, format_amount};
use crate::storage::blockindex::{BlockIndexEntry, target_to_difficulty};

/// True when the active chain holds exactly `hash` at `height`.
///
/// A block can be valid, fully stored, and still not be on the active chain —
/// a stale block from a losing branch. Core distinguishes the two everywhere it
/// reports `confirmations`, and tooling reasoning about forks depends on it.
pub(crate) fn is_on_active_chain(chain_state: &ChainState, hash: &bitcoin::BlockHash, height: u32) -> bool {
    height <= chain_state.tip_height()
        && chain_state.get_block_hash_by_height(height) == Some(*hash)
}

/// Core's `confirmations`: depth for a block on the active chain, `-1` for a
/// valid block that is not on it.
///
/// Deriving this from height alone reports a stale block as buried — a block
/// on a losing branch 60,000 deep claimed 60,000 confirmations, which is worse
/// than useless to anything deciding whether a block is final.
fn block_confirmations(chain_state: &ChainState, hash: &bitcoin::BlockHash, height: u32) -> i64 {
    if is_on_active_chain(chain_state, hash, height) {
        i64::from(chain_state.tip_height() - height + 1)
    } else {
        -1
    }
}

/// Core's `mediantime`: the median timestamp of this block and its ten
/// ancestors.
///
/// Walked through parent pointers rather than the height index, so a block off
/// the active chain gets its OWN ancestry instead of the active chain's — and
/// so the answer does not depend on an index that describes a different branch.
fn block_median_time(chain_state: &ChainState, entry: &BlockIndexEntry) -> u32 {
    let mut times = Vec::with_capacity(11);
    times.push(entry.header.time);
    let mut height = entry.height;
    let mut cursor = entry.header.prev_blockhash;
    while times.len() < 11 && height > 0 {
        let Some(parent) = chain_state.get_block_index(&cursor) else {
            break;
        };
        times.push(parent.header.time);
        height = parent.height;
        cursor = parent.header.prev_blockhash;
    }
    times.sort_unstable();
    times[times.len() / 2]
}

/// `nextblockhash`, which Core reports only for blocks on the active chain.
///
/// Resolving it by height for an off-chain block hands back the *active*
/// chain's successor, which makes a stale block and the canonical block at the
/// same height indistinguishable through this RPC.
fn next_block_hash(
    chain_state: &ChainState,
    hash: &bitcoin::BlockHash,
    height: u32,
) -> Option<String> {
    if !is_on_active_chain(chain_state, hash, height) {
        return None;
    }
    chain_state
        .get_block_hash_by_height(height + 1)
        .map(|h| h.to_string())
}

/// Build the `getblockchaininfo` response from real chain state.
pub fn get_blockchain_info(chain_state: &ChainState) -> Value {
    let chain = match chain_state.network {
        Network::Regtest => "regtest",
        Network::Testnet => "test",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Bitcoin => "main",
    };

    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();

    let (difficulty, time, mediantime, chainwork) =
        if let Some(entry) = chain_state.get_block_index(&tip_hash) {
            let cw_hex = hex::encode(entry.chainwork);
            (
                target_to_difficulty(entry.header.bits),
                entry.header.time as u64,
                block_median_time(chain_state, &entry) as u64,
                cw_hex,
            )
        } else {
            (0.0, 0u64, 0u64, "0".to_string())
        };

    // IBD heuristic: if tip is more than 24 hours behind wall clock, we're
    // in IBD. Shares one definition with the per-block flush gate in
    // `ChainState` (see `tip_time_is_ibd` / issue #262).
    // Node clock, for the same reason as `tip_time_is_ibd`, which this is
    // reported alongside.
    let now = crate::time::now_secs();
    let is_ibd = ChainState::tip_time_is_ibd(time as u32);

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
        // Core ≥ v27 warnings is an array of strings. Preserves older
        // behavior: if no active warnings, emit the empty-string form
        // Core used historically; otherwise emit the Core-v27 array.
        "warnings": match chain_state.warnings().as_strings() {
            v if v.is_empty() => Value::String(String::new()),
            v => Value::Array(v.into_iter().map(Value::String).collect()),
        },
    })
}

/// `getchainstates` — Core 27+ RPC describing the active chainstate(s).
///
/// A node with no loaded AssumeUTXO snapshot runs a single, fully
/// validated chainstate, so `chainstates` is a one-element array and no
/// entry carries `snapshot_blockhash`. Once `loadtxoutset` lands a
/// snapshot, this grows a second entry for the background chainstate and
/// the snapshot entry gains `snapshot_blockhash` + `validated: false`
/// until the background catch-up completes the handoff.
pub fn get_chain_states(chain_state: &ChainState) -> Value {
    let tip_hash = chain_state.tip_hash();
    let tip_height = chain_state.tip_height();

    let (difficulty, time) = chain_state
        .get_block_index(&tip_hash)
        .map(|entry| (target_to_difficulty(entry.header.bits), entry.header.time as u64))
        .unwrap_or((0.0, 0));

    // Node clock, matching `ChainState::tip_time_is_ibd`: both sides of this
    // comparison have to be on the same clock or a mocked chain reports itself
    // as syncing forever.
    let now = crate::time::now_secs();
    let is_ibd = time + 86400 < now;
    let verificationprogress = if is_ibd && now > 0 {
        time as f64 / now as f64
    } else {
        1.0
    };

    let mut chainstates = Vec::new();

    match chain_state.background() {
        // AssumeUTXO snapshot loaded: this chainstate serves the tip but
        // is not yet fully validated; a background chainstate validates
        // genesis→snapshot in parallel.
        Some(bg) => {
            // `assumeutxo_rejected` (satd extension) is set when background
            // validation has proven this snapshot invalid — distinct from
            // the merely-not-yet-validated state.
            chainstates.push(json!({
                "blocks": tip_height,
                "bestblockhash": tip_hash.to_string(),
                "difficulty": difficulty,
                "verificationprogress": verificationprogress,
                "coins_db_cache_bytes": 0,
                "coins_tip_cache_bytes": 0,
                "snapshot_blockhash": bg.snapshot_hash().to_string(),
                "validated": false,
                "assumeutxo_rejected": bg.is_rejected(),
            }));

            let bg_height = bg.tip_height();
            let bg_difficulty = chain_state
                .get_block_index(&bg.tip_hash())
                .map(|e| target_to_difficulty(e.header.bits))
                .unwrap_or(0.0);
            let bg_progress = if bg.snapshot_height() > 0 {
                (bg_height as f64 / bg.snapshot_height() as f64).min(1.0)
            } else {
                1.0
            };
            chainstates.push(json!({
                "blocks": bg_height,
                "bestblockhash": bg.tip_hash().to_string(),
                "difficulty": bg_difficulty,
                "verificationprogress": bg_progress,
                "coins_db_cache_bytes": 0,
                "coins_tip_cache_bytes": 0,
                "validated": true,
            }));
        }
        // No snapshot: a single, fully validated chainstate.
        None => {
            chainstates.push(json!({
                "blocks": tip_height,
                "bestblockhash": tip_hash.to_string(),
                "difficulty": difficulty,
                "verificationprogress": verificationprogress,
                "coins_db_cache_bytes": 0,
                "coins_tip_cache_bytes": 0,
                "validated": true,
            }));
        }
    }

    json!({
        "headers": chain_state.headers_tip_height().max(tip_height),
        "chainstates": chainstates,
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
/// verbosity 2+: JSON with header + full per-tx detail (same shape as
///               `getrawtransaction verbose=true`, embedded under `tx`)
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

    let confirmations = block_confirmations(chain_state, &hash, entry.height);

    // Bitcoin Core's verbosity contract:
    //   1 → tx is an array of txid strings
    //   2+ → tx is an array of full tx-detail objects (Core caps at 3,
    //        which adds prevout decoding; satd treats anything ≥2 as
    //        the standard full-detail shape).
    let block_hash_str = hash.to_string();
    let tx_field: Value = if verbosity >= 2 {
        let txs: Vec<Value> = block
            .txdata
            .iter()
            .map(|tx| {
                crate::rpc::rawtx::decode_transaction_verbose(
                    tx,
                    Some(&block_hash_str),
                    Some(entry.height),
                    Some(confirmations),
                )
            })
            .collect();
        Value::Array(txs)
    } else {
        let txids: Vec<String> = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect();
        json!(txids)
    };

    let difficulty = target_to_difficulty(entry.header.bits);
    let chainwork_hex = hex::encode(entry.chainwork);
    let block_size = serialize(&block).len();

    let prev_hash = if entry.height > 0 {
        Some(entry.header.prev_blockhash.to_string())
    } else {
        None
    };

    let next_hash = next_block_hash(chain_state, &hash, entry.height);

    let mut result = json!({
        "hash": block_hash_str,
        "confirmations": confirmations,
        "height": entry.height,
        "version": entry.header.version.to_consensus(),
        "versionHex": format!("{:08x}", entry.header.version.to_consensus()),
        "merkleroot": entry.header.merkle_root.to_string(),
        "tx": tx_field,
        "time": entry.header.time,
        "mediantime": block_median_time(chain_state, &entry),
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

    let confirmations = block_confirmations(chain_state, &hash, entry.height);

    let prev_hash = if entry.height > 0 {
        Some(entry.header.prev_blockhash.to_string())
    } else {
        None
    };

    let next_hash = next_block_hash(chain_state, &hash, entry.height);

    let mut result = json!({
        "hash": hash.to_string(),
        "confirmations": confirmations,
        "height": entry.height,
        "version": entry.header.version.to_consensus(),
        "versionHex": format!("{:08x}", entry.header.version.to_consensus()),
        "merkleroot": entry.header.merkle_root.to_string(),
        "time": entry.header.time,
        "mediantime": block_median_time(chain_state, &entry),
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

    // Bitcoin Core returns JSON `null` for a missing or spent
    // outpoint — not an error. Clients (including `bitcoincore-rpc`)
    // use this as the UTXO-existence probe; returning an error
    // breaks the `Option<GetTxOutResult>` round-trip.
    let Some(coin) = chain_state.get_coin(&outpoint) else {
        return Ok(Value::Null);
    };

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
            "asm": format!("{}", coin.script_pubkey),
            "hex": hex::encode(coin.script_pubkey.as_bytes()),
        },
        "coinbase": coin.coinbase,
    });
    annotate_units(&mut response, unit);
    Ok(response)
}

/// `gettxoutsetinfo` — return UTXO set statistics.
pub fn get_tx_out_set_info(chain_state: &ChainState) -> Result<Value, (i32, String)> {
    // One consistent view: tip, coin count, total amount and the height
    // histogram are read under the chain's accept lock (after a cache
    // flush) so a block connecting mid-call cannot pair a stale tip with
    // fresh totals (#556).
    let info = chain_state
        .utxo_set_info()
        .map_err(|e| (-32603, format!("Unable to read UTXO set: {e}")))?;
    let unit = default_unit();
    let total = format_amount(info.total_amount_sat, unit);

    // Compute age distribution from height histogram
    // Buckets: <1h (6 blk), <1d (144), <1w (1008), <1mo (4320),
    //          <6mo (25920), <1y (51840), <3y (155520), 3y+
    let age_buckets = height_hist_to_age_buckets(&info.height_hist, info.height);

    let mut response = json!({
        "height": info.height,
        "bestblock": info.best_block.to_string(),
        "txouts": info.txouts,
        "bogosize": info.txouts * 50,
        "total_amount": total,
        "hash_serialized_3": "",
        "utxo_age_distribution": {
            "labels": ["<1h", "<1d", "<1w", "<1mo", "<6mo", "<1y", "<3y", "3y+"],
            "counts": age_buckets,
        },
    });
    annotate_units(&mut response, unit);
    Ok(response)
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
                let rate = crate::mempool::policy::fee_rate_sat_per_kvb(fee, w);
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
        crate::mempool::policy::fee_rate_sat_per_kvb(total_fee, total_weight)
    } else {
        0
    };

    let subsidy = crate::chain::connect::block_subsidy(chain_state.network, entry.height);

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
        "mediantime": block_median_time(chain_state, &entry),
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
///
/// `final_blockhash` is Bitcoin Core's optional second argument: the block
/// that *ends* the window (default = chain tip). `txcount` is the cumulative
/// chain-wide transaction total through that block. When a cumulative count is
/// not yet recorded (e.g. a pre-snapshot block on an AssumeUTXO node whose
/// background validation hasn't reached it) the dependent fields are omitted
/// exactly as Core does: `txcount` (final block uncounted), `window_tx_count`
/// (either endpoint uncounted), and `txrate` (no `window_tx_count`).
pub fn get_chain_tx_stats(
    chain_state: &ChainState,
    nblocks: Option<u32>,
    final_blockhash: Option<bitcoin::BlockHash>,
) -> Result<Value, String> {
    // Resolve the window's final block (default = tip).
    let (final_hash, final_entry) = match final_blockhash {
        Some(hash) => {
            let entry = chain_state
                .get_block_index(&hash)
                .ok_or("Block not found")?;
            // Active-chain membership must be exact: the `height_hash` index is
            // "best known at height" and can be clobbered by side-chain
            // store_block/header paths (see the chain-state test
            // `test_reorg_fork_point_immune_to_polluted_height_hash`), so it is
            // NOT an active-chain oracle. Confirm authoritatively that the block
            // is the tip's ancestor at its height (Core: CChain::Contains).
            if chain_state.active_chain_hash_at_height(entry.height) != Some(hash) {
                return Err("Block is not in main chain".to_string());
            }
            (hash, entry)
        }
        None => {
            let hash = chain_state.tip_hash();
            let entry = chain_state.get_block_index(&hash).ok_or("Tip not found")?;
            (hash, entry)
        }
    };
    let final_height = final_entry.height;

    let window = nblocks.unwrap_or(30).min(final_height);
    if window == 0 {
        return Err("Window must be > 0".to_string());
    }
    let start_height = final_height - window;

    // Collect everything the window needs by walking back from the final block
    // (verified active above, or the tip) via `prev_blockhash`: the start block
    // hash and the per-height timestamps for both median-time-past windows. All
    // ancestors of an active block are themselves active, so this is immune to
    // height-index pollution — unlike `get_block_hash_by_height` /
    // `get_median_time_past`, which read that index. We descend to the lowest
    // height either MTP window touches.
    let mtp_lowest = start_height.saturating_sub(10);
    let mut ts_by_height: std::collections::HashMap<u32, u32> =
        std::collections::HashMap::new();
    ts_by_height.insert(final_height, final_entry.header.time);
    let mut start_hash: Option<bitcoin::BlockHash> = None;
    let mut cur = final_entry.header.prev_blockhash;
    let mut h = final_height;
    while h > mtp_lowest {
        h -= 1;
        let entry = chain_state
            .get_block_index(&cur)
            .ok_or("Block index entry missing while walking the active chain")?;
        ts_by_height.insert(h, entry.header.time);
        if h == start_height {
            start_hash = Some(cur);
        }
        cur = entry.header.prev_blockhash;
    }
    let start_hash = start_hash.ok_or("Start block not found")?;

    // Core measures the window interval between the two endpoint blocks'
    // median-time-past values (BIP113 MTP, including the block itself), not raw
    // header timestamps. MTP of a block at height H is the median of timestamps
    // over heights [H-10, H] (clamped at genesis), matching the semantics of
    // `get_median_time_past(H + 1)`. MTP is monotonic non-decreasing, so the
    // final block's value is never below the start's.
    let mtp_of = |height: u32| -> u32 {
        let mut times: Vec<u32> = (height.saturating_sub(10)..=height)
            .filter_map(|hh| ts_by_height.get(&hh).copied())
            .collect();
        times.sort_unstable();
        times[times.len() / 2]
    };
    let time_diff = mtp_of(final_height).saturating_sub(mtp_of(start_height));

    // Cumulative tx counts at the window endpoints. Either may be absent on an
    // AssumeUTXO node whose background validation hasn't reached that block.
    // Core gates each field on availability (src/rpc/blockchain.cpp,
    // getchaintxstats):
    //   * `txcount`         — omitted unless the final block's cumulative is known.
    //   * `window_tx_count` — the difference of the two cumulatives; omitted
    //                         unless BOTH endpoints are known.
    //   * `txrate`          — omitted unless `window_tx_count` is present and the
    //                         interval (MTP difference, computed above) is positive.
    // `window_interval` is always emitted here (window > 0).
    let final_cum = chain_state.cumulative_tx_count(&final_hash);
    let start_cum = chain_state.cumulative_tx_count(&start_hash);

    let mut obj = serde_json::Map::new();
    obj.insert("time".to_string(), json!(final_entry.header.time));
    if let Some(txcount) = final_cum {
        obj.insert("txcount".to_string(), json!(txcount));
    }
    obj.insert(
        "window_final_block_hash".to_string(),
        json!(final_hash.to_string()),
    );
    obj.insert(
        "window_final_block_height".to_string(),
        json!(final_height),
    );
    obj.insert("window_block_count".to_string(), json!(window));
    obj.insert("window_interval".to_string(), json!(time_diff));
    if let (Some(fc), Some(sc)) = (final_cum, start_cum) {
        let window_tx_count = fc.saturating_sub(sc);
        obj.insert("window_tx_count".to_string(), json!(window_tx_count));
        if time_diff > 0 {
            obj.insert(
                "txrate".to_string(),
                json!(window_tx_count as f64 / time_diff as f64),
            );
        }
    }
    Ok(Value::Object(obj))
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

/// `getmempoolentry` bulk variant — return a `{ "<txid>": entry_or_null }`
/// map for each requested txid. Missing entries surface as JSON `null`
/// instead of erroring so callers can batch-query and check per-tx.
/// Invalid txid strings produce a `null` entry keyed by the raw input.
pub fn get_mempool_entries_bulk(mempool: &Mempool, txid_strs: &[String]) -> Value {
    let mut out = serde_json::Map::with_capacity(txid_strs.len());
    for s in txid_strs {
        let entry = match s.parse::<bitcoin::Txid>() {
            Ok(txid) => mempool.get_entry_verbose(&txid).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        out.insert(s.clone(), entry);
    }
    Value::Object(out)
}

/// `preciousblock` — mark a block as precious (prefer during reorg tie-breaking).
pub fn precious_block(_hash_str: &str) -> Result<Value, String> {
    // Stub: acknowledge but don't implement tie-breaking preference
    Ok(Value::Null)
}

/// Map a chain-level invalidate/reconsider error to an `(rpc_code, message)`
/// pair, mirroring Bitcoin Core's error surface.
fn map_invalidate_err(e: crate::chain::state::ChainError) -> (i32, String) {
    use crate::chain::state::ChainError;
    match e {
        // RPC_INVALID_ADDRESS_OR_KEY
        ChainError::BlockNotFound => (-5, "Block not found".to_string()),
        // RPC_INVALID_PARAMETER
        ChainError::InvalidArgument(m) => (-8, m),
        // RPC_DATABASE_ERROR / misc
        other => (-1, other.to_string()),
    }
}

/// `invalidateblock` — mark a block invalid and re-activate the best valid
/// chain. Returns `null` on success (Core parity).
pub fn invalidate_block(
    chain_state: &ChainState,
    hash_str: &str,
) -> Result<Value, (i32, String)> {
    let hash: bitcoin::BlockHash = hash_str
        .parse()
        .map_err(|_| (-8, "blockhash must be hexadecimal string".to_string()))?;
    chain_state.invalidate_block(hash).map_err(map_invalidate_err)?;
    Ok(Value::Null)
}

/// `reconsiderblock` — clear a block's invalid mark (and its descendants') and
/// re-activate the best valid chain. Returns `null` on success (Core parity).
pub fn reconsider_block(
    chain_state: &ChainState,
    hash_str: &str,
) -> Result<Value, (i32, String)> {
    let hash: bitcoin::BlockHash = hash_str
        .parse()
        .map_err(|_| (-8, "blockhash must be hexadecimal string".to_string()))?;
    chain_state.reconsider_block(hash).map_err(map_invalidate_err)?;
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

/// `dumptxoutset <path>` — emit a Bitcoin Core-compatible UTXO snapshot
/// at the current tip. The file format is byte-compatible with
/// `bitcoin-cli dumptxoutset` and can be loaded into either Core or
/// satd via `loadtxoutset`.
///
/// Returns a JSON object matching Core's shape:
///   `{coins_written, base_hash, base_height, path, txoutset_hash}`.
///
/// `txoutset_hash` is Core's `hash_serialized_3` UTXO-set hash, NOT the
/// SHA-256 of the file. It is the double SHA-256 (`HashWriter::GetHash`)
/// over each coin's `TxOutSer` contribution in Core iteration order,
/// shown byte-reversed (uint256 display form). Operators compare it
/// against the height's `hash_serialized` in Core's
/// `m_assumeutxo_data` / `chain::assumeutxo`; `sha256sum` of the file
/// is unrelated and will not match.
pub fn dump_txout_set(chain_state: &ChainState, path: &str) -> Result<Value, (i32, String)> {
    use crate::chain::state::DumpError;
    use std::path::PathBuf;

    let path_buf = PathBuf::from(path);
    match chain_state.dump_utxo_snapshot(&path_buf) {
        Ok(summary) => Ok(json!({
            "coins_written": summary.coins_written,
            "base_hash": summary.base_hash.to_string(),
            "base_height": summary.base_height,
            "path": summary.path.to_string_lossy(),
            "txoutset_hash": hex::encode(summary.hash_serialized_3),
        })),
        Err(DumpError::RefuseOverwrite(p)) => Err((
            -8,
            format!(
                "refusing to overwrite existing file: {}",
                p.to_string_lossy()
            ),
        )),
        Err(DumpError::Io(e)) => Err((-1, format!("io error writing snapshot: {e}"))),
        Err(DumpError::Store(e)) => Err((-1, format!("storage error during snapshot: {e}"))),
        Err(DumpError::CountMismatch { expected, actual }) => Err((
            -1,
            format!(
                "snapshot wrote {actual} coins but UTXO count was {expected} \
                 (concurrent modification or storage corruption)"
            ),
        )),
    }
}

/// `loadtxoutset` — load a Bitcoin Core-format UTXO snapshot to bootstrap
/// from the snapshot's height, validating the chain behind it in the
/// background (AssumeUTXO).
///
/// `datadir` is the network datadir (the parent of `chainstate/`), used
/// to site the background chainstate at `chainstate_background/`.
/// `prune_target` is the configured `-prune` value; loadtxoutset refuses
/// when pruning is enabled (a follow-up milestone).
///
/// The snapshot's base block hash must match a hardcoded AssumeUTXO anchor
/// for this network, and the recomputed UTXO-set hash must match that
/// anchor — otherwise the load is rejected (and rolled back).
pub fn load_txout_set(
    chain_state: &ChainState,
    datadir: &std::path::Path,
    prune_target: u64,
    dbcache_mb: u64,
    path: &str,
) -> Result<Value, (i32, String)> {
    use crate::chain::assumeutxo;
    use crate::storage::compressed_coin::SnapshotMetadata;

    if prune_target > 0 {
        return Err((
            -1,
            "loadtxoutset is not supported with pruning enabled (-prune > 0)".to_string(),
        ));
    }

    // Peek the header to discover the base block, then look up the anchor.
    let mut header_reader = std::fs::File::open(path)
        .map_err(|e| (-1, format!("cannot open snapshot file {path}: {e}")))?;
    let meta = SnapshotMetadata::deserialize(&mut header_reader)
        .map_err(|e| (-22, format!("invalid snapshot header: {e}")))?;
    drop(header_reader);

    let anchor = assumeutxo::lookup_by_blockhash(chain_state.network, &meta.base_blockhash)
        .ok_or((
            -22,
            format!(
                "unknown snapshot: base block {} is not a recognized AssumeUTXO anchor for this \
                 network",
                meta.base_blockhash
            ),
        ))?;

    let bg_dir = datadir.join("chainstate_background");
    let mut reader = std::fs::File::open(path)
        .map_err(|e| (-1, format!("cannot open snapshot file {path}: {e}")))?;

    // max_open_files for the background coins DB: -1 (RocksDB default);
    // dbcache is operator-configured (passed in).
    match chain_state.load_utxo_snapshot(&mut reader, anchor, bg_dir, dbcache_mb, -1) {
        Ok(summary) => Ok(json!({
            "coins_loaded": summary.coins_loaded,
            "base_height": summary.base_height,
            "base_hash": summary.base_hash.to_string(),
            "tip_height": summary.tip_height,
        })),
        Err(e) => Err((-32, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    /// A partial `invalidateblock` keeps Core's error *code* and changes only
    /// the message. Operators and client libraries branch on the code, so a
    /// clearer explanation must not arrive as a different error.
    #[test]
    fn a_partial_invalidateblock_keeps_the_generic_error_code() {
        use crate::chain::state::ChainError;
        let (code, msg) = map_invalidate_err(ChainError::ReactivationFailed(
            "bad-txns-inputs-missingorspent".to_string(),
        ));
        assert_eq!(code, -1);
        assert!(msg.contains("bad-txns-inputs-missingorspent"), "{msg}");
        assert!(msg.contains("block index updated"), "{msg}");

        // The two codes Core distinguishes are untouched.
        assert_eq!(map_invalidate_err(ChainError::BlockNotFound).0, -5);
        assert_eq!(
            map_invalidate_err(ChainError::InvalidArgument("x".into())).0,
            -8
        );
    }

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
        Default::default(),
        Default::default(),
            Default::default(),)
        .unwrap();
        (cs, dir)
    }

    /// The reporter's scenario: a block on the active chain and a stale
    /// sibling at the SAME height. Before this fix both reported positive
    /// `confirmations` and the SAME `nextblockhash`, which made them
    /// indistinguishable through satd's own RPC and forced a fork
    /// investigation to cross-check against Bitcoin Core to tell them apart.
    #[test]
    fn a_stale_sibling_is_distinguishable_from_the_canonical_block() {
        use crate::storage::StoreBatch;
        use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};

        let (cs, dir) = make_cs();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        let mk = |prev, nonce: u32, height: u32| {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: prev,
                merkle_root: genesis.header.merkle_root,
                time: 1_600_000_000 + nonce,
                bits: genesis.header.bits,
                nonce,
            };
            (
                header.block_hash(),
                BlockIndexEntry {
                    header,
                    height,
                    status: BlockStatus::Valid,
                    num_tx: 1,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                },
            )
        };

        // A stale sibling of the active-chain tip: same height, fully valid,
        // simply not the block the active chain holds there.
        let (stale_hash, stale_entry) = mk(genesis.header.prev_blockhash, 7, 0);
        // A child on the active chain, so `nextblockhash` has something to find.
        let (child_hash, child_entry) = mk(genesis_hash, 8, 1);
        assert_ne!(stale_hash, genesis_hash);

        let batch = StoreBatch {
            block_index_puts: vec![(stale_hash, stale_entry), (child_hash, child_entry)],
            // The active chain holds genesis at 0 and the child at 1. The
            // stale sibling appears nowhere in it.
            height_hash_puts: vec![(1, child_hash)],
            ..Default::default()
        };
        cs.store_for_test().write_batch(batch).unwrap();

        assert_eq!(
            block_confirmations(&cs, &genesis_hash, 0),
            1,
            "the active-chain block is one deep"
        );
        assert_eq!(
            block_confirmations(&cs, &stale_hash, 0),
            -1,
            "Core reports -1 for a valid block that is not on the active chain"
        );
        assert_eq!(
            next_block_hash(&cs, &genesis_hash, 0),
            Some(child_hash.to_string()),
            "an active-chain block reports its successor"
        );
        assert_eq!(
            next_block_hash(&cs, &stale_hash, 0),
            None,
            "a stale block has no successor ON THE ACTIVE CHAIN; handing back \
             the canonical chain's next block is what made the two \
             indistinguishable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A block buried far below the tip on a losing branch must not claim the
    /// depth its height would imply.
    #[test]
    fn a_deeply_buried_stale_block_does_not_claim_confirmations() {
        let (cs, dir) = make_cs();
        let unknown_at_height_0 = bitcoin::BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x5A; 32]),
        );
        // Height 0 is at/below the tip, so a height-only calculation would
        // return a positive depth for a hash the active chain does not hold.
        assert_eq!(block_confirmations(&cs, &unknown_at_height_0, 0), -1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mediantime` is the median of the block and its ten ancestors, not the
    /// block's own timestamp.
    #[test]
    fn median_time_is_a_median_not_the_block_timestamp() {
        use crate::storage::StoreBatch;
        use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};

        let (cs, dir) = make_cs();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut prev = genesis.block_hash();
        let mut puts = Vec::new();
        let mut last = None;
        // Deliberately non-monotonic timestamps so the median differs from
        // both the newest block's time and a naive midpoint.
        let times = [500u32, 100, 900, 200, 800, 300, 700, 400, 600, 1000, 50];
        for (i, t) in times.iter().enumerate() {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: prev,
                merkle_root: genesis.header.merkle_root,
                time: *t,
                bits: genesis.header.bits,
                nonce: i as u32,
            };
            let h = header.block_hash();
            puts.push((
                h,
                BlockIndexEntry {
                    header,
                    height: (i + 1) as u32,
                    status: BlockStatus::Valid,
                    num_tx: 1,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                },
            ));
            prev = h;
            last = Some((h, header));
        }
        let (last_hash, last_header) = last.unwrap();
        let batch = StoreBatch {
            block_index_puts: puts.clone(),
            ..Default::default()
        };
        cs.store_for_test().write_batch(batch).unwrap();

        let entry = cs.get_block_index(&last_hash).unwrap();
        let mtp = block_median_time(&cs, &entry);
        assert_ne!(
            mtp, last_header.time,
            "reporting the block's own timestamp is the bug being fixed"
        );
        // The eleven newest timestamps are the whole `times` array; its median
        // is 500.
        assert_eq!(mtp, 500);

        let _ = std::fs::remove_dir_all(&dir);
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
    fn test_getchainstates_single_validated_chainstate() {
        let (cs, dir) = make_cs();
        let out = get_chain_states(&cs);

        let states = out["chainstates"].as_array().expect("chainstates array");
        // No snapshot loaded → exactly one, fully validated, chainstate.
        assert_eq!(states.len(), 1);
        let only = &states[0];
        assert_eq!(only["blocks"], 0);
        assert_eq!(only["validated"], true);
        assert!(
            only.get("snapshot_blockhash").is_none(),
            "non-snapshot chainstate must not carry snapshot_blockhash",
        );

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(only["bestblockhash"], genesis.block_hash().to_string());
        assert_eq!(out["headers"], 0);

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
