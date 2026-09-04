use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::mining::template::create_template;
use crate::rpc::descriptor::parse_descriptor;
use crate::storage::blockindex::target_to_difficulty;
use serde_json::{json, Value};

/// Handle the `submitblock` RPC call.
pub fn submit_block(chain_state: &ChainState, mempool: &Mempool, hex_block: &str) -> Value {
    let block_bytes = match hex::decode(hex_block) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    // Use a cursor-based decode that tolerates trailing bytes, matching
    // Core's CBlock::Unserialize (which reads exactly one block and
    // ignores any trailing data). `consensus::deserialize` is strict
    // and rejects trailing bytes — a problem for the functional test
    // `interface_http.py`, which sends a 4 MB garbage payload that
    // still starts with a decodable (all-zeros) header + 0 txs.
    let block: bitcoin::Block = {
        use bitcoin::consensus::Decodable;
        let mut cursor = std::io::Cursor::new(&block_bytes);
        match bitcoin::Block::consensus_decode(&mut cursor) {
            Ok(b) => b,
            Err(_) => return Value::String("Block decode failed".to_string()),
        }
    };

    // Check PoW before looking up the parent, matching Core's
    // `CheckBlockHeader` → `AcceptBlock` flow. If the header fails PoW,
    // Core returns "high-hash" without ever searching the block index
    // for the parent.
    if let Err(e) = crate::validation::pow::check_proof_of_work(&block.header) {
        return Value::String(e.to_string());
    }

    match chain_state.accept_block(&block) {
        Ok(acceptance) => {
            // Only a block that joined the active chain confirms anything.
            // `accept_block` also returns `Ok` for a block it stored without
            // connecting — a side chain whose work does not beat the tip, a
            // block far ahead during IBD, a reorg declined below an AssumeUTXO
            // snapshot — and `remove_for_block` is not a no-op in that case: it
            // deletes every transaction in the block from the mempool as
            // *confirmed* and tells every events subscriber so. Submitting an
            // ordinary stale sibling would have purged live transactions this
            // node would otherwise relay and mine.
            if let Some(height) = chain_state.connected_height(&acceptance) {
                mempool.remove_for_block(&block, height);
            }
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
        .map_err(|e| match &e {
            crate::mining::miner::MineError::BadAddress(_) => (-5, format!("Invalid address: {e}")),
            _ => (-1, e.to_string()),
        })?;

    Ok(json!(hashes))
}

/// Handle the `generatetodescriptor` RPC call (regtest only).
pub fn generate_to_descriptor(
    chain_state: &ChainState,
    mempool: &Mempool,
    nblocks: u32,
    descriptor: &str,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generatetodescriptor is only available in regtest mode".to_string()));
    }

    let script = parse_descriptor(descriptor, chain_state.network)
        .map_err(|e| (-8, e))?;

    let hashes = crate::mining::miner::mine_blocks_to_script(chain_state, mempool, script, nblocks)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!(hashes))
}

/// Handle the `generateblock` RPC call (regtest only).
pub fn generate_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
    submit: bool,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generateblock is only available in regtest mode".to_string()));
    }

    if submit {
        let block = crate::mining::miner::mine_block(chain_state, mempool, address)
            .map_err(|e| (-1, e.to_string()))?;
        let block_hash = block.block_hash();
        let hex = hex::encode(bitcoin::consensus::serialize(&block));
        Ok(json!({ "hash": block_hash.to_string(), "hex": hex }))
    } else {
        let block = crate::mining::miner::mine_block_only(chain_state, mempool, address)
            .map_err(|e| (-1, e.to_string()))?;
        let block_hash = block.block_hash();
        let hex = hex::encode(bitcoin::consensus::serialize(&block));
        Ok(json!({ "hash": block_hash.to_string(), "hex": hex }))
    }
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

    // Core shapes the whole template around segwit activation at the
    // template height (its `fPreSegWit`): before activation it does not
    // advertise the segwit/taproot rules, reports the unscaled pre-segwit
    // sigop and size limits, omits `weightlimit` entirely, and omits the
    // witness commitment (#548). Stock regtest activates segwit at genesis;
    // `-testactivationheight=segwit@N` is what makes the pre-segwit shape
    // reachable.
    let pre_segwit =
        !crate::validation::block::segwit_active_at(chain_state.network, template.height);
    let rules: Vec<&str> = if pre_segwit {
        vec!["csv"]
    } else {
        // Core marks segwit with `!`: a client that does not understand the
        // rule must not use the template as-is (BIP 9 / BIP 22).
        vec!["csv", "!segwit", "taproot"]
    };
    let scale = crate::validation::block::WITNESS_SCALE_FACTOR as u64;

    let mut result = json!({
        "version": template.version,
        "rules": rules,
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
        "sigoplimit": if pre_segwit { 80000 / scale } else { 80000 },
        "sizelimit": if pre_segwit { 4_000_000 / scale } else { 4_000_000 },
        "curtime": template.cur_time,
        "bits": format!("{:08x}", template.bits.to_consensus()),
        "height": template.height,
        "longpollid": format!("{}{:x}", template.prev_hash, template.cur_time),
        "expires": 120,
    });
    if !pre_segwit {
        // `weightlimit` is a post-segwit field, and Core includes
        // `default_witness_commitment` on every post-segwit template —
        // witness transactions or not.
        result["weightlimit"] = Value::from(4_000_000);
        result["default_witness_commitment"] = Value::String(
            crate::mining::template::compute_witness_commitment_hex(&template.transactions),
        );
    }
    result
}

/// `getmininginfo` — return mining-related info.
pub fn get_mining_info(chain_state: &ChainState, mempool: &Mempool) -> Value {
    // One read -- see `ChainState::tip_snapshot`.
    let (tip_hash, tip_height) = chain_state.tip_snapshot();
    let difficulty = if let Some(entry) = chain_state.get_block_index(&tip_hash) {
        target_to_difficulty(entry.header.bits)
    } else {
        0.0
    };
    let hashps = get_network_hash_ps(chain_state, None, None);

    let chain = match chain_state.network {
        bitcoin::Network::Regtest => "regtest",
        bitcoin::Network::Testnet => "test",
        bitcoin::Network::Testnet4 => "testnet4",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Bitcoin => "main",
    };

    let pooledtx = mempool.info().size;

    let mut out = json!({
        "blocks": tip_height,
        "difficulty": difficulty,
        "networkhashps": hashps,
        "pooledtx": pooledtx,
        "chain": chain,
        "warnings": "",
    });

    // `currentblocktx` / `currentblockweight` describe the last template that
    // was actually assembled, and are absent until one has been. Core reads
    // them straight off `BlockAssembler::m_last_block_num_txs` /
    // `m_last_block_weight` and pushes each key only when set — it does not
    // assemble a template to answer `getmininginfo`, and neither should we:
    // this is a hot `Read` RPC that monitoring polls, and assembling walks
    // the whole mempool.
    if let Some((num_txs, weight)) = crate::mining::template::last_block_stats() {
        out["currentblocktx"] = json!(num_txs);
        out["currentblockweight"] = json!(weight);
    }

    out
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
    if header_bytes.len() < 80 {
        return Err("Header decode failed".to_string());
    }
    // Core's `submitheader` accepts the full block hex (or just the 80-byte
    // header). `bitcoin::consensus::deserialize` enforces an exact-size
    // match, so trim to the first 80 bytes.
    let header: bitcoin::block::Header =
        bitcoin::consensus::deserialize(&header_bytes[..80])
            .map_err(|_| "Header decode failed".to_string())?;
    chain_state
        .accept_header(&header)
        .map_err(|e| e.to_string())?;
    Ok(Value::Null)
}
