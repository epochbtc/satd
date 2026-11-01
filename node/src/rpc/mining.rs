use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::mining::template::create_template;
use crate::storage::blockindex::{sub_u256, target_to_difficulty, u256_to_f64};
use crate::rpc::util::univalue_double;
use crate::storage::blockindex::BlockStatus;
use crate::validation::pow::RETARGET_INTERVAL;
use serde_json::{json, Value};

/// Core's `RPC_DESERIALIZATION_ERROR`.
const RPC_DESERIALIZATION_ERROR: i32 = -22;
/// Core's `RPC_VERIFY_ERROR`.
const RPC_VERIFY_ERROR: i32 = -25;

/// Handle the `submitblock` RPC call, as Core's `submitblock`
/// (src/rpc/mining.cpp) answers it.
///
/// Hex that does not decode into a block is an RPC error, -22 "Block decode
/// failed". Otherwise the answer is BIP 22's: `null` when the block joined the
/// active chain, a reject reason, `"duplicate"`, `"duplicate-invalid"` or
/// `"inconclusive"`. A failure of this node rather than a verdict on the block
/// is -25 (see [`rejection_answer`]).
pub fn submit_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    hex_block: &str,
) -> Result<Value, (i32, String)> {
    let decode_failed = || (RPC_DESERIALIZATION_ERROR, "Block decode failed".to_string());
    let block_bytes = hex::decode(hex_block).map_err(|_| decode_failed())?;

    // Use a cursor-based decode that tolerates trailing bytes, matching
    // Core's CBlock::Unserialize (which reads exactly one block and
    // ignores any trailing data). `consensus::deserialize` is strict
    // and rejects trailing bytes — a problem for the functional test
    // `interface_http.py`, which sends a 4 MB garbage payload that
    // still starts with a decodable (all-zeros) header + 0 txs.
    let mut block: bitcoin::Block = {
        use bitcoin::consensus::Decodable;
        let mut cursor = std::io::Cursor::new(&block_bytes);
        bitcoin::Block::consensus_decode(&mut cursor).map_err(|_| decode_failed())?
    };

    // Core runs `UpdateUncommittedBlockStructures` whenever the parent is in
    // the block index, before the block is processed.
    if let Some(parent) = chain_state.get_block_index(&block.header.prev_blockhash) {
        fill_witness_reserved_value(&mut block, chain_state.network, parent.height + 1);
    }

    // Check PoW before looking up the parent, matching Core's
    // `CheckBlockHeader` → `AcceptBlock` flow. If the header fails PoW,
    // Core returns "high-hash" without ever searching the block index
    // for the parent.
    if let Err(e) = crate::validation::pow::check_proof_of_work(&block.header) {
        return Ok(Value::String(e.to_string()));
    }

    let block_hash = block.block_hash();
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
            // Core returns `null` when the block joined the active chain, and
            // `"inconclusive"` when it was valid and stored but did not
            // connect (e.g. side chain, future block). Tests rely on the
            // distinction.
            if acceptance.connected() {
                Ok(Value::Null)
            } else {
                Ok(Value::String("inconclusive".to_string()))
            }
        }
        Err(e) => rejection_answer(chain_state, &block_hash, e),
    }
}

/// Core's `UpdateUncommittedBlockStructures` (src/validation.cpp): when the
/// coinbase has a BIP 141 commitment output, segwit is active at the block's
/// height, and no coinbase input carries witness data, the coinbase input gets
/// the 32-byte zero witness reserved value. Pool software working from
/// `getblocktemplate` often submits the coinbase without it, and the block
/// then fails `bad-witness-nonce-size`.
///
/// Nothing in the block hash covers the coinbase witness, so this changes
/// neither the header nor the merkle root.
fn fill_witness_reserved_value(block: &mut bitcoin::Block, network: bitcoin::Network, height: u32) {
    use crate::validation::block::{has_witness_commitment_output, segwit_active_at};
    if !has_witness_commitment_output(block) || !segwit_active_at(network, height) {
        return;
    }
    let Some(coinbase) = block.txdata.first_mut() else {
        return;
    };
    if coinbase.input.iter().any(|input| !input.witness.is_empty()) {
        return;
    }
    // Core writes `vin[0]` unconditionally; a coinbase with no input fails
    // `CheckBlock` regardless.
    if let Some(input) = coinbase.input.first_mut() {
        input.witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
    }
}

/// `submitblock`'s answer for a block `accept_block` refused, as Core's
/// `submitblock` and `BIP22ValidationResult` give it.
///
/// - A block already in the index: `"duplicate-invalid"` when its entry is
///   marked invalid (Core's `AcceptBlockHeader` on `BLOCK_FAILED_VALID`), and
///   `"duplicate"` otherwise. The entry's own status decides, not the path in
///   `accept_block` that noticed the duplicate, so the answer does not depend
///   on when that path marks a block.
/// - A failure of this node (storage, block files, a snapshot load, an
///   interrupted connect): Core's `state.IsError()`, thrown as -25 with the
///   error text.
/// - Every other error is a verdict on the block, and its text is the reject
///   reason.
pub(crate) fn rejection_answer(
    chain_state: &ChainState,
    hash: &bitcoin::BlockHash,
    e: crate::chain::state::ChainError,
) -> Result<Value, (i32, String)> {
    use crate::chain::state::ChainError as E;
    match e {
        E::Duplicate => {
            let invalid = chain_state
                .get_block_index(hash)
                .is_some_and(|entry| entry.status == BlockStatus::Invalid);
            let answer = if invalid { "duplicate-invalid" } else { "duplicate" };
            Ok(Value::String(answer.to_string()))
        }
        E::DecodeFailed => Err((RPC_DESERIALIZATION_ERROR, e.to_string())),
        e if is_verdict(&e) => Ok(Value::String(e.to_string())),
        e => Err((RPC_VERIFY_ERROR, e.to_string())),
    }
}

/// Whether `e` judges the block (a reject reason) rather than reporting a
/// fault of this node. Anything not listed here is a node failure.
fn is_verdict(e: &crate::chain::state::ChainError) -> bool {
    use crate::chain::state::ChainError as E;
    match e {
        E::PrevBlockNotFound
        | E::BadPrevBlock
        | E::CheckpointMismatch(_)
        | E::ForkBeforeCheckpoint(_)
        | E::Validation(_) => true,
        // A mutation-class failure is a verdict on these bytes, not one
        // `accept_block` may record against the hash: still a reject reason.
        E::Connect(c) => c.is_verdict_on_block() || c.is_mutation_class(),
        _ => false,
    }
}

/// Handle the `generatetoaddress` RPC call.
///
/// Available on every chain, as in Core: the miner grinds real proof of work
/// against the chain's target, so off regtest it spends its nonce budget and
/// almost always returns no blocks. Core's functional tests mine on signet
/// with an `OP_TRUE` challenge this way.
pub fn generate_to_address(
    chain_state: &ChainState,
    mempool: &Mempool,
    nblocks: u32,
    address: &str,
    max_tries: u64,
    stop: &dyn Fn() -> bool,
) -> Result<Value, (i32, String)> {
    let hashes = crate::mining::miner::mine_blocks_until(chain_state, mempool, address, nblocks, max_tries, stop)
        .map_err(|e| match &e {
            crate::mining::miner::MineError::BadAddress(_) => (-5, format!("Invalid address: {e}")),
            _ => (-1, e.to_string()),
        })?;

    Ok(json!(hashes))
}

/// Handle the `generatetodescriptor` RPC call. Every chain, as `generatetoaddress`.
pub fn generate_to_descriptor(
    chain_state: &ChainState,
    mempool: &Mempool,
    nblocks: u32,
    descriptor: &str,
    max_tries: u64,
    stop: &dyn Fn() -> bool,
) -> Result<Value, (i32, String)> {
    // `descriptor_to_coinbase_script` is the full key-based parser
    // `generateblock` already uses, and it answers `-5` as Core's
    // `RPC_INVALID_ADDRESS_OR_KEY` does. `parse_descriptor` is
    // `scantxoutset`'s: it handles `raw()` and `addr()` only, and its refusal
    // names `scantxoutset` — so `generatetodescriptor` refused every
    // key-based descriptor Core accepts, under the wrong code, in a message
    // about a different RPC.
    let script = crate::rpc::descriptor::descriptor_to_coinbase_script(
        descriptor,
        chain_state.network,
    )?;

    let hashes =
        crate::mining::miner::mine_blocks_to_script_until(chain_state, mempool, script, nblocks, max_tries, stop)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!(hashes))
}

/// Handle the `generateblock` RPC call. Every chain, as `generatetoaddress`.
pub fn generate_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
    submit: bool,
) -> Result<Value, (i32, String)> {
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

/// Core's gate before `getblocktemplate` builds a template
/// (`rpc/mining.cpp`): on mainnet a node with no peers is
/// `RPC_CLIENT_NOT_CONNECTED` (-9), and one in initial block download is
/// `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10), so a pool never mines on a tip it
/// cannot know is current. Test chains skip both (`IsTestChain`), which keeps
/// a lone regtest or signet miner working.
pub fn template_gate(
    network: bitcoin::Network,
    connections: usize,
    initial_block_download: bool,
) -> Result<(), (i32, String)> {
    if network != bitcoin::Network::Bitcoin {
        return Ok(());
    }
    if connections == 0 {
        return Err((-9, "satd is not connected!".to_string()));
    }
    if initial_block_download {
        return Err((-10, "satd is in initial sync and waiting for blocks...".to_string()));
    }
    Ok(())
}

/// Handle the `getblocktemplate` RPC call.
///
/// The template is checked before it is returned, as Core's `CreateNewBlock`
/// does, and a template that fails is an error with Core's message rather
/// than work for a miner (`mining::validity`). The script-level check follows
/// in the background, once per tip.
pub fn get_block_template(chain_state: &ChainState, mempool: &Mempool) -> Result<Value, (i32, String)> {
    use crate::mining::validity::{Check, CheckOrigin};
    let template = create_template(chain_state, mempool);
    let outcome = crate::mining::validity::check_template(chain_state, &template, Check::Structural);
    chain_state.template_validity().record(Check::Structural, &outcome, CheckOrigin::GetBlockTemplate);
    if let crate::chain::state::TemplateVerdict::Invalid(reason) = &outcome.verdict {
        return Err((-1, format!("TestBlockValidity failed: {reason}")));
    }
    chain_state.template_validity().queue_full_check_for_gbt(&template);
    let pre_segwit =
        !crate::validation::block::segwit_active_at(chain_state.network, template.height);
    let scale = crate::validation::block::WITNESS_SCALE_FACTOR as u64;

    // Core's `setTxIndex`: each transaction's place in the block, the
    // coinbase being 0, so a template transaction's index is its 1-based
    // position in `transactions`. `depends` lists, for each input that
    // spends an earlier template transaction, that transaction's index, in
    // input order and with repeats, as Core builds it.
    let mut tx_index: std::collections::HashMap<bitcoin::Txid, usize> =
        std::collections::HashMap::with_capacity(template.transactions.len());
    let txs: Vec<Value> = template
        .transactions
        .iter()
        .enumerate()
        .map(|(i, ttx)| {
            let raw = bitcoin::consensus::serialize(&ttx.tx);
            let txid = ttx.tx.compute_txid();
            let depends: Vec<usize> = ttx
                .tx
                .input
                .iter()
                .filter_map(|input| tx_index.get(&input.previous_output.txid).copied())
                .collect();
            tx_index.insert(txid, i + 1);
            json!({
                "data": hex::encode(&raw),
                "txid": txid.to_string(),
                "hash": ttx.tx.compute_wtxid().to_string(),
                "depends": depends,
                "fee": ttx.fee,
                // Core reports each transaction's sigop cost so a client that
                // builds its own block can keep to `sigoplimit`; pre-segwit,
                // both are unscaled (`src/rpc/mining.cpp`).
                "sigops": if pre_segwit { ttx.sigop_cost / scale } else { ttx.sigop_cost },
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
    let rules: Vec<&str> = if pre_segwit {
        vec!["csv"]
    } else {
        // Core marks segwit with `!`: a client that does not understand the
        // rule must not use the template as-is (BIP 9 / BIP 22).
        vec!["csv", "!segwit", "taproot"]
    };
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
        "mintime": template.min_time,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "capabilities": ["proposal"],
        "sigoplimit": if pre_segwit { 80000 / scale } else { 80000 },
        "sizelimit": if pre_segwit { 4_000_000 / scale } else { 4_000_000 },
        "curtime": template.cur_time,
        "bits": format!("{:08x}", template.bits.to_consensus()),
        "height": template.height,
        // Core's `<tip hash><transactions updated>`, what a long poll waits on.
        "longpollid": format!("{}{}", template.prev_hash, mempool.mempool_sequence()),
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
    Ok(result)
}

/// `getmininginfo.next`: the block after `tip` as Core's
/// `NextEmptyBlockIndex` builds it — timestamped `max(MTP + 1, now)` on the
/// node clock, with the `nBits` that timestamp requires.
fn next_block_info(chain_state: &ChainState, tip: &crate::storage::blockindex::BlockIndexEntry) -> Value {
    let now = u32::try_from(crate::time::now_secs()).unwrap_or(u32::MAX);
    let time = now.max(crate::rpc::blockchain::block_median_time(chain_state, tip) + 1);
    let bits = crate::validation::pow::next_bits(
        chain_state.network,
        tip,
        time,
        |hash| chain_state.get_block_index(hash),
    )
    .unwrap_or(tip.header.bits);
    json!({
        "height": tip.height + 1,
        "bits": crate::rpc::blockchain::bits_hex(bits),
        "difficulty": univalue_double(target_to_difficulty(bits)),
        "target": crate::rpc::blockchain::target_hex(bits),
    })
}

/// `getmininginfo` — return mining-related info.
pub fn get_mining_info(chain_state: &ChainState, mempool: &Mempool) -> Value {
    // One read -- see `ChainState::tip_snapshot`.
    let (tip_hash, tip_height) = chain_state.tip_snapshot();
    let tip_entry = chain_state.get_block_index(&tip_hash);
    let difficulty = tip_entry
        .as_ref()
        .map(|entry| target_to_difficulty(entry.header.bits))
        .unwrap_or(0.0);
    let hashps = get_network_hash_ps(chain_state, 120, -1).unwrap_or(0.0);

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
        // Doubles in Core's `%.16g` form (`UniValue::setFloat`).
        "difficulty": univalue_double(difficulty),
        "networkhashps": univalue_double(hashps),
        "pooledtx": pooledtx,
        // Core's `blockmintxfee`, BTC/kvB.
        "blockmintxfee": crate::rpc::amounts::format_feerate_sat_per_kvb(
            crate::mining::template::block_min_tx_fee(),
            crate::rpc::amounts::AmountUnit::Btc,
        ),
        "chain": chain,
        // The node's real warnings, the same ones `getblockchaininfo`
        // reports. This was `""` while the plumbing sat one call away —
        // `get_mining_info` already takes the `ChainState` that owns them, so
        // a miner watching `getmininginfo` for an unknown-softfork warning saw
        // nothing however loudly the node was warning elsewhere.
        "warnings": crate::rpc::deprecated::warnings_value(chain_state.warnings().as_strings()),
    });

    // `currentblocktx` / `currentblockweight` describe the last template that
    // was actually assembled, and are absent until one has been. Core reads
    // them straight off `BlockAssembler::m_last_block_num_txs` /
    // `m_last_block_weight` and pushes each key only when set — it does not
    // assemble a template to answer `getmininginfo`, and neither should we:
    // this is a hot `Read` RPC that monitoring polls, and assembling walks
    // the whole mempool.
    if let Some(entry) = &tip_entry {
        out["bits"] = json!(crate::rpc::blockchain::bits_hex(entry.header.bits));
        out["target"] = json!(crate::rpc::blockchain::target_hex(entry.header.bits));
        out["next"] = next_block_info(chain_state, entry);
    }
    if let Some(challenge) = chain_state.signet_challenge() {
        out["signet_challenge"] = json!(hex::encode(challenge));
    }

    if let Some((num_txs, weight)) = crate::mining::template::last_block_stats() {
        out["currentblocktx"] = json!(num_txs);
        out["currentblockweight"] = json!(weight);
    }

    out
}
/// `getnetworkhashps` -- estimated network hashes per second.
///
/// A faithful port of Core's `GetNetworkHashPS` (`src/rpc/mining.cpp`),
/// including its argument contract: `nblocks` is the window, or `-1` for
/// "since the last difficulty change"; `height` is the block to estimate at,
/// or `-1` for the tip. Both are signed because both use `-1` as a
/// meaningful value, and Core declares them `RPCArg::Type::NUM`.
///
/// The estimate is the *work* accumulated across the window divided by the
/// time it spanned. satd previously divided the work of a single block by the
/// whole window's time, understating the network hash rate by a factor of the
/// window size -- ~120x at the default `nblocks`. `getmininginfo`, the MCP
/// mining tool and the TUI all read this, so they were all wrong together.
///
/// Errors are `(code, message)` pairs carrying Core's exact strings.
pub fn get_network_hash_ps(
    chain_state: &ChainState,
    nblocks: i64,
    height: i64,
) -> Result<f64, (i32, String)> {
    if nblocks < -1 || nblocks == 0 {
        return Err((-8, "Invalid nblocks. Must be a positive number or -1.".to_string()));
    }
    let tip_height = chain_state.tip_height();
    if height < -1 || height > i64::from(tip_height) {
        return Err((-8, "Block does not exist at specified height".to_string()));
    }

    // Core indexes the active chain for an explicit height and takes the tip
    // otherwise; from there it walks parent pointers, which is what the rest
    // of this function does.
    let at_height = if height >= 0 { height as u32 } else { tip_height };
    let Some(hash) = chain_state.get_block_hash_by_height(at_height) else {
        return Ok(0.0);
    };
    let Some(pb) = chain_state.get_block_index(&hash) else {
        return Ok(0.0);
    };
    // Genesis has no window to measure.
    if pb.height == 0 {
        return Ok(0.0);
    }

    let mut lookup = if nblocks == -1 {
        i64::from(pb.height % difficulty_adjustment_interval(chain_state.network) + 1)
    } else {
        nblocks
    };
    // A window longer than the chain is the whole chain.
    lookup = lookup.min(i64::from(pb.height));

    let mut pb0 = pb.clone();
    let mut min_time = pb0.header.time;
    let mut max_time = min_time;
    for _ in 0..lookup {
        let prev = pb0.header.prev_blockhash;
        let Some(entry) = chain_state.get_block_index(&prev) else {
            return Ok(0.0);
        };
        pb0 = entry;
        min_time = min_time.min(pb0.header.time);
        max_time = max_time.max(pb0.header.time);
    }

    // Core guards the divide-by-zero this way rather than on the endpoints.
    if min_time == max_time {
        return Ok(0.0);
    }

    let work = u256_to_f64(&sub_u256(&pb.chainwork, &pb0.chainwork));
    Ok(work / f64::from(max_time - min_time))
}

/// Core's `DifficultyAdjustmentInterval()`: `nPowTargetTimespan /
/// nPowTargetSpacing`. Two weeks of ten-minute blocks (2016) everywhere but
/// regtest, whose timespan is one day (144, `chainparams.cpp`). Regtest never
/// retargets, but `getnetworkhashps -1` still measures its window in these
/// units.
fn difficulty_adjustment_interval(network: bitcoin::Network) -> u32 {
    match network {
        bitcoin::Network::Regtest => 144,
        _ => RETARGET_INTERVAL,
    }
}

/// Handle `getblocktemplate` in proposal mode (BIP 22/23).
///
/// Decodes the proposed block from `hex_data`, validates it against the
/// current chain state without persisting anything, and returns `null` for
/// a valid proposal or a reject-reason string.
pub fn get_block_template_proposal(
    chain_state: &ChainState,
    hex_data: &str,
) -> Result<Value, (i32, String)> {
    let block_bytes = hex::decode(hex_data)
        .map_err(|_| (-22, "Block decode failed".to_string()))?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)
        .map_err(|_| (-22, "Block decode failed".to_string()))?;

    // Core's `BIP22ValidationResult`: a valid proposal is JSON null, an
    // invalid one is its reject reason as a string, and an *error* (as opposed
    // to a verdict) is `RPC_VERIFY_ERROR` — -25, not -1.
    match chain_state.test_block_validity(&block) {
        Ok(None) => Ok(Value::Null),
        Ok(Some(reason)) if reason.is_empty() => Ok(Value::String("rejected".to_string())),
        Ok(Some(reason)) => Ok(Value::String(reason)),
        Err(e) => Err((-25, e.to_string())),
    }
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

#[cfg(test)]
#[path = "mining_gbtdeps_tests.rs"]
mod gbtdeps_tests;
