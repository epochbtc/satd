use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::Secp256k1;
use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::rpc::amounts::{annotate_units, default_unit, format_amount, format_feerate_sat_per_kvb};
use crate::storage::Store;
use serde_json::{json, Value};

/// Parse a JSON value as f64, handling both float and integer representations.
/// With `arbitrary_precision`, serde_json stores numbers as strings internally,
/// so `as_f64()` can fail on integer values like `1`. This helper falls back
/// through `as_i64()` / `as_u64()` and then attempts string parsing.
fn json_number_as_f64(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|i| i as f64))
        .or_else(|| v.as_u64().map(|u| u as f64))
        .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
}

/// `getmempoolinfo` — return mempool statistics.
pub fn get_mempool_info(mempool: &Mempool) -> Value {
    let info = mempool.info();
    let unit = default_unit();
    let min_fee = format_feerate_sat_per_kvb(info.min_fee_rate, unit);
    let incremental = format_feerate_sat_per_kvb(info.incremental_relay_fee, unit);

    let mut response = json!({
        "loaded": true,
        "size": info.size,
        "bytes": info.bytes,
        "usage": info.bytes,
        "maxmempool": info.max_size,
        "mempoolminfee": min_fee,
        "minrelaytxfee": min_fee,
        "incrementalrelayfee": incremental,
        "unbroadcastcount": info.unbroadcast,
        "fullrbf": info.full_rbf,
        "maxdatacarriersize": info.max_data_carrier_size,
        "permitbaremultisig": info.permit_bare_multisig,
    });
    annotate_units(&mut response, unit);
    response
}

/// `getrawmempool` — list mempool transaction ids.
pub fn get_raw_mempool(mempool: &Mempool, verbose: bool) -> Value {
    // Standard surface (design §6.1/§10): acting class only — quarantined txids
    // are simply absent, exactly as on a Core node whose relay policy refused
    // them. `entry_map` below is therefore acting-only, so the ancestor /
    // descendant rollups and counts never include a quarantined relative.
    let entries = mempool.get_acting_entries();

    if !verbose {
        let txids: Vec<String> = entries.iter().map(|(txid, _)| txid.to_string()).collect();
        return json!(txids);
    }

    let mut result = serde_json::Map::new();
    for (txid, _entry) in &entries {
        if let Some(verbose) = mempool.get_entry_verbose(txid) {
            result.insert(txid.to_string(), verbose);
        }
    }
    Value::Object(result)
}

/// `getrawtransaction` — get a transaction by txid.
pub fn get_raw_transaction(
    chain_state: &ChainState,
    mempool: &Mempool,
    txid_str: &str,
    verbose: bool,
    verbosity: u32,
    blockhash: Option<&str>,
) -> Result<Value, (i32, String)> {
    // Core: `ParseHashV(request.params[0], "parameter 1")`. The message here
    // was a fixed string claiming a length of 0 whatever the caller passed.
    let txid: bitcoin::Txid = crate::rpc::util::parse_hash_v(txid_str, "parameter 1")?;

    // Genesis-block coinbase is not reachable via getrawtransaction — Core
    // returns this error both when a blockhash is explicitly supplied and
    // when the txindex would otherwise resolve it.
    if is_genesis_coinbase(chain_state, &txid) {
        return Err((-5, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved; to get its block, use the getblock RPC".to_string()));
    }

    // Search mempool first (unless blockhash is specified). Bitcoin
    // Core reports unconfirmed-tx `confirmations` as 0 in the verbose
    // response; match that so clients that gate on the field don't
    // have to special-case satd.
    if blockhash.is_none()
        && let Some(entry) = mempool.get(&txid).filter(|e| e.scope.is_acting()) {
            return if verbose {
                Ok(decode_transaction_verbose_net(
                    &entry.tx,
                    None,
                    None,
                    Some(0),
                    verbosity,
                    None,
                    chain_state.network,
                ))
            } else {
                let raw = bitcoin::consensus::serialize(&entry.tx);
                Ok(Value::String(hex::encode(raw)))
            };
        }

    // Search in a specific block
    if let Some(hash_str) = blockhash {
        validate_blockhash_str(hash_str)?;
        let block_hash: bitcoin::BlockHash = hash_str
            .parse()
            .map_err(|_| (-8, format!("parameter 3 must be hexadecimal string (not '{hash_str}')")))?;

        // Verify the block is known.
        let entry = chain_state
            .get_block_index(&block_hash)
            .ok_or((-5, "Block hash not found".to_string()))?;

        let block = chain_state
            .get_block(&block_hash)
            .ok_or((-1, "Block not available (pruned data)".to_string()))?;

        for tx in &block.txdata {
            if tx.compute_txid() == txid {
                return if verbose {
                    let height = Some(entry.height);
                    let confirmations = height.map(|h| confirmations_for(chain_state, &block_hash, h));
                    let mut result = decode_transaction_verbose_net(
                        tx,
                        Some(hash_str),
                        height,
                        confirmations,
                        verbosity,
                        Some((chain_state, &block)),
                        chain_state.network,
                    );
                    // `in_active_chain` is only present when the caller
                    // explicitly provided a blockhash.
                    maybe_set_in_active_chain(&mut result, confirmations);
                    Ok(result)
                } else {
                    let raw = bitcoin::consensus::serialize(tx);
                    Ok(Value::String(hex::encode(raw)))
                };
            }
        }

        // The caller gave us a specific block and the tx is not in it.
        return Err((-5, "No such transaction found in the provided block. Use gettransaction for wallet transactions.".to_string()));
    }

    // Fallback to txindex if available
    if let Some(block_hash) = chain_state.get_tx_location(&txid)
        && let Some(block) = chain_state.get_block(&block_hash) {
            let entry = chain_state.get_block_index(&block_hash);
            for tx in &block.txdata {
                if tx.compute_txid() == txid {
                    return if verbose {
                        let height = entry.as_ref().map(|e| e.height);
                        let confirmations =
                            height.map(|h| confirmations_for(chain_state, &block_hash, h));
                        Ok(decode_transaction_verbose_net(
                            tx,
                            Some(&block_hash.to_string()),
                            height,
                            confirmations,
                            verbosity,
                            Some((chain_state, &block)),
                            chain_state.network,
                        ))
                    } else {
                        let raw = bitcoin::consensus::serialize(tx);
                        Ok(Value::String(hex::encode(raw)))
                    };
                }
            }
        }

    Err((-5, "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.".to_string()))
}

/// Validate a blockhash string for length and hex-ness, returning Core-compatible
/// error messages ("parameter 3 must be of length 64 (not N, for 'xxx')").
fn validate_blockhash_str(s: &str) -> Result<(), (i32, String)> {
    crate::rpc::util::parse_hash_v::<bitcoin::BlockHash>(s, "parameter 3").map(|_| ())
}

/// True when `txid` is the genesis block's coinbase.
///
/// The genesis block is a compile-time constant of the network, so this
/// answers from `bitcoin::constants` rather than reading and deserializing
/// the block from the flat files. `getrawtransaction` is a hot, `Read`-classified
/// RPC that monitoring polls; it must not do block I/O to answer a question
/// whose answer cannot change.
fn is_genesis_coinbase(chain_state: &ChainState, txid: &bitcoin::Txid) -> bool {
    *txid == genesis_coinbase_txid(chain_state.network)
}

/// The genesis coinbase txid for a network, computed once per process.
fn genesis_coinbase_txid(network: bitcoin::Network) -> bitcoin::Txid {
    use std::sync::OnceLock;
    fn cell(network: bitcoin::Network) -> &'static OnceLock<bitcoin::Txid> {
        static MAINNET: OnceLock<bitcoin::Txid> = OnceLock::new();
        static TESTNET: OnceLock<bitcoin::Txid> = OnceLock::new();
        static TESTNET4: OnceLock<bitcoin::Txid> = OnceLock::new();
        static SIGNET: OnceLock<bitcoin::Txid> = OnceLock::new();
        static REGTEST: OnceLock<bitcoin::Txid> = OnceLock::new();
        match network {
            bitcoin::Network::Bitcoin => &MAINNET,
            bitcoin::Network::Testnet4 => &TESTNET4,
            bitcoin::Network::Signet => &SIGNET,
            bitcoin::Network::Regtest => &REGTEST,
            // `Network` is non_exhaustive; Testnet3 and anything added later
            // share a cell, which is correct as long as one process serves one
            // network — which satd does.
            _ => &TESTNET,
        }
    }
    *cell(network).get_or_init(|| {
        bitcoin::constants::genesis_block(network).txdata[0].compute_txid()
    })
}

/// `decoderawtransaction` — decode a raw transaction hex to JSON.
///
/// `iswitness`: `None` = auto-detect (try witness first, fall back to
/// non-witness), `Some(true)` = force witness, `Some(false)` = force
/// non-witness. Matches Core's optional `iswitness` parameter.
pub fn decode_raw_transaction(
    hex_tx: &str,
    iswitness: Option<bool>,
    network: bitcoin::Network,
) -> Result<Value, (i32, String)> {
    let tx_bytes =
        hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let tx = decode_tx(&tx_bytes, iswitness != Some(true), iswitness != Some(false))
        .ok_or((-22i32, "TX decode failed".to_string()))?;
    Ok(decode_transaction_verbose_net(&tx, None, None, None, 1, None, network))
}

/// Read a transaction the way Core's `DecodeTx` (`core_io.cpp`) does.
///
/// The segwit marker `0x00 0x01` is ambiguous: read as extended serialization
/// it announces witnesses, read as legacy it is a zero-input one-output
/// transaction. Core decodes both ways where allowed, discards any reading
/// that does not consume the whole input, and picks between them with a
/// script-sanity check — preferring the extended reading when the check
/// cannot separate them.
///
/// satd had no legacy reader at all. `iswitness=false` called rust-bitcoin's
/// (extended) decoder and merely stopped requiring full consumption, so it
/// returned the *witness* reading of a segwit transaction — the opposite of
/// what the argument asks for — and silently accepted trailing bytes.
pub(crate) fn decode_tx(
    tx_bytes: &[u8],
    try_no_witness: bool,
    try_witness: bool,
) -> Option<bitcoin::Transaction> {
    let extended = if try_witness {
        // rust-bitcoin's `deserialize` already requires full consumption.
        bitcoin::consensus::deserialize::<bitcoin::Transaction>(tx_bytes).ok()
    } else {
        None
    };
    if let Some(tx) = &extended
        && check_tx_scripts_sanity(tx)
    {
        return extended;
    }

    let legacy = if try_no_witness {
        deserialize_legacy_tx(tx_bytes)
    } else {
        None
    };
    if let Some(tx) = &legacy
        && check_tx_scripts_sanity(tx)
    {
        return legacy;
    }

    extended.or(legacy)
}

/// Read a transaction with the pre-segwit serialization: version, inputs,
/// outputs, locktime, and nothing else. Refuses trailing bytes.
fn deserialize_legacy_tx(bytes: &[u8]) -> Option<bitcoin::Transaction> {
    use bitcoin::consensus::Decodable;
    let mut r = bytes;
    let version = i32::consensus_decode(&mut r).ok()?;
    let input = Vec::<bitcoin::TxIn>::consensus_decode(&mut r).ok()?;
    let output = Vec::<TxOut>::consensus_decode(&mut r).ok()?;
    let lock_time = u32::consensus_decode(&mut r).ok()?;
    if !r.is_empty() {
        return None;
    }
    Some(bitcoin::Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
        input,
        output,
    })
}

/// Core's `CheckTxScriptsSanity`: every script must parse and stay within
/// `MAX_SCRIPT_SIZE`. It is what separates the two readings of an ambiguous
/// transaction — the wrong one almost always yields nonsense scripts.
fn check_tx_scripts_sanity(tx: &bitcoin::Transaction) -> bool {
    const MAX_SCRIPT_SIZE: usize = 10_000;
    if !tx.is_coinbase() {
        for input in &tx.input {
            if !has_valid_ops(&input.script_sig) || input.script_sig.len() > MAX_SCRIPT_SIZE {
                return false;
            }
        }
    }
    tx.output
        .iter()
        .all(|o| has_valid_ops(&o.script_pubkey) && o.script_pubkey.len() <= MAX_SCRIPT_SIZE)
}

/// Confirmations for a transaction found in a block.
///
/// Returns the depth (>= 1) when the containing block is on the active
/// chain, and **-1** when it is not — matching Core's convention in
/// `getrawtransaction`. The caller uses the sign to derive
/// `in_active_chain`.
fn confirmations_for(chain_state: &ChainState, block_hash: &bitcoin::BlockHash, block_height: u32) -> i64 {
    if !crate::rpc::blockchain::is_on_active_chain(chain_state, block_hash, block_height) {
        return -1;
    }
    let tip = chain_state.tip_height();
    i64::from(tip.saturating_sub(block_height).saturating_add(1))
}

/// Build verbose transaction JSON (shared by getrawtransaction and
/// decoderawtransaction). `confirmations` is `Some(0)` for a mempool
/// hit, `Some(N)` for a confirmed tx, and `None` for offline decode
/// (`decoderawtransaction`) where there is no chain context.
///
/// `verbosity`: 1 = standard verbose, 2 = include `fee` and per-input
/// `prevout` (Core v25+). `chain_and_block` is `Some((chain, block))`
/// when the block is available for prevout lookup (verbosity 2).
/// Render a transaction as Core's verbose JSON.
///
/// `verbosity` >= 2 adds prevout data (Core's `getrawtransaction` verbosity 2);
/// `chain_and_block` supplies the chain context that needs.
pub(crate) fn decode_transaction_verbose_net(
    tx: &bitcoin::Transaction,
    blockhash: Option<&str>,
    block_height: Option<u32>,
    // Signed: Core reports -1 for a transaction in a block that is not on the
    // active chain, the same convention as the block's own `confirmations`.
    confirmations: Option<i64>,
    verbosity: u32,
    chain_and_block: Option<(&ChainState, &bitcoin::Block)>,
    network: bitcoin::Network,
) -> Value {
    let txid = tx.compute_txid();
    let raw = bitcoin::consensus::serialize(tx);
    let size = raw.len();
    let weight = tx.weight().to_wu() as usize;
    let vsize = weight.div_ceil(4);

    // For verbosity 2, resolve prevouts so we can compute the fee and
    // annotate each vin with its spent output.
    let prevouts: Vec<Option<bitcoin::TxOut>> = if verbosity >= 2 && !tx.is_coinbase() {
        resolve_prevouts(tx, chain_and_block)
    } else {
        vec![None; tx.input.len()]
    };

    let vin: Vec<Value> = tx
        .input
        .iter()
        .enumerate()
        .map(|(i, input)| {
            if tx.is_coinbase() && i == 0 {
                json!({
                    "coinbase": hex::encode(input.script_sig.as_bytes()),
                    "sequence": input.sequence.0,
                })
            } else {
                let mut v = json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptSig": {
                        "asm": format!("{}", input.script_sig),
                        "hex": hex::encode(input.script_sig.as_bytes()),
                    },
                    "sequence": input.sequence.0,
                });
                if !input.witness.is_empty() {
                    let witness: Vec<String> =
                        input.witness.iter().map(hex::encode).collect();
                    v["txinwitness"] = json!(witness);
                }
                // Verbosity 2: annotate with the spent prevout.
                if verbosity >= 2
                    && let Some(prevout) = &prevouts[i]
                {
                    let unit = default_unit();
                    let mut spk = json!({
                        "asm": format!("{}", prevout.script_pubkey),
                        "hex": hex::encode(prevout.script_pubkey.as_bytes()),
                        "type": script_type(&prevout.script_pubkey),
                    });
                    // Add address if derivable.
                    if let Some(addr) = script_to_address(&prevout.script_pubkey, network) {
                        spk["address"] = json!(addr);
                    }
                    // Lookup the prevout's confirming height and coinbase status.
                    let (prev_height, prev_generated) = if let Some((cs, _)) = chain_and_block {
                        lookup_prevout_height_generated(cs, &input.previous_output)
                    } else {
                        (0, false)
                    };
                    v["prevout"] = json!({
                        "generated": prev_generated,
                        "height": prev_height,
                        "value": format_amount(prevout.value.to_sat(), unit),
                        "scriptPubKey": spk,
                    });
                }
                v
            }
        })
        .collect();

    let unit = default_unit();

    // Compute fee for verbosity 2 (non-coinbase, all prevouts resolved).
    let fee: Option<u64> = if verbosity >= 2 && !tx.is_coinbase() {
        let total_in: Option<u64> = prevouts.iter().try_fold(0u64, |acc, p| {
            p.as_ref().map(|o| acc + o.value.to_sat())
        });
        let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        total_in.map(|i| i.saturating_sub(total_out))
    } else {
        None
    };

    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, output)| {
            let value = format_amount(output.value.to_sat(), unit);
            let mut spk = json!({
                "asm": format!("{}", output.script_pubkey),
                "hex": hex::encode(output.script_pubkey.as_bytes()),
                "type": script_type(&output.script_pubkey),
            });
            if let Some(addr) = script_to_address(&output.script_pubkey, network) {
                spk["address"] = json!(addr);
            }
            json!({
                "value": value,
                "n": n,
                "scriptPubKey": spk,
            })
        })
        .collect();

    // The wtxid (`hash` in Core's output). For non-segwit transactions
    // this equals the txid; for segwit transactions it is the hash that
    // commits to the witness data as well (BIP 141).
    let wtxid = tx.compute_wtxid();

    let mut result = json!({
        "txid": txid.to_string(),
        "hash": wtxid.to_string(),
        "version": tx.version.0 as u32,
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        // Bitcoin Core always echoes the raw hex in verbose responses
        // for `getrawtransaction`. `decoderawtransaction` technically
        // omits it upstream, but echoing the caller's own input back
        // is harmless and lets us share the same verbose builder.
        "hex": hex::encode(&raw),
    });

    // Verbosity 2: add fee (non-coinbase only).
    if let Some(f) = fee {
        result["fee"] = json!(format_amount(f, unit));
    }

    if let Some(bh) = blockhash {
        result["blockhash"] = Value::String(bh.to_string());
    }
    if let Some(h) = block_height {
        result["blockheight"] = json!(h);
    }
    if let Some(c) = confirmations {
        // `confirmations_for` returns -1 as an internal sentinel for "this
        // block is not on the active chain", which the caller turns into
        // `in_active_chain`. Core never puts a negative number on the wire:
        // `TxToJSON` pushes `0` for a block the active chain does not
        // contain, and a positive count otherwise.
        result["confirmations"] = json!(c.max(0));
    }

    // `time`/`blocktime` mimic Core: confirmed transactions get the
    // block's median-time-past, mempool transactions (confirmations==0)
    // get the block's time too in Core, but we omit it for the mempool
    // case. When we have a block header (confirmed), set both.
    if let Some((cs, _)) = chain_and_block
        && let Some(bh) = blockhash
        && let Ok(block_hash) = bh.parse::<bitcoin::BlockHash>()
        && let Some(entry) = cs.get_block_index(&block_hash)
    {
        result["time"] = json!(entry.header.time);
        result["blocktime"] = json!(entry.header.time);
    }

    result
}

/// Resolve prevouts for the inputs of `tx`. Uses the block's own
/// transaction list first (for intra-block spends and to avoid extra
/// lookups), then falls back to the chain state's UTXO/block data.
fn resolve_prevouts(
    tx: &bitcoin::Transaction,
    chain_and_block: Option<(&ChainState, &bitcoin::Block)>,
) -> Vec<Option<bitcoin::TxOut>> {
    let mut result = vec![None; tx.input.len()];

    // Build a quick lookup from the block's own transactions.
    let block_tx_map: std::collections::HashMap<bitcoin::Txid, &bitcoin::Transaction> =
        chain_and_block
            .map(|(_, blk)| {
                blk.txdata.iter().map(|t| (t.compute_txid(), t)).collect()
            })
            .unwrap_or_default();

    for (i, input) in tx.input.iter().enumerate() {
        // Intra-block: the prevout's tx is in the same block.
        if let Some(prev_tx) = block_tx_map.get(&input.previous_output.txid)
            && let Some(out) = prev_tx.output.get(input.previous_output.vout as usize)
        {
            result[i] = Some(out.clone());
            continue;
        }
        // Chain state: look up the UTXO or the full block containing the prevout.
        if let Some((cs, _)) = chain_and_block {
            // Try the UTXO set (unspent coins), then fall back to the
            // txindex for spent coins.
            if let Some(coin) = cs.get_coin(&input.previous_output) {
                result[i] = Some(bitcoin::TxOut {
                    value: Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey,
                });
            } else if let Some(block_hash) = cs.get_tx_location(&input.previous_output.txid)
                && let Some(prev_block) = cs.get_block(&block_hash) {
                    for ptx in &prev_block.txdata {
                        if ptx.compute_txid() == input.previous_output.txid {
                            if let Some(out) = ptx.output.get(input.previous_output.vout as usize) {
                                result[i] = Some(out.clone());
                            }
                            break;
                        }
                    }
                }
        }
    }
    result
}

/// Look up the confirming height and coinbase status of a prevout for
/// verbosity-2 annotation.
fn lookup_prevout_height_generated(
    chain_state: &ChainState,
    outpoint: &OutPoint,
) -> (u32, bool) {
    // Try the UTXO set first.
    if let Some(coin) = chain_state.get_coin(outpoint) {
        return (coin.height, coin.coinbase);
    }
    // Fallback: txindex.
    if let Some(block_hash) = chain_state.get_tx_location(&outpoint.txid)
        && let Some(entry) = chain_state.get_block_index(&block_hash) {
            // The tx at index 0 is the coinbase.
            let is_cb = chain_state.get_block(&block_hash)
                .and_then(|b| b.txdata.first().map(|t| t.compute_txid() == outpoint.txid))
                .unwrap_or(false);
            return (entry.height, is_cb);
        }
    (0, false)
}

/// Derive a Bitcoin address from a scriptPubKey if possible.
///
/// The network is not cosmetic and there is no "unqualified" address form:
/// it picks the bech32 HRP and the base58 version byte, so rendering a
/// mainnet output under `Regtest` returns `bcrt1…` for something that only
/// exists as `bc1…`. This field is read by explorers and copied by people, so
/// it takes the node's own network.
fn script_to_address(script: &bitcoin::Script, network: bitcoin::Network) -> Option<String> {
    bitcoin::address::Address::from_script(script, network)
        .ok()
        .map(|a| a.to_string())
}

/// Annotate the verbose response with `in_active_chain` when the
/// caller explicitly supplied a blockhash. Confirmations > 0 means the
/// block is on the active chain; -1 means it is not.
fn maybe_set_in_active_chain(result: &mut Value, confirmations: Option<i64>) {
    if let Some(c) = confirmations {
        result["in_active_chain"] = json!(c > 0);
    }
}

/// `createrawtransaction` — build an unsigned raw transaction from inputs and outputs.
///
/// Core signature: `createrawtransaction [inputs] [outputs] (locktime) (replaceable) (version)`
///
/// `replaceable`: when `Some(true)`, all inputs that don't have an
/// explicit sequence get `MAX_BIP125_RBF_SEQUENCE` (0xffff_fffd) instead of
/// `SEQUENCE_FINAL` (0xffff_ffff). When `Some(false)` and any input
/// already carries an RBF-signaling sequence, the call is rejected.
pub fn create_raw_transaction(
    inputs: &[Value],
    outputs: &Value,
    locktime: Option<u32>,
    replaceable: Option<bool>,
    version: Option<u32>,
    network: bitcoin::Network,
) -> Result<Value, (i32, String)> {
    const MAX_BIP125_RBF_SEQUENCE: u32 = 0xffff_fffd;

    // Default sequence, exactly Core's three cases in `ConstructTransaction`
    // (`src/rpc/rawtransaction_util.cpp`):
    //
    //     if (rbf.value_or(true))  MAX_BIP125_RBF_SEQUENCE   // FINAL - 2
    //     else if (nLockTime)      MAX_SEQUENCE_NONFINAL     // FINAL - 1
    //     else                     SEQUENCE_FINAL
    //
    // The middle case is not cosmetic. A transaction is final — and its
    // nLockTime therefore unenforced — when *every* input is at
    // SEQUENCE_FINAL. Handing back 0xffff_ffff for a caller who asked for a
    // locktime would silently produce a transaction spendable immediately,
    // which is the opposite of what they requested.
    const SEQUENCE_FINAL: u32 = 0xffff_ffff;
    const MAX_SEQUENCE_NONFINAL: u32 = SEQUENCE_FINAL - 1;
    let default_sequence = if replaceable != Some(false) {
        MAX_BIP125_RBF_SEQUENCE
    } else if locktime.unwrap_or(0) != 0 {
        MAX_SEQUENCE_NONFINAL
    } else {
        SEQUENCE_FINAL
    };

    let mut tx_inputs = Vec::new();
    for input in inputs {
        // Parse txid — validate length and hex-ness with Core messages.
        let txid_str = input["txid"]
            .as_str()
            .ok_or((-3, "JSON value of type null is not of expected type string".to_string()))?;
        let txid: bitcoin::Txid = crate::rpc::util::parse_hash_v(txid_str, "txid")?;

        // Parse vout — Core says "Invalid parameter, missing vout key" for both
        // absent and non-numeric.
        let vout_val = &input["vout"];
        let vout = if vout_val.is_null() || vout_val.is_string() || vout_val.is_boolean() {
            return Err((-8, "Invalid parameter, missing vout key".to_string()));
        } else if let Some(n) = vout_val.as_i64() {
            if n < 0 {
                return Err((-8, "Invalid parameter, vout cannot be negative".to_string()));
            }
            n as u32
        } else {
            return Err((-8, "Invalid parameter, missing vout key".to_string()));
        };

        // Parse optional sequence.
        let sequence = if let Some(seq_val) = input.get("sequence") {
            if seq_val.is_null() {
                default_sequence
            } else if let Some(n) = seq_val.as_i64() {
                if !(0..=0xffff_ffff_i64).contains(&n) {
                    return Err((-8, "Invalid parameter, sequence number is out of range".to_string()));
                }
                n as u32
            } else if let Some(n) = seq_val.as_u64() {
                if n > 0xffff_ffff_u64 {
                    return Err((-8, "Invalid parameter, sequence number is out of range".to_string()));
                }
                n as u32
            } else {
                return Err((-8, "Invalid parameter, sequence number is out of range".to_string()));
            }
        } else {
            default_sequence
        };

        tx_inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        });
    }

    // Core throws only when the transaction signals nothing at all:
    // `rbf && vin.size() > 0 && !SignalsOptInRBF(tx)`, and `SignalsOptInRBF`
    // is true if **any** input is at or below `MAX_BIP125_RBF_SEQUENCE`
    // (`util/rbf.cpp`). satd refused when *any* input was above it, so a
    // mixed transaction — one RBF-signalling input among several that are not
    // — was rejected here and accepted by Core. One signalling input makes
    // the whole transaction replaceable, which is what the flag asks for.
    if replaceable == Some(true)
        && !tx_inputs.is_empty()
        && !tx_inputs
            .iter()
            .any(|inp| inp.sequence.0 <= MAX_BIP125_RBF_SEQUENCE)
    {
        return Err((
            -8,
            "Invalid parameter combination: Sequence number(s) contradict replaceable option"
                .to_string(),
        ));
    }

    let tx_outputs = parse_outputs(outputs, network)?;

    let lt = locktime
        .map(bitcoin::blockdata::locktime::absolute::LockTime::from_consensus)
        .unwrap_or(bitcoin::blockdata::locktime::absolute::LockTime::ZERO);

    let tx_version = version.map(|v| Version(v as i32)).unwrap_or(Version(2));

    let tx = Transaction {
        version: tx_version,
        lock_time: lt,
        input: tx_inputs,
        output: tx_outputs,
    };

    let raw = bitcoin::consensus::serialize(&tx);
    Ok(Value::String(hex::encode(raw)))
}

/// Core's `ParseOutputs` + `NormalizeOutputs` (`src/rpc/rawtransaction_util.cpp`),
/// shared by `createrawtransaction` and `createpsbt` because Core routes both
/// through the same `ConstructTransaction`.
///
/// `network` is not decoration. Core decodes each key with the network-scoped
/// `DecodeDestination`, so a testnet address handed to a mainnet node is a
/// `-5 Invalid Bitcoin address` rather than an output. Accepting it builds a
/// payment to a scriptPubKey whose key the sender does not control, and the
/// address prefix — the one part of the encoding that would have caught the
/// mistake — is not carried in the scriptPubKey, so nothing downstream can
/// notice. `validateaddress`, `scantxoutset` and `deriveaddresses` are all
/// network-scoped already; these two were the surface that still was not.
pub fn parse_outputs(
    outputs: &Value,
    network: bitcoin::Network,
) -> Result<Vec<TxOut>, (i32, String)> {
    let mut tx_outputs = Vec::new();
    // Core dedupes on the decoded `CTxDestination`, not on the string, and
    // reports the caller's spelling in the error.
    let mut seen_destinations: std::collections::HashSet<bitcoin::ScriptBuf> =
        std::collections::HashSet::new();
    let mut seen_data = false;

    // The key/value pairs in source order, duplicates included.
    let mut pairs: Vec<(&str, &Value)> = Vec::new();

    if let Some(obj) = outputs.as_object() {
        for (key, val) in obj {
            pairs.push((key.as_str(), val));
        }
    } else if outputs.is_null() {
        // Core's `NormalizeOutputs` opens with this exact refusal.
        return Err((
            -8,
            "Invalid parameter, output argument must be non-null".to_string(),
        ));
    } else if !outputs.is_array() {
        // `NormalizeOutputs` calls `get_obj()`/`get_array()`, which throw for
        // any other type. Falling through instead left `createpsbt '"hello"'`
        // returning a perfectly valid PSBT with no outputs at all -- a funds
        // RPC answering a malformed request with a transaction.
        return Err((
            -3,
            format!(
                "JSON value of type {} is not of expected type array",
                crate::rpc::params::json_type_name(outputs)
            ),
        ));
    } else if let Some(arr) = outputs.as_array() {
        for item in arr {
            if let Some(map) = item.as_object() {
                if map.len() != 1 {
                    return Err((-8, "Invalid parameter, key-value pair must contain exactly one key".to_string()));
                }
                for (key, val) in map {
                    pairs.push((key.as_str(), val));
                }
            } else {
                return Err((-8, "Invalid parameter, key-value pair not an object as expected".to_string()));
            }
        }
    }

    // Core walks `outputs.getKeys()` -- which carries every repetition -- but
    // reads each value as `outputs[name_]`, and `UniValue::operator[]` returns
    // the *first* member with that key. So a repeated key is visited once per
    // occurrence, always with the first occurrence's value.
    //
    // Reading each occurrence's own value instead changed which error a
    // caller got: `{"<addr>": 0.01, "<addr>": "wat"}` is Core's
    // "duplicated address" (it parses 0.01 twice and trips the dedupe), but
    // reached `parse_btc_amount("wat")` here and came back "Invalid amount",
    // naming a problem that is not the one to fix. For `data` -- which Core
    // does not dedupe on value -- it changed the built script outright.
    // One pass, not a scan-the-prefix-per-entry: `createrawtransaction` is
    // reachable on the read-only listener with a body limit measured in
    // megabytes, so anything quadratic in the number of outputs is a lever.
    {
        let mut first_value: std::collections::HashMap<&str, &Value> =
            std::collections::HashMap::with_capacity(pairs.len());
        for (key, val) in pairs.iter_mut() {
            match first_value.get(*key) {
                Some(first) => *val = first,
                None => {
                    first_value.insert(*key, *val);
                }
            }
        }
    }

    for (key, val) in pairs {
        parse_output_entry(
            key,
            val,
            network,
            &mut tx_outputs,
            &mut seen_destinations,
            &mut seen_data,
        )?;
    }

    Ok(tx_outputs)
}

/// Parse a single key-value output entry for `createrawtransaction`.
fn parse_output_entry(
    key: &str,
    val: &Value,
    network: bitcoin::Network,
    tx_outputs: &mut Vec<TxOut>,
    seen_destinations: &mut std::collections::HashSet<bitcoin::ScriptBuf>,
    seen_data: &mut bool,
) -> Result<(), (i32, String)> {
    if key == "data" {
        if *seen_data {
            return Err((-8, "Invalid parameter, duplicate key: data".to_string()));
        }
        *seen_data = true;
        // Core's `ParseHexV(outputs[name_].getValStr(), "Data")`: the *literal
        // text* of the value, so a JSON number is its own spelling, and
        // `IsHex` requires a non-empty, even-length hex string. satd read
        // `as_str()` (rejecting `{"data": 1234}`, which Core accepts as
        // `"1234"`) and used `hex::decode`, which accepts `""` (Core does not,
        // and an empty `data` built an `OP_RETURN OP_0` output). The message
        // carries the offending value, as Core's does.
        let hex_data = match val {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            other => {
                return Err((
                    -8,
                    format!("Data must be hexadecimal string (not '{other}')"),
                ));
            }
        };
        let bad_hex = || (-8, format!("Data must be hexadecimal string (not '{hex_data}')"));
        if hex_data.is_empty() || hex_data.len() % 2 != 0 {
            return Err(bad_hex());
        }
        let data = hex::decode(&hex_data).map_err(|_| bad_hex())?;
        let push_data = bitcoin::script::PushBytesBuf::try_from(data)
            .map_err(|_| (-8, "OP_RETURN data too large".to_string()))?;
        let script = bitcoin::script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(&push_data)
            .into_script();
        tx_outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        });
    } else {
        // Core's order, which is observable: decode without throwing, parse
        // the amount, *then* reject an undecodable address, and dedupe last.
        // A bad amount on a bad address therefore reports the amount, and a
        // repeated bad address reports the address rather than the repeat.
        let decoded = crate::rpc::address_decode::decode_destination(key, network);
        let amount = parse_btc_amount(val)?;
        let script_pubkey = match decoded {
            crate::rpc::address_decode::Decoded::Valid(addr) => addr.script_pubkey(),
            crate::rpc::address_decode::Decoded::Invalid { .. } => {
                return Err((-5, format!("Invalid Bitcoin address: {key}")));
            }
        };
        if !seen_destinations.insert(script_pubkey.clone()) {
            return Err((-8, format!("Invalid parameter, duplicated address: {key}")));
        }
        tx_outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
    }
    Ok(())
}

/// Core's `ParseFixedPoint` (`src/util/strencodings.cpp`): exact decimal text
/// to a fixed-point integer, with no floating point anywhere.
///
/// The grammar is deliberately tight, and every one of its refusals matters
/// for a value denominated in money:
///
/// - an optional `-`, then either a *single* `0` or a digit `1`-`9` followed
///   by digits — so `01.0` is trailing garbage and `.5` is a missing digit;
/// - an optional `.` that must be followed by at least one digit, so `1.` is
///   refused;
/// - an optional `e`/`E` exponent with an optional sign and at least one
///   digit;
/// - nothing else, anywhere. No `+`, no whitespace, no `NaN`, no `inf`.
///
/// Returns `None` for anything outside that grammar or outside
/// `10^-decimals ..< 10^(18-decimals)`.
fn parse_fixed_point(val: &str, decimals: u32) -> Option<i64> {
    /// Core's `UPPER_BOUND`.
    const UPPER_BOUND: i64 = 1_000_000_000_000_000_000 - 1;

    // Core's `ProcessMantissaDigit`: trailing zeros are counted rather than
    // multiplied in, so `1.10` and `1.1` reach the same mantissa.
    fn mantissa_digit(ch: u8, mantissa: &mut i64, tzeros: &mut i32) -> bool {
        if ch == b'0' {
            *tzeros += 1;
        } else {
            for _ in 0..=*tzeros {
                if *mantissa > UPPER_BOUND / 10 {
                    return false;
                }
                *mantissa *= 10;
            }
            *mantissa += i64::from(ch - b'0');
            *tzeros = 0;
        }
        true
    }

    let b = val.as_bytes();
    let end = b.len();
    let mut ptr = 0usize;
    let mut mantissa: i64 = 0;
    let mut exponent: i64 = 0;
    let mut tzeros: i32 = 0;
    let mut point_ofs: i64 = 0;
    let mut mantissa_sign = false;
    let mut exponent_sign = false;

    if ptr < end && b[ptr] == b'-' {
        mantissa_sign = true;
        ptr += 1;
    }
    if ptr < end {
        if b[ptr] == b'0' {
            // A single leading zero, and only one.
            ptr += 1;
        } else if b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if !mantissa_digit(b[ptr], &mut mantissa, &mut tzeros) {
                    return None;
                }
                ptr += 1;
            }
        } else {
            return None; // missing expected digit
        }
    } else {
        return None; // empty string or a lone '-'
    }
    if ptr < end && b[ptr] == b'.' {
        ptr += 1;
        if ptr < end && b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if !mantissa_digit(b[ptr], &mut mantissa, &mut tzeros) {
                    return None;
                }
                ptr += 1;
                point_ofs += 1;
            }
        } else {
            return None; // missing expected digit
        }
    }
    if ptr < end && (b[ptr] == b'e' || b[ptr] == b'E') {
        ptr += 1;
        if ptr < end && b[ptr] == b'+' {
            ptr += 1;
        } else if ptr < end && b[ptr] == b'-' {
            exponent_sign = true;
            ptr += 1;
        }
        if ptr < end && b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if exponent > UPPER_BOUND / 10 {
                    return None;
                }
                exponent = exponent * 10 + i64::from(b[ptr] - b'0');
                ptr += 1;
            }
        } else {
            return None; // missing expected digit
        }
    }
    if ptr != end {
        return None; // trailing garbage
    }

    if exponent_sign {
        exponent = -exponent;
    }
    exponent = exponent - point_ofs + i64::from(tzeros);
    if mantissa_sign {
        mantissa = -mantissa;
    }

    exponent += i64::from(decimals);
    if exponent < 0 {
        return None; // finer than 10^-decimals
    }
    if exponent >= 18 {
        return None; // 10^(18-decimals) or larger
    }
    for _ in 0..exponent {
        if !(-(UPPER_BOUND / 10)..=UPPER_BOUND / 10).contains(&mantissa) {
            return None;
        }
        mantissa *= 10;
    }
    if !(-UPPER_BOUND..=UPPER_BOUND).contains(&mantissa) {
        return None;
    }
    Some(mantissa)
}

/// Core's `AmountFromValue` (`src/rpc/util.cpp`).
///
/// The decimal text is parsed exactly. satd used to round-trip it through
/// `f64` — `format!("{:.8}")` on a number, `f64::from_str` on a string — which
/// was wrong in both directions. Wrong *value*: 5.6% of five-decimal amounts
/// landed a satoshi away from the decimal the caller wrote, because the
/// nearest `f64` to `0.29` is below it. Wrong *domain*: `f64::from_str`
/// accepts `NaN`, and `NaN < 0.0` and `NaN > 21_000_000.0` are both false, so
/// both range guards fell through and `(NaN * 1e8).round() as u64` saturated
/// to `0` — an output worth nothing, built without an error.
fn parse_btc_amount(val: &Value) -> Result<Amount, (i32, String)> {
    // Core reads the *literal text* of a JSON number (`UniValue::getValStr`),
    // never a parsed double, so a number and its string spelling are the same
    // input to `ParseFixedPoint`.
    let amount_str = match val {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return Err((-3, "Amount is not a number or string".to_string())),
    };
    let sat = parse_fixed_point(&amount_str, 8)
        .ok_or((-3, "Invalid amount".to_string()))?;
    // Core's `MoneyRange`: `0 <= n <= MAX_MONEY`. Negative amounts fail here,
    // not in the parser.
    const MAX_MONEY: i64 = 21_000_000 * 100_000_000;
    if !(0..=MAX_MONEY).contains(&sat) {
        return Err((-3, "Amount out of range".to_string()));
    }
    Ok(Amount::from_sat(sat as u64))
}

/// `combinerawtransaction` — merge multiple partially-signed raw transactions.
pub fn combine_raw_transaction(hex_txs: &[String]) -> Result<Value, (i32, String)> {
    if hex_txs.is_empty() {
        return Err((-8, "Missing transactions".to_string()));
    }

    // Deserialize the first tx as the base
    let first_bytes = hex::decode(&hex_txs[0]).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let mut combined: Transaction = bitcoin::consensus::deserialize(&first_bytes)
        .map_err(|_| (-22, "TX decode failed".to_string()))?;

    // Merge scriptSig and witness from subsequent txs
    for hex_tx in &hex_txs[1..] {
        let tx_bytes = hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|_| (-22, "TX decode failed".to_string()))?;

        if tx.input.len() != combined.input.len() {
            return Err((-22, "Transaction input count mismatch".to_string()));
        }

        for (i, input) in tx.input.iter().enumerate() {
            if combined.input[i].script_sig.is_empty() && !input.script_sig.is_empty() {
                combined.input[i].script_sig = input.script_sig.clone();
            }
            if combined.input[i].witness.is_empty() && !input.witness.is_empty() {
                combined.input[i].witness = input.witness.clone();
            }
        }
    }

    let raw = bitcoin::consensus::serialize(&combined);
    Ok(Value::String(hex::encode(raw)))
}

/// `decodescript` — decode a hex-encoded script.
pub fn decode_script(
    hex_script: &str,
    network: bitcoin::Network,
) -> Result<Value, (i32, String)> {
    let script_bytes = hex::decode(hex_script).map_err(|_| (-22, "Script decode failed".to_string()))?;
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes);

    let script_type = script_type(&script);

    // Core emits `p2sh` as the P2SH address that would wrap this script
    // (`GetScriptForDestination(ScriptHash(script))`), omitting it only for a
    // script that cannot be wrapped. An empty string was indistinguishable
    // from "not a valid script", on the field whose whole use is telling you
    // the address to pay.
    let mut out = json!({
        "asm": format!("{}", script),
        "type": script_type,
    });
    if can_wrap_in_p2sh(&script) {
        // `p2sh_from_hash`, not `Address::p2sh`: the latter refuses a script
        // over 520 bytes (the redeemScript push limit), and Core applies no
        // such gate here -- its ceiling is `IsUnspendable()`'s 10,000. Going
        // through the hash directly keeps a 600-byte script's address, which
        // Core returns and satd used to swallow into an empty string and then
        // drop, leaving the caller no address and no error.
        let hash = bitcoin::hashes::Hash::hash(script.as_bytes());
        let p2sh = bitcoin::Address::p2sh_from_hash(bitcoin::ScriptHash::from_raw_hash(hash), network);
        out["p2sh"] = json!(p2sh.to_string());
    }
    Ok(out)
}

/// Bitcoin Core's `can_wrap` from `decodescript`
/// (`src/rpc/rawtransaction.cpp`): whether a P2SH address wrapping this script
/// is worth reporting.
///
/// satd's previous predicate -- "not already P2SH, and at most 520 bytes" --
/// was wrong in both directions. It emitted a P2SH address for scripts that
/// can never be spent (an `OP_RETURN`, a v1 taproot output script, a P2A
/// anchor, an unknown witness program, a truncated push), and it withheld one
/// for a 521-to-10,000-byte redeemScript that Core happily reports.
fn can_wrap_in_p2sh(script: &bitcoin::Script) -> bool {
    // The five `TxoutType`s Core returns false for outright.
    if script.is_op_return()          // NULL_DATA
        || script.is_p2sh()           // SCRIPTHASH
        || script.is_p2tr()           // WITNESS_V1_TAPROOT
        // WITNESS_UNKNOWN and ANCHOR: any witness program that is not v0.
        // (v0 keyhash / scripthash are wrappable; Core lists them above the
        // early return.)
        || (script.is_witness_program() && !script.is_p2wpkh() && !script.is_p2wsh())
    {
        return false;
    }
    // `!script.HasValidOps() || script.IsUnspendable()`.
    if !has_valid_ops(script) || script.len() > MAX_SCRIPT_SIZE {
        return false;
    }
    // `if (op == OP_CHECKSIGADD || IsOpSuccess(op)) return false;`
    // `OP_CHECKSIGADD` (0xba) is already above `MAX_OPCODE` and so is caught
    // by `HasValidOps`; the OP_SUCCESS opcodes at or below it are not.
    for op in script_opcodes(script) {
        if is_op_success(op) {
            return false;
        }
    }
    true
}

/// Core's `MAX_SCRIPT_SIZE` (`src/script/script.h`), the ceiling
/// `CScript::IsUnspendable` applies.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Core's `MAX_OPCODE` (`OP_NOP10`).
const MAX_OPCODE: u8 = 0xb9;

/// The opcodes of `script`, ignoring pushed data. `None` is never yielded: a
/// malformed push simply ends the walk, and [`has_valid_ops`] is what reports
/// that separately.
fn script_opcodes(script: &bitcoin::Script) -> impl Iterator<Item = u8> + '_ {
    script
        .instruction_indices()
        .filter_map(|r| r.ok())
        .filter_map(|(i, _)| script.as_bytes().get(i).copied())
}

/// Core's `IsOpSuccess` (`src/script/script.cpp`).
fn is_op_success(op: u8) -> bool {
    op == 80
        || op == 98
        || (126..=129).contains(&op)
        || (131..=134).contains(&op)
        || (137..=138).contains(&op)
        || (141..=142).contains(&op)
        || (149..=153).contains(&op)
        || (187..=254).contains(&op)
}

/// Parse a sighash type string into EcdsaSighashType.
fn parse_sighash_type(s: Option<&str>) -> Result<bitcoin::sighash::EcdsaSighashType, (i32, String)> {
    use bitcoin::sighash::EcdsaSighashType;
    match s.unwrap_or("ALL") {
        "ALL" => Ok(EcdsaSighashType::All),
        "NONE" => Ok(EcdsaSighashType::None),
        "SINGLE" => Ok(EcdsaSighashType::Single),
        "ALL|ANYONECANPAY" => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
        "NONE|ANYONECANPAY" => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
        "SINGLE|ANYONECANPAY" => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
        other => Err((-8, format!("Invalid sighash param: {}", other))),
    }
}

/// `signrawtransactionwithkey` — sign a raw transaction with provided private keys.
pub fn sign_raw_transaction_with_key(
    chain_state: &ChainState,
    hex_tx: &str,
    privkeys: &[String],
    prevtxs: Option<&[Value]>,
    sighash_type: Option<&str>,
) -> Result<Value, (i32, String)> {
    let tx_bytes = hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let mut tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_| (-22, "TX decode failed".to_string()))?;

    let secp = Secp256k1::new();
    let ecdsa_sighash_type = parse_sighash_type(sighash_type)?;

    // Parse private keys and build pubkey -> secret key lookup
    let mut key_map: std::collections::HashMap<bitcoin::PublicKey, bitcoin::secp256k1::SecretKey> =
        std::collections::HashMap::new();
    // Also track x-only pubkeys for taproot
    let mut xonly_key_map: std::collections::HashMap<bitcoin::key::XOnlyPublicKey, bitcoin::secp256k1::SecretKey> =
        std::collections::HashMap::new();

    for wif in privkeys {
        let privkey = bitcoin::PrivateKey::from_wif(wif)
            .map_err(|e| (-5, format!("Invalid private key: {}", e)))?;
        let pubkey = privkey.public_key(&secp);
        let (xonly, _parity) = pubkey.inner.x_only_public_key();
        key_map.insert(pubkey, privkey.inner);
        xonly_key_map.insert(xonly, privkey.inner);
    }

    // Collect prevout information for each input
    let num_inputs = tx.input.len();
    let mut prevouts: Vec<Option<TxOut>> = vec![None; num_inputs];

    // First, populate from user-supplied prevtxs
    if let Some(prev_array) = prevtxs {
        for prev in prev_array {
            let txid: bitcoin::Txid = prev["txid"]
                .as_str()
                .ok_or((-8, "Missing txid in prevtxs".to_string()))?
                .parse()
                .map_err(|_| (-8, "Invalid txid in prevtxs".to_string()))?;
            let vout = prev["vout"]
                .as_u64()
                .ok_or((-8, "Missing vout in prevtxs".to_string()))? as u32;
            let script_hex = prev["scriptPubKey"]
                .as_str()
                .ok_or((-8, "Missing scriptPubKey in prevtxs".to_string()))?;
            let script_bytes = hex::decode(script_hex)
                .map_err(|_| (-8, "Invalid scriptPubKey hex".to_string()))?;
            let script_pubkey = bitcoin::ScriptBuf::from_bytes(script_bytes);

            let amount = if let Some(amt) = prev.get("amount") {
                let btc = json_number_as_f64(amt).ok_or((-8, "Invalid amount".to_string()))?;
                Amount::from_sat((btc * 100_000_000.0) as u64)
            } else {
                Amount::ZERO
            };

            let outpoint = OutPoint { txid, vout };
            for (i, input) in tx.input.iter().enumerate() {
                if input.previous_output == outpoint {
                    prevouts[i] = Some(TxOut {
                        value: amount,
                        script_pubkey: script_pubkey.clone(),
                    });
                }
            }
        }
    }

    // Fill remaining from chain state UTXO set
    for (i, input) in tx.input.iter().enumerate() {
        if prevouts[i].is_none()
            && let Some(coin) = chain_state.get_coin(&input.previous_output)
        {
            prevouts[i] = Some(TxOut {
                value: Amount::from_sat(coin.amount),
                script_pubkey: coin.script_pubkey,
            });
        }
    }

    let mut errors: Vec<Value> = Vec::new();

    // The taproot key-spend sighash (BIP 341) commits to every input's amount
    // and scriptPubKey, so it is only computable when every prevout is known.
    // Never fabricate placeholder prevouts: that yields a consensus-invalid
    // signature while implying the input signed fine. Like Core, taproot
    // inputs stay unsigned (with a per-input error) when any prevout is
    // missing; non-taproot inputs commit only to their own prevout and are
    // unaffected.
    let all_prevouts_known = prevouts.iter().all(Option::is_some);
    let all_prevouts: Vec<TxOut> = if all_prevouts_known {
        prevouts.iter().map(|p| p.clone().unwrap()).collect()
    } else {
        Vec::new()
    };

    // Sign each input (index needed for both prevouts[] and tx.input[] mutation)
    #[allow(clippy::needless_range_loop)]
    for i in 0..num_inputs {
        let prevout = match &prevouts[i] {
            Some(p) => p.clone(),
            None => {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Input not found or already spent",
                }));
                continue;
            }
        };

        let script = &prevout.script_pubkey;

        if script.is_p2pkh() {
            // P2PKH: legacy signing
            let cache = bitcoin::sighash::SighashCache::new(&tx);
            let sighash = cache
                .legacy_signature_hash(i, script, ecdsa_sighash_type.to_u32())
                .map_err(|e| (-1, format!("Sighash error: {}", e)))?;

            let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
            // Find which key matches the P2PKH address
            let mut signed = false;
            for (pubkey, secret) in &key_map {
                let expected = bitcoin::ScriptBuf::new_p2pkh(&pubkey.pubkey_hash());
                if expected.as_bytes() == script.as_bytes() {
                    let sig = secp.sign_ecdsa(&msg, secret);
                    let ecdsa_sig = bitcoin::ecdsa::Signature::sighash_all(sig);
                    let mut script_sig = bitcoin::script::Builder::new()
                        .push_slice(ecdsa_sig.serialize())
                        .push_key(pubkey)
                        .into_script();
                    // Override sighash type if not ALL
                    if ecdsa_sighash_type != bitcoin::sighash::EcdsaSighashType::All {
                        script_sig = bitcoin::script::Builder::new()
                            .push_slice(bitcoin::ecdsa::Signature { signature: sig, sighash_type: ecdsa_sighash_type }.serialize())
                            .push_key(pubkey)
                            .into_script();
                    }
                    tx.input[i].script_sig = script_sig;
                    signed = true;
                    break;
                }
            }
            if !signed {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Unable to sign input, no matching key",
                }));
            }
        } else if script.is_p2wpkh() {
            // P2WPKH: segwit v0 signing
            let mut cache = bitcoin::sighash::SighashCache::new(&tx);
            let mut signed = false;
            for (pubkey, secret) in &key_map {
                let Ok(wpkh) = pubkey.wpubkey_hash() else { continue };
                let expected = bitcoin::ScriptBuf::new_p2wpkh(&wpkh);
                if expected.as_bytes() == script.as_bytes() {
                    let sighash = cache
                        .p2wpkh_signature_hash(i, script, prevout.value, ecdsa_sighash_type)
                        .map_err(|e| (-1, format!("Sighash error: {}", e)))?;
                    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                    let sig = secp.sign_ecdsa(&msg, secret);
                    let ecdsa_sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: ecdsa_sighash_type };
                    let mut witness = Witness::new();
                    witness.push(ecdsa_sig.serialize());
                    witness.push(pubkey.to_bytes());
                    tx.input[i].witness = witness;
                    signed = true;
                    break;
                }
            }
            if !signed {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Unable to sign input, no matching key",
                }));
            }
        } else if script.is_p2sh() {
            // P2SH-P2WPKH: check if any key matches wrapped segwit
            let mut signed = false;
            for (pubkey, secret) in &key_map {
                if let Ok(wpkh) = pubkey.wpubkey_hash() {
                    let redeem_script = bitcoin::ScriptBuf::new_p2wpkh(&wpkh);
                    let expected_p2sh = bitcoin::ScriptBuf::new_p2sh(&redeem_script.script_hash());
                    if expected_p2sh.as_bytes() == script.as_bytes() {
                        let mut cache = bitcoin::sighash::SighashCache::new(&tx);
                        let sighash = cache
                            .p2wpkh_signature_hash(i, &redeem_script, prevout.value, ecdsa_sighash_type)
                            .map_err(|e| (-1, format!("Sighash error: {}", e)))?;
                        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                        let sig = secp.sign_ecdsa(&msg, secret);
                        let ecdsa_sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: ecdsa_sighash_type };

                        // P2SH scriptSig pushes the redeem script
                        let redeem_bytes = bitcoin::script::PushBytesBuf::try_from(redeem_script.to_bytes())
                            .map_err(|_| (-1, "Redeem script too large".to_string()))?;
                        tx.input[i].script_sig = bitcoin::script::Builder::new()
                            .push_slice(&redeem_bytes)
                            .into_script();
                        let mut witness = Witness::new();
                        witness.push(ecdsa_sig.serialize());
                        witness.push(pubkey.to_bytes());
                        tx.input[i].witness = witness;
                        signed = true;
                        break;
                    }
                }
            }
            if !signed {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Unable to sign input, no matching key",
                }));
            }
        } else if script.is_p2tr() {
            // P2TR key-path: taproot signing. Like Core, try two readings of
            // each key in order: first as a BIP 341/86 internal key (taptweak
            // applied), then as the output key itself with no tweak — the
            // shape of a BIP 352 silent-payment output. The tweaked reading
            // must be tried first so BIP 86 spends keep their meaning.
            if !all_prevouts_known {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Unable to sign input, missing spent-output data for the taproot sighash",
                }));
                continue;
            }
            let mut cache = bitcoin::sighash::SighashCache::new(&tx);
            // is_p2tr() guarantees the shape OP_1 OP_PUSHBYTES_32 <output key>.
            let output_key = &script.as_bytes()[2..34];
            let mut chosen: Option<(bitcoin::secp256k1::SecretKey, bool)> = None;
            for (xonly_pub, secret) in &xonly_key_map {
                let expected = bitcoin::ScriptBuf::new_p2tr(&secp, *xonly_pub, None);
                if expected.as_bytes() == script.as_bytes() {
                    chosen = Some((*secret, true));
                    break;
                }
            }
            if chosen.is_none() {
                for (xonly_pub, secret) in &xonly_key_map {
                    if xonly_pub.serialize().as_slice() == output_key {
                        chosen = Some((*secret, false));
                        break;
                    }
                }
            }
            let mut signed = false;
            if let Some((secret, apply_tweak)) = chosen {
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &bitcoin::sighash::Prevouts::All(&all_prevouts),
                        bitcoin::sighash::TapSighashType::Default,
                    )
                    .map_err(|e| (-1, format!("Taproot sighash error: {}", e)))?;
                let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
                let sig = if apply_tweak {
                    let tweaked = keypair.tap_tweak(&secp, None);
                    secp.sign_schnorr(&msg, &tweaked.to_keypair())
                } else {
                    secp.sign_schnorr(&msg, &keypair)
                };
                let tap_sig = bitcoin::taproot::Signature {
                    signature: sig,
                    sighash_type: bitcoin::sighash::TapSighashType::Default,
                };
                let mut witness = Witness::new();
                witness.push(tap_sig.serialize());
                tx.input[i].witness = witness;
                signed = true;
            }
            if !signed {
                errors.push(json!({
                    "txid": tx.input[i].previous_output.txid.to_string(),
                    "vout": tx.input[i].previous_output.vout,
                    "error": "Unable to sign input, no matching key",
                }));
            }
        } else {
            errors.push(json!({
                "txid": tx.input[i].previous_output.txid.to_string(),
                "vout": tx.input[i].previous_output.vout,
                "error": "Unsupported script type",
            }));
        }
    }

    let complete = errors.is_empty()
        && tx.input.iter().all(|inp| !inp.script_sig.is_empty() || !inp.witness.is_empty());
    let raw = bitcoin::consensus::serialize(&tx);

    let mut result = json!({
        "hex": hex::encode(raw),
        "complete": complete,
    });
    if !errors.is_empty() {
        result["errors"] = json!(errors);
    }
    Ok(result)
}

/// Classify a script's type.
fn script_type(script: &bitcoin::Script) -> &'static str {
    if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_op_return() {
        "nulldata"
    } else {
        "nonstandard"
    }
}

/// True when an output should be counted toward the burn amount for the
/// `sendrawtransaction` `maxburnamount` check. Matches Core's
/// `(out.scriptPubKey.IsUnspendable() || !out.scriptPubKey.HasValidOps())`
/// (src/rpc/mempool.cpp).
///
/// - `IsUnspendable`: OP_RETURN (first byte == 0x6a), or script > 10,000 bytes
/// - `HasValidOps`: all opcodes in the script are defined (not OP_INVALIDOPCODE
///   0xff or other undefined opcode numbers)
pub fn is_burn_output(txout: &TxOut) -> bool {
    let script = &txout.script_pubkey;
    // OP_RETURN: unspendable.
    if script.is_op_return() {
        return true;
    }
    // Oversized script: unspendable.
    if script.len() > 10_000 {
        return true;
    }
    // Invalid opcodes: !HasValidOps(). Core iterates the script's opcodes
    // and returns false if any `GetOp` produces an opcode >=
    // FIRST_UNDEFINED_OP_VALUE. In practice, the only way to produce an
    // undefined opcode in a raw script is to embed 0xff (OP_INVALIDOPCODE)
    // or other undefined values. We check byte-by-byte for the presence
    // of bytes that represent undefined opcodes when encountered outside
    // of push data.
    !has_valid_ops(script)
}

/// Core's `CScript::HasValidOps` (`src/script/script.cpp`):
///
/// ```cpp
/// while (it < end()) {
///     if (!GetOp(it, opcode, item) || opcode > MAX_OPCODE
///         || item.size() > MAX_SCRIPT_ELEMENT_SIZE) return false;
/// }
/// ```
///
/// Three conditions, and satd checked only a corner of one: it rejected the
/// single byte `0xff` and accepted every other undefined opcode, every
/// truncated push, and every oversized pushed element. `MAX_OPCODE` is
/// `OP_NOP10` (0xb9), so everything above it -- `OP_CHECKSIGADD` at 0xba
/// included -- makes a script invalid-ops in Core.
fn has_valid_ops(script: &bitcoin::Script) -> bool {
    const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
    for instr in script.instructions() {
        match instr {
            // Core's `GetOp` returned false: a truncated or malformed push.
            Err(_) => return false,
            Ok(bitcoin::script::Instruction::PushBytes(b)) => {
                if b.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return false;
                }
            }
            Ok(bitcoin::script::Instruction::Op(op)) => {
                if op.to_u8() > MAX_OPCODE {
                    return false;
                }
            }
        }
    }
    true
}

/// `gettxoutproof` — return a hex-encoded merkle-block proof that one or more
/// transactions are included in a block.
///
/// Without an explicit `blockhash`, the block is located by scanning the UTXO
/// set for an unspent output of one of the txids; with `-txindex` the txindex
/// is consulted instead. All txids must reside in the same block.
/// The most outputs one transaction can have and still fit in a block: the
/// serialized form of an output is at least 9 bytes (8-byte value plus an
/// empty script's length prefix), so a 4 MWU block bounds the count.
const MAX_OUTPUTS_PER_BLOCK: u32 = 4_000_000 / 4 / 9;

pub fn get_tx_out_proof(
    chain_state: &ChainState,
    txids: &[String],
    blockhash_str: Option<&str>,
) -> Result<Value, (i32, String)> {
    use bitcoin::consensus::serialize;
    use crate::storage::blockindex::BlockStatus;
    use std::collections::HashSet;

    if txids.is_empty() {
        return Err((-8, "Parameter 'txids' cannot be empty".into()));
    }

    // Parse + validate txids and check for duplicates.
    let mut parsed_txids: Vec<bitcoin::Txid> = Vec::with_capacity(txids.len());
    let mut seen = HashSet::new();
    for raw in txids {
        let txid: bitcoin::Txid = crate::rpc::util::parse_hash_v(raw, "txid")?;
        if !seen.insert(txid) {
            return Err((-8, "Invalid parameter, duplicated txid".into()));
        }
        parsed_txids.push(txid);
    }

    // Resolve the block hash.
    let block_hash: bitcoin::BlockHash = if let Some(bh) = blockhash_str {
        crate::rpc::util::parse_hash_v(bh, "blockhash")?
    } else {
        // No explicit blockhash — try to find the block via txindex or UTXO.
        let mut found_hash: Option<bitcoin::BlockHash> = None;

        // Try txindex first.
        if chain_state.store_ref().has_txindex() {
            for txid in &parsed_txids {
                if let Some(bh) = chain_state.store_ref().get_tx_location(txid) {
                    found_hash = Some(bh);
                    break;
                }
            }
        }

        // Fall back to UTXO set: scan outputs of each txid for an unspent
        // coin, then look up its confirming block.
        //
        // The bound is the most outputs a transaction can have and still fit
        // in a block, not an arbitrary 100. A transaction whose only unspent
        // output is at index 100 or beyond reported "Transaction not yet in
        // block" for a transaction that is very much in one — and a paying
        // transaction with a long output list is exactly the shape a batching
        // service produces.
        if found_hash.is_none() {
            'outer: for txid in &parsed_txids {
                for vout in 0..MAX_OUTPUTS_PER_BLOCK {
                    let outpoint = OutPoint { txid: *txid, vout };
                    if let Some(coin) = chain_state.get_coin(&outpoint) {
                        // The coin is confirmed at `coin.height`; look up the
                        // block at that height.
                        if let Some(bh) =
                            chain_state.active_chain_hash_at_height(coin.height)
                        {
                            found_hash = Some(bh);
                            break 'outer;
                        }
                    }
                }
            }
        }

        found_hash.ok_or_else(|| (-5i32, "Transaction not yet in block".to_string()))?
    };

    // Verify the block index entry exists and has full data.
    let entry = chain_state
        .get_block_index(&block_hash)
        .ok_or((-5i32, "Block not found".to_string()))?;

    if entry.status == BlockStatus::HeaderOnly || entry.status == BlockStatus::Pruned {
        return Err((-1, "Block not available (not fully downloaded)".into()));
    }

    // Load the full block.
    let block = chain_state
        .get_block(&block_hash)
        .ok_or((-1i32, "Block not available (not fully downloaded)".to_string()))?;

    // Build a set of the block's txids for the predicate.
    let block_txids: Vec<bitcoin::Txid> =
        block.txdata.iter().map(|tx| tx.compute_txid()).collect();

    // Verify all requested txids are in this block.
    let block_txid_set: HashSet<bitcoin::Txid> = block_txids.iter().copied().collect();
    for txid in &parsed_txids {
        if !block_txid_set.contains(txid) {
            return Err((
                -5,
                "Not all transactions found in specified or retrieved block".into(),
            ));
        }
    }

    let target_set: HashSet<bitcoin::Txid> = parsed_txids.iter().copied().collect();
    let merkle_block = bitcoin::MerkleBlock::from_header_txids_with_predicate(
        &block.header,
        &block_txids,
        |txid| target_set.contains(txid),
    );

    Ok(Value::String(hex::encode(serialize(&merkle_block))))
}

/// `verifytxoutproof` — verify a merkle-block proof and return the txids it
/// proves, or an empty array if the proof is invalid.
pub fn verify_tx_out_proof(
    chain_state: &ChainState,
    proof_hex: &str,
) -> Result<Value, (i32, String)> {
    use bitcoin::consensus::deserialize;

    let proof_bytes =
        hex::decode(proof_hex).map_err(|_| (-22i32, "Invalid hex".to_string()))?;
    let merkle_block: bitcoin::MerkleBlock =
        deserialize(&proof_bytes).map_err(|_| (-22i32, "Invalid proof".to_string()))?;

    let mut matches: Vec<bitcoin::Txid> = Vec::new();
    let mut indices: Vec<u32> = Vec::new();

    if merkle_block
        .extract_matches(&mut matches, &mut indices)
        .is_err()
    {
        return Ok(json!([]));
    }

    // Core (`rpc/txoutproof.cpp`) requires the block to be **on the active
    // chain**, not merely indexed, and throws `-5 Block not found in chain`
    // when it is not — a proof against a stale branch proves nothing about
    // the chain the caller is asking about. satd accepted any indexed block
    // and returned the txids, so a proof built on a fork read as valid.
    let block_hash = merkle_block.header.block_hash();
    let entry = chain_state
        .get_block_index(&block_hash)
        .filter(|e| e.num_tx > 0)
        .filter(|e| chain_state.active_chain_hash_at_height(e.height) == Some(block_hash))
        .ok_or((
            -5i32,
            "Block not found in chain".to_string(),
        ))?;

    // Core also requires the proof to cover the whole block:
    // `pindex->nTx == merkleBlock.txn.GetNumTransactions()`. A proof built
    // over a different transaction count describes a different tree.
    if entry.num_tx as usize != merkle_block.txn.num_transactions() as usize {
        return Ok(json!([]));
    }

    // Load the block and verify each matched txid actually exists in it.
    // Without this, a crafted proof that sets nTransactions=1 and
    // vHash=[merkleRoot] would claim the merkle root itself is a
    // transaction — a tree-climbing attack.
    let block = match chain_state.get_block(&block_hash) {
        Some(b) => b,
        None => return Ok(json!([])),
    };
    let block_txid_set: std::collections::HashSet<bitcoin::Txid> =
        block.txdata.iter().map(|tx| tx.compute_txid()).collect();
    let verified: Vec<String> = matches
        .iter()
        .filter(|txid| block_txid_set.contains(*txid))
        .map(|t| t.to_string())
        .collect();
    Ok(json!(verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::pool::Mempool;
    use bitcoin::hashes::Hash;

    /// `decodescript.p2sh` is emitted exactly when Core's `can_wrap` says so.
    ///
    /// satd's predicate was "not already P2SH, and at most 520 bytes", which
    /// is wrong in both directions: it minted an address for scripts that can
    /// never be spent, and withheld one for a redeemScript Core reports.
    #[test]
    fn decodescript_p2sh_follows_cores_can_wrap() {
        let net = bitcoin::Network::Regtest;
        let p2sh_of = |hex: &str| -> Option<String> {
            let r = decode_script(hex, net).expect("decodes");
            r.get("p2sh").and_then(|v| v.as_str()).map(str::to_string)
        };

        // Wrappable: Core's MULTISIG / NONSTANDARD / PUBKEY / PUBKEYHASH /
        // WITNESS_V0_* arm.
        assert!(p2sh_of("51").is_some(), "OP_TRUE is nonstandard and wrappable");
        // P2WPKH output script: OP_0 <20 bytes>.
        assert!(p2sh_of("0014000102030405060708090a0b0c0d0e0f10111213").is_some());

        // The five types Core refuses outright.
        assert_eq!(p2sh_of("6a04deadbeef"), None, "NULL_DATA is unspendable");
        assert_eq!(
            p2sh_of("a914000102030405060708090a0b0c0d0e0f1011121387"),
            None,
            "SCRIPTHASH"
        );
        assert_eq!(
            p2sh_of(&format!("5120{}", "ab".repeat(32))),
            None,
            "WITNESS_V1_TAPROOT"
        );
        assert_eq!(p2sh_of("51024e73"), None, "ANCHOR");
        assert_eq!(
            p2sh_of("5214000102030405060708090a0b0c0d0e0f10111213"),
            None,
            "WITNESS_UNKNOWN"
        );

        // `!HasValidOps()`: a truncated push, and an undefined opcode.
        assert_eq!(p2sh_of("4c"), None, "a truncated PUSHDATA1");
        assert_eq!(p2sh_of("ff"), None, "OP_INVALIDOPCODE");
        assert_eq!(p2sh_of("ba"), None, "OP_CHECKSIGADD is above MAX_OPCODE");

        // `IsOpSuccess` at or below MAX_OPCODE, which HasValidOps lets past.
        assert_eq!(p2sh_of("50"), None, "opcode 80 is OP_SUCCESS");
        assert_eq!(p2sh_of("62"), None, "opcode 98 is OP_SUCCESS");

        // Core has no 520-byte gate here -- its ceiling is `IsUnspendable`'s
        // 10,000 -- so a 600-byte redeemScript gets an address. satd used to
        // swallow rust-bitcoin's refusal into an empty string and drop it,
        // leaving the caller no address and no error.
        assert!(
            p2sh_of(&"51".repeat(600)).is_some(),
            "a 600-byte redeemScript is wrappable"
        );
        assert_eq!(
            p2sh_of(&"51".repeat(10_001)),
            None,
            "over IsUnspendable's 10,000 bytes"
        );
    }

    #[test]
    fn test_getmempoolinfo_empty() {
        let mp = Mempool::new(1_000_000, 0);
        let info = get_mempool_info(&mp);

        assert_eq!(info["size"], 0);
        assert_eq!(info["bytes"], 0);
        assert_eq!(info["loaded"], true);
        assert_eq!(info["maxmempool"], 1_000_000);
    }

    #[test]
    fn test_decode_raw_transaction() {
        use bitcoin::blockdata::locktime::absolute::LockTime;

        // Build a simple transaction
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
                    ),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![
                        0x76, 0xa9, 0x14,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0x88, 0xac,
                    ]),
                },
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };

        // Encode to hex
        let raw = bitcoin::consensus::serialize(&tx);
        let hex_tx = hex::encode(&raw);

        // Decode via the RPC function
        let result = decode_raw_transaction(&hex_tx, None, bitcoin::Network::Regtest).unwrap();

        // Verify txid matches
        let expected_txid = tx.compute_txid().to_string();
        assert_eq!(result["txid"], expected_txid);

        // Verify vin and vout counts
        assert_eq!(result["vin"].as_array().unwrap().len(), 1);
        assert_eq!(result["vout"].as_array().unwrap().len(), 2);

        // Verify version
        assert_eq!(result["version"], 2);
    }

    /// Helper: create a chain state for tests that use prevtxs (chain state won't be queried).
    fn make_chain_state() -> (crate::chain::state::ChainState, std::path::PathBuf) {
        crate::chain::state::tests::make_chain_state()
    }

    /// Helper: generate a key pair and return (WIF, pubkey, secret_key).
    fn test_keypair() -> (String, bitcoin::PublicKey, bitcoin::secp256k1::SecretKey) {
        let secp = Secp256k1::new();
        // Well-known test key: secret = 1
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&key_bytes).unwrap();
        let pk = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: sk,
        });
        let wif = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: sk,
        }
        .to_wif();
        (wif, pk, sk)
    }

    /// Build an unsigned tx spending a fake outpoint to a burn output.
    fn unsigned_tx(outpoint: OutPoint) -> Transaction {
        Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9900_0000),
                script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::all_zeros(),
                ),
            }],
        }
    }

    #[test]
    fn test_sign_p2wpkh() {
        let (cs, _dir) = make_chain_state();
        let (wif, pk, _sk) = test_keypair();

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let script_pubkey = bitcoin::ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap());
        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(result["complete"], true);
        // The signed tx should be longer than the unsigned tx
        assert!(result["hex"].as_str().unwrap().len() > hex_tx.len());

        // Verify the signed tx deserializes and has a witness
        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert!(!signed_tx.input[0].witness.is_empty());
        assert_eq!(signed_tx.input[0].witness.len(), 2); // [sig, pubkey]
    }

    #[test]
    fn test_sign_p2pkh() {
        let (cs, _dir) = make_chain_state();
        let (wif, pk, _sk) = test_keypair();

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let script_pubkey = bitcoin::ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(result["complete"], true);

        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert!(!signed_tx.input[0].script_sig.is_empty());
    }

    #[test]
    fn test_sign_p2tr_keypath() {
        let (cs, _dir) = make_chain_state();
        let (wif, pk, _sk) = test_keypair();

        let secp = Secp256k1::new();
        let (xonly, _parity) = pk.inner.x_only_public_key();
        let script_pubkey = bitcoin::ScriptBuf::new_p2tr(&secp, xonly, None);

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(result["complete"], true);

        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert_eq!(signed_tx.input[0].witness.len(), 1); // [schnorr_sig]
    }

    /// Recompute the key-spend sighash of `signed_tx` input 0 and verify its
    /// witness signature under `expect_key`.
    fn assert_keyspend_sig_verifies(
        signed_tx: &Transaction,
        prevout_spk: &bitcoin::Script,
        expect_key: &bitcoin::key::XOnlyPublicKey,
    ) {
        let secp = Secp256k1::new();
        let prevout = TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: prevout_spk.into(),
        };
        let mut cache = bitcoin::sighash::SighashCache::new(signed_tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&[prevout]),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(
            &signed_tx.input[0].witness[0],
        )
        .unwrap();
        secp.verify_schnorr(&sig, &msg, expect_key)
            .expect("signature must verify under the output key");
    }

    #[test]
    fn test_sign_p2tr_untweaked_keypath() {
        // The output key IS the signing key, no taptweak — the shape of a
        // BIP 352 silent-payment output (#609).
        let (cs, _dir) = make_chain_state();
        let (wif, pk, _sk) = test_keypair();

        let (xonly, _parity) = pk.inner.x_only_public_key();
        let script_pubkey = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(
            result["complete"], true,
            "untweaked P2TR input did not sign: {}",
            result["errors"]
        );

        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert_eq!(signed_tx.input[0].witness.len(), 1);
        // A taptweaked signature would verify under taptweak(P), not P.
        assert_keyspend_sig_verifies(&signed_tx, &script_pubkey, &xonly);
    }

    #[test]
    fn test_sign_p2tr_missing_sibling_prevout_leaves_input_unsigned() {
        // The BIP 341 key-spend sighash commits to every input's prevout.
        // With a sibling prevout unknown, a fabricated placeholder would
        // produce a consensus-invalid signature that looks fine in the
        // response — the taproot input must instead stay unsigned with its
        // own error entry, like Core (script/sign.cpp gates schnorr signing
        // on m_spent_outputs_ready).
        let (cs, _dir) = make_chain_state();
        let (wif, pk, _sk) = test_keypair();

        let (xonly, _parity) = pk.inner.x_only_public_key();
        let script_pubkey = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );

        let known = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let missing = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 1,
        };
        let mut tx = unsigned_tx(known);
        tx.input.push(TxIn {
            previous_output: missing,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        });
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        // Only the P2TR input's prevout is supplied.
        let prevtxs = vec![json!({
            "txid": known.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result =
            sign_raw_transaction_with_key(&cs, &hex_tx, &[wif], Some(&prevtxs), None).unwrap();

        assert_eq!(result["complete"], false);
        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert!(
            signed_tx.input[0].witness.is_empty(),
            "taproot input must not be signed over fabricated prevouts"
        );
        let errors = result["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 2, "one error per input: {errors:?}");
        assert!(errors.iter().any(|e| e["vout"] == 0
            && e["error"]
                .as_str()
                .unwrap()
                .contains("missing spent-output data")));
        assert!(
            errors
                .iter()
                .any(|e| e["vout"] == 1 && e["error"] == "Input not found or already spent")
        );
    }

    #[test]
    fn test_sign_p2tr_tweaked_reading_verifies_and_survives_ambiguity() {
        // Script is the BIP 86 form taptweak(P); the keyset holds both the
        // internal key and the tweaked scalar (whose pubkey IS the output
        // key). Both readings resolve to the same signing scalar, so the
        // assertions are that the ambiguity doesn't break signing and the
        // signature verifies under the output key. Also proves the BIP 86
        // path still signs with the untweaked fallback present.
        let (cs, _dir) = make_chain_state();
        let (wif, pk, sk) = test_keypair();

        let secp = Secp256k1::new();
        let (xonly, _parity) = pk.inner.x_only_public_key();
        let script_pubkey = bitcoin::ScriptBuf::new_p2tr(&secp, xonly, None);
        let output_key =
            bitcoin::key::XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..34]).unwrap();

        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
        let tweaked_sk = keypair.tap_tweak(&secp, None).to_keypair().secret_key();
        let wif_tweaked = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: tweaked_sk,
        }
        .to_wif();

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif, wif_tweaked],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(
            result["complete"], true,
            "ambiguous keyset did not sign: {}",
            result["errors"]
        );

        let signed_bytes = hex::decode(result["hex"].as_str().unwrap()).unwrap();
        let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_bytes).unwrap();
        assert_keyspend_sig_verifies(&signed_tx, &script_pubkey, &output_key);
    }

    #[test]
    fn test_sign_wrong_key_returns_error() {
        let (cs, _dir) = make_chain_state();

        // Use key=1 but the scriptPubKey is for key=2
        let (wif, _pk, _sk) = test_keypair();

        let secp = Secp256k1::new();
        let mut key2_bytes = [0u8; 32];
        key2_bytes[31] = 2;
        let sk2 = bitcoin::secp256k1::SecretKey::from_slice(&key2_bytes).unwrap();
        let pk2 = bitcoin::PublicKey::from_private_key(&secp, &bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: sk2,
        });
        let script_pubkey = bitcoin::ScriptBuf::new_p2wpkh(&pk2.wpubkey_hash().unwrap());

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let prevtxs = vec![json!({
            "txid": outpoint.txid.to_string(),
            "vout": 0,
            "scriptPubKey": hex::encode(script_pubkey.as_bytes()),
            "amount": 50.0,
        })];

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &[wif],
            Some(&prevtxs),
            None,
        )
        .unwrap();

        assert_eq!(result["complete"], false);
        assert!(!result["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_sign_invalid_wif() {
        let (cs, _dir) = make_chain_state();

        let outpoint = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let tx = unsigned_tx(outpoint);
        let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));

        let result = sign_raw_transaction_with_key(
            &cs,
            &hex_tx,
            &["not-a-valid-wif".to_string()],
            None,
            None,
        );

        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, -5);
        assert!(msg.contains("Invalid private key"));
    }

    #[test]
    fn test_parse_sighash_types() {
        use bitcoin::sighash::EcdsaSighashType;
        assert_eq!(parse_sighash_type(None).unwrap(), EcdsaSighashType::All);
        assert_eq!(parse_sighash_type(Some("ALL")).unwrap(), EcdsaSighashType::All);
        assert_eq!(parse_sighash_type(Some("NONE")).unwrap(), EcdsaSighashType::None);
        assert_eq!(parse_sighash_type(Some("SINGLE")).unwrap(), EcdsaSighashType::Single);
        assert_eq!(
            parse_sighash_type(Some("ALL|ANYONECANPAY")).unwrap(),
            EcdsaSighashType::AllPlusAnyoneCanPay
        );
        assert!(parse_sighash_type(Some("INVALID")).is_err());
    }

    // --- PR 7a: standard-surface invisibility differential (design §6.1/§10) ---

    use crate::mempool::pool::QuarantineScope;

    const RELAY_ONLY: QuarantineScope = QuarantineScope {
        relay: true,
        template: false,
    };
    const TEMPLATE_ONLY: QuarantineScope = QuarantineScope {
        relay: false,
        template: true,
    };
    const RELAY_TEMPLATE: QuarantineScope = QuarantineScope {
        relay: true,
        template: true,
    };

    #[test]
    fn getrawmempool_and_info_invisible_to_quarantine() {
        // Reference: two acting txs only — what a Core node whose relay policy
        // refused the others would hold.
        let reference = Mempool::new(300_000_000, 1_000);
        reference.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        reference.insert_scoped_for_test(2, 100, QuarantineScope::acting());

        // Occupied: the same two acting txs plus a quarantined tx in every scope.
        let occupied = Mempool::new(300_000_000, 1_000);
        occupied.insert_scoped_for_test(1, 100, QuarantineScope::acting());
        occupied.insert_scoped_for_test(2, 100, QuarantineScope::acting());
        occupied.insert_scoped_for_test(3, 100, RELAY_ONLY);
        occupied.insert_scoped_for_test(4, 100, TEMPLATE_ONLY);
        occupied.insert_scoped_for_test(5, 100, RELAY_TEMPLATE);

        // getmempoolinfo is byte-identical.
        assert_eq!(
            get_mempool_info(&reference),
            get_mempool_info(&occupied),
            "getmempoolinfo must not reveal the quarantine class"
        );

        // getrawmempool (non-verbose): identical txid set (sorted — HashMap
        // iteration order is not stable across the two pools).
        let mut a: Vec<String> =
            serde_json::from_value(get_raw_mempool(&reference, false)).unwrap();
        let mut b: Vec<String> =
            serde_json::from_value(get_raw_mempool(&occupied, false)).unwrap();
        a.sort();
        b.sort();
        assert_eq!(a, b, "getrawmempool must list the acting class only");
        assert_eq!(a.len(), 2);

        // The quarantine class is genuinely occupied — the equalities are
        // load-bearing, not vacuous.
        assert!(occupied.quarantine_bytes() > 0);
    }

    #[test]
    fn getrawmempool_verbose_descendant_count_excludes_quarantine() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        let mk = |prev: OutPoint, val: u64| Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: Default::default(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(val),
                script_pubkey: Default::default(),
            }],
        };
        let parent = mk(
            OutPoint {
                txid: bitcoin::Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([7; 32]),
                ),
                vout: 0,
            },
            50_000,
        );
        let parent_txid = parent.compute_txid();
        let child = mk(
            OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            40_000,
        );

        let mp = Mempool::new(300_000_000, 1_000);
        mp.insert_tx_scoped_for_test(parent, QuarantineScope::acting());
        mp.insert_tx_scoped_for_test(child, RELAY_TEMPLATE);

        let v = get_raw_mempool(&mp, true);
        let entry = &v[parent_txid.to_string()];
        assert_eq!(
            entry["descendantcount"],
            json!(1),
            "the quarantined child is hidden from the parent's descendantcount"
        );
    }

    /// A mainnet address must not build an output on regtest, and vice
    /// versa. The reverse of the regtest example is what makes this a funds
    /// bug: a testnet address accepted on mainnet pays a scriptPubKey the
    /// sender does not control, and the prefix that would have caught it is
    /// not carried in the script.
    #[test]
    fn create_raw_transaction_rejects_a_foreign_network_address() {
        use bitcoin::Network;

        let inputs = vec![json!({
            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
            "vout": 0
        })];

        // (address, the network it belongs to)
        let cases = [
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Network::Bitcoin),
            ("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs", Network::Bitcoin),
            ("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202", Network::Regtest),
        ];
        for (addr, home) in cases {
            for network in [Network::Bitcoin, Network::Regtest] {
                let outputs = json!({ addr: 0.01 });
                let got = create_raw_transaction(&inputs, &outputs, None, None, None, network);
                if network == home {
                    assert!(got.is_ok(), "{addr} must build an output on {network}");
                } else {
                    let (code, msg) = got.expect_err("{addr} is not a {network} address");
                    assert_eq!(code, -5, "{addr} on {network}");
                    assert_eq!(msg, format!("Invalid Bitcoin address: {addr}"), "{addr} on {network}");
                }
            }
        }
    }

    /// `createpsbt` and `createrawtransaction` reach Core's `ParseOutputs`
    /// through the same `ConstructTransaction`, so the address rule cannot
    /// differ between them.
    #[test]
    fn create_psbt_applies_the_same_address_rule() {
        let inputs = vec![json!({
            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
            "vout": 0
        })];
        let outputs = json!({ "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": 0.01 });
        let (code, msg) = crate::rpc::psbt::create_psbt(
            &inputs,
            &outputs,
            None,
            bitcoin::Network::Regtest,
        )
        .expect_err("a mainnet address is not a regtest destination");
        assert_eq!(code, -5);
        assert_eq!(msg, "Invalid Bitcoin address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");

        // ...and the shared parser is what gives `createpsbt` the array form
        // and string amounts it did not have when it had its own loop.
        let outputs = json!([
            { "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": "0.01" },
            { "data": "deadbeef" },
        ]);
        let v = crate::rpc::psbt::create_psbt(&inputs, &outputs, None, bitcoin::Network::Regtest)
            .expect("array-form outputs");
        assert!(v.as_str().expect("base64").starts_with("cHNidP8"));
    }

    /// Core parses the *decimal text*, exactly. satd round-tripped it through
    /// `f64`, which was wrong in both directions: a wrong value for ordinary
    /// amounts, and a wrong domain for input `f64::from_str` accepts and
    /// Core's grammar does not.
    #[test]
    fn amounts_are_parsed_as_exact_decimals_not_floats() {
        // The value bug. The nearest f64 to 0.29 is below it, so
        // `(0.29_f64 * 1e8) as u64` truncated to 28999999 -- one satoshi
        // short of the decimal the caller wrote. 5.6% of five-decimal
        // amounts landed a satoshi away.
        for (text, sat) in [
            ("0.29", 29_000_000u64),
            ("0.57", 57_000_000),
            ("2.675", 267_500_000),
            ("0.00000001", 1),
            ("21000000", 2_100_000_000_000_000),
            ("1.10", 110_000_000),
            ("1e2", 10_000_000_000),
        ] {
            assert_eq!(
                parse_btc_amount(&json!(text)).expect(text),
                Amount::from_sat(sat),
                "string {text}"
            );
        }
        for (num, sat) in [(json!(0.29), 29_000_000u64), (json!(1), 100_000_000)] {
            assert_eq!(parse_btc_amount(&num).unwrap(), Amount::from_sat(sat), "{num}");
        }

        // The domain bug. `NaN` is the sharp one: it is neither `< 0.0` nor
        // `> 21_000_000.0`, so both range guards fell through and the
        // saturating cast produced a zero-value output with no error at all.
        for bad in ["NaN", "inf", "-inf", "1.000000009", ".5", "1.", "01.0", "+1.0", "", " 1", "1 "] {
            assert!(
                parse_btc_amount(&json!(bad)).is_err(),
                "{bad:?} must not parse as an amount"
            );
        }
        assert_eq!(parse_btc_amount(&json!("NaN")).unwrap_err().0, -3);

        // Range, which Core checks after the parse.
        assert_eq!(
            parse_btc_amount(&json!("-1")).unwrap_err(),
            (-3, "Amount out of range".to_string())
        );
        assert_eq!(
            parse_btc_amount(&json!("21000000.00000001")).unwrap_err(),
            (-3, "Amount out of range".to_string())
        );
        assert_eq!(parse_btc_amount(&json!(true)).unwrap_err().0, -3);
    }

    /// `outputs` that is neither an object nor an array is a request error,
    /// not an empty output set. `createpsbt '"hello"'` used to return a
    /// perfectly valid PSBT with no outputs.
    #[test]
    fn a_scalar_outputs_argument_is_refused() {
        let network = bitcoin::Network::Regtest;
        for (bad, ty) in [
            (json!("hello"), "string"),
            (json!(5), "number"),
            (json!(true), "bool"),
        ] {
            let (code, msg) =
                parse_outputs(&bad, network).expect_err("a scalar is not an output set");
            assert_eq!(code, -3, "{bad}");
            assert_eq!(
                msg,
                format!("JSON value of type {ty} is not of expected type array"),
                "{bad}"
            );
        }
        // Core's `NormalizeOutputs` opens by refusing null by name.
        let (code, msg) = parse_outputs(&json!(null), network).expect_err("null");
        assert_eq!(code, -8);
        assert_eq!(msg, "Invalid parameter, output argument must be non-null");

        // Both empty forms are legitimate and produce no outputs.
        assert!(parse_outputs(&json!({}), network).unwrap().is_empty());
        assert!(parse_outputs(&json!([]), network).unwrap().is_empty());
    }

    /// Core's `ParseHexV` reads the literal text and requires non-empty,
    /// even-length hex.
    #[test]
    fn data_outputs_follow_cores_hex_rules() {
        let network = bitcoin::Network::Regtest;
        // A JSON number is its own spelling to Core, and `1234` is valid hex.
        let outs = parse_outputs(&json!({"data": 1234}), network).expect("numeric data");
        assert_eq!(outs.len(), 1);
        // An empty string is not hex; it used to build `OP_RETURN OP_0`.
        for bad in [json!({"data": ""}), json!({"data": "abc"}), json!({"data": "zz"})] {
            let (code, msg) = parse_outputs(&bad, network).expect_err("{bad}");
            assert_eq!(code, -8, "{bad}");
            assert!(msg.starts_with("Data must be hexadecimal string (not '"), "{msg}");
        }
    }

    /// Dedup is on the decoded destination, not the address string, so two
    /// spellings of one script collide as they do in Core. Restoring
    /// string-keyed dedup must fail a named test.
    #[test]
    fn two_spellings_of_one_destination_are_a_duplicate() {
        const UPPER: &str = "BCRT1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQDKU202";
        const LOWER: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
        let (code, msg) = parse_outputs(
            &json!([{ UPPER: 0.01 }, { LOWER: 0.02 }]),
            bitcoin::Network::Regtest,
        )
        .expect_err("one destination, written twice");
        assert_eq!(code, -8);
        assert_eq!(msg, format!("Invalid parameter, duplicated address: {LOWER}"));
    }

    /// Core's `ParseOutputs` decodes, parses the amount, *then* throws on an
    /// undecodable address, and dedupes last. The order is observable through
    /// which of two simultaneous errors comes back.
    #[test]
    fn parse_outputs_reports_errors_in_cores_order() {
        let network = bitcoin::Network::Regtest;
        const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

        // Bad address *and* bad amount: Core reports the amount, because
        // `AmountFromValue` runs before `IsValidDestination`.
        let (code, _) = parse_outputs(&json!({ "notanaddress": "wat" }), network)
            .expect_err("neither the address nor the amount is usable");
        assert_eq!(code, -3, "the amount error precedes the address error");

        // A repeated *invalid* address is an address error, not a duplicate
        // one -- the validity check runs first.
        let (code, msg) = parse_outputs(
            &json!([{ "notanaddress": 0.01 }, { "notanaddress": 0.01 }]),
            network,
        )
        .expect_err("still not an address the second time");
        assert_eq!(code, -5);
        assert_eq!(msg, "Invalid Bitcoin address: notanaddress");

        // A repeated valid address is the duplicate error.
        let (code, msg) = parse_outputs(&json!([{ ADDR: 0.01 }, { ADDR: 0.02 }]), network)
            .expect_err("the same destination twice");
        assert_eq!(code, -8);
        assert_eq!(msg, format!("Invalid parameter, duplicated address: {ADDR}"));
    }

    /// Core reads a repeated key's value as `outputs[name_]`, which is the
    /// *first* member with that key -- so the second occurrence's value is
    /// never parsed, and the answer is the duplicate-address error rather than
    /// whatever the second value happens to be.
    ///
    /// Reading each occurrence's own value reported "Invalid amount" here,
    /// pointing the caller at the wrong half of their request. Deleting the
    /// first-occurrence pass fails this test.
    #[test]
    fn a_repeated_key_is_read_with_its_first_value() {
        let network = bitcoin::Network::Regtest;
        const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

        let (code, msg) = parse_outputs(&json!([{ ADDR: 0.01 }, { ADDR: "wat" }]), network)
            .expect_err("the same destination twice");
        assert_eq!(code, -8, "the unparseable second value is never reached");
        assert_eq!(msg, format!("Invalid parameter, duplicated address: {ADDR}"));

        // And the first value is the one a bad *first* entry is judged on.
        let (code, _) = parse_outputs(&json!([{ ADDR: "wat" }, { ADDR: 0.01 }]), network)
            .expect_err("the first value is unparseable");
        assert_eq!(code, -3);
    }

    /// An explicit `null` is Core's `NormalizeOutputs` refusal, by name. Core
    /// declares `outputs` with `skip_type_check`, so the null reaches the
    /// handler rather than the argument type checker.
    #[test]
    fn a_null_outputs_argument_is_refused_by_name() {
        let (code, msg) = parse_outputs(&json!(null), bitcoin::Network::Regtest)
            .expect_err("null is not an output set");
        assert_eq!(code, -8);
        assert_eq!(msg, "Invalid parameter, output argument must be non-null");
    }

    /// Core's `ConstructTransaction` picks the default sequence from three
    /// cases, not two. The middle one decides whether a requested locktime is
    /// enforceable at all.
    #[test]
    fn create_raw_transaction_sequence_matches_core_three_cases() {
        let inputs = vec![json!({
            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
            "vout": 0
        })];
        let outputs = json!({});

        let seq_of = |locktime: Option<u32>, replaceable: Option<bool>| -> u64 {
            let v = create_raw_transaction(
                &inputs,
                &outputs,
                locktime,
                replaceable,
                None,
                bitcoin::Network::Regtest,
            )
                .expect("well-formed request");
            let hex = v.as_str().expect("hex string");
            let raw = hex::decode(hex).expect("valid hex");
            let tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&raw).expect("valid tx");
            u64::from(tx.input[0].sequence.0)
        };

        // rbf true, or absent (Core's default is true): FINAL - 2.
        assert_eq!(seq_of(None, Some(true)), 0xffff_fffd);
        assert_eq!(seq_of(None, None), 0xffff_fffd);
        assert_eq!(seq_of(Some(500), None), 0xffff_fffd);

        // rbf false with no locktime: FINAL.
        assert_eq!(seq_of(None, Some(false)), 0xffff_ffff);
        assert_eq!(seq_of(Some(0), Some(false)), 0xffff_ffff);

        // rbf false *with* a locktime: FINAL - 1. At FINAL the transaction
        // would be final regardless of nLockTime, so the caller's timelock
        // would not be enforced.
        assert_eq!(
            seq_of(Some(500), Some(false)),
            0xffff_fffe,
            "an explicit locktime must not be silently disabled by a final sequence"
        );
    }

    /// The genesis coinbase txid is answered from network constants rather
    /// than a block read; pin it against the known mainnet value so that
    /// swap can never drift.
    #[test]
    fn genesis_coinbase_txid_matches_the_known_constants() {
        assert_eq!(
            genesis_coinbase_txid(bitcoin::Network::Bitcoin).to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        // Testnet3, signet and regtest reuse Satoshi's coinbase verbatim, so
        // they share mainnet's txid even though their block hashes differ.
        for n in [
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ] {
            assert_eq!(
                genesis_coinbase_txid(n),
                genesis_coinbase_txid(bitcoin::Network::Bitcoin),
                "{n:?} reuses the mainnet genesis coinbase"
            );
        }

        // Testnet4 does not: it carries its own coinbase message, which is
        // why the cache is keyed per network rather than computed once.
        assert_eq!(
            genesis_coinbase_txid(bitcoin::Network::Testnet4).to_string(),
            "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
        );
    }

    /// Core's `DecodeTx` reads an ambiguous transaction both ways and picks
    /// with `CheckTxScriptsSanity`. The segwit marker `0x00 0x01` is the
    /// ambiguity: extended serialization calls it a witness flag, legacy
    /// calls it zero inputs and one output.
    #[test]
    fn iswitness_selects_the_serialization_it_says_it_does() {
        use bitcoin::hashes::Hash as _;

        // A real segwit transaction: one input with a witness.
        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        tx.input[0].witness.push([0x02; 72]);
        let bytes = bitcoin::consensus::serialize(&tx);

        // Auto and forced-witness both read the witness.
        for (no_wit, wit) in [(true, true), (false, true)] {
            let decoded = decode_tx(&bytes, no_wit, wit).expect("decodes");
            assert_eq!(decoded.compute_wtxid(), tx.compute_wtxid());
            assert!(!decoded.input[0].witness.is_empty());
        }

        // Forced-legacy must NOT return the witness reading. satd used to
        // call the extended decoder here and merely stop requiring full
        // consumption, so `iswitness=false` returned the witness transaction
        // — the opposite of what the argument asks for.
        let legacy = decode_tx(&bytes, true, false);
        assert!(
            legacy.is_none_or(|t| t.compute_wtxid() != tx.compute_wtxid()),
            "iswitness=false returned the witness reading"
        );
    }

    /// A legacy transaction reads the same under every setting: there is no
    /// marker to be ambiguous about.
    #[test]
    fn a_legacy_transaction_reads_the_same_every_way() {
        use bitcoin::hashes::Hash as _;

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                    vout: 1,
                },
                script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(2_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let bytes = bitcoin::consensus::serialize(&tx);
        for (no_wit, wit) in [(true, true), (true, false), (false, true)] {
            let decoded = decode_tx(&bytes, no_wit, wit).expect("decodes");
            assert_eq!(decoded.compute_txid(), tx.compute_txid());
        }
    }

    /// Core discards any reading that does not consume the whole input
    /// ("Ignore serializations that do not fully consume the hex string").
    /// satd's forced-legacy path used `deserialize_partial`, which does not,
    /// so trailing bytes were accepted in silence.
    #[test]
    fn trailing_bytes_are_not_a_transaction() {
        use bitcoin::hashes::Hash as _;

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x33; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(3_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut bytes = bitcoin::consensus::serialize(&tx);
        assert!(decode_tx(&bytes, true, true).is_some(), "the fixture must decode");
        bytes.push(0xff);
        assert!(
            decode_tx(&bytes, true, true).is_none(),
            "a transaction with a byte glued on the end is not that transaction"
        );
    }

    /// `CheckTxScriptsSanity` is what separates the two readings. A script
    /// that does not parse fails it.
    #[test]
    fn script_sanity_rejects_an_unparseable_script() {
        use bitcoin::hashes::Hash as _;

        let mut tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(check_tx_scripts_sanity(&tx));
        // A push that claims more bytes than follow it.
        tx.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x4c, 0xff, 0x00]);
        assert!(!check_tx_scripts_sanity(&tx));
    }
}
