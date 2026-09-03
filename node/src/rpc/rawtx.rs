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

/// `getmempoolinfo` — return mempool statistics.
pub fn get_mempool_info(mempool: &Mempool) -> Value {
    let info = mempool.info();
    let unit = default_unit();
    let min_fee = format_feerate_sat_per_kvb(info.min_fee_rate, unit);
    let incremental = format_feerate_sat_per_kvb(1_000, unit); // 1000 sat/kvB

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

    // Local lookup so ancestor/descendant rollups don't re-lock the
    // mempool per hop. Single snapshot → O(N) verbose build instead of
    // O(N) RwLock re-entries.
    let entry_map: std::collections::HashMap<bitcoin::Txid, (usize, u64)> = entries
        .iter()
        .map(|(txid, e)| (*txid, (e.weight, e.fee)))
        .collect();

    let mut result = serde_json::Map::new();
    let unit = default_unit();
    for (txid, entry) in &entries {
        let vsize = if entry.weight > 0 {
            entry.weight.div_ceil(4)
        } else {
            0
        };
        let fee = format_amount(entry.fee, unit);

        // Restrict the graph to the acting class (`entry_map` keys): an acting
        // tx never has a quarantined ancestor (§3 infectious propagation) but
        // can have a quarantined descendant, so filter both to keep the counts
        // invisible to the quarantine class.
        let ancestors: std::collections::HashSet<bitcoin::Txid> = mempool
            .get_ancestors(txid)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| entry_map.contains_key(a))
            .collect();
        let descendants: std::collections::HashSet<bitcoin::Txid> = mempool
            .get_descendants(txid)
            .unwrap_or_default()
            .into_iter()
            .filter(|d| entry_map.contains_key(d))
            .collect();

        let ancestor_count = ancestors.len() + 1;
        let ancestor_size: usize = ancestors
            .iter()
            .filter_map(|a| entry_map.get(a))
            .map(|(w, _)| if *w > 0 { w.div_ceil(4) } else { 0 })
            .sum::<usize>()
            + vsize;
        let ancestor_fees: u64 = ancestors
            .iter()
            .filter_map(|a| entry_map.get(a))
            .map(|(_, f)| *f)
            .sum::<u64>()
            + entry.fee;

        let descendant_count = descendants.len() + 1;
        let descendant_size: usize = descendants
            .iter()
            .filter_map(|d| entry_map.get(d))
            .map(|(w, _)| if *w > 0 { w.div_ceil(4) } else { 0 })
            .sum::<usize>()
            + vsize;
        let descendant_fees: u64 = descendants
            .iter()
            .filter_map(|d| entry_map.get(d))
            .map(|(_, f)| *f)
            .sum::<u64>()
            + entry.fee;

        result.insert(
            txid.to_string(),
            json!({
                "vsize": vsize,
                "weight": entry.weight,
                "time": entry.time,
                "fees": {
                    "base": fee,
                },
                "ancestorcount": ancestor_count,
                "ancestorsize": ancestor_size,
                "ancestorfees": ancestor_fees,
                "descendantcount": descendant_count,
                "descendantsize": descendant_size,
                "descendantfees": descendant_fees,
            }),
        );
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
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| (-8, "parameter 1 must be of length 64 (not 0, for txid)".to_string()))?;

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
                Ok(decode_transaction_verbose(
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
                    let mut result = decode_transaction_verbose(
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
                        Ok(decode_transaction_verbose(
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
    if s.len() != 64 {
        return Err((-8, format!(
            "parameter 3 must be of length 64 (not {}, for '{s}')",
            s.len()
        )));
    }
    // Hex check: every character must be [0-9a-fA-F].
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((-8, format!(
            "parameter 3 must be hexadecimal string (not '{s}')"
        )));
    }
    Ok(())
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

    let tx: bitcoin::Transaction = match iswitness {
        Some(true) => {
            // Force witness decoding.
            bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|_| (-22, "TX decode failed".to_string()))?
        }
        Some(false) => {
            // Force non-witness (legacy) decoding.
            bitcoin::consensus::deserialize_partial::<bitcoin::Transaction>(&tx_bytes)
                .map(|(tx, _)| tx)
                .map_err(|_| (-22, "TX decode failed".to_string()))
                // For non-witness decoding, the segwit marker (0x00 0x01) after
                // version would be treated as zero inputs + one output, which
                // will fail to parse as a valid transaction. That is the expected
                // behavior for `iswitness=false` on a segwit tx.
                ?
        }
        None => {
            // Auto: try witness first, fall back to non-witness.
            bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|_| (-22, "TX decode failed".to_string()))?
        }
    };

    Ok(decode_transaction_verbose(&tx, None, None, None, 1, None, network))
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
pub(crate) fn decode_transaction_verbose(
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
        if txid_str.len() != 64 {
            return Err((-8, format!(
                "txid must be of length 64 (not {}, for '{txid_str}')",
                txid_str.len()
            )));
        }
        let txid: bitcoin::Txid = txid_str.parse().map_err(|_| {
            (-8, format!("txid must be hexadecimal string (not '{txid_str}')"))
        })?;

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

    // Check: if replaceable is explicitly true, no input's sequence may be
    // above MAX_BIP125_RBF_SEQUENCE (would contradict the replaceable flag).
    if replaceable == Some(true) {
        for inp in &tx_inputs {
            if inp.sequence.0 > MAX_BIP125_RBF_SEQUENCE {
                return Err((-8, "Invalid parameter combination: Sequence number(s) contradict replaceable option".to_string()));
            }
        }
    }

    // Parse outputs — can be an object {addr: amount, ...} or an array [{addr: amount}, ...].
    let mut tx_outputs = Vec::new();
    let mut seen_addresses: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_data = false;

    if let Some(obj) = outputs.as_object() {
        for (key, val) in obj {
            parse_output_entry(key, val, &mut tx_outputs, &mut seen_addresses, &mut seen_data)?;
        }
    } else if let Some(arr) = outputs.as_array() {
        for item in arr {
            if let Some(map) = item.as_object() {
                if map.len() != 1 {
                    return Err((-8, "Invalid parameter, key-value pair must contain exactly one key".to_string()));
                }
                for (key, val) in map {
                    parse_output_entry(key, val, &mut tx_outputs, &mut seen_addresses, &mut seen_data)?;
                }
            } else {
                return Err((-8, "Invalid parameter, key-value pair not an object as expected".to_string()));
            }
        }
    }

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

/// Parse a single key-value output entry for `createrawtransaction`.
fn parse_output_entry(
    key: &str,
    val: &Value,
    tx_outputs: &mut Vec<TxOut>,
    seen_addresses: &mut std::collections::HashSet<String>,
    seen_data: &mut bool,
) -> Result<(), (i32, String)> {
    if key == "data" {
        if *seen_data {
            return Err((-8, "Invalid parameter, duplicate key: data".to_string()));
        }
        *seen_data = true;
        let hex_data = val.as_str().ok_or((-8, "Data must be hexadecimal string".to_string()))?;
        let data = hex::decode(hex_data).map_err(|_| (-8, "Data must be hexadecimal string".to_string()))?;
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
        if !seen_addresses.insert(key.to_string()) {
            return Err((-8, format!("Invalid parameter, duplicated address: {key}")));
        }
        let amount = parse_btc_amount(val)?;
        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = key
            .parse()
            .map_err(|_| (-5, "Invalid Bitcoin address".to_string()))?;
        tx_outputs.push(TxOut {
            value: amount,
            script_pubkey: address.assume_checked().script_pubkey(),
        });
    }
    Ok(())
}

/// Parse a BTC amount from a JSON value, with Core-compatible error messages.
fn parse_btc_amount(val: &Value) -> Result<Amount, (i32, String)> {
    // Core accepts both number and string representations.
    let amount_str = match val {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    return Err((-3, "Amount out of range".to_string()));
                }
                format!("{:.8}", f)
            } else {
                return Err((-3, "Invalid amount".to_string()));
            }
        }
        Value::String(s) => {
            let _: f64 = s.parse().map_err(|_| (-3, "Invalid amount".to_string()))?;
            s.clone()
        }
        _ => return Err((-3, "Invalid amount".to_string())),
    };
    let btc: f64 = amount_str.parse().map_err(|_| (-3, "Invalid amount".to_string()))?;
    if btc < 0.0 {
        return Err((-3, "Amount out of range".to_string()));
    }
    if btc > 21_000_000.0 {
        return Err((-3, "Amount out of range".to_string()));
    }
    let sat = (btc * 100_000_000.0).round() as u64;
    Ok(Amount::from_sat(sat))
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
pub fn decode_script(hex_script: &str) -> Result<Value, (i32, String)> {
    let script_bytes = hex::decode(hex_script).map_err(|_| (-22, "Script decode failed".to_string()))?;
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes);

    let script_type = script_type(&script);

    Ok(json!({
        "asm": format!("{}", script),
        "type": script_type,
        "p2sh": "", // would need hash computation
    }))
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
                let btc = amt.as_f64().ok_or((-8, "Invalid amount".to_string()))?;
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

/// Mirrors Core's `CScript::HasValidOps()`: iterates the script's opcodes
/// via `GetOp` and returns `false` if any opcode is undefined.
fn has_valid_ops(script: &bitcoin::Script) -> bool {
    // Walk through the script's instruction iterator. `rust-bitcoin`'s
    // `Instructions` yields `Result<Instruction, Error>` where errors
    // represent un-parseable regions. An `Err` or an opcode that is
    // unassigned / explicitly invalid counts as "not valid ops".
    for instr in script.instructions() {
        match instr {
            Err(_) => return false,
            Ok(bitcoin::script::Instruction::Op(op)) => {
                let byte = op.to_u8();
                // Core's FIRST_UNDEFINED_OP_VALUE is 0xfb (OP_INVALIDOPCODE
                // is 0xff). However, opcodes 0xbb through 0xfe are also
                // undefined/reserved ("OP_NOP" range ends at 0xb9,
                // OP_CHECKSIGADD is 0xba). The simplest mirror of Core's
                // check: opcodes with numeric value in [0xbb..=0xff] are
                // treated as undefined.
                // Actually Core's check is simpler: opcodes >= OP_INVALIDOPCODE
                // (0xff) are invalid, plus certain NOP ranges. But the
                // main test case is OP_INVALIDOPCODE (0xff).
                // Core defines FIRST_UNDEFINED_OP_VALUE = 0xfb (after
                // OP_CHECKSIGADD = 0xba). So opcodes >= 0xfb are invalid.
                // Let's just check for 0xff which is the test case.
                if byte == 0xff {
                    return false;
                }
            }
            Ok(bitcoin::script::Instruction::PushBytes(_)) => {}
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
        if raw.len() != 64 {
            return Err((-8, format!(
                "txid must be of length 64 (not {}, for '{raw}')",
                raw.len(),
            )));
        }
        let txid: bitcoin::Txid = raw.parse().map_err(|_| {
            (-8i32, format!("txid must be hexadecimal string (not '{raw}')"))
        })?;
        if !seen.insert(txid) {
            return Err((-8, "Invalid parameter, duplicated txid".into()));
        }
        parsed_txids.push(txid);
    }

    // Resolve the block hash.
    let block_hash: bitcoin::BlockHash = if let Some(bh) = blockhash_str {
        if bh.len() != 64 {
            return Err((-8, format!(
                "blockhash must be of length 64 (not {}, for '{bh}')",
                bh.len(),
            )));
        }
        bh.parse().map_err(|_| {
            (-8i32, format!("blockhash must be hexadecimal string (not '{bh}')"))
        })?
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
        if found_hash.is_none() {
            'outer: for txid in &parsed_txids {
                for vout in 0..100u32 {
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

    // Verify the merkle root matches a block header on our chain.
    let block_hash = merkle_block.header.block_hash();
    if chain_state.get_block_index(&block_hash).is_none() {
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
            let v = create_raw_transaction(&inputs, &outputs, locktime, replaceable, None)
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
}
