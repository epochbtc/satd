use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use serde_json::{json, Value};

/// `sendrawtransaction` — submit a raw transaction to the mempool.
pub fn send_raw_transaction(
    chain_state: &ChainState,
    mempool: &Mempool,
    hex_tx: &str,
) -> Result<Value, (i32, String)> {
    let tx_bytes =
        hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_| (-22, "TX decode failed".to_string()))?;

    let txid = mempool
        .accept_transaction(tx, chain_state, chain_state.script_verifier())
        .map_err(|e| (-25, e.to_string()))?;

    Ok(Value::String(txid.to_string()))
}

/// `getmempoolinfo` — return mempool statistics.
pub fn get_mempool_info(mempool: &Mempool) -> Value {
    let info = mempool.info();
    let min_fee_btc = info.min_fee_rate as f64 / 100_000_000.0;

    json!({
        "loaded": true,
        "size": info.size,
        "bytes": info.bytes,
        "usage": info.bytes,
        "maxmempool": info.max_size,
        "mempoolminfee": min_fee_btc,
        "minrelaytxfee": min_fee_btc,
        "incrementalrelayfee": 0.00001000,
        "unbroadcastcount": 0,
        "fullrbf": false,
    })
}

/// `getrawmempool` — list mempool transaction ids.
pub fn get_raw_mempool(mempool: &Mempool, verbose: bool) -> Value {
    let entries = mempool.get_all_entries();

    if !verbose {
        let txids: Vec<String> = entries.iter().map(|(txid, _)| txid.to_string()).collect();
        return json!(txids);
    }

    let mut result = serde_json::Map::new();
    for (txid, entry) in &entries {
        let vsize = if entry.weight > 0 {
            (entry.weight + 3) / 4
        } else {
            0
        };
        let fee_btc = entry.fee as f64 / 100_000_000.0;

        result.insert(
            txid.to_string(),
            json!({
                "vsize": vsize,
                "weight": entry.weight,
                "time": entry.time,
                "fees": {
                    "base": fee_btc,
                },
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
    blockhash: Option<&str>,
) -> Result<Value, (i32, String)> {
    let txid: bitcoin::Txid = txid_str
        .parse()
        .map_err(|_| (-8, "parameter 1 must be of length 64 (not 0, for txid)".to_string()))?;

    // Search mempool first (unless blockhash is specified)
    if blockhash.is_none() {
        if let Some(entry) = mempool.get(&txid) {
            return if verbose {
                Ok(decode_transaction_verbose(&entry.tx, None, None))
            } else {
                let raw = bitcoin::consensus::serialize(&entry.tx);
                Ok(Value::String(hex::encode(raw)))
            };
        }
    }

    // Search in a specific block
    if let Some(hash_str) = blockhash {
        let block_hash: bitcoin::BlockHash = hash_str
            .parse()
            .map_err(|_| (-8, "Invalid block hash".to_string()))?;

        let block = chain_state
            .get_block(&block_hash)
            .ok_or((-5, "Block not found".to_string()))?;

        let entry = chain_state.get_block_index(&block_hash);

        for tx in &block.txdata {
            if tx.compute_txid() == txid {
                return if verbose {
                    let height = entry.as_ref().map(|e| e.height);
                    Ok(decode_transaction_verbose(
                        tx,
                        Some(hash_str),
                        height,
                    ))
                } else {
                    let raw = bitcoin::consensus::serialize(tx);
                    Ok(Value::String(hex::encode(raw)))
                };
            }
        }
    }

    Err((-5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.".to_string()))
}

/// `decoderawtransaction` — decode a raw transaction hex to JSON.
pub fn decode_raw_transaction(hex_tx: &str) -> Result<Value, (i32, String)> {
    let tx_bytes =
        hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_| (-22, "TX decode failed".to_string()))?;

    Ok(decode_transaction_verbose(&tx, None, None))
}

/// Build verbose transaction JSON (shared by getrawtransaction and decoderawtransaction).
fn decode_transaction_verbose(
    tx: &bitcoin::Transaction,
    blockhash: Option<&str>,
    block_height: Option<u32>,
) -> Value {
    let txid = tx.compute_txid();
    let raw = bitcoin::consensus::serialize(tx);
    let size = raw.len();
    let weight = tx.weight().to_wu() as usize;
    let vsize = (weight + 3) / 4;

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
                        input.witness.iter().map(|w| hex::encode(w)).collect();
                    v["txinwitness"] = json!(witness);
                }
                v
            }
        })
        .collect();

    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, output)| {
            let value_btc = output.value.to_sat() as f64 / 100_000_000.0;
            json!({
                "value": value_btc,
                "n": n,
                "scriptPubKey": {
                    "asm": format!("{}", output.script_pubkey),
                    "hex": hex::encode(output.script_pubkey.as_bytes()),
                    "type": script_type(&output.script_pubkey),
                },
            })
        })
        .collect();

    let mut result = json!({
        "txid": txid.to_string(),
        "hash": txid.to_string(),
        "version": tx.version.0,
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
    });

    if let Some(bh) = blockhash {
        result["blockhash"] = Value::String(bh.to_string());
    }
    if let Some(h) = block_height {
        result["blockheight"] = json!(h);
    }

    result
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
