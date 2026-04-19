use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::Secp256k1;
use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::rpc::amounts::{annotate_units, default_unit, format_amount, format_feerate_sat_per_kvb};
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
        "unbroadcastcount": 0,
        "fullrbf": info.full_rbf,
    });
    annotate_units(&mut response, unit);
    response
}

/// `getrawmempool` — list mempool transaction ids.
pub fn get_raw_mempool(mempool: &Mempool, verbose: bool) -> Value {
    let entries = mempool.get_all_entries();

    if !verbose {
        let txids: Vec<String> = entries.iter().map(|(txid, _)| txid.to_string()).collect();
        return json!(txids);
    }

    let mut result = serde_json::Map::new();
    let unit = default_unit();
    for (txid, entry) in &entries {
        let vsize = if entry.weight > 0 {
            entry.weight.div_ceil(4)
        } else {
            0
        };
        let fee = format_amount(entry.fee, unit);

        result.insert(
            txid.to_string(),
            json!({
                "vsize": vsize,
                "weight": entry.weight,
                "time": entry.time,
                "fees": {
                    "base": fee,
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
    if blockhash.is_none()
        && let Some(entry) = mempool.get(&txid) {
            return if verbose {
                Ok(decode_transaction_verbose(&entry.tx, None, None))
            } else {
                let raw = bitcoin::consensus::serialize(&entry.tx);
                Ok(Value::String(hex::encode(raw)))
            };
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

    // Fallback to txindex if available
    if blockhash.is_none()
        && let Some(block_hash) = chain_state.get_tx_location(&txid)
            && let Some(block) = chain_state.get_block(&block_hash) {
                let entry = chain_state.get_block_index(&block_hash);
                for tx in &block.txdata {
                    if tx.compute_txid() == txid {
                        return if verbose {
                            let height = entry.as_ref().map(|e| e.height);
                            Ok(decode_transaction_verbose(
                                tx,
                                Some(&block_hash.to_string()),
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
    let vsize = weight.div_ceil(4);

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
                v
            }
        })
        .collect();

    let unit = default_unit();
    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, output)| {
            let value = format_amount(output.value.to_sat(), unit);
            json!({
                "value": value,
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

/// `createrawtransaction` — build an unsigned raw transaction from inputs and outputs.
pub fn create_raw_transaction(
    inputs: &[Value],
    outputs: &Value,
    locktime: Option<u32>,
) -> Result<Value, (i32, String)> {
    let mut tx_inputs = Vec::new();
    for input in inputs {
        let txid: bitcoin::Txid = input["txid"]
            .as_str()
            .ok_or((-8, "Missing txid".to_string()))?
            .parse()
            .map_err(|_| (-8, "Invalid txid".to_string()))?;
        let vout = input["vout"]
            .as_u64()
            .ok_or((-8, "Missing vout".to_string()))? as u32;
        let sequence = input["sequence"]
            .as_u64()
            .unwrap_or(0xffff_fffd) as u32; // default: RBF-signaling

        tx_inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        });
    }

    let mut tx_outputs = Vec::new();
    if let Some(obj) = outputs.as_object() {
        for (addr_or_key, val) in obj {
            if addr_or_key == "data" {
                // OP_RETURN output
                let hex_data = val.as_str().ok_or((-8, "data must be hex string".to_string()))?;
                let data = hex::decode(hex_data).map_err(|_| (-8, "Invalid hex data".to_string()))?;
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
                let amount_btc = val
                    .as_f64()
                    .ok_or((-8, "Invalid amount".to_string()))?;
                let amount_sat = (amount_btc * 100_000_000.0) as u64;
                let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = addr_or_key
                    .parse()
                    .map_err(|_| (-8, format!("Invalid address: {}", addr_or_key)))?;
                tx_outputs.push(TxOut {
                    value: Amount::from_sat(amount_sat),
                    script_pubkey: address.assume_checked().script_pubkey(),
                });
            }
        }
    } else if let Some(arr) = outputs.as_array() {
        // Bitcoin Core also accepts array of {addr: amount} objects
        for obj in arr {
            if let Some(map) = obj.as_object() {
                for (addr_or_key, val) in map {
                    if addr_or_key == "data" {
                        let hex_data = val.as_str().ok_or((-8, "data must be hex".to_string()))?;
                        let data = hex::decode(hex_data).map_err(|_| (-8, "Invalid hex".to_string()))?;
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
                        let amount_btc = val.as_f64().ok_or((-8, "Invalid amount".to_string()))?;
                        let amount_sat = (amount_btc * 100_000_000.0) as u64;
                        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = addr_or_key
                            .parse()
                            .map_err(|_| (-8, format!("Invalid address: {}", addr_or_key)))?;
                        tx_outputs.push(TxOut {
                            value: Amount::from_sat(amount_sat),
                            script_pubkey: address.assume_checked().script_pubkey(),
                        });
                    }
                }
            }
        }
    }

    let lt = locktime
        .map(bitcoin::blockdata::locktime::absolute::LockTime::from_consensus)
        .unwrap_or(bitcoin::blockdata::locktime::absolute::LockTime::ZERO);

    let tx = Transaction {
        version: Version(2),
        lock_time: lt,
        input: tx_inputs,
        output: tx_outputs,
    };

    let raw = bitcoin::consensus::serialize(&tx);
    Ok(Value::String(hex::encode(raw)))
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

    // Build the list of all prevouts for SighashCache (needed for taproot)
    let all_prevouts: Vec<TxOut> = prevouts
        .iter()
        .map(|p| {
            p.clone().unwrap_or(TxOut {
                value: Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::new(),
            })
        })
        .collect();

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
            // P2TR key-path: taproot signing
            let mut cache = bitcoin::sighash::SighashCache::new(&tx);
            let mut signed = false;
            for (xonly_pub, secret) in &xonly_key_map {
                let expected = bitcoin::ScriptBuf::new_p2tr(&secp, *xonly_pub, None);
                if expected.as_bytes() == script.as_bytes() {
                    let sighash = cache
                        .taproot_key_spend_signature_hash(
                            i,
                            &bitcoin::sighash::Prevouts::All(&all_prevouts),
                            bitcoin::sighash::TapSighashType::Default,
                        )
                        .map_err(|e| (-1, format!("Taproot sighash error: {}", e)))?;
                    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
                    // Taproot key-path requires key tweaking
                    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, secret);
                    let tweaked = keypair.tap_tweak(&secp, None);
                    let sig = secp.sign_schnorr(&msg, &tweaked.to_keypair());
                    let tap_sig = bitcoin::taproot::Signature {
                        signature: sig,
                        sighash_type: bitcoin::sighash::TapSighashType::Default,
                    };
                    let mut witness = Witness::new();
                    witness.push(tap_sig.serialize());
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
        let result = decode_raw_transaction(&hex_tx).unwrap();

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
}
