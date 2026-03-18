use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};

use crate::chain::state::ChainState;

fn psbt_to_base64(psbt: &Psbt) -> String {
    let mut buf = Vec::new();
    psbt.serialize_to_writer(&mut buf).expect("PSBT serialization");
    B64.encode(&buf)
}

fn psbt_from_base64(b64: &str) -> Result<Psbt, (i32, String)> {
    let raw = B64.decode(b64).map_err(|_| (-22, "PSBT base64 decode failed".to_string()))?;
    Psbt::deserialize(&raw).map_err(|_| (-22, "PSBT decode failed".to_string()))
}

/// `createpsbt` — create a PSBT from inputs and outputs.
pub fn create_psbt(
    inputs: &[Value],
    outputs: &Value,
    locktime: Option<u32>,
) -> Result<Value, (i32, String)> {
    // Build the unsigned transaction (same logic as createrawtransaction)
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
            .unwrap_or(0xffff_fffd) as u32;

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

    let lt = locktime
        .map(bitcoin::blockdata::locktime::absolute::LockTime::from_consensus)
        .unwrap_or(bitcoin::blockdata::locktime::absolute::LockTime::ZERO);

    let tx = Transaction {
        version: Version(2),
        lock_time: lt,
        input: tx_inputs,
        output: tx_outputs,
    };

    let psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| (-22, format!("PSBT creation failed: {}", e)))?;
    Ok(Value::String(psbt_to_base64(&psbt)))
}

/// `decodepsbt` — decode a base64-encoded PSBT to JSON.
pub fn decode_psbt(psbt_b64: &str) -> Result<Value, (i32, String)> {
    let psbt = psbt_from_base64(psbt_b64)?;

    let tx = &psbt.unsigned_tx;
    let tx_hex = hex::encode(bitcoin::consensus::serialize(tx));

    let inputs: Vec<Value> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut v = json!({});
            if let Some(ref utxo) = input.witness_utxo {
                v["witness_utxo"] = json!({
                    "amount": utxo.value.to_sat() as f64 / 100_000_000.0,
                    "scriptPubKey": {
                        "hex": hex::encode(utxo.script_pubkey.as_bytes()),
                    },
                });
            }
            if !input.partial_sigs.is_empty() {
                let sigs: Vec<Value> = input
                    .partial_sigs
                    .iter()
                    .map(|(pk, sig)| {
                        json!({
                            "pubkey": pk.to_string(),
                            "signature": hex::encode(sig.serialize()),
                        })
                    })
                    .collect();
                v["partial_signatures"] = json!(sigs);
            }
            if let Some(ref script) = input.redeem_script {
                v["redeem_script"] = json!({"hex": hex::encode(script.as_bytes())});
            }
            if let Some(ref script) = input.witness_script {
                v["witness_script"] = json!({"hex": hex::encode(script.as_bytes())});
            }
            if let Some(ref final_sig) = input.final_script_sig {
                v["final_scriptSig"] = json!({"hex": hex::encode(final_sig.as_bytes())});
            }
            if let Some(ref final_witness) = input.final_script_witness {
                let items: Vec<String> = final_witness.iter().map(hex::encode).collect();
                v["final_scriptwitness"] = json!(items);
            }
            v["has_utxo"] = json!(input.witness_utxo.is_some() || input.non_witness_utxo.is_some());
            v["is_final"] = json!(input.final_script_sig.is_some() || input.final_script_witness.is_some());
            let _ = i; // suppress unused
            v
        })
        .collect();

    let outputs: Vec<Value> = psbt
        .outputs
        .iter()
        .map(|output| {
            let mut v = json!({});
            if let Some(ref script) = output.redeem_script {
                v["redeem_script"] = json!({"hex": hex::encode(script.as_bytes())});
            }
            if let Some(ref script) = output.witness_script {
                v["witness_script"] = json!({"hex": hex::encode(script.as_bytes())});
            }
            v
        })
        .collect();

    Ok(json!({
        "tx": {
            "txid": tx.compute_txid().to_string(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": tx.input.len(),
            "vout": tx.output.len(),
        },
        "tx_hex": tx_hex,
        "inputs": inputs,
        "outputs": outputs,
        "fee": Value::Null,
    }))
}

/// `analyzepsbt` — analyze PSBT completeness.
pub fn analyze_psbt(psbt_b64: &str) -> Result<Value, (i32, String)> {
    let psbt = psbt_from_base64(psbt_b64)?;

    let inputs: Vec<Value> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let has_utxo = input.witness_utxo.is_some() || input.non_witness_utxo.is_some();
            let is_final =
                input.final_script_sig.is_some() || input.final_script_witness.is_some();
            let has_sigs = !input.partial_sigs.is_empty();

            let next = if is_final {
                "finalized"
            } else if has_sigs || has_utxo {
                "signer"
            } else {
                "updater"
            };

            json!({
                "has_utxo": has_utxo,
                "is_final": is_final,
                "next": next,
                "input_index": i,
            })
        })
        .collect();

    let all_final = psbt.inputs.iter().all(|i| {
        i.final_script_sig.is_some() || i.final_script_witness.is_some()
    });

    let next = if all_final {
        "extractor"
    } else if psbt.inputs.iter().any(|i| !i.partial_sigs.is_empty()) {
        "finalizer"
    } else if psbt.inputs.iter().all(|i| i.witness_utxo.is_some() || i.non_witness_utxo.is_some()) {
        "signer"
    } else {
        "updater"
    };

    Ok(json!({
        "inputs": inputs,
        "estimated_vsize": psbt.unsigned_tx.weight().to_wu() / 4,
        "estimated_feerate": Value::Null,
        "fee": Value::Null,
        "next": next,
    }))
}

/// `combinepsbt` — merge multiple PSBTs.
pub fn combine_psbt(psbt_b64s: &[String]) -> Result<Value, (i32, String)> {
    if psbt_b64s.is_empty() {
        return Err((-8, "Missing PSBTs".to_string()));
    }

    let mut combined = psbt_from_base64(&psbt_b64s[0])?;

    for b64 in &psbt_b64s[1..] {
        let other = psbt_from_base64(b64)?;
        combined
            .combine(other)
            .map_err(|e| (-22, format!("PSBT combine failed: {}", e)))?;
    }

    Ok(Value::String(psbt_to_base64(&combined)))
}

/// `finalizepsbt` — finalize a fully-signed PSBT into a network transaction.
pub fn finalize_psbt(psbt_b64: &str, extract: bool) -> Result<Value, (i32, String)> {
    let psbt = psbt_from_base64(psbt_b64)?;

    // Check if all inputs are finalized
    let complete = psbt.inputs.iter().all(|i| {
        i.final_script_sig.is_some() || i.final_script_witness.is_some()
    });

    if extract && complete {
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
        Ok(json!({
            "hex": tx_hex,
            "complete": true,
        }))
    } else {
        Ok(json!({
            "psbt": psbt_to_base64(&psbt),
            "complete": complete,
        }))
    }
}

/// `converttopsbt` — convert a raw transaction to PSBT format.
pub fn convert_to_psbt(hex_tx: &str) -> Result<Value, (i32, String)> {
    let tx_bytes = hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let mut tx: Transaction =
        bitcoin::consensus::deserialize(&tx_bytes).map_err(|_| (-22, "TX decode failed".to_string()))?;

    // Clear scriptSigs and witnesses for the PSBT unsigned tx
    for input in &mut tx.input {
        input.script_sig = bitcoin::ScriptBuf::new();
        input.witness = Witness::new();
    }

    let psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| (-22, format!("PSBT creation failed: {}", e)))?;
    Ok(Value::String(psbt_to_base64(&psbt)))
}

/// `joinpsbts` — combine PSBTs with different inputs (for CoinJoin).
pub fn join_psbts(psbt_b64s: &[String]) -> Result<Value, (i32, String)> {
    if psbt_b64s.is_empty() {
        return Err((-8, "Missing PSBTs".to_string()));
    }

    // Merge all inputs and outputs into a single PSBT
    let mut merged = psbt_from_base64(&psbt_b64s[0])?;

    for b64 in &psbt_b64s[1..] {
        let other = psbt_from_base64(b64)?;

        merged.unsigned_tx.input.extend(other.unsigned_tx.input);
        merged.unsigned_tx.output.extend(other.unsigned_tx.output);
        merged.inputs.extend(other.inputs);
        merged.outputs.extend(other.outputs);
    }

    Ok(Value::String(psbt_to_base64(&merged)))
}

/// `utxoupdatepsbt` — update PSBT with UTXO data from the node's chain state.
pub fn utxo_update_psbt(
    chain_state: &ChainState,
    psbt_b64: &str,
) -> Result<Value, (i32, String)> {
    let mut psbt = psbt_from_base64(psbt_b64)?;

    // For each input without UTXO info, look up the coin from chain state
    // We need to collect the outpoints first since we can't borrow psbt mutably
    // and immutably at the same time.
    let outpoints: Vec<_> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect();

    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        if input.witness_utxo.is_none() && input.non_witness_utxo.is_none()
            && let Some(coin) = chain_state.get_coin(&outpoints[i]) {
                input.witness_utxo = Some(TxOut {
                    value: Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });
            }
    }

    Ok(Value::String(psbt_to_base64(&psbt)))
}
