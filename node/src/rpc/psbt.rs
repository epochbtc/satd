use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};

use crate::chain::state::ChainState;
use crate::rpc::amounts::{default_unit, format_amount};

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
///
/// Outputs go through `rawtx::parse_outputs`, the port of Core's
/// `ParseOutputs`. Core reaches it from `createpsbt` and `createrawtransaction`
/// alike (both call `ConstructTransaction`), so sharing it here is what keeps
/// the two agreeing — on the network-scoped address decode above all, but also
/// on duplicate detection, the array form of `outputs`, and string amounts.
pub fn create_psbt(
    inputs: &[Value],
    outputs: &Value,
    locktime: Option<u32>,
    network: bitcoin::Network,
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

    let tx_outputs = crate::rpc::rawtx::parse_outputs(outputs, network)?;

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
                    "amount": format_amount(utxo.value.to_sat(), default_unit()),
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
        // Core emits `fee` once every input's UTXO is present, and omits it
        // otherwise. This was an unconditional `null`, so a fully-populated
        // PSBT still reported no fee — the number a signer most wants before
        // committing.
        "fee": match psbt_fee(&psbt) {
            Some(fee) => json!(fee.to_sat() as f64 / 100_000_000.0),
            None => Value::Null,
        },
    }))
}

/// Total input value, when every input's UTXO is known.
///
/// Core computes the fee only when it has all of them (`PSBTInputAnalysis`:
/// `if (!input.have_utxo) { ... calc_fee = false; }`), and omits the field
/// otherwise rather than reporting a partial figure — a fee derived from a
/// subset of the inputs is not a smaller truth, it is a wrong number on the
/// one field a signer checks before committing funds.
fn total_input_value(psbt: &Psbt) -> Option<Amount> {
    let mut total = Amount::ZERO;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let prevout = psbt.unsigned_tx.input.get(i)?.previous_output;
        // Core's `PartiallySignedTransaction::GetInputUTXO` (`src/psbt.cpp`),
        // which is what `AnalyzePSBT` reads the amounts through:
        //
        //     if (input.non_witness_utxo) {
        //         if (prevout_index >= input.non_witness_utxo->vout.size()) return false;
        //         if (input.non_witness_utxo->GetHash() != tx->vin[i].prevout.hash) return false;
        //         utxo = input.non_witness_utxo->vout[prevout_index];
        //     } else if (!input.witness_utxo.IsNull()) {
        //         utxo = input.witness_utxo;
        //     } else { return false; }
        //
        // Two things this had backwards. The `non_witness_utxo` wins where one
        // is present, not the `witness_utxo`; and it is only usable once its
        // txid has been checked against the input's own `previous_output`.
        //
        // Without that check the value is whatever the PSBT's author wrote.
        // A PSBT handed to a user for inspection could carry a
        // `non_witness_utxo` that is not the transaction being spent -- or a
        // `witness_utxo` disagreeing with a correct `non_witness_utxo` -- and
        // `decodepsbt.fee` / `analyzepsbt.fee` would report a plausible, small
        // number derived from it. Core omits the field entirely in that case,
        // which is the signal to go and look. Both RPCs are `Read`, so this is
        // reachable on the read-only listener.
        let value = match (&input.non_witness_utxo, &input.witness_utxo) {
            (Some(tx), _) => {
                if tx.compute_txid() != prevout.txid {
                    return None;
                }
                tx.output.get(prevout.vout as usize)?.value
            }
            (None, Some(txout)) => txout.value,
            (None, None) => return None,
        };
        total = total.checked_add(value)?;
    }
    Some(total)
}

/// The fee this PSBT pays, when it can be known: inputs minus outputs.
fn psbt_fee(psbt: &Psbt) -> Option<Amount> {
    let inputs = total_input_value(psbt)?;
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))?;
    inputs.checked_sub(outputs)
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

    let estimated_vsize = psbt.unsigned_tx.weight().to_wu() / 4;
    let fee = psbt_fee(&psbt);
    Ok(json!({
        "inputs": inputs,
        "estimated_vsize": estimated_vsize,
        // `estimated_feerate` stays null, deliberately.
        //
        // Core derives it from a *dummy-signed* transaction: `AnalyzePSBT`
        // (`src/node/psbt.cpp`) signs every input with
        // `DUMMY_SIGNING_PROVIDER`, measures `GetVirtualTransactionSize` of
        // the result, and only then computes `CFeeRate(fee, size)`. If the
        // dummy signing fails for any input it emits neither
        // `estimated_vsize` nor `estimated_feerate`.
        //
        // satd has no dummy signing provider, so the only size available here
        // is the *unsigned* one -- which is what `estimated_vsize` above has
        // always reported, and it is smaller than the signed transaction by
        // the whole witness. Dividing the fee by it produces a feerate that is
        // systematically too high: a 1-in/2-out P2WPKH spend serialises to 114
        // bytes unsigned against ~141 vB signed, so the reported rate would
        // overstate by ~24%, and by more as inputs are added. A signer sizing
        // a fee off that number underpays.
        //
        // A wrong feerate on the one field a signer checks before committing
        // funds is worse than an absent one, which is exactly the principle
        // the rest of this change applies. Recorded in CORE_DIFFERENCES.md
        // along with `estimated_vsize`'s own inaccuracy.
        "estimated_feerate": Value::Null,
        "fee": match fee {
            Some(fee) => json!(fee.to_sat() as f64 / 100_000_000.0),
            None => Value::Null,
        },
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
    let mut psbt = psbt_from_base64(psbt_b64)?;

    // Attempt to finalize each input from partial_sigs / tap_key_sig
    for input in &mut psbt.inputs {
        try_finalize_input(input);
    }

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

/// Attempt to finalize a PSBT input by constructing final_script_sig or
/// final_script_witness from partial signatures and UTXO information.
fn try_finalize_input(input: &mut bitcoin::psbt::Input) {
    // Already finalized
    if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
        return;
    }

    // Determine the scriptPubKey from witness_utxo or non_witness_utxo
    let script = if let Some(ref utxo) = input.witness_utxo {
        utxo.script_pubkey.clone()
    } else {
        return; // Can't finalize without UTXO info
    };

    let mut finalized = false;

    if script.is_p2pkh() {
        if input.partial_sigs.len() == 1 {
            let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
            input.final_script_sig = Some(
                bitcoin::script::Builder::new()
                    .push_slice(sig.serialize())
                    .push_key(pubkey)
                    .into_script(),
            );
            finalized = true;
        }
    } else if script.is_p2wpkh() {
        if input.partial_sigs.len() == 1 {
            let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
            let mut witness = Witness::new();
            witness.push(sig.serialize());
            witness.push(pubkey.to_bytes());
            input.final_script_witness = Some(witness);
            finalized = true;
        }
    } else if script.is_p2sh()
        && let Some(ref redeem_script) = input.redeem_script
        && redeem_script.is_p2wpkh()
        && input.partial_sigs.len() == 1
    {
        let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
        let redeem_bytes = bitcoin::script::PushBytesBuf::try_from(redeem_script.to_bytes());
        if let Ok(push_bytes) = redeem_bytes {
            input.final_script_sig = Some(
                bitcoin::script::Builder::new()
                    .push_slice(&push_bytes)
                    .into_script(),
            );
            let mut witness = Witness::new();
            witness.push(sig.serialize());
            witness.push(pubkey.to_bytes());
            input.final_script_witness = Some(witness);
            finalized = true;
        }
    } else if script.is_p2tr()
        && let Some(ref sig) = input.tap_key_sig
    {
        let mut witness = Witness::new();
        witness.push(sig.serialize());
        input.final_script_witness = Some(witness);
        finalized = true;
    }

    // Clear interim PSBT fields after successful finalization (BIP 174)
    if finalized {
        input.partial_sigs.clear();
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation.clear();
        input.tap_key_sig = None;
        input.tap_script_sigs.clear();
        input.tap_key_origins.clear();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
    }
}

/// `converttopsbt` — convert a raw transaction to PSBT format.
///
/// `permit_sigdata` is Core's `permitsigdata`, and it defaults to **false**:
/// a transaction carrying signatures is refused rather than silently
/// stripped, because the conversion is lossy and the caller may not have
/// meant to discard them (`rawtransaction.cpp`, `Inputs must not have
/// scriptSigs and scriptWitnesses`).
pub fn convert_to_psbt(hex_tx: &str, permit_sigdata: bool) -> Result<Value, (i32, String)> {
    let tx_bytes = hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
    let mut tx: Transaction =
        bitcoin::consensus::deserialize(&tx_bytes).map_err(|_| (-22, "TX decode failed".to_string()))?;

    // Clear scriptSigs and witnesses for the PSBT unsigned tx
    for input in &mut tx.input {
        if !permit_sigdata && (!input.script_sig.is_empty() || !input.witness.is_empty()) {
            return Err((
                -22,
                "Inputs must not have scriptSigs and scriptWitnesses".to_string(),
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Core reads a PSBT input's amount through `GetInputUTXO`, which prefers
    /// the `non_witness_utxo` and only after checking its txid against the
    /// input's own `previous_output`. Reading the `witness_utxo` first, and
    /// never checking the txid, meant a PSBT's author chose the fee that
    /// `decodepsbt`/`analyzepsbt` reported -- on a `Read` surface.
    #[test]
    fn psbt_input_values_follow_cores_get_input_utxo() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let funding_txid = funding.compute_txid();

        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: funding_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let analyze = |psbt: &Psbt| {
            analyze_psbt(&psbt_to_base64(psbt)).expect("analyzes")
        };

        // The honest PSBT: a matching non_witness_utxo, fee 0.01 BTC.
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(unsigned.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(funding.clone());
        let out = analyze(&psbt);
        assert_eq!(out["fee"], json!(0.01), "{out}");

        // A `witness_utxo` disagreeing with a correct `non_witness_utxo` must
        // not be the one read: Core takes the non_witness_utxo.
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(unsigned.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(funding.clone());
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(500_000_000),
            script_pubkey: ScriptBuf::new(),
        });
        let out = analyze(&psbt);
        assert_eq!(out["fee"], json!(0.01), "the non_witness_utxo wins: {out}");

        // A non_witness_utxo that is not the transaction being spent: Core
        // returns false from GetInputUTXO and omits the fee entirely.
        let other = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(1),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        assert_ne!(other.compute_txid(), funding_txid);
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(unsigned.clone()).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(other);
        let out = analyze(&psbt);
        assert!(out["fee"].is_null(), "a mismatched txid has no usable value: {out}");

        // And `estimated_feerate` is never reported: satd cannot dummy-sign,
        // so the only size it has is the unsigned one, and a feerate divided
        // by that overstates by the whole witness.
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(funding);
        let out = analyze(&psbt);
        assert!(out["estimated_feerate"].is_null(), "{out}");
    }
}
