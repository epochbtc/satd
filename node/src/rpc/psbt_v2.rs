//! The version 2 half of the PSBT RPCs.
//!
//! `psbt.rs` sniffs the version and routes here when it is 2. Nothing in this
//! file touches the version 0 path, and nothing in the version 0 path knows
//! this file exists: that separation is what keeps `decodepsbt` on an
//! ordinary PSBT byte-identical to what it answered before.
//!
//! The governing rule throughout is that a field satd does not understand
//! must come out exactly as it went in. A PSBT is a document several parties
//! edit in turn, and a node that quietly drops an unfamiliar field breaks the
//! next party's work in a way nobody notices until the money has moved.

use bitcoin::{Amount, OutPoint, TxOut};
use satd_psbt::raw::{PsbtVersion, RawMap, RawPair, RawPsbt};
use satd_psbt::sp::{self, OutputStatus, PrevoutSource, SpReport};
use satd_psbt::{PsbtError, V2View, keys};
use serde_json::{Value, json};

use crate::chain::state::ChainState;
use crate::rpc::amounts::{default_unit, format_amount};

type RpcError = (i32, String);

fn bad(err: PsbtError) -> RpcError {
    (-22, err.to_string())
}

fn refuse(msg: impl Into<String>) -> RpcError {
    (-22, msg.into())
}

/// Whether an output's script has been computed.
///
/// BIP 375 lets a silent payment output carry no `PSBT_OUT_SCRIPT` at all
/// while the Signer is still working. An empty one means the same thing, and
/// the reference validator treats it the same way.
fn script_is_computed(map: &RawMap) -> bool {
    map.get_single(keys::output::SCRIPT)
        .is_some_and(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// decodepsbt
// ---------------------------------------------------------------------------

/// `decodepsbt` for a version 2 PSBT.
///
/// Field names follow Bitcoin Core's PSBTv2 pull request (#21283) wherever it
/// has one, so that a client written against Core's eventual v2 support reads
/// satd without a special case. Deviations are listed in
/// `CORE_DIFFERENCES.md`.
///
/// BIP 375 fields are rendered from the raw map rather than through the typed
/// accessors, so that a malformed share or proof is *shown* to the operator
/// rather than turning the whole call into a parse error. Diagnosing a PSBT
/// is what this method is for.
pub fn decode(raw: &RawPsbt, network: Option<bitcoin::Network>) -> Result<Value, RpcError> {
    let view = V2View::new(raw).map_err(bad)?;
    let unit = default_unit();

    let mut out = json!({
        "psbt_version": 2,
        "tx_version": view.tx_version().map_err(bad)?,
        "input_count": view.input_count(),
        "output_count": view.output_count(),
        "inputs_modifiable": view.inputs_modifiable().map_err(bad)?,
        "outputs_modifiable": view.outputs_modifiable().map_err(bad)?,
        "has_sighash_single": view.has_sighash_single().map_err(bad)?,
    });
    out["fallback_locktime"] = match view.fallback_locktime().map_err(bad)? {
        Some(lt) => json!(lt),
        None => Value::Null,
    };
    out["locktime"] = match view.lock_time() {
        Ok(lt) => json!(lt.to_consensus_u32()),
        // BIP 370 allows a PSBT whose inputs cannot agree on a lock-time
        // type. It has no transaction until that is resolved, and saying so
        // is more useful than refusing to decode it.
        Err(_) => Value::Null,
    };

    if let Some(sp) = global_silent_payments(&raw.global) {
        out["silent_payments"] = sp;
    }
    out["unknown"] = unknown_json(&raw.global, &known_global_types());

    let mut inputs = Vec::with_capacity(raw.inputs.len());
    for input in view.inputs() {
        let map = input.map();
        let mut v = json!({});
        if let Ok(txid) = input.previous_txid() {
            v["previous_txid"] = json!(txid.to_string());
        }
        if let Ok(vout) = input.output_index() {
            v["previous_vout"] = json!(vout);
        }
        if let Ok(seq) = input.sequence() {
            v["sequence"] = json!(seq.0);
        }
        if let Ok(Some(lt)) = input.time_locktime() {
            v["required_time_locktime"] = json!(lt);
        }
        if let Ok(Some(lt)) = input.height_locktime() {
            v["required_height_locktime"] = json!(lt);
        }

        // The same fields, under the same names, as the version 0 decoder.
        if let Ok(Some(utxo)) = input.witness_utxo() {
            v["witness_utxo"] = json!({
                "amount": format_amount(utxo.value.to_sat(), unit),
                "scriptPubKey": { "hex": hex::encode(utxo.script_pubkey.as_bytes()) },
            });
        }
        let sigs: Vec<Value> = input
            .partial_sigs()
            .map(|(pk, sig)| json!({ "pubkey": hex::encode(pk), "signature": hex::encode(sig) }))
            .collect();
        if !sigs.is_empty() {
            v["partial_signatures"] = json!(sigs);
        }
        if let Some(script) = map.get_single(keys::input::REDEEM_SCRIPT) {
            v["redeem_script"] = json!({ "hex": hex::encode(script) });
        }
        if let Some(script) = map.get_single(keys::input::WITNESS_SCRIPT) {
            v["witness_script"] = json!({ "hex": hex::encode(script) });
        }
        if let Some(sig) = map.get_single(keys::input::FINAL_SCRIPTSIG) {
            v["final_scriptSig"] = json!({ "hex": hex::encode(sig) });
        }
        if let Some(wit) = map.get_single(keys::input::FINAL_SCRIPTWITNESS) {
            v["final_scriptwitness"] = match bitcoin::consensus::deserialize::<bitcoin::Witness>(wit)
            {
                Ok(w) => json!(w.iter().map(hex::encode).collect::<Vec<_>>()),
                Err(_) => json!(hex::encode(wit)),
            };
        }
        if let Ok(Some(sighash)) = input.sighash_type() {
            v["sighash"] = json!(sighash);
        }
        v["has_utxo"] = json!(
            map.contains_type(keys::input::WITNESS_UTXO)
                || map.contains_type(keys::input::NON_WITNESS_UTXO)
        );
        v["is_final"] = json!(
            map.contains_type(keys::input::FINAL_SCRIPTSIG)
                || map.contains_type(keys::input::FINAL_SCRIPTWITNESS)
        );
        if let Some(shares) = shares_json(map, keys::input::SP_ECDH_SHARE, keys::input::SP_DLEQ) {
            v["sp_shares"] = shares;
        }
        v["unknown"] = unknown_json(map, &known_input_types());
        inputs.push(v);
    }
    out["inputs"] = json!(inputs);

    let mut outputs = Vec::with_capacity(raw.outputs.len());
    for output in view.outputs() {
        let map = output.map();
        let mut v = json!({});
        if let Ok(amount) = output.amount() {
            v["amount"] = format_amount(amount.to_sat(), unit);
        }
        // Absent means "not computed yet", which is a state only a silent
        // payment output can be in. Emitting an empty script here instead
        // would read as an output paying nobody.
        if let Some(script) = map.get_single(keys::output::SCRIPT) {
            v["script"] = json!({ "hex": hex::encode(script) });
        }
        if let Some(script) = map.get_single(keys::output::REDEEM_SCRIPT) {
            v["redeem_script"] = json!({ "hex": hex::encode(script) });
        }
        if let Some(script) = map.get_single(keys::output::WITNESS_SCRIPT) {
            v["witness_script"] = json!({ "hex": hex::encode(script) });
        }
        if let Some(info) = map.get_single(keys::output::SP_V0_INFO) {
            let mut sp = json!({});
            if info.len() == 66 {
                sp["scan_key"] = json!(hex::encode(&info[..33]));
                sp["spend_key"] = json!(hex::encode(&info[33..]));
                // The `sp1…` string the recipient handed the sender. It is
                // not in the PSBT — only the two keys are — so an operator
                // reading a PSBT has no other way to check that the recipient
                // written down is the one they meant.
                if let Some(network) = network
                    && let (Ok(scan), Ok(spend)) = (
                        bitcoin::secp256k1::PublicKey::from_slice(&info[..33]),
                        bitcoin::secp256k1::PublicKey::from_slice(&info[33..]),
                    )
                {
                    sp["address"] =
                        json!(satd_psbt::SpAddress::new(scan, spend).encode(network));
                }
            } else {
                // Shown, not swallowed: an operator staring at a rejected
                // PSBT needs to see which field is the wrong length.
                sp["raw"] = json!(hex::encode(info));
            }
            if let Some(label) = map.get_single(keys::output::SP_V0_LABEL) {
                sp["label"] = match label.len() {
                    4 => json!(u32::from_le_bytes([label[0], label[1], label[2], label[3]])),
                    _ => json!(hex::encode(label)),
                };
            }
            v["silent_payment"] = sp;
        }
        v["unknown"] = unknown_json(map, &known_output_types());
        outputs.push(v);
    }
    out["outputs"] = json!(outputs);

    // A transaction exists only once every output has a script. While a
    // silent payment output is still being computed there is nothing to
    // serialise, and inventing something would be worse than saying so.
    if let Ok(tx) = view.unsigned_tx() {
        out["tx"] = json!({
            "txid": tx.compute_txid().to_string(),
            "version": tx.version.0,
            "locktime": tx.lock_time.to_consensus_u32(),
            "vin": tx.input.len(),
            "vout": tx.output.len(),
        });
        out["tx_hex"] = json!(hex::encode(bitcoin::consensus::serialize(&tx)));
    }
    if let Ok(id) = view.unique_id() {
        out["unique_id"] = json!(id.to_string());
    }

    out["fee"] = match fee(&view) {
        Some(fee) => json!(fee.to_sat() as f64 / 100_000_000.0),
        None => Value::Null,
    };
    Ok(out)
}

/// The global ECDH shares and their proofs, if any are present.
fn global_silent_payments(global: &RawMap) -> Option<Value> {
    let shares = shares_json(global, keys::global::SP_ECDH_SHARE, keys::global::SP_DLEQ)?;
    Some(json!({ "global_shares": shares }))
}

/// Shares paired with the proofs under the same scan key. A share whose proof
/// is missing keeps its row with a null proof, rather than disappearing: a
/// missing proof is the thing the reader most needs to see.
fn shares_json(map: &RawMap, share_type: u64, proof_type: u64) -> Option<Value> {
    let mut rows = Vec::new();
    for (scan_key, share) in map.get_all(share_type) {
        rows.push(json!({
            "scan_key": hex::encode(scan_key),
            "ecdh_share": hex::encode(share),
            "dleq_proof": match map.get(proof_type, scan_key) {
                Some(proof) => json!(hex::encode(proof)),
                None => Value::Null,
            },
        }));
    }
    // A proof with no share is equally worth showing.
    for (scan_key, proof) in map.get_all(proof_type) {
        if map.get(share_type, scan_key).is_none() {
            rows.push(json!({
                "scan_key": hex::encode(scan_key),
                "ecdh_share": Value::Null,
                "dleq_proof": hex::encode(proof),
            }));
        }
    }
    if rows.is_empty() {
        None
    } else {
        Some(json!(rows))
    }
}

fn unknown_json(map: &RawMap, known: &[u64]) -> Value {
    let mut obj = serde_json::Map::new();
    for pair in map.pairs() {
        if known.contains(&pair.key_type) {
            continue;
        }
        let mut key = Vec::new();
        satd_psbt::raw::write_compact_size(&mut key, pair.key_type);
        key.extend_from_slice(&pair.key_data);
        obj.insert(hex::encode(&key), json!(hex::encode(&pair.value)));
    }
    Value::Object(obj)
}

fn known_global_types() -> Vec<u64> {
    vec![
        keys::global::UNSIGNED_TX,
        keys::global::XPUB,
        keys::global::TX_VERSION,
        keys::global::FALLBACK_LOCKTIME,
        keys::global::INPUT_COUNT,
        keys::global::OUTPUT_COUNT,
        keys::global::TX_MODIFIABLE,
        keys::global::SP_ECDH_SHARE,
        keys::global::SP_DLEQ,
        keys::global::VERSION,
        keys::global::PROPRIETARY,
    ]
}

fn known_input_types() -> Vec<u64> {
    let mut v: Vec<u64> = (0x00..=0x18).collect();
    v.extend([
        keys::input::SP_ECDH_SHARE,
        keys::input::SP_DLEQ,
        keys::input::PROPRIETARY,
    ]);
    v
}

fn known_output_types() -> Vec<u64> {
    let mut v: Vec<u64> = (0x00..=0x07).collect();
    v.extend([
        keys::output::SP_V0_INFO,
        keys::output::SP_V0_LABEL,
        keys::output::PROPRIETARY,
    ]);
    v
}

/// Inputs minus outputs, when every input's previous output is known.
///
/// Same rule as the version 0 path: Core omits the fee entirely rather than
/// report one derived from a subset of the inputs, because a wrong number on
/// the field a signer checks before committing funds is worse than an absent
/// one. Unlike the version 0 path this does not need the output scripts, only
/// the amounts, so a PSBT still waiting on a silent payment script still
/// reports its fee.
pub fn fee(view: &V2View<'_>) -> Option<Amount> {
    let mut total = Amount::ZERO;
    for input in view.inputs() {
        let prevout = input.prevout().ok()??;
        total = total.checked_add(prevout.value)?;
    }
    let mut spent = Amount::ZERO;
    for output in view.outputs() {
        spent = spent.checked_add(output.amount().ok()?)?;
    }
    total.checked_sub(spent)
}

// ---------------------------------------------------------------------------
// analyzepsbt
// ---------------------------------------------------------------------------

/// `analyzepsbt` for a version 2 PSBT.
///
/// The role logic is the version 0 logic read through the typed view. The
/// silent payment verdicts land in a later change; until then the object says
/// `"verified": false` so that a client can tell "not checked" from "checked
/// and fine". The two must never look the same.
pub fn analyze(raw: &RawPsbt, chain_state: Option<&ChainState>) -> Result<Value, RpcError> {
    let network = chain_state.map(|c| c.network);
    let view = V2View::new(raw).map_err(bad)?;

    let mut inputs = Vec::with_capacity(raw.inputs.len());
    for input in view.inputs() {
        let map = input.map();
        let has_utxo = map.contains_type(keys::input::WITNESS_UTXO)
            || map.contains_type(keys::input::NON_WITNESS_UTXO);
        let is_final = map.contains_type(keys::input::FINAL_SCRIPTSIG)
            || map.contains_type(keys::input::FINAL_SCRIPTWITNESS);
        let has_sigs = map.contains_type(keys::input::PARTIAL_SIG)
            || map.contains_type(keys::input::TAP_KEY_SIG);

        let next = if is_final {
            "finalized"
        } else if has_sigs || has_utxo {
            "signer"
        } else {
            "updater"
        };
        inputs.push(json!({
            "has_utxo": has_utxo,
            "is_final": is_final,
            "next": next,
            "input_index": input.index(),
        }));
    }

    let all_final = view.inputs().all(|i| {
        i.map().contains_type(keys::input::FINAL_SCRIPTSIG)
            || i.map().contains_type(keys::input::FINAL_SCRIPTWITNESS)
    });
    let any_sigs = view.inputs().any(|i| {
        i.map().contains_type(keys::input::PARTIAL_SIG)
            || i.map().contains_type(keys::input::TAP_KEY_SIG)
    });
    let all_utxos = view.inputs().all(|i| {
        i.map().contains_type(keys::input::WITNESS_UTXO)
            || i.map().contains_type(keys::input::NON_WITNESS_UTXO)
    });

    let mut next = if all_final {
        "extractor"
    } else if any_sigs {
        "finalizer"
    } else if all_utxos {
        "signer"
    } else {
        "updater"
    };

    // A silent payment output whose script has not been computed is the
    // Signer's job, whatever the inputs look like. Nothing downstream of the
    // Signer can run while the transaction is still undetermined.
    let awaiting_script = view.outputs().any(|o| {
        o.map().contains_type(keys::output::SP_V0_INFO) && !script_is_computed(o.map())
    });
    if awaiting_script && (next == "extractor" || next == "finalizer") {
        next = "signer";
    }

    let mut out = json!({
        "inputs": inputs,
        // `estimated_feerate` stays null for the same reason as the version 0
        // path: satd has no dummy signing provider, so the only size it has
        // is the unsigned one, and a feerate divided by that overstates by
        // the whole witness.
        "estimated_feerate": Value::Null,
        "next": next,
    });
    out["estimated_vsize"] = match view.unsigned_tx() {
        Ok(tx) => json!(tx.weight().to_wu() / 4),
        Err(_) => Value::Null,
    };
    out["fee"] = match fee(&view) {
        Some(fee) => json!(fee.to_sat() as f64 / 100_000_000.0),
        None => Value::Null,
    };
    if view.has_sp_outputs() {
        // `analyzepsbt` is the method an operator reaches for when a PSBT is
        // not working, so a PSBT too malformed to check must produce a
        // reading, not a refusal. `verified: false` with a reason is that
        // reading; it can never be mistaken for `verified: true`.
        let checked = satd_psbt::validate_structure(raw)
            .map_err(|e| e.to_string())
            .and_then(|()| verify_silent_payments(&view, chain_state).map_err(|(_, msg)| msg));
        match checked {
            Ok(report) => {
                // The Signer's work is not done while any silent payment
                // output is unverified, whatever the inputs look like.
                if !report.extractable() && (next == "extractor" || next == "finalizer") {
                    out["next"] = json!("signer");
                }
                out["silent_payments"] = silent_payments_json(&report, network);
            }
            Err(reason) => {
                out["next"] = json!("updater");
                out["silent_payments"] = json!({ "verified": false, "reason": reason });
            }
        }
    }
    Ok(out)
}

/// Run BIP 375's checks, with the UTXO set behind them when a node is asking.
pub fn verify_silent_payments(
    view: &V2View<'_>,
    chain_state: Option<&ChainState>,
) -> Result<SpReport, RpcError> {
    // A `witness_utxo` is whatever the PSBT's author wrote, and for a taproot
    // input it *is* the public key the ECDH share is supposed to belong to.
    // Looking the previous output up in the UTXO set is the one check a node
    // can do that a hardware wallet cannot.
    match chain_state {
        None => sp::verify(view, None).map_err(bad),
        Some(chain_state) => {
            let lookup = |outpoint: &OutPoint| {
                chain_state.get_coin(outpoint).map(|coin| TxOut {
                    value: Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                })
            };
            sp::verify(view, Some(&lookup)).map_err(bad)
        }
    }
}

/// The `silent_payments` object: what satd checked, and what it concluded.
fn silent_payments_json(report: &SpReport, network: Option<bitcoin::Network>) -> Value {
    let inputs: Vec<Value> = report
        .inputs
        .iter()
        .map(|input| {
            let mut v = json!({
                "input_index": input.index,
                "eligible": input.eligible(),
                "prevout": match input.prevout_source {
                    PrevoutSource::NotChecked => "not_checked",
                    PrevoutSource::UtxoSet => "utxo_set",
                    PrevoutSource::Psbt => "psbt",
                    PrevoutSource::Mismatch => "mismatch",
                },
            });
            if let Some(reason) = &input.ineligible {
                v["reason"] = json!(reason.reason());
            }
            v
        })
        .collect();

    let outputs: Vec<Value> = report
        .outputs
        .iter()
        .map(|output| {
            let mut v = json!({
                "output_index": output.index,
                "scan_key": hex::encode(output.scan_key.serialize()),
                "spend_key": hex::encode(output.spend_key.serialize()),
                "k": output.k,
                "status": output.status.as_str(),
                "script": output.script_state.as_str(),
            });
            if let Some(network) = network {
                v["address"] = json!(
                    satd_psbt::SpAddress::new(output.scan_key, output.spend_key).encode(network)
                );
            }
            if let Some(label) = output.label {
                v["label"] = json!(label);
            }
            if !output.missing_inputs.is_empty() {
                v["missing_inputs"] = json!(output.missing_inputs);
            }
            if !output.invalid_inputs.is_empty() {
                v["invalid_inputs"] = json!(
                    output
                        .invalid_inputs
                        .iter()
                        .map(|(index, reason)| json!({
                            "input_index": index,
                            "reason": reason,
                        }))
                        .collect::<Vec<_>>()
                );
            }
            if let Some(script) = &output.derived_script {
                v["derived_script"] = json!(hex::encode(script.as_bytes()));
            }
            if let Some(reason) = &output.reason {
                v["reason"] = json!(reason);
            }
            v
        })
        .collect();

    json!({
        "verified": true,
        "eligible_inputs": report.eligible_inputs(),
        "inputs": inputs,
        "outputs": outputs,
    })
}

/// The extractor gate. Every silent payment output must verify *and* carry the
/// script it derives to before a transaction may leave this PSBT.
///
/// There is no override flag. `extract=false` is gated too: a finalised PSBT
/// is one `sendrawtransaction` away from the chain, and a silent payment that
/// pays the wrong script is not recoverable — the recipient scans for an
/// output that was never created.
pub fn extractor_gate(view: &V2View<'_>, chain_state: Option<&ChainState>) -> Result<(), RpcError> {
    satd_psbt::validate_structure(view.raw()).map_err(bad)?;
    let report = verify_silent_payments(view, chain_state)?;
    let Some(problem) = report.first_problem() else {
        return Ok(());
    };
    let detail = problem
        .reason
        .clone()
        .or_else(|| {
            problem
                .invalid_inputs
                .first()
                .map(|(index, reason)| format!("input {index}: {reason}"))
        })
        .or_else(|| {
            (!problem.missing_inputs.is_empty()).then(|| {
                format!(
                    "inputs {:?} owe an ECDH share for this scan key",
                    problem.missing_inputs
                )
            })
        });
    let status = if problem.status == OutputStatus::Ready {
        // Ready but with no script yet: the Signer has not finished.
        "the script has not been computed".to_string()
    } else {
        problem.status.as_str().to_string()
    };
    Err(refuse(format!(
        "silent payment output {} is not ready to extract: {status}{}",
        problem.index,
        detail.map(|d| format!(" ({d})")).unwrap_or_default()
    )))
}

// ---------------------------------------------------------------------------
// combinepsbt
// ---------------------------------------------------------------------------

/// `combinepsbt` for version 2 PSBTs.
///
/// Where Core's version 0 combiner keeps whichever value it saw first for a
/// key present in both, this refuses by name. For a signature that hardly
/// matters — two valid signatures for one input are interchangeable. For a
/// BIP 375 ECDH share it decides where the money goes, and picking one
/// arbitrarily is the wrong default for a field like that.
pub fn combine(psbts: &[RawPsbt]) -> Result<RawPsbt, RpcError> {
    let first = psbts.first().ok_or((-8, "Missing PSBTs".to_string()))?;
    let id = V2View::new(first).map_err(bad)?.unique_id().map_err(bad)?;

    let mut out = first.clone();
    for (n, other) in psbts.iter().enumerate().skip(1) {
        let other_id = V2View::new(other).map_err(bad)?.unique_id().map_err(bad)?;
        if other_id != id {
            return Err(refuse(format!(
                "PSBT {n} describes a different transaction ({other_id}, not {id})"
            )));
        }
        // The unique id fixes the input and output counts, so these hold.
        merge_map(&mut out.global, &other.global, "global map")?;
        for (i, map) in other.inputs.iter().enumerate() {
            merge_map(&mut out.inputs[i], map, &format!("input {i}"))?;
        }
        for (i, map) in other.outputs.iter().enumerate() {
            merge_map(&mut out.outputs[i], map, &format!("output {i}"))?;
        }
    }
    Ok(out)
}

fn merge_map(into: &mut RawMap, from: &RawMap, label: &str) -> Result<(), RpcError> {
    for pair in from.pairs() {
        match into.get(pair.key_type, &pair.key_data) {
            None => {
                // `insert` cannot fail: we just established the key is absent.
                let _ = into.insert(pair.clone());
            }
            Some(existing) if existing == pair.value.as_slice() => {}
            Some(_) => {
                return Err(refuse(format!(
                    "{label}: conflicting values for {}",
                    field_name(label, pair.key_type)
                )));
            }
        }
    }
    Ok(())
}

fn field_name(label: &str, key_type: u64) -> String {
    let name = if label == "global map" {
        match key_type {
            keys::global::SP_ECDH_SHARE => Some("PSBT_GLOBAL_SP_ECDH_SHARE"),
            keys::global::SP_DLEQ => Some("PSBT_GLOBAL_SP_DLEQ"),
            keys::global::TX_MODIFIABLE => Some("PSBT_GLOBAL_TX_MODIFIABLE"),
            _ => None,
        }
    } else if label.starts_with("input") {
        match key_type {
            keys::input::SP_ECDH_SHARE => Some("PSBT_IN_SP_ECDH_SHARE"),
            keys::input::SP_DLEQ => Some("PSBT_IN_SP_DLEQ"),
            keys::input::SEQUENCE => Some("PSBT_IN_SEQUENCE"),
            keys::input::WITNESS_UTXO => Some("PSBT_IN_WITNESS_UTXO"),
            _ => None,
        }
    } else {
        match key_type {
            keys::output::SCRIPT => Some("PSBT_OUT_SCRIPT"),
            keys::output::AMOUNT => Some("PSBT_OUT_AMOUNT"),
            keys::output::SP_V0_INFO => Some("PSBT_OUT_SP_V0_INFO"),
            keys::output::SP_V0_LABEL => Some("PSBT_OUT_SP_V0_LABEL"),
            _ => None,
        }
    };
    match name {
        Some(n) => n.to_string(),
        None => format!("the field of type {key_type:#x}"),
    }
}

// ---------------------------------------------------------------------------
// joinpsbts
// ---------------------------------------------------------------------------

/// `joinpsbts` for version 2 PSBTs.
///
/// Joining adds inputs and outputs, which changes the silent payment shared
/// secret and every script derived from it. So a PSBT that has already
/// committed to that shared secret cannot be joined, and this says which one
/// and why rather than producing a transaction that pays the wrong scripts.
/// Per-input shares survive: they are statements about one input, and adding
/// a second input does not make the first one's share wrong.
pub fn join(psbts: &[RawPsbt]) -> Result<RawPsbt, RpcError> {
    let first = psbts.first().ok_or((-8, "Missing PSBTs".to_string()))?;
    let any_sp = psbts
        .iter()
        .any(|p| V2View::new(p).map(|v| v.has_sp_outputs()).unwrap_or(false));

    let base = V2View::new(first).map_err(bad)?;
    let tx_version = base.tx_version().map_err(bad)?;
    let fallback = base.fallback_locktime().map_err(bad)?;

    for (n, psbt) in psbts.iter().enumerate() {
        let view = V2View::new(psbt).map_err(bad)?;
        if view.tx_version().map_err(bad)? != tx_version {
            return Err(refuse(format!(
                "PSBT {n} has a different PSBT_GLOBAL_TX_VERSION"
            )));
        }
        if view.fallback_locktime().map_err(bad)? != fallback {
            return Err(refuse(format!(
                "PSBT {n} has a different PSBT_GLOBAL_FALLBACK_LOCKTIME"
            )));
        }
        if !any_sp {
            continue;
        }
        for output in view.outputs() {
            if output.map().contains_type(keys::output::SP_V0_INFO)
                && script_is_computed(output.map())
            {
                return Err(refuse(format!(
                    "PSBT {n} output {} is a silent payment output whose script has already \
                     been computed; joining would change the transaction it was computed from",
                    output.index()
                )));
            }
        }
        if psbt.global.contains_type(keys::global::SP_ECDH_SHARE) {
            return Err(refuse(format!(
                "PSBT {n} has a global ECDH share, which commits to its whole input set; \
                 joining would add inputs it does not cover"
            )));
        }
        let modifiable = view.tx_modifiable().map_err(bad)?;
        if modifiable & keys::modifiable::INPUTS == 0
            || modifiable & keys::modifiable::OUTPUTS == 0
        {
            return Err(refuse(format!(
                "PSBT {n} does not allow inputs and outputs to be added; \
                 PSBT_GLOBAL_TX_MODIFIABLE must have both bits set to join a silent payment PSBT"
            )));
        }
    }

    let mut global = RawMap::new();
    for psbt in psbts {
        merge_map(&mut global, &psbt.global, "global map")?;
    }
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for psbt in psbts {
        inputs.extend(psbt.inputs.iter().cloned());
        outputs.extend(psbt.outputs.iter().cloned());
    }

    global.set(RawPair::new(
        keys::global::INPUT_COUNT,
        Vec::new(),
        compact_size(inputs.len() as u64),
    ));
    global.set(RawPair::new(
        keys::global::OUTPUT_COUNT,
        Vec::new(),
        compact_size(outputs.len() as u64),
    ));

    Ok(RawPsbt {
        global,
        inputs,
        outputs,
    })
}

fn compact_size(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    satd_psbt::raw::write_compact_size(&mut out, v);
    out
}

// ---------------------------------------------------------------------------
// utxoupdatepsbt
// ---------------------------------------------------------------------------

/// Fill in `PSBT_IN_WITNESS_UTXO` for every input that has no previous output
/// yet and whose outpoint the node can find. Nothing else in the PSBT moves.
pub fn utxo_update(chain_state: &ChainState, raw: &RawPsbt) -> Result<RawPsbt, RpcError> {
    let view = V2View::new(raw).map_err(bad)?;
    let mut wanted: Vec<(usize, bitcoin::OutPoint)> = Vec::new();
    for input in view.inputs() {
        let map = input.map();
        if map.contains_type(keys::input::WITNESS_UTXO)
            || map.contains_type(keys::input::NON_WITNESS_UTXO)
        {
            continue;
        }
        if let Ok(outpoint) = input.outpoint() {
            wanted.push((input.index(), outpoint));
        }
    }

    let mut out = raw.clone();
    for (index, outpoint) in wanted {
        if let Some(coin) = chain_state.get_coin(&outpoint) {
            let txout = TxOut {
                value: Amount::from_sat(coin.amount),
                script_pubkey: coin.script_pubkey.clone(),
            };
            out.inputs[index].set(RawPair::new(
                keys::input::WITNESS_UTXO,
                Vec::new(),
                bitcoin::consensus::serialize(&txout),
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// finalizepsbt
// ---------------------------------------------------------------------------

/// The interim per-input fields BIP 174 says a Finalizer clears once it has
/// written the final scriptSig or witness. Mirrors the version 0 finaliser
/// exactly, `PSBT_IN_SIGHASH_TYPE` included: it does not clear that one.
const INTERIM_INPUT_FIELDS: [u64; 8] = [
    keys::input::PARTIAL_SIG,
    keys::input::REDEEM_SCRIPT,
    keys::input::WITNESS_SCRIPT,
    keys::input::BIP32_DERIVATION,
    keys::input::TAP_KEY_SIG,
    keys::input::TAP_SCRIPT_SIG,
    keys::input::TAP_INTERNAL_KEY,
    keys::input::TAP_MERKLE_ROOT,
];

/// Run the version 0 finaliser over a version 2 PSBT and write what it
/// produced back into the raw maps.
///
/// Returns the updated PSBT and whether every input is now final.
pub fn finalize(raw: &RawPsbt) -> Result<(RawPsbt, bool), RpcError> {
    let view = V2View::new(raw).map_err(bad)?;
    let mut v0 = view.to_v0().map_err(bad)?;

    for input in &mut v0.inputs {
        super::psbt::try_finalize_input(input);
    }

    let mut out = raw.clone();
    for (index, input) in v0.inputs.iter().enumerate() {
        let finalized = input.final_script_sig.is_some() || input.final_script_witness.is_some();
        if !finalized {
            continue;
        }
        if let Some(sig) = &input.final_script_sig {
            out.inputs[index].set(RawPair::new(
                keys::input::FINAL_SCRIPTSIG,
                Vec::new(),
                sig.to_bytes(),
            ));
        }
        if let Some(witness) = &input.final_script_witness {
            out.inputs[index].set(RawPair::new(
                keys::input::FINAL_SCRIPTWITNESS,
                Vec::new(),
                bitcoin::consensus::serialize(witness),
            ));
        }
        for ty in INTERIM_INPUT_FIELDS {
            out.inputs[index].remove_type(ty);
        }
        // BIP 371's taproot key origins share `TAP_BIP32_DERIVATION`.
        out.inputs[index].remove_type(keys::input::TAP_BIP32_DERIVATION);
    }

    let complete = out.inputs.iter().all(|m| {
        m.contains_type(keys::input::FINAL_SCRIPTSIG)
            || m.contains_type(keys::input::FINAL_SCRIPTWITNESS)
    });
    Ok((out, complete))
}

/// Build the network transaction from a finalised version 2 PSBT.
pub fn extract(raw: &RawPsbt) -> Result<bitcoin::Transaction, RpcError> {
    let view = V2View::new(raw).map_err(bad)?;
    let mut tx = view.unsigned_tx().map_err(bad)?;
    for (index, input) in view.inputs().enumerate() {
        if let Some(sig) = input.map().get_single(keys::input::FINAL_SCRIPTSIG) {
            tx.input[index].script_sig = bitcoin::ScriptBuf::from_bytes(sig.to_vec());
        }
        if let Some(witness) = input.map().get_single(keys::input::FINAL_SCRIPTWITNESS) {
            tx.input[index].witness = bitcoin::consensus::deserialize(witness)
                .map_err(|_| refuse(format!("input {index} has a malformed final witness")))?;
        }
    }
    Ok(tx)
}

/// Whether a version 2 PSBT carries any silent payment output.
pub fn has_silent_payments(raw: &RawPsbt) -> bool {
    raw.outputs
        .iter()
        .any(|o| o.contains_type(keys::output::SP_V0_INFO))
}

/// A short label for error messages that need to say which version a PSBT is.
pub fn version_label(version: PsbtVersion) -> &'static str {
    match version {
        PsbtVersion::V0 => "0",
        PsbtVersion::V2 => "2",
    }
}
