use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};

use satd_psbt::raw::{PsbtVersion, RawPsbt};

use crate::chain::state::ChainState;
use crate::rpc::amounts::{default_unit, format_amount};
use crate::rpc::psbt_v2;

fn psbt_to_base64(psbt: &Psbt) -> String {
    let mut buf = Vec::new();
    psbt.serialize_to_writer(&mut buf).expect("PSBT serialization");
    B64.encode(&buf)
}

/// A PSBT of either version.
pub(crate) enum Parsed {
    V0(Psbt),
    V2(RawPsbt),
}

impl Parsed {
    pub(crate) fn version(&self) -> PsbtVersion {
        match self {
            Parsed::V0(_) => PsbtVersion::V0,
            Parsed::V2(_) => PsbtVersion::V2,
        }
    }
}

/// Decode a PSBT, dispatching on the version it declares.
///
/// The sniff reads only the global map. Anything it cannot read — including a
/// PSBT that is simply corrupt — goes to the version 0 parser, so that a
/// version 0 caller keeps getting the version 0 verdict and the version 0
/// message. Nothing this crate says about version 2 may change what an
/// existing client sees.
pub(crate) fn parse_any(b64: &str) -> Result<Parsed, (i32, String)> {
    let raw = B64.decode(b64).map_err(|_| (-22, "PSBT base64 decode failed".to_string()))?;
    match satd_psbt::version_of_bytes(&raw) {
        Ok(PsbtVersion::V2) => RawPsbt::parse(&raw)
            .map(Parsed::V2)
            .map_err(|e| (-22, format!("PSBT decode failed: {e}"))),
        _ => Psbt::deserialize(&raw)
            .map(Parsed::V0)
            .map_err(|_| (-22, "PSBT decode failed".to_string())),
    }
}

fn parse_all(b64s: &[String]) -> Result<Vec<Parsed>, (i32, String)> {
    b64s.iter().map(|b| parse_any(b)).collect()
}

fn raw_to_base64(raw: &RawPsbt) -> String {
    B64.encode(raw.serialize())
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
    psbt_version: Option<u32>,
    chain_state: Option<&ChainState>,
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

    let parsed = parse_psbt_outputs(outputs, network)?;
    let has_silent_payments = parsed
        .iter()
        .any(|o| matches!(o, PsbtOutput::SilentPayment { .. }));

    match psbt_version {
        // D5: a caller whose signer cannot read version 2 should learn that at
        // creation, not at signing. Refusing by name is how.
        None | Some(0) => {
            if has_silent_payments {
                return Err((
                    -8,
                    "silent payment recipients need a version 2 PSBT; pass psbt_version=2"
                        .to_string(),
                ));
            }
        }
        Some(2) => {}
        Some(other) => {
            return Err((
                -8,
                format!("psbt_version must be 0 or 2, not {other}"),
            ));
        }
    }

    let lt = locktime
        .map(bitcoin::blockdata::locktime::absolute::LockTime::from_consensus)
        .unwrap_or(bitcoin::blockdata::locktime::absolute::LockTime::ZERO);

    if psbt_version == Some(2) {
        if has_silent_payments {
            refuse_ineligible_inputs(&tx_inputs, chain_state)?;
        }
        let raw = build_v2_psbt(&tx_inputs, &parsed, lt)?;
        return Ok(Value::String(raw_to_base64(&raw)));
    }

    let tx_outputs: Vec<TxOut> = parsed
        .into_iter()
        .map(|o| match o {
            PsbtOutput::Ordinary(txout) => txout,
            PsbtOutput::SilentPayment { .. } => {
                unreachable!("refused above when the version is not 2")
            }
        })
        .collect();

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

/// One requested output: an ordinary script, or a silent payment recipient
/// that has no script yet and will not have one until a Signer computes it.
enum PsbtOutput {
    Ordinary(TxOut),
    SilentPayment {
        amount: Amount,
        address: satd_psbt::SpAddress,
    },
}

/// `createpsbt`'s outputs, with silent payment recipients split out.
///
/// `createrawtransaction` shares `parse_outputs` with `createpsbt` and must
/// keep refusing an `sp1…` key: a raw transaction has nowhere to put the
/// information a Signer needs. So the silent payment keys are peeled off here,
/// in `createpsbt`'s own wrapper, and everything else goes to the shared
/// parser one entry at a time — the same parser, the same errors.
fn parse_psbt_outputs(
    outputs: &Value,
    network: bitcoin::Network,
) -> Result<Vec<PsbtOutput>, (i32, String)> {
    use satd_psbt::SpAddress;

    let mut pairs = crate::rpc::rawtx::normalize_output_pairs(outputs)?;

    // Core's first-value-wins rule exists because of how `UniValue` reads a
    // repeated key, and it applies to the keys Core knows about. A repeated
    // silent payment address is *legal* — two payments to one recipient get
    // k = 0 and k = 1 — so each occurrence has to keep its own amount.
    let (sp_pairs, mut ordinary): (Vec<_>, Vec<_>) = pairs
        .drain(..)
        .partition(|(key, _)| SpAddress::looks_like(key, network));
    crate::rpc::rawtx::apply_first_value_wins(&mut ordinary);

    // Rebuild the original order: the output order decides the transaction,
    // and for silent payments it decides the `k` values too.
    let mut ordinary = ordinary.into_iter();
    let mut sp_pairs = sp_pairs.into_iter();
    let original = crate::rpc::rawtx::normalize_output_pairs(outputs)?;

    let mut out = Vec::with_capacity(original.len());
    let mut seen_destinations: std::collections::HashSet<bitcoin::ScriptBuf> =
        std::collections::HashSet::new();
    let mut seen_data = false;

    for (key, _) in original {
        if SpAddress::looks_like(&key, network) {
            let (key, val) = sp_pairs.next().expect("partition preserved the count");
            let address = SpAddress::decode(&key, network)
                .map_err(|e| (-5, format!("Invalid silent payment address: {e}")))?;
            // A version above 0 carries something satd does not understand;
            // paying it by reading only the first two keys would be a guess.
            address
                .require_v0()
                .map_err(|e| (-5, format!("Invalid silent payment address: {e}")))?;
            let amount = crate::rpc::rawtx::parse_btc_amount_value(&val)?;
            out.push(PsbtOutput::SilentPayment { amount, address });
        } else {
            let (key, val) = ordinary.next().expect("partition preserved the count");
            let mut built = Vec::new();
            crate::rpc::rawtx::parse_output_entry(
                &key,
                &val,
                network,
                &mut built,
                &mut seen_destinations,
                &mut seen_data,
            )?;
            out.extend(built.into_iter().map(PsbtOutput::Ordinary));
        }
    }
    Ok(out)
}

/// BIP 352 forbids a segwit version 2 or later input anywhere in a transaction
/// that pays a silent payment address: there is no defined way for such an
/// input to contribute a public key, so the shared secret cannot be computed.
///
/// Checked here, at creation, against previous outputs the node actually has —
/// a caller learns before it starts collecting signatures rather than when the
/// extractor refuses.
fn refuse_ineligible_inputs(
    inputs: &[TxIn],
    chain_state: Option<&ChainState>,
) -> Result<(), (i32, String)> {
    let Some(chain_state) = chain_state else {
        return Ok(());
    };
    for (index, input) in inputs.iter().enumerate() {
        let Some(coin) = chain_state.get_coin(&input.previous_output) else {
            continue;
        };
        if let Some(version) = coin.script_pubkey.witness_version()
            && version > bitcoin::WitnessVersion::V1
        {
            return Err((
                -8,
                format!(
                    "input {index} spends a segwit version {} output, which cannot contribute \
                     to a silent payment",
                    version.to_num()
                ),
            ));
        }
    }
    Ok(())
}

/// Assemble a version 2 PSBT from the requested inputs and outputs.
///
/// A silent payment output gets an amount and a `PSBT_OUT_SP_V0_INFO` and
/// **no** `PSBT_OUT_SCRIPT`: BIP 375 gives computing it to the Signer, because
/// computing it is what freezes the transaction. `PSBT_GLOBAL_TX_MODIFIABLE`
/// says so — both inputs and outputs are still modifiable until then.
fn build_v2_psbt(
    inputs: &[TxIn],
    outputs: &[PsbtOutput],
    lock_time: bitcoin::absolute::LockTime,
) -> Result<satd_psbt::RawPsbt, (i32, String)> {
    use satd_psbt::keys;
    use satd_psbt::raw::{RawMap, RawPair, RawPsbt, write_compact_size};

    let mut global = RawMap::new();
    global.set(RawPair::new(
        keys::global::VERSION,
        Vec::new(),
        2u32.to_le_bytes().to_vec(),
    ));
    global.set(RawPair::new(
        keys::global::TX_VERSION,
        Vec::new(),
        2u32.to_le_bytes().to_vec(),
    ));
    global.set(RawPair::new(
        keys::global::FALLBACK_LOCKTIME,
        Vec::new(),
        lock_time.to_consensus_u32().to_le_bytes().to_vec(),
    ));
    let mut count = Vec::new();
    write_compact_size(&mut count, inputs.len() as u64);
    global.set(RawPair::new(keys::global::INPUT_COUNT, Vec::new(), count));
    let mut count = Vec::new();
    write_compact_size(&mut count, outputs.len() as u64);
    global.set(RawPair::new(keys::global::OUTPUT_COUNT, Vec::new(), count));
    global.set(RawPair::new(
        keys::global::TX_MODIFIABLE,
        Vec::new(),
        vec![keys::modifiable::INPUTS | keys::modifiable::OUTPUTS],
    ));

    let raw_inputs = inputs
        .iter()
        .map(|input| {
            let mut map = RawMap::new();
            map.set(RawPair::new(
                keys::input::PREVIOUS_TXID,
                Vec::new(),
                bitcoin::consensus::serialize(&input.previous_output.txid),
            ));
            map.set(RawPair::new(
                keys::input::OUTPUT_INDEX,
                Vec::new(),
                input.previous_output.vout.to_le_bytes().to_vec(),
            ));
            map.set(RawPair::new(
                keys::input::SEQUENCE,
                Vec::new(),
                input.sequence.0.to_le_bytes().to_vec(),
            ));
            map
        })
        .collect();

    let mut raw_outputs = Vec::with_capacity(outputs.len());
    for output in outputs {
        let mut map = RawMap::new();
        match output {
            PsbtOutput::Ordinary(txout) => {
                map.set(RawPair::new(
                    keys::output::AMOUNT,
                    Vec::new(),
                    (txout.value.to_sat() as i64).to_le_bytes().to_vec(),
                ));
                map.set(RawPair::new(
                    keys::output::SCRIPT,
                    Vec::new(),
                    txout.script_pubkey.to_bytes(),
                ));
            }
            PsbtOutput::SilentPayment { amount, address } => {
                map.set(RawPair::new(
                    keys::output::AMOUNT,
                    Vec::new(),
                    (amount.to_sat() as i64).to_le_bytes().to_vec(),
                ));
                map.set(RawPair::new(
                    keys::output::SP_V0_INFO,
                    Vec::new(),
                    address.to_info(),
                ));
            }
        }
        raw_outputs.push(map);
    }

    Ok(RawPsbt {
        global,
        inputs: raw_inputs,
        outputs: raw_outputs,
    })
}

/// `decodepsbt` — decode a base64-encoded PSBT to JSON.
/// `chain_state` is used only to spell a silent payment output's address for
/// the network this node is on. The version 0 path ignores it.
pub fn decode_psbt(
    psbt_b64: &str,
    chain_state: Option<&ChainState>,
) -> Result<Value, (i32, String)> {
    match parse_any(psbt_b64)? {
        Parsed::V0(psbt) => decode_psbt_v0(&psbt),
        Parsed::V2(raw) => psbt_v2::decode(&raw, chain_state.map(|c| c.network)),
    }
}

fn decode_psbt_v0(psbt: &Psbt) -> Result<Value, (i32, String)> {
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
        "fee": match psbt_fee(psbt) {
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
/// `chain_state` is what lets the silent payment checks cross-check each
/// previous output against the UTXO set. The version 0 path ignores it
/// entirely and behaves identically with or without it.
pub fn analyze_psbt(
    psbt_b64: &str,
    chain_state: Option<&ChainState>,
) -> Result<Value, (i32, String)> {
    match parse_any(psbt_b64)? {
        Parsed::V0(psbt) => analyze_psbt_v0(&psbt),
        Parsed::V2(raw) => psbt_v2::analyze(&raw, chain_state),
    }
}

fn analyze_psbt_v0(psbt: &Psbt) -> Result<Value, (i32, String)> {

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
    let fee = psbt_fee(psbt);
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
    let parsed = parse_all(psbt_b64s)?;
    match split_versions(&parsed, "combinepsbt")? {
        PsbtVersion::V0 => {
            let mut combined = as_v0(&parsed[0]);
            for other in &parsed[1..] {
                combined
                    .combine(as_v0(other))
                    .map_err(|e| (-22, format!("PSBT combine failed: {}", e)))?;
            }
            Ok(Value::String(psbt_to_base64(&combined)))
        }
        PsbtVersion::V2 => {
            let raws: Vec<RawPsbt> = parsed.iter().map(as_v2).collect();
            let combined = psbt_v2::combine(&raws)?;
            Ok(Value::String(raw_to_base64(&combined)))
        }
    }
}

/// The version every PSBT in a list shares, or a refusal naming the first one
/// that differs. Mixing versions is not a merge, it is two different
/// documents; Core has no version 2 at all, so there is no precedent to
/// follow and guessing is the wrong answer.
fn split_versions(parsed: &[Parsed], method: &str) -> Result<PsbtVersion, (i32, String)> {
    let first = parsed[0].version();
    for (n, p) in parsed.iter().enumerate().skip(1) {
        if p.version() != first {
            return Err((
                -22,
                format!(
                    "{method} needs every PSBT to be the same version; PSBT 0 is version {} \
                     and PSBT {n} is version {}",
                    psbt_v2::version_label(first),
                    psbt_v2::version_label(p.version())
                ),
            ));
        }
    }
    Ok(first)
}

fn as_v0(parsed: &Parsed) -> Psbt {
    match parsed {
        Parsed::V0(psbt) => psbt.clone(),
        Parsed::V2(_) => unreachable!("split_versions established every PSBT is version 0"),
    }
}

fn as_v2(parsed: &Parsed) -> RawPsbt {
    match parsed {
        Parsed::V2(raw) => raw.clone(),
        Parsed::V0(_) => unreachable!("split_versions established every PSBT is version 2"),
    }
}

/// `finalizepsbt` — finalize a fully-signed PSBT into a network transaction.
pub fn finalize_psbt(
    psbt_b64: &str,
    extract: bool,
    chain_state: Option<&ChainState>,
) -> Result<Value, (i32, String)> {
    match parse_any(psbt_b64)? {
        Parsed::V0(psbt) => finalize_psbt_v0(psbt, extract),
        Parsed::V2(raw) => {
            // BIP 375 gives the Transaction Extractor the duty of recomputing
            // every silent payment output script and checking it before a
            // transaction leaves the PSBT. There is no override: a silent
            // payment paid to the wrong script is not recoverable, and
            // `extract=false` is gated too because a finalised PSBT is one
            // `sendrawtransaction` away from the chain.
            if psbt_v2::has_silent_payments(&raw) {
                let view = satd_psbt::V2View::new(&raw).map_err(|e| (-22, e.to_string()))?;
                psbt_v2::extractor_gate(&view, chain_state)?;
            }
            let (finalized, complete) = psbt_v2::finalize(&raw)?;
            if extract && complete {
                let tx = psbt_v2::extract(&finalized)?;
                Ok(json!({
                    "hex": hex::encode(bitcoin::consensus::serialize(&tx)),
                    "complete": true,
                }))
            } else {
                Ok(json!({
                    "psbt": raw_to_base64(&finalized),
                    "complete": complete,
                }))
            }
        }
    }
}

fn finalize_psbt_v0(mut psbt: Psbt, extract: bool) -> Result<Value, (i32, String)> {

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
pub(crate) fn try_finalize_input(input: &mut bitcoin::psbt::Input) {
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
pub fn convert_to_psbt(
    hex_tx: &str,
    permit_sigdata: bool,
    iswitness: Option<bool>,
) -> Result<Value, (i32, String)> {
    let tx_bytes = hex::decode(hex_tx).map_err(|_| (-22, "TX decode failed".to_string()))?;
    // Core reaches one `DecodeHexTx(tx, hex, /*try_no_witness=*/..., /*try_witness=*/...)`
    // from `converttopsbt` and `decoderawtransaction` alike, so `iswitness`
    // means the same thing in both. satd refused the argument here rather
    // than accept a flag it could not honour; now it honours it.
    let mut tx: Transaction = crate::rpc::rawtx::decode_tx(
        &tx_bytes,
        iswitness != Some(true),
        iswitness != Some(false),
    )
    .ok_or((-22i32, "TX decode failed".to_string()))?;

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
    let parsed = parse_all(psbt_b64s)?;
    match split_versions(&parsed, "joinpsbts")? {
        PsbtVersion::V0 => {
            // Merge all inputs and outputs into a single PSBT
            let mut merged = as_v0(&parsed[0]);
            for other in &parsed[1..] {
                let other = as_v0(other);
                merged.unsigned_tx.input.extend(other.unsigned_tx.input);
                merged.unsigned_tx.output.extend(other.unsigned_tx.output);
                merged.inputs.extend(other.inputs);
                merged.outputs.extend(other.outputs);
            }
            Ok(Value::String(psbt_to_base64(&merged)))
        }
        PsbtVersion::V2 => {
            let raws: Vec<RawPsbt> = parsed.iter().map(as_v2).collect();
            let joined = psbt_v2::join(&raws)?;
            Ok(Value::String(raw_to_base64(&joined)))
        }
    }
}

/// `utxoupdatepsbt` — update PSBT with UTXO data from the node's chain state.
pub fn utxo_update_psbt(
    chain_state: &ChainState,
    psbt_b64: &str,
) -> Result<Value, (i32, String)> {
    let mut psbt = match parse_any(psbt_b64)? {
        Parsed::V0(psbt) => psbt,
        Parsed::V2(raw) => {
            let updated = psbt_v2::utxo_update(chain_state, &raw)?;
            return Ok(Value::String(raw_to_base64(&updated)));
        }
    };

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
            analyze_psbt(&psbt_to_base64(psbt), None).expect("analyzes")
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
