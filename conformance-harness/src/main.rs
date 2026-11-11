//! A harness for the bitcoin-consensus-spec conformance runner
//! (<https://github.com/coreyphillips/bitcoin-consensus-spec>), answering
//! from satd's own consensus code: the Rust script engine (`consensus`)
//! and the node's transaction checks.
//!
//! The protocol is the spec's `conformance/PROTOCOL.md`, version 1: one
//! JSON request per line on stdin, one JSON response per line on stdout,
//! in order. Run it under the spec's runner:
//!
//! ```sh
//! bcs-conformance --impl target/release/satd-conformance-harness --corpus <spec>/conformance/vectors/blocks
//! ```
//!
//! The chain operations run in a child process per `chain_reset`; see
//! [`chain`].

mod chain;

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{self, ffi, Secp256k1};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use serde_json::{json, Map, Value};

/// The specification version these answers are checked against.
const SPEC_VERSION: &str = "v32.1-1";

const OPS: &[&str] = &[
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
];

/// Why a request got `ok: false` (PROTOCOL.md section 2).
struct Fail {
    code: &'static str,
    message: String,
}

fn bad_request(message: impl Into<String>) -> Fail {
    Fail { code: "bad_request", message: message.into() }
}

type Fields = Map<String, Value>;

fn main() {
    let worker_mode = std::env::args().nth(1).as_deref() == Some("--chain-worker");
    let mut chain: Option<chain::Chain> = None;
    let mut worker: Option<chain::Worker> = None;
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("satd-conformance-harness: reading stdin: {e}");
                std::process::exit(1);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = if worker_mode {
            respond(&line, |op, req| chain::dispatch(&mut chain, op, req))
        } else {
            route(&line, &mut worker)
        };
        let written = serde_json::to_writer(&mut stdout, &response)
            .map_err(io::Error::from)
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush());
        if let Err(e) = written {
            eprintln!("satd-conformance-harness: writing stdout: {e}");
            std::process::exit(1);
        }
    }
}

/// One response line for one request line, in the main process: a chain
/// operation goes to the chain worker (a new one on every `chain_reset`),
/// everything else is answered here.
fn route(line: &str, worker: &mut Option<chain::Worker>) -> Value {
    let request = serde_json::from_str::<Value>(line).ok();
    let op = request.as_ref().and_then(|r| r.get("op")).and_then(Value::as_str);
    let Some(op) = op.filter(|op| chain::OPS.contains(op)) else {
        return respond(line, dispatch);
    };
    let id = request.as_ref().and_then(|r| r.get("id")).cloned().unwrap_or(Value::Null);
    if op == "chain_reset" {
        *worker = None;
        match chain::Worker::spawn() {
            Ok(w) => *worker = Some(w),
            Err(fail) => return failure(id, fail),
        }
    }
    match worker.as_mut() {
        None => failure(id, bad_request("no chain_reset yet")),
        Some(w) => w.call(line).unwrap_or_else(|fail| failure(id, fail)),
    }
}

/// One response line for one request line.
fn respond(line: &str, mut dispatch: impl FnMut(&str, &Fields) -> Result<Fields, Fail>) -> Value {
    let request = match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(request)) => request,
        _ => return failure(Value::Null, bad_request("not a JSON object")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if !id.is_i64() && !id.is_u64() {
        return failure(id, bad_request("missing integer id"));
    }
    let Some(op) = request.get("op").and_then(Value::as_str) else {
        return failure(id, bad_request("missing op"));
    };
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| dispatch(op, &request)))
        .unwrap_or_else(|_| Err(Fail { code: "internal", message: "panic".into() }));
    match outcome {
        Ok(mut fields) => {
            fields.insert("id".into(), id);
            fields.insert("ok".into(), Value::Bool(true));
            Value::Object(fields)
        }
        Err(fail) => failure(id, fail),
    }
}

fn failure(id: Value, fail: Fail) -> Value {
    json!({"id": id, "ok": false, "error": fail.code, "message": fail.message})
}

fn dispatch(op: &str, req: &Fields) -> Result<Fields, Fail> {
    match op {
        "info" => Ok(info()),
        "script_verify" => script_verify(req),
        "tx_check" => tx_check(req),
        "sighash_legacy" => sighash_legacy(req),
        "sighash_taproot" => sighash_taproot(req),
        "taproot_commitment_verify" => taproot_commitment_verify(req),
        "schnorr_verify" => schnorr_verify(req),
        _ => Err(Fail { code: "unsupported_op", message: format!("satd does not answer {op}") }),
    }
}

fn info() -> Fields {
    let mut fields = Fields::new();
    fields.insert("name".into(), json!("satd"));
    fields.insert("version".into(), json!(env!("CARGO_PKG_VERSION")));
    fields.insert("spec_version".into(), json!(SPEC_VERSION));
    let ops: Vec<&str> = OPS.iter().chain(chain::OPS).copied().collect();
    fields.insert("ops".into(), json!(ops));
    fields
}

/// PROTOCOL.md 4.2: one input, through the engine's public entry point, the
/// same call the node's Rust verifier makes.
fn script_verify(req: &Fields) -> Result<Fields, Fail> {
    let tx = field_tx(req, "tx")?;
    let index = field_index(req, "index")?;
    let spent = field_spent_outputs(req)?;
    let flags = field_flags(req)?;
    if index >= tx.input.len() {
        return Err(bad_request("index past the last input"));
    }
    if spent.len() != tx.input.len() {
        return Err(bad_request("spent_outputs needs one entry per input"));
    }
    let precomputed = consensus::PrecomputedTransactionData::new(&tx, &spent)
        .map_err(|e| bad_request(format!("spent outputs: {e}")))?;
    let prev = &spent[index];
    let result = consensus::verify(&prev.script_pubkey, prev.value, &tx, index, flags, &precomputed);
    let mut fields = Fields::new();
    match result {
        Ok(()) => {
            fields.insert("valid".into(), json!(true));
            fields.insert("script_error".into(), json!("OK"));
        }
        Err(consensus::Error::ErrScript(e)) => {
            fields.insert("valid".into(), json!(false));
            fields.insert("script_error".into(), json!(e.test_name()));
        }
        Err(e) => return Err(bad_request(format!("engine refused the call: {e}"))),
    }
    Ok(fields)
}

/// PROTOCOL.md 4.3: decode as the node decodes a transaction from the wire,
/// then the node's `CheckTransaction`.
fn tx_check(req: &Fields) -> Result<Fields, Fail> {
    let bytes = field_hex(req, "tx")?;
    let mut fields = Fields::new();
    let verdict = match deserialize::<Transaction>(&bytes) {
        Err(_) => Err("tx-decode".to_string()),
        Ok(tx) => node::validation::tx::check_transaction(&tx).map_err(|e| e.to_string()),
    };
    match verdict {
        Ok(()) => {
            fields.insert("valid".into(), json!(true));
        }
        Err(reason) => {
            fields.insert("valid".into(), json!(false));
            fields.insert("reason".into(), json!(reason));
        }
    }
    Ok(fields)
}

/// PROTOCOL.md 4.4.
fn sighash_legacy(req: &Fields) -> Result<Fields, Fail> {
    let tx = field_tx(req, "tx")?;
    let script_code = field_hex(req, "script_code")?;
    let index = field_index(req, "index")?;
    let hash_type = field_i64(req, "hash_type")?;
    let hash_type = i32::try_from(hash_type).map_err(|_| bad_request("hash_type is not a 32-bit integer"))?;
    // Core hashes the signed hash type's bit pattern.
    let sighash = consensus::sighash::legacy_sighash(&tx, index, &script_code, hash_type as u32)
        .ok_or_else(|| bad_request("index past the last input"))?;
    let mut fields = Fields::new();
    fields.insert("sighash".into(), json!(hex::encode(sighash)));
    Ok(fields)
}

/// PROTOCOL.md 4.5.
fn sighash_taproot(req: &Fields) -> Result<Fields, Fail> {
    let tx = field_tx(req, "tx")?;
    let index = field_index(req, "index")?;
    let spent = field_spent_outputs(req)?;
    let hash_type = field_i64(req, "hash_type")?;
    let hash_type = u8::try_from(hash_type).map_err(|_| bad_request("hash_type is not 0 to 255"))?;
    if index >= tx.input.len() {
        return Err(bad_request("index past the last input"));
    }
    if spent.len() != tx.input.len() {
        return Err(bad_request("spent_outputs needs one entry per input"));
    }
    let annex = optional_hex(req, "annex")?;
    let leaf_hash = match optional_hex(req, "leaf_hash")? {
        None => None,
        Some(bytes) => Some(<[u8; 32]>::try_from(bytes).map_err(|_| bad_request("leaf_hash is not 32 bytes"))?),
    };
    let codesep_pos = match req.get("codesep_pos") {
        None => u32::MAX,
        Some(v) => v
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| bad_request("codesep_pos is not a 32-bit unsigned integer"))?,
    };
    let sighash = consensus::sighash::taproot_sighash(
        &tx,
        index,
        &spent,
        hash_type,
        annex.as_deref(),
        leaf_hash,
        codesep_pos,
    );
    let mut fields = Fields::new();
    fields.insert("valid".into(), json!(sighash.is_some()));
    if let Some(sighash) = sighash {
        fields.insert("sighash".into(), json!(hex::encode(sighash)));
    }
    Ok(fields)
}

/// PROTOCOL.md 4.6: the script path check the engine runs on a witness.
fn taproot_commitment_verify(req: &Fields) -> Result<Fields, Fail> {
    let control = field_hex(req, "control_block")?;
    let script = field_hex(req, "script")?;
    let output_key = field_hex(req, "output_key")?;
    if output_key.len() != 32 {
        return Err(bad_request("output_key is not 32 bytes"));
    }
    let valid = consensus::witness::check_taproot_commitment(&control, &script, &output_key).is_ok();
    let mut fields = Fields::new();
    fields.insert("valid".into(), json!(valid));
    Ok(fields)
}

/// PROTOCOL.md 4.7: BIP 340 over a message of any length. The safe
/// secp256k1 API (0.29) takes only 32-byte messages, so this calls
/// libsecp256k1's `secp256k1_schnorrsig_verify`, which takes a length.
fn schnorr_verify(req: &Fields) -> Result<Fields, Fail> {
    let pubkey = field_hex(req, "pubkey")?;
    let msg = field_hex(req, "msg")?;
    let sig = field_hex(req, "sig")?;
    if pubkey.len() != 32 {
        return Err(bad_request("pubkey is not 32 bytes"));
    }
    if sig.len() != 64 {
        return Err(bad_request("sig is not 64 bytes"));
    }
    let valid = match secp256k1::XOnlyPublicKey::from_slice(&pubkey) {
        Err(_) => false,
        Ok(key) => {
            use secp256k1::ffi::CPtr;
            let secp = Secp256k1::verification_only();
            // SAFETY: the context is a live verification context; `sig` is 64
            // bytes, `msg` is `msg.len()` bytes, and `key` is a parsed
            // x-only key, as the function requires. libsecp256k1 reads the
            // message only when the length is not zero.
            unsafe {
                ffi::secp256k1_schnorrsig_verify(
                    secp.ctx().as_ptr(),
                    sig.as_c_ptr(),
                    msg.as_c_ptr(),
                    msg.len(),
                    key.as_c_ptr(),
                ) == 1
            }
        }
    };
    let mut fields = Fields::new();
    fields.insert("valid".into(), json!(valid));
    Ok(fields)
}

fn field<'a>(req: &'a Fields, name: &str) -> Result<&'a Value, Fail> {
    req.get(name).ok_or_else(|| bad_request(format!("missing {name}")))
}

fn field_hex(req: &Fields, name: &str) -> Result<Vec<u8>, Fail> {
    decode_hex(field(req, name)?, name)
}

fn optional_hex(req: &Fields, name: &str) -> Result<Option<Vec<u8>>, Fail> {
    req.get(name).map(|v| decode_hex(v, name)).transpose()
}

fn decode_hex(value: &Value, name: &str) -> Result<Vec<u8>, Fail> {
    let text = value.as_str().ok_or_else(|| bad_request(format!("{name} is not a string")))?;
    hex::decode(text).map_err(|e| bad_request(format!("{name}: {e}")))
}

fn field_tx(req: &Fields, name: &str) -> Result<Transaction, Fail> {
    let bytes = field_hex(req, name)?;
    deserialize(&bytes).map_err(|e| bad_request(format!("{name} does not decode: {e}")))
}

fn field_i64(req: &Fields, name: &str) -> Result<i64, Fail> {
    field(req, name)?.as_i64().ok_or_else(|| bad_request(format!("{name} is not an integer")))
}

fn field_index(req: &Fields, name: &str) -> Result<usize, Fail> {
    field(req, name)?
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| bad_request(format!("{name} is not a non-negative integer")))
}

/// `spent_outputs`. Test data may carry negative or oversized amounts; Core
/// keeps them as `int64_t`, so they are hashed as that bit pattern.
fn field_spent_outputs(req: &Fields) -> Result<Vec<TxOut>, Fail> {
    let entries = field(req, "spent_outputs")?
        .as_array()
        .ok_or_else(|| bad_request("spent_outputs is not an array"))?;
    entries
        .iter()
        .map(|entry| {
            let entry = entry.as_object().ok_or_else(|| bad_request("spent output is not an object"))?;
            let amount = field_i64(entry, "amount")?;
            let script_pubkey = field_hex(entry, "script_pubkey")?;
            Ok(TxOut { value: Amount::from_sat(amount as u64), script_pubkey: ScriptBuf::from_bytes(script_pubkey) })
        })
        .collect()
}

/// PROTOCOL.md 3.1: the seven consensus flags, by name.
fn field_flags(req: &Fields) -> Result<u32, Fail> {
    let names = field(req, "flags")?.as_array().ok_or_else(|| bad_request("flags is not an array"))?;
    let mut flags = consensus::VERIFY_NONE;
    for name in names {
        flags |= match name.as_str() {
            Some("P2SH") => consensus::VERIFY_P2SH,
            Some("DERSIG") => consensus::VERIFY_DERSIG,
            Some("NULLDUMMY") => consensus::VERIFY_NULLDUMMY,
            Some("CHECKLOCKTIMEVERIFY") => consensus::VERIFY_CHECKLOCKTIMEVERIFY,
            Some("CHECKSEQUENCEVERIFY") => consensus::VERIFY_CHECKSEQUENCEVERIFY,
            Some("WITNESS") => consensus::VERIFY_WITNESS,
            Some("TAPROOT") => consensus::VERIFY_TAPROOT,
            _ => return Err(bad_request(format!("unknown flag {name}"))),
        };
    }
    Ok(flags)
}
