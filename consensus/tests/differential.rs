//! Differential tests: run the same inputs through BOTH our Rust consensus
//! library and the C++ bitcoinconsensus FFI, asserting identical results.
//!
//! This is the key validation that our implementation matches Bitcoin Core.

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use helpers::{parse_flags, parse_script};
use serde_json::Value;
use std::collections::HashMap;

/// Run a single verification through both engines and compare results.
/// Returns (rust_ok, cpp_ok, matched).
fn verify_both(
    spent_output_script: &[u8],
    amount: u64,
    spending_tx_bytes: &[u8],
    input_index: usize,
    flags: u32,
    prev_outputs_for_taproot: Option<&[(Vec<u8>, u64)]>,
) -> (bool, bool, bool) {
    // Build Utxo arrays for both APIs
    let rust_result = if let Some(prevs) = prev_outputs_for_taproot {
        let utxos: Vec<consensus::Utxo> = prevs
            .iter()
            .map(|(spk, val)| consensus::Utxo {
                script_pubkey: spk.as_ptr(),
                script_pubkey_len: spk.len() as u32,
                value: *val as i64,
            })
            .collect();
        consensus::verify_with_flags(
            spent_output_script,
            amount,
            spending_tx_bytes,
            Some(&utxos),
            input_index,
            flags,
        )
    } else {
        consensus::verify_with_flags(
            spent_output_script,
            amount,
            spending_tx_bytes,
            None,
            input_index,
            flags,
        )
    };

    let cpp_result = if let Some(prevs) = prev_outputs_for_taproot {
        let utxos: Vec<bitcoinconsensus::Utxo> = prevs
            .iter()
            .map(|(spk, val)| bitcoinconsensus::Utxo {
                script_pubkey: spk.as_ptr(),
                script_pubkey_len: spk.len() as u32,
                value: *val as i64,
            })
            .collect();
        bitcoinconsensus::verify_with_flags(
            spent_output_script,
            amount,
            spending_tx_bytes,
            Some(&utxos),
            input_index,
            flags,
        )
    } else {
        bitcoinconsensus::verify_with_flags(
            spent_output_script,
            amount,
            spending_tx_bytes,
            None,
            input_index,
            flags,
        )
    };

    let rust_ok = rust_result.is_ok();
    let cpp_ok = cpp_result.is_ok();
    (rust_ok, cpp_ok, rust_ok == cpp_ok)
}

fn build_crediting_tx(script_pubkey: &[u8], value: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    }
}

fn build_spending_tx(
    script_sig: &[u8],
    witness: &[Vec<u8>],
    credit_tx: &Transaction,
) -> Transaction {
    let mut buf = Vec::new();
    credit_tx.consensus_encode(&mut buf).unwrap();
    let txid = Txid::from_byte_array(
        bitcoin::hashes::sha256d::Hash::hash(&buf).to_byte_array(),
    );
    let mut w = Witness::new();
    for item in witness {
        w.push(item);
    }
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut {
            value: credit_tx.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).unwrap();
    buf
}

/// The flags that bitcoinconsensus recognizes (it rejects unknown flag bits).
/// It only recognizes the 8 flags in its public API, not the full 21 we support.
const CPP_RECOGNIZED_FLAGS: u32 = bitcoinconsensus::VERIFY_P2SH
    | bitcoinconsensus::VERIFY_DERSIG
    | bitcoinconsensus::VERIFY_NULLDUMMY
    | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
    | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
    | bitcoinconsensus::VERIFY_WITNESS
    | bitcoinconsensus::VERIFY_TAPROOT;

/// Filter flags to only those recognized by the C++ bitcoinconsensus API.
fn cpp_safe_flags(flags: u32) -> u32 {
    flags & CPP_RECOGNIZED_FLAGS
}

// =========================================================================
// Differential test: script_tests.json
// =========================================================================

#[test]
fn differential_script_tests() {
    let data = include_str!("../test-data/script_tests.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut matched = 0;
    let mut mismatched = 0;
    let mut skipped = 0;
    let mut total = 0;

    for test in &tests {
        if test.is_string() {
            continue;
        }
        let arr = test.as_array().unwrap();

        total += 1;

        let (witness_items, script_sig_str, script_pubkey_str, flags_str, n_value): (Vec<Vec<u8>>, &str, &str, &str, u64) =
            if arr[0].is_array() {
                if arr.len() < 5 { skipped += 1; continue; }
                let wit_arr = arr[0].as_array().unwrap();
                let spk_str = arr[2].as_str().unwrap();
                if spk_str.contains("#TAPROOTOUTPUT#") { skipped += 1; continue; }
                let amount = if let Some(v) = wit_arr.last() {
                    if v.is_number() { (v.as_f64().unwrap() * 1e8) as u64 } else { 0 }
                } else { 0 };
                let mut has_special = false;
                let wit: Vec<Vec<u8>> = wit_arr[..wit_arr.len() - 1]
                    .iter()
                    .map(|v| {
                        let s = v.as_str().unwrap();
                        if s.starts_with('#') { has_special = true; Vec::new() }
                        else { hex::decode(s).unwrap() }
                    })
                    .collect();
                if has_special { skipped += 1; continue; }
                (wit, arr[1].as_str().unwrap(), spk_str, arr[3].as_str().unwrap(), amount)
            } else {
                if arr.len() < 4 || !arr[0].is_string() { skipped += 1; continue; }
                (Vec::new(), arr[0].as_str().unwrap(), arr[1].as_str().unwrap(),
                 arr[2].as_str().unwrap(), 0u64)
            };

        let mut script_flags = parse_flags(flags_str);
        if script_flags & consensus::flags::VERIFY_CLEANSTACK != 0 {
            script_flags |= consensus::flags::VERIFY_P2SH | consensus::flags::VERIFY_WITNESS;
        }

        // Only use flags recognized by C++ bitcoinconsensus
        let safe_flags = cpp_safe_flags(script_flags);

        let script_sig = parse_script(script_sig_str);
        let script_pubkey = parse_script(script_pubkey_str);

        let credit_tx = build_crediting_tx(&script_pubkey, n_value);
        let spend_tx = build_spending_tx(&script_sig, &witness_items, &credit_tx);
        let tx_bytes = serialize_tx(&spend_tx);

        // Build prev outputs for taproot
        let prevs = vec![(script_pubkey.clone(), n_value)];
        let has_taproot = safe_flags & bitcoinconsensus::VERIFY_TAPROOT != 0;

        let (rust_ok, cpp_ok, ok) = verify_both(
            &script_pubkey,
            n_value,
            &tx_bytes,
            0,
            safe_flags,
            if has_taproot { Some(&prevs) } else { None },
        );

        if ok {
            matched += 1;
        } else {
            mismatched += 1;
            if mismatched <= 5 {
                let comment = arr.last()
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                eprintln!(
                    "DIFF [{}]: rust={} cpp={} flags=0x{:x} sig='{}' pub='{}'",
                    comment, rust_ok, cpp_ok, safe_flags, script_sig_str, script_pubkey_str,
                );
            }
        }
    }

    eprintln!(
        "\nDifferential script_tests: {matched} matched, {mismatched} mismatched, {skipped} skipped out of {total}"
    );
    assert_eq!(mismatched, 0, "{mismatched} differential mismatches in script_tests");
}

// =========================================================================
// Differential test: tx_valid.json
// =========================================================================

fn parse_prevouts_map(inputs: &[Value]) -> Option<(HashMap<(Txid, u32), Vec<u8>>, HashMap<(Txid, u32), i64>)> {
    let mut script_map = HashMap::new();
    let mut value_map = HashMap::new();
    for input in inputs {
        let arr = input.as_array()?;
        if arr.len() < 3 || arr.len() > 4 { return None; }
        let txid_hex = arr[0].as_str()?;
        let txid_bytes = hex::decode(txid_hex).ok()?;
        if txid_bytes.len() != 32 { return None; }
        let mut txid_arr = [0u8; 32];
        for (i, b) in txid_bytes.iter().enumerate() { txid_arr[31 - i] = *b; }
        let txid = Txid::from_byte_array(txid_arr);
        let vout = arr[1].as_u64()? as u32;
        let script = parse_script(arr[2].as_str()?);
        script_map.insert((txid, vout), script);
        if arr.len() >= 4 { value_map.insert((txid, vout), arr[3].as_i64()?); }
    }
    Some((script_map, value_map))
}

fn fill_flags(mut f: u32) -> u32 {
    if f & consensus::flags::VERIFY_CLEANSTACK != 0 { f |= consensus::flags::VERIFY_WITNESS; }
    if f & consensus::flags::VERIFY_WITNESS != 0 { f |= consensus::flags::VERIFY_P2SH; }
    f
}

#[test]
fn differential_tx_valid() {
    let data = include_str!("../test-data/tx_valid.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut matched = 0;
    let mut mismatched = 0;
    let mut skipped = 0;

    for test in &tests {
        let arr = match test.as_array() {
            Some(a) if a.len() == 3 && a[0].is_array() => a,
            _ => { skipped += 1; continue; }
        };
        let inputs = arr[0].as_array().unwrap();
        let tx_hex = match arr[1].as_str() { Some(s) => s, None => { skipped += 1; continue; } };
        let flags_str = match arr[2].as_str() { Some(s) => s, None => { skipped += 1; continue; } };

        let (script_map, value_map) = match parse_prevouts_map(inputs) {
            Some(m) => m, None => { skipped += 1; continue; }
        };
        let tx_bytes = match hex::decode(tx_hex) { Ok(b) => b, Err(_) => { skipped += 1; continue; } };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(tx) => tx, Err(_) => { skipped += 1; continue; }
        };

        let excluded = parse_flags(flags_str);
        let verify_flags = fill_flags(!excluded & consensus::flags::ALL_FLAGS);
        let safe_flags = cpp_safe_flags(verify_flags);
        let has_taproot = safe_flags & bitcoinconsensus::VERIFY_TAPROOT != 0;

        // Build prev_outputs array for all inputs
        let prevs: Vec<(Vec<u8>, u64)> = tx.input.iter().map(|inp| {
            let key = (inp.previous_output.txid, inp.previous_output.vout);
            let spk = script_map.get(&key).cloned().unwrap_or_default();
            let val = value_map.get(&key).copied().unwrap_or(0) as u64;
            (spk, val)
        }).collect();

        let mut all_matched = true;
        for (i, inp) in tx.input.iter().enumerate() {
            let key = (inp.previous_output.txid, inp.previous_output.vout);
            let spk = match script_map.get(&key) { Some(s) => s, None => { all_matched = false; break; } };
            let amount = value_map.get(&key).copied().unwrap_or(0) as u64;

            let (rust_ok, cpp_ok, ok) = verify_both(
                spk, amount, &tx_bytes, i, safe_flags,
                if has_taproot { Some(&prevs) } else { None },
            );
            if !ok {
                all_matched = false;
                eprintln!(
                    "DIFF tx_valid input {i}: rust={rust_ok} cpp={cpp_ok} flags=0x{safe_flags:x} tx={:.40}...",
                    tx_hex,
                );
                break;
            }
        }

        if all_matched { matched += 1; } else { mismatched += 1; }
    }

    eprintln!("Differential tx_valid: {matched} matched, {mismatched} mismatched, {skipped} skipped");
    assert_eq!(mismatched, 0, "{mismatched} differential mismatches in tx_valid");
}

// =========================================================================
// Differential test: tx_invalid.json
// =========================================================================

#[test]
fn differential_tx_invalid() {
    let data = include_str!("../test-data/tx_invalid.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut matched = 0;
    let mut mismatched = 0;
    let mut skipped = 0;

    for test in &tests {
        let arr = match test.as_array() {
            Some(a) if a.len() == 3 && a[0].is_array() => a,
            _ => { skipped += 1; continue; }
        };
        let inputs = arr[0].as_array().unwrap();
        let tx_hex = match arr[1].as_str() { Some(s) => s, None => { skipped += 1; continue; } };
        let flags_str = match arr[2].as_str() { Some(s) => s, None => { skipped += 1; continue; } };

        if flags_str == "BADTX" { skipped += 1; continue; }

        let (script_map, value_map) = match parse_prevouts_map(inputs) {
            Some(m) => m, None => { skipped += 1; continue; }
        };
        let tx_bytes = match hex::decode(tx_hex) { Ok(b) => b, Err(_) => { skipped += 1; continue; } };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(tx) => tx, Err(_) => { skipped += 1; continue; }
        };

        let verify_flags = fill_flags(parse_flags(flags_str));
        let safe_flags = cpp_safe_flags(verify_flags);
        let has_taproot = safe_flags & bitcoinconsensus::VERIFY_TAPROOT != 0;

        let prevs: Vec<(Vec<u8>, u64)> = tx.input.iter().map(|inp| {
            let key = (inp.previous_output.txid, inp.previous_output.vout);
            let spk = script_map.get(&key).cloned().unwrap_or_default();
            let val = value_map.get(&key).copied().unwrap_or(0) as u64;
            (spk, val)
        }).collect();

        // For invalid txs, at least one input should fail in both engines.
        // We verify each input and check that both engines agree on pass/fail.
        let mut all_matched = true;
        for (i, inp) in tx.input.iter().enumerate() {
            let key = (inp.previous_output.txid, inp.previous_output.vout);
            let spk = match script_map.get(&key) { Some(s) => s, None => continue, };
            let amount = value_map.get(&key).copied().unwrap_or(0) as u64;

            let (rust_ok, cpp_ok, ok) = verify_both(
                spk, amount, &tx_bytes, i, safe_flags,
                if has_taproot { Some(&prevs) } else { None },
            );
            if !ok {
                all_matched = false;
                eprintln!(
                    "DIFF tx_invalid input {i}: rust={rust_ok} cpp={cpp_ok} flags=0x{safe_flags:x} tx={:.40}...",
                    tx_hex,
                );
                break;
            }
        }

        if all_matched { matched += 1; } else { mismatched += 1; }
    }

    eprintln!("Differential tx_invalid: {matched} matched, {mismatched} mismatched, {skipped} skipped");
    assert_eq!(mismatched, 0, "{mismatched} differential mismatches in tx_invalid");
}

// =========================================================================
// Differential test: BIP341 key-path spending
// =========================================================================

#[test]
fn differential_bip341_key_path() {
    let data = include_str!("../test-data/bip341_wallet_vectors.json");
    let vectors: Value = serde_json::from_str(data).unwrap();
    let kps = &vectors["keyPathSpending"][0];

    let tx_hex = kps["auxiliary"]["fullySignedTx"].as_str().unwrap();
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let utxos_json = kps["given"]["utxosSpent"].as_array().unwrap();
    let prevs: Vec<(Vec<u8>, u64)> = utxos_json.iter().map(|u| {
        let spk = hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap();
        let amount = u["amountSats"].as_u64().unwrap();
        (spk, amount)
    }).collect();

    let flags = bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_TAPROOT;

    let mut matched = 0;
    let mut mismatched = 0;
    for (i, prev) in prevs.iter().enumerate() {
        let (rust_ok, cpp_ok, ok) = verify_both(
            &prev.0, prev.1, &tx_bytes, i, flags, Some(&prevs),
        );
        if ok {
            matched += 1;
        } else {
            mismatched += 1;
            eprintln!("DIFF BIP341 input {i}: rust={rust_ok} cpp={cpp_ok}");
        }
    }

    eprintln!("Differential BIP341: {matched} matched, {mismatched} mismatched");
    assert_eq!(mismatched, 0);
}
