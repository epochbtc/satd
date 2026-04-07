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

type DiffScriptMap = HashMap<(Txid, u32), Vec<u8>>;
type DiffValueMap = HashMap<(Txid, u32), i64>;

fn parse_prevouts_map(inputs: &[Value]) -> Option<(DiffScriptMap, DiffValueMap)> {
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

// =========================================================================
// Differential test: P2SH-P2WPKH with non-standard sighash type (0x65)
//
// These are real mainnet transactions that were accepted by Bitcoin Core
// (libbitcoinconsensus) but rejected by the Rust verifier due to the
// sighash byte 0x65 being normalised to SIGHASH_ALL (0x01) in the BIP143
// preimage.  Bitcoin Core hashes the raw byte.
// =========================================================================

#[test]
fn differential_p2sh_p2wpkh_nonstandard_sighash() {
    // Flags matching block height 508k+ (post-segwit, pre-taproot)
    let flags = bitcoinconsensus::VERIFY_P2SH
        | bitcoinconsensus::VERIFY_DERSIG
        | bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY
        | bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY
        | bitcoinconsensus::VERIFY_WITNESS
        | bitcoinconsensus::VERIFY_NULLDUMMY;

    // (spend_tx_hex, prev_scriptpubkey_hex, prev_value_sats)
    let cases: &[(&str, &str, u64)] = &[
        // Height 508011: txid 969c4f116f0a68406d30dc80bf17991fb8fe7fa1b240382baefa2c324b79d50d
        // P2SH-P2WPKH, sighash byte 0x65
        (
            "01000000000101447e208868dbc8e930fc6eba4fe0d0abfe0d9dc2db4ba70542e02467f00205c9\
             0100000017160014e20c60563894174c253ae937ba59ace46ab9ffb1ffffffff010845f3050000\
             00001976a91414ac7fc2a782bde1555b753d75ff4ed146683cae88ac024730440220120003c32c\
             ca7eabf07bad5c31125accc09d13c39546fa93833b8b69a2c72ed7022057083dc2ed348156874b\
             8af859ac7a9c16e5ce39353f3f1ac2226b49c2b319af652103f73386ac6e567581f8d0611ad7a8\
             536c3cd0253e535f6fc4707514b2ab54198700000000",
            "a914e93f9e95f6d5cb1736a94de992d0d18819072fa587",
            99830000,
        ),
        // Height 508417: txid 76e43164383ea18ce4246beb08911b5650e174d2474cd9447f17418789ca4fbc
        // P2SH-P2WPKH, sighash byte 0x65
        (
            "01000000000101bb00b6b6a8f3a8160fb225dab4d81333fdc7b4af0bd41c1038369abfcc0aeecb\
             01000000171600145f15287308b7ed72571b7714ee9373ef5e0eab09ffffffff0158090300000000\
             001976a914b118683467b55901940767755d75a399e9c06c3488ac0247304402200f5bb587f6f01d\
             e296ef38a2cb2a78f5b6644dc3b5981a92169dac6b24c9682a02207b498fef6b4490086b25a9d65f\
             67ff35cfe2a3df8434486827905f930de812d965210320a3feab5802c0437c30380c03e9bb88a288\
             fa6f8492c1e0554448ccd657fa2e00000000",
            "a9147b4ee983fcded1f39e10456b25c24d372302c4e787",
            200000,
        ),
        // Height 509676: txid 702c51fb615d167de25f6e6efe706a3bd41ad3dd3151805a896ccb1f2462b66b
        // P2SH-P2WPKH, sighash byte 0x65
        (
            "0100000000010174a12ba10cb582a325c00bbcaf62b3138aab20d970cb359d07afef3c3bfaea9a\
             00000000171600144d581ecd16580411e1597f69c649a286540d4c36ffffffff0168bf00000000\
             00001976a914b138fe0cd7753ea419771e1a5c29af2111ea502488ac0247304402207e6a3da1c3\
             1156fe89fbd957061ef1af9382c36a0db11bdd06b850a62decd65a02206668c198c74594914b0a\
             f2e12493cd2d65c01d64df16e1d3934599cdde372d28652103225c519aafb783537e3c6b9cdd78\
             505bac11dc20dccb886311a32436e3d03eca00000000",
            "a914d8e00ebe7d7a8eb6859e6bc54715ddf318e5a81187",
            50000,
        ),
        // Height 509793: txid 3b2c470760c48c14036084acad104e8e4e7c224d8267e01d65e21175dfe3a5bb
        // P2SH-P2WPKH, sighash byte 0x65 (72-byte sig)
        (
            "01000000000101af9be42538e888f901528c9172f3024f630ae555873492167a77a4e2fdfe50a8\
             0000000017160014abb2fe16026f9030fb9a32c25be43430dbf20d75ffffffff01f88f04000000\
             00001976a91460e494ac538f27143186a518cd2c6443ab14bea388ac02483045022100f47becda\
             4d3f0bb483b377c17e650aad5678668d4a2f055bcde89d70aa5dc0fe022020cf2fe3ff345e10fd\
             89a4d8549d006b6be661a09b16451cd55f3add1724736d652103f558c5a39d140bf550a62e79e5\
             4db80edc6f18112f5f0270ea5b406b2b60111f00000000",
            "a914a32dad06254107467726feb5c59cbb5d5f28529587",
            300000,
        ),
    ];

    let mut matched = 0;
    let mut mismatched = 0;

    for (i, &(tx_hex, spk_hex, value)) in cases.iter().enumerate() {
        let tx_bytes = hex::decode(tx_hex).unwrap();
        let spk = hex::decode(spk_hex).unwrap();

        let prevs = vec![(spk.clone(), value)];
        let (rust_ok, cpp_ok, ok) = verify_both(
            &spk, value, &tx_bytes, 0, flags, Some(&prevs),
        );

        if ok {
            matched += 1;
        } else {
            mismatched += 1;
            eprintln!(
                "DIFF nonstandard_sighash case {i}: rust={rust_ok} cpp={cpp_ok} flags=0x{flags:x}"
            );
        }
    }

    eprintln!(
        "Differential nonstandard_sighash: {matched} matched, {mismatched} mismatched out of {}",
        cases.len()
    );
    assert_eq!(mismatched, 0, "{mismatched} mismatches in nonstandard sighash test");
}
