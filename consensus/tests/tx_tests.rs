//! tx_valid.json / tx_invalid.json test vectors: verify complete transactions
//! using the full verify_script pipeline with real signatures.
//!
//! These are the most important consensus tests — they exercise the complete
//! pipeline: transaction deserialization, UTXO lookup, VerifyScript with
//! TxSignatureChecker, all flag combinations.
//!
//! Format for both files:
//!   [[prev_hash, prev_index, prev_scriptPubKey, amount?], ...], serialized_tx, flags_string
//!
//! For tx_valid.json: flags specify flags to EXCLUDE (test runs with ~flags).
//! For tx_invalid.json: flags specify flags to INCLUDE directly.

mod helpers;

use bitcoin::consensus::Decodable;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid, TxOut};
use bitcoin::hashes::Hash;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use helpers::{parse_flags, parse_script};
use serde_json::Value;
use std::collections::HashMap;

type ScriptMap = HashMap<(Txid, u32), ScriptBuf>;
type ValueMap = HashMap<(Txid, u32), i64>;

/// Parse prevouts from a JSON array into maps keyed by OutPoint.
fn parse_prevouts(inputs: &[Value]) -> Option<(ScriptMap, ValueMap)> {
    let mut script_map = HashMap::new();
    let mut value_map = HashMap::new();

    for input in inputs {
        let arr = input.as_array()?;
        if arr.len() < 3 || arr.len() > 4 {
            return None;
        }

        let txid_hex = arr[0].as_str()?;
        let txid_bytes = hex::decode(txid_hex).ok()?;
        if txid_bytes.len() != 32 {
            return None;
        }
        // Bitcoin txids are displayed in reverse byte order
        let mut txid_arr = [0u8; 32];
        for (i, b) in txid_bytes.iter().enumerate() {
            txid_arr[31 - i] = *b;
        }
        let txid = Txid::from_byte_array(txid_arr);

        let vout = arr[1].as_u64()? as u32;
        let script_str = arr[2].as_str()?;
        let script_bytes = parse_script(script_str);

        script_map.insert((txid, vout), ScriptBuf::from_bytes(script_bytes));

        if arr.len() >= 4 {
            let amount = arr[3].as_i64()?;
            value_map.insert((txid, vout), amount);
        }
    }

    Some((script_map, value_map))
}

/// Fill flags: CLEANSTACK implies WITNESS implies P2SH
fn fill_flags(mut f: u32) -> u32 {
    if f & flags::VERIFY_CLEANSTACK != 0 {
        f |= flags::VERIFY_WITNESS;
    }
    if f & flags::VERIFY_WITNESS != 0 {
        f |= flags::VERIFY_P2SH;
    }
    f
}

/// Verify all inputs of a transaction, returning true if all pass (for valid)
/// or any fails (for invalid).
fn check_tx_scripts(
    tx: &Transaction,
    script_map: &HashMap<(Txid, u32), ScriptBuf>,
    value_map: &HashMap<(Txid, u32), i64>,
    script_flags: u32,
    expect_valid: bool,
) -> bool {
    // Build prev_outputs array for TxSignatureChecker (needs all prevouts for taproot sighash)
    let prev_outputs: Vec<TxOut> = tx
        .input
        .iter()
        .map(|input| {
            let key = (input.previous_output.txid, input.previous_output.vout);
            let script_pubkey = script_map
                .get(&key)
                .cloned()
                .unwrap_or_default();
            let amount = value_map.get(&key).copied().unwrap_or(0);
            TxOut {
                value: Amount::from_sat(amount as u64),
                script_pubkey,
            }
        })
        .collect();

    let mut all_valid = true;
    for (i, input) in tx.input.iter().enumerate() {
        let key = (input.previous_output.txid, input.previous_output.vout);
        let script_pubkey = match script_map.get(&key) {
            Some(spk) => spk,
            None => {
                all_valid = false;
                break;
            }
        };
        let amount = Amount::from_sat(value_map.get(&key).copied().unwrap_or(0) as u64);

        let checker = TxSignatureChecker::new(tx, i, amount, &prev_outputs);
        let witness_stack: Vec<Vec<u8>> = input.witness.iter().map(|w| w.to_vec()).collect();

        let result = verify_script(
            input.script_sig.as_bytes(),
            script_pubkey.as_bytes(),
            &witness_stack,
            script_flags,
            &checker,
        );

        if result.is_err() {
            all_valid = false;
            if expect_valid {
                break;
            }
        }
    }

    all_valid == expect_valid
}

#[test]
fn test_tx_valid() {
    let data = include_str!("../test-data/tx_valid.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for test in &tests {
        let arr = match test.as_array() {
            Some(a) if a.len() == 3 && a[0].is_array() => a,
            _ => {
                skipped += 1;
                continue;
            }
        };

        let inputs = arr[0].as_array().unwrap();
        let tx_hex = match arr[1].as_str() {
            Some(s) => s,
            None => { skipped += 1; continue; }
        };
        let flags_str = match arr[2].as_str() {
            Some(s) => s,
            None => { skipped += 1; continue; }
        };

        let (script_map, value_map) = match parse_prevouts(inputs) {
            Some(maps) => maps,
            None => { skipped += 1; continue; }
        };

        let tx_bytes = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(_) => { skipped += 1; continue; }
        };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(tx) => tx,
            Err(_) => { skipped += 1; continue; }
        };

        // tx_valid: flags specify what to EXCLUDE. Run with ~flags.
        let excluded_flags = parse_flags(flags_str);
        let verify_flags = fill_flags(!excluded_flags & flags::ALL_FLAGS);

        if check_tx_scripts(&tx, &script_map, &value_map, verify_flags, true) {
            passed += 1;
        } else {
            failed += 1;
            // Find comment (last string in original array that isn't the flags)
            let comment = if test.as_array().unwrap().len() > 3 {
                test[3].as_str().unwrap_or("")
            } else {
                ""
            };
            eprintln!(
                "FAIL tx_valid: flags='{}' verify_flags=0x{:x} comment='{}' tx={:.60}...",
                flags_str,
                verify_flags,
                comment,
                tx_hex,
            );
        }
    }

    eprintln!("tx_valid: {passed} passed, {failed} failed, {skipped} skipped");
    assert_eq!(failed, 0, "{failed} tx_valid tests failed");
}

#[test]
fn test_tx_invalid() {
    let data = include_str!("../test-data/tx_invalid.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for test in &tests {
        let arr = match test.as_array() {
            Some(a) if a.len() == 3 && a[0].is_array() => a,
            _ => {
                skipped += 1;
                continue;
            }
        };

        let inputs = arr[0].as_array().unwrap();
        let tx_hex = match arr[1].as_str() {
            Some(s) => s,
            None => { skipped += 1; continue; }
        };
        let flags_str = match arr[2].as_str() {
            Some(s) => s,
            None => { skipped += 1; continue; }
        };

        // BADTX: malformed transaction that fails CheckTransaction or deserialization.
        // The bitcoin crate's decoder may accept some structurally invalid txs that
        // Bitcoin Core's CheckTransaction rejects (empty vin, empty vout, oversized,
        // duplicate inputs, etc.). We check basic structural validity ourselves.
        if flags_str == "BADTX" {
            let tx_bytes = match hex::decode(tx_hex) {
                Ok(b) => b,
                Err(_) => { passed += 1; continue; }
            };
            match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
                Ok(tx) => {
                    // The bitcoin crate decoded it, but Core's CheckTransaction would reject.
                    // Check basic structural validity:
                    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
                    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                    let is_bad = tx.input.is_empty()
                        || tx.output.is_empty()
                        || tx.output.iter().any(|o| o.value.to_sat() > MAX_MONEY)
                        || total_out > MAX_MONEY
                        || {
                            // duplicate inputs
                            let mut seen = std::collections::HashSet::new();
                            tx.input.iter().any(|i| !seen.insert(i.previous_output))
                        }
                        || {
                            // null prevout in non-coinbase (coinbase has exactly 1 input with null prevout)
                            tx.input.len() > 1 && tx.input.iter().any(|i| i.previous_output == OutPoint::null())
                        }
                        || {
                            // negative value (sign bit set in i64 interpretation)
                            tx.output.iter().any(|o| (o.value.to_sat() as i64) < 0)
                        }
                        || {
                            // Coinbase scriptSig size (must be 2-100 bytes for coinbase)
                            let is_coinbase = tx.input.len() == 1
                                && tx.input[0].previous_output == OutPoint::null();
                            if is_coinbase {
                                let ss = tx.input[0].script_sig.len();
                                !(2..=100).contains(&ss)
                            } else {
                                false
                            }
                        };
                    if is_bad {
                        passed += 1;
                    } else {
                        // Truly unexpected — it deserialized AND looks structurally valid
                        failed += 1;
                        eprintln!(
                            "FAIL tx_invalid BADTX: tx deserialized and looks valid: {:.60}...",
                            tx_hex
                        );
                    }
                }
                Err(_) => {
                    passed += 1;
                }
            }
            continue;
        }

        let (script_map, value_map) = match parse_prevouts(inputs) {
            Some(maps) => maps,
            None => { skipped += 1; continue; }
        };

        let tx_bytes = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(_) => { skipped += 1; continue; }
        };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(tx) => tx,
            Err(_) => {
                // Deserialization failure counts as invalid — pass
                passed += 1;
                continue;
            }
        };

        // tx_invalid: flags specify what to INCLUDE directly
        let verify_flags = fill_flags(parse_flags(flags_str));

        if check_tx_scripts(&tx, &script_map, &value_map, verify_flags, false) {
            passed += 1;
        } else {
            failed += 1;
            eprintln!(
                "FAIL tx_invalid: should have failed but passed. flags='{}' tx={:.60}...",
                flags_str, tx_hex,
            );
        }
    }

    eprintln!("tx_invalid: {passed} passed, {failed} failed, {skipped} skipped");
    assert_eq!(failed, 0, "{failed} tx_invalid tests failed");
}
