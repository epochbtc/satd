mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use helpers::{parse_expected_error, parse_flags, parse_script};
use serde_json::Value;

/// Build a crediting transaction that pays `value` to `script_pubkey`.
/// Matches Bitcoin Core's `BuildCreditingTransaction`.
fn build_crediting_tx(script_pubkey: &[u8], value: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]), // OP_0 OP_0
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    }
}

/// Build a spending transaction that spends the crediting tx's output.
/// Matches Bitcoin Core's `BuildSpendingTransaction`.
fn build_spending_tx(
    script_sig: &[u8],
    witness: &[Vec<u8>],
    credit_tx: &Transaction,
) -> Transaction {
    let mut w = Witness::new();
    for item in witness {
        w.push(item);
    }

    // Compute the txid of the credit tx
    let mut buf = Vec::new();
    credit_tx.consensus_encode(&mut buf).unwrap();
    let txid = Txid::from_byte_array(
        bitcoin::hashes::sha256d::Hash::hash(&buf).to_byte_array(),
    );

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

/// Run ALL script_tests.json using synthetic crediting/spending transactions
/// and the real TxSignatureChecker, exactly as Bitcoin Core does.
#[test]
fn test_script_vectors() {
    let data = include_str!("../test-data/script_tests.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut total = 0;

    for test in &tests {
        if test.is_string() {
            continue;
        }

        let arr = test.as_array().unwrap();

        total += 1;

        // Parse witness format vs standard format
        let (witness_items, script_sig_str, script_pubkey_str, flags_str, expected_error_str, n_value) =
            if arr[0].is_array() {
                if arr.len() < 5 {
                    skipped += 1;
                    continue;
                }
                let wit_arr = arr[0].as_array().unwrap();
                let script_pubkey_str = arr[2].as_str().unwrap();

                // Skip auto-generated taproot tests
                if script_pubkey_str.contains("#TAPROOTOUTPUT#") {
                    skipped += 1;
                    continue;
                }

                // Last element of witness array is the amount
                let amount = if let Some(v) = wit_arr.last() {
                    if v.is_number() {
                        (v.as_f64().unwrap() * 100_000_000.0) as u64
                    } else {
                        0
                    }
                } else {
                    0
                };

                // All elements except the last are witness stack items (hex)
                // Skip tests using #SCRIPT# or #CONTROLBLOCK# syntax
                let mut has_special = false;
                let wit: Vec<Vec<u8>> = wit_arr[..wit_arr.len() - 1]
                    .iter()
                    .map(|v| {
                        let s = v.as_str().unwrap();
                        if s.starts_with('#') {
                            has_special = true;
                            Vec::new()
                        } else {
                            hex::decode(s).unwrap_or_else(|e| {
                                panic!("Bad witness hex '{s}': {e}");
                            })
                        }
                    })
                    .collect();

                if has_special {
                    skipped += 1;
                    continue;
                }

                (
                    wit,
                    arr[1].as_str().unwrap(),
                    script_pubkey_str,
                    arr[3].as_str().unwrap(),
                    arr[4].as_str().unwrap(),
                    amount,
                )
            } else {
                if arr.len() < 4 || !arr[0].is_string() {
                    skipped += 1;
                    continue;
                }
                (
                    Vec::new(),
                    arr[0].as_str().unwrap(),
                    arr[1].as_str().unwrap(),
                    arr[2].as_str().unwrap(),
                    arr[3].as_str().unwrap(),
                    0u64,
                )
            };

        if false {
            // All non-autogenerated tests should pass
            skipped += 1;
            continue;
        }

        let mut script_flags = parse_flags(flags_str);
        let expected = parse_expected_error(expected_error_str);

        // Bitcoin Core implicitly adds P2SH+WITNESS when CLEANSTACK is set
        if script_flags & flags::VERIFY_CLEANSTACK != 0 {
            script_flags |= flags::VERIFY_P2SH | flags::VERIFY_WITNESS;
        }

        let script_sig = parse_script(script_sig_str);
        let script_pubkey = parse_script(script_pubkey_str);

        // Build synthetic transactions (same as Bitcoin Core's test harness)
        let credit_tx = build_crediting_tx(&script_pubkey, n_value);
        let spend_tx = build_spending_tx(&script_sig, &witness_items, &credit_tx);

        // Build prev outputs for the checker (single input spending credit_tx output 0)
        let prev_outputs = vec![credit_tx.output[0].clone()];

        let checker = TxSignatureChecker::new(
            &spend_tx,
            0,
            credit_tx.output[0].value,
            &prev_outputs,
        );

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            &witness_items,
            script_flags,
            &checker,
        );

        let actual_err = match &result {
            Ok(()) => ScriptError::Ok,
            Err(e) => *e,
        };

        if actual_err == expected {
            passed += 1;
        } else {
            failed += 1;
            let comment = if arr.last().unwrap().is_string() {
                arr.last().unwrap().as_str().unwrap_or("")
            } else {
                ""
            };
            eprintln!(
                "FAIL [{}]: expected={:?} got={:?}  sig='{}' pub='{}' flags='{}'",
                comment, expected, actual_err, script_sig_str, script_pubkey_str, flags_str,
            );
        }
    }

    eprintln!(
        "\nScript tests: {passed} passed, {failed} failed, {skipped} skipped out of {total} total"
    );
    assert_eq!(
        failed, 0,
        "{failed} script tests failed (see output above)"
    );
}

/// Smoke test: verify_script with 1+2=3
#[test]
fn test_verify_basic() {
    let checker = consensus::checker::NoopChecker;
    let sig = vec![0x51, 0x52, 0x93];
    let pubkey = vec![0x53, 0x87];
    verify_script(&sig, &pubkey, &[], 0, &checker).unwrap();
}

/// P2SH test: scriptPubKey=HASH160 <hash> EQUAL, redeemScript=OP_1
#[test]
fn test_verify_p2sh() {
    let checker = consensus::checker::NoopChecker;
    let redeem = vec![0x51u8];
    let hash = {
        use sha2::Digest;
        let sha = sha2::Sha256::digest(&redeem);
        let mut hasher = ripemd::Ripemd160::new();
        ripemd::Digest::update(&mut hasher, sha);
        let h: [u8; 20] = ripemd::Digest::finalize(hasher).into();
        h
    };
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&hash);
    script_pubkey.push(0x87);
    let mut script_sig = vec![redeem.len() as u8];
    script_sig.extend_from_slice(&redeem);
    verify_script(&script_sig, &script_pubkey, &[], flags::VERIFY_P2SH, &checker).unwrap();
}

/// Disabled opcode fails even in dead branch
#[test]
fn test_verify_disabled_in_dead_branch() {
    let checker = consensus::checker::NoopChecker;
    let pubkey = vec![0x00, 0x63, 0x7e, 0x68, 0x51];
    let result = verify_script(&[], &pubkey, &[], 0, &checker);
    assert_eq!(result, Err(ScriptError::DisabledOpcode));
}

/// OP_RETURN fails
#[test]
fn test_verify_op_return() {
    let checker = consensus::checker::NoopChecker;
    let result = verify_script(&[], &[0x6a], &[], 0, &checker);
    assert_eq!(result, Err(ScriptError::OpReturn));
}
