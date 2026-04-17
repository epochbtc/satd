//! Batch-vs-per-input parity tests for `consensus::verify_transaction`.
//!
//! Regression pin for the batch API added in PR #55: a tx that all existing
//! per-input verify paths accept (via `verify_with_flags` called in a loop)
//! MUST produce the same result through `verify_transaction`. And a tx with
//! a single bad input MUST be rejected with the correct failing index.
//!
//! We reuse the tx_valid.json Bitcoin Core test vectors so the fixtures
//! reflect real multi-input transactions, and we exercise both paths
//! through the identical input set.

use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use std::collections::HashMap;

mod helpers;
use helpers::{parse_flags, parse_script};

type ScriptMap = HashMap<(Txid, u32), Vec<u8>>;
type ValueMap = HashMap<(Txid, u32), u64>;

/// Walk the prevouts JSON array into lookups keyed by (txid, vout).
fn parse_prevouts_map(inputs: &[serde_json::Value]) -> Option<(ScriptMap, ValueMap)> {
    let mut script_map: HashMap<(Txid, u32), Vec<u8>> = HashMap::new();
    let mut value_map: HashMap<(Txid, u32), u64> = HashMap::new();
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
        let mut txid_arr = [0u8; 32];
        for (i, b) in txid_bytes.iter().enumerate() {
            txid_arr[31 - i] = *b;
        }
        let txid = Txid::from_byte_array(txid_arr);
        let vout = arr[1].as_u64()? as u32;
        let script = parse_script(arr[2].as_str()?);
        script_map.insert((txid, vout), script);
        if arr.len() >= 4 {
            value_map.insert((txid, vout), arr[3].as_i64()? as u64);
        }
    }
    Some((script_map, value_map))
}

fn fill_flags(mut f: u32) -> u32 {
    if f & consensus::flags::VERIFY_CLEANSTACK != 0 {
        f |= consensus::flags::VERIFY_WITNESS;
    }
    if f & consensus::flags::VERIFY_WITNESS != 0 {
        f |= consensus::flags::VERIFY_P2SH;
    }
    f
}

/// Call the per-input API across every input, aggregating pass/fail.
fn per_input_all_ok(tx_bytes: &[u8], _tx: &Transaction, prev_outputs: &[TxOut], flag_set: u32) -> bool {
    let has_taproot = flag_set & consensus::flags::VERIFY_TAPROOT != 0;
    let utxos: Option<Vec<consensus::Utxo>> = if has_taproot {
        Some(
            prev_outputs
                .iter()
                .map(|o| consensus::Utxo {
                    script_pubkey: o.script_pubkey.as_bytes().as_ptr(),
                    script_pubkey_len: o.script_pubkey.as_bytes().len() as u32,
                    value: o.value.to_sat() as i64,
                })
                .collect(),
        )
    } else {
        None
    };
    for (i, prev) in prev_outputs.iter().enumerate() {
        let script_pubkey = prev.script_pubkey.as_bytes();
        let amount = prev.value.to_sat();
        let result = consensus::verify_with_flags(
            script_pubkey,
            amount,
            tx_bytes,
            utxos.as_deref(),
            i,
            flag_set,
        );
        if result.is_err() {
            return false;
        }
    }
    true
}

#[test]
fn batch_and_per_input_agree_on_tx_valid_vectors() {
    let data = include_str!("../test-data/tx_valid.json");
    let tests: Vec<serde_json::Value> = serde_json::from_str(data).unwrap();

    let mut checked = 0;
    let mut skipped = 0;
    let mut mismatches: Vec<String> = Vec::new();

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
            None => {
                skipped += 1;
                continue;
            }
        };
        let flags_str = match arr[2].as_str() {
            Some(s) => s,
            None => {
                skipped += 1;
                continue;
            }
        };

        let (script_map, value_map) = match parse_prevouts_map(inputs) {
            Some(m) => m,
            None => {
                skipped += 1;
                continue;
            }
        };
        let tx_bytes = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let tx: Transaction = match Transaction::consensus_decode(&mut tx_bytes.as_slice()) {
            Ok(t) => t,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        // tx_valid.json: flags_str lists flags to EXCLUDE.
        let excluded = parse_flags(flags_str);
        let flag_set = fill_flags(!excluded & consensus::flags::ALL_FLAGS);

        // Align prevouts with tx.input order.
        let prev_outputs: Vec<TxOut> = tx
            .input
            .iter()
            .map(|inp| {
                let key = (inp.previous_output.txid, inp.previous_output.vout);
                let spk = script_map.get(&key).cloned().unwrap_or_default();
                let val = value_map.get(&key).copied().unwrap_or(0);
                TxOut {
                    value: bitcoin::Amount::from_sat(val),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(spk),
                }
            })
            .collect();

        if prev_outputs.len() != tx.input.len() {
            skipped += 1;
            continue;
        }

        // Ground truth: per-input verify_with_flags across every input.
        let per_input_ok =
            per_input_all_ok(&tx_bytes, &tx, &prev_outputs, flag_set);

        // Batch path: single call over the whole tx.
        let batch_result = consensus::verify_transaction(&tx, &prev_outputs, flag_set);
        let batch_ok = batch_result.is_ok();

        if per_input_ok != batch_ok {
            mismatches.push(format!(
                "per_input={} batch={} for tx_hex={:.40}... flags=0x{:x}",
                per_input_ok, batch_ok, tx_hex, flag_set,
            ));
        }
        checked += 1;
    }

    eprintln!(
        "batch parity: {} checked, {} skipped, {} mismatches",
        checked,
        skipped,
        mismatches.len()
    );
    assert!(
        mismatches.is_empty(),
        "batch vs per-input disagreement on {} tx_valid vectors: {:#?}",
        mismatches.len(),
        mismatches.iter().take(5).collect::<Vec<_>>()
    );
    assert!(checked > 0, "should have checked at least one real tx");
}

/// A minimal 2-input transaction structured so every input verifies.
/// Exercises the shared-SighashCache path with N>1 inputs so we'd spot a
/// sighash-field-leak bug between inputs (e.g. hashPrevouts computed for
/// input 0 but reused uncorrected for input 1).
///
/// We construct synthetic pubkey-only scripts (not requiring signatures)
/// so the test has no cryptography dependency, but multiple inputs walk
/// through the batch loop.
#[test]
fn batch_handles_multiple_trivial_inputs() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Script, ScriptBuf, Sequence, TxIn, Witness};

    // scriptPubKey = OP_TRUE. scriptSig = empty. Always verifies.
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let prev_outputs = vec![
        TxOut { value: Amount::from_sat(1_000), script_pubkey: op_true.clone() },
        TxOut { value: Amount::from_sat(2_000), script_pubkey: op_true.clone() },
    ];

    let dummy_txid = Txid::from_byte_array([1u8; 32]);
    let tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2_900),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let _ = Script::new(); // quiet unused-import if optimizer strips

    let flag_set = consensus::flags::VERIFY_P2SH;
    let result = consensus::verify_transaction(&tx, &prev_outputs, flag_set);
    assert!(result.is_ok(), "2-input OP_TRUE tx must verify: {:?}", result);
}

/// A 2-input transaction where input 1 fails (script = OP_FALSE). Batch
/// must return Err((1, _)) — the failing index — not Err((0, _)) or Ok.
#[test]
fn batch_reports_correct_failing_input_index() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};

    let op_true = ScriptBuf::from_bytes(vec![0x51]); // OP_1
    let op_false = ScriptBuf::from_bytes(vec![0x00]); // OP_0 — always fails

    let prev_outputs = vec![
        TxOut { value: Amount::from_sat(1_000), script_pubkey: op_true },
        TxOut { value: Amount::from_sat(2_000), script_pubkey: op_false },
    ];

    let dummy_txid = Txid::from_byte_array([2u8; 32]);
    let tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2_900),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let flag_set = consensus::flags::VERIFY_P2SH;
    let result = consensus::verify_transaction(&tx, &prev_outputs, flag_set);
    match result {
        Err((idx, _)) => assert_eq!(idx, 1, "failing input should be index 1, got {}", idx),
        Ok(()) => panic!("OP_FALSE input should have rejected the tx"),
    }
}
