//! Bitcoin Core's `script_assets_test` (src/test/script_assets_tests.cpp),
//! ported to the Rust interpreter.
//!
//! The vectors are the ones Core's `test/functional/feature_taproot.py
//! --dumptests` writes, minimized by
//! `src/test/fuzz/script_assets_test_minimizer.cpp` and published as
//! `unit_test_data/script_assets_test.json` in the bitcoin-core/qa-assets
//! repository (2244 vectors at qa-assets b33d8510). Each vector is a
//! transaction, the outputs it spends, an input index, a flag set, and a
//! `success` and/or `failure` (scriptSig, witness) pair for that input.
//!
//! Two sources are run:
//! - `test-data/script_assets_test_subset.json`, committed here: for each
//!   distinct `comment` in Core's file, its smallest vector, plus every
//!   `opsuccess/*` vector, leaving out vectors over 100 kB (which drops only
//!   `tapscript/bigmulti`). Lines are copied unmodified from Core's file.
//!   225 vectors covering 160 of the 161 comments.
//! - Core's full file, when `DIR_UNIT_TEST_DATA` names a directory holding
//!   `script_assets_test.json`. That is the variable Core's own test reads.
//!
//! Every verification is checked against the vector's expected verdict, and
//! the same input is also run through libbitcoinconsensus (Core's own
//! interpreter, via the `bitcoinconsensus` crate) as a check on this harness.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::{ScriptBuf, Transaction, TxOut, Witness};
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use serde_json::Value;

/// Core's `ParseScriptFlags` for the names the asset file uses.
fn parse_flags(s: &str) -> u32 {
    let mut out = 0;
    for name in s.split(',').filter(|n| !n.is_empty()) {
        out |= match name {
            "P2SH" => flags::VERIFY_P2SH,
            "DERSIG" => flags::VERIFY_DERSIG,
            "NULLDUMMY" => flags::VERIFY_NULLDUMMY,
            "CHECKLOCKTIMEVERIFY" => flags::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => flags::VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => flags::VERIFY_WITNESS,
            "TAPROOT" => flags::VERIFY_TAPROOT,
            other => panic!("unexpected flag {other:?} in script assets"),
        };
    }
    out
}

/// Core's `AllConsensusFlags()`: every combination of the seven consensus
/// flags in which WITNESS implies P2SH and TAPROOT implies WITNESS.
fn all_consensus_flags() -> Vec<u32> {
    let bits = [
        flags::VERIFY_P2SH,
        flags::VERIFY_DERSIG,
        flags::VERIFY_NULLDUMMY,
        flags::VERIFY_CHECKLOCKTIMEVERIFY,
        flags::VERIFY_CHECKSEQUENCEVERIFY,
        flags::VERIFY_WITNESS,
        flags::VERIFY_TAPROOT,
    ];
    let mut ret = Vec::new();
    for i in 0u32..128 {
        let f = bits
            .iter()
            .enumerate()
            .filter(|(b, _)| i & (1 << b) != 0)
            .fold(0, |acc, (_, flag)| acc | flag);
        if f & flags::VERIFY_WITNESS != 0 && f & flags::VERIFY_P2SH == 0 {
            continue;
        }
        if f & flags::VERIFY_TAPROOT != 0 && f & flags::VERIFY_WITNESS == 0 {
            continue;
        }
        ret.push(f);
    }
    ret
}

/// One verification whose verdict differs from the vector's.
struct Failure {
    comment: String,
    expect_ok: bool,
    flags: u32,
    engine: &'static str,
    got: String,
}

/// Core's `AssetTest`. Returns how many verifications ran.
fn asset_test(test: &Value, all_flags: &[u32], failures: &mut Vec<Failure>) -> usize {
    let tx_bytes = hex::decode(test["tx"].as_str().unwrap()).unwrap();
    let mut tx = Transaction::consensus_decode(&mut tx_bytes.as_slice()).unwrap();
    let prevouts: Vec<TxOut> = test["prevouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let b = hex::decode(p.as_str().unwrap()).unwrap();
            TxOut::consensus_decode(&mut b.as_slice()).unwrap()
        })
        .collect();
    assert_eq!(prevouts.len(), tx.input.len());
    let idx = test["index"].as_u64().unwrap() as usize;
    let test_flags = parse_flags(test["flags"].as_str().unwrap());
    let fin = test.get("final").and_then(Value::as_bool).unwrap_or(false);
    let comment = test["comment"].as_str().unwrap_or("").to_string();
    let spk = prevouts[idx].script_pubkey.as_bytes().to_vec();
    let mut runs = 0;

    for (key, expect_ok) in [("success", true), ("failure", false)] {
        let Some(case) = test.get(key) else { continue };
        let script_sig = hex::decode(case["scriptSig"].as_str().unwrap()).unwrap();
        let witness: Vec<Vec<u8>> = case["witness"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| hex::decode(e.as_str().unwrap()).unwrap())
            .collect();
        tx.input[idx].script_sig = ScriptBuf::from_bytes(script_sig.clone());
        tx.input[idx].witness = Witness::from_slice(&witness);
        let checker = TxSignatureChecker::new(&tx, idx, prevouts[idx].value, &prevouts);

        let mut ser = Vec::new();
        tx.consensus_encode(&mut ser).unwrap();
        let utxos: Vec<bitcoinconsensus::Utxo> = prevouts
            .iter()
            .map(|p| bitcoinconsensus::Utxo {
                script_pubkey: p.script_pubkey.as_bytes().as_ptr(),
                script_pubkey_len: p.script_pubkey.len() as u32,
                value: p.value.to_sat() as i64,
            })
            .collect();

        for &f in all_flags {
            // A "final" success holds under every flag set, any other success
            // under every subset of the vector's flags. A failure must hold
            // under every superset of the vector's flags.
            let applies = if expect_ok {
                fin || (f & test_flags) == f
            } else {
                (f & test_flags) == test_flags
            };
            if !applies {
                continue;
            }
            runs += 1;
            let res = verify_script(&script_sig, &spk, &witness, f, &checker);
            if res.is_ok() != expect_ok {
                failures.push(Failure {
                    comment: comment.clone(),
                    expect_ok,
                    flags: f,
                    engine: "rust",
                    got: format!("{res:?}"),
                });
            }
            let cpp = bitcoinconsensus::verify_with_flags(
                &spk,
                prevouts[idx].value.to_sat(),
                &ser,
                Some(&utxos),
                idx,
                f,
            );
            if cpp.is_ok() != expect_ok {
                failures.push(Failure {
                    comment: comment.clone(),
                    expect_ok,
                    flags: f,
                    engine: "libbitcoinconsensus",
                    got: format!("{cpp:?}"),
                });
            }
        }
    }
    runs
}

/// Run every vector; print the wrong verdicts grouped by vector comment and
/// return how many there were.
fn run_assets(source: &str, tests: &[Value]) -> usize {
    let all_flags = all_consensus_flags();
    let mut failures = Vec::new();
    let mut runs = 0;
    for t in tests {
        runs += asset_test(t, &all_flags, &mut failures);
    }

    let mut grouped: BTreeMap<(String, &str, bool, String), (usize, u32)> = BTreeMap::new();
    for f in &failures {
        let e = grouped
            .entry((f.comment.clone(), f.engine, f.expect_ok, f.got.clone()))
            .or_insert((0, f.flags));
        e.0 += 1;
    }
    for ((comment, engine, expect_ok, got), (n, first_flags)) in &grouped {
        eprintln!(
            "FAIL [{comment}] {engine}: expected {}, got {got} ({n}x, first under flags {first_flags:#x})",
            if *expect_ok { "success" } else { "failure" },
        );
    }
    eprintln!(
        "{source}: {} vectors, {runs} verifications, {} wrong verdicts",
        tests.len(),
        failures.len()
    );
    failures.len()
}

#[test]
fn script_assets_subset() {
    let data = include_str!("../test-data/script_assets_test_subset.json");
    let tests: Vec<Value> = serde_json::from_str(data).unwrap();
    assert_eq!(tests.len(), 225);
    let wrong = run_assets("script_assets_test_subset.json", &tests);
    assert_eq!(wrong, 0, "{wrong} wrong verdicts (see above)");
}

/// Core's full asset file, run when `DIR_UNIT_TEST_DATA` is set, as Core's
/// `script_assets_test` does. Skipped, with a note, otherwise.
#[test]
fn script_assets_full() {
    let Some(dir) = std::env::var_os("DIR_UNIT_TEST_DATA") else {
        eprintln!("DIR_UNIT_TEST_DATA unset, skipping script_assets_full");
        return;
    };
    let path = PathBuf::from(dir).join("script_assets_test.json");
    if !path.exists() {
        eprintln!("{} not found, skipping script_assets_full", path.display());
        return;
    }
    let data = std::fs::read_to_string(&path).unwrap();
    let tests: Vec<Value> = serde_json::from_str(&data).unwrap();
    assert!(!tests.is_empty());
    let wrong = run_assets("script_assets_test.json", &tests);
    assert_eq!(wrong, 0, "{wrong} wrong verdicts (see above)");
}
