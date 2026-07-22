//! BIP 352 test-vector parity for the `node-sp-index` kernel.
//!
//! Vendored `send_and_receive_test_vectors.json` (BIP 352 v1.1.0). We
//! exercise the **receiving** side of every case — the node/index and
//! scan-key paths — against the vectors' expected `input_pub_key_sum`,
//! `tweak`, and matched `outputs`. Parity against these vectors (not
//! self-consistency) is the correctness bar (design §1 fact 10).
//!
//! For each receiving entry:
//!   * build a transaction from `given.vin` + `given.outputs`;
//!   * `eligible_inputs` sum must equal `input_pub_key_sum` (when the
//!     case is eligible);
//!   * `compute_tweak` must equal `expected.tweak` (or `None` when the
//!     case has no valid inputs / an infinity pubkey sum, i.e. a null
//!     expected tweak);
//!   * `scan_outputs` must find exactly the expected outputs (or the
//!     expected count, for the `K_max` case).

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, consensus, transaction::Version,
};
use node_sp_index::{compute_tweak, eligible_inputs, scan_outputs};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/send_and_receive_test_vectors.json");

fn hexbytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn witness_from_hex(s: &str) -> Witness {
    if s.is_empty() {
        return Witness::new();
    }
    consensus::deserialize(&hex::decode(s).unwrap()).unwrap()
}

/// Taproot scriptPubKey (`OP_1 <32-byte x-only>`) for an output key hex.
fn p2tr_spk(xonly_hex: &str) -> ScriptBuf {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend_from_slice(&hex::decode(xonly_hex).unwrap());
    ScriptBuf::from_bytes(bytes)
}

/// Build a transaction and the aligned prevout scriptPubKeys from a
/// receiving test's `given` block.
fn build_tx(given: &Value) -> (Transaction, Vec<ScriptBuf>) {
    let mut input = Vec::new();
    let mut prevouts = Vec::new();
    for vin in given["vin"].as_array().unwrap() {
        let txid = Txid::from_str(vin["txid"].as_str().unwrap()).unwrap();
        let vout = vin["vout"].as_u64().unwrap() as u32;
        input.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::from_bytes(hexbytes(&vin["scriptSig"])),
            sequence: Sequence::MAX,
            witness: witness_from_hex(vin["txinwitness"].as_str().unwrap()),
        });
        prevouts.push(ScriptBuf::from_bytes(hexbytes(
            &vin["prevout"]["scriptPubKey"]["hex"],
        )));
    }
    // Outputs: the scanned taproot outputs, as real P2TR scriptPubKeys.
    let output: Vec<TxOut> = given["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: p2tr_spk(o.as_str().unwrap()),
        })
        .collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    };
    (tx, prevouts)
}

#[test]
fn bip352_receiving_vectors() {
    let secp = Secp256k1::new();
    let cases: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(!cases.is_empty(), "no vectors loaded");

    let mut checked_eligible = 0usize;
    let mut checked_null = 0usize;
    let mut checked_labels = 0usize;

    for case in &cases {
        let comment = case["comment"].as_str().unwrap();
        for recv in case["receiving"].as_array().unwrap() {
            let given = &recv["given"];
            let expected = &recv["expected"];
            let (tx, prevouts) = build_tx(given);

            let pubkeys = eligible_inputs(&tx, &prevouts);
            let entry = compute_tweak(&tx, &prevouts);

            match expected["tweak"].as_str() {
                None => {
                    // Null expected tweak: no valid inputs, or the input
                    // pubkey sum is the point at infinity → not indexable.
                    assert!(
                        entry.is_none(),
                        "[{comment}] expected no tweak but compute_tweak produced one"
                    );
                    // These cases carry no input_pub_key_sum.
                    assert!(
                        expected.get("input_pub_key_sum").is_none(),
                        "[{comment}] unexpected input_pub_key_sum on a null-tweak case"
                    );
                    checked_null += 1;
                    continue;
                }
                Some(expected_tweak) => {
                    // Eligible: the input pubkey sum must match.
                    let refs: Vec<&PublicKey> = pubkeys.iter().collect();
                    let a_sum = PublicKey::combine_keys(&refs)
                        .unwrap_or_else(|_| panic!("[{comment}] pubkey sum is infinity"));
                    assert_eq!(
                        hex::encode(a_sum.serialize()),
                        expected["input_pub_key_sum"].as_str().unwrap(),
                        "[{comment}] input_pub_key_sum mismatch"
                    );

                    let entry =
                        entry.unwrap_or_else(|| panic!("[{comment}] expected a tweak, got None"));
                    assert_eq!(
                        hex::encode(entry.tweak.serialize()),
                        expected_tweak,
                        "[{comment}] tweak mismatch"
                    );
                    checked_eligible += 1;

                    // Scan the outputs with the receiver's keys.
                    let b_scan =
                        SecretKey::from_slice(&hexbytes(&given["key_material"]["scan_priv_key"]))
                            .unwrap();
                    let b_spend_priv =
                        SecretKey::from_slice(&hexbytes(&given["key_material"]["spend_priv_key"]))
                            .unwrap();
                    let b_spend = b_spend_priv.public_key(&secp);
                    let label_ms: Vec<u32> = given["labels"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|l| l.as_u64().unwrap() as u32)
                        .collect();
                    if !label_ms.is_empty() {
                        checked_labels += 1;
                    }
                    let outputs: Vec<XOnlyPublicKey> = given["outputs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|o| XOnlyPublicKey::from_slice(&hexbytes(o)).unwrap())
                        .collect();

                    let matches =
                        scan_outputs(&entry.tweak, &b_scan, &b_spend, &label_ms, &outputs);

                    if let Some(exp_outputs) = expected.get("outputs").and_then(|v| v.as_array()) {
                        // Detailed check: (pub_key, priv_key_tweak) set parity.
                        let got: BTreeSet<(String, String)> = matches
                            .iter()
                            .map(|m| {
                                (
                                    hex::encode(m.output.serialize()),
                                    hex::encode(m.priv_key_tweak),
                                )
                            })
                            .collect();
                        let want: BTreeSet<(String, String)> = exp_outputs
                            .iter()
                            .map(|o| {
                                (
                                    o["pub_key"].as_str().unwrap().to_string(),
                                    o["priv_key_tweak"].as_str().unwrap().to_string(),
                                )
                            })
                            .collect();
                        assert_eq!(got, want, "[{comment}] matched outputs mismatch");
                    } else if let Some(n) = expected.get("n_outputs").and_then(|v| v.as_u64()) {
                        // K_max case: only the count is asserted.
                        assert_eq!(
                            matches.len() as u64,
                            n,
                            "[{comment}] matched output count mismatch"
                        );
                    } else {
                        panic!("[{comment}] receiving expected has neither outputs nor n_outputs");
                    }
                }
            }
        }
    }

    // Guard that the suite actually exercised the edge classes it claims
    // to — a silently-empty run would otherwise pass.
    assert!(checked_eligible >= 20, "too few eligible cases checked");
    assert!(checked_null >= 2, "null-tweak cases not exercised");
    assert!(checked_labels >= 3, "labeled cases not exercised");
}
