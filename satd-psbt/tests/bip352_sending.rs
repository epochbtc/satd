//! The output derivation, refereed against BIP 352's own sending vectors.
//!
//! BIP 375 says only "compute the output script as BIP 352 does, substituting
//! the ECDH share for `a·B_scan`". So the arithmetic that decides where a
//! silent payment actually lands belongs to BIP 352, and BIP 352 publishes 28
//! cases for it — outpoint ordering, taproot parity, repeated recipients,
//! degenerate key sums, and the scan limit. Checking against BIP 375's
//! vectors alone would leave all of that untested.
//!
//! The vector file is the one the receive-side index already uses, read from
//! where it lives rather than copied: two copies of a referee are two
//! referees.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{OutPoint, Txid};
use satd_psbt::sp;
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../node-sp-index/tests/vectors/send_and_receive_test_vectors.json");

#[test]
fn bip352_sending_vectors() {
    let secp = Secp256k1::new();
    let doc: Value = serde_json::from_str(VECTORS).expect("the vector file parses");
    let cases = doc.as_array().expect("an array of cases");

    let mut derived_cases = 0usize;
    let mut refused_cases = 0usize;

    for case in cases {
        let comment = case["comment"].as_str().unwrap_or_default();
        for send in case["sending"].as_array().expect("a sending array") {
            let given = &send["given"];
            let expected = &send["expected"];

            let outpoints: Vec<OutPoint> = given["vin"]
                .as_array()
                .expect("vin")
                .iter()
                .map(|v| OutPoint {
                    txid: Txid::from_byte_array(
                        reversed(&hex_bytes(v["txid"].as_str().expect("a txid")))
                            .try_into()
                            .expect("32 bytes"),
                    ),
                    vout: v["vout"].as_u64().expect("a vout") as u32,
                })
                .collect();

            let input_keys: Vec<PublicKey> = expected["input_pub_keys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| public_key(k.as_str().unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            let key_sum = sp::sum_public_keys(input_keys.iter());

            let wanted: Vec<String> = expected["outputs"][0]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|o| o.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();

            // Recipients, expanded by the `count` a vector may attach, and
            // grouped by scan key so each group's `k` counts from zero.
            let mut recipients: Vec<(PublicKey, PublicKey)> = Vec::new();
            for r in given["recipients"].as_array().expect("recipients") {
                let scan = public_key(r["scan_pub_key"].as_str().expect("a scan key"))
                    .expect("a valid scan key");
                let spend = public_key(r["spend_pub_key"].as_str().expect("a spend key"))
                    .expect("a valid spend key");
                let count = r["count"].as_u64().unwrap_or(1);
                for _ in 0..count {
                    recipients.push((scan, spend));
                }
            }

            let secret_sum = expected["input_private_key_sum"]
                .as_str()
                .and_then(|s| SecretKey::from_slice(&hex_bytes(s)).ok());

            if wanted.is_empty() {
                // A vector with no expected outputs is one where sending
                // fails. satd must reach the same conclusion, for one of the
                // three reasons BIP 352 gives.
                let no_contributors = key_sum.is_none();
                let over_limit = recipients
                    .iter()
                    .filter(|(scan, _)| *scan == recipients[0].0)
                    .count()
                    > sp::K_MAX as usize;
                assert!(
                    no_contributors || over_limit || secret_sum.is_none(),
                    "{comment}: expected no outputs, but nothing stops the derivation"
                );
                refused_cases += 1;
                continue;
            }

            let key_sum = key_sum.unwrap_or_else(|| panic!("{comment}: no input keys"));
            let secret_sum =
                secret_sum.unwrap_or_else(|| panic!("{comment}: no input private key sum"));
            let input_hash = sp::input_hash(&outpoints, &key_sum)
                .unwrap_or_else(|| panic!("{comment}: no input hash"));
            let sum_scalar = Scalar::from_be_bytes(secret_sum.secret_bytes()).expect("a scalar");

            // BIP 352 states no ordering within a scan-key group: "for each
            // B_m in the group ... k++", and its only hard requirement is
            // that every k from zero upwards is used, because a receiver
            // stops scanning at the first miss. So the property to check is
            // that some assignment of k = 0..n-1 to the group's recipients
            // reproduces exactly the expected outputs — not that one
            // particular ordering does. BIP 352's own vectors and BIP 375's
            // disagree about which ordering they used, which is precisely why
            // this is the property satd verifies.
            let mut groups: Vec<(PublicKey, Vec<PublicKey>)> = Vec::new();
            for (scan, spend) in &recipients {
                match groups.iter_mut().find(|(s, _)| s == scan) {
                    Some((_, members)) => members.push(*spend),
                    None => groups.push((*scan, vec![*spend])),
                }
            }

            let mut got: Vec<String> = Vec::new();
            for (scan, members) in &groups {
                let ecdh = scan.mul_tweak(&secp, &sum_scalar).expect("a·B_scan");
                let mut taken = vec![false; members.len()];
                for (position, spend) in members.iter().enumerate() {
                    // The k this recipient must have been given: the one whose
                    // derived script is in the expected set and is not already
                    // claimed by an earlier recipient.
                    let mut matched = None;
                    for k in 0..members.len() as u32 {
                        if taken[k as usize] {
                            continue;
                        }
                        let script = sp::derive_output_script(&ecdh, &input_hash, spend, k)
                            .unwrap_or_else(|| panic!("{comment}: no script for k={k}"));
                        let xonly = hex(&script.as_bytes()[2..]);
                        if wanted.contains(&xonly) {
                            taken[k as usize] = true;
                            matched = Some(xonly);
                            break;
                        }
                    }
                    got.push(matched.unwrap_or_else(|| {
                        panic!(
                            "{comment}: recipient {position} matches no expected output under \
                             any unused k"
                        )
                    }));
                }
            }

            got.sort();
            let mut wanted = wanted;
            wanted.sort();
            assert_eq!(got, wanted, "{comment}");
            derived_cases += 1;
        }
    }

    assert!(derived_cases >= 20, "only {derived_cases} cases derived");
    assert!(refused_cases >= 3, "only {refused_cases} refusal cases");
}

/// A 33-byte compressed key, or a 32-byte x-only one lifted to even Y — which
/// is the form BIP 352 says a taproot input contributes.
fn public_key(hex: &str) -> Option<PublicKey> {
    let bytes = hex_bytes(hex);
    match bytes.len() {
        33 => PublicKey::from_slice(&bytes).ok(),
        32 => {
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&bytes);
            PublicKey::from_slice(&compressed).ok()
        }
        _ => None,
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
