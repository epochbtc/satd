//! BIP 352 **sending**-side parity for the test-only sender in
//! `tests/common/sp_send.rs`.
//!
//! `node-sp-index` is checked against the receiving half of the vendored
//! vectors. This checks the sending half, against the same file. Without it the
//! sender would only ever be validated by our own scanner finding its outputs —
//! which proves the two agree, not that either matches the spec.
//!
//! Cases whose inputs this sender does not model are skipped **loudly**: the
//! test prints what it skipped and asserts a floor on how many it actually
//! exercised, so a refactor that quietly stops covering anything fails here
//! rather than going green over nothing.

mod common;

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, Txid};
use common::sp_send::{sp_outputs, SpInput, SpRecipient};
use serde_json::Value;

fn vectors_path() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/satd for this crate.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("node-sp-index/tests/vectors/send_and_receive_test_vectors.json")
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    assert_eq!(v.len(), 32, "want 32 bytes, got {}", v.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Is this prevout a P2TR output? BIP 352 needs the even-Y private key for
/// taproot inputs, and the vectors carry the scriptPubKey to tell.
fn is_p2tr(spk_hex: &str) -> bool {
    let b = hex::decode(spk_hex).unwrap_or_default();
    b.len() == 34 && b[0] == 0x51 && b[1] == 0x20
}

/// BIP 341's NUMS point `H`, x-only.
const NUMS_H: [u8; 32] =
    hex_literal_nums(b"50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

const fn hex_literal_nums(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nib(s[i * 2]);
        let lo = hex_nib(s[i * 2 + 1]);
        out[i] = hi << 4 | lo;
        i += 1;
    }
    out
}

const fn hex_nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

/// Split a serialized witness (`count || (len || bytes)*`) into its elements.
fn witness_elements(hex_str: &str) -> Vec<Vec<u8>> {
    let b = match hex::decode(hex_str) {
        Ok(b) if !b.is_empty() => b,
        _ => return Vec::new(),
    };
    // The vectors only ever use single-byte compact sizes here.
    let mut out = Vec::new();
    let mut i = 1usize;
    for _ in 0..b[0] {
        if i >= b.len() {
            return Vec::new();
        }
        let n = b[i] as usize;
        i += 1;
        if i + n > b.len() {
            return Vec::new();
        }
        out.push(b[i..i + n].to_vec());
        i += n;
    }
    out
}

/// Split a scriptSig made only of data pushes into those pushes. Returns what it
/// managed to parse; the vectors' scriptSigs are all push-only.
fn push_elements(b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let op = b[i];
        i += 1;
        let n = match op {
            0x01..=0x4b => op as usize,
            0x4c => {
                if i >= b.len() {
                    break;
                }
                let n = b[i] as usize;
                i += 1;
                n
            }
            _ => break,
        };
        if i + n > b.len() {
            break;
        }
        out.push(b[i..i + n].to_vec());
        i += n;
    }
    out
}

/// Does this input contribute a key to `A_sum`?
///
/// BIP 352 excludes a taproot **script-path** spend whose control block names
/// the NUMS point `H` as the internal key: there is no key-path owner, so the
/// input contributes nothing. Its outpoint still counts for the `input_hash`
/// tiebreak, which is why the sender takes the eligible inputs and the full
/// outpoint list separately.
fn contributes_a_key(spk_hex: &str, witness_hex: &str, script_sig_hex: &str) -> bool {
    if !is_p2tr(spk_hex) {
        // BIP 352 also excludes any input spending with an UNCOMPRESSED public
        // key. The key lives in the witness for the segwit types and in the
        // scriptSig for P2PKH.
        let spk = hex::decode(spk_hex).unwrap_or_default();
        let is_p2pkh = spk.len() == 25 && spk[0] == 0x76 && spk[1] == 0xa9;
        let is_p2sh = spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14;
        if is_p2sh {
            // Only P2SH-P2WPKH contributes: the scriptSig must push exactly the
            // redeemScript `0014<20-byte keyhash>`. Anything else is a P2SH
            // wrapping something this scheme does not key on.
            let sig_pushes = push_elements(&hex::decode(script_sig_hex).unwrap_or_default());
            let redeem_ok = sig_pushes
                .last()
                .map(|r| r.len() == 22 && r[0] == 0x00 && r[1] == 0x14)
                .unwrap_or(false);
            if !redeem_ok {
                return false;
            }
        }
        let pubkey = if is_p2pkh {
            push_elements(&hex::decode(script_sig_hex).unwrap_or_default()).pop()
        } else {
            witness_elements(witness_hex).into_iter().nth(1)
        };
        return match pubkey {
            Some(pk) => pk.len() == 33,
            // Nothing to inspect: treat as contributing and let the vector say.
            None => true,
        };
    }
    let mut els = witness_elements(witness_hex);
    // A trailing element beginning with 0x50 is the annex, not part of the spend.
    if els.len() >= 2 && els.last().map(|e| e.first() == Some(&0x50)).unwrap_or(false) {
        els.pop();
    }
    if els.len() < 2 {
        return true; // key-path spend
    }
    let control = els.last().expect("non-empty");
    if control.len() < 33 {
        return true;
    }
    control[1..33] != NUMS_H
}

/// Does this sender model every input of the case?
///
/// The vectors include inputs with no private key (not the sender's), and
/// eligibility rules this test-only sender deliberately does not implement
/// (uncompressed keys, future-segwit witness versions, `OP_RETURN` prevouts).
/// Those cases are skipped rather than half-supported.
fn supported(vin: &[Value]) -> bool {
    vin.iter().all(|v| {
        let Some(sk) = v.get("private_key").and_then(Value::as_str) else {
            return false;
        };
        if hex::decode(sk).map(|b| b.len()) != Ok(32) {
            return false;
        }
        let spk = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap_or_default();
        let b = hex::decode(spk).unwrap_or_default();
        // P2TR, P2WPKH, P2PKH, or P2SH-P2WPKH — the eligible input types with a
        // straightforward single-key spend.
        is_p2tr(spk)
            || (b.len() == 22 && b[0] == 0x00 && b[1] == 0x14)
            || (b.len() == 25 && b[0] == 0x76 && b[1] == 0xa9)
            || (b.len() == 23 && b[0] == 0xa9 && b[1] == 0x14)
    })
}

#[test]
fn bip352_sending_vectors() {
    let raw = std::fs::read_to_string(vectors_path()).expect("vendored BIP 352 vectors");
    let cases: Vec<Value> = serde_json::from_str(&raw).expect("vectors parse");
    let secp = Secp256k1::new();

    let mut exercised = 0usize;
    let mut skipped: Vec<String> = Vec::new();

    for case in &cases {
        let comment = case["comment"].as_str().unwrap_or("<no comment>").to_string();
        for send in case["sending"].as_array().into_iter().flatten() {
            let vin = send["given"]["vin"].as_array().expect("vin").clone();
            if !supported(&vin) {
                skipped.push(comment.clone());
                continue;
            }

            let mut inputs = Vec::new();
            let mut all_outpoints = Vec::new();
            for v in &vin {
                let txid = Txid::from_str(v["txid"].as_str().expect("txid")).expect("txid parse");
                let vout = v["vout"].as_u64().expect("vout") as u32;
                let op = OutPoint { txid, vout };
                // Every outpoint counts for the input_hash tiebreak, including
                // those of inputs that contribute no key.
                all_outpoints.push(op);

                let spk = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap_or_default();
                let witness = v["txinwitness"].as_str().unwrap_or_default();
                let script_sig = v["scriptSig"].as_str().unwrap_or_default();
                if !contributes_a_key(spk, witness, script_sig) {
                    continue;
                }

                let secret = SecretKey::from_slice(&hex32(
                    v["private_key"].as_str().expect("private_key"),
                ))
                .expect("secret");
                inputs.push(SpInput { outpoint: op, secret, is_taproot: is_p2tr(spk) });
            }
            if inputs.is_empty() {
                skipped.push(format!("{comment} (no contributing inputs)"));
                continue;
            }

            let recipients: Vec<SpRecipient> = send["given"]["recipients"]
                .as_array()
                .expect("recipients")
                .iter()
                .map(|r| SpRecipient {
                    scan_pubkey: PublicKey::from_str(
                        r["scan_pub_key"].as_str().expect("scan_pub_key"),
                    )
                    .expect("scan pubkey"),
                    spend_pubkey: PublicKey::from_str(
                        r["spend_pub_key"].as_str().expect("spend_pub_key"),
                    )
                    .expect("spend pubkey"),
                })
                .collect();

            // `expected.outputs` is a list of ALTERNATIVES (the vectors allow
            // more than one valid ordering); a match against any one is a pass.
            let alternatives: Vec<BTreeSet<String>> = send["expected"]["outputs"]
                .as_array()
                .expect("outputs")
                .iter()
                .map(|alt| {
                    alt.as_array()
                        .expect("alternative is a list")
                        .iter()
                        .map(|o| o.as_str().expect("output hex").to_ascii_lowercase())
                        .collect()
                })
                .collect();

            // A case with no expected outputs is a "must not send" case; this
            // sender would panic rather than return an empty set, so skip it.
            if alternatives.iter().all(|a| a.is_empty()) {
                skipped.push(format!("{comment} (no expected outputs)"));
                continue;
            }

            let Some(derived) = sp_outputs(&secp, &inputs, &all_outpoints, &recipients) else {
                // BIP 352 "cannot send" (input keys sum to infinity). The
                // vectors express this as an empty expected-output set, which
                // the branch above already skipped, so reaching here with a
                // non-empty expectation is a real failure.
                panic!("{comment}: sender reported 'cannot send' but the vectors expect {alternatives:?}");
            };
            let got: BTreeSet<String> =
                derived.iter().map(|x| hex::encode(x.serialize())).collect();

            assert!(
                alternatives.contains(&got),
                "sending vector mismatch for {comment}\n  got:      {got:?}\n  expected: {alternatives:?}"
            );
            exercised += 1;
        }
    }

    eprintln!("BIP 352 sending vectors: {exercised} exercised, {} skipped", skipped.len());
    for s in &skipped {
        eprintln!("  skipped: {s}");
    }
    // A floor that can actually fail. `exercised > 0` would be satisfied by a
    // single trivial case; the vectors carry many multi-input and
    // multi-recipient sends, and silently dropping to a handful would mean this
    // file no longer validates the sender it exists to validate.
    //
    // At the time of writing this is 25 of 28, and all three skips are cases
    // with no expected outputs at all (no contributing inputs, input keys
    // summing to infinity, K_max exceeded) — i.e. the sender covers every case
    // that actually sends. The floor is set just below that so a vendored-vector
    // update has slack, but a filter regression does not.
    assert!(
        exercised >= 20,
        "only {exercised} sending vectors exercised — the support filter has \
         narrowed and this test is no longer meaningfully validating the sender"
    );
}

/// The hand-rolled `(a + b) mod n` is the one piece of arithmetic here not
/// borrowed from `secp256k1`, and the sending vectors only exercise it
/// incidentally. Pin its two edges directly.
#[test]
fn scalar_addition_reduces_at_the_curve_order() {
    use common::sp_send::scalar_add_mod_n_for_test as add;

    const N_MINUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;

    // (n-1) + 1 == 0 mod n — the wrap that a plain 256-bit add gets wrong.
    assert_eq!(add(&N_MINUS_1, &one), [0u8; 32], "n-1 + 1 must reduce to zero");
    // (n-1) + 2 == 1 mod n.
    assert_eq!(add(&N_MINUS_1, &two), one, "n-1 + 2 must reduce to one");
    // No reduction below n.
    assert_eq!(add(&one, &two), { let mut t = [0u8; 32]; t[31] = 3; t }, "1 + 2 == 3");
    // Identity.
    assert_eq!(add(&[0u8; 32], &N_MINUS_1), N_MINUS_1, "0 is the identity");
}
