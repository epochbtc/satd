//! BIP 322 verification against the BIP's own vectors, btcd's negative
//! vectors, and proofs signed here for the rules those vectors leave out.
//!
//! `testdata/` holds, unmodified:
//! - `basic-test-vectors.json` and `generated-test-vectors.json` from
//!   bitcoin/bips `bip-0322/` at 130b8e0f (sha256 a9184da5… and 187205f7…);
//! - `generated-negative-test-vectors.json` from btcd PR #2521
//!   (guggero/btcd e385217f, `bip322/testdata/`, sha256 03a77c86…), which the
//!   BIP references and whose generator made the BIP's vectors.

use std::cell::Cell;
use std::str::FromStr as _;

use bitcoin::hashes::Hash as _;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Address, Network, ScriptBuf, Witness, opcodes};
use serde_json::Value;

use super::*;

const BASIC: &str = include_str!("testdata/basic-test-vectors.json");
const GENERATED: &str = include_str!("testdata/generated-test-vectors.json");
const NEGATIVE: &str = include_str!("testdata/generated-negative-test-vectors.json");

fn json(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn challenge(address: &str) -> ScriptBuf {
    Address::from_str(address).unwrap().require_network(Network::Bitcoin).unwrap().script_pubkey()
}

/// Decode and verify, folding a decode error into `Invalid` as the BIP's
/// vectors do.
fn check(address: &str, message: &str, signature: &str) -> Verification {
    let spk = challenge(address);
    match decode(signature, &spk) {
        Ok(Signature::Bip322(proof)) => verify(&spk, message.as_bytes(), &proof),
        Ok(Signature::Legacy(_)) => panic!("no legacy vectors here"),
        Err(e) => Verification::Invalid(e.to_string()),
    }
}

#[test]
fn message_hash_and_virtual_transactions_match_the_bip() {
    let v = json(BASIC);
    for case in v["tx_hashes"].as_array().unwrap() {
        let msg = case["message"].as_str().unwrap().as_bytes();
        assert_eq!(hex::encode(message_hash(msg)), case["message_hash"].as_str().unwrap());
        let Some(to_spend_hash) = case["to_spend_tx_hash"].as_str() else { continue };
        let spk = challenge(case["address"].as_str().unwrap());
        let tx = to_spend(&spk, msg);
        assert_eq!(tx.compute_txid().to_string(), to_spend_hash);
        let sign = to_sign(tx.compute_txid(), Witness::new());
        assert_eq!(sign.compute_txid().to_string(), case["to_sign_tx_hash"].as_str().unwrap());
    }
}

#[test]
fn every_simple_and_full_vector_is_valid() {
    let mut n = 0;
    for file in [BASIC, GENERATED] {
        let v = json(file);
        for section in ["simple", "full"] {
            let Some(cases) = v[section].as_array() else { continue };
            for case in cases {
                let address = case["address"].as_str().unwrap();
                let message = case["message"].as_str().unwrap();
                for sig in case["bip322_signatures"].as_array().unwrap() {
                    let got = check(address, message, sig.as_str().unwrap());
                    let want = Verification::Valid {
                        version: case["tx_version"].as_i64().unwrap_or(0) as i32,
                        lock_time: case["lock_time"].as_u64().unwrap_or(0) as u32,
                        sequence: case["sequence"].as_u64().unwrap_or(0) as u32,
                    };
                    assert_eq!(got, want, "{section} {} {address}", case["type"]);
                    n += 1;
                }
            }
        }
    }
    // 2+2+1+1 basic simple, 4 generated simple, 10 generated full.
    assert_eq!(n, 20);
}

#[test]
fn proof_of_funds_vectors_are_refused() {
    let v = json(GENERATED);
    for case in v["proof_of_funds"].as_array().unwrap() {
        let spk = challenge(case["address"].as_str().unwrap());
        for sig in case["bip322_signatures"].as_array().unwrap() {
            assert_eq!(decode(sig.as_str().unwrap(), &spk), Err(DecodeError::ProofOfFunds));
        }
    }
}

#[test]
fn every_error_vector_fails() {
    for file in [BASIC, GENERATED] {
        for case in json(file)["error"].as_array().unwrap() {
            let got = check(
                case["address"].as_str().unwrap(),
                case["message"].as_str().unwrap(),
                case["signature"].as_str().unwrap(),
            );
            assert!(matches!(got, Verification::Invalid(_)), "{}: {got:?}", case["description"]);
        }
    }
}

/// btcd's negative vectors: each has an expected `invalid` or
/// `inconclusive`. A `pof` vector is refused at decode whatever it expects,
/// since this verifier does not take the format.
#[test]
fn btcd_negative_vectors_get_their_expected_result() {
    let (mut seen, mut pof) = (0, 0);
    for case in json(NEGATIVE)["error"].as_array().unwrap() {
        let desc = case["description"].as_str().unwrap();
        let sig = case["signature"].as_str().unwrap();
        if sig.starts_with("pof") {
            let spk = challenge(case["address"].as_str().unwrap());
            assert_eq!(decode(sig, &spk), Err(DecodeError::ProofOfFunds), "{desc}");
            pof += 1;
            continue;
        }
        let got = check(
            case["address"].as_str().unwrap(),
            case["message"].as_str().unwrap(),
            case["signature"].as_str().unwrap(),
        );
        match case["expected_result"].as_str().unwrap() {
            "invalid" => {
                let Verification::Invalid(reason) = &got else { panic!("{desc}: {got:?}") };
                // The rules the BIP's own vectors leave out fail for the
                // stated reason, not by accident.
                if desc.contains("SIGHASH") {
                    assert!(reason.contains("sighash"), "{desc}: {reason}");
                }
                if desc.contains("OP_CODESEPARATOR") {
                    assert!(reason.contains("OP_CODESEPARATOR"), "{desc}: {reason}");
                }
                if desc.contains("non-minimal true") {
                    assert!(reason.contains(ScriptError::MinimalIf.as_str()), "{desc}: {reason}");
                }
            }
            "inconclusive" => {
                assert!(matches!(got, Verification::Inconclusive(_)), "{desc}: {got:?}");
            }
            other => panic!("{desc}: unknown expected_result {other}"),
        }
        seen += 1;
    }
    assert_eq!((seen, pof), (43, 20));
}

// --- Proofs signed here ---------------------------------------------------

const MESSAGE: &[u8] = b"satd bip322 test";

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap()
}

/// A simple P2WPKH proof signed with `hash_type`.
fn p2wpkh_proof(hash_type: EcdsaSighashType) -> (ScriptBuf, Proof) {
    let secp = Secp256k1::new();
    let sk = secret(1);
    let pk = bitcoin::CompressedPublicKey(sk.public_key(&secp));
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let spend = to_spend(&spk, MESSAGE);
    let tx = to_sign(spend.compute_txid(), Witness::new());
    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(0, &spk, Amount::ZERO, hash_type)
        .unwrap();
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk);
    let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: hash_type };
    (spk, Proof::Simple(Witness::p2wpkh(&sig, &pk.0)))
}

/// A simple proof spending a one-leaf Taproot output by its script path.
/// `leaf` takes the x-only key; `hash_type` None is SIGHASH_DEFAULT.
fn tapscript_proof(
    leaf: impl Fn(bitcoin::XOnlyPublicKey) -> ScriptBuf,
    hash_type: Option<TapSighashType>,
) -> (ScriptBuf, Proof) {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &secret(2));
    let (xonly, _) = kp.x_only_public_key();
    let script = leaf(xonly);
    let info = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap().finalize(&secp, xonly).unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
    let spend = to_spend(&spk, MESSAGE);
    let tx = to_sign(spend.compute_txid(), Witness::new());
    let leaf_hash = bitcoin::TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let ty = hash_type.unwrap_or(TapSighashType::Default);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&spend.output), leaf_hash, ty)
        .unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &kp);
    let sig = bitcoin::taproot::Signature { signature: sig, sighash_type: ty };
    let control = info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
    let mut w = Witness::new();
    w.push(sig.to_vec());
    w.push(script.as_bytes());
    w.push(control.serialize());
    (spk, Proof::Simple(w))
}

fn checksig_leaf(xonly: bitcoin::XOnlyPublicKey) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_x_only_key(&xonly)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

#[test]
fn signed_p2wpkh_is_valid_only_with_sighash_all() {
    let (spk, proof) = p2wpkh_proof(EcdsaSighashType::All);
    assert_eq!(verify(&spk, MESSAGE, &proof), Verification::Valid { version: 0, lock_time: 0, sequence: 0 });
    assert!(matches!(verify(&spk, b"other", &proof), Verification::Invalid(_)));
    for ty in [EcdsaSighashType::None, EcdsaSighashType::Single, EcdsaSighashType::AllPlusAnyoneCanPay] {
        let (spk, proof) = p2wpkh_proof(ty);
        let Verification::Invalid(reason) = verify(&spk, MESSAGE, &proof) else { panic!("{ty:?}") };
        assert!(reason.contains("sighash"), "{ty:?}: {reason}");
    }
}

/// The scripts run once for a valid proof, and again under the required
/// flags alone only for one that fails, to tell invalid from inconclusive.
/// Perturbation: run the required flags first, as the BIP lists the steps,
/// and the valid proof runs twice.
#[test]
fn a_valid_proof_runs_its_scripts_once() {
    let runs = |spk: &ScriptBuf, message: &[u8], proof: &Proof| {
        SCRIPT_RUNS.with(|n| n.set(0));
        let got = verify(spk, message, proof);
        (got, SCRIPT_RUNS.with(Cell::get))
    };
    let (spk, proof) = p2wpkh_proof(EcdsaSighashType::All);
    let (got, n) = runs(&spk, MESSAGE, &proof);
    assert!(matches!(got, Verification::Valid { .. }), "{got:?}");
    assert_eq!(n, 1, "a valid proof");
    let (got, n) = runs(&spk, b"other", &proof);
    assert!(matches!(got, Verification::Invalid(_)), "{got:?}");
    assert_eq!(n, 2, "an invalid proof");
    let mut v2 = spk.to_bytes();
    v2[0] = 0x52;
    let (got, n) = runs(&ScriptBuf::from_bytes(v2), MESSAGE, &Proof::Simple(Witness::from_slice(&[vec![1u8]])));
    assert!(matches!(got, Verification::Inconclusive(_)), "{got:?}");
    assert_eq!(n, 2, "an inconclusive proof");
}

/// The `bip322` crate (0.0.12) rejects every Taproot script-path proof; the
/// design counts them, and this verifier runs the interpreter instead.
#[test]
fn signed_tapscript_is_valid_with_default_or_all_only() {
    for ty in [None, Some(TapSighashType::All)] {
        let (spk, proof) = tapscript_proof(checksig_leaf, ty);
        assert_eq!(verify(&spk, MESSAGE, &proof), Verification::Valid { version: 0, lock_time: 0, sequence: 0 }, "{ty:?}");
    }
    for ty in [TapSighashType::None, TapSighashType::Single, TapSighashType::AllPlusAnyoneCanPay] {
        let (spk, proof) = tapscript_proof(checksig_leaf, Some(ty));
        let Verification::Invalid(reason) = verify(&spk, MESSAGE, &proof) else { panic!("{ty:?}") };
        assert!(reason.contains("sighash"), "{ty:?}: {reason}");
    }
}

/// A tapscript leaf with an unexecuted `OP_CODESEPARATOR` is valid by
/// consensus and invalid under BIP 322. Perturbation: drop
/// `forbid_codeseparator` and this proof verifies.
#[test]
fn codeseparator_in_a_tapscript_leaf_is_invalid() {
    let leaf = |x| {
        bitcoin::script::Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_CODESEPARATOR)
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_x_only_key(&x)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    };
    let (spk, proof) = tapscript_proof(leaf, None);
    let Verification::Invalid(reason) = verify(&spk, MESSAGE, &proof) else { panic!() };
    assert!(reason.contains("OP_CODESEPARATOR"), "{reason}");
}

/// An `OP_SUCCESS` leaf is anyone-can-spend by consensus and upgradeable
/// under BIP 322.
#[test]
fn op_success_leaf_is_inconclusive() {
    let leaf = |_| ScriptBuf::from_bytes(vec![0x50]);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &secret(3));
    let (xonly, _) = kp.x_only_public_key();
    let script = leaf(xonly);
    let info = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap().finalize(&secp, xonly).unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
    let control = info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
    let w = Witness::from_slice(&[script.to_bytes(), control.serialize()]);
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Simple(w)), Verification::Inconclusive(_)));
}

#[test]
fn unknown_witness_version_is_inconclusive() {
    // OP_2 <32 bytes>: witness v2, anyone-can-spend today.
    let mut spk = vec![0x52, 32];
    spk.extend_from_slice(&[7; 32]);
    let spk = ScriptBuf::from_bytes(spk);
    let proof = Proof::Simple(Witness::from_slice(&[vec![1u8]]));
    assert!(matches!(verify(&spk, MESSAGE, &proof), Verification::Inconclusive(_)));
}

#[test]
fn full_structure_rules() {
    let (spk, Proof::Simple(w)) = p2wpkh_proof(EcdsaSighashType::All) else { unreachable!() };
    let txid = to_spend(&spk, MESSAGE).compute_txid();
    let good = to_sign(txid, w);
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Full(good.clone())), Verification::Valid { .. }));

    let mut two_inputs = good.clone();
    two_inputs.input.push(two_inputs.input[0].clone());
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Full(two_inputs)), Verification::Invalid(_)));

    let mut paying = good.clone();
    paying.output[0].value = Amount::from_sat(1);
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Full(paying)), Verification::Invalid(_)));

    let mut wrong_prevout = good.clone();
    wrong_prevout.input[0].previous_output.vout = 1;
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Full(wrong_prevout)), Verification::Invalid(_)));

    // Version 1 or 3 is upgradeable: the signature itself is checked first,
    // and this one (made for version 0) fails before the version is read.
    let mut v3 = good;
    v3.version = Version(3);
    assert!(matches!(verify(&spk, MESSAGE, &Proof::Full(v3)), Verification::Invalid(_)));
}

#[test]
fn simple_is_refused_for_non_native_segwit() {
    let (_, proof) = p2wpkh_proof(EcdsaSighashType::All);
    let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(vec![0x51]).script_hash());
    let Verification::Invalid(reason) = verify(&p2sh, MESSAGE, &proof) else { panic!() };
    assert!(reason.contains("native segwit"), "{reason}");
}

#[test]
fn decode_reads_prefixes_and_the_unprefixed_fallback() {
    let (spk, Proof::Simple(w)) = p2wpkh_proof(EcdsaSighashType::All) else { unreachable!() };
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bitcoin::consensus::serialize(&w));
    let want = Signature::Bip322(Proof::Simple(w));
    assert_eq!(decode(&format!("smp{b64}"), &spk), Ok(want.clone()));
    assert_eq!(decode(&b64, &spk), Ok(want));
    assert_eq!(decode(&format!("pof{b64}"), &spk), Err(DecodeError::ProofOfFunds));
    assert_eq!(decode("smp!!!", &spk), Err(DecodeError::Base64));

    // Unprefixed for a P2PKH challenge is Core's legacy format.
    let p2pkh = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::all_zeros());
    assert_eq!(decode("AAAA", &p2pkh), Ok(Signature::Legacy(vec![0, 0, 0])));
}
