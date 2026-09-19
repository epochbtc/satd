//! Binding an input's public key to the output it spends.
//!
//! BIP 375's reference validator reads an input's public key out of the first
//! `PSBT_IN_BIP32_DERIVATION` entry and never checks it against the previous
//! output's script (`validator/inputs.py:pubkey_from_eligible_input`). A PSBT
//! can therefore name any key it likes, produce a DLEQ proof that verifies
//! against that key, derive the output script from it, and pass every check —
//! while the transaction actually spends a different key, so the recipient
//! scans for an output that was never created and the money is gone.
//!
//! The whole test below is that attack, built step by step, with satd refusing
//! at the end and the reference's rule accepting.

mod common;

use bitcoin::hashes::{Hash, hash160};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, ScriptBuf, TxOut};
use satd_psbt::raw::{RawPair, RawPsbt};
use satd_psbt::sp::{self, KeyBinding, OutputStatus, ScriptState};
use satd_psbt::{V2View, keys};

/// A vector, rewritten so that each input's `witness_utxo` really is the
/// P2WPKH output its declared key unlocks.
///
/// The derivation depends on the outpoints and the public keys, not on the
/// previous outputs' scripts, so this changes nothing the shares or proofs
/// commit to — it only makes the PSBT internally honest, the way a PSBT from
/// a real wallet is.
fn bound_vector(prefix: &str) -> RawPsbt {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with(prefix))
        .unwrap_or_else(|| panic!("no vector starting {prefix:?}"));
    let mut raw = RawPsbt::parse(&v.psbt).expect("the vector parses");

    for input in &mut raw.inputs {
        let key = input
            .get_all(keys::input::BIP32_DERIVATION)
            .next()
            .map(|(key, _)| key.to_vec())
            .expect("the vector's inputs declare a key");
        let value = input
            .get_single(keys::input::WITNESS_UTXO)
            .map(|raw| {
                bitcoin::consensus::deserialize::<TxOut>(raw)
                    .expect("a TxOut")
                    .value
            })
            .unwrap_or(Amount::from_sat(100_000));
        let script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
            hash160::Hash::hash(&key).to_byte_array(),
        ));
        input.set(RawPair::new(
            keys::input::WITNESS_UTXO,
            Vec::new(),
            bitcoin::consensus::serialize(&TxOut {
                value,
                script_pubkey: script,
            }),
        ));
        input.remove_type(keys::input::NON_WITNESS_UTXO);
    }
    raw
}

/// The premise: with each key bound to the output it spends, satd's strict
/// rule reaches the same verdict as the reference's loose one. Without this,
/// the test below would prove only that satd refuses things.
#[test]
fn a_bound_key_is_ready_under_both_rules() {
    let raw = bound_vector("can finalize: two inputs single-signer using per-input");
    let view = V2View::new(&raw).unwrap();

    for binding in [KeyBinding::Required, KeyBinding::Declared] {
        let report = sp::verify_with_binding(&view, None, binding).expect("verifies");
        assert_eq!(report.eligible_inputs().len(), 2, "{binding:?}");
        for output in &report.outputs {
            assert_eq!(output.status, OutputStatus::Ready, "{binding:?}: {output:?}");
            assert_eq!(output.script_state, ScriptState::Matches, "{binding:?}");
        }
        assert!(report.extractable(), "{binding:?}");
    }
}

/// The attack. Input 0's declared key is replaced with one the attacker holds,
/// its ECDH share and DLEQ proof are regenerated so the proof is genuinely
/// valid for that key, and the output script is recomputed from the new key
/// set so the PSBT is internally consistent.
///
/// The reference validator's rule accepts the result: every proof verifies,
/// every script matches its derivation. satd refuses, because input 0's key
/// does not hash to the output input 0 spends — so whatever that PSBT is
/// describing, it is not this transaction.
#[test]
fn a_rebound_key_is_not_ready() {
    let secp = Secp256k1::new();
    let mut raw = bound_vector("can finalize: two inputs single-signer using per-input");

    // The attacker's key, and a share and proof that are correct for it.
    let attacker = SecretKey::from_slice(&[0x9au8; 32]).expect("a secret");
    let attacker_pub = PublicKey::from_secret_key(&secp, &attacker);

    let scan_key = {
        let view = V2View::new(&raw).unwrap();
        view.sp_scan_keys().unwrap()[0]
    };
    let share = scan_key
        .mul_tweak(
            &secp,
            &bitcoin::secp256k1::Scalar::from_be_bytes(attacker.secret_bytes()).unwrap(),
        )
        .expect("a·B_scan");
    let proof = satd_psbt::dleq::generate_proof(&attacker, &scan_key, &[0x5au8; 32], None)
        .expect("a proof");
    assert!(
        satd_psbt::dleq::verify_proof(&attacker_pub, &scan_key, &share, &proof, None),
        "the attacker's proof is genuinely valid for the attacker's key"
    );

    // Swap it into input 0, leaving its previous output — and therefore the
    // key that actually signs — alone.
    let derivation_value = raw.inputs[0]
        .get_all(keys::input::BIP32_DERIVATION)
        .next()
        .map(|(_, value)| value.to_vec())
        .expect("a derivation");
    raw.inputs[0].remove_type(keys::input::BIP32_DERIVATION);
    raw.inputs[0]
        .insert(RawPair::new(
            keys::input::BIP32_DERIVATION,
            attacker_pub.serialize().to_vec(),
            derivation_value,
        ))
        .expect("the map has no such key now");
    raw.inputs[0].set(RawPair::new(
        keys::input::SP_ECDH_SHARE,
        scan_key.serialize().to_vec(),
        share.serialize().to_vec(),
    ));
    raw.inputs[0].set(RawPair::new(
        keys::input::SP_DLEQ,
        scan_key.serialize().to_vec(),
        proof.to_vec(),
    ));

    // Recompute the output script from the tampered key set, so the PSBT is
    // internally consistent — which is what makes this an attack rather than
    // a typo.
    let derived = {
        let view = V2View::new(&raw).unwrap();
        let report =
            sp::verify_with_binding(&view, None, KeyBinding::Declared).expect("verifies");
        report.outputs[0]
            .derived_script
            .clone()
            .expect("a derived script")
    };
    let output_index = {
        let view = V2View::new(&raw).unwrap();
        let report =
            sp::verify_with_binding(&view, None, KeyBinding::Declared).expect("verifies");
        report.outputs[0].index
    };
    raw.outputs[output_index].set(RawPair::new(
        keys::output::SCRIPT,
        Vec::new(),
        derived.to_bytes(),
    ));

    let view = V2View::new(&raw).unwrap();

    // The reference validator's rule: everything checks out.
    let loose = sp::verify_with_binding(&view, None, KeyBinding::Declared).expect("verifies");
    assert_eq!(loose.outputs[0].status, OutputStatus::Ready);
    assert_eq!(loose.outputs[0].script_state, ScriptState::Matches);
    assert!(
        loose.extractable(),
        "the reference's rule accepts this PSBT, which is the problem"
    );

    // satd's rule, with the input's own signature still there to pin the real
    // key: the share proves something about a key that is not this input's.
    let strict = sp::verify(&view, None).expect("verifies");
    assert_eq!(
        strict.outputs[0].status,
        OutputStatus::InvalidProof,
        "{:?}",
        strict.outputs[0]
    );
    assert!(!strict.extractable());
    assert_eq!(
        strict.outputs[0].invalid_inputs.first().map(|(i, _)| *i),
        Some(0),
        "the verdict should name the input"
    );

    // And with nothing left in the PSBT to pin the real key, satd says so
    // rather than trusting what it is told.
    let mut stripped = raw.clone();
    stripped.inputs[0].remove_type(keys::input::PARTIAL_SIG);
    stripped.inputs[0].remove_type(keys::input::FINAL_SCRIPTWITNESS);
    let view = V2View::new(&stripped).unwrap();
    let strict = sp::verify(&view, None).expect("verifies");
    assert_eq!(
        strict.outputs[0].status,
        OutputStatus::Unverifiable,
        "{:?}",
        strict.outputs[0]
    );
    assert!(!strict.extractable());
    let reason = strict.outputs[0].reason.clone().unwrap_or_default();
    assert!(
        reason.contains("input 0") && reason.contains("hashes"),
        "the reason should name the input and what failed, got: {reason}"
    );

    // The loose rule still accepts the stripped version too — the reference's
    // gap is not an accident of this one shape.
    let loose = sp::verify_with_binding(&view, None, KeyBinding::Declared).expect("verifies");
    assert!(loose.extractable());
}

/// An uncompressed key is not usable for a silent payment, whatever it hashes
/// to: BIP 352 skips those inputs rather than deriving from them.
#[test]
fn an_uncompressed_key_makes_an_input_ineligible() {
    let secp = Secp256k1::new();
    let mut raw = bound_vector("can finalize: two inputs single-signer using per-input");

    let secret = SecretKey::from_slice(&[0x31u8; 32]).unwrap();
    let uncompressed = PublicKey::from_secret_key(&secp, &secret).serialize_uncompressed();
    let script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
        hash160::Hash::hash(&uncompressed).to_byte_array(),
    ));
    raw.inputs[0].set(RawPair::new(
        keys::input::WITNESS_UTXO,
        Vec::new(),
        bitcoin::consensus::serialize(&TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        }),
    ));
    raw.inputs[0].remove_type(keys::input::BIP32_DERIVATION);
    raw.inputs[0]
        .insert(RawPair::new(
            keys::input::BIP32_DERIVATION,
            uncompressed.to_vec(),
            vec![0u8; 4],
        ))
        .expect("inserts");

    let view = V2View::new(&raw).unwrap();
    let report = sp::verify(&view, None).expect("verifies");
    assert!(
        !report.eligible_inputs().contains(&0),
        "an uncompressed key must not contribute"
    );
    assert!(
        matches!(
            report.inputs[0].ineligible,
            Some(satd_psbt::sp::Ineligible::ScriptType)
        ),
        "{:?}",
        report.inputs[0].ineligible
    );
}

/// A taproot input's key comes from its own script, so there is nothing to
/// bind and nothing to tamper with: rewriting the declared derivation changes
/// no verdict.
#[test]
fn a_taproot_input_takes_its_key_from_the_script() {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("in progress: two P2TR inputs"))
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    let report = sp::verify(&view, None).expect("verifies");

    for input in &report.inputs {
        let Some(prevout) = &input.prevout else {
            continue;
        };
        if !prevout.script_pubkey.is_p2tr() {
            continue;
        }
        if input.ineligible.is_some() {
            // The nothing-up-my-sleeve case is its own vector.
            continue;
        }
        let key = input.public_key.expect("a taproot input has a key");
        assert_eq!(
            &key.serialize()[1..],
            &prevout.script_pubkey.as_bytes()[2..34],
            "the key must be the one in the script"
        );
        assert_eq!(key.serialize()[0], 0x02, "lifted to even Y");
    }
}

/// And a taproot input committed to the nothing-up-my-sleeve internal key
/// contributes nothing: nobody holds the key-path secret.
#[test]
fn a_nums_internal_key_makes_a_taproot_input_ineligible() {
    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("can finalize: two mixed input types"))
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    let report =
        sp::verify_with_binding(&view, None, KeyBinding::Declared).expect("verifies");
    assert!(
        report
            .inputs
            .iter()
            .any(|i| matches!(i.ineligible, Some(satd_psbt::sp::Ineligible::NumsInternalKey))),
        "the vector has an input with the nothing-up-my-sleeve internal key: {:?}",
        report.inputs
    );
}
