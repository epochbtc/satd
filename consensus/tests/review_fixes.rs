//! Tests for PR review findings:
//! 1. Tapscript sighash must include codeseparator_pos (not always 0xFFFFFFFF)
//! 2. Tapscript sighash must include annex when present
//! 3. Tapscript CHECKSIG with invalid non-empty sig must hard-fail (BIP342)

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{
    self, Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, Parity,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;

const TEST_SECKEY: &str = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";

fn secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
}

fn keypair() -> (SecretKey, XOnlyPublicKey, Keypair) {
    let s = secp();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&s, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    (sk, xonly, kp)
}

fn credit_tx(spk: &[u8], value: u64) -> Transaction {
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
            script_pubkey: ScriptBuf::from_bytes(spk.to_vec()),
        }],
    }
}

fn spend_tx_with_witness(credit: &Transaction, witness: &[Vec<u8>]) -> Transaction {
    let mut buf = Vec::new();
    credit.consensus_encode(&mut buf).unwrap();
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
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut {
            value: credit.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapLeaf");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(&[leaf_version]);
    let compact = bitcoin::consensus::encode::serialize(&bitcoin::VarInt(script.len() as u64));
    engine.input(&compact);
    engine.input(script);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn compute_tap_tweak(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapTweak");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(internal_key);
    engine.input(merkle_root);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn build_taproot_output(internal_key: &XOnlyPublicKey, leaf_script: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let s = secp();
    let leaf_hash = compute_tapleaf_hash(0xc0, leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&s, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());

    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    (spk, control)
}

/// Sign a tapscript spend using the bitcoin crate's sighash with proper
/// codeseparator_pos and annex support.
fn sign_tapscript(
    tx: &Transaction,
    input_index: usize,
    prev_outputs: &[TxOut],
    leaf_hash: &[u8; 32],
    codesep_pos: u32,
    annex_bytes: Option<&[u8]>,
    keypair: &Keypair,
) -> Vec<u8> {
    let s = secp();
    let prevouts = Prevouts::All(prev_outputs);
    let annex = annex_bytes.and_then(|b| bitcoin::sighash::Annex::new(b).ok());
    let tap_leaf = TapLeafHash::from_byte_array(*leaf_hash);

    let mut cache = SighashCache::new(tx);
    let mut engine = bitcoin::TapSighash::engine();
    cache
        .taproot_encode_signing_data_to(
            &mut engine,
            input_index,
            &prevouts,
            annex,
            Some((tap_leaf, codesep_pos)),
            TapSighashType::Default,
        )
        .unwrap();
    let sighash = bitcoin::TapSighash::from_engine(engine);

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = s.sign_schnorr(&msg, keypair);
    sig.serialize().to_vec() // 64 bytes = SIGHASH_DEFAULT (implicit)
}

const TR_FLAGS: u32 = flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT;

// =========================================================================
// Finding 2: Tapscript sighash must include codeseparator_pos
// =========================================================================

/// Tapscript with OP_CODESEPARATOR: sighash must include the codesep
/// position, not always 0xFFFFFFFF.
///
/// Script: OP_CODESEPARATOR <pubkey> OP_CHECKSIG
/// The OP_CODESEPARATOR at opcode_pos=0 changes codeseparator_pos from
/// 0xFFFFFFFF to 0. If we hardcode 0xFFFFFFFF, the signature won't verify.
#[test]
fn test_tapscript_codeseparator_affects_sighash() {
    let (_, internal_key, kp) = keypair();

    // Script: OP_CODESEPARATOR <32-byte-pubkey> OP_CHECKSIG
    let mut leaf_script = Vec::new();
    leaf_script.push(0xab); // OP_CODESEPARATOR
    leaf_script.push(0x20); // push 32 bytes
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac); // OP_CHECKSIG

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);
    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);

    // Build the spending tx structure first (need it for sighash)
    let value = 100_000u64;
    let c = credit_tx(&spk, value);
    // Placeholder witness — will replace with real sig
    let placeholder_wit = vec![vec![0u8; 64], leaf_script.clone(), control.clone()];
    let tx = spend_tx_with_witness(&c, &placeholder_wit);
    let prev_outputs = vec![c.output[0].clone()];

    // Sign with codeseparator_pos = 0 (position of the OP_CODESEPARATOR opcode)
    let sig = sign_tapscript(&tx, 0, &prev_outputs, &leaf_hash, 0, None, &kp);

    // Rebuild with real signature
    let real_wit = vec![sig, leaf_script.clone(), control];
    let tx = spend_tx_with_witness(&c, &real_wit);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    assert!(
        result.is_ok(),
        "Tapscript with OP_CODESEPARATOR should verify with correct codesep_pos: {:?}",
        result.err()
    );
}

/// Same script but signed with the WRONG codeseparator_pos (0xFFFFFFFF)
/// must fail verification (proves codesep_pos actually matters).
#[test]
fn test_tapscript_wrong_codeseparator_pos_fails() {
    let (_, internal_key, kp) = keypair();

    let mut leaf_script = Vec::new();
    leaf_script.push(0xab); // OP_CODESEPARATOR
    leaf_script.push(0x20);
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac);

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);
    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);

    let value = 100_000u64;
    let c = credit_tx(&spk, value);
    let placeholder_wit = vec![vec![0u8; 64], leaf_script.clone(), control.clone()];
    let tx = spend_tx_with_witness(&c, &placeholder_wit);
    let prev_outputs = vec![c.output[0].clone()];

    // Sign with WRONG codesep_pos (0xFFFFFFFF instead of 0)
    let sig = sign_tapscript(&tx, 0, &prev_outputs, &leaf_hash, 0xFFFFFFFF, None, &kp);

    let real_wit = vec![sig, leaf_script.clone(), control];
    let tx = spend_tx_with_witness(&c, &real_wit);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    assert_eq!(
        result,
        Err(ScriptError::SchnorrSig),
        "Wrong codesep_pos should cause sig verification failure"
    );
}

// =========================================================================
// Finding 2 continued: Annex in tapscript sighash
// =========================================================================

/// Tapscript spend with annex: sighash must include the annex.
/// We sign with annex-aware sighash and verify it works.
#[test]
fn test_tapscript_annex_in_sighash() {
    let (_, internal_key, kp) = keypair();

    // Simple script: <pubkey> OP_CHECKSIG
    let mut leaf_script = Vec::new();
    leaf_script.push(0x20);
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac);

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);
    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);

    let annex = vec![0x50, 0x01, 0x02, 0x03]; // valid annex (starts with 0x50)

    let value = 100_000u64;
    let c = credit_tx(&spk, value);
    // Witness layout: [sig, leaf_script, control_block, annex]
    let placeholder_wit = vec![
        vec![0u8; 64],
        leaf_script.clone(),
        control.clone(),
        annex.clone(),
    ];
    let tx = spend_tx_with_witness(&c, &placeholder_wit);
    let prev_outputs = vec![c.output[0].clone()];

    // Sign with annex included in sighash
    let sig = sign_tapscript(
        &tx,
        0,
        &prev_outputs,
        &leaf_hash,
        0xFFFFFFFF, // no codesep
        Some(&annex),
        &kp,
    );

    let real_wit = vec![sig, leaf_script.clone(), control, annex];
    let tx = spend_tx_with_witness(&c, &real_wit);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    assert!(
        result.is_ok(),
        "Tapscript with annex should verify: {:?}",
        result.err()
    );
}

/// Tapscript with annex: sig computed WITHOUT annex must fail when
/// annex IS present (proves annex is actually included in sighash).
#[test]
fn test_tapscript_annex_missing_from_sig_fails() {
    let (_, internal_key, kp) = keypair();

    let mut leaf_script = Vec::new();
    leaf_script.push(0x20);
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac);

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);
    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let annex = vec![0x50, 0x01, 0x02, 0x03];

    let value = 100_000u64;
    let c = credit_tx(&spk, value);
    let placeholder_wit = vec![
        vec![0u8; 64],
        leaf_script.clone(),
        control.clone(),
        annex.clone(),
    ];
    let tx = spend_tx_with_witness(&c, &placeholder_wit);
    let prev_outputs = vec![c.output[0].clone()];

    // Sign WITHOUT annex (wrong sighash)
    let sig = sign_tapscript(&tx, 0, &prev_outputs, &leaf_hash, 0xFFFFFFFF, None, &kp);

    let real_wit = vec![sig, leaf_script.clone(), control, annex];
    let tx = spend_tx_with_witness(&c, &real_wit);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    assert_eq!(
        result,
        Err(ScriptError::SchnorrSig),
        "Sig computed without annex should fail when annex is present"
    );
}

// =========================================================================
// Finding 1: Tapscript CHECKSIG with invalid non-empty sig = hard fail
// =========================================================================

/// BIP342: A non-empty signature that fails Schnorr verification in
/// tapscript must cause the entire script to fail (not just push false).
/// This is intentional — it's the tapscript equivalent of NULLFAIL.
#[test]
fn test_tapscript_invalid_nonempty_sig_hard_fails() {
    let (_, internal_key, _) = keypair();

    // Script: <pubkey> OP_CHECKSIG
    let mut leaf_script = Vec::new();
    leaf_script.push(0x20);
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac);

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);

    // Witness: [invalid_64byte_sig, leaf_script, control]
    let bad_sig = vec![0x42u8; 64]; // 64 bytes but not a valid Schnorr sig
    let wit_items = vec![bad_sig, leaf_script.clone(), control];
    let c = credit_tx(&spk, 100_000);
    let tx = spend_tx_with_witness(&c, &wit_items);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    // Must be SchnorrSig error (hard fail), not EvalFalse (soft fail)
    assert_eq!(result, Err(ScriptError::SchnorrSig),
        "Invalid non-empty Schnorr sig in tapscript must hard-fail per BIP342");
}

/// But an EMPTY signature in tapscript CHECKSIG should push false (not hard fail).
/// The script fails with EvalFalse, not SchnorrSig.
#[test]
fn test_tapscript_empty_sig_pushes_false() {
    let (_, internal_key, _) = keypair();

    let mut leaf_script = Vec::new();
    leaf_script.push(0x20);
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac);

    let (spk, control) = build_taproot_output(&internal_key, &leaf_script);

    // Witness: [empty_sig, leaf_script, control]
    let wit_items = vec![vec![], leaf_script.clone(), control];
    let c = credit_tx(&spk, 100_000);
    let tx = spend_tx_with_witness(&c, &wit_items);
    let prev_outputs = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(&[], &spk, &wit, TR_FLAGS, &checker);
    // Empty sig → success=false → CHECKSIG pushes false → script fails with EvalFalse
    assert_eq!(result, Err(ScriptError::EvalFalse),
        "Empty sig in tapscript CHECKSIG should soft-fail with EvalFalse");
}
