//! Tests for Bitcoin Core consensus edge cases that have historically tripped
//! up alternative implementations. Based on comprehensive analysis of Bitcoin's
//! consensus quirks and corner cases.

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Keypair, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, Parity};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::checker::{NoopChecker, SigVersion};
use consensus::error::ScriptError;
use consensus::eval::eval_script_simple;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::stack;
use consensus::verify::verify_script;
use sha2::Digest as _;

const TEST_SECKEY: &str = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";

fn credit_tx(script_pubkey: &[u8], value: u64) -> Transaction {
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
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        }],
    }
}

fn spend_tx(credit: &Transaction, script_sig: &[u8], witness: &[Vec<u8>]) -> Transaction {
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
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut {
            value: credit.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

// =========================================================================
// 1. SIGHASH_SINGLE bug: uint256(1) return
//
// When SIGHASH_SINGLE is used on input index >= number of outputs,
// SignatureHash returns 0x01000...00 (the integer 1 as uint256).
// This is a known bug preserved as consensus.
// =========================================================================

/// Verify that our sighash delegation to the bitcoin crate correctly
/// handles the SIGHASH_SINGLE bug by checking that the bitcoin crate
/// returns the expected constant.
#[test]
fn test_sighash_single_bug_returns_uint256_one() {
    use bitcoin::sighash::SighashCache;
    use bitcoin::hashes::Hash;

    // Create a tx with 2 inputs but only 1 output.
    // Signing input 1 with SIGHASH_SINGLE should trigger the bug.
    let tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let cache = SighashCache::new(&tx);
    let script = bitcoin::Script::from_bytes(&[0x51]); // OP_1
    // Input 1, SIGHASH_SINGLE (0x03). Input 1 >= outputs.len() (1).
    let result = cache.legacy_signature_hash(1, script, 0x03);

    match result {
        Ok(hash) => {
            // The SIGHASH_SINGLE bug should return uint256(1) = 0x01000...00
            let mut expected = [0u8; 32];
            expected[0] = 0x01;
            assert_eq!(
                hash.as_byte_array(), &expected,
                "SIGHASH_SINGLE bug should return uint256(1)"
            );
        }
        Err(_) => panic!("SIGHASH_SINGLE bug case should not return an error"),
    }
}

// =========================================================================
// 2. P2SH-wrapped taproot = anyone can spend
//
// BIP341 explicitly excludes P2SH-wrapped witness v1 from taproot
// validation. P2SH(P2TR) falls through to the unknown-version handler
// which always succeeds. We must NOT accidentally validate taproot
// inside P2SH.
// =========================================================================

/// P2SH-wrapped witness v1 (would-be taproot) should succeed without
/// actual taproot validation. This is the "anyone can spend" behavior
/// for P2SH-P2TR, which is consensus-correct.
#[test]
fn test_p2sh_wrapped_taproot_is_anyone_can_spend() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);

    // Build P2TR scriptPubKey (OP_1 <32-byte-key>)
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&xonly.serialize());

    // Wrap in P2SH
    let redeem_hash = {
        use sha2::Digest;
        let sha = sha2::Sha256::digest(&p2tr);
        let mut hasher = ripemd::Ripemd160::new();
        ripemd::Digest::update(&mut hasher, &sha);
        let h: [u8; 20] = ripemd::Digest::finalize(hasher).into();
        h
    };
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&redeem_hash);
    script_pubkey.push(0x87);

    // scriptSig: push the P2TR redeemScript
    let mut script_sig = vec![p2tr.len() as u8];
    script_sig.extend_from_slice(&p2tr);

    // Witness: just a dummy element (the P2TR key-path sig would go here,
    // but since P2SH-P2TR is anyone-can-spend, any witness should work)
    let witness = vec![vec![0x01]];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    // P2SH-wrapped taproot should succeed (anyone can spend)
    assert!(
        result.is_ok(),
        "P2SH-wrapped taproot should be anyone-can-spend: {:?}",
        result.err()
    );
}

// =========================================================================
// 3. CScriptNum arithmetic overflow
//
// Arithmetic results can exceed the 4-byte range. They are valid as long
// as they aren't used as input to another numeric opcode.
// =========================================================================

/// Arithmetic producing a 5-byte result is valid if the result is used
/// by a non-numeric opcode (e.g., OP_EQUAL for byte comparison).
#[test]
fn test_scriptnum_overflow_result_usable_non_numeric() {
    let checker = NoopChecker;
    // Push 2^31-1 (max 4-byte value): 0x04 0xff 0xff 0xff 0x7f
    // Add 1: result = 2^31 which requires 5 bytes
    // Push 2^31 as 5 bytes: 0x05 0x00 0x00 0x00 0x80 0x00
    // OP_EQUAL: byte comparison (not numeric), should succeed
    let script = vec![
        0x04, 0xff, 0xff, 0xff, 0x7f, // push 2147483647
        0x51, // OP_1
        0x93, // OP_ADD → 2147483648 (5 bytes)
        0x05, 0x00, 0x00, 0x00, 0x80, 0x00, // push 2147483648 as 5-byte scriptnum
        0x87, // OP_EQUAL
    ];
    let mut stack = Vec::new();
    let result = eval_script_simple(&mut stack, &script, 0, &checker, SigVersion::Base);
    assert!(result.is_ok(), "Overflow result used by OP_EQUAL should work: {:?}", result);
    assert!(stack::cast_to_bool(&stack[0]), "Should be equal");
}

/// Arithmetic producing a 5-byte result fails if used as input to
/// another numeric opcode (exceeds 4-byte decode limit).
#[test]
fn test_scriptnum_overflow_result_fails_as_numeric_input() {
    let checker = NoopChecker;
    // Push 2^31-1 + 1 = 2^31 (5 bytes), then OP_1ADD (numeric op)
    let script = vec![
        0x04, 0xff, 0xff, 0xff, 0x7f, // push 2147483647
        0x51, // OP_1
        0x93, // OP_ADD → 2147483648 (5 bytes)
        0x8b, // OP_1ADD → tries to decode 5-byte value, should fail
    ];
    let mut stack = Vec::new();
    let result = eval_script_simple(&mut stack, &script, 0, &checker, SigVersion::Base);
    assert_eq!(result, Err(ScriptError::ScriptNum));
}

// =========================================================================
// 4. NULLFAIL in CHECKMULTISIG
//
// When CHECKMULTISIG fails and NULLFAIL flag is set, all signatures
// must be empty. Non-empty signatures in a failed multisig must trigger
// SigNullFail.
// =========================================================================

/// CHECKMULTISIG with NULLFAIL: failed check with non-empty sig must error.
#[test]
fn test_nullfail_checkmultisig_nonempty_sig() {
    // scriptPubKey: OP_1 <33-byte-pubkey> OP_1 OP_CHECKMULTISIG
    // We use a dummy 33-byte pubkey (won't match any sig)
    let mut script_pubkey = Vec::new();
    script_pubkey.push(0x51); // OP_1 (1 pubkey)
    script_pubkey.push(0x21); // push 33 bytes
    script_pubkey.extend_from_slice(&[0x02; 33]); // dummy compressed pubkey
    script_pubkey.push(0x51); // OP_1 (1 sig required)
    script_pubkey.push(0xae); // OP_CHECKMULTISIG

    // scriptSig: OP_0 (dummy) + non-empty sig (will fail verification)
    let mut script_sig = Vec::new();
    script_sig.push(0x00); // dummy element for CHECKMULTISIG bug
    script_sig.push(0x01); // push 1 byte
    script_sig.push(0xff); // non-empty invalid sig

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &[],
        flags::VERIFY_P2SH | flags::VERIFY_NULLFAIL,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::SigNullFail));
}

/// CHECKMULTISIG with NULLFAIL: empty sig in failed check is acceptable
/// (the operation still fails, but NULLFAIL doesn't trigger).
#[test]
fn test_nullfail_checkmultisig_empty_sig() {
    let mut script_pubkey = Vec::new();
    script_pubkey.push(0x51); // OP_1
    script_pubkey.push(0x21); // push 33
    script_pubkey.extend_from_slice(&[0x02; 33]);
    script_pubkey.push(0x51); // OP_1
    script_pubkey.push(0xae); // OP_CHECKMULTISIG

    // scriptSig: OP_0 (dummy) + OP_0 (empty sig)
    let script_sig = vec![0x00, 0x00];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &[],
        flags::VERIFY_P2SH | flags::VERIFY_NULLFAIL,
        &checker,
    );
    // Empty sig satisfies NULLFAIL, but the script still evaluates to false
    assert_eq!(result, Err(ScriptError::EvalFalse));
}

// =========================================================================
// 5. Schnorr explicit 0x00 hashtype
//
// A 65-byte Schnorr signature with the last byte = 0x00 is invalid.
// Only the implicit 64-byte form represents SIGHASH_DEFAULT.
// =========================================================================

/// 65-byte Schnorr sig with explicit 0x00 hashtype byte must fail.
#[test]
fn test_schnorr_explicit_default_hashtype_rejected() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&kp);

    // Tapscript: <32-byte-key> OP_CHECKSIG
    let mut leaf_script = vec![0x20]; // push 32 bytes
    leaf_script.extend_from_slice(&internal_key.serialize());
    leaf_script.push(0xac); // OP_CHECKSIG

    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());
    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    // Build 65-byte sig: 64 zero bytes + 0x00 hashtype
    let mut bad_sig = vec![0u8; 64];
    bad_sig.push(0x00); // explicit DEFAULT — INVALID

    let witness = vec![bad_sig, leaf_script.clone(), control];
    let c = credit_tx(&spk, 100_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &spk,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::SchnorrSigHashtype));
}

// =========================================================================
// 6. Flags not covered by differential testing
//
// libbitcoinconsensus doesn't support NULLFAIL, MINIMALIF,
// CONST_SCRIPTCODE, STRICTENC, LOW_S, etc. These must be tested
// independently since differential tests can't catch bugs here.
// =========================================================================

/// SIGPUSHONLY: scriptSig with non-push opcode must fail.
#[test]
fn test_sigpushonly_rejects_non_push() {
    // scriptSig: OP_1 OP_NOP (NOP is non-push)
    // scriptPubKey: OP_1
    let result = verify_script(
        &[0x51, 0x61], // OP_1 OP_NOP
        &[0x51],       // OP_1
        &[],
        flags::VERIFY_SIGPUSHONLY,
        &NoopChecker,
    );
    assert_eq!(result, Err(ScriptError::SigPushOnly));
}

/// SIGPUSHONLY: scriptSig with only push operations must pass.
#[test]
fn test_sigpushonly_accepts_push_only() {
    let result = verify_script(
        &[0x51, 0x52], // OP_1 OP_2 (both push)
        &[0x93, 0x53, 0x87], // OP_ADD OP_3 OP_EQUAL
        &[],
        flags::VERIFY_SIGPUSHONLY,
        &NoopChecker,
    );
    assert!(result.is_ok());
}

/// NULLFAIL with CHECKSIG: non-empty failing sig must trigger error.
#[test]
fn test_nullfail_checksig() {
    // scriptPubKey: <dummy-pubkey> OP_CHECKSIG
    let mut spk = vec![0x21]; // push 33 bytes
    spk.extend_from_slice(&[0x02; 33]);
    spk.push(0xac); // OP_CHECKSIG

    // scriptSig: push a non-empty invalid sig
    let script_sig = vec![0x01, 0xff]; // push 1 byte [0xff]

    let c = credit_tx(&spk, 50_000);
    let tx = spend_tx(&c, &script_sig, &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(&script_sig, &spk, &[], flags::VERIFY_NULLFAIL, &checker);
    assert_eq!(result, Err(ScriptError::SigNullFail));
}

/// CONST_SCRIPTCODE: OP_CODESEPARATOR in non-segwit is rejected.
#[test]
fn test_const_scriptcode_rejects_codeseparator() {
    // scriptPubKey: OP_CODESEPARATOR OP_1
    let result = verify_script(
        &[],
        &[0xab, 0x51], // OP_CODESEPARATOR OP_1
        &[],
        flags::VERIFY_CONST_SCRIPTCODE,
        &NoopChecker,
    );
    assert_eq!(result, Err(ScriptError::OpCodeSeparator));
}

/// NULLDUMMY: non-empty dummy in CHECKMULTISIG must fail.
#[test]
fn test_nulldummy_rejects_nonempty() {
    // 0-of-0 CHECKMULTISIG with non-empty dummy
    // scriptPubKey: OP_0 OP_0 OP_CHECKMULTISIG
    let spk = vec![0x00, 0x00, 0xae];
    // scriptSig: push 1 byte (non-empty dummy)
    let sig = vec![0x01, 0x42];

    let c = credit_tx(&spk, 50_000);
    let tx = spend_tx(&c, &sig, &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(&sig, &spk, &[], flags::VERIFY_NULLDUMMY, &checker);
    assert_eq!(result, Err(ScriptError::SigNullDummy));
}

/// NULLDUMMY: empty dummy in CHECKMULTISIG should pass.
#[test]
fn test_nulldummy_accepts_empty() {
    let spk = vec![0x00, 0x00, 0xae]; // OP_0 OP_0 OP_CHECKMULTISIG
    let sig = vec![0x00]; // OP_0 (empty dummy)

    let c = credit_tx(&spk, 50_000);
    let tx = spend_tx(&c, &sig, &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(&sig, &spk, &[], flags::VERIFY_NULLDUMMY, &checker);
    assert!(result.is_ok(), "Empty dummy should pass NULLDUMMY: {:?}", result.err());
}

// =========================================================================
// 7. Negative zero edge cases
// =========================================================================

/// [0x80] is negative zero → falsy. With MINIMALDATA, it's rejected as
/// a script number but still evaluates as false in boolean context.
#[test]
fn test_negative_zero_is_falsy() {
    let checker = NoopChecker;
    // Push 0x80 (negative zero), OP_NOT → should push 1 (true)
    // because CastToBool([0x80]) = false, and NOT(false) = true
    let script = vec![0x01, 0x80, 0x91]; // push-1 0x80, OP_NOT
    let mut stack = Vec::new();
    // Without MINIMALDATA, 0x80 decodes to ScriptNum(0) for OP_NOT
    let result = eval_script_simple(&mut stack, &script, 0, &checker, SigVersion::Base);
    assert!(result.is_ok());
    assert_eq!(stack[0], vec![1]); // NOT(0) = 1
}

/// [0x80] with MINIMALDATA flag must be rejected by numeric opcodes.
#[test]
fn test_negative_zero_rejected_by_minimaldata() {
    let checker = NoopChecker;
    let script = vec![0x01, 0x80, 0x91]; // push-1 0x80, OP_NOT
    let mut stack = Vec::new();
    let result = eval_script_simple(
        &mut stack, &script, flags::VERIFY_MINIMALDATA, &checker, SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::ScriptNum));
}

/// [0x00, 0x80] is also negative zero (2-byte encoding) → falsy.
#[test]
fn test_two_byte_negative_zero_is_falsy() {
    assert!(!stack::cast_to_bool(&[0x00, 0x80]));
}

/// [0x80, 0x00] is NOT negative zero — it's 128 → truthy.
#[test]
fn test_0x80_0x00_is_truthy() {
    assert!(stack::cast_to_bool(&[0x80, 0x00]));
}

// =========================================================================
// 8. Tapscript removes script size and op count limits
// =========================================================================

/// Tapscript has no MAX_SCRIPT_SIZE (10000 byte) limit.
#[test]
fn test_tapscript_no_script_size_limit() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&kp);

    // Build a tapscript larger than 10000 bytes: many OP_NOPs followed by OP_1
    let mut leaf_script = vec![0x61u8; 10_001]; // 10001 NOPs
    leaf_script.push(0x51); // OP_1

    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());
    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    let witness = vec![leaf_script.clone(), control];
    let c = credit_tx(&spk, 100_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &spk,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(
        result.is_ok(),
        "Tapscript should accept >10000 byte scripts: {:?}",
        result.err()
    );
}

/// But segwit v0 DOES enforce the 10000-byte limit.
#[test]
fn test_segwit_v0_script_size_limit() {
    // Build a P2WSH witness script > 10000 bytes
    let mut witness_script = vec![0x61u8; 10_001]; // 10001 NOPs
    witness_script.push(0x51); // OP_1

    let ws_hash: [u8; 32] = sha256_hash(&witness_script);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&ws_hash);

    let witness = vec![witness_script];
    let c = credit_tx(&spk, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &spk,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::ScriptSize));
}

// =========================================================================
// Helpers
// =========================================================================

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
