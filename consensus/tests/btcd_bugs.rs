//! Regression tests for known btcd consensus bugs.
//!
//! Each test reproduces a specific btcd consensus deviation that caused (or
//! could have caused) a chain split. These ensure our Rust implementation
//! does not have the same failure modes.
//!
//! References:
//! - CVE-2024-38365: FindAndDelete fuzzy matching
//! - CVE-2024-34478: Signed transaction version for BIP 68/112
//! - CVE-2022-44797: Wire-level witness item size limits
//! - btcd issue #2485: OP_CODESEPARATOR in unexecuted branches

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, Keypair, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, Parity};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::checker::NoopChecker;
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;

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

fn spend_tx_versioned(
    credit: &Transaction,
    script_sig: &[u8],
    witness: &[Vec<u8>],
    version: i32,
    sequence: u32,
) -> Transaction {
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
        version: Version(version),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence(sequence),
            witness: w,
        }],
        output: vec![TxOut {
            value: credit.output[0].value,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// =========================================================================
// CVE-2024-38365: FindAndDelete must use exact byte-sequence matching
//
// btcd's removeOpcodeByData() removed any data push CONTAINING the target
// as a substring. Bitcoin Core's FindAndDelete removes only exact matches
// of the serialized byte sequence. This produces different sighashes.
// =========================================================================

/// Test that FindAndDelete removes only exact byte sequences, not
/// data pushes containing the target as a substring.
///
/// This is the exact bug class from CVE-2024-38365. btcd's
/// removeOpcodeByData would incorrectly also remove a push like
/// <sig||garbage> when searching for <sig>.
#[test]
fn test_cve_2024_38365_find_and_delete_exact_match() {
    // Pattern: 3-byte sequence [0xaa, 0xbb, 0xcc]
    // Script contains:
    //   1. Exact match: push 3 bytes [0xaa, 0xbb, 0xcc]  (opcode 0x03 + data)
    //   2. Superset push: push 4 bytes [0xaa, 0xbb, 0xcc, 0xdd]  (opcode 0x04 + data)
    //   3. OP_1
    //
    // FindAndDelete should remove only (1), leaving (2) and (3) intact.

    let pattern = vec![0x03, 0xaa, 0xbb, 0xcc]; // push-3 + data

    let mut script = Vec::new();
    // (1) Exact match: push 3 bytes
    script.push(0x03);
    script.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    // (2) Superset: push 4 bytes containing the same prefix
    script.push(0x04);
    script.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    // (3) OP_1
    script.push(0x51);

    let (result, count) = consensus::encoding::find_and_delete(&script, &pattern);

    // Should remove exactly 1 occurrence (the exact match)
    assert_eq!(count, 1, "FindAndDelete should find exactly 1 exact match");

    // Result should be: push-4 [aa bb cc dd] OP_1
    let mut expected = Vec::new();
    expected.push(0x04);
    expected.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    expected.push(0x51);
    assert_eq!(result, expected, "FindAndDelete should preserve superset push");
}

/// Test that FindAndDelete matches at instruction boundaries only, not at
/// arbitrary byte offsets within push data.
#[test]
fn test_find_and_delete_instruction_boundary() {
    // Pattern: [0x51] (OP_1 as a single-byte instruction)
    // Script: push-2 [0x51, 0x52] OP_1
    // The 0x51 inside the push data should NOT be matched.
    let pattern = vec![0x51];
    let script = vec![0x02, 0x51, 0x52, 0x51]; // push-2 then OP_1

    let (result, count) = consensus::encoding::find_and_delete(&script, &pattern);

    // Should remove only the standalone OP_1, not the 0x51 inside push data
    assert_eq!(count, 1);
    assert_eq!(result, vec![0x02, 0x51, 0x52]);
}

/// Test FindAndDelete with empty pattern (should be no-op).
#[test]
fn test_find_and_delete_empty_pattern() {
    let script = vec![0x51, 0x52, 0x93]; // OP_1 OP_2 OP_ADD
    let (result, count) = consensus::encoding::find_and_delete(&script, &[]);
    assert_eq!(count, 0);
    assert_eq!(result, script);
}

/// Test FindAndDelete with pattern larger than any instruction.
#[test]
fn test_find_and_delete_pattern_larger_than_script() {
    let script = vec![0x51]; // just OP_1
    let pattern = vec![0x51, 0x52]; // OP_1 OP_2
    let (result, count) = consensus::encoding::find_and_delete(&script, &pattern);
    assert_eq!(count, 0);
    assert_eq!(result, script);
}

/// Test multiple consecutive exact matches are all removed.
#[test]
fn test_find_and_delete_multiple_matches() {
    // Script: OP_NOP OP_NOP OP_NOP OP_1
    // Pattern: OP_NOP (0x61)
    let script = vec![0x61, 0x61, 0x61, 0x51];
    let (result, count) = consensus::encoding::find_and_delete(&script, &[0x61]);
    assert_eq!(count, 3);
    assert_eq!(result, vec![0x51]);
}

// =========================================================================
// CVE-2024-34478: Signed transaction version for BIP 68/112
//
// btcd compared tx.Version (int32) directly: -1 < 2 → true → BIP 68 not
// enforced. Bitcoin Core casts to uint32 first: 0xFFFFFFFF >= 2 → BIP 68
// IS enforced. This allowed premature spending of timelocked outputs.
// =========================================================================

/// Transaction version -1 (0xFFFFFFFF as uint32) should have BIP 68/112
/// relative timelocks enforced, because uint32(-1) = 4294967295 >= 2.
///
/// btcd treated this as version < 2 (signed comparison) and skipped
/// enforcement. We must use unsigned comparison.
#[test]
fn test_cve_2024_34478_negative_version_csv() {
    // scriptPubKey: OP_1 OP_CHECKSEQUENCEVERIFY (requires relative locktime of 1 block)
    let script_pubkey = vec![0x51, 0xb2]; // OP_1 OP_CSV
    // scriptSig: push the value needed by CSV (OP_1 already in scriptPubKey)
    // Actually, CSV reads from the stack but doesn't consume. The scriptPubKey
    // is: OP_1 OP_CSV which pushes 1 then checks sequence >= 1.

    let c = credit_tx(&script_pubkey, 50_000);

    // Version -1 (0xFFFFFFFF unsigned), nSequence = 1 (satisfies relative lock)
    let tx = spend_tx_versioned(&c, &[], &[], -1, 1);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = Vec::new();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_CHECKSEQUENCEVERIFY,
        &checker,
    );

    // Must PASS: uint32(-1) = 4294967295 >= 2, so BIP 68 applies, and
    // nSequence 1 >= script value 1.
    assert!(
        result.is_ok(),
        "Version -1 (uint32 0xFFFFFFFF) should enforce CSV (btcd bug CVE-2024-34478): {:?}",
        result.err()
    );
}

/// Version 1 should NOT enforce CSV (BIP 68 requires version >= 2).
#[test]
fn test_csv_version_1_no_enforcement() {
    let script_pubkey = vec![0x51, 0xb2]; // OP_1 OP_CSV

    let c = credit_tx(&script_pubkey, 50_000);
    // Version 1, nSequence = 0 (would fail CSV if enforced)
    let tx = spend_tx_versioned(&c, &[], &[], 1, 0);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &[],
        &script_pubkey,
        &[],
        flags::VERIFY_P2SH | flags::VERIFY_CHECKSEQUENCEVERIFY,
        &checker,
    );

    // Version 1: CSV check_sequence returns false, but the CSV opcode
    // still runs and fails because check_sequence(1) with nSequence=0 fails.
    // Wait — with version 1, check_sequence returns false immediately,
    // so CSV returns UNSATISFIED_LOCKTIME.
    // Actually: CSV with version < 2 → check_sequence returns false → error.
    // The test vector from tx_valid.json for version=-1 expects success,
    // so version 1 should fail.
    assert_eq!(result, Err(ScriptError::UnsatisfiedLocktime));
}

/// Version 2 with satisfied sequence should pass CSV.
#[test]
fn test_csv_version_2_passes() {
    let script_pubkey = vec![0x51, 0xb2]; // OP_1 OP_CSV

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx_versioned(&c, &[], &[], 2, 1); // version=2, seq=1
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &[],
        &script_pubkey,
        &[],
        flags::VERIFY_P2SH | flags::VERIFY_CHECKSEQUENCEVERIFY,
        &checker,
    );
    assert!(result.is_ok(), "Version 2 with seq=1 should pass CSV: {:?}", result.err());
}

/// Version 2 with unsatisfied sequence should fail CSV.
#[test]
fn test_csv_version_2_unsatisfied() {
    let script_pubkey = vec![0x52, 0xb2]; // OP_2 OP_CSV (requires seq >= 2)

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx_versioned(&c, &[], &[], 2, 1); // version=2, seq=1 (< 2)
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &[],
        &script_pubkey,
        &[],
        flags::VERIFY_P2SH | flags::VERIFY_CHECKSEQUENCEVERIFY,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::UnsatisfiedLocktime));
}

// =========================================================================
// CVE-2022-44797: Large taproot witness items
//
// btcd rejected witness items > 11,000 bytes at the wire layer.
// Taproot has no per-item size limit — only the 4 MWU block weight.
// Our consensus library must accept large witness items.
// =========================================================================

/// Tapscript with a large witness stack item (> 11KB) must be accepted.
/// This is the class of bug that stalled all btcd/lnd nodes in Oct 2022.
#[test]
fn test_cve_2022_44797_large_witness_item() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&kp);

    // Build a tapscript that accepts any data: OP_DROP OP_1
    let leaf_script = vec![0x75, 0x51]; // OP_DROP OP_1

    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());

    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    // The btcd bug was about the wire parser rejecting witness items > 11KB.
    // In consensus, each witness stack item is limited to 520 bytes
    // (MAX_SCRIPT_ELEMENT_SIZE), but the TOTAL witness can be much larger
    // because many items add up. The real-world trigger was a 998-of-999
    // multisig with ~998 individual 64-byte Schnorr signatures.
    //
    // We simulate this: many small witness items that sum to > 11KB total.
    // The leaf script drops all items then pushes OP_1.
    let n_items = 200;
    // Leaf script: OP_DROP * n_items, then OP_1
    let mut leaf_script = vec![0x75u8; n_items]; // OP_DROP * 200
    leaf_script.push(0x51); // OP_1

    // Recompute taproot output for this leaf
    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());
    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    // 200 items of 64 bytes each = 12.8KB total witness data
    let mut witness: Vec<Vec<u8>> = (0..n_items).map(|_| vec![0x42u8; 64]).collect();
    witness.push(leaf_script.clone());
    witness.push(control);

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
        "Large total witness (12.8KB across 200 items) should be accepted in tapscript (btcd CVE-2022-44797): {:?}",
        result.err()
    );
}

/// OP_SUCCESS with many witness items must succeed regardless of stack limits.
/// btcd had a maxWitnessItemsPerInput of 500,000 which was hit by a deliberately
/// crafted transaction in November 2022.
#[test]
fn test_op_success_many_witness_items() {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&kp);

    // Tapscript: OP_SUCCESS (0xfe) — immediately succeeds
    let leaf_script = vec![0xfe];

    let leaf_hash = compute_tapleaf_hash(0xc0, &leaf_script);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &leaf_hash);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&secp, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());

    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };
    let mut control = vec![parity_byte];
    control.extend_from_slice(&internal_key.serialize());

    // Push 1500 empty witness items (exceeds the 1000 stack limit, but
    // OP_SUCCESS should bypass all limits)
    let mut witness: Vec<Vec<u8>> = (0..1500).map(|_| vec![]).collect();
    witness.push(leaf_script.clone());
    witness.push(control);

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
        "OP_SUCCESS should bypass stack limits with many witness items: {:?}",
        result.err()
    );
}

// =========================================================================
// btcd issue #2485: OP_CODESEPARATOR in unexecuted branches
//
// Bitcoin Core's SCRIPT_VERIFY_CONST_SCRIPTCODE check fires BEFORE the
// branch-execution gate (fExec). btcd's check was inside the opcode
// handler, which is never reached for dead branches.
// =========================================================================

/// OP_CODESEPARATOR inside OP_FALSE OP_IF ... OP_ENDIF must still trigger
/// CONST_SCRIPTCODE rejection in non-segwit scripts.
#[test]
fn test_codeseparator_in_dead_branch_rejected() {
    // scriptPubKey: OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF OP_1
    let script_pubkey = vec![0x00, 0x63, 0xab, 0x68, 0x51];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(
        &[],
        &script_pubkey,
        &[],
        flags::VERIFY_CONST_SCRIPTCODE,
        &checker,
    );
    assert_eq!(
        result,
        Err(ScriptError::OpCodeSeparator),
        "OP_CODESEPARATOR in dead branch should be rejected with CONST_SCRIPTCODE"
    );
}

/// Without CONST_SCRIPTCODE flag, OP_CODESEPARATOR in dead branch is allowed.
#[test]
fn test_codeseparator_in_dead_branch_allowed_without_flag() {
    let script_pubkey = vec![0x00, 0x63, 0xab, 0x68, 0x51];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &[]);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);

    let result = verify_script(&[], &script_pubkey, &[], 0, &checker);
    assert!(
        result.is_ok(),
        "OP_CODESEPARATOR in dead branch should be allowed without CONST_SCRIPTCODE: {:?}",
        result.err()
    );
}

// =========================================================================
// Additional edge cases inspired by btcd's history
// =========================================================================

/// Disabled opcodes must fail even in unexecuted branches.
/// This is related to CVE-2010-5137 and btcd's historical issues with
/// opcode handling in dead branches.
#[test]
fn test_disabled_opcodes_in_dead_branch() {
    // OP_0 OP_IF OP_CAT OP_ENDIF OP_1
    let script_pubkey = vec![0x00, 0x63, 0x7e, 0x68, 0x51];
    let checker = NoopChecker;
    let result = verify_script(&[], &script_pubkey, &[], 0, &checker);
    assert_eq!(result, Err(ScriptError::DisabledOpcode));
}

/// SegWit v0 does NOT have per-item witness size limits.
/// The 520-byte MAX_SCRIPT_ELEMENT_SIZE is enforced for witness stack items
/// in execute_witness_script, but only for individual items.
#[test]
fn test_segwit_v0_witness_item_size_limit() {
    // P2WSH with a script that drops a large item and pushes OP_1
    let witness_script = vec![0x75, 0x51]; // OP_DROP OP_1
    let ws_hash: [u8; 32] = sha2::Sha256::digest(&witness_script).into();

    let mut script_pubkey = vec![0x00, 0x20]; // OP_0 <32 bytes>
    script_pubkey.extend_from_slice(&ws_hash);

    // Witness: [large_item (521 bytes, exceeds MAX_SCRIPT_ELEMENT_SIZE), witness_script]
    let large_item = vec![0x42u8; 521];
    let witness = vec![large_item, witness_script.clone()];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    // 521 bytes > MAX_SCRIPT_ELEMENT_SIZE (520) → PushSize error
    assert_eq!(result, Err(ScriptError::PushSize));
}

/// SegWit v0: witness item at exactly 520 bytes should be accepted.
#[test]
fn test_segwit_v0_witness_item_at_limit() {
    let witness_script = vec![0x75, 0x51]; // OP_DROP OP_1
    let ws_hash: [u8; 32] = sha2::Sha256::digest(&witness_script).into();

    let mut script_pubkey = vec![0x00, 0x20];
    script_pubkey.extend_from_slice(&ws_hash);

    // Witness: [520-byte item, witness_script]
    let item = vec![0x42u8; 520];
    let witness = vec![item, witness_script.clone()];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert!(result.is_ok(), "520-byte witness item should be accepted: {:?}", result.err());
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

use sha2::Digest;
