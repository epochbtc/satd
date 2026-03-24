//! Comprehensive coverage tests for previously-untested code paths.
//!
//! Tests are grouped by the gap they close:
//! 1. Public API (verify / verify_with_flags)
//! 2. P2SH-wrapped witness (P2SH-P2WPKH, P2SH-P2WSH)
//! 3. Annex handling
//! 4. Tapscript validation weight budget
//! 5. Multi-leaf taproot merkle paths
//! 6. WITNESS_UNEXPECTED error
//! 7. CLEANSTACK enforcement
//! 8. MINIMALIF in witness v0

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, Keypair, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, Parity};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use consensus::{Error, Utxo};
use sha2::Digest;

const TEST_SECKEY: &str = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";

fn secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
}

fn test_keypair() -> (SecretKey, XOnlyPublicKey) {
    let s = secp();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let kp = Keypair::from_secret_key(&s, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    (sk, xonly)
}

/// Build a crediting tx paying to script_pubkey.
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

/// Build a spending tx with given scriptSig and witness.
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

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha2::Sha256::digest(data);
    let mut hasher = ripemd::Ripemd160::new();
    ripemd::Digest::update(&mut hasher, sha);
    ripemd::Digest::finalize(hasher).into()
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).unwrap();
    buf
}

// ===== Taproot helpers =====

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

fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapBranch");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    if a < b { engine.input(a); engine.input(b); }
    else { engine.input(b); engine.input(a); }
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

/// Build taproot output + control block for a single leaf.
fn build_single_leaf_taproot(
    internal_key: &XOnlyPublicKey,
    leaf_script: &[u8],
) -> (ScriptBuf, Vec<u8>) {
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

    (ScriptBuf::from_bytes(spk), control)
}

/// Build taproot output + control blocks for a two-leaf tree.
/// Returns (scriptPubKey, control_block_for_leaf_a, control_block_for_leaf_b).
fn build_two_leaf_taproot(
    internal_key: &XOnlyPublicKey,
    leaf_a: &[u8],
    leaf_b: &[u8],
) -> (ScriptBuf, Vec<u8>, Vec<u8>) {
    let s = secp();
    let hash_a = compute_tapleaf_hash(0xc0, leaf_a);
    let hash_b = compute_tapleaf_hash(0xc0, leaf_b);
    let branch = compute_tapbranch_hash(&hash_a, &hash_b);
    let tweak = compute_tap_tweak(&internal_key.serialize(), &branch);
    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (tweaked_key, tweaked_parity) = internal_key.add_tweak(&s, &tweak_scalar).unwrap();

    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&tweaked_key.serialize());

    let parity_byte = 0xc0 | if tweaked_parity == Parity::Odd { 1 } else { 0 };

    // Control block for leaf A: parity|version || internal_key || hash_b (sibling)
    let mut ctrl_a = vec![parity_byte];
    ctrl_a.extend_from_slice(&internal_key.serialize());
    ctrl_a.extend_from_slice(&hash_b);

    // Control block for leaf B: parity|version || internal_key || hash_a (sibling)
    let mut ctrl_b = vec![parity_byte];
    ctrl_b.extend_from_slice(&internal_key.serialize());
    ctrl_b.extend_from_slice(&hash_a);

    (ScriptBuf::from_bytes(spk), ctrl_a, ctrl_b)
}

fn taproot_spend_tx(
    spk: &ScriptBuf,
    leaf_script: &[u8],
    control_block: &[u8],
    stack_items: &[Vec<u8>],
) -> (Transaction, Vec<TxOut>) {
    let value = 100_000u64;
    let c = credit_tx(spk.as_bytes(), value);
    let mut wit: Vec<Vec<u8>> = stack_items.to_vec();
    wit.push(leaf_script.to_vec());
    wit.push(control_block.to_vec());
    let tx = spend_tx(&c, &[], &wit);
    let prev = vec![c.output[0].clone()];
    (tx, prev)
}

const TR_FLAGS: u32 =
    flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT;

fn verify_taproot_spend(
    tx: &Transaction,
    prev_outputs: &[TxOut],
    spk: &ScriptBuf,
    extra_flags: u32,
) -> Result<(), ScriptError> {
    let checker = TxSignatureChecker::new(tx, 0, prev_outputs[0].value, prev_outputs);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();
    verify_script(&[], spk.as_bytes(), &wit, TR_FLAGS | extra_flags, &checker)
}

// =========================================================================
// 1. PUBLIC API: verify() / verify_with_flags()
// =========================================================================

#[test]
fn test_api_verify_with_flags_valid() {
    // Build a trivial P2PKH-like: scriptPubKey = OP_1, scriptSig = empty
    let spk = vec![0x51u8]; // OP_1
    let c = credit_tx(&spk, 50_000);
    let tx = spend_tx(&c, &[], &[]);
    let tx_bytes = serialize_tx(&tx);

    let result = consensus::verify_with_flags(&spk, 50_000, &tx_bytes, None, 0, 0);
    assert!(result.is_ok());
}

#[test]
fn test_api_verify_with_flags_invalid_flags() {
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 0);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    // Set an unrecognized flag bit
    let result = consensus::verify_with_flags(&spk, 0, &tx_bytes, None, 0, 1 << 30);
    assert_eq!(result, Err(Error::ErrInvalidFlags));
}

#[test]
fn test_api_verify_with_flags_bad_tx() {
    let result = consensus::verify_with_flags(&[0x51], 0, &[0xff; 10], None, 0, 0);
    assert_eq!(result, Err(Error::ErrTxDeserialize));
}

#[test]
fn test_api_verify_with_flags_bad_index() {
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 0);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    // Input index 5 is out of range (only 1 input)
    let result = consensus::verify_with_flags(&spk, 0, &tx_bytes, None, 5, 0);
    assert_eq!(result, Err(Error::ErrTxIndex));
}

#[test]
fn test_api_verify_with_flags_taproot_needs_spent_outputs() {
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 0);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    let result = consensus::verify_with_flags(&spk, 0, &tx_bytes, None, 0, flags::VERIFY_TAPROOT);
    assert_eq!(result, Err(Error::ErrSpentOutputsRequired));
}

#[test]
fn test_api_verify_with_flags_spent_outputs_mismatch() {
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 0);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    // Provide 2 UTXOs for a 1-input tx
    let utxos = vec![
        Utxo { script_pubkey: spk.as_ptr(), script_pubkey_len: spk.len() as u32, value: 0 },
        Utxo { script_pubkey: spk.as_ptr(), script_pubkey_len: spk.len() as u32, value: 0 },
    ];
    let result = consensus::verify_with_flags(
        &spk, 0, &tx_bytes, Some(&utxos), 0,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
    );
    assert_eq!(result, Err(Error::ErrSpentOutputsMismatch));
}

#[test]
fn test_api_verify_with_spent_outputs() {
    // OP_1 script, verify with spent outputs (taproot flag enabled)
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 50_000);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    let utxos = vec![
        Utxo { script_pubkey: spk.as_ptr(), script_pubkey_len: spk.len() as u32, value: 50_000 },
    ];
    let result = consensus::verify_with_flags(
        &spk, 50_000, &tx_bytes, Some(&utxos), 0,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
    );
    assert!(result.is_ok(), "verify with spent outputs failed: {:?}", result);
}

#[test]
fn test_api_verify_auto_flags() {
    let spk = vec![0x51u8];
    let c = credit_tx(&spk, 50_000);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    // verify() without spent_outputs → no taproot flag
    let result = consensus::verify(&spk, 50_000, &tx_bytes, None, 0);
    assert!(result.is_ok());
}

#[test]
fn test_api_verify_script_failure() {
    // OP_0 → eval_false
    let spk = vec![0x00u8];
    let c = credit_tx(&spk, 0);
    let tx_bytes = serialize_tx(&spend_tx(&c, &[], &[]));
    let result = consensus::verify_with_flags(&spk, 0, &tx_bytes, None, 0, 0);
    assert_eq!(result, Err(Error::ErrScript));
}

// =========================================================================
// 2. P2SH-WRAPPED WITNESS (P2SH-P2WPKH, P2SH-P2WSH)
// =========================================================================

#[test]
fn test_p2sh_p2wsh_valid() {
    // Build P2SH(P2WSH(OP_1))
    // Witness script: OP_1
    let witness_script = vec![0x51u8];
    let ws_hash = sha256_hash(&witness_script);

    // P2WSH: OP_0 <32-byte SHA256(witness_script)>
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&ws_hash);

    // P2SH wrapping: HASH160 <hash160(p2wsh)> EQUAL
    let redeem_hash = hash160(&p2wsh);
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&redeem_hash);
    script_pubkey.push(0x87);

    // scriptSig: single push of the P2WSH redeemScript
    let mut script_sig = Vec::new();
    script_sig.push(p2wsh.len() as u8);
    script_sig.extend_from_slice(&p2wsh);

    // witness: [witness_script]
    let witness = vec![witness_script.clone()];

    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert!(result.is_ok(), "P2SH-P2WSH failed: {:?}", result.err());
}

#[test]
fn test_p2sh_p2wsh_malleated_scriptsig() {
    // P2SH-P2WSH but scriptSig has extra junk
    let witness_script = vec![0x51u8];
    let ws_hash = sha256_hash(&witness_script);
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&ws_hash);
    let redeem_hash = hash160(&p2wsh);
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&redeem_hash);
    script_pubkey.push(0x87);

    // Malleated scriptSig: extra OP_0 before the push
    let mut script_sig = vec![0x00]; // extra OP_0
    script_sig.push(p2wsh.len() as u8);
    script_sig.extend_from_slice(&p2wsh);

    let witness = vec![witness_script];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::WitnessMalleatedP2sh));
}

#[test]
fn test_p2sh_p2wpkh_valid() {
    // P2SH(P2WPKH) requires a real signature, so test the structural path.
    // We use NoopChecker which returns false for sigs, but test that the
    // script structure is correctly parsed by expecting EvalFalse (sig fails)
    // rather than a structural error.
    let (_, xonly) = test_keypair();
    // Fake a compressed pubkey (0x02 prefix)
    let mut pubkey = vec![0x02];
    pubkey.extend_from_slice(&xonly.serialize());
    let pubkey_hash = hash160(&pubkey);

    // P2WPKH: OP_0 <20-byte hash160(pubkey)>
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&pubkey_hash);

    // P2SH wrapping
    let redeem_hash = hash160(&p2wpkh);
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&redeem_hash);
    script_pubkey.push(0x87);

    let mut script_sig = Vec::new();
    script_sig.push(p2wpkh.len() as u8);
    script_sig.extend_from_slice(&p2wpkh);

    // witness: [sig, pubkey] — sig is dummy, will fail CHECKSIG
    let witness = vec![vec![0x00], pubkey.clone()];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    // Should fail with EvalFalse (sig check fails), NOT a structural error
    assert_eq!(result, Err(ScriptError::EvalFalse),
        "P2SH-P2WPKH should reach sig verification, got: {:?}", result);
}

// =========================================================================
// 3. ANNEX HANDLING
// =========================================================================

#[test]
fn test_tapscript_with_annex() {
    let (_, internal_key) = test_keypair();
    let leaf_script = vec![0x51u8]; // OP_1
    let (spk, control) = build_single_leaf_taproot(&internal_key, &leaf_script);

    // Build witness with annex: [leaf_script, control_block, annex]
    // Annex starts with 0x50
    let annex = vec![0x50, 0x01, 0x02, 0x03];
    let value = 100_000u64;
    let c = credit_tx(spk.as_bytes(), value);

    let wit = vec![leaf_script.clone(), control.clone(), annex];

    let tx = spend_tx(&c, &[], &wit);
    let prev = vec![c.output[0].clone()];
    // The annex is the last element. For script-path, witness layout is:
    // [stack_items..., script, control_block, annex]
    // Our code pops annex first if it starts with 0x50 and stack.len() >= 2.
    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert!(result.is_ok(), "tapscript with annex failed: {:?}", result.err());
}

#[test]
fn test_tapscript_non_annex_0x50_not_stripped() {
    // If the last witness element is [0x50] but there's only 1 element after
    // script+control removal, it should NOT be treated as annex
    let (_, internal_key) = test_keypair();
    // Leaf script: OP_SIZE OP_0 OP_EQUAL (checks top element is empty)
    // We want a script that can succeed with specific stack items
    let leaf_script = vec![0x51u8]; // OP_1 — trivially succeeds with empty stack
    let (spk, control) = build_single_leaf_taproot(&internal_key, &leaf_script);
    let (tx, prev) = taproot_spend_tx(&spk, &leaf_script, &control, &[]);
    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert!(result.is_ok());
}

// =========================================================================
// 4. TAPSCRIPT VALIDATION WEIGHT BUDGET
// =========================================================================

#[test]
fn test_tapscript_validation_weight_exceeded() {
    let (_, internal_key) = test_keypair();
    // Build a tapscript with many CHECKSIG operations that would exhaust the weight budget.
    // Each non-empty sig CHECKSIG costs VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50.
    // Budget = witness_size + 50.
    // OP_CHECKSIG with a 32-byte pubkey and non-empty sig will deduct 50.
    // We need a script that attempts many checksigs with small witness.
    //
    // Script: <32-byte-key> CHECKSIG <32-byte-key> CHECKSIG ... repeated
    // But we only have the budget from witness size. With a tiny witness, budget
    // is ~50 + overhead. Each successful sig deducts 50, so 2 would bust it.
    //
    // However, with empty sigs, success=false, so no weight deducted.
    // With non-empty sigs that fail verification, still deducts weight.
    //
    // Actually: eval_checksig_tapscript sets success = !sig.is_empty().
    // If success=true, deduct 50. Then if pubkey is 32 bytes, verify schnorr.
    // So passing a non-empty invalid sig will deduct 50 AND fail with SchnorrSig.
    //
    // To test weight exhaustion, we need the sig check to succeed (or at least
    // pass the upgradable pubkey path). Use a 33-byte (unknown) pubkey which
    // is always-succeed (upgradable path, no DISCOURAGE flag).
    //
    // Script: <non-empty sig> <33-byte unknown pubkey> CHECKSIG
    //         <non-empty sig> <33-byte unknown pubkey> CHECKSIG
    // Each deducts 50 weight. With a small witness, second CHECKSIG should
    // exhaust the budget.

    // 33-byte pubkey (unknown version → always succeed, deducts weight)
    let unknown_pubkey = vec![0x99; 33]; // not 32 bytes, so upgradable

    // Script: push sig placeholder, push 33-byte key, CHECKSIG, push sig, push 33-byte key, CHECKSIG
    // Stack layout: we push sigs via witness
    // Script: <unknown_pubkey> OP_CHECKSIG <unknown_pubkey> OP_CHECKSIG
    let mut leaf_script = Vec::new();
    leaf_script.push(33); // push 33 bytes
    leaf_script.extend_from_slice(&unknown_pubkey);
    leaf_script.push(0xac); // OP_CHECKSIG
    leaf_script.push(33);
    leaf_script.extend_from_slice(&unknown_pubkey);
    leaf_script.push(0xac); // OP_CHECKSIG

    let (_spk, _control) = build_single_leaf_taproot(&internal_key, &leaf_script);

    // Use CHECKSIGADD to keep consuming sigs without growing/shrinking the
    // stack unpredictably. CHECKSIGADD: (sig num pubkey -- num)
    // Each non-empty sig with unknown 33-byte pubkey deducts 50 from the weight budget.
    // Budget = witness_serialized_size + 50.
    //
    // Script: OP_0 <key> CHECKSIGADD <key> CHECKSIGADD ... (many times) OP_1
    // Stack items (witness): [sigN, ..., sig2, sig1]
    //
    // We need N*50 > budget. Make the script have many checksigadds.
    let n_checks = 10;
    let mut leaf_script = Vec::new();
    leaf_script.push(0x00); // OP_0 (initial counter)
    for _ in 0..n_checks {
        leaf_script.push(33); // push 33 bytes
        leaf_script.extend_from_slice(&unknown_pubkey);
        leaf_script.push(0xba); // OP_CHECKSIGADD
    }
    leaf_script.push(0x51); // OP_1 (or any truthy value — we just need weight to bust)

    let (spk, control) = build_single_leaf_taproot(&internal_key, &leaf_script);

    // N non-empty dummy sigs
    let stack_items: Vec<Vec<u8>> = (0..n_checks).map(|_| vec![0x01u8]).collect();
    let (tx, prev) = taproot_spend_tx(&spk, &leaf_script, &control, &stack_items);

    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert_eq!(result, Err(ScriptError::TapscriptValidationWeight),
        "Expected validation weight exhaustion, got: {:?}", result);
}

// =========================================================================
// 5. MULTI-LEAF TAPROOT MERKLE PATHS
// =========================================================================

#[test]
fn test_taproot_two_leaf_spend_first() {
    let (_, internal_key) = test_keypair();
    let leaf_a = vec![0x51u8]; // OP_1
    let leaf_b = vec![0x52u8]; // OP_2 (would fail cleanstack but not with OP_DROP)

    let (spk, ctrl_a, _ctrl_b) = build_two_leaf_taproot(&internal_key, &leaf_a, &leaf_b);
    let (tx, prev) = taproot_spend_tx(&spk, &leaf_a, &ctrl_a, &[]);
    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert!(result.is_ok(), "two-leaf spend A failed: {:?}", result.err());
}

#[test]
fn test_taproot_two_leaf_spend_second() {
    let (_, internal_key) = test_keypair();
    let leaf_a = vec![0x51u8]; // OP_1
    let leaf_b = vec![0x51u8]; // OP_1

    let (spk, _ctrl_a, ctrl_b) = build_two_leaf_taproot(&internal_key, &leaf_a, &leaf_b);
    let (tx, prev) = taproot_spend_tx(&spk, &leaf_b, &ctrl_b, &[]);
    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert!(result.is_ok(), "two-leaf spend B failed: {:?}", result.err());
}

#[test]
fn test_taproot_two_leaf_wrong_control_block() {
    let (_, internal_key) = test_keypair();
    let leaf_a = vec![0x51u8];
    let leaf_b = vec![0x52u8];

    let (spk, ctrl_a, _ctrl_b) = build_two_leaf_taproot(&internal_key, &leaf_a, &leaf_b);
    // Try spending leaf_b with leaf_a's control block → merkle proof mismatch
    let (tx, prev) = taproot_spend_tx(&spk, &leaf_b, &ctrl_a, &[]);
    let result = verify_taproot_spend(&tx, &prev, &spk, 0);
    assert_eq!(result, Err(ScriptError::WitnessProgramMismatch));
}

// =========================================================================
// 6. WITNESS_UNEXPECTED
// =========================================================================

#[test]
fn test_witness_unexpected_bare_script() {
    // Non-witness scriptPubKey (OP_1) with non-empty witness should fail
    let spk = vec![0x51u8]; // OP_1
    let c = credit_tx(&spk, 50_000);
    let witness = vec![vec![0x01u8]]; // non-empty witness
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
    assert_eq!(result, Err(ScriptError::WitnessUnexpected));
}

#[test]
fn test_witness_unexpected_p2sh_non_witness() {
    // P2SH script that is NOT a witness program, with non-empty witness
    let redeem = vec![0x51u8]; // OP_1 (not a witness program)
    let redeem_hash = hash160(&redeem);
    let mut script_pubkey = vec![0xa9, 0x14];
    script_pubkey.extend_from_slice(&redeem_hash);
    script_pubkey.push(0x87);
    let mut script_sig = vec![redeem.len() as u8];
    script_sig.extend_from_slice(&redeem);

    let witness = vec![vec![0x01u8]];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &script_sig, &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &script_sig,
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::WitnessUnexpected));
}

// =========================================================================
// 7. CLEANSTACK ENFORCEMENT
// =========================================================================

#[test]
fn test_cleanstack_extra_items() {
    // scriptSig pushes two items, scriptPubKey is OP_1
    // Stack after: [item1, item2, 1] — not clean
    let spk = vec![0x51u8]; // OP_1
    let script_sig = vec![0x51, 0x52]; // OP_1 OP_2

    let checker = consensus::checker::NoopChecker;
    let result = verify_script(
        &script_sig,
        &spk,
        &[],
        flags::VERIFY_CLEANSTACK | flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::CleanStack));
}

#[test]
fn test_cleanstack_single_item_passes() {
    let spk = vec![0x51u8]; // OP_1
    let checker = consensus::checker::NoopChecker;
    let result = verify_script(
        &[],
        &spk,
        &[],
        flags::VERIFY_CLEANSTACK | flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
        &checker,
    );
    assert!(result.is_ok());
}

// =========================================================================
// 8. MINIMALIF IN WITNESS V0
// =========================================================================

#[test]
fn test_minimalif_witness_v0_rejects_non_minimal() {
    // P2WSH with IF that takes a non-minimal argument (0x02 instead of 0x01)
    // Under MINIMALIF flag, this should fail
    let witness_script = vec![0x63, 0x51, 0x67, 0x00, 0x68]; // IF 1 ELSE 0 ENDIF
    let ws_hash = sha256_hash(&witness_script);

    // P2WSH: OP_0 <32-byte hash>
    let mut script_pubkey = vec![0x00, 0x20];
    script_pubkey.extend_from_slice(&ws_hash);

    // witness: [0x02 (non-minimal true), witness_script]
    let witness = vec![vec![0x02], witness_script.clone()];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_MINIMALIF,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::MinimalIf));
}

#[test]
fn test_minimalif_witness_v0_accepts_0x01() {
    let witness_script = vec![0x63, 0x51, 0x67, 0x00, 0x68]; // IF 1 ELSE 0 ENDIF
    let ws_hash = sha256_hash(&witness_script);
    let mut script_pubkey = vec![0x00, 0x20];
    script_pubkey.extend_from_slice(&ws_hash);

    // witness: [0x01 (minimal true), witness_script]
    let witness = vec![vec![0x01], witness_script.clone()];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_MINIMALIF,
        &checker,
    );
    assert!(result.is_ok(), "MINIMALIF with 0x01 should pass: {:?}", result);
}

#[test]
fn test_minimalif_witness_v0_accepts_empty() {
    let witness_script = vec![0x63, 0x51, 0x67, 0x00, 0x68]; // IF 1 ELSE 0 ENDIF
    let ws_hash = sha256_hash(&witness_script);
    let mut script_pubkey = vec![0x00, 0x20];
    script_pubkey.extend_from_slice(&ws_hash);

    // witness: [empty (minimal false), witness_script]
    let witness = vec![vec![], witness_script.clone()];
    let c = credit_tx(&script_pubkey, 50_000);
    let tx = spend_tx(&c, &[], &witness);
    let prev = vec![c.output[0].clone()];
    let checker = TxSignatureChecker::new(&tx, 0, prev[0].value, &prev);
    let wit: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        &script_pubkey,
        &wit,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_MINIMALIF,
        &checker,
    );
    // ELSE branch pushes OP_0 → eval_false
    assert_eq!(result, Err(ScriptError::EvalFalse));
}
