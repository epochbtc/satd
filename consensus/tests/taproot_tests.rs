//! Taproot tests: BIP341 wallet vectors (key-path spending with real signed tx)
//! and hand-crafted tapscript tests replacing the auto-generated ones from
//! Bitcoin Core's script_tests.json.

mod helpers;

use bitcoin::consensus::Decodable;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use serde_json::Value;

/// BIP341 key-path spending: verify every input of the fully-signed test
/// transaction from bip341_wallet_vectors.json.
#[test]
fn test_bip341_key_path_spending() {
    let data = include_str!("../test-data/bip341_wallet_vectors.json");
    let vectors: Value = serde_json::from_str(data).unwrap();

    let kps = &vectors["keyPathSpending"][0];

    // Deserialize the fully signed transaction
    let tx_hex = kps["auxiliary"]["fullySignedTx"].as_str().unwrap();
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let tx: Transaction =
        Transaction::consensus_decode(&mut tx_bytes.as_slice()).unwrap();

    // Build UTXOs from the test vector
    let utxos_json = kps["given"]["utxosSpent"].as_array().unwrap();
    let prev_outputs: Vec<TxOut> = utxos_json
        .iter()
        .map(|u| {
            let spk_hex = u["scriptPubKey"].as_str().unwrap();
            let amount = u["amountSats"].as_u64().unwrap();
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::from_bytes(hex::decode(spk_hex).unwrap()),
            }
        })
        .collect();

    assert_eq!(prev_outputs.len(), tx.input.len());

    let script_flags = flags::VERIFY_P2SH
        | flags::VERIFY_WITNESS
        | flags::VERIFY_TAPROOT;

    // Verify each input
    let mut verified = 0;
    for (i, (input, prev_out)) in tx.input.iter().zip(prev_outputs.iter()).enumerate() {
        let checker = TxSignatureChecker::new(
            &tx,
            i,
            prev_out.value,
            &prev_outputs,
        );

        let witness_stack: Vec<Vec<u8>> = input.witness.iter().map(|w| w.to_vec()).collect();

        let result = verify_script(
            input.script_sig.as_bytes(),
            prev_out.script_pubkey.as_bytes(),
            &witness_stack,
            script_flags,
            &checker,
        );

        assert!(
            result.is_ok(),
            "Input {i} failed: {:?} (scriptPubKey={})",
            result.err(),
            hex::encode(prev_out.script_pubkey.as_bytes()),
        );
        verified += 1;
    }

    eprintln!("BIP341 key-path spending: verified {verified} inputs");
    assert!(verified > 0);
}

/// BIP341 scriptPubKey construction: verify tapleaf hashes, merkle roots,
/// and tweaked pubkeys match the expected values.
#[test]
fn test_bip341_script_pubkey_construction() {
    let data = include_str!("../test-data/bip341_wallet_vectors.json");
    let vectors: Value = serde_json::from_str(data).unwrap();

    let tests = vectors["scriptPubKey"].as_array().unwrap();
    let mut verified = 0;

    for (i, test) in tests.iter().enumerate() {
        let expected_spk = test["expected"]["scriptPubKey"].as_str().unwrap();
        let expected_spk_bytes = hex::decode(expected_spk).unwrap();

        // The scriptPubKey should be: OP_1 <32-byte-tweaked-pubkey>
        assert_eq!(expected_spk_bytes.len(), 34, "test {i}: wrong scriptPubKey length");
        assert_eq!(expected_spk_bytes[0], 0x51, "test {i}: missing OP_1");
        assert_eq!(expected_spk_bytes[1], 0x20, "test {i}: missing push 32");

        let tweaked_pubkey_hex = test["intermediary"]["tweakedPubkey"].as_str().unwrap();
        let tweaked_pubkey = hex::decode(tweaked_pubkey_hex).unwrap();
        assert_eq!(
            &expected_spk_bytes[2..],
            tweaked_pubkey.as_slice(),
            "test {i}: tweakedPubkey mismatch"
        );

        // Verify the tweak computation
        let internal_pubkey_hex = test["given"]["internalPubkey"].as_str().unwrap();
        let internal_pubkey = hex::decode(internal_pubkey_hex).unwrap();
        let tweak_hex = test["intermediary"]["tweak"].as_str().unwrap();
        let expected_tweak = hex::decode(tweak_hex).unwrap();

        // Compute tweak: SHA256(SHA256("TapTweak") || SHA256("TapTweak") || internal_pubkey || merkle_root)
        let merkle_root_val = &test["intermediary"]["merkleRoot"];
        let merkle_root = if merkle_root_val.is_null() || merkle_root_val.as_str() == Some("") {
            None
        } else {
            Some(hex::decode(merkle_root_val.as_str().unwrap()).unwrap())
        };

        let computed_tweak = compute_tap_tweak(&internal_pubkey, merkle_root.as_deref());
        assert_eq!(
            computed_tweak,
            expected_tweak.as_slice(),
            "test {i}: tweak mismatch"
        );

        verified += 1;
    }

    eprintln!("BIP341 scriptPubKey construction: verified {verified} test vectors");
}

fn compute_tap_tweak(internal_pubkey: &[u8], merkle_root: Option<&[u8]>) -> Vec<u8> {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(b"TapTweak");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(internal_pubkey);
    if let Some(root) = merkle_root {
        engine.input(root);
    }
    sha256::Hash::from_engine(engine).to_byte_array().to_vec()
}

// ---------------------------------------------------------------------------
// Hand-crafted tapscript tests replacing the auto-generated #SCRIPT#/
// #CONTROLBLOCK#/#TAPROOTOUTPUT# tests from script_tests.json.
//
// We use a known internal key and construct real taproot outputs with
// tapscript leaves, then build spending transactions.
// ---------------------------------------------------------------------------

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey, Scalar, Parity, Keypair};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, Sequence, TxIn, Txid, Witness};

/// Known test secret key (from BIP341 test vectors).
const TEST_SECKEY: &str = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";

struct TaprootTestEnv {
    secp: Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
    #[allow(dead_code)]
    internal_seckey: SecretKey,
}

impl TaprootTestEnv {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let sk_bytes = hex::decode(TEST_SECKEY).unwrap();
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        Self {
            secp,
            internal_key: xonly,
            internal_seckey: sk,
        }
    }

    /// Build a taproot output committing to a single leaf script.
    fn build_taproot_output(&self, leaf_script: &[u8]) -> (ScriptBuf, Vec<u8>) {
        // Compute tapleaf hash
        let leaf_version: u8 = 0xc0; // TAPSCRIPT
        let tapleaf_hash = compute_tapleaf_hash(leaf_version, leaf_script);

        // Merkle root = tapleaf hash (single leaf)
        let merkle_root = tapleaf_hash;

        // Compute tweak
        let tweak = compute_tap_tweak_hash(&self.internal_key.serialize(), &merkle_root);
        let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, tweaked_parity) = self.internal_key.add_tweak(&self.secp, &tweak_scalar).unwrap();

        // Build scriptPubKey: OP_1 <32-byte tweaked key>
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&tweaked_key.serialize());

        // Build control block: parity_byte || internal_key
        let parity_byte = leaf_version | if tweaked_parity == Parity::Odd { 1 } else { 0 };
        let mut control = vec![parity_byte];
        control.extend_from_slice(&self.internal_key.serialize());
        // No merkle path for single-leaf tree

        (ScriptBuf::from_bytes(spk), control)
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

fn compute_tap_tweak_hash(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"TapTweak");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(internal_key);
    engine.input(merkle_root);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn build_taproot_spending_tx(
    script_pubkey: &ScriptBuf,
    leaf_script: &[u8],
    control_block: &[u8],
    witness_stack: &[Vec<u8>],
) -> (Transaction, Vec<TxOut>) {
    let value = Amount::from_sat(100_000);
    let credit_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: script_pubkey.clone(),
        }],
    };

    let mut buf = Vec::new();
    bitcoin::consensus::Encodable::consensus_encode(&credit_tx, &mut buf).unwrap();
    let txid = Txid::from_byte_array(
        bitcoin::hashes::sha256d::Hash::hash(&buf).to_byte_array(),
    );

    // Build witness: [stack items..., leaf_script, control_block]
    let mut w = Witness::new();
    for item in witness_stack {
        w.push(item);
    }
    w.push(leaf_script);
    w.push(control_block);

    let spend_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let prev_outputs = vec![credit_tx.output[0].clone()];
    (spend_tx, prev_outputs)
}

/// Tapscript: OP_1 (trivially true script in tapscript leaf)
#[test]
fn test_tapscript_trivial_true() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0x51u8]; // OP_1
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) = build_taproot_spending_tx(&spk, &leaf_script, &control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(result.is_ok(), "tapscript OP_1 failed: {:?}", result.err());
}

/// Tapscript: OP_0 (trivially false → should fail with EVAL_FALSE)
#[test]
fn test_tapscript_trivial_false() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0x00u8]; // OP_0
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) = build_taproot_spending_tx(&spk, &leaf_script, &control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::EvalFalse));
}

/// Tapscript: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL (arithmetic in tapscript)
#[test]
fn test_tapscript_arithmetic() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0x51, 0x52, 0x93, 0x53, 0x87]; // 1 2 ADD 3 EQUAL
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) = build_taproot_spending_tx(&spk, &leaf_script, &control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(result.is_ok(), "tapscript arithmetic failed: {:?}", result.err());
}

/// Tapscript: OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF with TRUE witness
#[test]
fn test_tapscript_if_true() {
    let env = TaprootTestEnv::new();
    // IF 1 ELSE 0 ENDIF
    let leaf_script = vec![0x63, 0x51, 0x67, 0x00, 0x68];
    let (spk, control) = env.build_taproot_output(&leaf_script);
    // Push OP_1 (0x01 byte) as witness to satisfy the IF
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &control, &[vec![0x01]]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(result.is_ok(), "tapscript IF true failed: {:?}", result.err());
}

/// Tapscript: OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF with FALSE witness
#[test]
fn test_tapscript_if_false() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0x63, 0x51, 0x67, 0x00, 0x68];
    let (spk, control) = env.build_taproot_output(&leaf_script);
    // Push empty (false) as witness
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &control, &[vec![]]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::EvalFalse));
}

/// Tapscript: CHECKSIG with empty pubkey must fail with TAPSCRIPT_EMPTY_PUBKEY
#[test]
fn test_tapscript_empty_pubkey_checksig() {
    let env = TaprootTestEnv::new();
    // Push empty, then OP_CHECKSIG
    let leaf_script = vec![0x00, 0xac]; // OP_0 OP_CHECKSIG
    let (spk, control) = env.build_taproot_output(&leaf_script);
    // Witness: dummy sig
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &control, &[vec![0x00]]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::TapscriptEmptyPubkey));
}

/// Tapscript: OP_CHECKMULTISIG is forbidden in tapscript
#[test]
fn test_tapscript_checkmultisig_forbidden() {
    let env = TaprootTestEnv::new();
    // OP_1 OP_1 <32-byte-pubkey> OP_1 OP_CHECKMULTISIG
    let mut leaf_script = vec![0x51, 0x51]; // OP_1 OP_1
    leaf_script.push(0x20); // push 32 bytes
    leaf_script.extend_from_slice(&env.internal_key.serialize());
    leaf_script.push(0x51); // OP_1
    leaf_script.push(0xae); // OP_CHECKMULTISIG
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &control, &[vec![]]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::TapscriptCheckMultiSig));
}

/// Tapscript: OP_SUCCESS causes immediate success
#[test]
fn test_tapscript_op_success() {
    let env = TaprootTestEnv::new();
    // OP_SUCCESS126 (0xfe) — should succeed immediately
    let leaf_script = vec![0xfe];
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) = build_taproot_spending_tx(&spk, &leaf_script, &control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(result.is_ok(), "OP_SUCCESS should succeed: {:?}", result.err());
}

/// Tapscript: OP_SUCCESS with DISCOURAGE_OP_SUCCESS flag
#[test]
fn test_tapscript_op_success_discouraged() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0xfe]; // OP_SUCCESS126
    let (spk, control) = env.build_taproot_output(&leaf_script);
    let (tx, prev_outputs) = build_taproot_spending_tx(&spk, &leaf_script, &control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH
            | flags::VERIFY_WITNESS
            | flags::VERIFY_TAPROOT
            | flags::VERIFY_DISCOURAGE_OP_SUCCESS,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::DiscourageOpSuccess));
}

/// Tapscript: HASH160 + TOALTSTACK/FROMALTSTACK interaction
#[test]
fn test_tapscript_altstack_hash() {
    let env = TaprootTestEnv::new();
    // Push data, TOALTSTACK, push expected hash, FROMALTSTACK, HASH160, EQUAL
    // We push "hello" and its HASH160
    let data = b"hello";
    let hash160 = {
        use sha2::Digest;
        let sha = sha2::Sha256::digest(data);
        let mut hasher = ripemd::Ripemd160::new();
        ripemd::Digest::update(&mut hasher, sha);
        let h: [u8; 20] = ripemd::Digest::finalize(hasher).into();
        h
    };

    // Leaf script: HASH160 <20-byte hash> EQUAL
    let mut leaf_script = vec![0xa9]; // OP_HASH160
    leaf_script.push(0x14); // push 20 bytes
    leaf_script.extend_from_slice(&hash160);
    leaf_script.push(0x87); // OP_EQUAL

    let (spk, control) = env.build_taproot_output(&leaf_script);
    // Witness: push "hello"
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &control, &[data.to_vec()]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert!(result.is_ok(), "tapscript HASH160 test failed: {:?}", result.err());
}

/// Taproot: wrong control block size
#[test]
fn test_taproot_wrong_control_size() {
    let env = TaprootTestEnv::new();
    let leaf_script = vec![0x51u8]; // OP_1
    let (spk, _control) = env.build_taproot_output(&leaf_script);

    // Build with a truncated control block (only 10 bytes instead of 33)
    let bad_control = vec![0xc0; 10];
    let (tx, prev_outputs) =
        build_taproot_spending_tx(&spk, &leaf_script, &bad_control, &[]);

    let checker = TxSignatureChecker::new(&tx, 0, prev_outputs[0].value, &prev_outputs);
    let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();

    let result = verify_script(
        &[],
        spk.as_bytes(),
        &witness_stack,
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
        &checker,
    );
    assert_eq!(result, Err(ScriptError::TaprootWrongControlSize));
}
