//! Script shapes at the edges of the interpreter's parsing and size checks:
//! a push whose length runs past the end of the script, a PUSHDATA4 length
//! that only reads right with all four bytes, a 40-byte witness program, a
//! control block one node over the limit. Core's own vectors miss them.
//!
//! `core_edge_cases.rs` and `taproot_tests.rs` check the exact error each one
//! gives; `differential.rs` runs those whose flags libbitcoinkernel takes
//! through Core's interpreter too, so Core confirms the verdict.
#![allow(dead_code)]

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, HashEngine, hash160, sha256, sha256d};
use bitcoin::secp256k1::{
    Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;

const TEST_SECKEY: &str = "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa";

/// One input to verify: the spending transaction (input 0), the output it
/// spends, and the flags to verify it under.
pub struct Case {
    pub tx: Transaction,
    pub spent: TxOut,
    pub flags: u32,
}

impl Case {
    fn new(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: u32) -> Self {
        let spent = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
        };
        let credit = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![spent.clone()],
        };
        let mut buf = Vec::new();
        credit.consensus_encode(&mut buf).unwrap();
        let txid = Txid::from_byte_array(sha256d::Hash::hash(&buf).to_byte_array());
        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(witness),
            }],
            output: vec![TxOut {
                value: spent.value,
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Case { tx, spent, flags }
    }

    pub fn script_sig(&self) -> &[u8] {
        self.tx.input[0].script_sig.as_bytes()
    }

    pub fn script_pubkey(&self) -> &[u8] {
        self.spent.script_pubkey.as_bytes()
    }

    pub fn witness(&self) -> Vec<Vec<u8>> {
        self.tx.input[0]
            .witness
            .iter()
            .map(|w| w.to_vec())
            .collect()
    }

    /// Verify input 0 with the Rust interpreter.
    pub fn verify(&self) -> Result<(), ScriptError> {
        let prev = [self.spent.clone()];
        let checker = TxSignatureChecker::new(&self.tx, 0, self.spent.value, &prev);
        verify_script(
            self.script_sig(),
            self.script_pubkey(),
            &self.witness(),
            self.flags,
            &checker,
        )
    }
}

fn p2sh(redeem_script: &[u8]) -> Vec<u8> {
    let mut spk = vec![0xa9, 0x14]; // OP_HASH160 <20 bytes>
    spk.extend_from_slice(hash160::Hash::hash(redeem_script).as_byte_array());
    spk.push(0x87); // OP_EQUAL
    spk
}

/// A PUSHDATA2 with one length byte, at the end of the scriptPubKey.
pub fn pushdata2_missing_a_length_byte() -> Case {
    Case::new(&[], &[0x4d, 0x01], &[], flags::VERIFY_NONE)
}

/// `OP_CHECKSIG 0x4d 0x01`: FindAndDelete walks the scriptCode, truncated
/// PUSHDATA2 and all, before the signature is looked at.
pub fn pushdata2_missing_a_length_byte_after_checksig() -> Case {
    // Push sig [07], pubkey [01].
    Case::new(
        &[0x01, 0x07, 0x01, 0x01],
        &[0xac, 0x4d, 0x01],
        &[],
        flags::VERIFY_NONE,
    )
}

/// The same scriptCode as a P2SH redeemScript, under every flag: what a
/// relayed transaction would carry.
pub fn p2sh_redeem_script_with_a_truncated_pushdata2() -> Case {
    let redeem = [0xac, 0x4d, 0x01];
    // Push sig [30], pubkey [20], then the redeemScript. None is an OP_N
    // value, so MINIMALDATA is met.
    let mut script_sig = vec![0x01, 0x30, 0x01, 0x20, redeem.len() as u8];
    script_sig.extend_from_slice(&redeem);
    Case::new(&script_sig, &p2sh(&redeem), &[], flags::ALL_FLAGS)
}

/// PUSHDATA4 with length 0x00010001 (byte 2 set) and one byte of data.
pub fn pushdata4_length_with_byte_2_set() -> Case {
    Case::new(
        &[],
        &[0x4e, 0x01, 0x00, 0x01, 0x00, 0x51],
        &[],
        flags::VERIFY_NONE,
    )
}

/// PUSHDATA4 with length 1 and one byte of data, which is true.
pub fn pushdata4_length_of_one() -> Case {
    Case::new(
        &[],
        &[0x4e, 0x01, 0x00, 0x00, 0x00, 0x51],
        &[],
        flags::VERIFY_NONE,
    )
}

/// A 257-byte redeemScript, `PUSHDATA1 <253 zero bytes> OP_DROP OP_1`, pushed
/// in the scriptSig with PUSHDATA4 (length bytes 0 and 1 set). Push only,
/// and MINIMALDATA is not a consensus rule, so it spends.
pub fn p2sh_redeem_script_pushed_with_pushdata4() -> Case {
    let mut redeem = vec![0x4c, 0xfd];
    redeem.extend([0x00; 253]);
    redeem.extend([0x75, 0x51]); // OP_DROP OP_1
    assert_eq!(redeem.len(), 257);
    let mut script_sig = vec![0x4e];
    script_sig.extend((redeem.len() as u32).to_le_bytes());
    script_sig.extend_from_slice(&redeem);
    Case::new(&script_sig, &p2sh(&redeem), &[], flags::VERIFY_P2SH)
}

/// `<pubkey> OP_CHECKSIG PUSHDATA1 <80 x 0xab> OP_DROP`, signed with
/// SIGHASH_ALL. The scriptCode holds no OP_CODESEPARATOR, only 0xab bytes in
/// push data, so the legacy sighash is over the script as it is.
pub fn checksig_with_codeseparator_bytes_in_pushdata1_data() -> Case {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let mut spk = vec![0x21];
    spk.extend_from_slice(&pk.serialize());
    spk.extend([0xac, 0x4c, 0x50]); // OP_CHECKSIG PUSHDATA1 80
    spk.extend([0xab; 80]);
    spk.push(0x75); // OP_DROP
    let flags = flags::VERIFY_P2SH
        | flags::VERIFY_STRICTENC
        | flags::VERIFY_DERSIG
        | flags::VERIFY_LOW_S
        | flags::VERIFY_NULLFAIL;

    // The legacy sighash leaves every scriptSig out, so sign the unsigned
    // transaction and then put the signature in.
    let mut case = Case::new(&[], &spk, &[], flags);
    let sighash = SighashCache::new(&case.tx)
        .legacy_signature_hash(0, &case.spent.script_pubkey, 0x01)
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let mut sig = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    sig.push(0x01); // SIGHASH_ALL
    let mut script_sig = vec![sig.len() as u8];
    script_sig.extend_from_slice(&sig);
    case.tx.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
    case
}

/// `OP_n <40 bytes>`: the longest witness program.
fn witness_program_of_40_bytes(version_opcode: u8, witness: &[Vec<u8>], flags: u32) -> Case {
    let mut spk = vec![version_opcode, 0x28];
    spk.extend([0x01; 40]);
    Case::new(&[], &spk, witness, flags)
}

/// A version 1 program of 40 bytes is an unknown witness program: it spends.
pub fn witness_v1_program_of_40_bytes(extra_flags: u32) -> Case {
    witness_program_of_40_bytes(
        0x51,
        &[vec![0x01]],
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | extra_flags,
    )
}

/// A version 0 program of 40 bytes is neither P2WPKH nor P2WSH.
pub fn witness_v0_program_of_40_bytes() -> Case {
    witness_program_of_40_bytes(0x00, &[], flags::VERIFY_P2SH | flags::VERIFY_WITNESS)
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// A script path spend of the leaf `OP_1` through a path of `nodes` sibling
/// hashes, with the output key tweaked by the root that path gives, so the
/// commitment holds at any depth.
pub fn taproot_script_path_with_nodes(nodes: usize) -> Case {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(TEST_SECKEY).unwrap()).unwrap();
    let (internal, _) = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk));
    let leaf = [0x51u8]; // OP_1
    let mut root = tagged_hash(b"TapLeaf", &[&[0xc0, leaf.len() as u8], &leaf]);
    let path: Vec<[u8; 32]> = (0..nodes as u32)
        .map(|i| sha256::Hash::hash(&i.to_le_bytes()).to_byte_array())
        .collect();
    for node in &path {
        root = if root < *node {
            tagged_hash(b"TapBranch", &[&root, node])
        } else {
            tagged_hash(b"TapBranch", &[node, &root])
        };
    }
    let tweak = tagged_hash(b"TapTweak", &[&internal.serialize(), &root]);
    let (output, parity) = internal
        .add_tweak(&secp, &Scalar::from_be_bytes(tweak).unwrap())
        .unwrap();
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&output.serialize());
    let mut control = vec![0xc0 | u8::from(parity == Parity::Odd)];
    control.extend_from_slice(&internal.serialize());
    for node in &path {
        control.extend_from_slice(node);
    }
    assert_eq!(control.len(), 33 + 32 * nodes);
    Case::new(
        &[],
        &spk,
        &[leaf.to_vec(), control],
        flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_TAPROOT,
    )
}

/// A 33-byte pubkey that is never valid: CHECKSIG against it is false.
const NOT_A_PUBKEY: [u8; 33] = [0x02; 33];

/// `<push X> OP_DROP <pubkey> OP_CHECKSIG OP_NOT`, with `push_x` the push of
/// X and `script_sig` pushing the signature. The script spends exactly when
/// FindAndDelete raises no error.
fn checksig_not_after_a_push(script_sig: &[u8], push_x: &[u8]) -> Case {
    let mut spk = push_x.to_vec();
    spk.extend([0x75, 0x21]); // OP_DROP, push 33
    spk.extend_from_slice(&NOT_A_PUBKEY);
    spk.extend([0xac, 0x91]); // OP_CHECKSIG OP_NOT
    Case::new(script_sig, &spk, &[], flags::VERIFY_CONST_SCRIPTCODE)
}

/// A 256-byte signature, which takes a PUSHDATA2, found in the scriptCode.
pub fn const_scriptcode_finds_a_256_byte_signature() -> Case {
    let mut push = vec![0x4d, 0x00, 0x01];
    push.extend([0x11; 256]);
    checksig_not_after_a_push(&push, &push)
}

/// A signature `[07]` whose push, `01 07`, only appears inside the data of a
/// 256-byte PUSHDATA4 in the scriptCode.
pub fn const_scriptcode_skips_a_signature_inside_pushdata4_data() -> Case {
    let mut push = vec![0x4e, 0x00, 0x01, 0x00, 0x00];
    for _ in 0..128 {
        push.extend([0x01, 0x07]);
    }
    checksig_not_after_a_push(&[0x01, 0x07], &push)
}
