//! The signet commitment rewrite matches Bitcoin Core's byte for byte.
//!
//! A signet solution signs the block with the solution itself cut out of the
//! coinbase (`FetchAndClearCommitmentSection`, `signet.cpp:32-57`). The bytes
//! left behind change the coinbase txid and so the merkle root the signature
//! commits to: a rewrite that differs from Core's in one byte refuses a block
//! Core accepts. An op that does not parse ends Core's scan without losing the
//! section found before it, so the solution is still checked.
//!
//! Every expected rewrite below is Core's output, not a reading of it: the
//! function from `signet.cpp`, copied verbatim, compiled with Core's own
//! `script/script.cpp` (`GetScriptOp`, `CScript`) at commit 16613c9de9 and run
//! over each input.

use super::*;
use bitcoin::hashes::hex::FromHex;
use bitcoin::script::PushBytes;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{block, BlockHash, CompactTarget, Network, TxMerkleNode};

/// `OP_RETURN PUSH36[aa21a9ed || 32 zero bytes]`: a BIP 141 commitment.
const COMMITMENT: &str = "6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000";

fn hex(s: &str) -> Vec<u8> {
    Vec::<u8>::from_hex(s).expect("test hex")
}

/// `COMMITMENT` followed by `rest` (hex).
fn commitment_then(rest: &str) -> Vec<u8> {
    hex(&format!("{COMMITMENT}{rest}"))
}

/// The rewrite of `script`, or `None` when no signet section is found (Core
/// then leaves the script as it is).
fn rewrite(script: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    fetch_and_clear_signet_section(&ScriptBuf::from_bytes(script.to_vec()))
        .map(|(cleared, solution)| (cleared.into_bytes(), solution))
}

/// `(name, commitment output script after COMMITMENT, Core's rewrite after
/// COMMITMENT, Core's solution)`. `06ecc7daa20000` is a signet section holding
/// an empty scriptSig and an empty witness stack.
const CORE_REWRITES: &[(&str, &str, &str, &str)] = &[
    ("section only", "06ecc7daa20000", "04ecc7daa2", "0000"),
    ("zero-length PUSHDATA1 before", "4c0006ecc7daa20000", "4c04ecc7daa2", "0000"),
    ("zero-length PUSHDATA1 after", "06ecc7daa200004c00", "04ecc7daa24c", "0000"),
    ("zero-length PUSHDATA2 before", "4d000006ecc7daa20000", "4d04ecc7daa2", "0000"),
    ("zero-length PUSHDATA2 after", "06ecc7daa200004d0000", "04ecc7daa24d", "0000"),
    ("zero-length PUSHDATA4 before", "4e0000000006ecc7daa20000", "4e04ecc7daa2", "0000"),
    ("zero-length PUSHDATA4 after", "06ecc7daa200004e00000000", "04ecc7daa24e", "0000"),
    ("PUSHDATA1 with no length byte after", "06ecc7daa200004c", "04ecc7daa2", "0000"),
    ("PUSHDATA1 data cut short after", "06ecc7daa200004c05aabb", "04ecc7daa2", "0000"),
    ("direct push cut short after", "06ecc7daa2000005aabb", "04ecc7daa2", "0000"),
    ("PUSHDATA2 length cut short after", "06ecc7daa200004d01", "04ecc7daa2", "0000"),
    ("PUSHDATA4 length cut short after", "06ecc7daa200004e0100", "04ecc7daa2", "0000"),
    ("OP_0 before", "0006ecc7daa20000", "0004ecc7daa2", "0000"),
    ("non-push ops around", "0051ac06ecc7daa20000004f61", "0051ac04ecc7daa2004f61", "0000"),
    (
        "long length prefixes are rewritten short",
        "4c01014c06ecc7daa200004d0300aabbcc",
        "010104ecc7daa203aabbcc",
        "0000",
    ),
    ("a header with no data is not a section", "04ecc7daa206ecc7daa20000", "04ecc7daa204ecc7daa2", "0000"),
    ("only the first section is cleared", "06ecc7daa2000006ecc7daa20101", "04ecc7daa206ecc7daa20101", "0000"),
];

#[test]
fn the_commitment_rewrite_is_cores_byte_for_byte() {
    for (name, input, core_rewrite, core_solution) in CORE_REWRITES {
        let (cleared, solution) =
            rewrite(&commitment_then(input)).unwrap_or_else(|| panic!("{name}: Core finds the section"));
        assert_eq!(
            bitcoin::hex::DisplayHex::to_lower_hex_string(&cleared[..]),
            format!("{COMMITMENT}{core_rewrite}"),
            "{name}: rewritten commitment"
        );
        assert_eq!(solution, hex(core_solution), "{name}: solution");
    }

    // A section long enough to need OP_PUSHDATA1 keeps only the header.
    let data = "11".repeat(80);
    let (cleared, solution) =
        rewrite(&commitment_then(&format!("4c54ecc7daa2{data}"))).expect("Core finds the section");
    assert_eq!(cleared, commitment_then("04ecc7daa2"));
    assert_eq!(solution, hex(&data));
}

/// Core finds no section in these and keeps the script as it is.
#[test]
fn a_commitment_without_a_section_is_left_alone() {
    for (name, input) in [
        ("commitment only", ""),
        ("zero-length PUSHDATA1", "4c00"),
        ("PUSHDATA1 with no length byte", "4c"),
        ("a header with no data", "04ecc7daa2"),
        ("an unparseable op hides a later header", "4c0a04ecc7daa20000"),
    ] {
        assert_eq!(rewrite(&commitment_then(input)), None, "{name}");
    }
}

/// Core's `signet_parse_tests` (`src/test/validation_tests.cpp:69-128`), with
/// its `OP_TRUE` challenge.
#[test]
fn cores_signet_parse_tests() {
    let challenge = ScriptBuf::from_bytes(vec![0x51]);
    let genesis = bitcoin::constants::genesis_block(Network::Signet).block_hash();
    let check = |block: &Block| {
        let created = SignetTxs::create(block, &challenge).is_some();
        let checked = check_signet_block_solution(block, challenge.as_bytes(), genesis).is_ok();
        assert_eq!(created, checked, "Create and the check agree");
        checked
    };
    let mut block = Block {
        header: block::Header {
            version: block::Version::from_consensus(0),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata: vec![],
    };

    // empty block is invalid
    assert!(!check(&block));

    // no witness commitment
    let mut cb = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() }],
    };
    block.txdata = vec![cb.clone(), cb.clone()];
    assert!(!check(&block));

    let section_141: Vec<u8> = [0xaa, 0x21, 0xa9, 0xed].into_iter().chain([0xff; 32]).collect();
    let with_sections = |cb: &mut Transaction, block: &mut Block, sections: &[&[u8]]| {
        let mut b = Builder::new().push_opcode(OP_RETURN);
        for s in sections {
            let pb: &PushBytes = (*s).try_into().unwrap();
            b = b.push_slice(pb);
        }
        cb.output[0].script_pubkey = b.into_script();
        block.txdata[0] = cb.clone();
    };

    // no header is treated valid
    with_sections(&mut cb, &mut block, &[&section_141]);
    assert!(check(&block));

    // no data after header, valid
    let mut section_325 = vec![0xec, 0xc7, 0xda, 0xa2];
    with_sections(&mut cb, &mut block, &[&section_141, &section_325]);
    assert!(check(&block));

    // Premature end of data, invalid
    section_325.extend([0x01, 0x51]);
    with_sections(&mut cb, &mut block, &[&section_141, &section_325]);
    assert!(!check(&block));

    // has data, valid
    section_325.push(0x00);
    with_sections(&mut cb, &mut block, &[&section_141, &section_325]);
    assert!(check(&block));

    // Extraneous data, invalid
    section_325.push(0x00);
    with_sections(&mut cb, &mut block, &[&section_141, &section_325]);
    assert!(!check(&block));
}

// ---- Whole blocks, checked the way a block from the network is ----

fn block_with_commitment(script: Vec<u8>) -> Block {
    let coinbase = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new().push_int(42).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) }],
    };
    Block {
        header: block::Header {
            version: block::Version::from_consensus(0x20000000),
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root: TxMerkleNode::from_raw_hash(coinbase.compute_txid().to_raw_hash()),
            time: 1_600_000_000,
            bits: CompactTarget::from_consensus(0x1e0377ae),
            nonce: 0,
        },
        txdata: vec![coinbase],
    }
}

fn genesis() -> BlockHash {
    bitcoin::constants::genesis_block(Network::Signet).block_hash()
}

/// A P2WPKH challenge and its key.
fn p2wpkh_challenge() -> (ScriptBuf, bitcoin::secp256k1::SecretKey, bitcoin::CompressedPublicKey) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
    let pk = bitcoin::CompressedPublicKey(sk.public_key(&secp));
    (ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()), sk, pk)
}

/// A solution (empty scriptSig, P2WPKH witness) signing the block whose
/// coinbase commitment is `signed_commitment` exactly. `signed_commitment`
/// must hold no signet section, so that the message is built over it as it
/// stands; the fixed header, prev hash and time are those of every block here.
fn solution_signing(signed_commitment: &[u8]) -> Vec<u8> {
    assert_eq!(rewrite(signed_commitment), None, "the signed commitment carries no section");
    let (challenge, sk, pk) = p2wpkh_challenge();
    let txs = SignetTxs::create(&block_with_commitment(signed_commitment.to_vec()), &challenge)
        .expect("signing transactions");
    let sighash = SighashCache::new(&txs.to_sign)
        .p2wpkh_signature_hash(0, &challenge, Amount::ZERO, EcdsaSighashType::All)
        .expect("sighash");
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let mut sig = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    let witness = Witness::from_slice(&[sig, pk.to_bytes().to_vec()]);
    let mut solution = bitcoin::consensus::serialize(&ScriptBuf::new());
    solution.extend_from_slice(&bitcoin::consensus::serialize(&witness));
    solution
}

/// `before || PUSH[signet header || solution] || after`, all after
/// `COMMITMENT`.
fn commitment_with_section(before: &str, solution: &[u8], after: &str) -> Vec<u8> {
    let mut section = SIGNET_HEADER.to_vec();
    section.extend_from_slice(solution);
    let mut script = commitment_then(before);
    let mut pushed = Vec::new();
    append_push(&mut pushed, &section);
    script.extend_from_slice(&pushed);
    script.extend_from_slice(&hex(after));
    script
}

/// A zero-length `OP_PUSHDATA1/2/4` stays its own opcode in the signed
/// message. A block signed over Core's rewrite is accepted, and the same
/// block signed over the rewrite with `OP_0` in that place is refused.
#[test]
fn a_zero_length_pushdata_is_signed_as_its_own_opcode() {
    let (challenge, _, _) = p2wpkh_challenge();
    // (before, after, Core's rewrite after COMMITMENT, the rewrite with OP_0)
    for (before, after, core, with_op_0) in [
        ("4c00", "", "4c04ecc7daa2", "0004ecc7daa2"),
        ("", "4c00", "04ecc7daa24c", "04ecc7daa200"),
        ("", "4d0000", "04ecc7daa24d", "04ecc7daa200"),
        ("", "4e00000000", "04ecc7daa24e", "04ecc7daa200"),
    ] {
        let signed_over_core = commitment_with_section(before, &solution_signing(&commitment_then(core)), after);
        assert!(
            check_signet_block_solution(&block_with_commitment(signed_over_core), challenge.as_bytes(), genesis())
                .is_ok(),
            "{before}|section|{after}: a block signed over Core's rewrite {core} must verify"
        );

        let signed_over_op_0 =
            commitment_with_section(before, &solution_signing(&commitment_then(with_op_0)), after);
        assert!(
            matches!(
                check_signet_block_solution(&block_with_commitment(signed_over_op_0), challenge.as_bytes(), genesis()),
                Err(ValidationError::BadSignetSolution)
            ),
            "{before}|section|{after}: a block signed over {with_op_0} is not one Core accepts"
        );
    }
}

/// Core keeps the section it found before an op that does not parse, and drops
/// the rest of the script from the signed message. A block signed that way is
/// accepted.
#[test]
fn a_section_before_an_unparseable_push_is_checked() {
    let (challenge, _, _) = p2wpkh_challenge();
    for after in ["4c", "4c05aabb", "05aabb", "4d01", "4e0100"] {
        let script = commitment_with_section("", &solution_signing(&commitment_then("04ecc7daa2")), after);
        assert!(
            check_signet_block_solution(&block_with_commitment(script), challenge.as_bytes(), genesis()).is_ok(),
            "section then {after}: Core checks the section and accepts the block"
        );
    }
}

/// The other side of the same rule: the section is checked, so a solution that
/// does not parse is refused, even under a challenge any empty solution meets.
#[test]
fn a_bad_section_before_an_unparseable_push_is_refused() {
    let op_true = [0x51];
    // A solution whose scriptSig claims one byte and has none.
    let script = commitment_with_section("", &[0x01], "4c");
    assert!(matches!(
        check_signet_block_solution(&block_with_commitment(script), &op_true, genesis()),
        Err(ValidationError::BadSignetSolution)
    ));
    // The same block without the tail: refused too, for the same reason.
    let script = commitment_with_section("", &[0x01], "");
    assert!(matches!(
        check_signet_block_solution(&block_with_commitment(script), &op_true, genesis()),
        Err(ValidationError::BadSignetSolution)
    ));
    // And with a well-formed solution and the tail, accepted.
    let script = commitment_with_section("", &[0x00, 0x00], "4c");
    assert!(check_signet_block_solution(&block_with_commitment(script), &op_true, genesis()).is_ok());
}
