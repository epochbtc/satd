//! Every opcode in a tapscript leaf, against libbitcoinconsensus (Core's
//! interpreter), plus pay-to-anchor through `verify_script`.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use consensus::checker::NoopChecker;
use consensus::error::ScriptError;
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;

/// Core's `IsOpSuccess` (src/script/script.cpp:364-370), transcribed.
fn core_is_op_success(opcode: u8) -> bool {
    let opcode = opcode as u32;
    opcode == 80 || opcode == 98 || (126..=129).contains(&opcode)
        || (131..=134).contains(&opcode) || (137..=138).contains(&opcode)
        || (141..=142).contains(&opcode) || (149..=153).contains(&opcode)
        || (187..=254).contains(&opcode)
}

const CONSENSUS_FLAGS: u32 = flags::VERIFY_ALL_PRE_TAPROOT | flags::VERIFY_TAPROOT;

/// A script-path spend of a one-leaf taproot output holding `leaf`.
struct LeafSpend {
    spk: Vec<u8>,
    tx: Transaction,
    prevouts: Vec<TxOut>,
    witness: Vec<Vec<u8>>,
}

fn leaf_spend(leaf: &[u8]) -> LeafSpend {
    let secp = Secp256k1::new();
    let mut sk = [0u8; 32];
    sk[31] = 1;
    let (internal, _) = SecretKey::from_slice(&sk).unwrap().x_only_public_key(&secp);
    let script = ScriptBuf::from_bytes(leaf.to_vec());
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let control = info.control_block(&(script, LeafVersion::TapScript)).unwrap().serialize();
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&info.output_key().to_x_only_public_key().serialize());

    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes(spk.clone()),
    };
    let witness = vec![leaf.to_vec(), control];
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&witness),
        }],
        output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: ScriptBuf::new() }],
    };
    LeafSpend { spk, tx, prevouts: vec![prevout], witness }
}

fn rust_verify(s: &LeafSpend, script_flags: u32) -> Result<(), ScriptError> {
    let checker = TxSignatureChecker::new(&s.tx, 0, s.prevouts[0].value, &s.prevouts);
    verify_script(&[], &s.spk, &s.witness, script_flags, &checker)
}

fn cpp_verify(s: &LeafSpend, script_flags: u32) -> bool {
    let mut ser = Vec::new();
    s.tx.consensus_encode(&mut ser).unwrap();
    let utxos = [bitcoinconsensus::Utxo {
        script_pubkey: s.spk.as_ptr(),
        script_pubkey_len: s.spk.len() as u32,
        value: s.prevouts[0].value.to_sat() as i64,
    }];
    bitcoinconsensus::verify_with_flags(
        &s.spk,
        s.prevouts[0].value.to_sat(),
        &ser,
        Some(&utxos),
        0,
        script_flags,
    )
    .is_ok()
}

/// Each opcode alone as the leaf, and inside an unexecuted `0 IF .. ENDIF 1`.
fn leaves(op: u8) -> [Vec<u8>; 2] {
    [vec![op], vec![0x00, 0x63, op, 0x68, 0x51]]
}

#[test]
fn every_opcode_in_a_tapscript_leaf_matches_libbitcoinconsensus() {
    let mut diffs = Vec::new();
    for op in 0..=255u8 {
        for leaf in leaves(op) {
            let s = leaf_spend(&leaf);
            let rust = rust_verify(&s, CONSENSUS_FLAGS);
            let cpp = cpp_verify(&s, CONSENSUS_FLAGS);
            if rust.is_ok() != cpp {
                diffs.push(format!("leaf {leaf:02x?}: rust={rust:?} libbitcoinconsensus ok={cpp}"));
            }
        }
    }
    assert!(diffs.is_empty(), "{} verdicts differ:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn op_success_leaf_is_valid_and_discouraged_by_policy_flag() {
    let mut ops = 0;
    for op in (0..=255u8).filter(|&op| core_is_op_success(op)) {
        ops += 1;
        for leaf in leaves(op) {
            let s = leaf_spend(&leaf);
            assert_eq!(rust_verify(&s, CONSENSUS_FLAGS), Ok(()), "leaf {leaf:02x?}");
            assert_eq!(
                rust_verify(&s, CONSENSUS_FLAGS | flags::VERIFY_DISCOURAGE_OP_SUCCESS),
                Err(ScriptError::DiscourageOpSuccess),
                "leaf {leaf:02x?}"
            );
        }
    }
    assert_eq!(ops, 87);
    // An ordinary opcode in the same unexecuted branch is skipped, not a
    // success: `0 IF SIZE ENDIF 1` leaves [1] and passes under both flag sets,
    // while `0 IF SIZE ENDIF` leaves an empty stack and fails.
    let s = leaf_spend(&[0x00, 0x63, 0x82, 0x68, 0x51]);
    assert_eq!(rust_verify(&s, CONSENSUS_FLAGS | flags::VERIFY_DISCOURAGE_OP_SUCCESS), Ok(()));
    let s = leaf_spend(&[0x00, 0x63, 0x82, 0x68]);
    assert_eq!(rust_verify(&s, CONSENSUS_FLAGS), Err(ScriptError::CleanStack));
}

/// `OP_1 <0x4e73>`, the pay-to-anchor output.
const P2A_SPK: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

fn hash160(data: &[u8]) -> [u8; 20] {
    bitcoin::hashes::hash160::Hash::hash(data).to_byte_array()
}

#[test]
fn pay_to_anchor_spend_passes_discourage_upgradable_witness_program() {
    let policy = flags::VERIFY_ALL_PRE_TAPROOT
        | flags::VERIFY_TAPROOT
        | flags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;

    // Bare P2A: Core returns true before the discourage branch
    // (src/script/interpreter.cpp:1990).
    assert_eq!(verify_script(&[], &P2A_SPK, &[], policy, &NoopChecker), Ok(()));

    // P2SH-wrapped P2A: is_p2sh, so Core discourages it.
    let mut wrapped_spk = vec![0xa9, 0x14];
    wrapped_spk.extend_from_slice(&hash160(&P2A_SPK));
    wrapped_spk.push(0x87);
    let mut script_sig = vec![P2A_SPK.len() as u8];
    script_sig.extend_from_slice(&P2A_SPK);
    assert_eq!(
        verify_script(&script_sig, &wrapped_spk, &[], policy, &NoopChecker),
        Err(ScriptError::DiscourageUpgradableWitnessProgram)
    );
    // Both pass under consensus flags alone.
    assert_eq!(verify_script(&[], &P2A_SPK, &[], CONSENSUS_FLAGS, &NoopChecker), Ok(()));
    assert_eq!(
        verify_script(&script_sig, &wrapped_spk, &[], CONSENSUS_FLAGS, &NoopChecker),
        Ok(())
    );
}
