//! Core's `ValidateInputsStandardness` and `IsWitnessStandard`, rule by rule
//! (`src/policy/policy.cpp`; Core's `transaction_tests.cpp` covers the same
//! ground).

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness, absolute, transaction};

fn tx(inputs: Vec<(ScriptBuf, Witness)>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .into_iter()
            .enumerate()
            .map(|(i, (script_sig, witness))| TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([i as u8 + 1; 32]), 0),
                script_sig,
                sequence: Sequence::MAX,
                witness,
            })
            .collect(),
        output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: p2wpkh() }],
    }
}

fn out(spk: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(10_000), script_pubkey: spk }
}

fn p2wpkh() -> ScriptBuf {
    ScriptBuf::from_bytes([&[0x00, 20][..], &[7; 20]].concat())
}

fn p2wsh_of(script: &[u8]) -> ScriptBuf {
    let h = bitcoin::hashes::sha256::Hash::hash(script);
    ScriptBuf::from_bytes([&[0x00, 32][..], h.as_byte_array()].concat())
}

fn p2tr() -> ScriptBuf {
    ScriptBuf::from_bytes([&[0x51, 32][..], &[9; 32]].concat())
}

fn p2sh_of(redeem: &[u8]) -> ScriptBuf {
    let h = bitcoin::hashes::hash160::Hash::hash(redeem);
    ScriptBuf::from_bytes([&[0xa9, 20][..], h.as_byte_array(), &[0x87]].concat())
}

/// A scriptSig that pushes `data` (a redeem script, say).
fn push(data: &[u8]) -> ScriptBuf {
    Builder::new().push_slice(PushBytesBuf::try_from(data.to_vec()).unwrap()).into_script()
}

/// `n` `OP_CHECKSIG`s.
fn checksigs(n: usize) -> Vec<u8> {
    vec![0xac; n]
}

fn nonstd(t: &Transaction, prevouts: &[TxOut]) -> String {
    validate_inputs_standardness(t, prevouts).expect_err("nonstandard")
}

#[test]
fn the_spent_output_types_core_solves_are_standard_inputs() {
    let key33 = [&[0x21, 0x02][..], &[1; 32], &[0xac]].concat();
    let key65 = [&[0x41, 0x04][..], &[1; 64], &[0xac]].concat();
    let p2pkh = [&[0x76, 0xa9, 20][..], &[3; 20], &[0x88, 0xac]].concat();
    let anchor = vec![0x51, 0x02, 0x4e, 0x73];
    let mut multisig_4of5 = vec![0x54];
    for _ in 0..5 {
        multisig_4of5.extend([0x21, 0x03]);
        multisig_4of5.extend([2; 32]);
    }
    multisig_4of5.extend([0x55, 0xae]);
    for spk in [key33, key65, p2pkh, anchor, multisig_4of5, p2wpkh().into_bytes(), p2tr().into_bytes()] {
        let spk = ScriptBuf::from_bytes(spk);
        let t = tx(vec![(ScriptBuf::new(), Witness::new())]);
        assert_eq!(validate_inputs_standardness(&t, &[out(spk.clone())]), Ok(()), "{spk:?}");
    }
}

#[test]
fn an_unknown_spent_script_is_nonstandard() {
    let t = tx(vec![(ScriptBuf::new(), Witness::new()), (ScriptBuf::new(), Witness::new())]);
    // OP_TRUE, and a multisig whose "key" has no valid prefix.
    let bad_multisig = [&[0x51, 0x21, 0x05][..], &[1; 32], &[0x51, 0xae]].concat();
    assert_eq!(nonstd(&t, &[out(p2wpkh()), out(ScriptBuf::from_bytes(vec![0x51]))]), "input 1 script unknown");
    assert_eq!(nonstd(&t, &[out(ScriptBuf::from_bytes(bad_multisig)), out(p2wpkh())]), "input 0 script unknown");
    // A v0 program of neither 20 nor 32 bytes.
    let v0_25 = ScriptBuf::from_bytes([&[0x00, 25][..], &[1; 25]].concat());
    assert_eq!(nonstd(&t, &[out(v0_25), out(p2wpkh())]), "input 0 script unknown");
}

#[test]
fn a_future_witness_version_is_an_undefined_program() {
    let t = tx(vec![(ScriptBuf::new(), Witness::new())]);
    let v2 = ScriptBuf::from_bytes([&[0x52, 32][..], &[1; 32]].concat());
    let v1_20 = ScriptBuf::from_bytes([&[0x51, 20][..], &[1; 20]].concat());
    assert_eq!(nonstd(&t, &[out(v2)]), "input 0 witness program is undefined");
    assert_eq!(nonstd(&t, &[out(v1_20)]), "input 0 witness program is undefined");
}

#[test]
fn a_p2sh_redeem_script_holds_at_most_fifteen_sigops() {
    let ok = checksigs(15);
    let t = tx(vec![(push(&ok), Witness::new())]);
    assert_eq!(validate_inputs_standardness(&t, &[out(p2sh_of(&ok))]), Ok(()));

    let over = checksigs(16);
    let t = tx(vec![(push(&over), Witness::new())]);
    assert_eq!(nonstd(&t, &[out(p2sh_of(&over))]), "p2sh redeemscript sigops exceed limit (input 0: 16 > 15)");
}

#[test]
fn a_p2sh_spend_needs_a_redeem_script_its_scriptsig_can_produce() {
    let t = tx(vec![(ScriptBuf::new(), Witness::new())]);
    assert_eq!(nonstd(&t, &[out(p2sh_of(&[0x51]))]), "input 0 P2SH redeemscript missing");
    // `OP_RETURN` stops the scriptSig.
    let t = tx(vec![(ScriptBuf::from_bytes(vec![0x6a]), Witness::new())]);
    assert_eq!(nonstd(&t, &[out(p2sh_of(&[0x51]))]), "p2sh scriptsig malformed (input 0: OP_RETURN was encountered)");
}

/// BIP 54 counts the spent outputs' signature checks, redeem scripts
/// included: 167 inputs of 15 come to 2505, over 2500; 166 are 2490.
#[test]
fn the_legacy_sigops_of_all_inputs_are_capped_at_2500() {
    let redeem = checksigs(15);
    let spend = |n: usize| {
        let t = tx((0..n).map(|_| (push(&redeem), Witness::new())).collect());
        let prevouts: Vec<_> = (0..n).map(|_| out(p2sh_of(&redeem))).collect();
        validate_inputs_standardness(&t, &prevouts)
    };
    assert_eq!(spend(166), Ok(()));
    assert_eq!(spend(167), Err("non-witness sigops exceed bip54 limit".to_string()));
}

fn witness(items: &[&[u8]]) -> Witness {
    Witness::from_slice(items)
}

#[test]
fn a_witness_only_where_a_witness_program_is_spent() {
    let p2pkh = ScriptBuf::from_bytes([&[0x76, 0xa9, 20][..], &[3; 20], &[0x88, 0xac]].concat());
    let t = tx(vec![(ScriptBuf::new(), witness(&[&[1]]))]);
    assert!(!is_witness_standard(&t, &[out(p2pkh)]), "a witness on a non-witness spend");
    assert!(!is_witness_standard(&t, &[out(ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]))]), "anchor stuffing");
    assert!(is_witness_standard(&t, &[out(p2wpkh())]));
    let bare = tx(vec![(ScriptBuf::new(), Witness::new())]);
    assert!(is_witness_standard(&bare, &[out(ScriptBuf::from_bytes(vec![0x51]))]), "no witness, nothing to check");
}

#[test]
fn p2wsh_limits_its_script_and_items() {
    let script = vec![0x51; MAX_STANDARD_P2WSH_SCRIPT_SIZE];
    let item = [0u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE];
    let spend = |items: Vec<&[u8]>, script: &[u8]| {
        let mut all = items;
        all.push(script);
        is_witness_standard(&tx(vec![(ScriptBuf::new(), witness(&all))]), &[out(p2wsh_of(script))])
    };
    assert!(spend(vec![&item; MAX_STANDARD_P2WSH_STACK_ITEMS], &script));
    assert!(!spend(vec![&item; MAX_STANDARD_P2WSH_STACK_ITEMS + 1], &script), "101 items");
    assert!(!spend(vec![&[0u8; MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1]], &script), "an 81-byte item");
    assert!(!spend(vec![], &vec![0x51; MAX_STANDARD_P2WSH_SCRIPT_SIZE + 1]), "a 3601-byte script");

    // The same limits through P2SH.
    let wsh = p2wsh_of(&script);
    let t = tx(vec![(push(wsh.as_bytes()), witness(&[&[0u8; 81][..], &script]))]);
    assert!(!is_witness_standard(&t, &[out(p2sh_of(wsh.as_bytes()))]), "P2SH-P2WSH, an 81-byte item");
}

#[test]
fn taproot_spends_carry_no_annex_and_small_tapscript_items() {
    let spend = |items: &[&[u8]]| is_witness_standard(&tx(vec![(ScriptBuf::new(), witness(items))]), &[out(p2tr())]);
    let sig = [1u8; 64];
    let control = [0xc0u8; 33];
    let script = [0x51u8];
    assert!(spend(&[&sig]), "key path");
    assert!(!spend(&[&sig, &[ANNEX_TAG, 1]]), "an annex on the key path");
    assert!(!spend(&[&script, &control, &[ANNEX_TAG]]), "an annex on the script path");
    assert!(spend(&[&[0u8; 80], &script, &control]), "an 80-byte tapscript item");
    assert!(!spend(&[&[0u8; 81], &script, &control]), "an 81-byte tapscript item");
    // Another leaf version has no item limit.
    assert!(spend(&[&[0u8; 81], &script, &[0xc2u8; 33]]));
    assert!(!spend(&[&[0u8; 1], &script, &[]]), "an empty control block");
}
