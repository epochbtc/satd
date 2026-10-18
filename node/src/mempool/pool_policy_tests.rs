//! Core's mempool script policy at admission: the standard script flags
//! (`PolicyScriptChecks`), the standardness of what a transaction spends and
//! how (`ValidateInputsStandardness`, `IsWitnessStandard`), and the 16000
//! sigop-cost cap. satd checked scripts under the block's flags alone, so it
//! relayed and mined spends of soft-fork upgrade hooks.

use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::{NoopVerifier, RustVerifier};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};

const COIN_VALUE: u64 = 100_000;

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

fn coin(script_pubkey: ScriptBuf) -> Coin {
    Coin { amount: COIN_VALUE, script_pubkey, height: 0, coinbase: false, txseq: node_index::TXSEQ_UNKNOWN }
}

fn p2wsh(witness_script: &[u8]) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(witness_script.to_vec()).wscript_hash())
}

/// Spend each of `prevs` with `witness` (and an empty scriptSig), paying
/// all but 1000 sat to one P2WPKH output.
fn spend(prevs: &[OutPoint], witness: &[&[u8]]) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: *p,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(witness),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(COIN_VALUE * prevs.len() as u64 - 1_000),
            script_pubkey: ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x21; 20]].concat()),
        }],
    }
}

fn rust() -> RustVerifier {
    RustVerifier::new(bitcoin::Network::Regtest)
}

/// `OP_NOP4 OP_1`: valid by consensus; a NOP Core keeps for a soft fork.
const UPGRADABLE_NOP: &[u8] = &[0xb3, 0x51];

/// A spend of an upgradable NOP is valid under the block's flags, so the
/// node's verifier passes it, and Core refuses it as non-standard: a soft
/// fork that gave the NOP a meaning would make it invalid. Non-standard,
/// not invalid: `PolicyScript`, which costs the relaying peer nothing.
#[test]
fn an_upgrade_hook_spend_is_refused_as_nonstandard() {
    let coins = vec![(prev(1), coin(p2wsh(UPGRADABLE_NOP)))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let tx = spend(&[prev(1)], &[UPGRADABLE_NOP]);
    rust().verify_transaction(&tx, &[TxOut { value: Amount::from_sat(COIN_VALUE), script_pubkey: p2wsh(UPGRADABLE_NOP) }], 1)
        .expect("valid by consensus");

    let want = "mempool-script-verify-flag-failed (NOPx reserved for soft-fork upgrades)";
    let err = mp.test_accept(&tx, &cs, &rust()).expect_err("testmempoolaccept refuses it");
    assert!(matches!(err, MempoolError::PolicyScript(..)), "{err:?}");
    assert_eq!(err.reject_reason(), want);
    let err = mp.accept_transaction(tx, &cs, &rust(), TxSource::P2p, false).expect_err("refused");
    assert!(matches!(err, MempoolError::PolicyScript(..)), "{err:?}");
    assert_eq!(err.reject_reason(), want);
    assert_eq!(mp.acting_bytes(), 0, "nothing admitted");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A script that fails under the block's flags is still `Script`: the
/// consensus pass runs first and decides validity.
#[test]
fn an_invalid_script_is_still_refused_as_invalid() {
    let script = [0x00]; // OP_0: leaves false on the stack.
    let coins = vec![(prev(1), coin(p2wsh(&script)))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let err = mp
        .accept_transaction(spend(&[prev(1)], &[&script]), &cs, &rust(), TxSource::P2p, false)
        .expect_err("refused");
    assert!(matches!(err, MempoolError::Script(..)), "{err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-acceptnonstdtxn` lifts Core's standardness, not its policy flags:
/// Core's `PolicyScriptChecks` always runs under the standard flags.
#[test]
fn acceptnonstdtxn_does_not_lift_the_policy_flags() {
    let coins = vec![(prev(1), coin(p2wsh(UPGRADABLE_NOP)))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    mp.config.write().accept_non_std_txn = true;
    let err = mp
        .accept_transaction(spend(&[prev(1)], &[UPGRADABLE_NOP]), &cs, &rust(), TxSource::Rpc, false)
        .expect_err("refused");
    assert!(matches!(err, MempoolError::PolicyScript(..)), "{err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spending an output of no type Core solves (`OP_TRUE`) is
/// `bad-txns-nonstandard-inputs`, which `-acceptnonstdtxn` lifts.
#[test]
fn a_spend_of_an_unknown_script_type_is_nonstandard() {
    let coins = vec![(prev(1), coin(ScriptBuf::from_bytes(vec![0x51]))), (prev(2), coin(ScriptBuf::from_bytes(vec![0x51])))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let err = mp
        .accept_transaction(spend(&[prev(1)], &[]), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect_err("refused");
    assert_eq!(err.state_string(), "bad-txns-nonstandard-inputs, input 0 script unknown");
    let err = mp.test_accept(&spend(&[prev(1)], &[]), &cs, &NoopVerifier).expect_err("refused");
    assert_eq!(err.reject_reason(), "bad-txns-nonstandard-inputs");

    mp.config.write().accept_non_std_txn = true;
    mp.accept_transaction(spend(&[prev(2)], &[]), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("admitted with -acceptnonstdtxn");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A P2WSH stack item over 80 bytes is `bad-witness-nonstandard`.
#[test]
fn a_bloated_witness_is_nonstandard() {
    let script = [0x75, 0x51]; // OP_DROP OP_1
    let coins = vec![(prev(1), coin(p2wsh(&script)))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let err = mp
        .accept_transaction(spend(&[prev(1)], &[&[0u8; 81], &script]), &cs, &rust(), TxSource::Rpc, false)
        .expect_err("refused");
    assert_eq!(err.reject_reason(), "bad-witness-nonstandard");
    mp.accept_transaction(spend(&[prev(1)], &[&[0u8; 80], &script]), &cs, &rust(), TxSource::Rpc, false)
        .expect("80 bytes is standard");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `OP_0 OP_IF OP_1 OP_CHECKMULTISIG×198 OP_ENDIF OP_1`: 3941 sigops by
/// Core's accurate count (see `pool_sigops_tests.rs`).
fn heavy_script() -> Vec<u8> {
    let mut s = vec![0x00, 0x63, 0x51];
    s.extend(std::iter::repeat_n(0xae, 198));
    s.extend([0x68, 0x51]);
    s
}

/// Core's `MAX_STANDARD_TX_SIGOPS_COST`: four heavy inputs (15764) are
/// admitted and five (19705) are not, `-acceptnonstdtxn` or not.
#[test]
fn the_sigop_cost_of_a_transaction_is_capped_at_16000() {
    let ws = heavy_script();
    let coins: Vec<_> = (1..=9).map(|t| (prev(t), coin(p2wsh(&ws)))).collect();
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let four: Vec<_> = (1..=4).map(prev).collect();
    let five: Vec<_> = (5..=9).map(prev).collect();

    mp.config.write().accept_non_std_txn = true;
    let err = mp
        .accept_transaction(spend(&five, &[&ws]), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect_err("refused");
    assert_eq!(err.state_string(), "bad-txns-too-many-sigops, 19705");
    let err = mp.test_accept(&spend(&five, &[&ws]), &cs, &NoopVerifier).expect_err("refused");
    assert_eq!(err.reject_reason(), "bad-txns-too-many-sigops");
    mp.accept_transaction(spend(&four, &[&ws]), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("15764 is under the cap");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fee-bypass path a `submitpackage` ephemeral-dust parent takes applies
/// the same checks: it skipped every standardness check.
#[test]
fn the_fee_bypass_path_applies_the_same_policy() {
    let ws = heavy_script();
    let mut coins = vec![
        (prev(1), coin(ScriptBuf::from_bytes(vec![0x51]))),
        (prev(2), coin(p2wsh(UPGRADABLE_NOP))),
    ];
    coins.extend((3..=7).map(|t| (prev(t), coin(p2wsh(&ws)))));
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));

    let err = mp.accept_transaction_bypass_fee(spend(&[prev(1)], &[]), &cs, &NoopVerifier).expect_err("refused");
    assert_eq!(err.reject_reason(), "bad-txns-nonstandard-inputs");
    let err = mp
        .accept_transaction_bypass_fee(spend(&[prev(2)], &[UPGRADABLE_NOP]), &cs, &rust())
        .expect_err("refused");
    assert!(matches!(err, MempoolError::PolicyScript(..)), "{err:?}");
    let five: Vec<_> = (3..=7).map(prev).collect();
    let err = mp.accept_transaction_bypass_fee(spend(&five, &[&ws]), &cs, &NoopVerifier).expect_err("refused");
    assert_eq!(err.reject_reason(), "bad-txns-too-many-sigops");
    let _ = std::fs::remove_dir_all(&dir);
}
