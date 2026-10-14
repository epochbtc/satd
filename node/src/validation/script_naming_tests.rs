//! Naming a libbitcoinconsensus rejection.
//!
//! libbitcoinconsensus reports a coarse `ERR_SCRIPT`; Bitcoin Core, calling
//! `VerifyScript` directly, names the script error (`ScriptErrorString`,
//! src/script/script_error.cpp). satd asks its own engine for the name. That
//! takes only the input that failed, and the caller decides when to do it.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_RETURN};
use bitcoin::opcodes::OP_0;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness};

const HEIGHT: u32 = 1_000;
const EVAL_FALSE: &str = "Script evaluated without error but finished with a false/empty top stack element";
const OP_RETURN_HIT: &str = "OP_RETURN was encountered";

/// A P2WSH input per witness script, each revealing its script.
fn p2wsh_spend(scripts: &[ScriptBuf]) -> (Transaction, Vec<TxOut>) {
    let prevs: Vec<TxOut> = scripts
        .iter()
        .map(|ws| TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2wsh(&ws.wscript_hash()),
        })
        .collect();
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: scripts
            .iter()
            .enumerate()
            .map(|(i, ws)| TxIn {
                previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([i as u8 + 1; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[ws.as_bytes()]),
            })
            .collect(),
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new_op_return([]) }],
    };
    (tx, prevs)
}

fn script(op: u8) -> ScriptBuf {
    ScriptBuf::from_bytes(vec![op])
}

/// Only the input that failed is run to name it. Input 0 here fails too,
/// but naming input 1's failure must not depend on it: libbitcoinconsensus
/// already passed every input before the one it rejected, and running them
/// again only repeats that work.
#[test]
fn naming_runs_only_the_failing_input() {
    let (tx, prevs) = p2wsh_spend(&[script(OP_0.to_u8()), script(OP_RETURN.to_u8())]);
    let cpp = ConsensusVerifier::new(Network::Regtest);
    let coarse = ScriptError::VerifyFailed { input: 1, reason: "ERR_SCRIPT".into() };
    let named = cpp.name_failure(&tx, &prevs, HEIGHT, coarse);
    assert_eq!(named.input(), 1);
    assert_eq!(named.reason(), OP_RETURN_HIT);
}

/// `verify_transaction` names the failure as Core does, on the input that
/// failed.
#[test]
fn verify_transaction_names_the_failure() {
    let (tx, prevs) = p2wsh_spend(&[script(OP_PUSHNUM_1.to_u8()), script(OP_RETURN.to_u8())]);
    let err = ConsensusVerifier::new(Network::Regtest)
        .verify_transaction(&tx, &prevs, HEIGHT)
        .expect_err("input 1 fails");
    assert_eq!((err.input(), err.reason()), (1, OP_RETURN_HIT));

    let (tx, prevs) = p2wsh_spend(&[script(OP_0.to_u8())]);
    let err = ConsensusVerifier::new(Network::Regtest)
        .verify_transaction(&tx, &prevs, HEIGHT)
        .expect_err("input 0 fails");
    assert_eq!((err.input(), err.reason()), (0, EVAL_FALSE));

    let (tx, prevs) = p2wsh_spend(&[script(OP_PUSHNUM_1.to_u8())]);
    ConsensusVerifier::new(Network::Regtest)
        .verify_transaction(&tx, &prevs, HEIGHT)
        .expect("a true script passes");
}

/// The unnamed verify gives the same verdict and input with the coarse
/// reason, and leaves the name to `name_failure`. The shadow verifier passes
/// both through to its primary engine.
#[test]
fn the_unnamed_verify_leaves_the_name_for_later() {
    let (tx, prevs) = p2wsh_spend(&[script(OP_PUSHNUM_1.to_u8()), script(OP_RETURN.to_u8())]);
    let shadow = ShadowVerifier::new(
        Box::new(ConsensusVerifier::new(Network::Regtest)),
        Box::new(RustVerifier::new(Network::Regtest)),
        "cpp",
        "rust",
        16,
        1,
    );
    let verifiers: [(&str, &dyn ScriptVerifier); 2] =
        [("cpp", &ConsensusVerifier::new(Network::Regtest)), ("rust-shadow", &shadow)];
    for (name, v) in verifiers {
        let err = v.verify_transaction_unnamed(&tx, &prevs, HEIGHT).expect_err("input 1 fails");
        assert_eq!(err.input(), 1, "{name}");
        assert_eq!(err.reason(), "ERR_SCRIPT", "{name}: named under the caller's lock");
        let named = v.name_failure(&tx, &prevs, HEIGHT, err);
        assert_eq!((named.input(), named.reason()), (1, OP_RETURN_HIT), "{name}");

        v.verify_transaction_unnamed(&p2wsh_spend(&[script(OP_PUSHNUM_1.to_u8())]).0, &prevs[..1], HEIGHT)
            .expect("a true script passes");
    }
}
