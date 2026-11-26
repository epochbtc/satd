//! The `sigops` field of the transaction JSON: Bitcoin Core's
//! `GetTransactionSigOpCost` for each kind of spend, where the field is
//! served, and where it is left out.
//!
//! The expected costs are worked out here from Core's rules (legacy and
//! P2SH sigops cost 4, witness sigops 1), not read back from the counter.
//! Keys and signatures are placeholders of the right length: no count reads
//! their bytes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bitcoin::hashes::Hash as _;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::{
    Amount, OutPoint, PubkeyHash, ScriptBuf, ScriptHash, Sequence, TxIn, TxOut, WPubkeyHash,
    WScriptHash, Witness, opcodes,
};
use tower::ServiceExt as _;

use super::*;
use crate::test_support::{regtest_block, regtest_state};

const SIG: [u8; 72] = [0x30; 72];
const KEY: [u8; 33] = [0x02; 33];

fn push(bytes: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(bytes.to_vec()).unwrap()
}

fn p2pkh() -> ScriptBuf {
    ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x11; 20]))
}

fn p2wpkh() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x22; 20]))
}

fn p2tr() -> ScriptBuf {
    let mut script = vec![0x51, 0x20];
    script.extend([0x33; 32]);
    ScriptBuf::from_bytes(script)
}

/// `m <key> * n n OP_CHECKMULTISIG`.
fn multisig(m: i64, n: i64) -> ScriptBuf {
    let mut script = Builder::new().push_int(m);
    for _ in 0..n {
        script = script.push_slice(KEY);
    }
    script.push_int(n).push_opcode(opcodes::all::OP_CHECKMULTISIG).into_script()
}

fn input(script_sig: ScriptBuf, witness: &[&[u8]]) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([0x77; 32]), vout: 0 },
        script_sig,
        sequence: Sequence::MAX,
        witness: Witness::from_slice(witness),
    }
}

fn tx(input: Vec<TxIn>, outputs: Vec<ScriptBuf>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output: outputs
            .into_iter()
            .map(|script_pubkey| TxOut { value: Amount::from_sat(1_000), script_pubkey })
            .collect(),
    }
}

fn spending(script_pubkey: ScriptBuf) -> Vec<Option<TxOut>> {
    vec![Some(TxOut { value: Amount::from_sat(5_000), script_pubkey })]
}

#[test]
fn a_legacy_p2pkh_spend_costs_four_per_output_checksig() {
    let script_sig = Builder::new().push_slice(SIG).push_slice(KEY).into_script();
    // The scriptSig only pushes. Each P2PKH output holds one OP_CHECKSIG.
    let one = tx(vec![input(script_sig.clone(), &[])], vec![p2pkh()]);
    assert_eq!(sigop_cost(&one, &spending(p2pkh())), 4);
    let two = tx(vec![input(script_sig, &[])], vec![p2pkh(), p2pkh()]);
    assert_eq!(sigop_cost(&two, &spending(p2pkh())), 8);
}

#[test]
fn a_bare_multisig_output_costs_eighty() {
    // Counted without the key count: 20 sigops, at 4 each.
    let script_sig = Builder::new().push_slice(SIG).push_slice(KEY).into_script();
    let t = tx(vec![input(script_sig, &[])], vec![multisig(1, 2)]);
    assert_eq!(sigop_cost(&t, &spending(p2pkh())), 80);
}

#[test]
fn a_p2sh_multisig_spend_costs_four_per_key_of_the_redeem_script() {
    for (m, n, cost) in [(1, 2, 8), (2, 3, 12)] {
        let redeem = multisig(m, n);
        let script_sig = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_slice(SIG)
            .push_slice(push(redeem.as_bytes()))
            .into_script();
        let spent = ScriptBuf::new_p2sh(&ScriptHash::hash(redeem.as_bytes()));
        // Paying to P2SH: the output adds nothing.
        let t = tx(vec![input(script_sig, &[])], vec![spent.clone()]);
        assert_eq!(sigop_cost(&t, &spending(spent)), cost, "{m}-of-{n}");
    }
}

#[test]
fn a_p2wpkh_spend_costs_one() {
    let t = tx(vec![input(ScriptBuf::new(), &[&SIG, &KEY])], vec![p2wpkh()]);
    assert_eq!(sigop_cost(&t, &spending(p2wpkh())), 1);
}

#[test]
fn a_p2sh_wrapped_p2wpkh_spend_costs_one() {
    let program = p2wpkh();
    let script_sig = Builder::new().push_slice(push(program.as_bytes())).into_script();
    let spent = ScriptBuf::new_p2sh(&ScriptHash::hash(program.as_bytes()));
    let t = tx(vec![input(script_sig, &[&SIG, &KEY])], vec![p2wpkh()]);
    assert_eq!(sigop_cost(&t, &spending(spent)), 1);
}

#[test]
fn a_p2wsh_multisig_spend_costs_one_per_key_of_the_witness_script() {
    let witness_script = multisig(2, 3);
    let spent = ScriptBuf::new_p2wsh(&WScriptHash::hash(witness_script.as_bytes()));
    let t = tx(
        vec![input(ScriptBuf::new(), &[&[], &SIG, &SIG, witness_script.as_bytes()])],
        vec![p2wpkh()],
    );
    assert_eq!(sigop_cost(&t, &spending(spent)), 3);
}

#[test]
fn a_taproot_spend_costs_nothing() {
    let t = tx(vec![input(ScriptBuf::new(), &[&[0x44; 64]])], vec![p2tr()]);
    assert_eq!(sigop_cost(&t, &spending(p2tr())), 0);
}

#[test]
fn inputs_and_outputs_add_up() {
    // P2WPKH (1) and P2SH 1-of-2 (8) in, P2PKH (4) and P2TR (0) out.
    let redeem = multisig(1, 2);
    let script_sig = Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_slice(SIG)
        .push_slice(push(redeem.as_bytes()))
        .into_script();
    let t = tx(
        vec![input(ScriptBuf::new(), &[&SIG, &KEY]), input(script_sig, &[])],
        vec![p2pkh(), p2tr()],
    );
    let spent = vec![
        Some(TxOut { value: Amount::from_sat(1), script_pubkey: p2wpkh() }),
        Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::hash(redeem.as_bytes())),
        }),
    ];
    assert_eq!(sigop_cost(&t, &spent), 13);
}

#[test]
fn an_input_whose_spent_output_is_unknown_adds_nothing() {
    let redeem = multisig(1, 2);
    let script_sig = Builder::new()
        .push_opcode(opcodes::OP_FALSE)
        .push_slice(SIG)
        .push_slice(push(redeem.as_bytes()))
        .into_script();
    let t = tx(
        vec![input(ScriptBuf::new(), &[&SIG, &KEY]), input(script_sig, &[])],
        vec![p2pkh()],
    );
    // The P2WPKH output is known, the P2SH one is not: 1 + the output's 4.
    let spent = vec![Some(TxOut { value: Amount::from_sat(1), script_pubkey: p2wpkh() }), None];
    assert_eq!(sigop_cost(&t, &spent), 5);
    // Neither: the legacy count alone.
    assert_eq!(sigop_cost(&t, &[None, None]), 4);
}

fn coinbase(outputs: Vec<ScriptBuf>) -> Transaction {
    let mut cb = regtest_block(BlockHash::all_zeros(), 1, 0).txdata.remove(0);
    cb.output = outputs
        .into_iter()
        .map(|script_pubkey| TxOut { value: Amount::from_sat(1_000), script_pubkey })
        .collect();
    cb
}

#[test]
fn a_coinbase_costs_its_legacy_sigops() {
    let p2pk = Builder::new().push_slice(KEY).push_opcode(opcodes::all::OP_CHECKSIG).into_script();
    assert_eq!(sigop_cost(&coinbase(vec![p2pk.clone(), p2wpkh()]), &[None]), 4);
    assert_eq!(sigop_cost(&coinbase(vec![p2wpkh()]), &[None]), 0);
    // An OP_CHECKSIG in the coinbase's scriptSig counts too.
    let mut cb = coinbase(vec![p2pk]);
    let mut script_sig = cb.input[0].script_sig.to_bytes();
    script_sig.push(opcodes::all::OP_CHECKSIG.to_u8());
    cb.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
    assert_eq!(sigop_cost(&cb, &[None]), 8);
}

/// Connect a block whose coinbase also pays `outputs`, and return the
/// coinbase.
fn connect_coinbase_paying(state: &EsploraState, outputs: Vec<ScriptBuf>) -> Transaction {
    let (tip, height) = state.chain.tip_snapshot();
    let mut block = regtest_block(tip, height + 1, 0);
    block.txdata[0].output.extend(
        outputs
            .into_iter()
            .map(|script_pubkey| TxOut { value: Amount::from_sat(5_000), script_pubkey }),
    );
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block.header.nonce = 0;
    let target = block.header.target();
    while !target.is_met_by(block.block_hash()) {
        block.header.nonce += 1;
    }
    state.chain.accept_block(&block).expect("connect test block");
    assert_eq!(state.chain.tip_snapshot().0, block.block_hash());
    block.txdata.remove(0)
}

/// The JSON builder hands the counter the outputs it resolved: a spend of a
/// P2WPKH coin costs 1 only if its prevout reached the count.
#[test]
fn the_tx_json_counts_with_the_prevouts_it_resolved() {
    let (state, _dir) = regtest_state();
    let funding = connect_coinbase_paying(&state, vec![p2wpkh()]);
    let mut spend = tx(vec![input(ScriptBuf::new(), &[&SIG, &KEY])], vec![p2pkh()]);
    spend.input[0].previous_output = OutPoint { txid: funding.compute_txid(), vout: 1 };

    let json = build_mempool_tx_json(&state, &spend).unwrap();
    assert_eq!(json.fee, Some(4_000), "the prevout was resolved");
    // 1 for the P2WPKH input, 4 for the P2PKH output.
    assert_eq!(json.sigops, 5);
    assert_eq!(serde_json::to_value(&json).unwrap()["sigops"], serde_json::json!(5));

    // The same spend of an output nobody holds: the legacy count, no fee.
    spend.input[0].previous_output.vout = 9;
    let json = build_mempool_tx_json(&state, &spend).unwrap();
    assert_eq!((json.fee, json.sigops), (None, 4));
}

/// Through the router, for a confirmed coinbase.
#[tokio::test]
async fn tx_route_serves_sigops_for_a_coinbase() {
    let (state, _dir) = regtest_state();
    let p2pk = Builder::new().push_slice(KEY).push_opcode(opcodes::all::OP_CHECKSIG).into_script();
    let with_sigop = connect_coinbase_paying(&state, vec![p2pk]).compute_txid();
    let without = connect_coinbase_paying(&state, vec![p2wpkh()]).compute_txid();
    let router = crate::build_router(state).unwrap();
    for (txid, sigops) in [(with_sigop, 4), (without, 0)] {
        let resp = router
            .clone()
            .oneshot(Request::get(format!("/tx/{txid}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["vin"][0]["is_coinbase"], true, "{json}");
        // A number even when it is 0, not a missing key.
        assert_eq!(json["sigops"], serde_json::json!(sigops), "{json}");
        assert_eq!(json["fee"], 0);
    }
}

/// A stripped transaction keeps its `sigops`: the zero-filled script counts
/// nothing, as the pushes it replaced counted nothing.
#[test]
fn a_stripped_transaction_keeps_its_sigops() {
    let (state, _dir) = regtest_state();
    let t = tx(vec![input(ScriptBuf::new(), &[])], vec![p2pkh(), ScriptBuf::new_op_return([])]);
    let stripped = [(1u32, 40u64)];
    let view = TxView { tx: &t, txid: t.compute_txid(), stripped: Some(&stripped) };
    let json = serde_json::to_value(build_tx_json(&state, &view, None).unwrap()).unwrap();
    assert_eq!(json["opreturn_stripped"], true);
    assert_eq!(json["sigops"], 4, "{json}");

    let json = serde_json::to_value(build_tx_json(&state, &TxView::intact(&t), None).unwrap()).unwrap();
    assert_eq!(json["sigops"], 4, "{json}");
}
