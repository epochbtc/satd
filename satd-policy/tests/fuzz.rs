//! Property tests for invariant I4: the front-end never panics, and the
//! evaluator is total (never panics, never exhausts beyond the fuel flag) and
//! deterministic (same inputs → same value).

use proptest::prelude::*;
use satd_policy::{
    Ctx, InputView, Network, OutputView, ScriptType, Source, TxView, compile, compile_bool,
};

// A small owned transaction the fuzzer can fill with random data.
#[derive(Debug)]
struct Owned {
    txid: Vec<u8>,
    in_scripts: Vec<Vec<u8>>,
    out_scripts: Vec<Vec<u8>>,
    fee: i128,
    fee_rate: i128,
    vsize: i128,
    weight: i128,
    total_witness_size: i128,
    version: i128,
    out_values: Vec<i128>,
}

fn ctx() -> Ctx {
    Ctx {
        network: Network::Mainnet,
        height: 900_000,
        min_relay_fee: 1_000,
        dust_relay_fee: 3_000,
        mempool_bytes: 1,
        mempool_min_fee: 1_000,
    }
}

fn eval_value(rule: &satd_policy::CompiledExpr, o: &Owned) -> (bool, bool) {
    let ins: Vec<InputView> = o
        .in_scripts
        .iter()
        .map(|s| InputView {
            prevout_txid: &o.txid,
            prevout_vout: 0,
            sequence: 0xffff_fffe,
            script_sig: s,
            witness_items: 1,
            witness_size: s.len() as i128,
            max_witness_item: s.len() as i128,
            has_annex: false,
            prevout_value: 10_000,
            prevout_script_type: ScriptType::P2tr,
            prevout_script: s,
            spends_coinbase: false,
            leaf_script: s,
        })
        .collect();
    let outs: Vec<OutputView> = o
        .out_scripts
        .iter()
        .enumerate()
        .map(|(i, s)| OutputView {
            value: *o.out_values.get(i).unwrap_or(&0),
            script_type: ScriptType::Nonstandard,
            script: s,
            op_return_size: 0,
            is_dust: false,
        })
        .collect();
    let tx = TxView {
        version: o.version,
        locktime: 0,
        vsize: o.vsize,
        weight: o.weight,
        total_witness_size: o.total_witness_size,
        signals_rbf: true,
        txid: &o.txid,
        fee: o.fee,
        fee_rate: o.fee_rate,
        sigops_cost: 0,
        source: Source::P2p,
        from_whitelisted_peer: false,
        inputs: &ins,
        outputs: &outs,
    };
    let out = rule.eval(&tx, &ctx());
    (out.value.as_bool(), out.fuel_exhausted)
}

fn arb_owned() -> impl Strategy<Value = Owned> {
    (
        prop::collection::vec(any::<u8>(), 0..40), // txid
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..4), // in scripts
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..4), // out scripts
        any::<i64>(),
        any::<i64>(),
        any::<i64>(),
        prop::collection::vec(any::<i64>(), 0..4),
    )
        .prop_map(
            |(txid, in_scripts, out_scripts, fee, fee_rate, vsize, out_values)| Owned {
                txid,
                out_values: out_values.into_iter().map(|v| v as i128).collect(),
                in_scripts,
                out_scripts,
                fee: fee as i128,
                fee_rate: fee_rate as i128,
                vsize: vsize as i128,
                weight: (vsize as i128).saturating_mul(4),
                total_witness_size: (fee as i128).abs(),
                version: 2,
            },
        )
}

// The front-end must never panic on any input — only return Ok or Err.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn compile_never_panics(s in ".{0,80}") {
        let _ = compile(&s);
    }
}

fn corpus() -> Vec<satd_policy::CompiledExpr> {
    [
        "tx.fee_rate < node.min_relay_fee * 3",
        "tx.fee / tx.vsize >= 0 or tx.fee % tx.vsize == 0",
        "tx.total_witness_size > 100kb",
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))",
        "count outputs (out.value > 0) >= 1",
        "sum outputs (out.value) > tx.fee",
        "any outputs (out.script.max_push > 32 and out.script.well_formed)",
        "tx.txid.starts_with(0xdeadbeef) or tx.txid.len() < 32",
        "all inputs (in.script_sig.len() == 0)",
    ]
    .iter()
    .map(|s| compile_bool(s).expect("corpus compiles"))
    .collect()
}

// Evaluation is total (no panic) and deterministic across arbitrary inputs.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]
    #[test]
    fn eval_total_and_deterministic(o in arb_owned()) {
        for rule in corpus() {
            let a = eval_value(&rule, &o);
            let b = eval_value(&rule, &o);
            prop_assert_eq!(a, b, "non-deterministic evaluation");
        }
    }
}
