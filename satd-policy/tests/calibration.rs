//! Cost-calibration harness (§7, §14 precondition).
//!
//! This is the "cost-calibration bench" the PR-1 plan calls for, shipped as an
//! `#[ignore]`d test so it does not gate CI but can be run on demand — crucially
//! on the dogfood fleet's slowest (Pi-class) hardware, where the real ns/unit
//! number that sets `POLICY_BUDGET` / `DEFAULT_FUEL` is established.
//!
//! Run with:  `cargo test -p satd-policy --release -- --ignored --nocapture`

use std::time::Instant;

use satd_policy::{Ctx, InputView, Network, OutputView, ScriptType, Source, TxView, compile_bool};

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

#[test]
#[ignore = "calibration harness; run with --release --ignored --nocapture"]
fn calibrate_worst_case_ruleset() {
    // A representative full cookbook ruleset.
    let rules: Vec<_> = [
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x61746f6d))))",
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))",
        "any outputs (out.script_type == bare_multisig)",
        "any outputs (out.script_type == op_return and out.op_return_size > 83) and tx.fee_rate < node.min_relay_fee * 3",
        "count outputs (out.is_dust and out.script_type != p2a) >= 5",
        "tx.total_witness_size > 100kb",
    ]
    .iter()
    .map(|s| compile_bool(s).unwrap())
    .collect();

    let total_cost: u64 = rules.iter().map(|r| r.cost().total()).sum();

    // A heavy-ish but realistic transaction: a large inscription-style witness
    // in one input plus several outputs.
    let big_leaf = {
        let mut s = vec![0x20u8];
        s.extend_from_slice(&[0xaa; 32]);
        s.push(0xac); // OP_CHECKSIG
        s.push(0x00); // OP_FALSE
        s.push(0x63); // OP_IF
        // ~100 KB of pushed "inscription" data, chunked into 520-byte pushes.
        for _ in 0..200 {
            s.push(0x4d); // PUSHDATA2
            s.extend_from_slice(&520u16.to_le_bytes());
            s.extend_from_slice(&[0x42u8; 520]);
        }
        s.push(0x68); // OP_ENDIF
        s
    };
    let txid = vec![0u8; 32];
    let ins = vec![InputView {
        prevout_txid: &txid,
        prevout_vout: 0,
        sequence: 0xffff_fffe,
        script_sig: &[],
        witness_items: 2,
        witness_size: big_leaf.len() as i128,
        max_witness_item: big_leaf.len() as i128,
        has_annex: false,
        prevout_value: 100_000,
        prevout_script_type: ScriptType::P2tr,
        prevout_script: &[],
        spends_coinbase: false,
        leaf_script: &big_leaf,
    }];
    let op_ret = vec![0x6a, 0x02, 0xaa, 0xbb];
    let outs: Vec<OutputView> = (0..6)
        .map(|_| OutputView {
            value: 1_000,
            script_type: ScriptType::OpReturn,
            script: &op_ret,
            op_return_size: 2,
            is_dust: false,
        })
        .collect();
    let tx = TxView {
        version: 2,
        locktime: 0,
        vsize: 30_000,
        weight: 120_000,
        total_witness_size: big_leaf.len() as i128,
        signals_rbf: true,
        txid: &txid,
        fee: 2_000,
        fee_rate: 1_500,
        sigops_cost: 4,
        source: Source::P2p,
        from_whitelisted_peer: false,
        inputs: &ins,
        outputs: &outs,
    };
    let ctx = ctx();

    let iters = 2_000u32;
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..iters {
        for r in &rules {
            let out = r.eval(&tx, &ctx);
            acc += out.value.as_bool() as u64;
            acc += out.fuel_exhausted as u64;
        }
    }
    let elapsed = start.elapsed();
    let per_tx = elapsed / iters;

    println!("--- satd-policy calibration ---");
    println!("rules: {}", rules.len());
    println!(
        "summed static cost: {total_cost} units (budget {})",
        satd_policy::POLICY_BUDGET
    );
    println!("witness size: {} bytes", big_leaf.len());
    println!("eval time per full-ruleset pass: {per_tx:?}");
    println!("(acc={acc}) — target is < ~100µs/pass on Pi-class hardware");
}
