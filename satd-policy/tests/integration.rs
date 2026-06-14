//! End-to-end tests for the policy expression core: parse → typecheck → cost →
//! eval, the `script(…)` matcher, and the §17 cookbook rules.
// Tests build a baseline tx then tweak individual fields; the readability of
// `let mut b = TxB::default(); b.field = …` beats struct-update spread here.
#![allow(clippy::field_reassign_with_default)]

use satd_policy::{
    Ctx, InputView, Network, OutputView, ScriptType, Source, Stage, TxView, compile, compile_bool,
};

// --- test scaffolding: owned backing data + borrowed views ---

struct InB {
    prevout_txid: Vec<u8>,
    prevout_vout: i128,
    sequence: i128,
    script_sig: Vec<u8>,
    witness_items: i128,
    witness_size: i128,
    max_witness_item: i128,
    has_annex: bool,
    prevout_value: i128,
    prevout_script_type: ScriptType,
    prevout_script: Vec<u8>,
    spends_coinbase: bool,
    leaf_script: Vec<u8>,
}

impl Default for InB {
    fn default() -> Self {
        InB {
            prevout_txid: vec![0u8; 32],
            prevout_vout: 0,
            sequence: 0xffff_ffff,
            script_sig: vec![],
            witness_items: 0,
            witness_size: 0,
            max_witness_item: 0,
            has_annex: false,
            prevout_value: 100_000,
            prevout_script_type: ScriptType::P2wpkh,
            prevout_script: vec![],
            spends_coinbase: false,
            leaf_script: vec![],
        }
    }
}

struct OutB {
    value: i128,
    script_type: ScriptType,
    script: Vec<u8>,
    op_return_size: i128,
    is_dust: bool,
}

impl Default for OutB {
    fn default() -> Self {
        OutB {
            value: 50_000,
            script_type: ScriptType::P2wpkh,
            script: vec![],
            op_return_size: 0,
            is_dust: false,
        }
    }
}

struct TxB {
    version: i128,
    locktime: i128,
    vsize: i128,
    weight: i128,
    total_witness_size: i128,
    signals_rbf: bool,
    txid: Vec<u8>,
    fee: i128,
    fee_rate: i128,
    sigops_cost: i128,
    source: Source,
    from_whitelisted_peer: bool,
    inputs: Vec<InB>,
    outputs: Vec<OutB>,
}

impl Default for TxB {
    fn default() -> Self {
        TxB {
            version: 2,
            locktime: 0,
            vsize: 200,
            weight: 800,
            total_witness_size: 0,
            signals_rbf: false,
            txid: vec![0u8; 32],
            fee: 2_000,
            fee_rate: 10_000,
            sigops_cost: 4,
            source: Source::P2p,
            from_whitelisted_peer: false,
            inputs: vec![InB::default()],
            outputs: vec![OutB::default()],
        }
    }
}

impl TxB {
    fn input_views(&self) -> Vec<InputView<'_>> {
        self.inputs
            .iter()
            .map(|i| InputView {
                prevout_txid: &i.prevout_txid,
                prevout_vout: i.prevout_vout,
                sequence: i.sequence,
                script_sig: &i.script_sig,
                witness_items: i.witness_items,
                witness_size: i.witness_size,
                max_witness_item: i.max_witness_item,
                has_annex: i.has_annex,
                prevout_value: i.prevout_value,
                prevout_script_type: i.prevout_script_type,
                prevout_script: &i.prevout_script,
                spends_coinbase: i.spends_coinbase,
                leaf_script: &i.leaf_script,
            })
            .collect()
    }

    fn output_views(&self) -> Vec<OutputView<'_>> {
        self.outputs
            .iter()
            .map(|o| OutputView {
                value: o.value,
                script_type: o.script_type,
                script: &o.script,
                op_return_size: o.op_return_size,
                is_dust: o.is_dust,
            })
            .collect()
    }

    fn tx_view<'a>(&'a self, ins: &'a [InputView<'a>], outs: &'a [OutputView<'a>]) -> TxView<'a> {
        TxView {
            version: self.version,
            locktime: self.locktime,
            vsize: self.vsize,
            weight: self.weight,
            total_witness_size: self.total_witness_size,
            signals_rbf: self.signals_rbf,
            txid: &self.txid,
            fee: self.fee,
            fee_rate: self.fee_rate,
            sigops_cost: self.sigops_cost,
            source: self.source,
            from_whitelisted_peer: self.from_whitelisted_peer,
            inputs: ins,
            outputs: outs,
        }
    }
}

fn ctx() -> Ctx {
    Ctx {
        network: Network::Mainnet,
        height: 900_000,
        min_relay_fee: 1_000,
        dust_relay_fee: 3_000,
        mempool_bytes: 10_000_000,
        mempool_min_fee: 1_000,
    }
}

/// Compile a Bool expression and evaluate it against `b`, asserting no fuel
/// exhaustion.
fn run(src: &str, b: &TxB) -> bool {
    let ce = compile_bool(src).unwrap_or_else(|e| panic!("compile `{src}`: {e}"));
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    let out = ce.eval(&tx, &ctx());
    assert!(
        !out.fuel_exhausted,
        "unexpected fuel exhaustion for `{src}`"
    );
    out.value.as_bool()
}

// --- parse / typecheck errors ---

#[test]
fn rejects_unknown_attribute() {
    let e = compile("tx.frobnicate").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
    assert!(e.message.contains("tx.frobnicate"), "{}", e.message);
}

#[test]
fn rejects_unknown_identifier() {
    let e = compile("flooblegerb").unwrap_err();
    assert_eq!(e.stage, Stage::Parse);
}

#[test]
fn rejects_type_mismatch_bool_condition() {
    let e = compile_bool("tx.fee_rate + 1").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
}

#[test]
fn rejects_arithmetic_on_bool() {
    let e = compile("tx.signals_rbf + 1").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
}

#[test]
fn rejects_cross_enum_comparison() {
    let e = compile("out.script_type == mainnet").unwrap_err();
    // out.* outside a quantifier is the first problem the checker hits.
    assert_eq!(e.stage, Stage::Type);
}

#[test]
fn rejects_enum_mismatch_inside_quantifier() {
    let e = compile("any outputs (out.script_type == mainnet)").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
    assert!(e.message.contains("compare"), "{}", e.message);
}

#[test]
fn rejects_binder_outside_quantifier() {
    let e = compile("out.value > 0").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
    assert!(e.message.contains("'out'"), "{}", e.message);
}

#[test]
fn rejects_nested_quantifier() {
    let e = compile("any inputs (any outputs (out.value > 0))").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
    assert!(e.message.contains("nested"), "{}", e.message);
}

#[test]
fn rejects_property_with_parens() {
    let e = compile("any outputs (out.script.max_push() > 0)").unwrap_err();
    assert_eq!(e.stage, Stage::Parse);
}

#[test]
fn rejects_contains_ops_on_flat_bytes() {
    let e = compile("tx.txid.contains_ops(script(OP_RETURN))").unwrap_err();
    assert_eq!(e.stage, Stage::Type);
}

#[test]
fn rejects_needle_too_long() {
    let long = "0x".to_string() + &"ab".repeat(65); // 65 bytes
    let e = compile(&format!("tx.txid.starts_with({long})")).unwrap_err();
    assert_eq!(e.stage, Stage::Lex); // 130 hex digits > 128 cap caught at lex
}

#[test]
fn rejects_stray_equals() {
    let e = compile("tx.version = 2").unwrap_err();
    assert_eq!(e.stage, Stage::Lex);
}

#[test]
fn rejects_too_long_script_pattern() {
    let body = "OP_NOP ".repeat(33);
    let e = compile(&format!(
        "any inputs (in.leaf_script.contains_ops(script({body})))"
    ))
    .unwrap_err();
    assert_eq!(e.stage, Stage::Parse);
    assert!(e.message.contains("too long"), "{}", e.message);
}

#[test]
fn error_render_has_caret() {
    let e = compile("tx.version and tx.fee").unwrap_err();
    let rendered = e.render("tx.version and tx.fee");
    assert!(rendered.contains('^'), "rendered:\n{rendered}");
    assert!(rendered.contains("line 1"), "rendered:\n{rendered}");
}

// --- scalar evaluation ---

#[test]
fn arithmetic_and_comparison() {
    let b = TxB::default();
    // fee_rate 10000 vs min_relay_fee*3 == 3000.
    assert!(!run("tx.fee_rate < node.min_relay_fee * 3", &b));
    assert!(run("tx.fee_rate >= node.min_relay_fee", &b));
    assert!(run("tx.version == 2", &b));
    assert!(run("tx.fee * 1000 / tx.vsize == 10000", &b)); // 2000*1000/200
}

#[test]
fn division_and_modulo_by_zero_are_total() {
    let b = TxB::default();
    assert!(run("tx.fee / 0 == 0", &b));
    assert!(run("tx.fee % 0 == 0", &b));
}

#[test]
fn unit_suffixes() {
    let mut b = TxB::default();
    b.total_witness_size = 150_000;
    assert!(run("tx.total_witness_size > 100kb", &b));
    assert!(!run("tx.total_witness_size > 200kb", &b));
}

#[test]
fn enum_source_and_network() {
    let mut b = TxB::default();
    b.source = Source::Rpc;
    assert!(run("tx.source == rpc", &b));
    assert!(run("tx.source == rpc or tx.source == mcp", &b));
    assert!(!run("tx.source == p2p", &b));
    assert!(run("node.network == mainnet", &b));
}

#[test]
fn signals_rbf() {
    let mut b = TxB::default();
    assert!(!run("tx.signals_rbf", &b));
    b.signals_rbf = true;
    assert!(run("tx.signals_rbf", &b));
    assert!(run("not tx.signals_rbf == false", &b));
}

// --- quantifiers ---

#[test]
fn quantifiers_any_all_count_sum() {
    let mut b = TxB::default();
    b.outputs = vec![
        OutB {
            value: 1_000,
            ..Default::default()
        },
        OutB {
            value: 2_000,
            ..Default::default()
        },
        OutB {
            value: 600,
            is_dust: true,
            ..Default::default()
        },
    ];
    assert!(run("any outputs (out.is_dust)", &b));
    assert!(!run("all outputs (out.is_dust)", &b));
    assert!(run("count outputs (out.value >= 1000) == 2", &b));
    assert!(run("sum outputs (out.value) == 3600", &b));
}

#[test]
fn input_count_helpers() {
    let mut b = TxB::default();
    b.inputs = vec![InB::default(), InB::default()];
    assert!(run("tx.input_count == 2", &b));
    assert!(run("tx.output_count == 1", &b));
}

// --- bytes / script matching ---

#[test]
fn starts_ends_contains_len() {
    let mut b = TxB::default();
    b.txid = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11];
    assert!(run("tx.txid.starts_with(0xdead)", &b));
    assert!(run("tx.txid.ends_with(0x0011)", &b));
    assert!(run("tx.txid.contains(0xbeef)", &b));
    assert!(run("tx.txid.len() == 6", &b));
    assert!(!run("tx.txid.starts_with(0xbeef)", &b));
}

/// Build a taproot-style leaf script: `<32-byte pubkey> OP_CHECKSIG OP_FALSE
/// OP_IF <push "ord"> <push "text/plain"> OP_ENDIF` — the ordinals envelope.
fn ord_leaf() -> Vec<u8> {
    let mut s = Vec::new();
    s.push(0x20); // push 32
    s.extend_from_slice(&[0xaa; 32]);
    s.push(0xac); // OP_CHECKSIG
    s.push(0x00); // OP_FALSE
    s.push(0x63); // OP_IF
    s.push(0x03); // push 3
    s.extend_from_slice(b"ord");
    s.push(0x0a); // push 10
    s.extend_from_slice(b"text/plain");
    s.push(0x68); // OP_ENDIF
    s
}

#[test]
fn contains_ops_matches_ordinals_envelope() {
    let mut b = TxB::default();
    b.inputs = vec![InB {
        leaf_script: ord_leaf(),
        ..Default::default()
    }];
    assert!(run(
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        &b
    ));
    // A plain key-path spend (empty leaf) must not match.
    let mut b2 = TxB::default();
    b2.inputs = vec![InB::default()];
    assert!(!run(
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        &b2
    ));
}

#[test]
fn contains_ops_is_position_safe() {
    // The bytes 0x6f7264 ("ord") appear INSIDE a larger push, not as their own
    // push token — must NOT match push(0x6f7264).
    let mut s = Vec::new();
    s.push(0x00); // OP_FALSE
    s.push(0x63); // OP_IF
    s.push(0x05); // push 5
    s.extend_from_slice(&[0x6f, 0x72, 0x64, 0xff, 0xee]); // "ord" + extra, one push
    let mut b = TxB::default();
    b.inputs = vec![InB {
        leaf_script: s,
        ..Default::default()
    }];
    assert!(!run(
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        &b
    ));
    // But the prefix form matches a push that *starts with* the marker.
    assert!(run(
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264*))))",
        &b
    ));
}

#[test]
fn runes_runestone_op13() {
    // OP_RETURN OP_PUSHNUM_13 <push payload>
    let mut s = vec![0x6a, 0x5d, 0x04];
    s.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let mut b = TxB::default();
    b.outputs = vec![OutB {
        script_type: ScriptType::OpReturn,
        script: s,
        ..Default::default()
    }];
    assert!(run(
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))",
        &b
    ));
    // OP_13 alias resolves identically.
    assert!(run(
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_13 *)))",
        &b
    ));
    // An ordinary OP_RETURN datacarrier (OP_RETURN <push>) is not a runestone.
    let mut b2 = TxB::default();
    b2.outputs = vec![OutB {
        script_type: ScriptType::OpReturn,
        script: vec![0x6a, 0x02, 0xaa, 0xbb],
        ..Default::default()
    }];
    assert!(!run(
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))",
        &b2
    ));
}

#[test]
fn push_size_and_range_and_count_and_maxpush() {
    // OP_RETURN <push 40 bytes>
    let mut s = vec![0x6a, 0x28];
    s.extend_from_slice(&[0x7a; 40]);
    let mut b = TxB::default();
    b.outputs = vec![OutB {
        script_type: ScriptType::OpReturn,
        script: s,
        ..Default::default()
    }];
    assert!(run(
        "any outputs (out.script.contains_ops(script(OP_RETURN push(40))))",
        &b
    ));
    assert!(run(
        "any outputs (out.script.contains_ops(script(OP_RETURN push(32..80))))",
        &b
    ));
    assert!(!run(
        "any outputs (out.script.contains_ops(script(OP_RETURN push(41))))",
        &b
    ));
    assert!(run("any outputs (out.script.max_push == 40)", &b));
    assert!(run("any outputs (out.script.count_op(OP_RETURN) == 1)", &b));
    assert!(run("any outputs (out.script.well_formed)", &b));
}

#[test]
fn well_formed_false_on_truncated_push() {
    // OP_PUSHBYTES_10 with no data.
    let mut b = TxB::default();
    b.outputs = vec![OutB {
        script_type: ScriptType::Nonstandard,
        script: vec![0x0a],
        ..Default::default()
    }];
    assert!(!run("any outputs (out.script.well_formed)", &b));
}

// --- §17 cookbook rules compile & behave ---

#[test]
fn cookbook_rules_compile() {
    let rules = [
        "tx.source == rpc or tx.source == mcp",
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        "any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x61746f6d))))",
        "any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))",
        "any outputs (out.script_type == bare_multisig)",
        "any outputs (out.script_type == op_return and out.op_return_size > 83) and tx.fee_rate < node.min_relay_fee * 3",
        "count outputs (out.is_dust and out.script_type != p2a) >= 5",
        "tx.total_witness_size > 100kb",
    ];
    for r in rules {
        compile_bool(r).unwrap_or_else(|e| panic!("cookbook rule failed to compile `{r}`: {e}"));
    }
}

#[test]
fn dust_storm_carves_out_p2a() {
    let mut b = TxB::default();
    // 5 dust outputs but one is a P2A anchor → only 4 count.
    b.outputs = (0..5)
        .map(|i| OutB {
            value: 300,
            is_dust: true,
            script_type: if i == 0 {
                ScriptType::P2a
            } else {
                ScriptType::P2wpkh
            },
            ..Default::default()
        })
        .collect();
    assert!(!run(
        "count outputs (out.is_dust and out.script_type != p2a) >= 5",
        &b
    ));
    // Add a 6th non-anchor dust output → now 5 qualify.
    b.outputs.push(OutB {
        value: 300,
        is_dust: true,
        ..Default::default()
    });
    assert!(run(
        "count outputs (out.is_dust and out.script_type != p2a) >= 5",
        &b
    ));
}

#[test]
fn cheap_bulk_opreturn_pays_its_way() {
    // Oversized OP_RETURN but paying well → not caught.
    let mut b = TxB::default();
    b.fee_rate = 50_000;
    b.outputs = vec![OutB {
        script_type: ScriptType::OpReturn,
        op_return_size: 200,
        ..Default::default()
    }];
    let rule = "any outputs (out.script_type == op_return and out.op_return_size > 83) and tx.fee_rate < node.min_relay_fee * 3";
    assert!(!run(rule, &b));
    // Same shape, underpaying → caught.
    b.fee_rate = 1_500;
    assert!(run(rule, &b));
}

// --- cost & fuel ---

#[test]
fn budget_rejects_pathological_ruleset() {
    // Two output-quantified 32-token contains_ops scans exceed POLICY_BUDGET.
    let pat = "OP_NOP ".repeat(30);
    let one = format!("any outputs (out.script.contains_ops(script(OP_RETURN {pat})))");
    let two = format!("{one} or {one}");
    // A single one is within budget...
    compile_bool(&one).expect("single heavy rule within budget");
    // ...two of them are not.
    let e = compile_bool(&two).unwrap_err();
    assert_eq!(e.stage, Stage::Cost);
}

#[test]
fn fuel_exhaustion_is_reported_not_panicked() {
    // A large script scanned with a tiny fuel budget exhausts fuel.
    let big = vec![0x51u8; 2_000]; // 2000 OP_1 opcodes
    let b = {
        let mut b = TxB::default();
        b.outputs = vec![OutB {
            script_type: ScriptType::Nonstandard,
            script: big,
            ..Default::default()
        }];
        b
    };
    let ce = compile_bool("any outputs (out.script.contains_ops(script(OP_CHECKSIG)))").unwrap();
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    let out = ce.eval_metered(&tx, &ctx(), 50);
    assert!(out.fuel_exhausted);
}

#[test]
fn whitespace_comments_and_aliases() {
    let b = TxB::default();
    let src = "# leading comment\n  tx.version == 2  and  not tx.signals_rbf # trailing";
    assert!(run(src, &b));
    // && / || / ! aliases.
    assert!(run("tx.version == 2 && !tx.signals_rbf", &b));
    assert!(run("tx.version == 2 || tx.version == 3", &b));
}
