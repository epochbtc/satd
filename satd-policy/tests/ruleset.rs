//! Tests for the policy-file layer (§5): grammar, version gate, scopes,
//! auto-naming, first-match evaluation, `allow` shielding, strict-loading error
//! messages (with golden caret renderings), and the §17.2 cookbook file.
#![allow(clippy::field_reassign_with_default)]

use satd_policy::{Action, ScriptType, Source, Stage, Verdict, parse_ruleset};

mod common;
use common::*;

fn eval(src: &str, b: &TxB) -> Verdict {
    let rs = parse_ruleset(src).unwrap_or_else(|e| panic!("parse:\n{}", e.render(src)));
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    rs.evaluate(&tx, &ctx())
}

// --- version gate ---

#[test]
fn empty_file_needs_version() {
    let e = parse_ruleset("# just a comment\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("version"), "{}", e.message);
}

#[test]
fn version_must_be_first() {
    let e = parse_ruleset("quarantine when tx.version == 2\nversion 1\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
}

#[test]
fn rejects_unsupported_version() {
    let e = parse_ruleset("version 2\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(
        e.message.contains("unsupported policy version 2"),
        "{}",
        e.message
    );
}

#[test]
fn version_only_is_valid_empty_ruleset() {
    let rs = parse_ruleset("version 1\n").unwrap();
    assert!(rs.is_empty());
    assert_eq!(rs.version(), 1);
    assert!(!rs.has_allow());
}

// --- structure & scopes ---

#[test]
fn parses_named_rule_with_scope() {
    let rs =
        parse_ruleset("version 1\nquarantine big on template when tx.total_witness_size > 100kb\n")
            .unwrap();
    let r = &rs.rules()[0];
    assert_eq!(r.name, "big");
    assert!(!r.auto_named);
    assert_eq!(r.action, Action::Quarantine);
    assert!(r.scope.template && !r.scope.relay);
}

#[test]
fn default_scope_is_both() {
    let rs = parse_ruleset("version 1\nquarantine when tx.version == 2\n").unwrap();
    let r = &rs.rules()[0];
    assert!(r.scope.relay && r.scope.template);
}

#[test]
fn scope_list_relay_and_template() {
    let rs =
        parse_ruleset("version 1\nquarantine n on relay,template when tx.version == 2\n").unwrap();
    assert!(rs.rules()[0].scope.relay && rs.rules()[0].scope.template);
}

#[test]
fn allow_rejects_scope() {
    let e = parse_ruleset("version 1\nallow x on relay when tx.source == rpc\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("allow"), "{}", e.message);
}

#[test]
fn rejects_unknown_scope() {
    let e = parse_ruleset("version 1\nquarantine on wire when tx.version == 2\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("unknown scope"), "{}", e.message);
}

#[test]
fn rejects_unknown_action() {
    let e = parse_ruleset("version 1\nquarintine when tx.version == 2\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("quarantine"), "{}", e.message);
}

#[test]
fn rejects_missing_when() {
    let e = parse_ruleset("version 1\nquarantine big\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("when"), "{}", e.message);
}

#[test]
fn rejects_reserved_name() {
    let e = parse_ruleset("version 1\nquarantine relay when tx.version == 2\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    // `relay` after the action is parsed as a name candidate and rejected as
    // reserved (it isn't `on`).
    assert!(
        e.message.contains("reserved") || e.message.contains("on"),
        "{}",
        e.message
    );
}

#[test]
fn rejects_bad_name_chars() {
    let e = parse_ruleset("version 1\nquarantine Big_Rule when tx.version == 2\n").unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
}

#[test]
fn rejects_duplicate_names() {
    let src =
        "version 1\nquarantine dup when tx.version == 2\nquarantine dup when tx.version == 3\n";
    let e = parse_ruleset(src).unwrap_err();
    assert_eq!(e.stage, Stage::Ruleset);
    assert!(e.message.contains("duplicate"), "{}", e.message);
}

// --- expression errors bubble up with file coordinates ---

#[test]
fn expression_error_maps_to_file_span() {
    let src = "version 1\nquarantine when tx.frobnicate > 1\n";
    let e = parse_ruleset(src).unwrap_err();
    assert_eq!(e.stage, Stage::Type);
    let rendered = e.render(src);
    // The caret must land on line 2 (where the bad attribute is), not line 1.
    assert!(rendered.contains("line 2"), "rendered:\n{rendered}");
    assert!(rendered.contains("frobnicate"), "rendered:\n{rendered}");
}

#[test]
fn golden_unknown_scope_render() {
    let src = "version 1\nquarantine n on wire when tx.version == 2\n";
    let e = parse_ruleset(src).unwrap_err();
    let rendered = e.render(src);
    assert!(rendered.contains('^'), "rendered:\n{rendered}");
    assert!(rendered.contains("line 2"), "rendered:\n{rendered}");
    assert!(rendered.contains("unknown scope"), "rendered:\n{rendered}");
}

// --- auto-naming ---

#[test]
fn auto_name_is_stable_and_format() {
    let a = parse_ruleset("version 1\nquarantine when tx.version == 2\n").unwrap();
    let b = parse_ruleset("version 1\nquarantine   when   tx.version == 2  # comment\n").unwrap();
    let na = &a.rules()[0].name;
    let nb = &b.rules()[0].name;
    assert!(a.rules()[0].auto_named);
    assert!(na.starts_with("r-") && na.len() == 10, "{na}");
    // Whitespace and comments don't change the auto-name.
    assert_eq!(na, nb);
}

#[test]
fn auto_name_changes_with_content() {
    let a = parse_ruleset("version 1\nquarantine when tx.version == 2\n").unwrap();
    let b = parse_ruleset("version 1\nquarantine when tx.version == 3\n").unwrap();
    assert_ne!(a.rules()[0].name, b.rules()[0].name);
}

// --- first-match evaluation ---

#[test]
fn first_match_wins_and_allow_shields() {
    // allow own submissions first; a later quarantine must not fire for them.
    let src = "version 1\n\
               allow mine when tx.source == rpc or tx.source == mcp\n\
               quarantine no-rbf when tx.signals_rbf\n";
    let mut b = TxB::default();
    b.source = Source::Rpc;
    b.signals_rbf = true;
    assert_eq!(
        eval(src, &b),
        Verdict::Allow {
            rule: "mine".into()
        }
    );

    // A p2p tx with the same shape gets quarantined by the second rule.
    b.source = Source::P2p;
    match eval(src, &b) {
        Verdict::Quarantine { rule, scope } => {
            assert_eq!(rule, "no-rbf");
            assert!(scope.relay && scope.template);
        }
        other => panic!("expected quarantine, got {other:?}"),
    }
}

#[test]
fn no_match_is_pass() {
    let src = "version 1\nquarantine when tx.version == 99\n";
    assert_eq!(eval(src, &TxB::default()), Verdict::Pass);
}

#[test]
fn template_scope_verdict() {
    let src = "version 1\nquarantine big on template when tx.total_witness_size > 100kb\n";
    let mut b = TxB::default();
    b.total_witness_size = 200_000;
    match eval(src, &b) {
        Verdict::Quarantine { rule, scope } => {
            assert_eq!(rule, "big");
            assert!(scope.template && !scope.relay);
        }
        other => panic!("expected template quarantine, got {other:?}"),
    }
}

// --- the §17.2 cookbook, as a real policy file ---

const COOKBOOK: &str = "\
version 1

# Exception first: my own submissions are never filtered.
allow own-submissions when tx.source == rpc or tx.source == mcp

# Ordinals / BRC-20 inscriptions.
quarantine ordinals on relay,template
    when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))

# Atomicals / ARC-20.
quarantine atomicals
    when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x61746f6d))))

# Runes.
quarantine runes
    when any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))

# Bitcoin Stamps / SRC-20, classic bare-multisig variant.
quarantine stamps-baremultisig when any outputs (out.script_type == bare_multisig)

# Cheap, oversized generic OP_RETURN.
quarantine cheap-bulk-opreturn
    when any outputs (out.script_type == op_return and out.op_return_size > 83)
         and tx.fee_rate < node.min_relay_fee * 3

# Dust storms (P2A anchors carved out in place).
quarantine dust-storm
    when count outputs (out.is_dust and out.script_type != p2a) >= 5

# Mine-neutral big-witness: relay it, just don't mine it.
quarantine no-mine-big-witness on template when tx.total_witness_size > 100kb
";

#[test]
fn cookbook_parses_with_expected_rules() {
    let rs = parse_ruleset(COOKBOOK).unwrap_or_else(|e| panic!("{}", e.render(COOKBOOK)));
    assert!(rs.has_allow());
    let names: Vec<&str> = rs.rules().iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "own-submissions",
            "ordinals",
            "atomicals",
            "runes",
            "stamps-baremultisig",
            "cheap-bulk-opreturn",
            "dust-storm",
            "no-mine-big-witness",
        ]
    );
    assert!(rs.total_cost().total() < satd_policy::POLICY_BUDGET);
}

#[test]
fn cookbook_quarantines_an_inscription() {
    let rs = parse_ruleset(COOKBOOK).unwrap();
    let mut b = TxB::default();
    b.inputs = vec![InB {
        leaf_script: ord_leaf(),
        ..Default::default()
    }];
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    match rs.evaluate(&tx, &ctx()) {
        Verdict::Quarantine { rule, .. } => assert_eq!(rule, "ordinals"),
        other => panic!("expected ordinals quarantine, got {other:?}"),
    }
}

#[test]
fn cookbook_passes_an_ordinary_payment() {
    let rs = parse_ruleset(COOKBOOK).unwrap();
    let b = TxB::default(); // plain p2wpkh payment, no markers
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    assert_eq!(rs.evaluate(&tx, &ctx()), Verdict::Pass);
}

#[test]
fn cookbook_allows_own_rpc_submission_even_if_it_looks_like_spam() {
    let rs = parse_ruleset(COOKBOOK).unwrap();
    let mut b = TxB::default();
    b.source = Source::Rpc;
    b.inputs = vec![InB {
        leaf_script: ord_leaf(),
        ..Default::default()
    }];
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    assert_eq!(
        rs.evaluate(&tx, &ctx()),
        Verdict::Allow {
            rule: "own-submissions".into()
        }
    );
}

#[test]
fn cookbook_runes_and_dust() {
    let rs = parse_ruleset(COOKBOOK).unwrap();
    // A runestone output.
    let mut b = TxB::default();
    b.outputs = vec![OutB {
        script_type: ScriptType::OpReturn,
        script: vec![0x6a, 0x5d, 0x01, 0x00],
        ..Default::default()
    }];
    let ins = b.input_views();
    let outs = b.output_views();
    let tx = b.tx_view(&ins, &outs);
    assert_eq!(rs.evaluate(&tx, &ctx()).rule(), Some("runes"));
}

// Regression: classic-Mac / CR-only line endings must split into separate
// logical lines, not collapse the whole file into one (which fails to load).
#[test]
fn cr_only_line_endings_parse_as_separate_lines() {
    let src = "version 1\rquarantine when tx.version == 2\r";
    let rs = parse_ruleset(src).unwrap_or_else(|e| panic!("CR-only:\n{}", e.render(src)));
    assert_eq!(rs.rules().len(), 1);
}

/// The shipped example/dogfood ruleset (`contrib/policy/example.policy`) must
/// always compile and stay within budget — it is loaded by the dogfood fleet and
/// referenced from the Operator Manual, so a grammar change that breaks it must
/// fail CI here, not in production.
#[test]
fn shipped_example_policy_compiles() {
    let src = include_str!("../../contrib/policy/example.policy");
    let rs = parse_ruleset(src).unwrap_or_else(|e| panic!("example.policy:\n{}", e.render(src)));
    assert_eq!(rs.version(), 1);
    assert_eq!(rs.rules().len(), 5);
    assert!(rs.has_allow(), "the example leads with an `allow own-submissions` rule");
    assert!(
        rs.total_cost().total() <= satd_policy::POLICY_BUDGET,
        "example.policy must stay within the static cost budget"
    );
    // The shipped example must not trip the strict danger gate (§2.5): a node
    // would refuse to start with it otherwise. No rule may withhold relay for a
    // Lightning enforcement shape.
    let findings = satd_policy::analyze_danger(&rs);
    let relay: Vec<_> = findings.iter().filter(|f| f.withholds_relay()).collect();
    assert!(
        relay.is_empty(),
        "example.policy would be refused by the danger gate: {relay:?}"
    );
}
