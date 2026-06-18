//! L2-shape advisory lint (design §2.5 D2).
//!
//! An **advisory — never blocking** warning emitted when a `quarantine` rule's
//! predicate plausibly matches time-sensitive Lightning / L2 transaction shapes:
//! anchor outputs (p2a / ephemeral-value anchors), small-value outputs and
//! dust filters that sweep anchors up, witness-size caps low enough to catch
//! unilateral closes, and commitment / justice / HTLC script structure
//! (`OP_CHECKSEQUENCEVERIFY` / `OP_CHECKLOCKTIMEVERIFY`).
//!
//! These heuristics are *warnings about* protocols, not policy *for* them: they
//! carry **no consensus or admission weight whatsoever** (design §2.5). The
//! operator is free to proceed — it is their node — but incidental Lightning
//! breakage happens with eyes open. Under the quarantine model the operator can
//! also simply watch anchor-shaped transactions accumulate in quarantine and
//! see the rule is too broad, then fix it losslessly.
//!
//! Surfaced both by `policylint` and once at ruleset load (the node logs it).
//! `allow` rules are never flagged: they only make relay *more* permissive, so
//! they cannot withhold an L2 transaction.

use crate::ast::*;
use crate::ruleset::{Action, CompiledRuleset, Rule};
use crate::script::{self, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY};
use crate::value::{EnumKind, ScriptType};

/// `out.value` / `in.prevout_value` thresholds at or below this (sat) are
/// treated as "would catch anchor/dust outputs". A standard p2a anchor is 240
/// sat and ephemeral anchors are 0-value, so a small lower bound sweeps them up.
const ANCHOR_VALUE_CEILING: i128 = 1_000;

/// The L2 flow a rule may impair. Used to deduplicate advisories per rule and to
/// give each a stable headline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum L2Flow {
    /// Pay-to-anchor outputs (CPFP fee-bump anchors).
    Anchor,
    /// Dust / small-value output filters that also catch anchors.
    DustAnchor,
    /// Witness-size caps that can catch unilateral-close / justice witnesses.
    WitnessClose,
    /// Commitment / justice / HTLC script structure (OP_CSV / OP_CLTV).
    CommitmentScript,
}

impl L2Flow {
    /// A short, stable headline for the flow.
    pub fn headline(self) -> &'static str {
        match self {
            L2Flow::Anchor => "may quarantine Lightning/L2 anchor (CPFP) outputs",
            L2Flow::DustAnchor => "may quarantine anchor / small-value L2 outputs",
            L2Flow::WitnessClose => "may quarantine Lightning unilateral-close witnesses",
            L2Flow::CommitmentScript => {
                "may quarantine Lightning commitment / justice / HTLC scripts"
            }
        }
    }
}

/// One advisory finding: the rule that triggered it, the flow it may impair, and
/// a concrete reason naming what in the predicate matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub rule: String,
    pub flow: L2Flow,
    pub detail: String,
}

/// Compute advisories for an entire ruleset, in rule order.
pub fn advise_ruleset(rs: &CompiledRuleset) -> Vec<Advisory> {
    rs.rules().iter().flat_map(advise_rule).collect()
}

/// Compute advisories for a single rule. `allow` rules are never flagged.
pub fn advise_rule(rule: &Rule) -> Vec<Advisory> {
    if rule.action != Action::Quarantine {
        return Vec::new();
    }
    let mut signals = Signals::default();
    walk(rule.condition().ast(), &mut signals);
    // Emit at most one advisory per flow, in a stable order, each with the first
    // concrete reason collected for it.
    let mut out = Vec::new();
    for flow in [
        L2Flow::Anchor,
        L2Flow::DustAnchor,
        L2Flow::WitnessClose,
        L2Flow::CommitmentScript,
    ] {
        if let Some(detail) = signals.detail(flow) {
            out.push(Advisory {
                rule: rule.name.clone(),
                flow,
                detail,
            });
        }
    }
    out
}

#[derive(Default)]
struct Signals {
    anchor: Option<String>,
    dust: Option<String>,
    witness: Option<String>,
    commitment: Option<String>,
}

impl Signals {
    fn detail(&self, flow: L2Flow) -> Option<String> {
        match flow {
            L2Flow::Anchor => self.anchor.clone(),
            L2Flow::DustAnchor => self.dust.clone(),
            L2Flow::WitnessClose => self.witness.clone(),
            L2Flow::CommitmentScript => self.commitment.clone(),
        }
    }
    fn set_anchor(&mut self, d: impl Into<String>) {
        self.anchor.get_or_insert_with(|| d.into());
    }
    fn set_dust(&mut self, d: impl Into<String>) {
        self.dust.get_or_insert_with(|| d.into());
    }
    fn set_witness(&mut self, d: impl Into<String>) {
        self.witness.get_or_insert_with(|| d.into());
    }
    fn set_commitment(&mut self, d: impl Into<String>) {
        self.commitment.get_or_insert_with(|| d.into());
    }
}

fn walk(expr: &Expr, sig: &mut Signals) {
    match expr {
        Expr::Bool(..) | Expr::Int(..) | Expr::Bytes(..) => {}
        Expr::Enum(ev, _) => {
            // A reference to the p2a script type targets anchor outputs directly.
            if ev.kind == EnumKind::ScriptType && ev.code == ScriptType::P2a as u8 {
                sig.set_anchor(
                    "references the `p2a` script type — pay-to-anchor outputs are \
                     Lightning/L2 CPFP fee-bump anchors",
                );
            }
        }
        Expr::Attr { root, field, .. } => attr_signal(*root, field, sig),
        Expr::Unary { expr, .. } => walk(expr, sig),
        Expr::Binary { op, lhs, rhs, .. } => {
            // A small value threshold catches dust-sized anchor outputs.
            value_threshold(*op, lhs, rhs, sig);
            value_threshold(flip(*op), rhs, lhs, sig);
            walk(lhs, sig);
            walk(rhs, sig);
        }
        Expr::Method { recv, call, .. } => {
            method_signal(call, sig);
            walk(recv, sig);
        }
        Expr::Quant { body, .. } => walk(body, sig),
    }
}

/// `out.is_dust`, and the witness-size attributes, are signals on their own.
fn attr_signal(root: Root, field: &str, sig: &mut Signals) {
    match (root, field) {
        (Root::Out, "is_dust") => sig.set_dust(
            "filters on `out.is_dust` — anchor and other intentionally-dust L2 \
             outputs are dust by construction",
        ),
        (Root::In, "witness_size")
        | (Root::In, "max_witness_item")
        | (Root::Tx, "total_witness_size") => sig.set_witness(format!(
            "constrains `{}.{field}` — Lightning unilateral-close and justice \
             transactions carry distinctive witness sizes",
            root.as_str()
        )),
        _ => {}
    }
}

/// `count_op`/`contains_ops` referencing OP_CSV / OP_CLTV signal commitment-style
/// script structure.
fn method_signal(call: &MethodCall, sig: &mut Signals) {
    match call {
        MethodCall::CountOp(op) if is_commitment_op(*op) => sig.set_commitment(format!(
            "counts `{}` — distinctive of Lightning commitment / justice / HTLC scripts",
            script::opcode_name(*op)
        )),
        MethodCall::ContainsOps(pat) => {
            for t in &pat.tokens {
                if let crate::script::PatToken::Op(op) = t
                    && is_commitment_op(*op)
                {
                    sig.set_commitment(format!(
                        "matches an opcode pattern containing `{}` — distinctive of \
                         Lightning commitment / justice / HTLC scripts",
                        script::opcode_name(*op)
                    ));
                }
            }
        }
        _ => {}
    }
}

/// Recognize `<value-attr> <op> <int const>` with a small constant.
fn value_threshold(op: BinOp, attr: &Expr, lit: &Expr, sig: &mut Signals) {
    let (Expr::Attr { root, field, .. }, Expr::Int(n, _)) = (attr, lit) else {
        return;
    };
    let is_value = matches!(
        (root, field.as_str()),
        (Root::Out, "value") | (Root::In, "prevout_value")
    );
    if !is_value {
        return;
    }
    // Upper-bounding the value (`< / <=`), or equality with a small constant,
    // sweeps up dust-sized anchor / L2 outputs.
    let small_upper_bound = matches!(op, BinOp::Lt | BinOp::Le) && *n <= ANCHOR_VALUE_CEILING;
    let small_equality = matches!(op, BinOp::Eq) && *n <= ANCHOR_VALUE_CEILING;
    if small_upper_bound || small_equality {
        sig.set_dust(format!(
            "bounds `{}.{field}` at {n} sat — at or below this, intentionally-dust \
             anchor / L2 outputs (p2a is 240 sat, ephemeral anchors are 0) are caught",
            root.as_str()
        ));
    }
}

fn is_commitment_op(op: u8) -> bool {
    op == OP_CHECKSEQUENCEVERIFY || op == OP_CHECKLOCKTIMEVERIFY
}

/// The comparison operator with its operands swapped, so a single
/// `value_threshold` body handles both `attr < n` and `n > attr`.
fn flip(op: BinOp) -> BinOp {
    match op {
        BinOp::Lt => BinOp::Gt,
        BinOp::Le => BinOp::Ge,
        BinOp::Gt => BinOp::Lt,
        BinOp::Ge => BinOp::Le,
        other => other, // Eq/Ne and the non-comparisons are symmetric here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_ruleset;

    fn flows(src: &str) -> Vec<L2Flow> {
        let rs = parse_ruleset(src).unwrap();
        advise_ruleset(&rs).into_iter().map(|a| a.flow).collect()
    }

    #[test]
    fn flags_p2a_anchor_reference() {
        let f = flows("version 1\nquarantine r when any outputs (out.script_type == p2a)");
        assert!(f.contains(&L2Flow::Anchor), "{f:?}");
    }

    #[test]
    fn flags_is_dust_filter() {
        let f = flows("version 1\nquarantine r when any outputs (out.is_dust)");
        assert!(f.contains(&L2Flow::DustAnchor), "{f:?}");
    }

    #[test]
    fn flags_small_value_threshold_either_orientation() {
        let f = flows("version 1\nquarantine r when any outputs (out.value < 546)");
        assert!(f.contains(&L2Flow::DustAnchor), "{f:?}");
        // Reversed operand order must trigger identically.
        let g = flows("version 1\nquarantine r when any outputs (330 > out.value)");
        assert!(g.contains(&L2Flow::DustAnchor), "{g:?}");
    }

    #[test]
    fn does_not_flag_large_value_threshold() {
        // A high-value filter has nothing to do with anchors.
        let f = flows("version 1\nquarantine r when any outputs (out.value < 100000)");
        assert!(!f.contains(&L2Flow::DustAnchor), "{f:?}");
    }

    #[test]
    fn flags_witness_size_cap() {
        let f = flows("version 1\nquarantine r when any inputs (in.witness_size > 5000)");
        assert!(f.contains(&L2Flow::WitnessClose), "{f:?}");
    }

    #[test]
    fn flags_csv_in_count_op_and_pattern() {
        let f = flows(
            "version 1\nquarantine r when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)",
        );
        assert!(f.contains(&L2Flow::CommitmentScript), "{f:?}");
        let g = flows(
            "version 1\nquarantine r when any inputs (in.leaf_script.contains_ops(script(OP_CHECKLOCKTIMEVERIFY)))",
        );
        assert!(g.contains(&L2Flow::CommitmentScript), "{g:?}");
    }

    #[test]
    fn does_not_flag_innocuous_opreturn_rule() {
        // The canonical ordinals/spam rule must NOT produce L2 advisories — this
        // is the false-positive guard.
        let f = flows(
            "version 1\nquarantine ordinals when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        );
        assert!(f.is_empty(), "unexpected advisories: {f:?}");
    }

    #[test]
    fn allow_rules_are_never_flagged() {
        // Even though it references p2a, an `allow` only widens relay.
        let f = flows("version 1\nallow anchors when any outputs (out.script_type == p2a)");
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn one_advisory_per_flow_even_with_repeated_signals() {
        let rs = parse_ruleset(
            "version 1\nquarantine r when any outputs (out.value < 546 or out.value == 0)",
        )
        .unwrap();
        let adv = advise_ruleset(&rs);
        assert_eq!(adv.iter().filter(|a| a.flow == L2Flow::DustAnchor).count(), 1);
    }
}
