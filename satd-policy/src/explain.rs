//! Plain-English rendering of rules and expressions (design §2.5 D5).
//!
//! `policylint --explain` renders any ruleset — including a downloaded one — as
//! readable sentences, so third-party rules are adopted with understanding
//! rather than blindly. The same renderer backs operator-facing rule summaries
//! (`getpolicyinfo`).
//!
//! This is a *lossy, human-facing* projection of the AST, not a serializer:
//! arithmetic stays symbolic (English for `a * b + c` reads worse than the
//! source), but the structure and every comparison are spelled out.

use crate::ast::*;
use crate::ruleset::{Action, CompiledRuleset, Rule};
use crate::script;

/// Render a whole ruleset as a numbered list of plain-English rule summaries.
pub fn explain_ruleset(rs: &CompiledRuleset) -> String {
    let mut out = String::new();
    for (i, rule) in rs.rules().iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&explain_rule(rule));
        out.push('\n');
    }
    out
}

/// Render one rule: its name, what it does, and its condition in English.
pub fn explain_rule(rule: &Rule) -> String {
    let verb = match rule.action {
        Action::Quarantine => {
            // Spell out what the scope actually withholds.
            let scope = match (rule.scope.relay, rule.scope.template) {
                (true, true) => "hold back from relay and from block templates",
                (true, false) => "hold back from relay (still mineable)",
                (false, true) => "decline to mine, but keep relaying",
                // An empty scope is unreachable for a parsed rule, but render
                // something honest rather than panicking.
                (false, false) => "take no withholding action on",
            };
            scope.to_string()
        }
        Action::Allow => "accept immediately, skipping any later rule, for".to_string(),
    };
    let named = if rule.auto_named {
        format!("`{}` (auto-named)", rule.name)
    } else {
        format!("`{}`", rule.name)
    };
    format!(
        "{named}: {verb} any transaction where {}.",
        explain_expr(rule.condition().ast())
    )
}

/// Render an expression as an English clause (no trailing period).
pub fn explain_expr(expr: &Expr) -> String {
    render(expr, None)
}

fn render(expr: &Expr, dom: Option<Domain>) -> String {
    match expr {
        Expr::Bool(b, _) => if *b { "always" } else { "never" }.to_string(),
        Expr::Int(n, _) => n.to_string(),
        Expr::Bytes(b, _) => format!("0x{}", hex(b)),
        Expr::Enum(ev, _) => ev.name().to_string(),
        Expr::Attr { root, field, .. } => attr_phrase(*root, field),
        Expr::Unary {
            op: UnOp::Not,
            expr,
            ..
        } => format!("it is not the case that {}", render(expr, dom)),
        Expr::Binary { op, lhs, rhs, .. } => render_binary(*op, lhs, rhs, dom),
        Expr::Method { recv, call, .. } => render_method(recv, call, dom),
        Expr::Quant {
            kind, domain, body, ..
        } => render_quant(*kind, *domain, body),
    }
}

fn render_binary(op: BinOp, lhs: &Expr, rhs: &Expr, dom: Option<Domain>) -> String {
    let l = render(lhs, dom);
    let r = render(rhs, dom);
    match op {
        BinOp::And => format!("({l}) and ({r})"),
        BinOp::Or => format!("({l}) or ({r})"),
        BinOp::Eq => format!("{l} is {r}"),
        BinOp::Ne => format!("{l} is not {r}"),
        BinOp::Lt => format!("{l} is less than {r}"),
        BinOp::Le => format!("{l} is at most {r}"),
        BinOp::Gt => format!("{l} is greater than {r}"),
        BinOp::Ge => format!("{l} is at least {r}"),
        // Arithmetic reads better symbolically than spelled out.
        BinOp::Add => format!("({l} + {r})"),
        BinOp::Sub => format!("({l} - {r})"),
        BinOp::Mul => format!("({l} * {r})"),
        BinOp::Div => format!("({l} / {r})"),
        BinOp::Mod => format!("({l} mod {r})"),
    }
}

fn render_method(recv: &Expr, call: &MethodCall, dom: Option<Domain>) -> String {
    let r = render(recv, dom);
    match call {
        MethodCall::Len => format!("the length of {r}"),
        MethodCall::StartsWith(n) => format!("{r} starts with 0x{}", hex(n)),
        MethodCall::EndsWith(n) => format!("{r} ends with 0x{}", hex(n)),
        MethodCall::Contains(n) => format!("{r} contains the bytes 0x{}", hex(n)),
        MethodCall::ContainsOps(pat) => {
            format!("{r} contains the opcode pattern `{}`", pat.render())
        }
        MethodCall::CountOp(op) => {
            format!("the number of {} opcodes in {r}", script::opcode_name(*op))
        }
        MethodCall::MaxPush => format!("the largest data push in {r}"),
        MethodCall::WellFormed => format!("{r} is well-formed script"),
    }
}

fn render_quant(kind: QuantKind, domain: Domain, body: &Expr) -> String {
    let (singular, plural) = match domain {
        Domain::Inputs => ("input", "inputs"),
        Domain::Outputs => ("output", "outputs"),
    };
    let b = render(body, Some(domain));
    match kind {
        QuantKind::Any => format!("at least one {singular} satisfies [{b}]"),
        QuantKind::All => format!("every {singular} satisfies [{b}]"),
        QuantKind::Count => format!("the number of {plural} for which [{b}]"),
        QuantKind::Sum => format!("the sum over {plural} of [{b}]"),
    }
}

/// English phrase for an attribute. Inside a quantifier `in`/`out` read as "the
/// input"/"the output"; at top level `tx`/`node` read naturally.
fn attr_phrase(root: Root, field: &str) -> String {
    match (root, field) {
        // tx.*
        (Root::Tx, "version") => "the transaction version".into(),
        (Root::Tx, "locktime") => "the transaction locktime".into(),
        (Root::Tx, "vsize") => "the virtual size (vB)".into(),
        (Root::Tx, "weight") => "the transaction weight (WU)".into(),
        (Root::Tx, "input_count") => "the number of inputs".into(),
        (Root::Tx, "output_count") => "the number of outputs".into(),
        (Root::Tx, "signals_rbf") => "the transaction signals RBF".into(),
        (Root::Tx, "total_witness_size") => "the total witness size (bytes)".into(),
        (Root::Tx, "txid") => "the txid".into(),
        (Root::Tx, "fee") => "the fee (sat)".into(),
        (Root::Tx, "fee_rate") => "the fee rate (sat/kvB)".into(),
        (Root::Tx, "sigops_cost") => "the sigops cost".into(),
        (Root::Tx, "source") => "the submission source".into(),
        (Root::Tx, "from_whitelisted_peer") => "the tx came from a whitelisted peer".into(),
        // node.*
        (Root::Node, "network") => "the node's network".into(),
        (Root::Node, "height") => "the chain height".into(),
        (Root::Node, "min_relay_fee") => "the node's min relay fee (sat/kvB)".into(),
        (Root::Node, "dust_relay_fee") => "the node's dust relay fee (sat/kvB)".into(),
        (Root::Node, "mempool_bytes") => "the mempool size (bytes)".into(),
        (Root::Node, "mempool_min_fee") => "the mempool min fee (sat/kvB)".into(),
        // out.*
        (Root::Out, "value") => "the output value (sat)".into(),
        (Root::Out, "script_type") => "the output script type".into(),
        (Root::Out, "script") => "the output script".into(),
        (Root::Out, "op_return_size") => "the OP_RETURN payload size (bytes)".into(),
        (Root::Out, "is_dust") => "the output is dust".into(),
        // in.*
        (Root::In, "prevout_txid") => "the input's prevout txid".into(),
        (Root::In, "prevout_vout") => "the input's prevout index".into(),
        (Root::In, "sequence") => "the input's sequence".into(),
        (Root::In, "script_sig") => "the input's scriptSig".into(),
        (Root::In, "witness_items") => "the input's witness item count".into(),
        (Root::In, "witness_size") => "the input's witness size (bytes)".into(),
        (Root::In, "max_witness_item") => "the input's largest witness item (bytes)".into(),
        (Root::In, "has_annex") => "the input has a taproot annex".into(),
        (Root::In, "prevout_value") => "the input's prevout value (sat)".into(),
        (Root::In, "prevout_script_type") => "the input's prevout script type".into(),
        (Root::In, "prevout_script") => "the input's prevout script".into(),
        (Root::In, "spends_coinbase") => "the input spends a coinbase".into(),
        (Root::In, "leaf_script") => "the input's tapscript leaf".into(),
        // Unknown attributes never reach here (typecheck rejects them), but be
        // honest rather than panic.
        (r, f) => format!("{}.{f}", r.as_str()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_ruleset;

    fn rule0(src: &str) -> String {
        let rs = parse_ruleset(src).unwrap();
        explain_rule(&rs.rules()[0])
    }

    #[test]
    fn explains_a_simple_comparison() {
        let s = rule0("version 1\nallow own when tx.source == rpc");
        assert!(s.contains("`own`"), "{s}");
        assert!(s.contains("accept immediately"), "{s}");
        assert!(s.contains("the submission source is rpc"), "{s}");
    }

    #[test]
    fn explains_quarantine_scope_and_quantifier() {
        let s = rule0(
            "version 1\nquarantine big on template when any outputs (out.op_return_size > 80)",
        );
        assert!(s.contains("decline to mine"), "{s}");
        assert!(s.contains("at least one output satisfies"), "{s}");
        assert!(s.contains("the OP_RETURN payload size (bytes) is greater than 80"), "{s}");
    }

    #[test]
    fn explains_script_pattern_and_marks_auto_name() {
        let s = rule0(
            "version 1\nquarantine when any inputs (in.leaf_script.contains_ops(script(OP_RETURN push)))",
        );
        assert!(s.contains("(auto-named)"), "{s}");
        assert!(s.contains("contains the opcode pattern"), "{s}");
        assert!(s.contains("OP_RETURN push"), "{s}");
    }

    #[test]
    fn explains_boolean_structure() {
        let s = rule0("version 1\nquarantine r when tx.fee_rate < 2 and not tx.signals_rbf");
        assert!(s.contains("the fee rate (sat/kvB) is less than 2"), "{s}");
        assert!(s.contains("it is not the case that"), "{s}");
    }
}
