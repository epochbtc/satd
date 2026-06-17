//! `sat-cli policylint <file>` — offline parse / typecheck / cost report for a
//! policy file (design §2.5 D2/D5, §11). Pure offline consumer of the
//! `satd-policy` engine: it never contacts a node, so operators can validate a
//! ruleset — their own or a downloaded one — before any node loads it.
//!
//! Output:
//! * a per-rule cost table and the ruleset total against the static budget,
//! * the **L2-shape advisory** (`--no-advisories` to silence for CI),
//! * the **Lightning-enforcement danger** report (§2.5) — semantic, gate-grade,
//! * `--explain` plain-English rendering of each rule.
//!
//! Exit codes (for CI): `0` the file loads, `1` a load error (with a caret
//! diagnostic), `2` the file could not be read, `3` the file loads but contains
//! a rule that would **withhold relay** for Lightning enforcement traffic and
//! `--allow-dangerous-filters` was not given (strict by default — the same gate
//! the node applies at load). The syntactic L2-shape advisory never changes the
//! exit code; the danger report does, unless overridden.

use std::path::Path;

use satd_policy::{
    CompiledRuleset, DangerFinding, POLICY_BUDGET, advise_ruleset, analyze_danger, explain_rule,
    parse_ruleset,
};

/// Run the linter against `path`. Returns the process exit code.
pub fn run(path: &Path, explain: bool, no_advisories: bool, allow_dangerous: bool) -> i32 {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read policy file {}: {e}", path.display());
            return 2;
        }
    };

    let ruleset = match parse_ruleset(&src) {
        Ok(rs) => rs,
        Err(e) => {
            // The caret diagnostic is the whole point (D5: hand-authors are the
            // audience). Header names the file so the line/column are locatable.
            eprintln!("error: {} failed to load:\n", path.display());
            eprintln!("{}", e.render(&src));
            return 1;
        }
    };

    print_summary(path, &ruleset);
    print_cost_table(&ruleset);

    if explain {
        print_explanations(&ruleset);
    }

    if !no_advisories {
        print_advisories(&ruleset);
    }

    print_danger(&ruleset, allow_dangerous)
}

fn print_summary(path: &Path, rs: &CompiledRuleset) {
    let total = rs.total_cost().total();
    let pct = if POLICY_BUDGET == 0 {
        0.0
    } else {
        100.0 * total as f64 / POLICY_BUDGET as f64
    };
    let n = rs.rules().len();
    println!("policy file: {}", path.display());
    println!(
        "version {} — {n} rule{}, total cost {total} / {POLICY_BUDGET} budget ({pct:.2}%)",
        rs.version(),
        if n == 1 { "" } else { "s" },
    );
    println!();
}

fn print_cost_table(rs: &CompiledRuleset) {
    // Width the name column to the widest rule name (min 4 for the header).
    let name_w = rs
        .rules()
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    println!(
        "  {:name_w$}  {:<10}  {:<14}  {:>12}",
        "RULE", "ACTION", "SCOPE", "COST"
    );
    for r in rs.rules() {
        let (action, scope) = match r.action {
            satd_policy::Action::Quarantine => ("quarantine", r.scope.to_string()),
            satd_policy::Action::Allow => ("allow", "—".to_string()),
        };
        println!(
            "  {:name_w$}  {:<10}  {:<14}  {:>12}",
            r.name,
            action,
            scope,
            r.condition().cost().total(),
        );
    }
    println!();
}

fn print_explanations(rs: &CompiledRuleset) {
    println!("EXPLANATIONS:");
    for r in rs.rules() {
        // Indent the (possibly long) sentence under a bullet.
        println!("  • {}", explain_rule(r));
    }
    println!();
}

/// The Lightning-enforcement danger report (semantic, gate-grade §2.5). Returns
/// the process exit code: `3` if a relay-withholding rule matched an enforcement
/// shape and `allow_dangerous` is false, else `0`. `on template` matches warn
/// but never fail — E1 is about relay homogeneity, and a template-only rule
/// still relays the transaction.
fn print_danger(rs: &CompiledRuleset, allow_dangerous: bool) -> i32 {
    let findings = analyze_danger(rs);
    if findings.is_empty() {
        println!("No Lightning-enforcement danger findings.");
        return 0;
    }

    // Group by rule (scope is constant within a rule), preserving rule order.
    let mut groups: Vec<(&str, String, bool, Vec<&DangerFinding>)> = Vec::new();
    for f in &findings {
        if let Some(g) = groups.iter_mut().find(|(n, ..)| *n == f.rule) {
            g.3.push(f);
        } else {
            groups.push((&f.rule, f.scope.to_string(), f.scope.relay, vec![f]));
        }
    }
    let relay_rules = groups.iter().filter(|(.., relay, _)| *relay).count();

    println!(
        "LIGHTNING-ENFORCEMENT DANGER ({} rule{}):",
        groups.len(),
        if groups.len() == 1 { "" } else { "s" },
    );
    for (name, scope, relay, fs) in &groups {
        let sev = if *relay {
            "REFUSE (withholds relay)"
        } else {
            "warn (template-only — still relayed)"
        };
        println!("  [{name}] {sev} — scope: {scope}");
        for f in fs {
            println!("      • matches {} — {}", f.shape.label(), f.class.headline());
        }
    }
    println!();

    if relay_rules == 0 {
        // Only template-only matches: warn, never block.
        eprintln!(
            "warning: {} rule(s) decline to MINE Lightning enforcement transactions \
             (on template); they still relay, so propagation is unaffected.",
            groups.len()
        );
        return 0;
    }

    if allow_dangerous {
        eprintln!(
            "warning: {relay_rules} rule(s) would WITHHOLD RELAY for Lightning enforcement \
             transactions (E1); accepted via --allow-dangerous-filters."
        );
        0
    } else {
        eprintln!(
            "error: refusing — {relay_rules} rule(s) would WITHHOLD RELAY for Lightning \
             enforcement transactions, degrading L2 enforcement network-wide (E1)."
        );
        eprintln!(
            "       Narrow the rule(s), scope them `on template`, or re-run with \
             --allow-dangerous-filters to accept the risk."
        );
        3
    }
}

fn print_advisories(rs: &CompiledRuleset) {
    let advisories = advise_ruleset(rs);
    if advisories.is_empty() {
        println!("No L2-shape advisories.");
        return;
    }
    println!(
        "ADVISORIES ({}) — informational only; these never block loading or relay:",
        advisories.len()
    );
    for a in &advisories {
        println!("  [{}] {}", a.rule, a.flow.headline());
        println!("      {}", a.detail);
    }
    println!();
}
