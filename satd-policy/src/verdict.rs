//! The verdict a ruleset returns for a transaction (§2.6, §6).
//!
//! There is no `Reject`: the quarantine-only model (the v2 design change) means
//! a ruleset can withhold a transaction from relay and/or block templates, or
//! explicitly allow it, but never causes the node to reject a transaction that
//! baseline policy would accept. Consensus is untouched by construction.

use crate::scope::ScopeSet;

/// The name used for the implicit fail-safe rule that fires when runtime fuel is
/// exhausted (§7). Static cost analysis (I5) makes this unreachable for
/// budget-respecting rulesets on normally-sized transactions; if it ever fires
/// it is a bug signal and is counted in metrics by the node.
pub const FUEL_RULE: &str = "__fuel";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matched — baseline policy decides; the transaction enters the
    /// acting class.
    Pass,
    /// An `allow` rule matched: exempt from the standardness set (§6.2) and
    /// shielded from later quarantine rules.
    Allow { rule: String },
    /// A `quarantine` rule matched: hold the transaction in the quarantine class
    /// along the given scope.
    Quarantine { rule: String, scope: ScopeSet },
}

impl Verdict {
    /// The fail-safe-restrictive verdict for fuel exhaustion: full-scope
    /// quarantine attributed to the implicit [`FUEL_RULE`].
    pub fn fuel() -> Verdict {
        Verdict::Quarantine {
            rule: FUEL_RULE.to_string(),
            scope: ScopeSet::all(),
        }
    }

    /// The name of the rule that produced this verdict, if any.
    pub fn rule(&self) -> Option<&str> {
        match self {
            Verdict::Pass => None,
            Verdict::Allow { rule } | Verdict::Quarantine { rule, .. } => Some(rule),
        }
    }
}
