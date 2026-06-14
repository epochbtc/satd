//! Static cost model (§7, invariant I5).
//!
//! Every compiled expression gets a worst-case cost at load time. A ruleset
//! whose summed cost exceeds [`POLICY_BUDGET`] is rejected — this is what bounds
//! admission-path latency before any transaction is ever evaluated.
//!
//! ## Two decoupled bounds (important)
//!
//! The design states two things that pull in different directions: that
//! `MAX_ELEMENTS` is the *consensus* bound on inputs/outputs of a ≤4MWU tx, and
//! that the worst case must be **< ~100µs** on Pi-class hardware. A literal
//! `MAX_ELEMENTS × per-element-scan` product over a 4 MB transaction is
//! inherently milliseconds, so those two cannot both be a single number. We
//! resolve it the way §7 intends, with two separate mechanisms:
//!
//! 1. **[`POLICY_BUDGET`] — a ruleset *complexity* ceiling** (this module).
//!    Worst-case scan-equivalent units a whole ruleset may demand. It rejects
//!    absurd rulesets at load. Crucially, scan work inside a quantifier is
//!    capped at the total transaction size (`MAX_TX_SCAN`), because the sum of
//!    all per-element script/witness bytes cannot exceed the transaction — so
//!    the model does not multiply a full-tx scan by the element count.
//! 2. **Runtime fuel ([`crate::eval`]) — the real per-tx wall.** Decremented per
//!    AST node and per scanned byte, calibrated to ~100µs; a transaction whose
//!    *actual* evaluation would exceed it is cut off and treated as
//!    fail-safe-restrictive (Quarantine) by the rule layer.
//!
//! The constants below are *calibration* values: defensible defaults plus the
//! calibration test (`tests/`) that reports ns/unit on the host. Final numbers
//! land after the dogfood-fleet bench (§7, §14 precondition).

use crate::ast::*;

/// Maximum summed cost of a loaded ruleset, in worst-case scan-equivalent units.
/// A complexity ceiling, *not* a time bound (see module docs). PR 2 sums rule
/// costs against this; PR 1 checks single expressions.
pub const POLICY_BUDGET: u64 = 256_000_000;

/// Upper bound on total script/witness bytes scanned across all elements of one
/// transaction (a ≤4 MWU tx holds at most ~4 MB of data). A scanning method over
/// *transaction-resident* data (script_sig, witness/leaf script, output script)
/// inside a quantifier is costed as one whole-transaction pass — *not*
/// `element_count × per-element`, because the sum of all per-element script
/// bytes cannot exceed the transaction.
const MAX_TX_SCAN: u64 = 4_000_000;

/// Consensus upper bound on a single prevout scriptPubKey (`MAX_SCRIPT_SIZE`).
/// Unlike script_sig / witness / output scripts, `in.prevout_script` is sourced
/// from the UTXO set, **not** from the transaction being evaluated — so the sum
/// across inputs is *not* bounded by the transaction size and must be costed
/// per element (`element_count × per-element`), via the `scan_elem` axis.
const MAX_PREVOUT_SCRIPT: u64 = 10_000;

/// A txid/flat-bytes field is fixed-size.
const TXID_BYTES: u64 = 32;

/// Consensus-ish element bounds for a ≤4 MWU transaction (minimal input ≈164 WU,
/// minimal output ≈36 WU). These bound the *flat* per-element work; scan work is
/// separately capped at `MAX_TX_SCAN`.
const MAX_INPUTS: u64 = 24_000;
const MAX_OUTPUTS: u64 = 111_000;

/// Base cost of visiting one AST node / doing one fixed comparison.
const LEAF: u64 = 1;

/// Split cost across three axes:
/// * `flat` — per-element-fixed work, multiplied by element count in a quantifier.
/// * `scan` — byte scanning over *transaction-resident* data, capped at the
///   transaction size (`MAX_TX_SCAN`) and **not** multiplied by element count.
/// * `scan_elem` — byte scanning over *non-transaction-resident* data
///   (`in.prevout_script`, from the UTXO set), which **is** multiplied by element
///   count because the sum across inputs is unbounded by the transaction.
///
/// Keeping these separate is what lets a quantifier treat a witness scan as one
/// tx-pass while still charging prevout-script scans per input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub flat: u64,
    pub scan: u64,
    pub scan_elem: u64,
}

impl Cost {
    fn leaf() -> Cost {
        Cost {
            flat: LEAF,
            scan: 0,
            scan_elem: 0,
        }
    }
    fn plus_flat(self, n: u64) -> Cost {
        Cost {
            flat: self.flat.saturating_add(n),
            ..self
        }
    }
    fn plus_scan(self, n: u64) -> Cost {
        Cost {
            scan: self.scan.saturating_add(n),
            ..self
        }
    }
    fn plus_scan_elem(self, n: u64) -> Cost {
        Cost {
            scan_elem: self.scan_elem.saturating_add(n),
            ..self
        }
    }
    /// Total budget cost.
    pub fn total(self) -> u64 {
        self.flat
            .saturating_add(self.scan)
            .saturating_add(self.scan_elem)
    }
    pub fn within_budget(self) -> bool {
        self.total() <= POLICY_BUDGET
    }
}

impl std::ops::Add for Cost {
    type Output = Cost;
    /// Sum two costs axis-wise (saturating).
    fn add(self, other: Cost) -> Cost {
        Cost {
            flat: self.flat.saturating_add(other.flat),
            scan: self.scan.saturating_add(other.scan),
            scan_elem: self.scan_elem.saturating_add(other.scan_elem),
        }
    }
}

/// Worst-case cost of an expression.
pub fn cost(expr: &Expr) -> Cost {
    match expr {
        Expr::Bool(..) | Expr::Int(..) | Expr::Bytes(..) | Expr::Enum(..) | Expr::Attr { .. } => {
            Cost::leaf()
        }
        Expr::Unary { expr, .. } => cost(expr).plus_flat(LEAF),
        Expr::Binary { lhs, rhs, .. } => (cost(lhs) + cost(rhs)).plus_flat(LEAF),
        Expr::Method { recv, call, .. } => {
            let base = cost(recv).plus_flat(LEAF);
            // Worst-case bytes this op scans, and whether that scan is over
            // transaction-resident data (capped at `MAX_TX_SCAN`, one tx-pass) or
            // per-element non-resident data (`in.prevout_script`, charged per input).
            let (bound, per_elem) = scan_bound(recv);
            let scanned = match call {
                // O(1): just reads a length.
                MethodCall::Len => 0,
                // Compare only up to the needle length.
                MethodCall::StartsWith(n) | MethodCall::EndsWith(n) => n.len() as u64,
                // One linear pass over the receiver bytes.
                MethodCall::Contains(_)
                | MethodCall::CountOp(_)
                | MethodCall::MaxPush
                | MethodCall::WellFormed => bound,
                // Non-backtracking glob: O(tokens × pattern_tokens); tokens ≈
                // scanned bytes, pattern includes the +2 AnyRun padding.
                MethodCall::ContainsOps(pat) => {
                    let factor = pat.len() as u64 + 2;
                    bound.saturating_mul(factor)
                }
            };
            if per_elem {
                base.plus_scan_elem(scanned)
            } else {
                base.plus_scan(scanned)
            }
        }
        Expr::Quant { domain, body, .. } => {
            let n = match domain {
                Domain::Inputs => MAX_INPUTS,
                Domain::Outputs => MAX_OUTPUTS,
            };
            let b = cost(body);
            Cost {
                // Flat per-element work scales with the element count.
                flat: n.saturating_mul(b.flat).saturating_add(LEAF),
                // Transaction-resident scan work is one whole-transaction pass
                // regardless of element count — all per-element scripts together
                // are bounded by the tx.
                scan: b.scan,
                // Non-resident (prevout-script) scan work genuinely recurs per
                // element, so it scales with the element count.
                scan_elem: n.saturating_mul(b.scan_elem),
            }
        }
    }
}

/// The scan bound for a script/bytes-valued receiver expression, plus whether
/// the scan recurs per element (true only for `in.prevout_script`, which is not
/// transaction-resident). Methods are only applied to attributes in v1, so this
/// inspects the attribute; anything else falls back to the conservative
/// transaction-resident per-script bound.
fn scan_bound(expr: &Expr) -> (u64, bool) {
    if let Expr::Attr { root, field, .. } = expr {
        match (root, field.as_str()) {
            (Root::Tx, "txid") | (Root::In, "prevout_txid") => return (TXID_BYTES, false),
            // From the UTXO set, not the tx — charged per input.
            (Root::In, "prevout_script") => return (MAX_PREVOUT_SCRIPT, true),
            (Root::Out, "script") | (Root::In, "script_sig") | (Root::In, "leaf_script") => {
                return (MAX_TX_SCAN, false);
            }
            _ => {}
        }
    }
    (MAX_TX_SCAN, false)
}

#[cfg(test)]
mod tests {
    use crate::compile;

    // `in.prevout_script` is sourced from the UTXO set, not the transaction, so
    // its scan must scale per input — unlike the tx-resident script fields, whose
    // combined size is bounded by the transaction (one tx-pass).
    #[test]
    fn prevout_script_scan_is_per_element_not_one_tx_pass() {
        // leaf_script (witness, tx-resident): one tx-pass, no per-element scan.
        let leaf =
            compile("all inputs (in.leaf_script.contains_ops(script(OP_RETURN)))").unwrap();
        assert_eq!(leaf.cost().scan_elem, 0);
        assert!(leaf.cost().within_budget());

        // prevout_script (UTXO set): per-element scan ≈ MAX_INPUTS × MAX_PREVOUT_SCRIPT.
        let prevout = compile("all inputs (in.prevout_script.well_formed)").unwrap();
        assert!(prevout.cost().scan_elem >= 200_000_000, "{:?}", prevout.cost());
        assert!(prevout.cost().within_budget());
    }

    // A glob over every input's prevout script is now correctly counted as
    // hundreds of millions of units and rejected at load, rather than passing the
    // gate and silently fuel-quarantining every matching transaction at runtime.
    #[test]
    fn pathological_prevout_glob_rejected_at_load() {
        let err =
            compile("all inputs (in.prevout_script.contains_ops(script(OP_RETURN OP_DUP)))")
                .unwrap_err();
        assert!(err.message.contains("cost budget"), "{}", err.message);
    }
}
