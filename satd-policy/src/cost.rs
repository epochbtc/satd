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
/// transaction (a ≤4 MWU tx holds at most ~4 MB of data). A scanning method
/// inside a quantifier is costed as one whole-transaction pass — *not*
/// `element_count × per-element`, because the sum of all per-element script
/// bytes cannot exceed the transaction.
const MAX_TX_SCAN: u64 = 4_000_000;

/// A txid/flat-bytes field is fixed-size.
const TXID_BYTES: u64 = 32;

/// Consensus-ish element bounds for a ≤4 MWU transaction (minimal input ≈164 WU,
/// minimal output ≈36 WU). These bound the *flat* per-element work; scan work is
/// separately capped at `MAX_TX_SCAN`.
const MAX_INPUTS: u64 = 24_000;
const MAX_OUTPUTS: u64 = 111_000;

/// Base cost of visiting one AST node / doing one fixed comparison.
const LEAF: u64 = 1;

/// Split cost: `flat` is per-element-fixed work, `scan` is variable byte
/// scanning over script/witness data. Kept separate so a quantifier can cap its
/// scan contribution at the transaction size rather than `count × per-element`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub flat: u64,
    pub scan: u64,
}

impl Cost {
    fn leaf() -> Cost {
        Cost {
            flat: LEAF,
            scan: 0,
        }
    }
    fn add(self, other: Cost) -> Cost {
        Cost {
            flat: self.flat.saturating_add(other.flat),
            scan: self.scan.saturating_add(other.scan),
        }
    }
    fn plus_flat(self, n: u64) -> Cost {
        Cost {
            flat: self.flat.saturating_add(n),
            scan: self.scan,
        }
    }
    fn plus_scan(self, n: u64) -> Cost {
        Cost {
            flat: self.flat,
            scan: self.scan.saturating_add(n),
        }
    }
    /// Total budget cost.
    pub fn total(self) -> u64 {
        self.flat.saturating_add(self.scan)
    }
    pub fn within_budget(self) -> bool {
        self.total() <= POLICY_BUDGET
    }
}

/// Worst-case cost of an expression.
pub fn cost(expr: &Expr) -> Cost {
    match expr {
        Expr::Bool(..) | Expr::Int(..) | Expr::Bytes(..) | Expr::Enum(..) | Expr::Attr { .. } => {
            Cost::leaf()
        }
        Expr::Unary { expr, .. } => cost(expr).plus_flat(LEAF),
        Expr::Binary { lhs, rhs, .. } => cost(lhs).add(cost(rhs)).plus_flat(LEAF),
        Expr::Method { recv, call, .. } => {
            let base = cost(recv).plus_flat(LEAF);
            // Worst-case bytes this op scans: a flat 32-byte field, or a whole
            // transaction's worth of script/witness data (`MAX_TX_SCAN`).
            let bound = scan_bound(recv);
            match call {
                // O(1): just reads a length.
                MethodCall::Len => base,
                // Compare only up to the needle length.
                MethodCall::StartsWith(n) | MethodCall::EndsWith(n) => {
                    base.plus_scan(n.len() as u64)
                }
                // One linear pass over the receiver bytes.
                MethodCall::Contains(_)
                | MethodCall::CountOp(_)
                | MethodCall::MaxPush
                | MethodCall::WellFormed => base.plus_scan(bound),
                // Non-backtracking glob: O(tokens × pattern_tokens); tokens ≈
                // scanned bytes, pattern includes the +2 AnyRun padding.
                MethodCall::ContainsOps(pat) => {
                    let factor = pat.len() as u64 + 2;
                    base.plus_scan(bound.saturating_mul(factor))
                }
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
                // Scan work is one whole-transaction pass regardless of element
                // count — the body's scans already represent the full tx, since
                // all per-element scripts together are bounded by it.
                scan: b.scan,
            }
        }
    }
}

/// The scan bound for a script/bytes-valued receiver expression. Methods are
/// only applied to attributes in v1, so this inspects the attribute; anything
/// else falls back to the conservative per-script bound.
fn scan_bound(expr: &Expr) -> u64 {
    if let Expr::Attr { root, field, .. } = expr {
        match (root, field.as_str()) {
            (Root::Tx, "txid") | (Root::In, "prevout_txid") => return TXID_BYTES,
            (Root::Out, "script")
            | (Root::In, "script_sig")
            | (Root::In, "leaf_script")
            | (Root::In, "prevout_script") => return MAX_TX_SCAN,
            _ => {}
        }
    }
    MAX_TX_SCAN
}
