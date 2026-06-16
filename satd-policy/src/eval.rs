//! The total, fuel-metered evaluator (§4.4, invariant I4).
//!
//! `eval` cannot return an error: every operator is defined on every input of
//! its type (saturating arithmetic, `x/0 == 0`, no indexing, no parsing), and
//! the only non-local exit is fuel exhaustion, which is reported as a flag
//! rather than an error. The rule layer (PR 2) maps a fuel-exhausted evaluation
//! to a fail-safe-restrictive Quarantine via the implicit `__fuel` rule; the
//! static cost model (§7) makes that path unreachable for budget-respecting
//! rulesets on normally-sized transactions.

use crate::ast::*;
use crate::script::{self, ScriptToken};
use crate::value::{EnumVal, Value};
use crate::view::{Ctx, InputView, OutputView, TxView};

/// Default runtime fuel. Decremented per AST node and per scanned byte;
/// calibrated to ~100µs on Pi-class hardware (see the calibration test, and the
/// fleet-tuning note in [`crate::cost`]). Generous enough that normally-sized
/// transactions never exhaust it, low enough to cut off pathological scans.
pub const DEFAULT_FUEL: i64 = 8_000_000;

/// Outcome of evaluating an expression.
#[derive(Clone, Copy, Debug)]
pub struct Outcome<'a> {
    pub value: Value<'a>,
    /// True iff fuel ran out mid-evaluation. When set, `value` is a sentinel and
    /// the rule layer treats the transaction as fail-safe-restrictive.
    pub fuel_exhausted: bool,
    /// Fuel left after evaluation (never negative). The rule engine threads this
    /// across a ruleset so the whole first-match pass shares one budget.
    pub fuel_remaining: i64,
}

/// Evaluate `expr` against a transaction/context view with [`DEFAULT_FUEL`].
pub fn eval<'a>(expr: &'a Expr, tx: &'a TxView<'a>, ctx: &Ctx) -> Outcome<'a> {
    eval_metered(expr, tx, ctx, DEFAULT_FUEL)
}

/// Evaluate with an explicit fuel budget.
pub fn eval_metered<'a>(expr: &'a Expr, tx: &'a TxView<'a>, ctx: &Ctx, fuel: i64) -> Outcome<'a> {
    let mut ev = Ev {
        fuel,
        exhausted: false,
        tx,
        ctx,
        cur_in: None,
        cur_out: None,
    };
    let value = ev.eval(expr);
    Outcome {
        value,
        fuel_exhausted: ev.exhausted,
        fuel_remaining: ev.fuel.max(0),
    }
}

struct Ev<'a, 'c> {
    fuel: i64,
    exhausted: bool,
    tx: &'a TxView<'a>,
    ctx: &'c Ctx,
    cur_in: Option<&'a InputView<'a>>,
    cur_out: Option<&'a OutputView<'a>>,
}

impl<'a, 'c> Ev<'a, 'c> {
    /// Charge `n` fuel; flips `exhausted` once the budget is gone.
    fn burn(&mut self, n: u64) {
        self.fuel = self.fuel.saturating_sub(n as i64);
        if self.fuel <= 0 {
            self.exhausted = true;
        }
    }

    fn eval(&mut self, expr: &'a Expr) -> Value<'a> {
        if self.exhausted {
            return Value::Bool(false);
        }
        self.burn(1);
        match expr {
            Expr::Bool(b, _) => Value::Bool(*b),
            Expr::Int(i, _) => Value::Int(*i),
            Expr::Bytes(v, _) => Value::Bytes(v.as_slice()),
            Expr::Enum(ev, _) => Value::Enum(*ev),
            Expr::Attr { root, field, .. } => self.attr(*root, field),
            Expr::Unary {
                op: UnOp::Not,
                expr,
                ..
            } => Value::Bool(!self.eval(expr).as_bool()),
            Expr::Binary { op, lhs, rhs, .. } => self.binary(*op, lhs, rhs),
            Expr::Method { recv, call, .. } => self.method(recv, call),
            Expr::Quant {
                kind, domain, body, ..
            } => self.quant(*kind, *domain, body),
        }
    }

    fn binary(&mut self, op: BinOp, lhs: &'a Expr, rhs: &'a Expr) -> Value<'a> {
        // Short-circuit boolean operators.
        match op {
            BinOp::And => {
                let l = self.eval(lhs).as_bool();
                if !l {
                    return Value::Bool(false);
                }
                return Value::Bool(self.eval(rhs).as_bool());
            }
            BinOp::Or => {
                let l = self.eval(lhs).as_bool();
                if l {
                    return Value::Bool(true);
                }
                return Value::Bool(self.eval(rhs).as_bool());
            }
            _ => {}
        }
        let l = self.eval(lhs);
        let r = self.eval(rhs);
        match op {
            BinOp::Eq => Value::Bool(value_eq(l, r)),
            BinOp::Ne => Value::Bool(!value_eq(l, r)),
            BinOp::Lt => Value::Bool(l.as_int() < r.as_int()),
            BinOp::Le => Value::Bool(l.as_int() <= r.as_int()),
            BinOp::Gt => Value::Bool(l.as_int() > r.as_int()),
            BinOp::Ge => Value::Bool(l.as_int() >= r.as_int()),
            BinOp::Add => Value::Int(l.as_int().saturating_add(r.as_int())),
            BinOp::Sub => Value::Int(l.as_int().saturating_sub(r.as_int())),
            BinOp::Mul => Value::Int(l.as_int().saturating_mul(r.as_int())),
            BinOp::Div => Value::Int(checked_div(l.as_int(), r.as_int())),
            BinOp::Mod => Value::Int(checked_rem(l.as_int(), r.as_int())),
            BinOp::And | BinOp::Or => unreachable!("handled above"),
        }
    }

    fn method(&mut self, recv: &'a Expr, call: &MethodCall) -> Value<'a> {
        let recv_val = self.eval(recv);
        let bytes = match recv_val {
            Value::Bytes(b) => b,
            // Typechecked to be Bytes; defensive default keeps eval total.
            _ => return Value::Bool(false),
        };
        match call {
            MethodCall::Len => Value::Int(bytes.len() as i128),
            MethodCall::StartsWith(n) => {
                self.burn(n.len() as u64);
                Value::Bool(bytes.starts_with(n))
            }
            MethodCall::EndsWith(n) => {
                self.burn(n.len() as u64);
                Value::Bool(bytes.ends_with(n))
            }
            MethodCall::Contains(n) => {
                // Naive substring scan is O(haystack × needle); charge for it and
                // bail before scanning if that exhausts fuel (the value is then
                // ignored — the rule layer fail-safe-quarantines on exhaustion).
                self.burn((bytes.len() as u64).saturating_mul(n.len() as u64));
                if self.exhausted {
                    return Value::Bool(false);
                }
                Value::Bool(contains_subslice(bytes, n))
            }
            MethodCall::CountOp(op) => {
                let toks = self.tokenize(bytes);
                Value::Int(script::count_op(&toks, *op))
            }
            MethodCall::MaxPush => {
                let toks = self.tokenize(bytes);
                Value::Int(script::max_push(&toks))
            }
            MethodCall::WellFormed => {
                self.burn(bytes.len() as u64);
                if self.exhausted {
                    return Value::Bool(false);
                }
                Value::Bool(script::tokenize(bytes).well_formed)
            }
            MethodCall::ContainsOps(pat) => {
                let toks = self.tokenize(bytes);
                self.burn((toks.len() as u64).saturating_mul(pat.len() as u64 + 2));
                // Don't run the (potentially large) glob once fuel is gone.
                if self.exhausted {
                    return Value::Bool(false);
                }
                Value::Bool(pat.contains_in(&toks))
            }
        }
    }

    /// Tokenize, charging fuel for the linear pass first. If that exhausts the
    /// budget we skip the actual scan entirely and return no tokens: the only
    /// consumer that matters on the exhausted path is the rule layer, which
    /// fail-safe-quarantines on `fuel_exhausted` regardless of the token stream.
    /// This bounds the work of any single tokenize call by the fuel available at
    /// the call (≤ [`DEFAULT_FUEL`]) rather than by the unbounded script length.
    fn tokenize<'b>(&mut self, bytes: &'b [u8]) -> Vec<ScriptToken<'b>> {
        self.burn(bytes.len() as u64);
        if self.exhausted {
            return Vec::new();
        }
        script::tokenize(bytes).tokens
    }

    fn quant(&mut self, kind: QuantKind, domain: Domain, body: &'a Expr) -> Value<'a> {
        match domain {
            Domain::Inputs => {
                let inputs = self.tx.inputs;
                self.quant_over(kind, body, inputs.len(), |ev, idx| {
                    ev.cur_in = Some(&inputs[idx]);
                })
            }
            Domain::Outputs => {
                let outputs = self.tx.outputs;
                self.quant_over(kind, body, outputs.len(), |ev, idx| {
                    ev.cur_out = Some(&outputs[idx]);
                })
            }
        }
    }

    fn quant_over(
        &mut self,
        kind: QuantKind,
        body: &'a Expr,
        len: usize,
        mut bind: impl FnMut(&mut Self, usize),
    ) -> Value<'a> {
        let mut count: i128 = 0;
        let mut sum: i128 = 0;
        let mut any = false;
        let mut all = true;
        for idx in 0..len {
            if self.exhausted {
                break;
            }
            self.burn(1);
            bind(self, idx);
            let v = self.eval(body);
            match kind {
                QuantKind::Any => {
                    if v.as_bool() {
                        any = true;
                        break; // short-circuit
                    }
                }
                QuantKind::All => {
                    if !v.as_bool() {
                        all = false;
                        break; // short-circuit
                    }
                }
                QuantKind::Count => {
                    if v.as_bool() {
                        count = count.saturating_add(1);
                    }
                }
                QuantKind::Sum => {
                    sum = sum.saturating_add(v.as_int());
                }
            }
        }
        // Clear binders so a sibling expression can't accidentally see them.
        self.cur_in = None;
        self.cur_out = None;
        match kind {
            QuantKind::Any => Value::Bool(any),
            QuantKind::All => Value::Bool(all),
            QuantKind::Count => Value::Int(count),
            QuantKind::Sum => Value::Int(sum),
        }
    }

    fn attr(&mut self, root: Root, field: &str) -> Value<'a> {
        match root {
            Root::Tx => self.tx_attr(field),
            Root::Node => self.node_attr(field),
            Root::In => match self.cur_in {
                Some(i) => in_attr(i, field),
                None => Value::Bool(false), // unreachable post-typecheck
            },
            Root::Out => match self.cur_out {
                Some(o) => out_attr(o, field),
                None => Value::Bool(false),
            },
        }
    }

    fn tx_attr(&self, field: &str) -> Value<'a> {
        let tx = self.tx;
        match field {
            "version" => Value::Int(tx.version),
            "locktime" => Value::Int(tx.locktime),
            "vsize" => Value::Int(tx.vsize),
            "weight" => Value::Int(tx.weight),
            "input_count" => Value::Int(tx.input_count()),
            "output_count" => Value::Int(tx.output_count()),
            "signals_rbf" => Value::Bool(tx.signals_rbf),
            "total_witness_size" => Value::Int(tx.total_witness_size),
            "txid" => Value::Bytes(tx.txid),
            "fee" => Value::Int(tx.fee),
            "fee_rate" => Value::Int(tx.fee_rate),
            "sigops_cost" => Value::Int(tx.sigops_cost),
            "source" => Value::Enum(EnumVal::from(tx.source)),
            "from_whitelisted_peer" => Value::Bool(tx.from_whitelisted_peer),
            _ => Value::Bool(false),
        }
    }

    fn node_attr(&self, field: &str) -> Value<'a> {
        let n = self.ctx;
        match field {
            "network" => Value::Enum(EnumVal::from(n.network)),
            "height" => Value::Int(n.height),
            "min_relay_fee" => Value::Int(n.min_relay_fee),
            "dust_relay_fee" => Value::Int(n.dust_relay_fee),
            "mempool_bytes" => Value::Int(n.mempool_bytes),
            "mempool_min_fee" => Value::Int(n.mempool_min_fee),
            _ => Value::Bool(false),
        }
    }
}

fn in_attr<'a>(i: &'a InputView<'a>, field: &str) -> Value<'a> {
    match field {
        "prevout_txid" => Value::Bytes(i.prevout_txid),
        "prevout_vout" => Value::Int(i.prevout_vout),
        "sequence" => Value::Int(i.sequence),
        "script_sig" => Value::Bytes(i.script_sig),
        "witness_items" => Value::Int(i.witness_items),
        "witness_size" => Value::Int(i.witness_size),
        "max_witness_item" => Value::Int(i.max_witness_item),
        "has_annex" => Value::Bool(i.has_annex),
        "prevout_value" => Value::Int(i.prevout_value),
        "prevout_script_type" => Value::Enum(EnumVal::from(i.prevout_script_type)),
        "prevout_script" => Value::Bytes(i.prevout_script),
        "spends_coinbase" => Value::Bool(i.spends_coinbase),
        "leaf_script" => Value::Bytes(i.leaf_script),
        _ => Value::Bool(false),
    }
}

fn out_attr<'a>(o: &'a OutputView<'a>, field: &str) -> Value<'a> {
    match field {
        "value" => Value::Int(o.value),
        "script_type" => Value::Enum(EnumVal::from(o.script_type)),
        "script" => Value::Bytes(o.script),
        "op_return_size" => Value::Int(o.op_return_size),
        "is_dust" => Value::Bool(o.is_dust),
        _ => Value::Bool(false),
    }
}

fn value_eq(a: Value, b: Value) -> bool {
    match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => x == y,
        (Value::Enum(x), Value::Enum(y)) => x == y,
        _ => false,
    }
}

/// `x / 0 == 0` (total, §4.4).
fn checked_div(a: i128, b: i128) -> i128 {
    if b == 0 {
        0
    } else {
        // i128::MIN / -1 overflows; saturate.
        a.checked_div(b).unwrap_or(i128::MAX)
    }
}

/// `x % 0 == 0` (total, §4.4).
fn checked_rem(a: i128, b: i128) -> i128 {
    if b == 0 {
        0
    } else {
        a.checked_rem(b).unwrap_or(0)
    }
}

/// Naive substring scan (bounded by the fuel charged before the call).
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
