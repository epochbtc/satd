//! Static typechecker (§4.2). Every type error is a load-time error with a
//! span. There are no implicit conversions; enums compare only within their own
//! kind. This is also where the binder rules are enforced: `in`/`out` are only
//! legal inside the matching quantifier, and quantifiers do not nest (v1).

use std::fmt;

use crate::ast::*;
use crate::error::{PolicyError, Result, Span};
use crate::value::EnumKind;

/// A static type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Bool,
    Int,
    /// `script: true` marks script-interpretable bytes (the only receivers
    /// allowed for `contains_ops`/`count_op`/`max_push`/`well_formed`).
    Bytes {
        script: bool,
    },
    Enum(EnumKind),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Bool => f.write_str("Bool"),
            Type::Int => f.write_str("Int"),
            Type::Bytes { script: true } => f.write_str("Bytes(script)"),
            Type::Bytes { script: false } => f.write_str("Bytes"),
            Type::Enum(k) => write!(f, "{}", k.name()),
        }
    }
}

/// Typecheck an expression, returning its type. The expression must stand at top
/// level (no `in`/`out` available).
pub fn typecheck(expr: &Expr) -> Result<Type> {
    check(expr, None)
}

/// Typecheck and require the result to be `Bool` (a rule's `when` / a streaming
/// filter predicate).
pub fn typecheck_bool(expr: &Expr) -> Result<()> {
    let t = typecheck(expr)?;
    if t != Type::Bool {
        return Err(PolicyError::typ(
            expr.span(),
            format!("a rule condition must be Bool, but this is {t}"),
        ));
    }
    Ok(())
}

fn check(expr: &Expr, domain: Option<Domain>) -> Result<Type> {
    match expr {
        Expr::Bool(..) => Ok(Type::Bool),
        Expr::Int(..) => Ok(Type::Int),
        Expr::Bytes(..) => Ok(Type::Bytes { script: false }),
        Expr::Enum(ev, _) => Ok(Type::Enum(ev.kind)),
        Expr::Attr { root, field, span } => attr_type(*root, field, *span, domain),
        Expr::Unary {
            op: UnOp::Not,
            expr,
            span,
        } => {
            let t = check(expr, domain)?;
            expect(t, Type::Bool, *span, "operand of 'not'")?;
            Ok(Type::Bool)
        }
        Expr::Binary { op, lhs, rhs, span } => check_binary(*op, lhs, rhs, *span, domain),
        Expr::Method { recv, call, span } => check_method(recv, call, *span, domain),
        Expr::Quant {
            kind,
            domain: dom,
            body,
            span,
        } => {
            if domain.is_some() {
                return Err(PolicyError::typ(
                    *span,
                    "quantifiers cannot be nested (v1: no quantifier inside a quantifier body)",
                ));
            }
            let body_ty = check(body, Some(*dom))?;
            match kind {
                QuantKind::Any | QuantKind::All => {
                    expect(
                        body_ty,
                        Type::Bool,
                        body.span(),
                        "a quantifier body (any/all)",
                    )?;
                    Ok(Type::Bool)
                }
                QuantKind::Count => {
                    expect(body_ty, Type::Bool, body.span(), "a count quantifier body")?;
                    Ok(Type::Int)
                }
                QuantKind::Sum => {
                    expect(body_ty, Type::Int, body.span(), "a sum quantifier body")?;
                    Ok(Type::Int)
                }
            }
        }
    }
}

fn check_binary(
    op: BinOp,
    lhs: &Expr,
    rhs: &Expr,
    span: Span,
    domain: Option<Domain>,
) -> Result<Type> {
    let lt = check(lhs, domain)?;
    let rt = check(rhs, domain)?;
    match op {
        BinOp::And | BinOp::Or => {
            expect(lt, Type::Bool, lhs.span(), "operand of a boolean operator")?;
            expect(rt, Type::Bool, rhs.span(), "operand of a boolean operator")?;
            Ok(Type::Bool)
        }
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
            expect(lt, Type::Int, lhs.span(), "operand of arithmetic")?;
            expect(rt, Type::Int, rhs.span(), "operand of arithmetic")?;
            Ok(Type::Int)
        }
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
            expect(
                lt,
                Type::Int,
                lhs.span(),
                "operand of an ordering comparison",
            )?;
            expect(
                rt,
                Type::Int,
                rhs.span(),
                "operand of an ordering comparison",
            )?;
            Ok(Type::Bool)
        }
        BinOp::Eq | BinOp::Ne => {
            if comparable(lt, rt) {
                Ok(Type::Bool)
            } else {
                Err(PolicyError::typ(
                    span,
                    format!("cannot compare {lt} with {rt}"),
                ))
            }
        }
    }
}

/// Two types are equality-comparable iff: both Int, both Bytes (script flag is
/// irrelevant for content equality), both Bool, or both the *same* enum kind.
fn comparable(a: Type, b: Type) -> bool {
    match (a, b) {
        (Type::Int, Type::Int) => true,
        (Type::Bool, Type::Bool) => true,
        (Type::Bytes { .. }, Type::Bytes { .. }) => true,
        (Type::Enum(x), Type::Enum(y)) => x == y,
        _ => false,
    }
}

fn check_method(
    recv: &Expr,
    call: &MethodCall,
    span: Span,
    domain: Option<Domain>,
) -> Result<Type> {
    let rt = check(recv, domain)?;
    let is_bytes = matches!(rt, Type::Bytes { .. });
    let is_script = matches!(rt, Type::Bytes { script: true });
    match call {
        MethodCall::Len => {
            require(is_bytes, rt, span, "len")?;
            Ok(Type::Int)
        }
        MethodCall::StartsWith(_) | MethodCall::EndsWith(_) | MethodCall::Contains(_) => {
            require(is_bytes, rt, span, call.name())?;
            Ok(Type::Bool)
        }
        MethodCall::ContainsOps(_) | MethodCall::WellFormed => {
            require_script(is_script, rt, span, call.name())?;
            Ok(Type::Bool)
        }
        MethodCall::CountOp(_) | MethodCall::MaxPush => {
            require_script(is_script, rt, span, call.name())?;
            Ok(Type::Int)
        }
    }
}

fn require(ok: bool, got: Type, span: Span, what: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(PolicyError::typ(
            span,
            format!("'{what}' applies to Bytes, but the receiver is {got}"),
        ))
    }
}

fn require_script(ok: bool, got: Type, span: Span, what: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(PolicyError::typ(
            span,
            format!(
                "'{what}' applies only to script-typed bytes \
                 (out.script, in.script_sig, in.leaf_script, in.prevout_script), but the receiver is {got}"
            ),
        ))
    }
}

fn expect(got: Type, want: Type, span: Span, what: &str) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(PolicyError::typ(
            span,
            format!("{what} must be {want}, but this is {got}"),
        ))
    }
}

/// The attribute table (§4.3, version 1 — Tier-2 attributes excluded).
fn attr_type(root: Root, field: &str, span: Span, domain: Option<Domain>) -> Result<Type> {
    let flat = Type::Bytes { script: false };
    let script = Type::Bytes { script: true };
    use EnumKind::*;
    use Type::*;

    // Binder availability first, so the error names the real problem.
    match root {
        Root::In if domain != Some(Domain::Inputs) => {
            return Err(PolicyError::typ(
                span,
                "'in' is only available inside an input quantifier, e.g. any inputs ( in.… )",
            ));
        }
        Root::Out if domain != Some(Domain::Outputs) => {
            return Err(PolicyError::typ(
                span,
                "'out' is only available inside an output quantifier, e.g. any outputs ( out.… )",
            ));
        }
        _ => {}
    }

    let ty = match (root, field) {
        // tx.* (context-free + prevout-derived + submission context)
        (Root::Tx, "version") => Int,
        (Root::Tx, "locktime") => Int,
        (Root::Tx, "vsize") => Int,
        (Root::Tx, "weight") => Int,
        (Root::Tx, "input_count") => Int,
        (Root::Tx, "output_count") => Int,
        (Root::Tx, "signals_rbf") => Bool,
        (Root::Tx, "total_witness_size") => Int,
        (Root::Tx, "txid") => flat,
        (Root::Tx, "fee") => Int,
        (Root::Tx, "fee_rate") => Int,
        (Root::Tx, "sigops_cost") => Int,
        (Root::Tx, "source") => Enum(Source),
        (Root::Tx, "from_whitelisted_peer") => Bool,
        // node.*
        (Root::Node, "network") => Enum(Network),
        (Root::Node, "height") => Int,
        (Root::Node, "min_relay_fee") => Int,
        (Root::Node, "dust_relay_fee") => Int,
        (Root::Node, "mempool_bytes") => Int,
        (Root::Node, "mempool_min_fee") => Int,
        // out.*
        (Root::Out, "value") => Int,
        (Root::Out, "script_type") => Enum(ScriptType),
        (Root::Out, "script") => script,
        (Root::Out, "op_return_size") => Int,
        (Root::Out, "is_dust") => Bool,
        // in.*
        (Root::In, "prevout_txid") => flat,
        (Root::In, "prevout_vout") => Int,
        (Root::In, "sequence") => Int,
        (Root::In, "script_sig") => script,
        (Root::In, "witness_items") => Int,
        (Root::In, "witness_size") => Int,
        (Root::In, "max_witness_item") => Int,
        (Root::In, "has_annex") => Bool,
        (Root::In, "prevout_value") => Int,
        (Root::In, "prevout_script_type") => Enum(ScriptType),
        (Root::In, "prevout_script") => script,
        (Root::In, "spends_coinbase") => Bool,
        (Root::In, "leaf_script") => script,
        (r, f) => {
            return Err(PolicyError::typ(
                span,
                format!("unknown attribute '{}.{f}'", r.as_str()),
            ));
        }
    };
    Ok(ty)
}
