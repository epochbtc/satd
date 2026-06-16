//! satd transaction-filtering policy language — the **expression core** (§4 of
//! the design).
//!
//! This crate is a total, statically typed, non-Turing-complete expression
//! language over a fixed view of a Bitcoin transaction and the node's context.
//! It is the reusable engine behind three surfaces — admission policy, block-
//! template policy, and streaming subscription filters — and intentionally
//! contains **no node integration**: it parses, typechecks, statically costs,
//! and evaluates an expression against a borrowed [`view::TxView`] /
//! [`view::Ctx`] that the node fills in elsewhere.
//!
//! Pipeline: [`parse`](parser::parse) → [`typecheck`](typeck::typecheck) →
//! [`cost`](cost::cost) → [`eval`](eval::eval). [`compile`] runs the first three
//! and hands back a [`CompiledExpr`] ready to evaluate.
//!
//! Invariants this crate is responsible for:
//! - **I4 (totality/determinism):** `eval` returns a [`value::Value`], never a
//!   `Result`; every operator is defined on every input of its type.
//! - **I5 (static cost bound):** [`CompiledExpr`] carries a worst-case
//!   [`cost::Cost`]; the loader rejects anything over [`cost::POLICY_BUDGET`].
//!
//! Scope note: this is **version 1**. The Tier-2 byte transforms
//! (`rc4`/`sha256`/`reverse` + `tx.first_input_txid`/`out.op_return_data`) are a
//! deliberate `version 2` fast-follow (design §13) and are not implemented here.

pub mod ast;
pub mod cost;
pub mod error;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod ruleset;
pub mod scope;
pub mod script;
pub mod typeck;
pub mod value;
pub mod verdict;
pub mod view;

pub use cost::{Cost, POLICY_BUDGET};
pub use error::{PolicyError, Result, Span, Stage};
pub use eval::{DEFAULT_FUEL, Outcome};
pub use ruleset::{Action, CompiledRuleset, Rule, SUPPORTED_VERSION, parse_ruleset};
pub use scope::ScopeSet;
pub use typeck::Type;
pub use value::{EnumKind, EnumVal, Network, ScriptType, Source, Value};
pub use verdict::Verdict;
pub use view::{Ctx, InputView, OutputView, TxView};

use ast::Expr;

/// A parsed, typechecked, cost-bounded expression, ready to evaluate.
#[derive(Clone, Debug)]
pub struct CompiledExpr {
    ast: Expr,
    ty: Type,
    cost: Cost,
}

impl CompiledExpr {
    /// The expression's static type.
    pub fn ty(&self) -> Type {
        self.ty
    }
    /// The expression's worst-case static cost (I5).
    pub fn cost(&self) -> Cost {
        self.cost
    }
    /// Borrow the underlying AST (for tooling: `policylint`, `--explain`).
    pub fn ast(&self) -> &Expr {
        &self.ast
    }

    /// Evaluate against a transaction/context view with [`DEFAULT_FUEL`].
    ///
    /// The compiled expression must outlive the view (`&'a self`): byte literals
    /// in the AST are returned as borrowed [`Value::Bytes`], so they share the
    /// view's lifetime. In the node this holds trivially — the ruleset is
    /// long-lived (ArcSwap), the per-transaction view is short-lived.
    pub fn eval<'a>(&'a self, tx: &'a TxView<'a>, ctx: &Ctx) -> Outcome<'a> {
        eval::eval(&self.ast, tx, ctx)
    }

    /// Evaluate with an explicit fuel budget (testing / calibration).
    pub fn eval_metered<'a>(&'a self, tx: &'a TxView<'a>, ctx: &Ctx, fuel: i64) -> Outcome<'a> {
        eval::eval_metered(&self.ast, tx, ctx, fuel)
    }
}

/// Compile a source expression of any type: parse, typecheck, and bound its
/// cost. Returns the typed, costed expression.
pub fn compile(src: &str) -> Result<CompiledExpr> {
    let ast = parser::parse(src)?;
    let ty = typeck::typecheck(&ast)?;
    finish(ast, ty)
}

/// Compile a source expression that must be `Bool` — the shape a rule condition
/// or a streaming filter predicate requires.
pub fn compile_bool(src: &str) -> Result<CompiledExpr> {
    let ast = parser::parse(src)?;
    typeck::typecheck_bool(&ast)?;
    finish(ast, Type::Bool)
}

fn finish(ast: Expr, ty: Type) -> Result<CompiledExpr> {
    let cost = cost::cost(&ast);
    if !cost.within_budget() {
        return Err(PolicyError::cost(
            ast.span(),
            format!(
                "expression exceeds the policy cost budget ({} > {POLICY_BUDGET})",
                cost.total()
            ),
        ));
    }
    Ok(CompiledExpr { ast, ty, cost })
}
