//! The abstract syntax tree.
//!
//! Produced by the parser, validated by the typechecker, costed by the cost
//! model, and walked by the evaluator. Every node carries a [`Span`] so any
//! later phase can point a caret at it.

use crate::error::Span;
use crate::script::ScriptPattern;
use crate::value::EnumVal;

/// Attribute root: the object an attribute hangs off (§4.3). `In`/`Out` are the
/// fixed quantifier binders and are only valid inside the matching quantifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    Tx,
    Node,
    In,
    Out,
}

impl Root {
    pub fn as_str(self) -> &'static str {
        match self {
            Root::Tx => "tx",
            Root::Node => "node",
            Root::In => "in",
            Root::Out => "out",
        }
    }
}

/// Quantifier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Inputs,
    Outputs,
}

/// Quantifier kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuantKind {
    Any,
    All,
    Count,
    Sum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

/// A zero-or-one-argument method/property call on a value (§4.4). The receiver
/// is the boxed expression in [`Expr::Method`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodCall {
    /// `b.len()`
    Len,
    /// `b.starts_with(0x…)`
    StartsWith(Vec<u8>),
    /// `b.ends_with(0x…)`
    EndsWith(Vec<u8>),
    /// `b.contains(0x…)`
    Contains(Vec<u8>),
    /// `s.contains_ops(script(…))`
    ContainsOps(ScriptPattern),
    /// `s.count_op(OP_X)`
    CountOp(u8),
    /// `s.max_push` (property, no parens)
    MaxPush,
    /// `s.well_formed` (property, no parens)
    WellFormed,
}

impl MethodCall {
    pub fn name(&self) -> &'static str {
        match self {
            MethodCall::Len => "len",
            MethodCall::StartsWith(_) => "starts_with",
            MethodCall::EndsWith(_) => "ends_with",
            MethodCall::Contains(_) => "contains",
            MethodCall::ContainsOps(_) => "contains_ops",
            MethodCall::CountOp(_) => "count_op",
            MethodCall::MaxPush => "max_push",
            MethodCall::WellFormed => "well_formed",
        }
    }
}

/// An expression node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Bool(bool, Span),
    Int(i128, Span),
    Bytes(Vec<u8>, Span),
    Enum(EnumVal, Span),
    Attr {
        root: Root,
        field: String,
        span: Span,
    },
    Unary {
        op: UnOp,
        expr: Box<Expr>,
        span: Span,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        span: Span,
    },
    Method {
        recv: Box<Expr>,
        call: MethodCall,
        span: Span,
    },
    Quant {
        kind: QuantKind,
        domain: Domain,
        body: Box<Expr>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> Span {
        match self {
            Expr::Bool(_, s)
            | Expr::Int(_, s)
            | Expr::Bytes(_, s)
            | Expr::Enum(_, s)
            | Expr::Attr { span: s, .. }
            | Expr::Unary { span: s, .. }
            | Expr::Binary { span: s, .. }
            | Expr::Method { span: s, .. }
            | Expr::Quant { span: s, .. } => *s,
        }
    }
}
