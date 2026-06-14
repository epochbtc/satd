//! Recursive-descent parser (§4.5). Depth-capped (no unbounded recursion),
//! total, and span-accurate. Produces an untyped [`Expr`]; the typechecker
//! (§4.2) validates it afterwards.

use crate::ast::*;
use crate::error::{PolicyError, Result, Span};
use crate::lexer::{Tok, Token, lex};
use crate::script::{PatToken, ScriptPattern, opcode_byte};
use crate::value::enum_literal;

/// Maximum expression nesting depth. Guards against stack exhaustion from
/// pathological parenthesization; far above anything a hand-author writes.
const MAX_DEPTH: usize = 64;

/// Maximum tokens in a `script(…)` pattern (§4.4).
const MAX_PATTERN_TOKENS: usize = 32;

/// Parse a complete expression from source.
pub fn parse(src: &str) -> Result<Expr> {
    let toks = lex(src)?;
    let mut p = Parser {
        toks,
        pos: 0,
        depth: 0,
    };
    let e = p.expr()?;
    p.expect(Tok::Eof, "expected end of expression")?;
    Ok(e)
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }
    fn peek_span(&self) -> Span {
        self.toks[self.pos].span
    }
    fn bump(&mut self) -> &Token {
        let t = &self.toks[self.pos];
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn at_ident(&self, name: &str) -> bool {
        matches!(self.peek(), Tok::Ident(s) if s == name)
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t {
            self.bump();
            true
        } else {
            false
        }
    }
    fn eat_ident(&mut self, name: &str) -> bool {
        if self.at_ident(name) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: Tok, msg: &str) -> Result<()> {
        if self.peek() == &t {
            self.bump();
            Ok(())
        } else {
            Err(PolicyError::parse(
                self.peek_span(),
                format!("{msg} (found {})", describe(self.peek())),
            ))
        }
    }
    fn expect_ident(&mut self, msg: &str) -> Result<(String, Span)> {
        let span = self.peek_span();
        if let Tok::Ident(s) = self.peek() {
            let s = s.clone();
            self.bump();
            Ok((s, span))
        } else {
            Err(PolicyError::parse(
                span,
                format!("{msg} (found {})", describe(self.peek())),
            ))
        }
    }

    fn enter(&mut self, at: Span) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(PolicyError::parse(at, "expression nested too deeply"));
        }
        Ok(())
    }
    fn leave(&mut self) {
        self.depth -= 1;
    }

    // --- precedence climbing ---

    fn expr(&mut self) -> Result<Expr> {
        self.enter(self.peek_span())?;
        let r = self.or_expr();
        self.leave();
        r
    }

    fn or_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.and_expr()?;
        loop {
            if self.eat(&Tok::OrOr) || self.eat_ident("or") {
                let rhs = self.and_expr()?;
                let span = lhs.span().to(rhs.span());
                lhs = Expr::Binary {
                    op: BinOp::Or,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span,
                };
            } else {
                return Ok(lhs);
            }
        }
    }

    fn and_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.not_expr()?;
        loop {
            if self.eat(&Tok::AndAnd) || self.eat_ident("and") {
                let rhs = self.not_expr()?;
                let span = lhs.span().to(rhs.span());
                lhs = Expr::Binary {
                    op: BinOp::And,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span,
                };
            } else {
                return Ok(lhs);
            }
        }
    }

    fn not_expr(&mut self) -> Result<Expr> {
        let start = self.peek_span();
        if self.eat(&Tok::Bang) || self.eat_ident("not") {
            let inner = self.not_expr()?;
            let span = start.to(inner.span());
            Ok(Expr::Unary {
                op: UnOp::Not,
                expr: Box::new(inner),
                span,
            })
        } else {
            self.cmp_expr()
        }
    }

    fn cmp_expr(&mut self) -> Result<Expr> {
        let lhs = self.add_expr()?;
        let op = match self.peek() {
            Tok::EqEq => BinOp::Eq,
            Tok::NotEq => BinOp::Ne,
            Tok::Lt => BinOp::Lt,
            Tok::Le => BinOp::Le,
            Tok::Gt => BinOp::Gt,
            Tok::Ge => BinOp::Ge,
            _ => return Ok(lhs),
        };
        self.bump();
        let rhs = self.add_expr()?;
        let span = lhs.span().to(rhs.span());
        Ok(Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            span,
        })
    }

    fn add_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.mul_expr()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => return Ok(lhs),
            };
            self.bump();
            let rhs = self.mul_expr()?;
            let span = lhs.span().to(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
    }

    fn mul_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.postfix()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                Tok::Percent => BinOp::Mod,
                _ => return Ok(lhs),
            };
            self.bump();
            let rhs = self.postfix()?;
            let span = lhs.span().to(rhs.span());
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
    }

    fn postfix(&mut self) -> Result<Expr> {
        let mut recv = self.primary()?;
        while self.eat(&Tok::Dot) {
            let (name, name_span) =
                self.expect_ident("expected a method or property name after '.'")?;
            let call = self.method(&name, name_span)?;
            let span = recv.span().to(self.toks[self.pos.saturating_sub(1)].span);
            recv = Expr::Method {
                recv: Box::new(recv),
                call,
                span,
            };
        }
        Ok(recv)
    }

    fn primary(&mut self) -> Result<Expr> {
        let span = self.peek_span();
        match self.peek().clone() {
            Tok::LParen => {
                self.bump();
                let e = self.expr()?;
                self.expect(Tok::RParen, "expected ')'")?;
                Ok(e)
            }
            Tok::Int(v) => {
                self.bump();
                Ok(Expr::Int(v, span))
            }
            Tok::Bytes(v) => {
                self.bump();
                Ok(Expr::Bytes(v, span))
            }
            Tok::Ident(name) => self.ident_primary(&name, span),
            other => Err(PolicyError::parse(
                span,
                format!("expected an expression (found {})", describe(&other)),
            )),
        }
    }

    fn ident_primary(&mut self, name: &str, span: Span) -> Result<Expr> {
        match name {
            "true" => {
                self.bump();
                Ok(Expr::Bool(true, span))
            }
            "false" => {
                self.bump();
                Ok(Expr::Bool(false, span))
            }
            "any" | "all" | "count" | "sum" => self.quant(name, span),
            "tx" | "node" | "in" | "out" => self.attr(name, span),
            "script" => Err(PolicyError::parse(
                span,
                "script(…) is only valid as the argument to contains_ops()",
            )),
            other => {
                if let Some(ev) = enum_literal(other) {
                    self.bump();
                    Ok(Expr::Enum(ev, span))
                } else {
                    Err(PolicyError::parse(
                        span,
                        format!("unknown identifier '{other}'"),
                    ))
                }
            }
        }
    }

    fn attr(&mut self, root_name: &str, root_span: Span) -> Result<Expr> {
        let root = match root_name {
            "tx" => Root::Tx,
            "node" => Root::Node,
            "in" => Root::In,
            "out" => Root::Out,
            _ => unreachable!(),
        };
        self.bump(); // root
        self.expect(Tok::Dot, &format!("expected '.' after '{root_name}'"))?;
        let (field, field_span) = self.expect_ident("expected an attribute name")?;
        Ok(Expr::Attr {
            root,
            field,
            span: root_span.to(field_span),
        })
    }

    fn quant(&mut self, kw: &str, start: Span) -> Result<Expr> {
        let kind = match kw {
            "any" => QuantKind::Any,
            "all" => QuantKind::All,
            "count" => QuantKind::Count,
            "sum" => QuantKind::Sum,
            _ => unreachable!(),
        };
        self.bump(); // quantifier keyword
        let (dom_word, dom_span) =
            self.expect_ident("expected 'inputs' or 'outputs' after a quantifier")?;
        let domain = match dom_word.as_str() {
            "input" | "inputs" => Domain::Inputs,
            "output" | "outputs" => Domain::Outputs,
            other => {
                return Err(PolicyError::parse(
                    dom_span,
                    format!("expected 'inputs' or 'outputs', found '{other}'"),
                ));
            }
        };
        self.expect(Tok::LParen, "expected '(' after the quantifier domain")?;
        let body = self.expr()?;
        let end = self.peek_span();
        self.expect(Tok::RParen, "expected ')' to close the quantifier body")?;
        Ok(Expr::Quant {
            kind,
            domain,
            body: Box::new(body),
            span: start.to(end),
        })
    }

    fn method(&mut self, name: &str, name_span: Span) -> Result<MethodCall> {
        match name {
            "max_push" => {
                self.reject_parens(name, name_span)?;
                Ok(MethodCall::MaxPush)
            }
            "well_formed" => {
                self.reject_parens(name, name_span)?;
                Ok(MethodCall::WellFormed)
            }
            "len" => {
                self.expect(Tok::LParen, "expected '(' after len")?;
                self.expect(Tok::RParen, "len takes no arguments")?;
                Ok(MethodCall::Len)
            }
            "starts_with" | "ends_with" | "contains" => {
                self.expect(Tok::LParen, &format!("expected '(' after {name}"))?;
                let (needle, nspan) =
                    self.expect_bytes(&format!("{name} takes a hex byte literal"))?;
                check_needle(&needle, nspan)?;
                self.expect(Tok::RParen, &format!("expected ')' to close {name}(…)"))?;
                Ok(match name {
                    "starts_with" => MethodCall::StartsWith(needle),
                    "ends_with" => MethodCall::EndsWith(needle),
                    "contains" => MethodCall::Contains(needle),
                    _ => unreachable!(),
                })
            }
            "count_op" => {
                self.expect(Tok::LParen, "expected '(' after count_op")?;
                let (op, ospan) =
                    self.expect_ident("count_op takes an opcode name, e.g. OP_RETURN")?;
                let byte = opcode_byte(&op)
                    .ok_or_else(|| PolicyError::parse(ospan, format!("unknown opcode '{op}'")))?;
                self.expect(Tok::RParen, "expected ')' to close count_op(…)")?;
                Ok(MethodCall::CountOp(byte))
            }
            "contains_ops" => {
                self.expect(Tok::LParen, "expected '(' after contains_ops")?;
                let pat = self.script_pattern()?;
                self.expect(Tok::RParen, "expected ')' to close contains_ops(…)")?;
                Ok(MethodCall::ContainsOps(pat))
            }
            other => Err(PolicyError::parse(
                name_span,
                format!("unknown method '{other}'"),
            )),
        }
    }

    fn reject_parens(&mut self, name: &str, name_span: Span) -> Result<()> {
        if matches!(self.peek(), Tok::LParen) {
            return Err(PolicyError::parse(
                name_span,
                format!("'{name}' is a property, not a method — drop the parentheses"),
            ));
        }
        Ok(())
    }

    fn expect_bytes(&mut self, msg: &str) -> Result<(Vec<u8>, Span)> {
        let span = self.peek_span();
        if let Tok::Bytes(v) = self.peek() {
            let v = v.clone();
            self.bump();
            Ok((v, span))
        } else {
            Err(PolicyError::parse(
                span,
                format!("{msg} (found {})", describe(self.peek())),
            ))
        }
    }

    fn script_pattern(&mut self) -> Result<ScriptPattern> {
        let kw_span = self.peek_span();
        if !self.eat_ident("script") {
            return Err(PolicyError::parse(
                kw_span,
                "contains_ops expects a script(…) pattern as its argument",
            ));
        }
        self.expect(Tok::LParen, "expected '(' after script")?;
        let mut tokens = Vec::new();
        loop {
            if matches!(self.peek(), Tok::RParen) {
                break;
            }
            if matches!(self.peek(), Tok::Eof) {
                return Err(PolicyError::parse(
                    self.peek_span(),
                    "unterminated script(…) pattern",
                ));
            }
            let pt = self.pat_token()?;
            tokens.push(pt);
            if tokens.len() > MAX_PATTERN_TOKENS {
                return Err(PolicyError::parse(
                    self.peek_span(),
                    format!("script pattern too long (max {MAX_PATTERN_TOKENS} tokens)"),
                ));
            }
        }
        self.expect(Tok::RParen, "expected ')' to close script(…)")?;
        if tokens.is_empty() {
            return Err(PolicyError::parse(kw_span, "empty script(…) pattern"));
        }
        Ok(ScriptPattern { tokens })
    }

    fn pat_token(&mut self) -> Result<PatToken> {
        let span = self.peek_span();
        match self.peek().clone() {
            Tok::Star => {
                self.bump();
                Ok(PatToken::AnyRun)
            }
            Tok::Ident(name) if name == "_" => {
                self.bump();
                Ok(PatToken::AnyOne)
            }
            Tok::Ident(name) if name == "push" => {
                self.bump();
                if !self.eat(&Tok::LParen) {
                    return Ok(PatToken::Push);
                }
                self.push_arg()
            }
            Tok::Ident(name) => {
                self.bump();
                let byte = opcode_byte(&name)
                    .ok_or_else(|| PolicyError::parse(span, format!("unknown opcode '{name}'")))?;
                Ok(PatToken::Op(byte))
            }
            other => Err(PolicyError::parse(
                span,
                format!(
                    "unexpected token in script pattern (found {})",
                    describe(&other)
                ),
            )),
        }
    }

    /// Parse the argument of `push(...)`: `n`, `a..b`, `0x…`, or `0x…*`.
    fn push_arg(&mut self) -> Result<PatToken> {
        let span = self.peek_span();
        match self.peek().clone() {
            Tok::Int(n) => {
                self.bump();
                let n = u32_from(n, span)?;
                if self.eat(&Tok::DotDot) {
                    let bspan = self.peek_span();
                    let b = match self.peek().clone() {
                        Tok::Int(b) => {
                            self.bump();
                            u32_from(b, bspan)?
                        }
                        other => {
                            return Err(PolicyError::parse(
                                bspan,
                                format!(
                                    "expected the upper bound of push(a..b) (found {})",
                                    describe(&other)
                                ),
                            ));
                        }
                    };
                    if b < n {
                        return Err(PolicyError::parse(
                            span.to(bspan),
                            "push(a..b) requires a <= b",
                        ));
                    }
                    self.expect(Tok::RParen, "expected ')' to close push(a..b)")?;
                    Ok(PatToken::PushRange(n, b))
                } else {
                    self.expect(Tok::RParen, "expected ')' to close push(n)")?;
                    Ok(PatToken::PushLen(n))
                }
            }
            Tok::Bytes(v) => {
                self.bump();
                check_needle(&v, span)?;
                let prefix = self.eat(&Tok::Star);
                self.expect(Tok::RParen, "expected ')' to close push(0x…)")?;
                Ok(if prefix {
                    PatToken::PushPrefix(v)
                } else {
                    PatToken::PushExact(v)
                })
            }
            other => Err(PolicyError::parse(
                span,
                format!(
                    "push(...) expects a size, a..b range, or 0x… content (found {})",
                    describe(&other)
                ),
            )),
        }
    }
}

fn u32_from(v: i128, span: Span) -> Result<u32> {
    u32::try_from(v)
        .map_err(|_| PolicyError::parse(span, "push size out of range (0..=4294967295)"))
}

fn check_needle(needle: &[u8], span: Span) -> Result<()> {
    if needle.is_empty() {
        return Err(PolicyError::parse(
            span,
            "byte needle must be at least 1 byte",
        ));
    }
    if needle.len() > 64 {
        return Err(PolicyError::parse(
            span,
            "byte needle too long (max 64 bytes)",
        ));
    }
    Ok(())
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Ident(s) => format!("'{s}'"),
        Tok::Int(_) => "an integer".into(),
        Tok::Bytes(_) => "a hex literal".into(),
        Tok::Eof => "end of input".into(),
        Tok::LParen => "'('".into(),
        Tok::RParen => "')'".into(),
        Tok::Dot => "'.'".into(),
        Tok::DotDot => "'..'".into(),
        Tok::Plus => "'+'".into(),
        Tok::Minus => "'-'".into(),
        Tok::Star => "'*'".into(),
        Tok::Slash => "'/'".into(),
        Tok::Percent => "'%'".into(),
        Tok::EqEq => "'=='".into(),
        Tok::NotEq => "'!='".into(),
        Tok::Lt => "'<'".into(),
        Tok::Le => "'<='".into(),
        Tok::Gt => "'>'".into(),
        Tok::Ge => "'>='".into(),
        Tok::AndAnd => "'&&'".into(),
        Tok::OrOr => "'||'".into(),
        Tok::Bang => "'!'".into(),
    }
}
