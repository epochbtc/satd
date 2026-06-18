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
        // Each chain link deepens the *left spine* of the AST by one. The parse
        // loop itself is iterative (no parser-stack growth), but typeck/cost/eval
        // — and even `Drop` of the boxed tree — recurse structurally, so a long
        // `a or a or …` run would overflow the native stack. Charge each link
        // against the shared depth budget and unwind it on success so sibling
        // chains start fresh. (On error we abort the whole parse, so leftover
        // depth is irrelevant.)
        let mut links = 0usize;
        loop {
            if self.eat(&Tok::OrOr) || self.eat_ident("or") {
                self.enter(self.peek_span())?;
                links += 1;
                let rhs = self.and_expr()?;
                let span = lhs.span().to(rhs.span());
                lhs = Expr::Binary {
                    op: BinOp::Or,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span,
                };
            } else {
                break;
            }
        }
        for _ in 0..links {
            self.leave();
        }
        Ok(lhs)
    }

    fn and_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.not_expr()?;
        // See `or_expr`: charge each chain link so a long `a and a and …` run
        // can't build a stack-overflowing left spine.
        let mut links = 0usize;
        loop {
            if self.eat(&Tok::AndAnd) || self.eat_ident("and") {
                self.enter(self.peek_span())?;
                links += 1;
                let rhs = self.not_expr()?;
                let span = lhs.span().to(rhs.span());
                lhs = Expr::Binary {
                    op: BinOp::And,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span,
                };
            } else {
                break;
            }
        }
        for _ in 0..links {
            self.leave();
        }
        Ok(lhs)
    }

    fn not_expr(&mut self) -> Result<Expr> {
        let start = self.peek_span();
        if self.eat(&Tok::Bang) || self.eat_ident("not") {
            // `not`/`!` self-recurses without passing back through `expr()`, so it
            // must account for nesting depth itself; otherwise a long run of
            // unary operators (`not not not …`) recurses unbounded and overflows
            // the stack regardless of MAX_DEPTH.
            self.enter(start)?;
            let inner = self.not_expr();
            self.leave();
            let inner = inner?;
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
        // See `or_expr`: charge each chain link so a long `a + a + …` run can't
        // build a stack-overflowing left spine.
        let mut links = 0usize;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => break,
            };
            self.enter(self.peek_span())?;
            links += 1;
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
        for _ in 0..links {
            self.leave();
        }
        Ok(lhs)
    }

    fn mul_expr(&mut self) -> Result<Expr> {
        let mut lhs = self.postfix()?;
        // See `or_expr`: charge each chain link so a long `a * a * …` run can't
        // build a stack-overflowing left spine.
        let mut links = 0usize;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                Tok::Percent => BinOp::Mod,
                _ => break,
            };
            self.enter(self.peek_span())?;
            links += 1;
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
        for _ in 0..links {
            self.leave();
        }
        Ok(lhs)
    }

    fn postfix(&mut self) -> Result<Expr> {
        let mut recv = self.primary()?;
        // Each `.method`/`.prop` link wraps another `Expr::Method` around the
        // receiver, deepening the AST by one. The parse loop is iterative, but
        // typeck/cost/eval — and even `Drop` of the boxed tree — recurse
        // structurally, so a paren-free property chain (e.g.
        // `out.script.max_push.max_push…`) would build a stack-overflowing
        // spine. Charge each link against the shared depth budget exactly as
        // the binary productions do (see `or_expr`) and unwind on success so
        // sibling chains start fresh. (On error the whole parse aborts, so
        // leftover depth is irrelevant.)
        let mut links = 0usize;
        while self.eat(&Tok::Dot) {
            self.enter(self.peek_span())?;
            links += 1;
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
        for _ in 0..links {
            self.leave();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Stage;

    // Regression: `not`/`!` self-recurse without passing back through `expr()`,
    // so without their own depth accounting a long unary run overflows the stack
    // regardless of MAX_DEPTH. These must return a bounded parse error.
    #[test]
    fn deep_not_chain_is_bounded() {
        let src = format!("{}true", "not ".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    #[test]
    fn deep_bang_chain_is_bounded() {
        let src = format!("{}true", "!".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    #[test]
    fn deep_parens_are_bounded() {
        let src = format!("{}true{}", "(".repeat(50_000), ")".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
    }

    // Regression: the binary-operator productions (`or`/`and`/`+`/`*`) are
    // parsed iteratively into deep left-leaning trees. Without per-link depth
    // accounting, a long flat chain builds an AST that overflows the native
    // stack when typeck/cost/eval (or `Drop`) recurse over it — even though the
    // parse loop itself never recurses. These must return a bounded parse error.
    #[test]
    fn deep_or_chain_is_bounded() {
        let src = format!("true{}", " or true".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    #[test]
    fn deep_and_chain_is_bounded() {
        let src = format!("true{}", " and true".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    #[test]
    fn deep_add_chain_is_bounded() {
        let src = format!("1{}", " + 1".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    #[test]
    fn deep_mul_chain_is_bounded() {
        let src = format!("1{}", " * 1".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    // Regression: paren-free method/property chains (`a.max_push.max_push…`)
    // are parsed iteratively in `postfix`, but each link nests another
    // `Expr::Method`, so without per-link depth accounting a long chain builds
    // an AST that overflows the native stack when typeck/cost/eval (or `Drop`)
    // recurse over it — the parse itself survives, then the deep tree aborts
    // the process. This must return a bounded parse error.
    #[test]
    fn deep_method_chain_is_bounded() {
        let src = format!("out.script{}", ".max_push".repeat(50_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err.stage, Stage::Parse);
        assert!(err.message.contains("nested too deeply"), "{}", err.message);
    }

    // Sibling chains must each start from a fresh depth budget — the unwind in
    // each binary production prevents one chain's links from leaking into the
    // next. A modest disjunction of modest conjunctions must still parse.
    #[test]
    fn sibling_chains_do_not_share_depth() {
        let clause = (0..20)
            .map(|i| format!("{} == {}", i, i))
            .collect::<Vec<_>>()
            .join(" and ");
        let src = (0..20)
            .map(|_| format!("({clause})"))
            .collect::<Vec<_>>()
            .join(" or ");
        assert!(parse(&src).is_ok(), "modest nested chains should parse");
    }
}
