//! Hand-rolled lexer (§4.5). No dependencies; total over any input.
//!
//! Newlines are ordinary whitespace at the expression level — the policy *file*
//! layer (PR 2) handles indentation-based rule continuation on top of this.
//! `#` comments run to end of line.

use crate::error::{PolicyError, Result, Span};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// Identifier / keyword / enum literal / opcode name. Canonical text.
    Ident(String),
    /// Integer literal, already multiplied out by any unit suffix.
    Int(i128),
    /// Hex byte literal (`0x…`), decoded.
    Bytes(Vec<u8>),
    LParen,
    RParen,
    Dot,
    DotDot,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    Eof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
}

pub fn lex(src: &str) -> Result<Vec<Token>> {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut out = Vec::new();

    while i < n {
        let c = bytes[i];
        // Whitespace
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            i += 1;
            continue;
        }
        // Comment to end of line
        if c == b'#' {
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        // Multi-char punctuation first.
        let two = |a: u8, b: u8| i + 1 < n && bytes[i] == a && bytes[i + 1] == b;
        if two(b'=', b'=') {
            push(&mut out, Tok::EqEq, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'!', b'=') {
            push(&mut out, Tok::NotEq, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'<', b'=') {
            push(&mut out, Tok::Le, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'>', b'=') {
            push(&mut out, Tok::Ge, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'&', b'&') {
            push(&mut out, Tok::AndAnd, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'|', b'|') {
            push(&mut out, Tok::OrOr, start, i + 2);
            i += 2;
            continue;
        }
        if two(b'.', b'.') {
            push(&mut out, Tok::DotDot, start, i + 2);
            i += 2;
            continue;
        }
        // Single-char punctuation.
        let single = match c {
            b'(' => Some(Tok::LParen),
            b')' => Some(Tok::RParen),
            b'.' => Some(Tok::Dot),
            b'+' => Some(Tok::Plus),
            b'-' => Some(Tok::Minus),
            b'*' => Some(Tok::Star),
            b'/' => Some(Tok::Slash),
            b'%' => Some(Tok::Percent),
            b'<' => Some(Tok::Lt),
            b'>' => Some(Tok::Gt),
            b'!' => Some(Tok::Bang),
            _ => None,
        };
        if let Some(t) = single {
            push(&mut out, t, start, i + 1);
            i += 1;
            continue;
        }
        if c == b'=' {
            return Err(PolicyError::lex(
                Span::new(start, i + 1),
                "stray '='; did you mean '==' (equality)?",
            ));
        }
        // Hex literal: 0x...
        if c == b'0' && i + 1 < n && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            i += 2;
            let hstart = i;
            while i < n && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex = &src[hstart..i];
            if hex.is_empty() {
                return Err(PolicyError::lex(
                    Span::new(start, i),
                    "empty hex literal after '0x'",
                ));
            }
            if !hex.len().is_multiple_of(2) {
                return Err(PolicyError::lex(
                    Span::new(start, i),
                    "hex literal must have an even number of digits (whole bytes)",
                ));
            }
            if hex.len() > 128 {
                return Err(PolicyError::lex(
                    Span::new(start, i),
                    "hex literal too long (max 64 bytes / 128 digits)",
                ));
            }
            let mut v = Vec::with_capacity(hex.len() / 2);
            let hb = hex.as_bytes();
            for pair in hb.chunks(2) {
                v.push((hexval(pair[0]) << 4) | hexval(pair[1]));
            }
            push(&mut out, Tok::Bytes(v), start, i);
            continue;
        }
        // Decimal integer with optional unit suffix.
        if c.is_ascii_digit() {
            while i < n && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let digits = &src[start..i];
            // Optional contiguous alphabetic unit suffix.
            let ustart = i;
            while i < n && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            let unit = &src[ustart..i];
            let base: i128 = digits.parse().map_err(|_| {
                PolicyError::lex(
                    Span::new(start, ustart),
                    "integer literal out of range (i128)",
                )
            })?;
            let mult: i128 = match unit {
                "" | "sat" | "wu" => 1,
                "kb" | "kvb" => 1000,
                other => {
                    return Err(PolicyError::lex(
                        Span::new(ustart, i),
                        format!("unknown unit suffix '{other}' (expected sat, wu, kb or kvb)"),
                    ));
                }
            };
            let val = base.checked_mul(mult).ok_or_else(|| {
                PolicyError::lex(Span::new(start, i), "integer literal out of range (i128)")
            })?;
            push(&mut out, Tok::Int(val), start, i);
            continue;
        }
        // Identifier: [A-Za-z_][A-Za-z0-9_]*
        if c == b'_' || c.is_ascii_alphabetic() {
            while i < n && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            push(&mut out, Tok::Ident(src[start..i].to_string()), start, i);
            continue;
        }
        return Err(PolicyError::lex(
            Span::new(start, i + 1),
            format!("unexpected character '{}'", c as char),
        ));
    }
    out.push(Token {
        tok: Tok::Eof,
        span: Span::point(n),
    });
    Ok(out)
}

fn push(out: &mut Vec<Token>, tok: Tok, start: usize, end: usize) {
    out.push(Token {
        tok,
        span: Span::new(start, end),
    });
}

fn hexval(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
