//! Errors and source spans.
//!
//! Every load-time failure (lex, parse, typecheck, cost-budget) carries a
//! [`Span`] into the original source so callers can render a caret pointing at
//! the offending token. Error quality is a feature here, not polish: the
//! design's audience is humans hand-authoring policy files (D5), so diagnostics
//! must always be able to point exactly at what went wrong.

use std::fmt;

/// A half-open byte range `[start, end)` into the source string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    /// A zero-width span at `pos` (used for "unexpected end of input").
    pub fn point(pos: usize) -> Self {
        Span {
            start: pos,
            end: pos,
        }
    }

    /// Smallest span covering both `self` and `other`.
    pub fn to(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// The stage that produced an error — useful for metrics and for testing that a
/// given malformed input fails at the expected phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Lex,
    Parse,
    Type,
    Cost,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Stage::Lex => "lex error",
            Stage::Parse => "parse error",
            Stage::Type => "type error",
            Stage::Cost => "cost error",
        };
        f.write_str(s)
    }
}

/// A compilation error with a message and the source span it refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub stage: Stage,
    pub message: String,
    pub span: Span,
}

impl PolicyError {
    pub fn new(stage: Stage, span: Span, message: impl Into<String>) -> Self {
        PolicyError {
            stage,
            message: message.into(),
            span,
        }
    }

    pub fn lex(span: Span, message: impl Into<String>) -> Self {
        Self::new(Stage::Lex, span, message)
    }
    pub fn parse(span: Span, message: impl Into<String>) -> Self {
        Self::new(Stage::Parse, span, message)
    }
    pub fn typ(span: Span, message: impl Into<String>) -> Self {
        Self::new(Stage::Type, span, message)
    }
    pub fn cost(span: Span, message: impl Into<String>) -> Self {
        Self::new(Stage::Cost, span, message)
    }

    /// Render a multi-line diagnostic against the original `source`, with a
    /// caret span underlining the offending token:
    ///
    /// ```text
    /// type error at line 2, column 14: expected Bool, found Int
    ///   2 | quarantine when tx.fee_rate + 1
    ///      |             ^^^^^^^^^^^^^^^^^^
    /// ```
    pub fn render(&self, source: &str) -> String {
        let (line_no, col_no, line_text, line_start) = locate(source, self.span.start);
        let caret_len = self
            .span
            .end
            .saturating_sub(self.span.start)
            .max(1)
            // Don't run the caret past the end of the displayed line.
            .min(
                line_text
                    .len()
                    .saturating_sub(self.span.start - line_start)
                    .max(1),
            );
        let pad = " ".repeat(col_no.saturating_sub(1));
        let carets = "^".repeat(caret_len);
        let gutter = format!("{line_no}");
        let gw = gutter.len();
        format!(
            "{stage} at line {line_no}, column {col_no}: {msg}\n\
             {blank} |\n\
             {gutter} | {line_text}\n\
             {blank} | {pad}{carets}",
            stage = self.stage,
            msg = self.message,
            blank = " ".repeat(gw),
        )
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.message)
    }
}

impl std::error::Error for PolicyError {}

/// Map a byte offset to (1-based line, 1-based column, that line's text, line
/// start offset).
fn locate(source: &str, offset: usize) -> (usize, usize, &str, usize) {
    let offset = offset.min(source.len());
    let mut line_start = 0usize;
    let mut line_no = 1usize;
    for (i, b) in source.bytes().enumerate() {
        if i >= offset {
            break;
        }
        if b == b'\n' {
            line_no += 1;
            line_start = i + 1;
        }
    }
    let line_end = source[line_start..]
        .find('\n')
        .map(|p| line_start + p)
        .unwrap_or(source.len());
    let col_no = offset - line_start + 1;
    (line_no, col_no, &source[line_start..line_end], line_start)
}

pub type Result<T> = std::result::Result<T, PolicyError>;
