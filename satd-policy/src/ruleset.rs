//! The policy-file layer (§5): version declaration, `quarantine`/`allow` rules
//! with optional `on` scopes, indentation-based continuation, strict loading,
//! auto-naming, the version gate, and the first-match evaluation engine.
//!
//! One grammar end-to-end: a rule's `when` condition is the very expression
//! language of the rest of the crate, compiled by [`crate::compile_bool`]. This
//! layer only adds the rule wrapper around it.
//!
//! Loading is strict (no warn-and-continue): unknown keywords, unknown
//! attributes/enums, type errors, duplicate names, needle-length and
//! cost-budget violations are all load errors with a file/line/column span.

use std::collections::HashSet;

use bitcoin::hashes::{Hash, sha256};

use crate::cost::{Cost, POLICY_BUDGET};
use crate::error::{PolicyError, Result, Span};
use crate::eval::DEFAULT_FUEL;
use crate::scope::ScopeSet;
use crate::verdict::Verdict;
use crate::view::{Ctx, TxView};
use crate::{CompiledExpr, compile_bool};

/// The only policy-file version this build accepts. Tier-2 byte transforms will
/// bump this to 2 as a fast-follow (design §5, §13).
pub const SUPPORTED_VERSION: u32 = 1;

/// Maximum length of a rule name.
const MAX_NAME_LEN: usize = 64;

/// Words that may not be used as a rule name.
const RESERVED: &[&str] = &[
    "version",
    "quarantine",
    "allow",
    "when",
    "on",
    "relay",
    "template",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Quarantine,
    Allow,
}

/// A single compiled rule.
#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    /// Scope of a `quarantine` rule (ignored for `allow`).
    pub scope: ScopeSet,
    /// True if the name was auto-generated rather than written by the operator.
    pub auto_named: bool,
    cond: CompiledExpr,
}

impl Rule {
    pub fn condition(&self) -> &CompiledExpr {
        &self.cond
    }
}

/// A parsed, typechecked, cost-bounded policy file.
#[derive(Debug)]
pub struct CompiledRuleset {
    version: u32,
    rules: Vec<Rule>,
    total_cost: Cost,
    has_allow: bool,
}

impl CompiledRuleset {
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    pub fn total_cost(&self) -> Cost {
        self.total_cost
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    /// Whether any `allow` rule is present. The node uses this to skip the
    /// deferred-standardness machinery entirely when there are none (§7).
    pub fn has_allow(&self) -> bool {
        self.has_allow
    }

    /// Evaluate the ruleset against a transaction, first-match-wins (§5). One
    /// fuel budget is shared across the whole pass; exhaustion yields the
    /// fail-safe full-scope quarantine ([`Verdict::fuel`]).
    pub fn evaluate<'a>(&'a self, tx: &'a TxView<'a>, ctx: &Ctx) -> Verdict {
        let mut fuel = DEFAULT_FUEL;
        for rule in &self.rules {
            let out = rule.cond.eval_metered(tx, ctx, fuel);
            if out.fuel_exhausted {
                return Verdict::fuel();
            }
            fuel = out.fuel_remaining;
            if out.value.as_bool() {
                return match rule.action {
                    Action::Quarantine => Verdict::Quarantine {
                        rule: rule.name.clone(),
                        scope: rule.scope,
                    },
                    Action::Allow => Verdict::Allow {
                        rule: rule.name.clone(),
                    },
                };
            }
        }
        Verdict::Pass
    }
}

/// Parse and compile a policy file.
pub fn parse_ruleset(src: &str) -> Result<CompiledRuleset> {
    let lines = classify_lines(src);
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.kind == LineKind::Start)
        .map(|(i, _)| i)
        .collect();

    if starts.is_empty() {
        return Err(PolicyError::ruleset(
            Span::point(0),
            "policy file must begin with a version declaration (e.g. `version 1`)",
        ));
    }

    // Byte span of each structural unit: [this start line's begin, next start
    // line's begin) — includes indented continuations and interspersed comments.
    let unit_span = |k: usize| -> (usize, usize) {
        let begin = lines[starts[k]].start;
        let end = if k + 1 < starts.len() {
            lines[starts[k + 1]].start
        } else {
            src.len()
        };
        (begin, end)
    };

    // First unit: the version declaration.
    let (vb, ve) = unit_span(0);
    let version = parse_version(src, vb, ve)?;

    let mut rules = Vec::new();
    let mut names: HashSet<String> = HashSet::new();
    let mut total = Cost::default();
    let mut has_allow = false;

    for k in 1..starts.len() {
        let (b, e) = unit_span(k);
        let rule = parse_rule(src, b, e, &mut names)?;
        total = Cost {
            flat: total.flat.saturating_add(rule.cond.cost().flat),
            scan: total.scan.saturating_add(rule.cond.cost().scan),
        };
        if total.total() > POLICY_BUDGET {
            return Err(PolicyError::cost(
                Span::new(b, e.min(b + 1)),
                format!(
                    "ruleset exceeds the policy cost budget ({} > {POLICY_BUDGET}) at this rule",
                    total.total()
                ),
            ));
        }
        if rule.action == Action::Allow {
            has_allow = true;
        }
        rules.push(rule);
    }

    Ok(CompiledRuleset {
        version,
        rules,
        total_cost: total,
        has_allow,
    })
}

// --- line classification ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineKind {
    /// Blank or comment-only — ignorable for structure.
    Skip,
    /// Indented content — continues the previous rule.
    Continuation,
    /// Unindented content — begins a version decl or a rule.
    Start,
}

struct LineInfo {
    start: usize,
    kind: LineKind,
}

fn classify_lines(src: &str) -> Vec<LineInfo> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    for line in src.split_inclusive('\n') {
        let start = pos;
        pos += line.len();
        let text = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = text.trim_start();
        let content = trimmed.trim_end();
        let kind = if content.is_empty() || content.starts_with('#') {
            LineKind::Skip
        } else if trimmed.len() != text.len() {
            LineKind::Continuation
        } else {
            LineKind::Start
        };
        out.push(LineInfo { start, kind });
    }
    out
}

// --- version declaration ---

fn parse_version(src: &str, b: usize, e: usize) -> Result<u32> {
    let words = words_with_spans(src, b, e);
    if words.is_empty() || words[0].0 != "version" {
        let at = words.first().map(|w| w.1).unwrap_or(Span::point(b));
        return Err(PolicyError::ruleset(
            at,
            "policy file must begin with a version declaration (e.g. `version 1`)",
        ));
    }
    if words.len() < 2 {
        return Err(PolicyError::ruleset(
            words[0].1,
            "expected a version number after `version`",
        ));
    }
    if words.len() > 2 {
        return Err(PolicyError::ruleset(
            words[2].1,
            "unexpected text after the version declaration",
        ));
    }
    let n: u32 = words[1]
        .0
        .parse()
        .map_err(|_| PolicyError::ruleset(words[1].1, "version must be a non-negative integer"))?;
    if n != SUPPORTED_VERSION {
        return Err(PolicyError::ruleset(
            words[1].1,
            format!(
                "unsupported policy version {n}; this build supports version {SUPPORTED_VERSION}"
            ),
        ));
    }
    Ok(n)
}

// --- a single rule ---

fn parse_rule(src: &str, b: usize, e: usize, names: &mut HashSet<String>) -> Result<Rule> {
    let words = words_with_spans(src, b, e);
    // words is guaranteed non-empty: a Start line has content.
    let (action_word, action_span) = (&words[0].0, words[0].1);
    let action = match action_word.as_str() {
        "quarantine" => Action::Quarantine,
        "allow" => Action::Allow,
        other => {
            return Err(PolicyError::ruleset(
                action_span,
                format!("a rule must start with `quarantine` or `allow` (found `{other}`)"),
            ));
        }
    };

    // Locate the `when` separator (the first such word after the action). The
    // expression grammar never contains the word `when`, so this is unambiguous.
    let when_idx = words[1..]
        .iter()
        .position(|(w, _)| w == "when")
        .map(|i| i + 1)
        .ok_or_else(|| PolicyError::ruleset(action_span, "rule is missing its `when` condition"))?;
    let when_span = words[when_idx].1;
    let middle = &words[1..when_idx];

    // Parse optional [name] [on scopes].
    let mut idx = 0usize;
    let mut explicit_name: Option<(String, Span)> = None;
    if idx < middle.len() && middle[idx].0 != "on" {
        explicit_name = Some((middle[idx].0.clone(), middle[idx].1));
        idx += 1;
    }
    let mut scope = ScopeSet::all();
    if idx < middle.len() {
        let (w, sp) = &middle[idx];
        if w != "on" {
            return Err(PolicyError::ruleset(
                *sp,
                format!("expected `on` or `when` (found `{w}`)"),
            ));
        }
        if action == Action::Allow {
            return Err(PolicyError::ruleset(
                *sp,
                "`allow` rules do not take an `on` scope (allow has no scope)",
            ));
        }
        let fallback = Span::new(sp.end, when_span.start.max(sp.end + 1));
        scope = parse_scopes(&middle[idx + 1..], fallback)?;
        idx = middle.len();
    }
    if idx != middle.len() {
        return Err(PolicyError::ruleset(
            middle[idx].1,
            "unexpected text in the rule header",
        ));
    }

    // Compile the expression: a contiguous slice from just after `when` to the
    // end of this unit. Spans from the sub-compile are offset back to the file.
    let expr_start = when_span.end;
    let expr_src = &src[expr_start..e];
    let cond = compile_bool(expr_src).map_err(|err| err.offset(expr_start))?;

    // Name: explicit (validated) or auto-derived from the normalized rule text.
    let (name, auto_named) = match explicit_name {
        Some((n, sp)) => {
            validate_name(&n, sp)?;
            (n, false)
        }
        None => (auto_name(&words), true),
    };
    if !names.insert(name.clone()) {
        let at = explicit_name_span(&words, when_idx).unwrap_or(action_span);
        return Err(PolicyError::ruleset(
            at,
            format!("duplicate rule name `{name}`"),
        ));
    }

    Ok(Rule {
        name,
        action,
        scope,
        auto_named,
        cond,
    })
}

fn explicit_name_span(words: &[(String, Span)], when_idx: usize) -> Option<Span> {
    // The name, if present, is the word right after the action and before `on`.
    if when_idx > 1 && words[1].0 != "on" {
        Some(words[1].1)
    } else {
        None
    }
}

fn validate_name(name: &str, span: Span) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(PolicyError::ruleset(
            span,
            format!("rule name must be 1..={MAX_NAME_LEN} characters"),
        ));
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(PolicyError::ruleset(
            span,
            "rule name must be lowercase letters, digits, or hyphens",
        ));
    }
    if RESERVED.contains(&name) {
        return Err(PolicyError::ruleset(
            span,
            format!("`{name}` is a reserved keyword, not a valid rule name"),
        ));
    }
    Ok(())
}

/// Auto-name: `r-` + first 4 bytes (8 hex) of SHA-256 over the rule's
/// whitespace-and-comment-normalized text. Renaming-by-editing is therefore
/// visible; reformatting and comment edits are not.
fn auto_name(words: &[(String, Span)]) -> String {
    let normalized = words
        .iter()
        .map(|(w, _)| w.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let h = sha256::Hash::hash(normalized.as_bytes());
    let b = h.to_byte_array();
    format!("r-{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}

/// Parse the scope list from the (comment-stripped) words between `on` and
/// `when`. Each word may itself carry commas (`relay,template`). Empty pieces
/// from a trailing comma are tolerated; unknown scopes are rejected.
fn parse_scopes(words: &[(String, Span)], fallback: Span) -> Result<ScopeSet> {
    let mut scope = ScopeSet::empty();
    let mut any = false;
    for (w, sp) in words {
        for part in w.split(',') {
            if part.is_empty() {
                continue;
            }
            match part {
                "relay" => scope.relay = true,
                "template" => scope.template = true,
                other => {
                    return Err(PolicyError::ruleset(
                        *sp,
                        format!("unknown scope `{other}` (expected `relay` or `template`)"),
                    ));
                }
            }
            any = true;
        }
    }
    if !any {
        return Err(PolicyError::ruleset(fallback, "expected scopes after `on`"));
    }
    Ok(scope)
}

/// Scan `src[b..e]` into whitespace-delimited words with absolute spans,
/// skipping `#`-to-end-of-line comments.
fn words_with_spans(src: &str, b: usize, e: usize) -> Vec<(String, Span)> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = b;
    while i < e {
        let c = bytes[i];
        if c == b'#' {
            while i < e && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < e && !bytes[i].is_ascii_whitespace() && bytes[i] != b'#' {
            i += 1;
        }
        out.push((src[start..i].to_string(), Span::new(start, i)));
    }
    out
}
