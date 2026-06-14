//! Script tokenization and the `script(…)` pattern matcher (§4.4).
//!
//! Script-typed bytes (`out.script`, `in.script_sig`, `in.leaf_script`,
//! `in.prevout_script`) are interpreted as a stream of opcode / push tokens.
//! Matching against a `script(…)` pattern is a **non-backtracking token glob**
//! (worst case O(tokens × pattern_tokens), both bounded), so it is encoding-proof
//! (pushdata re-encoding cannot dodge it) and position-safe (it never matches
//! marker bytes that merely appear *inside* some other push).

use std::collections::HashMap;
use std::sync::OnceLock;

/// One token of a tokenized script: the leading opcode byte, plus the pushed
/// data for the data-push opcodes (`OP_PUSHBYTES_*`, `OP_PUSHDATA{1,2,4}`).
/// Plain opcodes — including the numeric pushes `OP_0`/`OP_1..16`/`OP_1NEGATE`,
/// which push a value via a single opcode rather than a data push — carry
/// `data: None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptToken<'a> {
    pub op: u8,
    pub data: Option<&'a [u8]>,
}

/// Result of tokenizing a script.
pub struct Tokenized<'a> {
    pub tokens: Vec<ScriptToken<'a>>,
    /// True iff tokenization consumed the script exactly — no truncated final
    /// push and no leftover bytes. Backs `s.well_formed` (§4.4).
    pub well_formed: bool,
}

/// Tokenize a raw script. A push that declares more bytes than remain ends the
/// token stream (§4.4) and sets `well_formed = false`; the truncated push is not
/// emitted.
pub fn tokenize(script: &[u8]) -> Tokenized<'_> {
    let mut tokens = Vec::new();
    let mut i = 0usize;
    let n = script.len();
    let mut well_formed = true;
    while i < n {
        let op = script[i];
        i += 1;
        let take = match op {
            0x01..=0x4b => op as usize,
            0x4c => {
                // OP_PUSHDATA1
                if i + 1 > n {
                    well_formed = false;
                    break;
                }
                let l = script[i] as usize;
                i += 1;
                l
            }
            0x4d => {
                // OP_PUSHDATA2
                if i + 2 > n {
                    well_formed = false;
                    break;
                }
                let l = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                l
            }
            0x4e => {
                // OP_PUSHDATA4
                if i + 4 > n {
                    well_formed = false;
                    break;
                }
                let l = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                    as usize;
                i += 4;
                l
            }
            _ => {
                // Plain opcode (incl. OP_0/OP_1..16/OP_1NEGATE numeric pushes).
                tokens.push(ScriptToken { op, data: None });
                continue;
            }
        };
        if i + take > n {
            // Declared push runs past the end: truncated, stream ends here.
            well_formed = false;
            break;
        }
        tokens.push(ScriptToken {
            op,
            data: Some(&script[i..i + take]),
        });
        i += take;
    }
    Tokenized {
        tokens,
        well_formed,
    }
}

/// Largest data push in `tokens`, in bytes (0 if there are no data pushes).
/// Backs `s.max_push`.
pub fn max_push(tokens: &[ScriptToken]) -> i128 {
    tokens
        .iter()
        .filter_map(|t| t.data.map(|d| d.len() as i128))
        .max()
        .unwrap_or(0)
}

/// Count tokens whose leading opcode equals `op`. Backs `s.count_op(OP_X)`.
pub fn count_op(tokens: &[ScriptToken], op: u8) -> i128 {
    tokens.iter().filter(|t| t.op == op).count() as i128
}

// --- pattern types ---

/// One element of a compiled `script(…)` pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatToken {
    /// A named opcode — matches any token whose leading opcode byte equals this.
    Op(u8),
    /// `push` — any data push.
    Push,
    /// `push(n)` — a data push of exactly `n` bytes.
    PushLen(u32),
    /// `push(a..b)` — a data push whose length is in `a..=b` (both inclusive).
    PushRange(u32, u32),
    /// `push(0x…)` — a data push whose content equals the needle exactly.
    PushExact(Vec<u8>),
    /// `push(0x…*)` — a data push whose content *starts with* the needle.
    PushPrefix(Vec<u8>),
    /// `_` — any single token.
    AnyOne,
    /// `*` — any run of tokens (zero or more).
    AnyRun,
}

/// A compiled `script(…)` pattern (the user-written token sequence, ≤ 32 tokens).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptPattern {
    pub tokens: Vec<PatToken>,
}

impl ScriptPattern {
    /// Number of pattern tokens — used by the static cost model (§7).
    pub fn len(&self) -> usize {
        self.tokens.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// `contains_ops`: does the pattern occur as a contiguous sub-run anywhere in
    /// the token stream? Implemented as a full-stream glob of `* pattern *`, so
    /// internal `*`/`_` behave as documented while the pattern itself is
    /// unanchored.
    pub fn contains_in(&self, tokens: &[ScriptToken]) -> bool {
        glob_search(tokens, &self.tokens)
    }
}

fn token_matches(tok: &ScriptToken, p: &PatToken) -> bool {
    match p {
        PatToken::Op(b) => tok.op == *b,
        PatToken::Push => tok.data.is_some(),
        PatToken::PushLen(n) => tok.data.is_some_and(|d| d.len() == *n as usize),
        PatToken::PushRange(a, b) => tok
            .data
            .is_some_and(|d| (*a as usize..=*b as usize).contains(&d.len())),
        PatToken::PushExact(x) => tok.data.is_some_and(|d| d == x.as_slice()),
        PatToken::PushPrefix(x) => tok
            .data
            .is_some_and(|d| d.len() >= x.len() && &d[..x.len()] == x.as_slice()),
        PatToken::AnyOne => true,
        PatToken::AnyRun => unreachable!("AnyRun handled by the glob driver"),
    }
}

/// Unanchored search: true iff `pat` matches some contiguous sub-run of `toks`.
/// Equivalent to a full-stream glob of `[AnyRun] ++ pat ++ [AnyRun]`.
fn glob_search(toks: &[ScriptToken], pat: &[PatToken]) -> bool {
    // The classic two-pointer wildcard matcher with a single backtrack pointer
    // for the most-recent `AnyRun` — non-backtracking, O(n × m) worst case.
    let n = toks.len();

    // Pad with a leading and trailing AnyRun so a full-stream glob match is
    // equivalent to an unanchored substring search. The pattern is ≤ 32 tokens
    // (≤ 34 padded), so this small allocation is negligible.
    let mut padded = Vec::with_capacity(pat.len() + 2);
    padded.push(PatToken::AnyRun);
    padded.extend_from_slice(pat);
    padded.push(PatToken::AnyRun);

    let m = padded.len();
    let (mut i, mut j) = (0usize, 0usize);
    let mut star_j: Option<usize> = None;
    let mut star_i = 0usize;
    while i < n {
        if j < m && matches!(padded[j], PatToken::AnyRun) {
            star_j = Some(j);
            star_i = i;
            j += 1; // try matching zero tokens first
        } else if j < m
            && !matches!(padded[j], PatToken::AnyRun)
            && token_matches(&toks[i], &padded[j])
        {
            i += 1;
            j += 1;
        } else if let Some(sj) = star_j {
            // Backtrack: let the last star consume one more token.
            j = sj + 1;
            star_i += 1;
            i = star_i;
        } else {
            return false;
        }
    }
    // Trailing stars match empty.
    while j < m && matches!(padded[j], PatToken::AnyRun) {
        j += 1;
    }
    j == m
}

// --- opcode name table ---

/// Resolve a canonical opcode name (case-insensitive) to its byte, or `None`.
///
/// The base table is built once from rust-bitcoin's authoritative opcode set
/// (every byte's `Display` name), then augmented with the human-friendly
/// aliases operators expect (`OP_FALSE`/`OP_TRUE`/`OP_0`..`OP_16`/`OP_1NEGATE`).
pub fn opcode_byte(name: &str) -> Option<u8> {
    static TABLE: OnceLock<HashMap<String, u8>> = OnceLock::new();
    let table = TABLE.get_or_init(build_opcode_table);
    table.get(&name.to_ascii_uppercase()).copied()
}

fn build_opcode_table() -> HashMap<String, u8> {
    let mut m = HashMap::new();
    for b in 0u16..=255 {
        let b = b as u8;
        let op = bitcoin::opcodes::Opcode::from(b);
        let name = format!("{op}").to_ascii_uppercase();
        // Don't let a generic placeholder name clobber a real one; first writer
        // wins for any (vanishingly unlikely) duplicate Display string.
        m.entry(name).or_insert(b);
    }
    // Human aliases not present (or differently spelled) in the Display table.
    m.insert("OP_FALSE".into(), 0x00);
    m.insert("OP_0".into(), 0x00);
    m.insert("OP_TRUE".into(), 0x51);
    m.insert("OP_1NEGATE".into(), 0x4f);
    for n in 1u8..=16 {
        // OP_1 .. OP_16  ==  0x50 + n  ==  OP_PUSHNUM_n
        m.insert(format!("OP_{n}"), 0x50 + n);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    // The opcode table is load-bearing for `script(…)` matching: a wrong byte is
    // a silent mis-match. Pin the bytes operators will actually write.
    #[test]
    fn opcode_names_resolve() {
        assert_eq!(opcode_byte("OP_RETURN"), Some(0x6a));
        assert_eq!(opcode_byte("op_return"), Some(0x6a)); // case-insensitive
        assert_eq!(opcode_byte("OP_IF"), Some(0x63));
        assert_eq!(opcode_byte("OP_DUP"), Some(0x76));
        assert_eq!(opcode_byte("OP_EQUAL"), Some(0x87));
        assert_eq!(opcode_byte("OP_EQUALVERIFY"), Some(0x88));
        assert_eq!(opcode_byte("OP_HASH160"), Some(0xa9));
        assert_eq!(opcode_byte("OP_CHECKSIG"), Some(0xac));
        assert_eq!(opcode_byte("OP_CHECKMULTISIG"), Some(0xae));
        // Aliases.
        assert_eq!(opcode_byte("OP_FALSE"), Some(0x00));
        assert_eq!(opcode_byte("OP_0"), Some(0x00));
        assert_eq!(opcode_byte("OP_TRUE"), Some(0x51));
        assert_eq!(opcode_byte("OP_1"), Some(0x51));
        assert_eq!(opcode_byte("OP_13"), Some(0x5d));
        assert_eq!(opcode_byte("OP_16"), Some(0x60));
        assert_eq!(opcode_byte("OP_1NEGATE"), Some(0x4f));
        // Runes marker, both spellings.
        assert_eq!(opcode_byte("OP_PUSHNUM_13"), Some(0x5d));
        // Pushdata opcodes.
        assert_eq!(opcode_byte("OP_PUSHDATA1"), Some(0x4c));
        assert_eq!(opcode_byte("OP_PUSHBYTES_3"), Some(0x03));
        assert_eq!(opcode_byte("OP_NONSENSE"), None);
    }

    fn toks(script: &[u8]) -> Vec<ScriptToken<'_>> {
        tokenize(script).tokens
    }

    #[test]
    fn tokenize_basic_pushes_and_opcodes() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (P2PKH)
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0xab; 20]);
        s.push(0x88);
        s.push(0xac);
        let t = toks(&s);
        assert_eq!(t.len(), 5);
        assert_eq!(t[0].op, 0x76);
        assert!(t[0].data.is_none());
        assert_eq!(t[2].op, 0x14);
        assert_eq!(t[2].data.unwrap().len(), 20);
        assert!(tokenize(&s).well_formed);
        assert_eq!(max_push(&t), 20);
        assert_eq!(count_op(&t, 0xac), 1);
    }

    #[test]
    fn tokenize_pushdata1() {
        // OP_PUSHDATA1 0x02 <2 bytes>
        let s = [0x4c, 0x02, 0xde, 0xad];
        let t = toks(&s);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, 0x4c);
        assert_eq!(t[0].data.unwrap(), &[0xde, 0xad]);
    }

    #[test]
    fn truncated_push_ends_stream_and_marks_malformed() {
        // OP_PUSHBYTES_5 but only 2 bytes follow.
        let s = [0x05, 0x01, 0x02];
        let r = tokenize(&s);
        assert!(!r.well_formed);
        assert!(r.tokens.is_empty());
    }
}
