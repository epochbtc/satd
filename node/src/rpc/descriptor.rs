//! Output descriptors — the subset `scantxoutset` understands, and the
//! inference that names a matched output script.
//!
//! Two directions, both ported from Bitcoin Core v31.1
//! (`src/script/descriptor.cpp`):
//!
//! * **Parsing** turns a scan object into the output scripts to look for.
//!   satd implements `raw(<hex script>)` and `addr(<address>)` — the
//!   key-free forms. Every other descriptor function is rejected by name
//!   rather than silently matching nothing, because a scan that returns
//!   zero unspents is indistinguishable from a scan that found none.
//!
//! * **Inference** goes the other way: given a script that matched, produce
//!   the descriptor Core would put in the `desc` field. Core runs this
//!   against the signing provider the scan objects populated; `raw()` and
//!   `addr()` populate none, so this is Core's inference under an empty
//!   provider, which is the only case satd can reach.
//!
//! The checksum is BIP380's. It is optional on input (Core's
//! `EvalDescriptorStringOrObject` calls `Parse` with
//! `require_checksum=false`) but verified when present, and always
//! appended on output.

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::{Network, ScriptBuf, address::Address, opcodes::all as opcodes};

/// Core's `INPUT_CHARSET`. Position in this string is a symbol's value;
/// the low 5 bits and the high bits are fed to the checksum separately.
const INPUT_CHARSET: &[u8] =
    b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// Core's `CHECKSUM_CHARSET` — bech32's.
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

/// Core's `PolyMod`: one step of the BCH code over GF(32).
fn poly_mod(c: u64, val: u64) -> u64 {
    let c0 = (c >> 35) as u8;
    let mut c = ((c & 0x7_ffff_ffff) << 5) ^ val;
    for (i, g) in GENERATOR.iter().enumerate() {
        if (c0 >> i) & 1 == 1 {
            c ^= *g;
        }
    }
    c
}

/// Compute the 8-character checksum of a descriptor payload (the part
/// before `#`). `None` if the payload has a character outside
/// `INPUT_CHARSET` — Core's "Invalid characters in payload".
pub fn checksum(payload: &str) -> Option<String> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount = 0;

    for ch in payload.bytes() {
        let pos = INPUT_CHARSET.iter().position(|&b| b == ch)? as u64;
        c = poly_mod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if clscount == 3 {
            c = poly_mod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        c = poly_mod(c, cls);
    }
    for _ in 0..8 {
        c = poly_mod(c, 0);
    }
    c ^= 1;

    Some(
        (0..8)
            .map(|j| CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize] as char)
            .collect(),
    )
}

/// Core's `AddChecksum`: `payload#checksum`. Panics only on a payload
/// outside `INPUT_CHARSET`, which no descriptor this module *emits* can
/// contain — every emitter builds from hex, base58 or bech32.
fn add_checksum(payload: &str) -> String {
    match checksum(payload) {
        Some(sum) => format!("{payload}#{sum}"),
        // Unreachable for emitted descriptors; degrade to the unchecksummed
        // form rather than aborting an operator's scan.
        None => payload.to_string(),
    }
}

/// Core's `CheckChecksum`: split off an optional `#checksum`, verify it,
/// and return the payload.
fn strip_checksum(desc: &str) -> Result<&str, String> {
    let mut parts = desc.splitn(3, '#');
    let payload = parts.next().unwrap_or("");
    let provided = parts.next();
    if parts.next().is_some() {
        return Err("Multiple '#' symbols".to_string());
    }
    if let Some(p) = provided
        && p.len() != 8
    {
        return Err(format!(
            "Expected 8 character checksum, not {} characters",
            p.len()
        ));
    }
    let computed = checksum(payload).ok_or_else(|| "Invalid characters in payload".to_string())?;
    if let Some(p) = provided
        && p != computed
    {
        return Err(format!(
            "Provided checksum '{p}' does not match computed checksum '{computed}'"
        ));
    }
    Ok(payload)
}

/// Core's `Func`: match `name(<inner>)` and yield the inner span.
fn func<'a>(name: &str, expr: &'a str) -> Option<&'a str> {
    let rest = expr.strip_prefix(name)?.strip_prefix('(')?;
    rest.strip_suffix(')')
}

/// Error codes Core uses on this path.
const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;
const RPC_INVALID_PARAMETER: i32 = -8;

/// Descriptor functions Core implements. Naming them individually lets an
/// unsupported-but-real descriptor say so, and keeps a typo (`addrr(...)`)
/// reading as a malformed descriptor rather than an unimplemented feature.
const KNOWN_FUNCS: &[&str] = &[
    "combo", "pk", "pkh", "wpkh", "sh", "wsh", "tr", "rawtr", "multi", "sortedmulti", "multi_a",
    "sortedmulti_a", "musig",
];

/// Core's `ParseRange` + `ParseDescriptorRange`.
///
/// Core validates the range's *shape* before it parses the descriptor, whether
/// or not the descriptor turns out to be ranged — so a malformed `range` is
/// rejected even alongside a descriptor that would ignore it. satd parses no
/// ranged descriptors, but skipping the check would answer a caller's
/// nonsensical range with silence, and Core's own `rpc_scantxoutset.py` asserts
/// these messages.
fn check_range(value: &serde_json::Value) -> Result<(), (i32, String)> {
    let invalid = |m: &str| (RPC_INVALID_PARAMETER, m.to_string());
    let (low, high) = match value {
        serde_json::Value::Number(n) => (
            0i64,
            n.as_i64()
                .ok_or_else(|| invalid("Range must be specified as end or as [begin,end]"))?,
        ),
        serde_json::Value::Array(a) if a.len() == 2 && a.iter().all(|v| v.is_number()) => {
            let low = a[0].as_i64().unwrap_or(i64::MIN);
            let high = a[1].as_i64().unwrap_or(i64::MAX);
            if low > high {
                return Err(invalid(
                    "Range specified as [begin,end] must not have begin after end",
                ));
            }
            (low, high)
        }
        _ => return Err(invalid("Range must be specified as end or as [begin,end]")),
    };
    if low < 0 {
        return Err(invalid("Range should be greater or equal than 0"));
    }
    if (high >> 31) != 0 {
        return Err(invalid("End of range is too high"));
    }
    if high >= low.saturating_add(1_000_000) {
        return Err(invalid("Range is too large"));
    }
    Ok(())
}

/// Turn one element of `scanobjects` into the output scripts to search
/// for. Core's `EvalDescriptorStringOrObject`, minus the ranged descriptors —
/// satd parses none, so a valid `range` is accepted and ignored exactly as
/// Core ignores it for a non-ranged descriptor. An *invalid* one is still
/// rejected, because Core checks it before it looks at the descriptor.
pub fn scan_object_to_scripts(
    obj: &serde_json::Value,
    network: Network,
) -> Result<Vec<ScriptBuf>, (i32, String)> {
    let desc = match obj {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(map) => {
            let desc = match map.get("desc") {
                Some(serde_json::Value::String(s)) => s.as_str(),
                Some(_) | None => {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        "Descriptor needs to be provided in scan object".to_string(),
                    ));
                }
            };
            // Checked before the descriptor, as Core does.
            match map.get("range") {
                None | Some(serde_json::Value::Null) => {}
                Some(r) => check_range(r)?,
            }
            desc
        }
        _ => {
            return Err((
                RPC_INVALID_PARAMETER,
                "Scan object needs to be either a string or an object".to_string(),
            ));
        }
    };

    parse_descriptor(desc, network)
        .map(|script| vec![script])
        .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))
}

/// Parse a `raw()` or `addr()` descriptor into its output script.
pub fn parse_descriptor(desc: &str, network: Network) -> Result<ScriptBuf, String> {
    let expr = strip_checksum(desc)?;

    if let Some(inner) = func("raw", expr) {
        // Core gates on `IsHex`, which is false for the empty string, so
        // `raw()` is refused before any scanning. `hex::decode("")` succeeds,
        // which would turn one token into a full pass over the UTXO set
        // looking for the empty output script -- minute-scale on mainnet, and
        // holding the scan reservation for all of it.
        if inner.is_empty() {
            return Err("Raw script is not hex".to_string());
        }
        let bytes = hex::decode(inner).map_err(|_| "Raw script is not hex".to_string())?;
        return Ok(ScriptBuf::from_bytes(bytes));
    }

    if let Some(inner) = func("addr", expr) {
        let unchecked: Address<bitcoin::address::NetworkUnchecked> = inner
            .parse()
            .map_err(|_| "Address is not valid".to_string())?;
        let address = unchecked
            .require_network(network)
            .map_err(|_| "Address is not valid".to_string())?;
        return Ok(address.script_pubkey());
    }

    // Name the form so an unsupported descriptor is never mistaken for a
    // scan that legitimately matched nothing.
    for name in KNOWN_FUNCS {
        if func(name, expr).is_some() {
            return Err(format!(
                "satd's scantxoutset does not implement {name}() descriptors; \
                 it supports raw(<hex script>) and addr(<address>)"
            ));
        }
    }
    Err(format!(
        "'{expr}' is not a valid descriptor function; \
         satd's scantxoutset supports raw(<hex script>) and addr(<address>)"
    ))
}

// ============================================================
// Rich descriptor parsing — key-based descriptors + derivation
// ============================================================
//
// The `parse_descriptor` above handles `raw()` and `addr()` for
// scantxoutset. This section adds full key-based descriptor parsing
// for `getdescriptorinfo`, `deriveaddresses`, and `generateblock`'s
// `combo()` / `pkh()` / etc. support.

/// Key origin info: `[fingerprint/path]`.
#[derive(Clone, Debug)]
struct KeyOrigin {
    fingerprint: [u8; 4],
    path: Vec<ChildNumber>,
}

/// An element in the derivation path following an extended key.
#[derive(Clone, Debug)]
enum DescPathElem {
    /// A single child number.
    Child(ChildNumber),
    /// Wildcard `*` or `*h`.
    Wildcard { hardened: bool },
    /// Multipath element `<a;b;...>`.
    Multipath(Vec<ChildNumber>),
}

/// The kind of key in a descriptor expression.
#[derive(Clone, Debug)]
enum DescKeyKind {
    /// Hex-encoded public key (compressed or uncompressed).
    Pubkey(bitcoin::PublicKey),
    /// WIF-encoded private key.
    PrivKey(bitcoin::PrivateKey),
    /// Extended public key (xpub/tpub).
    ExtPub(Xpub),
    /// Extended private key (xprv/tprv).
    ExtPriv(Xpriv),
}

/// A parsed key expression with optional origin and derivation path.
#[derive(Clone, Debug)]
struct DescKeyExpr {
    origin: Option<KeyOrigin>,
    key: DescKeyKind,
    path: Vec<DescPathElem>,
}

/// A fully parsed output descriptor.
#[derive(Clone, Debug)]
enum FullDescriptor {
    Pk(DescKeyExpr),
    Pkh(DescKeyExpr),
    Wpkh(DescKeyExpr),
    Sh(Box<FullDescriptor>),
    Wsh(Box<FullDescriptor>),
    Combo(DescKeyExpr),
    Multi {
        threshold: u32,
        keys: Vec<DescKeyExpr>,
        sorted: bool,
    },
    /// Held unchecked: the network is not known at parse time, so validation
    /// happens in `expand`, which has it. Core gets this for free — its
    /// `DecodeDestination` is chain-params-aware, so an address for another
    /// network simply fails to decode and reports "Address is not valid".
    Addr(bitcoin::Address<bitcoin::address::NetworkUnchecked>),
    Raw(ScriptBuf),
}

/// Result of parsing a descriptor string with full support.
#[derive(Debug)]
pub struct ParsedDescriptorSet {
    /// The expanded descriptors (one per multipath branch, or just one).
    descriptors: Vec<FullDescriptor>,
    /// Whether any key in the original input was private.
    pub has_private_keys: bool,
    /// The payload (before `#`) of the input, for checksum computation.
    pub input_payload: String,
}

// --- Key expression parsing ---

/// Parse a child-number step like `0`, `1h`, `2'`, `44h`.
fn parse_child_num(s: &str) -> Result<ChildNumber, String> {
    let (num_str, hardened) = if let Some(n) = s.strip_suffix('h').or_else(|| s.strip_suffix('\'')) {
        (n, true)
    } else {
        (s, false)
    };
    let num: u32 = num_str.parse().map_err(|_| format!("'{s}' is not a valid key path step"))?;
    if hardened {
        ChildNumber::from_hardened_idx(num)
            .map_err(|_| format!("Key path value {num} is out of range"))
    } else {
        ChildNumber::from_normal_idx(num)
            .map_err(|_| format!("Key path value {num} is out of range"))
    }
}

/// Parse a key origin `[fingerprint/step/step/...]` from the start of `expr`.
/// Returns `(origin, remaining)`.
fn parse_origin(expr: &str) -> Result<(Option<KeyOrigin>, &str), String> {
    let Some(rest) = expr.strip_prefix('[') else {
        return Ok((None, expr));
    };
    let close = rest.find(']').ok_or("Key origin not closed with ']'")?;
    let inside = &rest[..close];
    let after = &rest[close + 1..];

    let mut parts = inside.split('/');
    let fp_str = parts.next().ok_or("Key origin missing fingerprint")?;
    if fp_str.len() != 8 {
        return Err(format!(
            "Fingerprint must be 4 bytes (8 hex chars), got {} chars",
            fp_str.len()
        ));
    }
    let fp_bytes = hex::decode(fp_str).map_err(|_| "Fingerprint is not valid hex")?;
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&fp_bytes);

    let mut path = Vec::new();
    for step in parts {
        path.push(parse_child_num(step)?);
    }

    Ok((Some(KeyOrigin { fingerprint, path }), after))
}

/// Parse a derivation path element after the key. Handles `num`, `numh`,
/// `num'`, `*`, `*h`, `*'`, `<a;b;...>`.
fn parse_path_elem(s: &str) -> Result<DescPathElem, String> {
    if s == "*" {
        return Ok(DescPathElem::Wildcard { hardened: false });
    }
    if s == "*h" || s == "*'" {
        return Ok(DescPathElem::Wildcard { hardened: true });
    }
    if let Some(inner) = s.strip_prefix('<').and_then(|r| r.strip_suffix('>')) {
        let branches: Vec<ChildNumber> = inner
            .split(';')
            .map(parse_child_num)
            .collect::<Result<_, String>>()?;
        // Core's `ParseKeyPath` rejects both of these by name. The first also
        // keeps `key_select_branch` in range: it maps every multipath element
        // through one branch index, so two specifiers of different lengths
        // would index past the shorter one and panic out of the RPC handler.
        if branches.len() < 2 {
            return Err("Multipath key path specifiers must have at least two items".to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for b in &branches {
            if !seen.insert(*b) {
                return Err(format!(
                    "Duplicated key path value {} in multipath specifier",
                    u32::from(*b)
                ));
            }
        }
        return Ok(DescPathElem::Multipath(branches));
    }
    Ok(DescPathElem::Child(parse_child_num(s)?))
}

/// Parse a key expression: `[origin]key[/path...]`.
///
/// `ctx` is the descriptor function name for error messages, e.g.
/// `"pk()"` or `"Multi:"`.
fn parse_key_expr(
    expr: &str,
    ctx: &str,
    permit_uncompressed: bool,
) -> Result<DescKeyExpr, String> {
    // Check for whitespace.
    if expr.starts_with(' ') || expr.starts_with('\t')
        || expr.ends_with(' ') || expr.ends_with('\t')
    {
        return Err(format!(
            "{ctx} Key '{expr}' is invalid due to whitespace"
        ));
    }

    let (origin, rest) = parse_origin(expr)?;

    // Split on '/' to separate the key from derivation path steps.
    let mut slash_parts: Vec<&str> = rest.split('/').collect();

    // The first element is the key itself.
    let key_str = slash_parts.remove(0);

    // Try to parse the key.
    let key = if key_str.starts_with("xpub")
        || key_str.starts_with("tpub")
        || key_str.starts_with("ypub")
        || key_str.starts_with("zpub")
    {
        let xpub: Xpub = key_str
            .parse()
            .map_err(|e| format!("{ctx} Extended public key is invalid: {e}"))?;
        DescKeyKind::ExtPub(xpub)
    } else if key_str.starts_with("xprv")
        || key_str.starts_with("tprv")
        || key_str.starts_with("yprv")
        || key_str.starts_with("zprv")
    {
        let xpriv: Xpriv = key_str
            .parse()
            .map_err(|e| format!("{ctx} Extended private key is invalid: {e}"))?;
        DescKeyKind::ExtPriv(xpriv)
    } else if key_str.chars().all(|c| c.is_ascii_hexdigit())
        && (key_str.len() == 66 || key_str.len() == 130)
    {
        // Hex public key.
        let bytes = hex::decode(key_str).map_err(|_| format!("{ctx} Public key hex is invalid"))?;
        let pubkey = bitcoin::PublicKey::from_slice(&bytes)
            .map_err(|e| format!("{ctx} Public key is invalid: {e}"))?;
        DescKeyKind::Pubkey(pubkey)
    } else {
        // Try WIF private key.
        let privkey = bitcoin::PrivateKey::from_wif(key_str)
            .map_err(|_| format!("{ctx} Key '{key_str}' is not valid"))?;
        DescKeyKind::PrivKey(privkey)
    };

    // Parse derivation path elements.
    let mut path = Vec::new();
    for step in slash_parts {
        if step.is_empty() {
            continue;
        }
        path.push(parse_path_elem(step)?);
    }

    // Hex pubkeys and WIF keys cannot have derivation paths.
    if !path.is_empty() {
        match &key {
            DescKeyKind::Pubkey(_) | DescKeyKind::PrivKey(_) => {
                return Err(format!(
                    "{ctx} Non-extended key cannot have a derivation path"
                ));
            }
            _ => {}
        }
    }

    // One multipath specifier per key, as Core requires. Everything downstream
    // assumes it: `key_multipath_count` reports the first element's length and
    // `key_select_branch` applies that one index to every element.
    if path
        .iter()
        .filter(|e| matches!(e, DescPathElem::Multipath(_)))
        .count()
        > 1
    {
        return Err(format!("{ctx} Multiple multipath key path specifiers found"));
    }

    // An uncompressed key cannot go under a witness program: the script would
    // be unspendable. Core gates this on the parse context.
    if !permit_uncompressed {
        let uncompressed = match &key {
            DescKeyKind::Pubkey(pk) => !pk.compressed,
            DescKeyKind::PrivKey(sk) => !sk.compressed,
            _ => false,
        };
        if uncompressed {
            return Err(format!("{ctx} Uncompressed keys are not allowed"));
        }
    }

    Ok(DescKeyExpr { origin, key, path })
}

// --- Descriptor parsing ---

/// Split on commas at the top nesting level (respecting parentheses).
fn split_top_level_commas(expr: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, ch) in expr.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(&expr[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    result.push(&expr[start..]);
    result
}

/// Find the matching close paren for a function call, handling nesting.
/// Returns `(inner, rest_after_close_paren)` where rest_after_close_paren
/// should be empty for a well-formed descriptor.
fn func_inner<'a>(name: &str, expr: &'a str) -> Option<&'a str> {
    let rest = expr.strip_prefix(name)?.strip_prefix('(')?;
    // Find the matching close paren (the last one, since the outermost
    // function's close paren is always the last character).
    rest.strip_suffix(')')
}

/// Bitcoin Core's `MAX_PUBKEYS_PER_MULTISIG` (`src/script/script.h`).
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
/// Bitcoin Core's `MAX_SCRIPT_ELEMENT_SIZE` (`src/script/script.h`).
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Where in a descriptor a sub-expression sits — Core's `ParseScriptContext`.
///
/// This is not a convenience: it is what bounds the parser. Every descriptor
/// function is legal in only some contexts, and because `sh()` is top-level
/// only and `wsh()` is top-level or inside `sh()`, the maximum nesting depth a
/// well-formed descriptor can reach is three. Without the rule the recursion
/// below has no bound at all, and a nested string long enough to exhaust the
/// stack aborts the process — a Rust stack overflow is not a catchable panic.
///
/// It is also what stops the parser building scripts that cannot be spent:
/// `wsh(wpkh(k))` yields a P2WSH address whose witnessScript is itself a
/// witness program, which fails CLEANSTACK. Core refuses it by context, and
/// `deriveaddresses` is exactly the RPC people use to make receive addresses.
///
/// satd implements no `tr()`, so Core's `P2TR` context has no counterpart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParseCtx {
    /// Script goes straight into the scriptPubKey.
    Top,
    /// Inside `sh()` — the script becomes a P2SH redeemScript.
    P2sh,
    /// Inside `wsh()` — the script becomes a v0 witness script.
    P2wsh,
}

impl ParseCtx {
    /// Core's `permit_uncompressed`: an uncompressed pubkey is only allowed
    /// where no witness program will carry it (`src/script/descriptor.cpp`).
    fn permits_uncompressed(self) -> bool {
        matches!(self, Self::Top | Self::P2sh)
    }
}

/// Parse a full descriptor expression (recursive for sh/wsh).
fn parse_descriptor_expr(expr: &str, ctx: ParseCtx) -> Result<FullDescriptor, String> {
    if expr.is_empty() {
        return Err("'' is not a valid descriptor function".to_string());
    }

    // raw() and addr()
    if let Some(inner) = func_inner("raw", expr) {
        if ctx != ParseCtx::Top {
            return Err("Can only have raw() at top level".to_string());
        }
        if inner.is_empty() {
            return Err("Raw script is not hex".to_string());
        }
        let bytes = hex::decode(inner).map_err(|_| "Raw script is not hex".to_string())?;
        return Ok(FullDescriptor::Raw(ScriptBuf::from_bytes(bytes)));
    }

    if let Some(inner) = func_inner("addr", expr) {
        if ctx != ParseCtx::Top {
            return Err("Can only have addr() at top level".to_string());
        }
        let unchecked: Address<bitcoin::address::NetworkUnchecked> = inner
            .parse()
            .map_err(|_| "Address is not valid".to_string())?;
        return Ok(FullDescriptor::Addr(unchecked));
    }

    // Single-key descriptors. `pk()` is legal in every context; the rest are
    // gated exactly as Core gates them.
    if let Some(inner) = func_inner("pk", expr) {
        let key = parse_key_expr(inner, "pk():", ctx.permits_uncompressed())?;
        return Ok(FullDescriptor::Pk(key));
    }
    if let Some(inner) = func_inner("pkh", expr) {
        let key = parse_key_expr(inner, "pkh():", ctx.permits_uncompressed())?;
        return Ok(FullDescriptor::Pkh(key));
    }
    if let Some(inner) = func_inner("wpkh", expr) {
        if !matches!(ctx, ParseCtx::Top | ParseCtx::P2sh) {
            return Err("Can only have wpkh() at top level or inside sh()".to_string());
        }
        // Core parses this key in `P2WPKH` context, which never permits an
        // uncompressed key regardless of where the wpkh() itself sits.
        let key = parse_key_expr(inner, "wpkh():", false)?;
        return Ok(FullDescriptor::Wpkh(key));
    }
    if let Some(inner) = func_inner("combo", expr) {
        if ctx != ParseCtx::Top {
            return Err("Can only have combo() at top level".to_string());
        }
        let key = parse_key_expr(inner, "combo():", true)?;
        return Ok(FullDescriptor::Combo(key));
    }

    // Script wrappers. These two are what bound the recursion: `sh()` only at
    // the top, `wsh()` only at the top or inside `sh()`, so the deepest legal
    // descriptor is sh(wsh(...)) — three levels.
    if let Some(inner) = func_inner("sh", expr) {
        if ctx != ParseCtx::Top {
            return Err("Can only have sh() at top level".to_string());
        }
        let inner_desc = parse_descriptor_expr(inner, ParseCtx::P2sh)?;
        return Ok(FullDescriptor::Sh(Box::new(inner_desc)));
    }
    if let Some(inner) = func_inner("wsh", expr) {
        if !matches!(ctx, ParseCtx::Top | ParseCtx::P2sh) {
            return Err("Can only have wsh() at top level or inside sh()".to_string());
        }
        let inner_desc = parse_descriptor_expr(inner, ParseCtx::P2wsh)?;
        return Ok(FullDescriptor::Wsh(Box::new(inner_desc)));
    }

    // Multi/sortedmulti.
    if let Some(inner) = func_inner("multi", expr) {
        return parse_multi(inner, false, ctx);
    }
    if let Some(inner) = func_inner("sortedmulti", expr) {
        return parse_multi(inner, true, ctx);
    }

    // If we get here, identify the function name for the error message.
    if let Some(paren) = expr.find('(') {
        let name = &expr[..paren];
        return Err(format!("'{name}' is not a valid descriptor function"));
    }
    Err(format!("'{expr}' is not a valid descriptor function"))
}

/// Serialized length of the pubkey this expression will produce.
///
/// Feeds the P2SH redeem-script size check. Extended keys always derive
/// compressed, so only a literal key or WIF can be 65 bytes.
fn key_serialized_len(key: &DescKeyExpr) -> usize {
    match &key.key {
        DescKeyKind::Pubkey(pk) if !pk.compressed => 65,
        DescKeyKind::PrivKey(sk) if !sk.compressed => 65,
        _ => 33,
    }
}

fn parse_multi(inner: &str, sorted: bool, ctx: ParseCtx) -> Result<FullDescriptor, String> {
    // `multi()` produces a bare script, so it cannot sit under a wpkh() or at
    // any depth Core does not reach.
    if !matches!(ctx, ParseCtx::Top | ParseCtx::P2sh | ParseCtx::P2wsh) {
        return Err("Can only have multi/sortedmulti at top level, in sh(), or in wsh()".to_string());
    }

    let parts = split_top_level_commas(inner);
    if parts.len() < 2 {
        return Err("Multi: need threshold and at least one key".to_string());
    }
    // Core parses the threshold with `ToIntegral<uint32_t>`, which rejects a
    // sign; Rust's `u32::from_str` accepts a leading '+'.
    if parts[0].starts_with('+') {
        return Err("Multi: threshold is not a valid number".to_string());
    }
    let threshold: u32 = parts[0]
        .parse()
        .map_err(|_| "Multi: threshold is not a valid number".to_string())?;

    let mut keys = Vec::new();
    let mut script_size = 0usize;
    for part in &parts[1..] {
        let key = parse_key_expr(part, "Multi:", ctx.permits_uncompressed())?;
        // Core accumulates `pubkey_size + 1` per key: the push opcode plus the
        // key itself.
        script_size += key_serialized_len(&key) + 1;
        keys.push(key);
    }

    if keys.is_empty() || keys.len() > MAX_PUBKEYS_PER_MULTISIG {
        return Err(format!(
            "Cannot have {} keys in multisig; must have between 1 and {} keys, inclusive",
            keys.len(),
            MAX_PUBKEYS_PER_MULTISIG
        ));
    }
    if threshold < 1 {
        return Err(format!(
            "Multisig threshold cannot be {threshold}, must be at least 1"
        ));
    }
    if threshold as usize > keys.len() {
        return Err(format!(
            "Multisig threshold cannot be larger than the number of keys; \
             threshold is {} but only {} keys specified",
            threshold,
            keys.len()
        ));
    }
    if ctx == ParseCtx::Top && keys.len() > 3 {
        return Err(format!(
            "Cannot have {} pubkeys in bare multisig; only at most 3 pubkeys",
            keys.len()
        ));
    }
    if ctx == ParseCtx::P2sh {
        // The redeemScript must fit in one stack element or it can never be
        // supplied, so the coins would be unspendable. Core caps compressed
        // keys at 15 this way. `+3` is OP_m, OP_n and OP_CHECKMULTISIG.
        if script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(format!(
                "P2SH script is too large, {} bytes is larger than {} bytes",
                script_size + 3,
                MAX_SCRIPT_ELEMENT_SIZE
            ));
        }
    }

    Ok(FullDescriptor::Multi {
        threshold,
        keys,
        sorted,
    })
}

// --- Full descriptor parsing entry point ---

/// Parse a descriptor string into a `ParsedDescriptorSet`.
///
/// If `require_checksum` is true, a missing checksum is an error
/// (`deriveaddresses` requires it).
pub fn parse_full_descriptor(
    desc: &str,
    require_checksum: bool,
) -> Result<ParsedDescriptorSet, String> {
    // Strip and verify checksum.
    let mut parts = desc.splitn(3, '#');
    let payload = parts.next().unwrap_or("");
    let provided_checksum = parts.next();
    if parts.next().is_some() {
        return Err("Multiple '#' symbols".to_string());
    }

    if require_checksum && provided_checksum.is_none() {
        return Err("Missing checksum".to_string());
    }

    if let Some(p) = provided_checksum {
        if p.len() != 8 {
            return Err(format!(
                "Expected 8 character checksum, not {} characters",
                p.len()
            ));
        }
        let computed =
            checksum(payload).ok_or_else(|| "Invalid characters in payload".to_string())?;
        if p != computed {
            return Err(format!(
                "Provided checksum '{p}' does not match computed checksum '{computed}'"
            ));
        }
    }

    // Parse the descriptor body.
    let base = parse_descriptor_expr(payload, ParseCtx::Top)?;

    // Check for private keys.
    let has_private_keys = descriptor_has_private_keys(&base);

    // Expand multipath branches.
    let descriptors = expand_multipath(base)?;

    Ok(ParsedDescriptorSet {
        descriptors,
        has_private_keys,
        input_payload: payload.to_string(),
    })
}

/// Check if any key in a descriptor is private.
fn descriptor_has_private_keys(desc: &FullDescriptor) -> bool {
    match desc {
        FullDescriptor::Pk(k)
        | FullDescriptor::Pkh(k)
        | FullDescriptor::Wpkh(k)
        | FullDescriptor::Combo(k) => key_is_private(k),
        FullDescriptor::Sh(inner) | FullDescriptor::Wsh(inner) => {
            descriptor_has_private_keys(inner)
        }
        FullDescriptor::Multi { keys, .. } => keys.iter().any(key_is_private),
        FullDescriptor::Addr(_) | FullDescriptor::Raw(_) => false,
    }
}

fn key_is_private(key: &DescKeyExpr) -> bool {
    matches!(key.key, DescKeyKind::PrivKey(_) | DescKeyKind::ExtPriv(_))
}

// --- Multipath expansion ---

/// Count the number of multipath branches in a key expression.
/// Returns 0 if no multipath elements, or the branch count if any.
fn key_multipath_count(key: &DescKeyExpr) -> usize {
    for elem in &key.path {
        if let DescPathElem::Multipath(branches) = elem {
            return branches.len();
        }
    }
    0
}

/// Get the multipath branch count for a descriptor, or 0 if none.
fn descriptor_multipath_count(desc: &FullDescriptor) -> Result<usize, String> {
    let counts: Vec<usize> = match desc {
        FullDescriptor::Pk(k)
        | FullDescriptor::Pkh(k)
        | FullDescriptor::Wpkh(k)
        | FullDescriptor::Combo(k) => vec![key_multipath_count(k)],
        FullDescriptor::Sh(inner) | FullDescriptor::Wsh(inner) => {
            return descriptor_multipath_count(inner);
        }
        FullDescriptor::Multi { keys, .. } => {
            keys.iter().map(key_multipath_count).collect()
        }
        FullDescriptor::Addr(_) | FullDescriptor::Raw(_) => return Ok(0),
    };

    let nonzero: Vec<usize> = counts.into_iter().filter(|&c| c > 0).collect();
    if nonzero.is_empty() {
        return Ok(0);
    }
    if !nonzero.windows(2).all(|w| w[0] == w[1]) {
        return Err("All multipath elements must have the same number of branches".to_string());
    }
    Ok(nonzero[0])
}

/// Replace multipath elements in a key with the i-th branch.
fn key_select_branch(key: &DescKeyExpr, branch: usize) -> DescKeyExpr {
    let path = key
        .path
        .iter()
        .map(|elem| match elem {
            DescPathElem::Multipath(branches) => DescPathElem::Child(branches[branch]),
            other => other.clone(),
        })
        .collect();
    DescKeyExpr {
        origin: key.origin.clone(),
        key: key.key.clone(),
        path,
    }
}

fn descriptor_select_branch(desc: &FullDescriptor, branch: usize) -> FullDescriptor {
    match desc {
        FullDescriptor::Pk(k) => FullDescriptor::Pk(key_select_branch(k, branch)),
        FullDescriptor::Pkh(k) => FullDescriptor::Pkh(key_select_branch(k, branch)),
        FullDescriptor::Wpkh(k) => FullDescriptor::Wpkh(key_select_branch(k, branch)),
        FullDescriptor::Combo(k) => FullDescriptor::Combo(key_select_branch(k, branch)),
        FullDescriptor::Sh(inner) => {
            FullDescriptor::Sh(Box::new(descriptor_select_branch(inner, branch)))
        }
        FullDescriptor::Wsh(inner) => {
            FullDescriptor::Wsh(Box::new(descriptor_select_branch(inner, branch)))
        }
        FullDescriptor::Multi {
            threshold,
            keys,
            sorted,
        } => FullDescriptor::Multi {
            threshold: *threshold,
            keys: keys.iter().map(|k| key_select_branch(k, branch)).collect(),
            sorted: *sorted,
        },
        FullDescriptor::Addr(a) => FullDescriptor::Addr(a.clone()),
        FullDescriptor::Raw(s) => FullDescriptor::Raw(s.clone()),
    }
}

/// Expand multipath elements, producing one descriptor per branch.
fn expand_multipath(desc: FullDescriptor) -> Result<Vec<FullDescriptor>, String> {
    let count = descriptor_multipath_count(&desc)?;
    if count == 0 {
        return Ok(vec![desc]);
    }
    Ok((0..count)
        .map(|i| descriptor_select_branch(&desc, i))
        .collect())
}

// --- Property queries ---

impl FullDescriptor {
    /// Whether this descriptor is ranged (contains a wildcard `*`).
    fn is_range(&self) -> bool {
        match self {
            FullDescriptor::Pk(k)
            | FullDescriptor::Pkh(k)
            | FullDescriptor::Wpkh(k)
            | FullDescriptor::Combo(k) => key_is_ranged(k),
            FullDescriptor::Sh(inner) | FullDescriptor::Wsh(inner) => inner.is_range(),
            FullDescriptor::Multi { keys, .. } => keys.iter().any(key_is_ranged),
            FullDescriptor::Addr(_) | FullDescriptor::Raw(_) => false,
        }
    }

    /// Whether the descriptor has enough info to produce output scripts.
    /// Key-based descriptors are always solvable (we have the pubkey or
    /// can derive it). `raw()` and `addr()` are not solvable in Core's
    /// sense (no signing info), but the tests treat them differently.
    fn is_solvable(&self) -> bool {
        match self {
            FullDescriptor::Pk(_)
            | FullDescriptor::Pkh(_)
            | FullDescriptor::Wpkh(_)
            | FullDescriptor::Combo(_)
            | FullDescriptor::Multi { .. } => true,
            FullDescriptor::Sh(inner) | FullDescriptor::Wsh(inner) => inner.is_solvable(),
            FullDescriptor::Addr(_) | FullDescriptor::Raw(_) => false,
        }
    }
}

fn key_is_ranged(key: &DescKeyExpr) -> bool {
    key.path
        .iter()
        .any(|e| matches!(e, DescPathElem::Wildcard { .. }))
}

// --- Key derivation ---

/// Derive the concrete public key from a key expression at the given
/// position (for ranged descriptors). Returns the public key and whether
/// it is compressed.
fn derive_pubkey(
    key: &DescKeyExpr,
    pos: u32,
) -> Result<bitcoin::PublicKey, String> {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    match &key.key {
        DescKeyKind::Pubkey(pk) => {
            // No derivation possible for raw pubkeys.
            Ok(*pk)
        }
        DescKeyKind::PrivKey(pk) => Ok(pk.public_key(&secp)),
        DescKeyKind::ExtPub(xpub) => {
            let child_path = resolve_path(&key.path, pos)?;
            // All path steps must be non-hardened for xpub derivation.
            for cn in &child_path {
                if let ChildNumber::Hardened { .. } = cn {
                    return Err(
                        "Cannot derive script without private keys".to_string()
                    );
                }
            }
            let derived = xpub
                .derive_pub(&secp, &child_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            Ok(bitcoin::PublicKey::new(derived.public_key))
        }
        DescKeyKind::ExtPriv(xpriv) => {
            let child_path = resolve_path(&key.path, pos)?;
            let derived = xpriv
                .derive_priv(&secp, &child_path)
                .map_err(|e| format!("Key derivation failed: {e}"))?;
            let xpub = Xpub::from_priv(&secp, &derived);
            Ok(bitcoin::PublicKey::new(xpub.public_key))
        }
    }
}

/// Resolve a path with wildcards to concrete child numbers.
fn resolve_path(path: &[DescPathElem], pos: u32) -> Result<Vec<ChildNumber>, String> {
    let mut result = Vec::new();
    for elem in path {
        match elem {
            DescPathElem::Child(cn) => result.push(*cn),
            DescPathElem::Wildcard { hardened } => {
                if *hardened {
                    result.push(
                        ChildNumber::from_hardened_idx(pos)
                            .map_err(|_| "Position out of range for hardened derivation")?,
                    );
                } else {
                    result.push(
                        ChildNumber::from_normal_idx(pos)
                            .map_err(|_| "Position out of range")?,
                    );
                }
            }
            DescPathElem::Multipath(_) => {
                return Err(
                    "Multipath elements should be expanded before derivation".to_string()
                );
            }
        }
    }
    Ok(result)
}

// --- Script generation ---

impl FullDescriptor {
    /// Expand this descriptor at position `pos` into the output script(s).
    ///
    /// For most descriptors this returns one script. For `combo()` it
    /// returns 2 (uncompressed) or 4 (compressed) scripts in Core's
    /// order: P2PK, P2PKH, [P2WPKH, P2SH-P2WPKH].
    #[allow(clippy::only_used_in_recursion)]
    pub fn expand(
        &self,
        pos: u32,
        network: Network,
    ) -> Result<Vec<ScriptBuf>, String> {
        match self {
            FullDescriptor::Pk(key) => {
                let pk = derive_pubkey(key, pos)?;
                Ok(vec![make_p2pk_script(&pk)])
            }
            FullDescriptor::Pkh(key) => {
                let pk = derive_pubkey(key, pos)?;
                Ok(vec![ScriptBuf::new_p2pkh(&pk.pubkey_hash())])
            }
            FullDescriptor::Wpkh(key) => {
                let pk = derive_pubkey(key, pos)?;
                let wpkh = pk
                    .wpubkey_hash()
                    .map_err(|_| "Cannot create P2WPKH from uncompressed key".to_string())?;
                Ok(vec![ScriptBuf::new_p2wpkh(&wpkh)])
            }
            FullDescriptor::Combo(key) => {
                let pk = derive_pubkey(key, pos)?;
                let mut scripts = Vec::new();
                // P2PK
                scripts.push(make_p2pk_script(&pk));
                // P2PKH
                scripts.push(ScriptBuf::new_p2pkh(&pk.pubkey_hash()));
                // P2WPKH + P2SH-P2WPKH (compressed only)
                if pk.compressed {
                    let wpkh = pk.wpubkey_hash().expect("compressed key has wpubkey_hash");
                    let p2wpkh = ScriptBuf::new_p2wpkh(&wpkh);
                    let p2sh_p2wpkh = ScriptBuf::new_p2sh(&p2wpkh.script_hash());
                    scripts.push(p2wpkh);
                    scripts.push(p2sh_p2wpkh);
                }
                Ok(scripts)
            }
            FullDescriptor::Sh(inner) => {
                let inner_scripts = inner.expand(pos, network)?;
                if inner_scripts.len() != 1 {
                    return Err("P2SH inner must produce exactly one script".to_string());
                }
                let redeem = &inner_scripts[0];
                Ok(vec![ScriptBuf::new_p2sh(&redeem.script_hash())])
            }
            FullDescriptor::Wsh(inner) => {
                let inner_scripts = inner.expand(pos, network)?;
                if inner_scripts.len() != 1 {
                    return Err("P2WSH inner must produce exactly one script".to_string());
                }
                let witness_script = &inner_scripts[0];
                Ok(vec![ScriptBuf::new_p2wsh(&witness_script.wscript_hash())])
            }
            FullDescriptor::Multi {
                threshold,
                keys,
                sorted,
            } => {
                let mut pubkeys: Vec<bitcoin::PublicKey> = Vec::new();
                for k in keys {
                    pubkeys.push(derive_pubkey(k, pos)?);
                }
                if *sorted {
                    pubkeys.sort_by_key(|a| a.to_bytes());
                }
                Ok(vec![make_multisig_script(*threshold, &pubkeys)])
            }
            FullDescriptor::Addr(a) => {
                // The network check the previous parser did at parse time.
                // Without it, `deriveaddresses("addr(<testnet address>)")` on
                // mainnet re-encodes the payload as its mainnet twin and hands
                // it back as a valid destination.
                let checked = a
                    .clone()
                    .require_network(network)
                    .map_err(|_| "Address is not valid".to_string())?;
                Ok(vec![checked.script_pubkey()])
            }
            FullDescriptor::Raw(s) => Ok(vec![s.clone()]),
        }
    }
}

/// Build a P2PK script: `<push key> OP_CHECKSIG`.
fn make_p2pk_script(pubkey: &bitcoin::PublicKey) -> ScriptBuf {
    bitcoin::blockdata::script::Builder::new()
        .push_key(pubkey)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

/// Build a bare multisig script: `OP_m <key1>...<keyn> OP_n OP_CHECKMULTISIG`.
fn make_multisig_script(threshold: u32, keys: &[bitcoin::PublicKey]) -> ScriptBuf {
    let mut builder = bitcoin::blockdata::script::Builder::new()
        .push_int(threshold as i64);
    for key in keys {
        builder = builder.push_key(key);
    }
    builder
        .push_int(keys.len() as i64)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

// --- Canonical string output ---

impl DescKeyExpr {
    /// Convert this key expression to its canonical public string form.
    fn to_public_string(&self) -> String {
        let mut out = String::new();
        if let Some(origin) = &self.origin {
            out.push('[');
            out.push_str(&hex::encode(origin.fingerprint));
            for cn in &origin.path {
                out.push('/');
                out.push_str(&child_number_to_string(*cn));
            }
            out.push(']');
        }

        match &self.key {
            DescKeyKind::Pubkey(pk) => {
                out.push_str(&pk.to_string());
            }
            DescKeyKind::PrivKey(pk) => {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let pubkey = pk.public_key(&secp);
                out.push_str(&pubkey.to_string());
            }
            DescKeyKind::ExtPub(xpub) => {
                out.push_str(&xpub.to_string());
            }
            DescKeyKind::ExtPriv(xpriv) => {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let xpub = Xpub::from_priv(&secp, xpriv);
                out.push_str(&xpub.to_string());
            }
        }

        for elem in &self.path {
            out.push('/');
            match elem {
                DescPathElem::Child(cn) => out.push_str(&child_number_to_string(*cn)),
                DescPathElem::Wildcard { hardened } => {
                    out.push('*');
                    if *hardened {
                        out.push('h');
                    }
                }
                DescPathElem::Multipath(branches) => {
                    out.push('<');
                    for (i, cn) in branches.iter().enumerate() {
                        if i > 0 {
                            out.push(';');
                        }
                        out.push_str(&child_number_to_string(*cn));
                    }
                    out.push('>');
                }
            }
        }

        out
    }
}

fn child_number_to_string(cn: ChildNumber) -> String {
    match cn {
        ChildNumber::Normal { index } => index.to_string(),
        ChildNumber::Hardened { index } => format!("{index}h"),
    }
}

impl FullDescriptor {
    /// Convert to canonical public string form (without checksum).
    fn to_public_payload(&self) -> String {
        match self {
            FullDescriptor::Pk(k) => format!("pk({})", k.to_public_string()),
            FullDescriptor::Pkh(k) => format!("pkh({})", k.to_public_string()),
            FullDescriptor::Wpkh(k) => format!("wpkh({})", k.to_public_string()),
            FullDescriptor::Combo(k) => format!("combo({})", k.to_public_string()),
            FullDescriptor::Sh(inner) => format!("sh({})", inner.to_public_payload()),
            FullDescriptor::Wsh(inner) => format!("wsh({})", inner.to_public_payload()),
            FullDescriptor::Multi {
                threshold,
                keys,
                sorted,
            } => {
                let name = if *sorted { "sortedmulti" } else { "multi" };
                let key_strs: Vec<String> =
                    keys.iter().map(|k| k.to_public_string()).collect();
                format!("{name}({threshold},{})", key_strs.join(","))
            }
            // Re-rendering the descriptor is not the place to enforce the
            // network — `expand` does that — so show the address as written.
            FullDescriptor::Addr(a) => format!("addr({})", a.clone().assume_checked()),
            FullDescriptor::Raw(s) => format!("raw({})", hex::encode(s.as_bytes())),
        }
    }

    /// Convert to canonical public string form with checksum.
    pub fn to_public_string(&self) -> String {
        add_checksum(&self.to_public_payload())
    }
}

// --- Script selection for generateblock (Core's getScriptFromDescriptor) ---

/// Given a descriptor, produce the single coinbase output script for
/// `generateblock`. For combo() descriptors, selects P2WPKH for
/// compressed keys and P2PKH for uncompressed, matching Core's
/// `getScriptFromDescriptor`.
pub fn descriptor_to_coinbase_script(
    desc: &str,
    network: Network,
) -> Result<ScriptBuf, (i32, String)> {
    let parsed = parse_full_descriptor(desc, false)
        .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))?;

    if parsed.descriptors.len() > 1 {
        return Err((
            RPC_INVALID_PARAMETER,
            "Multipath descriptor not accepted".to_string(),
        ));
    }

    let descriptor = &parsed.descriptors[0];

    if descriptor.is_range() {
        return Err((
            RPC_INVALID_PARAMETER,
            "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?"
                .to_string(),
        ));
    }

    let scripts = descriptor
        .expand(0, network)
        .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))?;

    // Core's getScriptFromDescriptor logic for combo().
    let script = match scripts.len() {
        1 => scripts.into_iter().next().unwrap(),
        4 => {
            // Compressed combo: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH.
            // Take P2WPKH (index 2).
            scripts.into_iter().nth(2).unwrap()
        }
        2 => {
            // Uncompressed combo: P2PK, P2PKH.
            // Take P2PKH (index 1).
            scripts.into_iter().nth(1).unwrap()
        }
        n => {
            return Err((
                RPC_INVALID_PARAMETER,
                format!("Unexpected number of scripts from descriptor: {n}"),
            ));
        }
    };

    Ok(script)
}

// --- RPC handler helpers ---

/// Implements `getdescriptorinfo`.
pub fn get_descriptor_info(descriptor: &str) -> Result<serde_json::Value, (i32, String)> {
    let parsed = parse_full_descriptor(descriptor, false)
        .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))?;

    let primary = &parsed.descriptors[0];

    let mut result = serde_json::Map::new();

    // Canonical public descriptor with checksum.
    result.insert(
        "descriptor".to_string(),
        serde_json::Value::String(primary.to_public_string()),
    );

    // Multipath expansion.
    if parsed.descriptors.len() > 1 {
        let expansions: Vec<serde_json::Value> = parsed
            .descriptors
            .iter()
            .map(|d| serde_json::Value::String(d.to_public_string()))
            .collect();
        result.insert(
            "multipath_expansion".to_string(),
            serde_json::Value::Array(expansions),
        );
    }

    // Checksum of the input payload.
    let cksum = checksum(&parsed.input_payload)
        .ok_or_else(|| (RPC_INVALID_ADDRESS_OR_KEY, "Invalid characters in payload".to_string()))?;
    result.insert(
        "checksum".to_string(),
        serde_json::Value::String(cksum),
    );

    result.insert(
        "isrange".to_string(),
        serde_json::Value::Bool(primary.is_range()),
    );
    result.insert(
        "issolvable".to_string(),
        serde_json::Value::Bool(primary.is_solvable()),
    );
    result.insert(
        "hasprivatekeys".to_string(),
        serde_json::Value::Bool(parsed.has_private_keys),
    );

    Ok(serde_json::Value::Object(result))
}

/// Implements `deriveaddresses`.
pub fn derive_addresses(
    descriptor: &str,
    range: Option<&serde_json::Value>,
    network: Network,
) -> Result<serde_json::Value, (i32, String)> {
    let parsed = parse_full_descriptor(descriptor, true)
        .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))?;

    let primary = &parsed.descriptors[0];

    // Parse range.
    let (range_begin, range_end) = if let Some(r) = range {
        parse_derive_range(r)?
    } else {
        (0i64, 0i64)
    };

    // Check range vs ranged descriptor.
    if !primary.is_range() && range.is_some() {
        return Err((
            RPC_INVALID_PARAMETER,
            "Range should not be specified for an un-ranged descriptor".to_string(),
        ));
    }
    if primary.is_range() && range.is_none() {
        return Err((
            RPC_INVALID_PARAMETER,
            "Range must be specified for a ranged descriptor".to_string(),
        ));
    }

    // Derive addresses for the primary descriptor.
    let derive_one = |desc: &FullDescriptor| -> Result<serde_json::Value, (i32, String)> {
        let mut addresses = Vec::new();
        for i in range_begin..=range_end {
            let scripts = desc
                .expand(i as u32, network)
                .map_err(|e| (RPC_INVALID_ADDRESS_OR_KEY, e))?;

            for script in &scripts {
                // Skip P2PK in combo descriptors (no address).
                if scripts.len() > 1 && p2pk_key(script).is_some() {
                    continue;
                }
                let addr = Address::from_script(script, network).map_err(|_| {
                    (
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Descriptor does not have a corresponding address".to_string(),
                    )
                })?;
                addresses.push(serde_json::Value::String(addr.to_string()));
            }
        }

        if addresses.is_empty() {
            return Err((-1, "Unexpected empty result".to_string()));
        }

        Ok(serde_json::Value::Array(addresses))
    };

    if parsed.descriptors.len() == 1 {
        derive_one(primary)
    } else {
        // Multipath: return array of arrays.
        let mut result = Vec::new();
        for desc in &parsed.descriptors {
            result.push(derive_one(desc)?);
        }
        Ok(serde_json::Value::Array(result))
    }
}

/// Parse the `range` argument for `deriveaddresses`.
fn parse_derive_range(value: &serde_json::Value) -> Result<(i64, i64), (i32, String)> {
    let invalid = |m: &str| (RPC_INVALID_PARAMETER, m.to_string());

    let (low, high) = match value {
        serde_json::Value::Number(n) => {
            let high = n
                .as_i64()
                .ok_or_else(|| invalid("Range must be specified as end or as [begin,end]"))?;
            (0i64, high)
        }
        serde_json::Value::Array(a) if a.len() == 2 && a.iter().all(|v| v.is_number()) => {
            let low = a[0].as_i64().unwrap_or(i64::MIN);
            let high = a[1].as_i64().unwrap_or(i64::MAX);
            if low > high {
                return Err(invalid(
                    "Range specified as [begin,end] must not have begin after end",
                ));
            }
            (low, high)
        }
        _ => return Err(invalid("Range must be specified as end or as [begin,end]")),
    };

    if low < 0 {
        return Err(invalid("Range should be greater or equal than 0"));
    }
    if (high >> 31) != 0 {
        return Err(invalid("End of range is too high"));
    }
    if high >= low.saturating_add(1_000_000) {
        return Err(invalid("Range is too large"));
    }

    Ok((low, high))
}

/// Core's `CPubKey::IsValidNonHybrid` composed with the length check
/// `CPubKey::Set` applies: 33 bytes behind 0x02/0x03, or 65 behind 0x04.
/// Deliberately *not* a curve check — Core infers `pk()` for a
/// well-formed-but-off-curve key, and diverging here would rename a real
/// output.
fn is_valid_non_hybrid(key: &[u8]) -> bool {
    match key.first() {
        Some(0x02 | 0x03) => key.len() == 33,
        Some(0x04) => key.len() == 65,
        _ => false,
    }
}

/// Core's `InferScript` at top level under an empty signing provider.
///
/// The provider matters: with keys in hand Core can name a P2PKH output
/// `pkh(<pubkey>)`. `raw()` and `addr()` scan objects supply no keys, so
/// the hash-committed forms fall through to `addr()`, which is what an
/// operator sees.
pub fn infer_descriptor(script: &bitcoin::Script, network: Network) -> String {
    let bytes = script.as_bytes();

    // P2TR is checked ahead of the address fallback so an on-curve output
    // key is named rather than re-encoded as an address.
    if script.is_p2tr()
        && bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes[2..34]).is_ok()
    {
        return add_checksum(&format!("rawtr({})", hex::encode(&bytes[2..34])));
    }

    if let Some(key) = p2pk_key(script)
        && is_valid_non_hybrid(key)
    {
        return add_checksum(&format!("pk({})", hex::encode(key)));
    }

    if let Some((threshold, keys)) = bare_multisig(script)
        && keys.iter().all(|k| is_valid_non_hybrid(k))
    {
        let joined: Vec<String> = keys.iter().map(hex::encode).collect();
        return add_checksum(&format!("multi({threshold},{})", joined.join(",")));
    }

    // Core's `ExtractDestination` + a round-trip check: the descriptor is
    // only `addr()` if re-encoding the destination reproduces this exact
    // script.
    if let Ok(address) = Address::from_script(script, network)
        && address.script_pubkey().as_bytes() == bytes
    {
        return add_checksum(&format!("addr({address})"));
    }

    add_checksum(&format!("raw({})", hex::encode(bytes)))
}

/// The pubkey of a bare P2PK output (`<key> OP_CHECKSIG`), by length.
fn p2pk_key(script: &bitcoin::Script) -> Option<&[u8]> {
    let b = script.as_bytes();
    match b.len() {
        35 if b[0] == 33 && b[34] == opcodes::OP_CHECKSIG.to_u8() => Some(&b[1..34]),
        67 if b[0] == 65 && b[66] == opcodes::OP_CHECKSIG.to_u8() => Some(&b[1..66]),
        _ => None,
    }
}

/// Core's `MatchMultisig`: `<m> <key>... <n> OP_CHECKMULTISIG` with
/// minimal pushes and `1 <= m <= n`.
fn bare_multisig(script: &bitcoin::Script) -> Option<(u8, Vec<&[u8]>)> {
    use bitcoin::script::Instruction;

    if script.as_bytes().last() != Some(&opcodes::OP_CHECKMULTISIG.to_u8()) {
        return None;
    }
    // `instructions_minimal` errors on a non-minimal push, which is where
    // Core's `CheckMinimalPush` breaks the key loop and then fails the
    // small-integer check.
    let mut it = script.instructions_minimal();

    let threshold = small_int(it.next()?.ok()?)?;
    let mut keys: Vec<&[u8]> = Vec::new();
    let n = loop {
        let insn = it.next()?.ok()?;
        if let Some(n) = small_int(insn) {
            break n;
        }
        match insn {
            // Core's `CPubKey::ValidSize`, the only sizes it collects.
            Instruction::PushBytes(p) if p.len() == 33 || p.len() == 65 => keys.push(p.as_bytes()),
            _ => return None,
        }
    };

    // The small integer must be followed by OP_CHECKMULTISIG and nothing else.
    match it.next()? {
        Ok(Instruction::Op(op)) if op == opcodes::OP_CHECKMULTISIG => {}
        _ => return None,
    }
    if it.next().is_some() {
        return None;
    }
    if keys.len() != n as usize || n < threshold || threshold == 0 {
        return None;
    }
    Some((threshold, keys))
}

/// Core's `GetScriptNumber` for the two multisig integers: OP_1..OP_16, **or**
/// a minimally-encoded single-byte push for 17..=20.
///
/// Consensus allows up to `MAX_PUBKEYS_PER_MULTISIG` = 20 keys, and 17..20
/// cannot be spelled as a push-number opcode, so Core accepts
/// `OP_PUSHBYTES_1 0x11` there. Reading only the opcode form named those
/// outputs `raw()` instead of `multi()`.
fn small_int(insn: bitcoin::script::Instruction<'_>) -> Option<u8> {
    const MAX_PUBKEYS_PER_MULTISIG: u8 = 20;
    match insn {
        bitcoin::script::Instruction::Op(op) => {
            let v = op.to_u8();
            (opcodes::OP_PUSHNUM_1.to_u8()..=opcodes::OP_PUSHNUM_16.to_u8())
                .contains(&v)
                .then(|| v - opcodes::OP_PUSHNUM_1.to_u8() + 1)
        }
        // `instructions_minimal` has already rejected a non-minimal push, so a
        // one-byte push reaching here is minimal by construction.
        bitcoin::script::Instruction::PushBytes(p) => match p.as_bytes() {
            [n] if *n > 16 && *n <= MAX_PUBKEYS_PER_MULTISIG => Some(*n),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checksums produced by Core's own reference implementation
    /// (`test/functional/test_framework/descriptors.py`, Pieter Wuille).
    /// The first row is also Core's `EXAMPLE_DESCRIPTOR_RAW` constant in
    /// `src/rpc/blockchain.cpp`, so the two agree independently.
    #[test]
    fn checksums_match_cores_reference_implementation() {
        let cases = [
            ("raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)", "fm24fxxy"),
            ("raw(51)", "8lvh9jxk"),
            ("raw()", "58lrscpx"),
            ("addr(bcrt1qxwj8ny5j8dz4rx0vqhcmzqsmv8h3zsjq5eqvrn)", "u9yvmetn"),
            ("addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)", "45hf9yxk"),
            (
                "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
                "gn28ywm7",
            ),
            (
                "multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,\
                 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)",
                "hzhjw406",
            ),
            (
                "rawtr(a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c)",
                "h9nmpf4q",
            ),
            (
                "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
                "lq9sf04s",
            ),
        ];
        for (payload, expected) in cases {
            // The multi() row above is a continued string literal; strip the
            // indentation the line continuation would otherwise embed.
            let payload = payload.replace(' ', "");
            assert_eq!(checksum(&payload).as_deref(), Some(expected), "{payload}");
            // And a descriptor carrying its own checksum round-trips.
            let with = format!("{payload}#{expected}");
            assert_eq!(strip_checksum(&with).unwrap(), payload);
        }
    }

    #[test]
    fn checksum_errors_match_core() {
        let good = "raw(51)#8lvh9jxk";
        assert!(strip_checksum(good).is_ok());
        // A descriptor with no checksum is accepted: Core's
        // `EvalDescriptorStringOrObject` parses with require_checksum=false.
        assert_eq!(strip_checksum("raw(51)").unwrap(), "raw(51)");
        assert_eq!(
            strip_checksum("raw(51)#8lvh9jxk#x").unwrap_err(),
            "Multiple '#' symbols"
        );
        assert_eq!(
            strip_checksum("raw(51)#abc").unwrap_err(),
            "Expected 8 character checksum, not 3 characters"
        );
        assert_eq!(
            strip_checksum("raw(51)#8lvh9jxq").unwrap_err(),
            "Provided checksum '8lvh9jxq' does not match computed checksum '8lvh9jxk'"
        );
        // 0x7f is outside INPUT_CHARSET.
        assert_eq!(
            strip_checksum("raw(5\u{7f}1)").unwrap_err(),
            "Invalid characters in payload"
        );
    }

    /// A one-character edit anywhere must change the checksum — the property
    /// the checksum exists for, and one a transposed constant would break.
    #[test]
    fn checksum_detects_single_character_substitutions() {
        let base = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)";
        let expected = checksum(base).unwrap();
        let mut changed = 0;
        for i in 0..base.len() {
            for repl in ['0', '9', 'a', 'f'] {
                let mut m: Vec<char> = base.chars().collect();
                if m[i] == repl {
                    continue;
                }
                m[i] = repl;
                let s: String = m.into_iter().collect();
                if let Some(c) = checksum(&s) {
                    assert_ne!(c, expected, "collision on edit at {i} -> {repl}");
                    changed += 1;
                }
            }
        }
        assert!(changed > 100, "expected many mutations, got {changed}");
    }

    fn script(hex_str: &str) -> ScriptBuf {
        ScriptBuf::from_bytes(hex::decode(hex_str).unwrap())
    }

    /// Vectors measured against Bitcoin Core 29.3: fund one output of each
    /// script type on regtest, then read what `scantxoutset` reports in
    /// `desc`. Every row is Core's actual answer, not a reading of
    /// `InferScript`.
    ///
    /// The empty-signing-provider cases are the interesting ones. `raw()`
    /// and `addr()` scan objects supply no keys, so the hash-committed
    /// scripts (p2pkh, p2sh, p2wpkh, p2wsh) cannot be named by key and come
    /// back as `addr()`.
    #[test]
    fn inference_matches_bitcoin_core() {
        let cases: &[(&str, &str)] = &[
            // Key-carrying scripts are named by key.
            ("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
             "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7"),
            ("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
             "pk(0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)#fsjyjr2x"),
            ("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
             "rawtr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#xsjqcczm"),
            ("51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae",
             "multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#l5sy3u48"),
            ("52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae",
             "multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#52kq63aa"),

            // Hash-committed scripts fall through to the address form.
            ("76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac",
             "addr(mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF)#csqdsq99"),
            ("a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3187",
             "addr(2MtrpPcsiWtFWjx5s3zCGJczVAE99BWkZwJ)#sx9nz3sr"),
            ("001411b366edfc0a8b66feebae5c2e25a7b6a5d1cf31",
             "addr(bcrt1qzxekdm0up29kdlht4ewzufd8k6jarne3636jrk)#s0c4m6g7"),
            ("0020a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
             "addr(bcrt1q5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqxl3r02)#swac23xe"),
            // Pay-to-anchor and an unknown witness version are still
            // addressable, so they are named that way rather than as raw.
            ("51024e73", "addr(bcrt1pfeesnyr2tx)#swxgse0y"),
            ("521411b366edfc0a8b66feebae5c2e25a7b6a5d1cf31",
             "addr(bcrt1zzxekdm0up29kdlht4ewzufd8k6jarne3ecdguz)#tu76kusy"),

            // A taproot output key that is not on the curve cannot be a
            // rawtr() key, but the output is still addressable.
            ("51200000000000000000000000000000000000000000000000000000000000000005",
             "addr(bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzssr24l3)#2a5jhpn9"),
            // A P2PK key that is well-formed but off the curve is still
            // named by key: Core checks the prefix and length, not the curve.
            ("21020000000000000000000000000000000000000000000000000000000000000005ac",
             "pk(020000000000000000000000000000000000000000000000000000000000000005)#2rnwvw4c"),
            // ... but a bad prefix, or a hybrid key, is not a key at all.
            ("21050000000000000000000000000000000000000000000000000000000000000005ac",
             "raw(21050000000000000000000000000000000000000000000000000000000000000005ac)#p0735ysy"),
            ("410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac",
             "raw(410679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac)#qhj9gd8d"),
            // One unusable key poisons the whole multisig inference.
            ("51210500000000000000000000000000000000000000000000000000000000000000052102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae",
             "raw(51210500000000000000000000000000000000000000000000000000000000000000052102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae)#d4v8smd4"),
            // An off-curve key does not, for the same reason as pk() above.
            ("51210200000000000000000000000000000000000000000000000000000000000000052102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae",
             "multi(1,020000000000000000000000000000000000000000000000000000000000000005,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#0wwgafnz"),

            // Neither a key nor an address.
            ("5151", "raw(5151)#xf09ykut"),
        ];
        for (spk, expected) in cases {
            assert_eq!(
                infer_descriptor(script(spk).as_script(), Network::Regtest),
                *expected,
                "script {spk}"
            );
        }
    }

    /// OP_RETURN outputs never enter the UTXO set, so the differential above
    /// cannot reach this branch on a live node. It is still what a caller
    /// gets if one is ever handed to the inferrer.
    #[test]
    fn unspendable_outputs_infer_as_raw() {
        assert_eq!(
            infer_descriptor(script("6a0548656c6c6f").as_script(), Network::Regtest),
            "raw(6a0548656c6c6f)#p5l78u99"
        );
    }

    /// The 16-key boundary of Core's `IsSmallInteger`: OP_16 is a threshold,
    /// anything above it is a push and stops being a multisig.
    #[test]
    fn bare_multisig_accepts_up_to_sixteen_keys() {
        const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let spk = format!("60 21{A}{}60ae", format!("21{B}").repeat(15)).replace(' ', "");
        let got = infer_descriptor(script(&spk).as_script(), Network::Regtest);
        assert!(got.starts_with("multi(16,"), "{got}");
        assert_eq!(got.matches(B).count(), 15);

        // Threshold above the key count is not a multisig.
        let bad = format!("5321{A}21{B}52ae");
        assert!(
            infer_descriptor(script(&bad).as_script(), Network::Regtest).starts_with("raw("),
        );
        // Nor is a key count that disagrees with the keys present.
        let bad2 = format!("5121{A}21{B}53ae");
        assert!(
            infer_descriptor(script(&bad2).as_script(), Network::Regtest).starts_with("raw("),
        );
    }

    /// The parser must refuse nesting Core refuses, which is what bounds its
    /// own recursion. Without the context rule a long enough `sh(sh(sh(...)))`
    /// exhausts the stack, and a Rust stack overflow aborts the process — it
    /// is not a catchable panic, so there is no recovering from it on an RPC
    /// any read-only caller can reach.
    /// Core's `addr()` decodes through `DecodeDestination`, which is
    /// chain-params-aware — an address for another network is simply not
    /// valid. Without the equivalent check `deriveaddresses` re-encodes the
    /// payload as the *current* network's twin and returns it as a real
    /// destination, which is a way to lose money.
    #[test]
    fn addr_descriptors_are_rejected_for_the_wrong_network() {
        // A regtest/signet bech32 address must not resolve on mainnet.
        let testnet_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let err = parse_descriptor(&format!("addr({testnet_addr})"), Network::Bitcoin)
            .expect_err("a testnet address must not be valid on mainnet");
        assert!(err.contains("Address is not valid"), "{err}");

        // And a mainnet address must not resolve on testnet.
        let mainnet_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let err = parse_descriptor(&format!("addr({mainnet_addr})"), Network::Testnet)
            .expect_err("a mainnet address must not be valid on testnet");
        assert!(err.contains("Address is not valid"), "{err}");

        // The matching network still works, and yields that address's script.
        let script = parse_descriptor(&format!("addr({mainnet_addr})"), Network::Bitcoin)
            .expect("a mainnet address on mainnet");
        let expected: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            mainnet_addr.parse().unwrap();
        assert_eq!(script, expected.assume_checked().script_pubkey());
    }

    #[test]
    fn descriptor_nesting_is_bounded_by_context_like_core() {
        const K: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // The pathological input. 20k levels is far below what a 10 MiB body
        // allows and far above what any stack survives.
        let deep = format!("{}raw(51){}", "sh(".repeat(20_000), ")".repeat(20_000));
        let err = parse_full_descriptor(&deep, false).unwrap_err();
        assert_eq!(err, "Can only have sh() at top level", "got {err}");

        // The three legal shapes still parse.
        for ok in [
            format!("sh(wsh(pkh({K})))"),
            format!("wsh(pkh({K}))"),
            format!("sh(wpkh({K}))"),
        ] {
            assert!(parse_full_descriptor(&ok, false).is_ok(), "{ok} should parse");
        }

        // wsh(wpkh(k)) builds a P2WSH whose witnessScript is itself a witness
        // program: it fails CLEANSTACK, so anything paid to that address is
        // unspendable. `deriveaddresses` is what people use to make receive
        // addresses, so accepting this loses money.
        assert_eq!(
            parse_full_descriptor(&format!("wsh(wpkh({K}))"), false).unwrap_err(),
            "Can only have wpkh() at top level or inside sh()"
        );
        for (desc, want) in [
            (format!("wsh(sh(pkh({K})))"), "Can only have sh() at top level"),
            ("sh(addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080))".to_string(),
             "Can only have addr() at top level"),
            ("wsh(raw(51))".to_string(), "Can only have raw() at top level"),
            (format!("sh(combo({K}))"), "Can only have combo() at top level"),
        ] {
            assert_eq!(parse_full_descriptor(&desc, false).unwrap_err(), want, "{desc}");
        }
    }

    /// Core's four multisig bounds, plus the two that depend on context. Each
    /// one it drops produces a descriptor whose coins cannot be spent.
    #[test]
    fn multisig_key_and_size_limits_match_core() {
        const K: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let keys = |n: usize| vec![K; n].join(",");

        // 21 keys: above MAX_PUBKEYS_PER_MULTISIG, so consensus-invalid.
        assert_eq!(
            parse_full_descriptor(&format!("wsh(multi(1,{}))", keys(21)), false).unwrap_err(),
            "Cannot have 21 keys in multisig; must have between 1 and 20 keys, inclusive"
        );
        // Threshold bounds.
        assert_eq!(
            parse_full_descriptor(&format!("wsh(multi(0,{K}))"), false).unwrap_err(),
            "Multisig threshold cannot be 0, must be at least 1"
        );
        assert!(
            parse_full_descriptor(&format!("wsh(multi(3,{}))", keys(2)), false)
                .unwrap_err()
                .starts_with("Multisig threshold cannot be larger than the number of keys")
        );
        // A leading '+' parses as a number in Rust but not in Core.
        assert_eq!(
            parse_full_descriptor(&format!("wsh(multi(+1,{K}))"), false).unwrap_err(),
            "Multi: threshold is not a valid number"
        );

        // Bare multisig above 3 keys is non-standard, so it would never relay.
        assert_eq!(
            parse_full_descriptor(&format!("multi(1,{})", keys(4)), false).unwrap_err(),
            "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys"
        );
        assert!(parse_full_descriptor(&format!("multi(1,{})", keys(3)), false).is_ok());

        // 16 compressed keys give a 547-byte redeemScript. Above the 520-byte
        // push limit it can never be supplied, so the coins are unspendable —
        // 15 is the most that fits.
        assert_eq!(
            parse_full_descriptor(&format!("sh(multi(1,{}))", keys(16)), false).unwrap_err(),
            "P2SH script is too large, 547 bytes is larger than 520 bytes"
        );
        assert!(parse_full_descriptor(&format!("sh(multi(1,{}))", keys(15)), false).is_ok());
        // The same 16 keys are fine under wsh(), which has no such cap.
        assert!(parse_full_descriptor(&format!("wsh(multi(1,{}))", keys(16)), false).is_ok());
    }

    /// A second multipath specifier used to walk off the end of the shorter
    /// one and panic out of the RPC handler.
    #[test]
    fn multipath_specifiers_are_refused_like_core() {
        const X: &str = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";

        // The panicking input: lengths 3 and 2.
        assert!(
            parse_full_descriptor(&format!("wpkh({X}/<0;1;2>/<0;1>/*)"), false)
                .unwrap_err()
                .contains("Multiple multipath key path specifiers found")
        );
        // Equal lengths silently returned 2 of 6 expansions; also refused.
        assert!(
            parse_full_descriptor(&format!("wpkh({X}/<0;1>/<2;3>/*)"), false)
                .unwrap_err()
                .contains("Multiple multipath key path specifiers found")
        );
        assert_eq!(
            parse_full_descriptor(&format!("wpkh({X}/<0>/*)"), false).unwrap_err(),
            "Multipath key path specifiers must have at least two items"
        );
        assert_eq!(
            parse_full_descriptor(&format!("wpkh({X}/<0;0>/*)"), false).unwrap_err(),
            "Duplicated key path value 0 in multipath specifier"
        );
        // One well-formed specifier still expands.
        assert!(parse_full_descriptor(&format!("wpkh({X}/<0;1>/*)"), false).is_ok());
    }

    /// An uncompressed key under a witness program is unspendable, so Core
    /// permits it only where no witness program will carry it.
    #[test]
    fn uncompressed_keys_are_refused_under_witness_programs() {
        const U: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

        assert!(parse_full_descriptor(&format!("pkh({U})"), false).is_ok());
        assert!(parse_full_descriptor(&format!("sh(pkh({U}))"), false).is_ok());
        for desc in [format!("wsh(pkh({U}))"), format!("wpkh({U})"), format!("sh(wpkh({U}))")] {
            assert!(
                parse_full_descriptor(&desc, false)
                    .unwrap_err()
                    .contains("Uncompressed keys are not allowed"),
                "{desc} should refuse an uncompressed key"
            );
        }
    }

    #[test]
    fn parses_raw_and_addr_descriptors() {
        let spk = "76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac";
        // With and without a checksum, and via the object form.
        for desc in [
            format!("raw({spk})"),
            format!("raw({spk})#fm24fxxy"),
        ] {
            assert_eq!(parse_descriptor(&desc, Network::Regtest).unwrap(), script(spk));
        }
        assert_eq!(
            parse_descriptor("addr(mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF)", Network::Regtest).unwrap(),
            script(spk)
        );

        assert_eq!(
            parse_descriptor("raw(nothex)", Network::Regtest).unwrap_err(),
            "Raw script is not hex"
        );
        assert_eq!(
            parse_descriptor("addr(not-an-address)", Network::Regtest).unwrap_err(),
            "Address is not valid"
        );
        // A mainnet address on a regtest node is not valid here.
        assert_eq!(
            parse_descriptor("addr(1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)", Network::Regtest)
                .unwrap_err(),
            "Address is not valid"
        );
    }

    /// An unimplemented descriptor must fail loudly. A scan that matched
    /// nothing and a scan that never understood the request look identical
    /// to the caller, so silence here is the dangerous outcome.
    #[test]
    fn unsupported_descriptors_are_named_not_ignored() {
        for desc in [
            "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
            "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
            "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
            "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
            "sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))",
            "multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        ] {
            let err = parse_descriptor(desc, Network::Regtest).unwrap_err();
            assert!(err.contains("does not implement"), "{desc}: {err}");
            let name = &desc[..desc.find('(').unwrap()];
            assert!(err.contains(name), "{desc}: {err} should name {name}");
        }
        // Something that is not a descriptor function at all reads as
        // malformed rather than unimplemented.
        let err = parse_descriptor("addrr(x)", Network::Regtest).unwrap_err();
        assert!(err.contains("not a valid descriptor function"), "{err}");
    }

    /// `raw()` with nothing in it is not "the empty script", it is a typo.
    /// Core's `IsHex` is false for the empty string and refuses it before any
    /// scanning; accepting it turned one token into a full pass over the UTXO
    /// set, holding the scan reservation for all of it.
    #[test]
    fn an_empty_raw_descriptor_is_refused_like_core() {
        assert_eq!(
            parse_descriptor("raw()", Network::Regtest).unwrap_err(),
            "Raw script is not hex"
        );
        assert_eq!(
            parse_descriptor("raw()#58lrscpx", Network::Regtest).unwrap_err(),
            "Raw script is not hex"
        );
        // An odd-length payload is Core's other `IsHex` rejection.
        assert_eq!(
            parse_descriptor("raw(5)", Network::Regtest).unwrap_err(),
            "Raw script is not hex"
        );
        // …and one real byte is still fine.
        assert_eq!(
            parse_descriptor("raw(51)", Network::Regtest).unwrap(),
            script("51")
        );
    }

    /// Consensus allows up to 20 keys, and 17..=20 cannot be spelled as a
    /// push-number opcode — Core reads both multisig integers through
    /// `GetScriptNumber`, which also accepts a minimal one-byte push. Reading
    /// only `OP_1..OP_16` named those outputs `raw()` instead of `multi()`.
    #[test]
    fn bare_multisig_reads_thresholds_above_sixteen() {
        const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // 17-of-17: `OP_PUSHBYTES_1 0x11 <17 keys> OP_PUSHBYTES_1 0x11 OP_CHECKMULTISIG`
        let keys = format!("21{A}").repeat(17);
        let spk = format!("0111{keys}0111ae");
        let got = infer_descriptor(script(&spk).as_script(), Network::Regtest);
        assert!(got.starts_with("multi(17,"), "{got}");
        assert_eq!(got.matches(A).count(), 17);

        // 20 is the ceiling; 21 is not a multisig.
        let keys20 = format!("21{A}").repeat(20);
        assert!(
            infer_descriptor(script(&format!("0114{keys20}0114ae")).as_script(), Network::Regtest)
                .starts_with("multi(20,")
        );
        let keys21 = format!("21{A}").repeat(21);
        assert!(
            infer_descriptor(script(&format!("0115{keys21}0115ae")).as_script(), Network::Regtest)
                .starts_with("raw(")
        );
    }

    /// Core validates the range's shape before it even parses the descriptor,
    /// so these fire regardless of whether the descriptor is ranged.
    #[test]
    fn range_is_validated_like_core() {
        let bad = |range: serde_json::Value, want: &str| {
            let obj = serde_json::json!({"desc": "raw(51)", "range": range});
            let (code, msg) = scan_object_to_scripts(&obj, Network::Regtest).unwrap_err();
            assert_eq!(code, -8, "{msg}");
            assert_eq!(msg, want);
        };
        // The five rows `rpc_scantxoutset.py` asserts, verbatim. Note a bare
        // `-1` becomes the range {0, -1}, so it is the *end* that is rejected.
        bad(serde_json::json!(-1), "End of range is too high");
        bad(serde_json::json!([-1, 10]), "Range should be greater or equal than 0");
        bad(
            serde_json::json!([(2i64 << 32) - 1_000_000, 2i64 << 32]),
            "End of range is too high",
        );
        bad(
            serde_json::json!([2, 1]),
            "Range specified as [begin,end] must not have begin after end",
        );
        bad(serde_json::json!([0, 1_000_001]), "Range is too large");
        bad(
            serde_json::json!("nope"),
            "Range must be specified as end or as [begin,end]",
        );
        bad(
            serde_json::json!([1, 2, 3]),
            "Range must be specified as end or as [begin,end]",
        );

        // A valid range is accepted and ignored: satd parses no ranged forms.
        for ok in [serde_json::json!(999), serde_json::json!([0, 999])] {
            let obj = serde_json::json!({"desc": "raw(51)", "range": ok});
            assert_eq!(
                scan_object_to_scripts(&obj, Network::Regtest).unwrap(),
                vec![script("51")]
            );
        }
    }

    #[test]
    fn scan_object_accepts_core_shapes() {
        let spk = "76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac";
        let want = vec![script(spk)];
        assert_eq!(
            scan_object_to_scripts(&serde_json::json!(format!("raw({spk})")), Network::Regtest)
                .unwrap(),
            want
        );
        // The object form, with a `range` that a non-ranged descriptor ignores.
        assert_eq!(
            scan_object_to_scripts(
                &serde_json::json!({"desc": format!("raw({spk})"), "range": 100}),
                Network::Regtest
            )
            .unwrap(),
            want
        );
        assert_eq!(
            scan_object_to_scripts(&serde_json::json!({"nope": 1}), Network::Regtest).unwrap_err(),
            (-8, "Descriptor needs to be provided in scan object".to_string())
        );
        assert_eq!(
            scan_object_to_scripts(&serde_json::json!(42), Network::Regtest).unwrap_err(),
            (-8, "Scan object needs to be either a string or an object".to_string())
        );
    }
}
