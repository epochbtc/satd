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

/// Turn one element of `scanobjects` into the output scripts to search
/// for. Core's `EvalDescriptorStringOrObject`, minus the ranged forms —
/// nothing satd parses is a ranged descriptor, so `range` is accepted and
/// ignored exactly as Core ignores it for a non-range descriptor.
pub fn scan_object_to_scripts(
    obj: &serde_json::Value,
    network: Network,
) -> Result<Vec<ScriptBuf>, (i32, String)> {
    let desc = match obj {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(map) => match map.get("desc") {
            Some(serde_json::Value::String(s)) => s.as_str(),
            Some(_) | None => {
                return Err((
                    RPC_INVALID_PARAMETER,
                    "Descriptor needs to be provided in scan object".to_string(),
                ));
            }
        },
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

/// Core's `IsSmallInteger` + `DecodeOP_N`: OP_1..OP_16 only.
fn small_int(insn: bitcoin::script::Instruction<'_>) -> Option<u8> {
    match insn {
        bitcoin::script::Instruction::Op(op) => {
            let v = op.to_u8();
            (opcodes::OP_PUSHNUM_1.to_u8()..=opcodes::OP_PUSHNUM_16.to_u8())
                .contains(&v)
                .then(|| v - opcodes::OP_PUSHNUM_1.to_u8() + 1)
        }
        _ => None,
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
