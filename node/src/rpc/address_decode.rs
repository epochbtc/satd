//! Bitcoin Core's address-decode diagnostics, for `validateaddress`.
//!
//! `validateaddress` answers `{"isvalid": false}` for anything it cannot
//! decode. Core answers *why*: an `error` string and, for a Bech32 string
//! whose checksum fails, an `error_locations` array pointing at the
//! characters most likely to be wrong. Wallets and address-entry UIs use both
//! ("did you mean…", highlighting the bad character), and `rpc_validateaddress`
//! / `rpc_invalid_address_message` assert every message literally.
//!
//! This is a port of `DecodeDestination` (`src/key_io.cpp`) and
//! `bech32::LocateErrors` (`src/bech32.cpp`) at Core v31.1. The error locator
//! is BCH decoding over GF(1024): the Bech32 generator is the least common
//! multiple of the minimal polynomials of three consecutive powers of a
//! primitive element, which makes the code distance-4 and lets a syndrome
//! identify up to two error positions. The two GF(1024) tables are *generated*
//! from the same defining polynomial Core uses (x^2 + 9x + 23 over GF(32),
//! itself x^5 + x^3 + 1 over GF(2)) rather than transcribed, so there is no
//! table to mistype.

use bitcoin::Network;
use bitcoin::hashes::Hash as _;

const CHECKSUM_SIZE: usize = 6;
const SEPARATOR: char = '1';
/// BIP173/350 character limit for a Bech32(m) address. Within it the code
/// guarantees finding up to 4 errors.
const CHAR_LIMIT: usize = 90;

const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, //
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, //
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, //
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, //
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, //
];

/// `GF1024_EXP[k] = (e)^k`, and `GF1024_LOG[GF1024_EXP[k]] = k`, for the
/// primitive element (e) of GF(1024) = GF(32)[x]/(x^2 + 9x + 23).
struct GfTables {
    exp: [i16; 1023],
    log: [i16; 1024],
}

fn gf_tables() -> &'static GfTables {
    static TABLES: std::sync::OnceLock<GfTables> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        // GF(32) = GF(2)[x]/(x^5 + x^3 + 1); 41 == 0b101001 packs that modulus.
        const FMOD: i32 = 41;
        let mut gf32_exp = [0i32; 31];
        let mut gf32_log = [-1i32; 32];
        gf32_exp[0] = 1;
        gf32_log[1] = 0;
        let mut v: i32 = 1;
        // Indexed rather than iterated: the loop writes `gf32_exp[i]` and
        // `gf32_log[v]`, two arrays keyed differently, so `i` is the value
        // being computed, not a cursor into one of them.
        #[allow(clippy::needless_range_loop)]
        for i in 1..31 {
            // Multiplying by x is a left shift; an x^5 term is reduced by
            // XORing the modulus (subtraction is XOR in characteristic 2).
            v <<= 1;
            if v & 32 != 0 {
                v ^= FMOD;
            }
            gf32_exp[i] = v;
            gf32_log[v as usize] = i as i32;
        }

        // An element of GF(1024) is v1 || v0, two GF(32) elements. (e) is
        // 1 || 0, so multiplying by (e) is
        //   v0' = 23*v1;  v1' = 9*v1 + v0.
        let mut exp = [0i16; 1023];
        let mut log = [-1i16; 1024];
        exp[0] = 1;
        log[1] = 0;
        let mut v: i32 = 1;
        let mul32 = |a: i32, b: i32| -> i32 {
            if a == 0 || b == 0 {
                0
            } else {
                gf32_exp[((gf32_log[a as usize] + gf32_log[b as usize]) % 31) as usize]
            }
        };
        #[allow(clippy::needless_range_loop)]
        for i in 1..1023usize {
            let v0 = v & 31;
            let v1 = v >> 5;
            let v0n = mul32(v1, 23);
            let v1n = mul32(v1, 9) ^ v0;
            v = v1n << 5 | v0n;
            exp[i] = v as i16;
            log[v as usize] = i as i16;
        }
        GfTables { exp, log }
    })
}

fn syndrome_consts() -> &'static [u32; 25] {
    static CONSTS: std::sync::OnceLock<[u32; 25]> = std::sync::OnceLock::new();
    CONSTS.get_or_init(|| {
        let t = gf_tables();
        let mut c = [0u32; 25];
        for k in 1..6i32 {
            for shift in 0..5i32 {
                let b = i32::from(t.log[1usize << shift]);
                let c0 = i32::from(t.exp[((997 * k + b) % 1023) as usize]);
                let c1 = i32::from(t.exp[((998 * k + b) % 1023) as usize]);
                let c2 = i32::from(t.exp[((999 * k + b) % 1023) as usize]);
                c[(5 * (k - 1) + shift) as usize] =
                    ((c2 as u32) << 20) | ((c1 as u32) << 10) | c0 as u32;
            }
        }
        c
    })
}

fn poly_mod(v: &[u8]) -> u32 {
    let mut c: u32 = 1;
    for &vi in v {
        let c0 = (c >> 25) as u8;
        c = ((c & 0x01ff_ffff) << 5) ^ u32::from(vi);
        if c0 & 1 != 0 {
            c ^= 0x3b6a_57b2;
        }
        if c0 & 2 != 0 {
            c ^= 0x2650_8e6d;
        }
        if c0 & 4 != 0 {
            c ^= 0x1ea1_19fa;
        }
        if c0 & 8 != 0 {
            c ^= 0x3d42_33dd;
        }
        if c0 & 16 != 0 {
            c ^= 0x2a14_62b3;
        }
    }
    c
}

/// `s_997`, `s_998`, `s_999` packed into three 10-bit groups.
fn syndrome(residue: u32) -> u32 {
    let low = residue & 0x1f;
    let mut result = low ^ (low << 10) ^ (low << 20);
    let consts = syndrome_consts();
    for (i, k) in consts.iter().enumerate() {
        if (residue >> (5 + i)) & 1 != 0 {
            result ^= k;
        }
    }
    result
}

fn expand_hrp(hrp: &str, values: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(hrp.len() * 2 + 1 + values.len());
    for b in hrp.bytes() {
        ret.push(b >> 5);
    }
    ret.push(0);
    for b in hrp.bytes() {
        ret.push(b & 0x1f);
    }
    ret.extend_from_slice(values);
    ret
}

/// Core's `CheckCharacters`: every character must be printable ASCII, and the
/// string must not mix cases. Returns the offending indices.
fn check_characters(s: &str) -> Vec<usize> {
    let mut errors = Vec::new();
    let (mut lower, mut upper) = (false, false);
    for (i, c) in s.bytes().enumerate() {
        if c.is_ascii_lowercase() {
            if upper {
                errors.push(i);
            } else {
                lower = true;
            }
        } else if c.is_ascii_uppercase() {
            if lower {
                errors.push(i);
            } else {
                upper = true;
            }
        } else if !(33..=126).contains(&c) {
            errors.push(i);
        }
    }
    errors
}

/// Core's `bech32::LocateErrors`. Returns the diagnostic and the 0-based
/// character indices most likely to be wrong.
pub fn locate_errors(s: &str) -> (String, Vec<usize>) {
    if s.len() > CHAR_LIMIT {
        return (
            "Bech32 string too long".to_string(),
            (CHAR_LIMIT..s.len()).collect(),
        );
    }
    let bad = check_characters(s);
    if !bad.is_empty() {
        return ("Invalid character or mixed case".to_string(), bad);
    }
    let Some(pos) = s.rfind(SEPARATOR) else {
        return ("Missing separator".to_string(), Vec::new());
    };
    if pos == 0 || pos + CHECKSUM_SIZE >= s.len() {
        return ("Invalid separator position".to_string(), vec![pos]);
    }

    let hrp: String = s[..pos].to_ascii_lowercase();
    let length = s.len() - 1 - pos;
    let mut values = vec![0u8; length];
    for (i, c) in s.as_bytes()[pos + 1..].iter().enumerate() {
        let rev = CHARSET_REV.get(*c as usize).copied().unwrap_or(-1);
        if rev == -1 {
            return ("Invalid Base 32 character".to_string(), vec![pos + 1 + i]);
        }
        values[i] = rev as u8;
    }

    let t = gf_tables();
    let mut error_locations: Vec<usize> = Vec::new();
    // Which encoding produced the best (fewest-error) explanation, if any.
    let mut error_encoding: Option<u32> = None;

    // Try both checksum constants and keep whichever explains the string with
    // fewer errors: the witness version is itself a candidate error, so it
    // cannot be used to pick the encoding.
    for encoding_const in [1u32, 0x2bc8_30a3] {
        let mut possible: Vec<usize> = Vec::new();
        let enc = expand_hrp(&hrp, &values);
        let residue = poly_mod(&enc) ^ encoding_const;
        if residue == 0 {
            // This encoding checks out: the string is not in error at all.
            return (String::new(), Vec::new());
        }

        let syn = syndrome(residue);
        let s0 = (syn & 0x3ff) as usize;
        let s1 = ((syn >> 10) & 0x3ff) as usize;
        let s2 = (syn >> 20) as usize;
        let l_s0 = i32::from(t.log[s0]);
        let l_s1 = i32::from(t.log[s1]);
        let l_s2 = i32::from(t.log[s2]);

        // One error: E(x) = e1*x^p1, so s1^2 == s0*s2.
        if l_s0 != -1 && l_s1 != -1 && l_s2 != -1 && (2 * l_s1 - l_s2 - l_s0 + 2046) % 1023 == 0 {
            let p1 = ((l_s1 - l_s0 + 1023) % 1023) as usize;
            let l_e1 = l_s0 + (1023 - 997) * p1 as i32;
            // e1 must land inside the data part and inside GF(32) -- the 31
            // non-zero elements of GF(32) are the index-33 subgroup of
            // GF(1024)'s 1023.
            if p1 < length && l_e1 % 33 == 0 {
                possible.push(s.len() - p1 - 1);
            }
        } else {
            // Two errors: guess p1, solve for p2.
            for p1 in 0..length {
                let s2_s1p1 = s2
                    ^ if s1 == 0 {
                        0
                    } else {
                        usize::try_from(t.exp[((l_s1 + p1 as i32) % 1023) as usize]).unwrap_or(0)
                    };
                if s2_s1p1 == 0 {
                    continue;
                }
                let l_s2_s1p1 = i32::from(t.log[s2_s1p1]);

                let s1_s0p1 = s1
                    ^ if s0 == 0 {
                        0
                    } else {
                        usize::try_from(t.exp[((l_s0 + p1 as i32) % 1023) as usize]).unwrap_or(0)
                    };
                if s1_s0p1 == 0 {
                    continue;
                }
                let l_s1_s0p1 = i32::from(t.log[s1_s0p1]);

                let p2 = ((l_s2_s1p1 - l_s1_s0p1 + 1023) % 1023) as usize;
                if p2 >= length || p1 == p2 {
                    continue;
                }

                let s1_s0p2 = s1
                    ^ if s0 == 0 {
                        0
                    } else {
                        usize::try_from(t.exp[((l_s0 + p2 as i32) % 1023) as usize]).unwrap_or(0)
                    };
                if s1_s0p2 == 0 {
                    continue;
                }
                let l_s1_s0p2 = i32::from(t.log[s1_s0p2]);

                let inv_p1_p2 = 1023
                    - i32::from(
                        t.log[(t.exp[p1] ^ t.exp[p2]) as usize],
                    );
                let l_e2 = l_s1_s0p1 + inv_p1_p2 + (1023 - 997) * p2 as i32;
                if l_e2 % 33 != 0 {
                    continue;
                }
                let l_e1 = l_s1_s0p2 + inv_p1_p2 + (1023 - 997) * p1 as i32;
                if l_e1 % 33 != 0 {
                    continue;
                }

                // Report positions left to right. Core deliberately does not
                // report the error *values*: suggesting a correction for an
                // address is dangerous.
                if p1 > p2 {
                    possible.push(s.len() - p1 - 1);
                    possible.push(s.len() - p2 - 1);
                } else {
                    possible.push(s.len() - p2 - 1);
                    possible.push(s.len() - p1 - 1);
                }
                break;
            }
        }

        if error_locations.is_empty()
            || (!possible.is_empty() && possible.len() < error_locations.len())
        {
            error_locations = possible;
            if !error_locations.is_empty() {
                error_encoding = Some(encoding_const);
            }
        }
    }

    let message = match error_encoding {
        Some(0x2bc8_30a3) => "Invalid Bech32m checksum",
        Some(_) => "Invalid Bech32 checksum",
        None => "Invalid checksum",
    };
    (message.to_string(), error_locations)
}

/// What `validateaddress` learned about a string.
pub enum Decoded {
    /// A valid destination on this network.
    Valid(bitcoin::Address),
    /// Not a destination here. Core's `error_str`, plus the character
    /// positions it could attribute (empty for everything but a Bech32
    /// checksum failure).
    Invalid { error: String, locations: Vec<usize> },
}

fn bech32_hrp(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bc",
        Network::Regtest => "bcrt",
        _ => "tb",
    }
}

/// Core's `CChainParams::Base58Prefix` for PUBKEY_ADDRESS and SCRIPT_ADDRESS.
fn base58_prefixes(network: Network) -> (u8, u8) {
    match network {
        Network::Bitcoin => (0, 5),
        _ => (111, 196),
    }
}

/// Verify a Bech32(m) checksum, returning which constant it satisfied.
/// `None` is Core's `Encoding::INVALID`.
fn verify_checksum(hrp: &str, values: &[u8]) -> Option<u32> {
    let residue = poly_mod(&expand_hrp(hrp, values));
    match residue {
        1 => Some(1),
        0x2bc8_30a3 => Some(0x2bc8_30a3),
        _ => None,
    }
}

/// Core's `bech32::Decode`: `(encoding_const, hrp, data)` with the checksum
/// symbols stripped, or `None` for anything that does not decode at all.
fn bech32_decode(s: &str) -> Option<(u32, String, Vec<u8>)> {
    if !check_characters(s).is_empty() || s.len() > CHAR_LIMIT {
        return None;
    }
    let pos = s.rfind(SEPARATOR)?;
    if pos == 0 || pos + CHECKSUM_SIZE >= s.len() {
        return None;
    }
    let mut values = Vec::with_capacity(s.len() - 1 - pos);
    for c in s.as_bytes()[pos + 1..].iter() {
        let rev = CHARSET_REV.get(*c as usize).copied().unwrap_or(-1);
        if rev == -1 {
            return None;
        }
        values.push(rev as u8);
    }
    let hrp = s[..pos].to_ascii_lowercase();
    let encoding = verify_checksum(&hrp, &values)?;
    values.truncate(values.len() - CHECKSUM_SIZE);
    Some((encoding, hrp, values))
}

/// Core's `ConvertBits<5, 8, false>`: repack 5-bit symbols as bytes, refusing
/// non-zero padding or a padding run of 5 bits or more.
fn convert_bits_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    for &v in data {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        return None;
    }
    Some(out)
}

/// Core's `DecodeDestination(str, params, error_str, error_locations)`
/// (`src/key_io.cpp` at v31.1), reproduced branch for branch.
///
/// The network matters twice over: a string is only *treated* as Bech32 when
/// its prefix matches this network's HRP -- so a `bc1…` on regtest falls
/// through to the Base58 path and reports an encoding error, exactly as Core
/// does -- and a Base58 address only decodes with this network's version
/// bytes.
///
/// satd's previous implementation parsed `NetworkUnchecked` and called
/// `assume_checked()`, so it reported a mainnet address as valid on regtest.
pub fn decode_destination(s: &str, network: Network) -> Decoded {
    let hrp = bech32_hrp(network);
    let is_bech32 = s.len() >= hrp.len() && s[..hrp.len()].eq_ignore_ascii_case(hrp);
    let (pubkey_prefix, script_prefix) = base58_prefixes(network);

    if !is_bech32 {
        // Core calls `DecodeBase58Check(str, data, 21)`: the *decoded payload*
        // is capped at 21 bytes, and exceeding it is a decode failure, not a
        // long address. `rust-bitcoin` has no such cap, so apply it here --
        // without it a 50-character string whose first byte happens to match a
        // version prefix gets the wrong message.
        match bitcoin::base58::decode_check(s).map_err(|_| ()).and_then(|d| {
            if d.len() <= 21 { Ok(d) } else { Err(()) }
        }) {
            Ok(data) if data.len() == 21 => {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&data[1..]);
                if data[0] == pubkey_prefix {
                    let h = bitcoin::PubkeyHash::from(bitcoin::hashes::hash160::Hash::from_byte_array(hash));
                    return Decoded::Valid(bitcoin::Address::p2pkh(h, network));
                }
                if data[0] == script_prefix {
                    let h = bitcoin::ScriptHash::from(bitcoin::hashes::hash160::Hash::from_byte_array(hash));
                    return Decoded::Valid(bitcoin::Address::p2sh_from_hash(h, network));
                }
                return Decoded::Invalid {
                    error: "Invalid or unsupported Base58-encoded address.".to_string(),
                    locations: Vec::new(),
                };
            }
            Ok(data) => {
                // Core: right prefix, wrong length is a length error;
                // anything else is an unsupported address.
                let error = if data.first() == Some(&pubkey_prefix)
                    || data.first() == Some(&script_prefix)
                {
                    "Invalid length for Base58 address (P2PKH or P2SH)"
                } else {
                    "Invalid or unsupported Base58-encoded address."
                };
                return Decoded::Invalid { error: error.to_string(), locations: Vec::new() };
            }
            Err(_) => {
                // Core retries the decode without the checksum and with a
                // much larger length cap: a string that is Base58 at all gets
                // the checksum message, one that is not gets the encoding
                // message.
                let error = match bitcoin::base58::decode(s) {
                    Ok(d) if d.len() <= 100 => {
                        "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
                    }
                    _ => "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
                };
                return Decoded::Invalid { error: error.to_string(), locations: Vec::new() };
            }
        }
    }

    let Some((encoding, dec_hrp, data5)) = bech32_decode(s) else {
        // Not decodable: this is where Core runs the error locator.
        let (error, locations) = locate_errors(s);
        return Decoded::Invalid { error, locations };
    };

    if data5.is_empty() {
        return Decoded::Invalid {
            error: "Empty Bech32 data section".to_string(),
            locations: Vec::new(),
        };
    }
    if dec_hrp != hrp {
        return Decoded::Invalid {
            error: format!(
                "Invalid or unsupported prefix for Segwit (Bech32) address (expected {hrp}, got {dec_hrp})."
            ),
            locations: Vec::new(),
        };
    }

    const BECH32: u32 = 1;
    const BECH32M: u32 = 0x2bc8_30a3;
    let version = data5[0];
    if version == 0 && encoding != BECH32 {
        return Decoded::Invalid {
            error: "Version 0 witness address must use Bech32 checksum".to_string(),
            locations: Vec::new(),
        };
    }
    if version != 0 && encoding != BECH32M {
        return Decoded::Invalid {
            error: "Version 1+ witness address must use Bech32m checksum".to_string(),
            locations: Vec::new(),
        };
    }

    let Some(program) = convert_bits_5_to_8(&data5[1..]) else {
        return Decoded::Invalid {
            error: "Invalid padding in Bech32 data section".to_string(),
            locations: Vec::new(),
        };
    };
    let byte_str = if program.len() == 1 { "byte" } else { "bytes" };

    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Decoded::Invalid {
            error: format!(
                "Invalid Bech32 v0 address program size ({} {byte_str}), per BIP141",
                program.len()
            ),
            locations: Vec::new(),
        };
    }
    // Core checks P2A (v1, {0x4e,0x73}) before the witness-version bound, so
    // the ordering below matches: v1/32 first, then P2A, then version > 16.
    let is_p2a = version == 1 && program == [0x4e, 0x73];
    if version > 16 && !is_p2a {
        return Decoded::Invalid {
            error: "Invalid Bech32 address witness version".to_string(),
            locations: Vec::new(),
        };
    }
    let taproot = version == 1 && program.len() == 32;
    if !taproot && !is_p2a && !(2..=40).contains(&program.len()) {
        return Decoded::Invalid {
            error: format!("Invalid Bech32 address program size ({} {byte_str})", program.len()),
            locations: Vec::new(),
        };
    }

    let Ok(wv) = bitcoin::WitnessVersion::try_from(version) else {
        return Decoded::Invalid {
            error: "Invalid Bech32 address witness version".to_string(),
            locations: Vec::new(),
        };
    };
    match bitcoin::WitnessProgram::new(wv, &program) {
        Ok(wp) => Decoded::Valid(bitcoin::Address::from_witness_program(wp, network)),
        Err(_) => Decoded::Invalid {
            error: format!("Invalid Bech32 address program size ({} {byte_str})", program.len()),
            locations: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors are Core's own, from `test/functional/rpc_invalid_address_message.py`
    /// at v31.1 -- the same strings and the same expected positions.
    #[test]
    fn error_locations_match_core() {
        let cases: &[(&str, &str, &[usize])] = &[
            (
                "bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23m",
                "Bech32 string too long",
                &[90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107],
            ),
            ("bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv", "Invalid Bech32 checksum", &[9]),
            ("bcrt1qax9suht3qv95sw33xavx8crpxduefdrsvgsklu", "Invalid Bech32 checksum", &[22, 43]),
            ("BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U32RAH7R", "Invalid Bech32 checksum", &[38]),
            ("bcrtq049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv", "Missing separator", &[]),
            ("bcrt1q04oldschfnwystcqnsvyfpj23mpsg3jcedq9xv", "Invalid Base 32 character", &[8]),
            (
                "bcrt1qdg3myrgvzw7ml8q0ejxhlkyxn7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks",
                "Invalid Bech32 checksum",
                &[19, 30],
            ),
            ("bcrt1ptmp74ayg7p24uslctssvjm06q5phz4yrxucgnv", "Invalid Bech32 checksum", &[5]),
        ];
        for (addr, want_msg, want_pos) in cases {
            let (msg, pos) = locate_errors(addr);
            assert_eq!(&msg, want_msg, "message for {addr}");
            assert_eq!(pos, want_pos.to_vec(), "locations for {addr}");
        }
    }

    /// A well-formed address has no errors to locate.
    #[test]
    fn a_valid_address_locates_no_errors() {
        let (msg, pos) = locate_errors("bcrt1qtmp74ayg7p24uslctssvjm06q5phz4yrxucgnv");
        assert_eq!(msg, "");
        assert!(pos.is_empty());
    }

    /// The defect this module was written for: satd parsed `NetworkUnchecked`
    /// and called `assume_checked()`, so a mainnet address validated on
    /// regtest.
    #[test]
    fn an_address_for_another_network_is_not_valid_here() {
        // A mainnet P2SH address (`wallet_disable.py` uses this exact one).
        let m = decode_destination("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Network::Regtest);
        assert!(matches!(m, Decoded::Invalid { .. }), "mainnet P2SH must not validate on regtest");
        // ... and the regtest one it pairs with must still validate.
        let r = decode_destination("mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ", Network::Regtest);
        assert!(matches!(r, Decoded::Valid(_)), "regtest P2PKH must validate on regtest");
        // A mainnet bech32 string on regtest: the HRP does not match, so Core
        // routes it to the Base58 path and reports an encoding error.
        let b = decode_destination(
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            Network::Regtest,
        );
        match b {
            Decoded::Invalid { error, .. } => assert_eq!(
                error,
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding."
            ),
            Decoded::Valid(_) => panic!("a mainnet bech32 address must not validate on regtest"),
        }
    }

    /// Core's messages for the Base58 failures, from the same test file.
    #[test]
    fn base58_errors_match_core() {
        for (addr, want) in [
            (
                "17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem",
                "Invalid or unsupported Base58-encoded address.",
            ),
            (
                "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJJfn",
                "Invalid checksum or length of Base58 address (P2PKH or P2SH)",
            ),
            (
                "2VKf7XKMrp4bVNVmuRbyCewkP8FhGLP2E54LHDPakr9Sq5mtU2",
                "Invalid checksum or length of Base58 address (P2PKH or P2SH)",
            ),
            (
                "asfah14i8fajz0123f",
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
            ),
            (
                "1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv",
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
            ),
        ] {
            match decode_destination(addr, Network::Regtest) {
                Decoded::Invalid { error, locations } => {
                    assert_eq!(error, want, "message for {addr}");
                    assert!(locations.is_empty(), "Base58 failures carry no locations");
                }
                Decoded::Valid(_) => panic!("{addr} must not validate"),
            }
        }
    }

    /// Core's messages for the Bech32 shape failures (not checksum errors).
    #[test]
    fn bech32_shape_errors_match_core() {
        for (addr, want) in [
            (
                "bcrt1s0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav25430mtr",
                "Invalid Bech32 address program size (41 bytes)",
            ),
            (
                "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqdmchcc",
                "Version 1+ witness address must use Bech32m checksum",
            ),
            (
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k35mrzd",
                "Version 0 witness address must use Bech32 checksum",
            ),
            (
                "bcrt130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqynjegk",
                "Invalid Bech32 address witness version",
            ),
            (
                "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kqqq5k3my",
                "Invalid Bech32 v0 address program size (21 bytes), per BIP141",
            ),
        ] {
            match decode_destination(addr, Network::Regtest) {
                Decoded::Invalid { error, .. } => assert_eq!(error, want, "message for {addr}"),
                Decoded::Valid(_) => panic!("{addr} must not validate"),
            }
        }
    }

    #[test]
    fn core_s_valid_regtest_addresses_still_validate() {
        for addr in [
            "bcrt1qtmp74ayg7p24uslctssvjm06q5phz4yrxucgnv",
            "bcrt1p424qxxyd0r",
            "BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U33RAH7R",
            "bcrt1qdg3myrgvzw7ml9q0ejxhlkyxm7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks",
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        ] {
            assert!(
                matches!(decode_destination(addr, Network::Regtest), Decoded::Valid(_)),
                "{addr} must validate on regtest"
            );
        }
    }
}
