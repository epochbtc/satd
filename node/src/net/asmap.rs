//! ASN lookup from a Bitcoin Core `-asmap` file (BIP-less, Core's
//! `util/asmap.cpp` format). The file is a bit-serialized binary trie
//! that maps an IP address to the Autonomous System Number (ASN) that
//! announces it. satd uses the ASN as the addrman *network group* so that
//! bucketing — and therefore eclipse resistance — is per-AS rather than
//! per-`/16`, matching Bitcoin Core.
//!
//! The interpreter is a direct port of Core's `Interpret` / `DecodeBits`;
//! `interpret` is exposed for direct testing against constructed
//! bitstreams (a test-only encoder round-trips it).

use std::net::IpAddr;

/// Trie opcodes (Core's `Instruction`).
const RETURN: u32 = 0;
const JUMP: u32 = 1;
const MATCH: u32 = 2;
const DEFAULT: u32 = 3;

const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];
const ASN_BIT_SIZES: &[u8] = &[
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const MATCH_BIT_SIZES: &[u8] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

const INVALID: u32 = u32::MAX;

/// A cursor over the asmap bitstream.
struct Bits<'a> {
    data: &'a [bool],
    pos: usize,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [bool]) -> Self {
        Self { data, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn next(&mut self) -> Option<bool> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

/// Core's `DecodeBits`: a prefix-coded variable-length integer.
fn decode_bits(bits: &mut Bits, minval: u32, bit_sizes: &[u8]) -> u32 {
    let mut val = minval;
    for (i, &bs) in bit_sizes.iter().enumerate() {
        let bit = if i + 1 != bit_sizes.len() {
            match bits.next() {
                Some(b) => b,
                None => return INVALID,
            }
        } else {
            false
        };
        if bit {
            val = val.wrapping_add(1u32 << bs);
        } else {
            for b in 0..bs {
                let bit = match bits.next() {
                    Some(x) => x,
                    None => return INVALID,
                };
                if bit {
                    val = val.wrapping_add(1u32 << (bs - 1 - b));
                }
            }
            return val;
        }
    }
    INVALID
}

fn decode_type(bits: &mut Bits) -> u32 {
    decode_bits(bits, 0, TYPE_BIT_SIZES)
}
fn decode_asn(bits: &mut Bits) -> u32 {
    decode_bits(bits, 1, ASN_BIT_SIZES)
}
fn decode_match(bits: &mut Bits) -> u32 {
    decode_bits(bits, 2, MATCH_BIT_SIZES)
}
fn decode_jump(bits: &mut Bits) -> u32 {
    decode_bits(bits, 5, JUMP_BIT_SIZES)
}

/// Bits needed to represent `x` (Core's `CountBits`): position of the
/// highest set bit, plus one. `CountBits(0) == 0`.
fn count_bits(x: u32) -> u32 {
    32 - x.leading_zeros()
}

/// Interpret the asmap bitstream for `ip_bits` (the address as a
/// big-endian bit vector). Returns the ASN, or 0 for "unknown".
pub fn interpret(asmap: &[bool], ip_bits: &[bool]) -> u32 {
    let mut bits = Bits::new(asmap);
    let total = ip_bits.len();
    let mut remaining = total; // IP bits still to consume
    let mut default_asn: u32 = 0;

    while !bits.at_end() {
        let opcode = decode_type(&mut bits);
        if opcode == RETURN {
            return decode_asn(&mut bits);
        } else if opcode == JUMP {
            let jump = decode_jump(&mut bits);
            if jump == INVALID || remaining == 0 {
                break;
            }
            let bit = ip_bits[total - remaining];
            if bit {
                if (jump as usize) > bits.remaining() {
                    break;
                }
                bits.pos += jump as usize;
            }
            remaining -= 1;
        } else if opcode == MATCH {
            let m = decode_match(&mut bits);
            if m == INVALID {
                break;
            }
            let matchlen = count_bits(m) - 1;
            if (remaining as u32) < matchlen {
                break;
            }
            let mut mismatch = false;
            for b in 0..matchlen {
                let want = (m >> (matchlen - 1 - b)) & 1 == 1;
                if ip_bits[total - remaining] != want {
                    mismatch = true;
                    break;
                }
                remaining -= 1;
            }
            if mismatch {
                return default_asn;
            }
        } else if opcode == DEFAULT {
            let d = decode_asn(&mut bits);
            if d == INVALID {
                break;
            }
            default_asn = d;
        } else {
            break;
        }
    }
    0
}

/// Convert an IP address to its 128-bit big-endian bit vector (IPv4 is
/// represented as IPv4-mapped, matching how asmap files are built).
pub fn ip_to_bits(ip: IpAddr) -> Vec<bool> {
    let octets: [u8; 16] = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut bits = Vec::with_capacity(128);
    for byte in octets {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// A loaded asmap file.
pub struct AsMap {
    bits: Vec<bool>,
}

impl AsMap {
    /// Build from the raw file bytes (each byte expands to 8 bits,
    /// most-significant first).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for &byte in bytes {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        Self { bits }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("reading asmap {}: {e}", path.display()))?;
        if bytes.is_empty() {
            return Err(format!("asmap {} is empty", path.display()));
        }
        Ok(Self::from_bytes(&bytes))
    }

    /// Look up the ASN for `ip` (0 = unknown / not in the map).
    pub fn lookup(&self, ip: IpAddr) -> u32 {
        interpret(&self.bits, &ip_to_bits(ip))
    }

    /// addrman network-group key for `ip`: the ASN's bytes when known,
    /// else a `/16`-style fallback so unmapped addresses still bucket
    /// sensibly.
    pub fn group_key(&self, ip: IpAddr) -> Vec<u8> {
        let asn = self.lookup(ip);
        if asn != 0 {
            // Tag ASN groups distinctly from the v4 /16 fallback.
            let mut k = vec![0xA0];
            k.extend_from_slice(&asn.to_be_bytes());
            k
        } else {
            match ip {
                IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
                IpAddr::V6(v6) => v6.octets()[..4].to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- test-only encoder (round-trips the decoder) ------------------

    fn enc_bits(out: &mut Vec<bool>, val: u32, minval: u32, bit_sizes: &[u8]) {
        // Find the smallest ladder entry that can represent (val - minval).
        let delta = val - minval;
        let mut acc = 0u32;
        for (i, &bs) in bit_sizes.iter().enumerate() {
            let span = 1u32 << bs;
            if delta < acc + span || i + 1 == bit_sizes.len() {
                if i + 1 != bit_sizes.len() {
                    out.push(false); // selector bit: stop here
                }
                let rem = delta - acc;
                for b in 0..bs {
                    out.push((rem >> (bs - 1 - b)) & 1 == 1);
                }
                return;
            }
            out.push(true); // selector bit: advance ladder
            acc += span;
        }
    }

    fn enc_type(out: &mut Vec<bool>, t: u32) {
        enc_bits(out, t, 0, TYPE_BIT_SIZES);
    }
    fn enc_asn(out: &mut Vec<bool>, asn: u32) {
        enc_bits(out, asn, 1, ASN_BIT_SIZES);
    }
    fn enc_jump(out: &mut Vec<bool>, j: u32) {
        enc_bits(out, j, 5, JUMP_BIT_SIZES);
    }

    fn ret(asn: u32) -> Vec<bool> {
        let mut v = Vec::new();
        enc_type(&mut v, RETURN);
        enc_asn(&mut v, asn);
        v
    }

    #[test]
    fn single_return_maps_everything() {
        let asmap = ret(12345);
        // Any ip_bits → 12345.
        assert_eq!(interpret(&asmap, &[false; 128]), 12345);
        assert_eq!(interpret(&asmap, &[true; 128]), 12345);
        assert_eq!(interpret(&asmap, &ip_to_bits("8.8.8.8".parse().unwrap())), 12345);
    }

    #[test]
    fn jump_branches_on_first_bit() {
        // root JUMP: if first ip bit == 1, skip the left RETURN(A) and
        // fall into RETURN(B); if 0, take RETURN(A).
        let left = ret(111);
        let right = ret(222);
        let mut asmap = Vec::new();
        enc_type(&mut asmap, JUMP);
        enc_jump(&mut asmap, left.len() as u32); // skip the left branch
        asmap.extend_from_slice(&left);
        asmap.extend_from_slice(&right);

        let mut ip0 = vec![false; 128];
        ip0[0] = false;
        assert_eq!(interpret(&asmap, &ip0), 111, "first bit 0 → left");

        let mut ip1 = vec![false; 128];
        ip1[0] = true;
        assert_eq!(interpret(&asmap, &ip1), 222, "first bit 1 → right");
    }

    #[test]
    fn default_then_truncated_returns_default_on_match_fail() {
        // DEFAULT(99) then a MATCH that requires the next bit to be 1.
        let mut asmap = Vec::new();
        enc_type(&mut asmap, DEFAULT);
        enc_asn(&mut asmap, 99);
        // MATCH for the single bit "1": match value = 0b1<sentinel> = 0b11 = 3
        // (CountBits(3)-1 = 1 bit, value's low bit = 1).
        enc_type(&mut asmap, MATCH);
        enc_bits(&mut asmap, 3, 2, MATCH_BIT_SIZES);
        enc_type(&mut asmap, RETURN);
        enc_asn(&mut asmap, 7);

        // first bit 1 → MATCH passes → RETURN 7
        let mut ip1 = vec![false; 128];
        ip1[0] = true;
        assert_eq!(interpret(&asmap, &ip1), 7);

        // first bit 0 → MATCH fails → returns the default (99)
        let ip0 = vec![false; 128];
        assert_eq!(interpret(&asmap, &ip0), 99);
    }

    #[test]
    fn ip_to_bits_is_128_and_v4_mapped() {
        let b = ip_to_bits("0.0.0.0".parse().unwrap());
        assert_eq!(b.len(), 128);
        // v4-mapped prefix ::ffff:0:0 → bits 80..96 are all 1.
        assert!(b[80..96].iter().all(|&x| x));
    }

    #[test]
    fn from_bytes_round_trips_via_group_key() {
        // Pack a single-RETURN asmap into bytes and confirm group_key
        // returns the tagged ASN.
        let bitvec = ret(64512);
        let mut bytes = vec![0u8; bitvec.len().div_ceil(8)];
        for (i, &bit) in bitvec.iter().enumerate() {
            if bit {
                bytes[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        let am = AsMap::from_bytes(&bytes);
        // Trailing pad bits decode as a RETURN's tail; the first RETURN
        // wins, so the mapped ASN is 64512.
        assert_eq!(am.lookup("1.2.3.4".parse().unwrap()), 64512);
        let key = am.group_key("1.2.3.4".parse().unwrap());
        assert_eq!(key[0], 0xA0);
    }
}
