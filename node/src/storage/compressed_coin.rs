//! Bitcoin Core-compatible compressed-coin codec.
//!
//! This is a peer to [`super::coinview`] — the satd-internal codec used
//! for the live RocksDB `coins` column family. This module is used ONLY
//! for AssumeUTXO snapshot file I/O: reading snapshot files produced by
//! Bitcoin Core, and writing snapshot files that Core can read.
//!
//! Wire format references (Bitcoin Core, src/):
//! - `serialize.h` — `WriteVarInt`/`ReadVarInt` (the "B-style" varint with
//!   the increment-by-1 trick on every byte except the last)
//! - `compressor.cpp` — `CompressAmount`/`DecompressAmount`,
//!   `CompressScript`/`DecompressScript`
//! - `compressor.h` — `ScriptCompression` and `TxOutCompression` wrappers
//!   plus `nSpecialScripts = 6` constant
//! - `node/utxo_snapshot.h` — `SnapshotMetadata` (51-byte header)

use std::io::{self, Read, Write};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, OutPoint, ScriptBuf};

use crate::storage::coinview::Coin;

/// Bitcoin Core's `MAX_SCRIPT_SIZE` consensus limit. Compressed-script
/// records that decode to a raw size exceeding this are replaced with
/// `OP_RETURN`, matching Core's `ScriptCompression::Unser` fallback.
pub const MAX_SCRIPT_SIZE: u32 = 10_000;

/// Number of special-script type slots in the compressed encoding.
/// Values 0..5 in the leading varint denote special-script types
/// (`CompressScript` outputs); values >= 6 denote raw scripts of length
/// `(varint - 6)`. The +6 offset is the trap to get right.
const NUM_SPECIAL_SCRIPTS: u32 = 6;

/// Magic bytes at the start of every Bitcoin Core UTXO snapshot file.
pub const SNAPSHOT_MAGIC_BYTES: [u8; 5] = [b'u', b't', b'x', b'o', 0xff];

/// Snapshot format version. Bumped by Core when the wire format changes;
/// satd refuses to load other versions.
pub const SNAPSHOT_VERSION: u16 = 2;

/// Errors raised by the codec.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("varint overflow")]
    VarintOverflow,
    #[error("non-canonical CompactSize encoding")]
    NonCanonicalCompactSize,
    #[error("snapshot file magic bytes do not match: got {0:?}")]
    BadMagic([u8; 5]),
    #[error("unsupported snapshot version: {0}")]
    UnsupportedVersion(u16),
    #[error("height varint exceeds u32::MAX")]
    HeightOverflow,
    #[error("invalid uncompressed pubkey x-coordinate")]
    InvalidPubkey,
}

// ---------------------------------------------------------------------------
// Snapshot file header
// ---------------------------------------------------------------------------

/// The 51-byte header at the start of a Bitcoin Core UTXO snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMetadata {
    pub version: u16,
    /// `pchMessageStart` bytes for the network (mainnet `0xf9beb4d9`, etc.).
    pub network_magic: [u8; 4],
    pub base_blockhash: BlockHash,
    pub coins_count: u64,
}

impl SnapshotMetadata {
    /// Serialize the 51-byte snapshot header.
    pub fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&SNAPSHOT_MAGIC_BYTES)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.network_magic)?;
        w.write_all(&self.base_blockhash[..])?;
        w.write_all(&self.coins_count.to_le_bytes())?;
        Ok(())
    }

    /// Read and validate a snapshot header. Errors on bad magic or
    /// unsupported version.
    pub fn deserialize<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut magic = [0u8; 5];
        r.read_exact(&mut magic)?;
        if magic != SNAPSHOT_MAGIC_BYTES {
            return Err(CodecError::BadMagic(magic));
        }
        let mut version_bytes = [0u8; 2];
        r.read_exact(&mut version_bytes)?;
        let version = u16::from_le_bytes(version_bytes);
        if version != SNAPSHOT_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let mut network_magic = [0u8; 4];
        r.read_exact(&mut network_magic)?;
        let mut hash_bytes = [0u8; 32];
        r.read_exact(&mut hash_bytes)?;
        let base_blockhash = BlockHash::from_byte_array(hash_bytes);
        let mut count_bytes = [0u8; 8];
        r.read_exact(&mut count_bytes)?;
        Ok(Self {
            version,
            network_magic,
            base_blockhash,
            coins_count: u64::from_le_bytes(count_bytes),
        })
    }
}

// ---------------------------------------------------------------------------
// Core "B-style" VarInt
// ---------------------------------------------------------------------------

/// Write `n` using Bitcoin Core's `WriteVarInt` (DEFAULT mode).
///
/// The encoding subtracts 1 from `n` on every shift, so K-byte encodings
/// don't overlap with shorter ones — each value has exactly one valid
/// representation. Do **not** unify this with satd's internal varint in
/// [`super::coinview`]; their formats are distinct.
pub fn write_varint<W: Write>(w: &mut W, mut n: u64) -> io::Result<()> {
    // Worst-case length: ceil(64 / 7) = 10 bytes
    let mut tmp = [0u8; 10];
    let mut len: usize = 0;
    loop {
        tmp[len] = ((n & 0x7F) as u8) | if len > 0 { 0x80 } else { 0 };
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    // Write in reverse: most-significant byte first.
    let mut i = len;
    loop {
        w.write_all(&[tmp[i]])?;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    Ok(())
}

/// Read a Core `ReadVarInt` (DEFAULT mode) and return the decoded value.
///
/// Returns [`CodecError::VarintOverflow`] if the encoding would shift
/// past `u64::MAX`, matching Core's `std::ios_base::failure` behavior.
pub fn read_varint<R: Read>(r: &mut R) -> Result<u64, CodecError> {
    let mut n: u64 = 0;
    loop {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        let b = buf[0];
        if n > (u64::MAX >> 7) {
            return Err(CodecError::VarintOverflow);
        }
        n = (n << 7) | ((b & 0x7F) as u64);
        if b & 0x80 != 0 {
            if n == u64::MAX {
                return Err(CodecError::VarintOverflow);
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

// ---------------------------------------------------------------------------
// Core CompactSize
// ---------------------------------------------------------------------------
//
// A separate varint family from [`write_varint`] / [`read_varint`] above —
// these two encodings have nothing in common except both producing one byte
// for small values. CompactSize is Core's `WriteCompactSize` /
// `ReadCompactSize` from `serialize.h`, used for size prefixes in network
// and disk wire formats (including the AssumeUTXO snapshot's per-txid
// coin counts and vout indices). The "B-style" VarInt is what Core's
// `compressor.h` uses for the coin's `code`, compressed amount, and
// compressed script size.
//
// CompactSize wire layout:
//   n < 253         → [n]                   (1 byte)
//   n ≤ 0xFFFF      → [0xfd, n_le_u16]      (3 bytes)
//   n ≤ 0xFFFFFFFF  → [0xfe, n_le_u32]      (5 bytes)
//   else            → [0xff, n_le_u64]      (9 bytes)
//
// Decoding rejects non-canonical encodings (a value that would fit in a
// shorter prefix), matching Core.

/// Write `n` as a Core `CompactSize`.
pub fn write_compact_size<W: Write>(w: &mut W, n: u64) -> io::Result<()> {
    if n < 253 {
        w.write_all(&[n as u8])
    } else if n <= u64::from(u16::MAX) {
        w.write_all(&[0xfd])?;
        w.write_all(&(n as u16).to_le_bytes())
    } else if n <= u64::from(u32::MAX) {
        w.write_all(&[0xfe])?;
        w.write_all(&(n as u32).to_le_bytes())
    } else {
        w.write_all(&[0xff])?;
        w.write_all(&n.to_le_bytes())
    }
}

/// Read a Core `CompactSize`. Rejects non-canonical encodings.
pub fn read_compact_size<R: Read>(r: &mut R) -> Result<u64, CodecError> {
    let mut prefix = [0u8; 1];
    r.read_exact(&mut prefix)?;
    let val = match prefix[0] {
        253 => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            let v = u64::from(u16::from_le_bytes(buf));
            if v < 253 {
                return Err(CodecError::NonCanonicalCompactSize);
            }
            v
        }
        254 => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            let v = u64::from(u32::from_le_bytes(buf));
            if v < 0x1_0000 {
                return Err(CodecError::NonCanonicalCompactSize);
            }
            v
        }
        255 => {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            let v = u64::from_le_bytes(buf);
            if v < 0x1_0000_0000 {
                return Err(CodecError::NonCanonicalCompactSize);
            }
            v
        }
        n => u64::from(n),
    };
    Ok(val)
}

// ---------------------------------------------------------------------------
// CompressAmount / DecompressAmount
// ---------------------------------------------------------------------------

/// Compress a Bitcoin amount (in satoshis) using Core's exponent-mantissa
/// encoding. Round-trips losslessly via [`decompress_amount`] for all
/// realistic amounts (capped by consensus at 21M BTC).
///
/// Arithmetic uses `wrapping_*` to match Core's C++ `uint64_t` overflow
/// semantics (which wrap by language rule). Real Bitcoin amounts can't
/// trigger overflow, but a corrupt RocksDB entry with a u64 amount
/// above ~2^63/9 could, and the codec should never panic on that.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e: u32 = 0;
    while n.is_multiple_of(10) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        debug_assert!((1..=9).contains(&d));
        n /= 10;
        // 1 + (n*9 + d - 1)*10 + e, with C++-style wrap on overflow.
        1u64.wrapping_add(
            n.wrapping_mul(9)
                .wrapping_add(d)
                .wrapping_sub(1)
                .wrapping_mul(10)
                .wrapping_add(u64::from(e)),
        )
    } else {
        // 1 + (n - 1)*10 + 9
        1u64.wrapping_add(n.wrapping_sub(1).wrapping_mul(10))
            .wrapping_add(9)
    }
}

/// Inverse of [`compress_amount`]. Wrapping arithmetic for the same
/// reason — adversarial varint input must not panic the codec.
pub fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let mut x = x - 1;
    let e = (x % 10) as u32;
    x /= 10;
    let mut n: u64 = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x.wrapping_mul(10).wrapping_add(d)
    } else {
        x.wrapping_add(1)
    };
    for _ in 0..e {
        n = n.wrapping_mul(10);
    }
    n
}

// ---------------------------------------------------------------------------
// CompressScript / DecompressScript
// ---------------------------------------------------------------------------

/// Try to compress `script` into Core's special-script form. On success,
/// `out` is filled with `[type_byte (0..5)] [20 or 32 bytes payload]` and
/// the function returns `true`. On failure (script is not a recognized
/// standard form), `out` is unchanged and the function returns `false`.
pub fn try_compress_script(script: &bitcoin::Script, out: &mut Vec<u8>) -> bool {
    let s = script.as_bytes();
    // P2PKH: OP_DUP OP_HASH160 <0x14> [20] OP_EQUALVERIFY OP_CHECKSIG
    if s.len() == 25
        && s[0] == 0x76
        && s[1] == 0xa9
        && s[2] == 0x14
        && s[23] == 0x88
        && s[24] == 0xac
    {
        out.push(0x00);
        out.extend_from_slice(&s[3..23]);
        return true;
    }
    // P2SH: OP_HASH160 <0x14> [20] OP_EQUAL
    if s.len() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87 {
        out.push(0x01);
        out.extend_from_slice(&s[2..22]);
        return true;
    }
    // P2PK compressed: <0x21> [33 starting with 0x02/0x03] OP_CHECKSIG
    if s.len() == 35 && s[0] == 33 && (s[1] == 0x02 || s[1] == 0x03) && s[34] == 0xac {
        out.push(s[1]);
        out.extend_from_slice(&s[2..34]);
        return true;
    }
    // P2PK uncompressed: <0x41> [65 starting with 0x04] OP_CHECKSIG. The
    // pubkey must be valid (on the secp256k1 curve) — otherwise the
    // y-coordinate can't be recovered at decompression time and we'd
    // silently corrupt the script.
    if s.len() == 67
        && s[0] == 65
        && s[1] == 0x04
        && s[66] == 0xac
        && PublicKey::from_slice(&s[1..66]).is_ok()
    {
        let parity = s[65] & 0x01;
        out.push(0x04 | parity);
        out.extend_from_slice(&s[2..34]);
        return true;
    }
    false
}

/// Decompress a special-script payload back into the canonical script form.
/// `ns` is the type code (0..5); `payload` must be exactly
/// [`special_script_payload_size`] bytes long.
pub fn decompress_special_script(ns: u32, payload: &[u8]) -> Result<ScriptBuf, CodecError> {
    match ns {
        0 => {
            debug_assert_eq!(payload.len(), 20);
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(payload);
            s.extend_from_slice(&[0x88, 0xac]);
            Ok(ScriptBuf::from_bytes(s))
        }
        1 => {
            debug_assert_eq!(payload.len(), 20);
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(payload);
            s.push(0x87);
            Ok(ScriptBuf::from_bytes(s))
        }
        2 | 3 => {
            debug_assert_eq!(payload.len(), 32);
            let mut s = Vec::with_capacity(35);
            s.push(33);
            s.push(ns as u8);
            s.extend_from_slice(payload);
            s.push(0xac);
            Ok(ScriptBuf::from_bytes(s))
        }
        4 | 5 => {
            debug_assert_eq!(payload.len(), 32);
            let mut compressed = [0u8; 33];
            compressed[0] = (ns - 2) as u8;
            compressed[1..].copy_from_slice(payload);
            let pk =
                PublicKey::from_slice(&compressed).map_err(|_| CodecError::InvalidPubkey)?;
            let uncomp = pk.serialize_uncompressed();
            let mut s = Vec::with_capacity(67);
            s.push(65);
            s.extend_from_slice(&uncomp);
            s.push(0xac);
            Ok(ScriptBuf::from_bytes(s))
        }
        _ => unreachable!("caller must verify ns < NUM_SPECIAL_SCRIPTS"),
    }
}

/// Size of the payload following the special-script type byte.
pub fn special_script_payload_size(ns: u32) -> usize {
    match ns {
        0 | 1 => 20,
        2..=5 => 32,
        _ => unreachable!("caller must verify ns < NUM_SPECIAL_SCRIPTS"),
    }
}

/// Write the varint-prefixed compressed-script encoding of `script`.
/// Standard forms (P2PKH/P2SH/P2PK) use the special-script encoding;
/// everything else is written as `varint(size + 6) || raw_bytes`.
pub fn write_compressed_script<W: Write>(w: &mut W, script: &bitcoin::Script) -> io::Result<()> {
    let mut compr: Vec<u8> = Vec::new();
    if try_compress_script(script, &mut compr) {
        // `compr` already starts with the type byte (0..5), which IS the
        // single-byte varint encoding of that value — no length prefix
        // needed.
        w.write_all(&compr)?;
    } else {
        let n_size = script.as_bytes().len() as u64 + NUM_SPECIAL_SCRIPTS as u64;
        write_varint(w, n_size)?;
        w.write_all(script.as_bytes())?;
    }
    Ok(())
}

/// Read and decode a compressed script. Scripts whose decoded raw size
/// exceeds [`MAX_SCRIPT_SIZE`] are replaced with `OP_RETURN` (matching
/// Core's behavior — no valid script can be that large).
pub fn read_compressed_script<R: Read>(r: &mut R) -> Result<ScriptBuf, CodecError> {
    let n_size = read_varint(r)?;
    if n_size < NUM_SPECIAL_SCRIPTS as u64 {
        let ns = n_size as u32;
        let mut payload = vec![0u8; special_script_payload_size(ns)];
        r.read_exact(&mut payload)?;
        decompress_special_script(ns, &payload)
    } else {
        let raw_size = n_size - NUM_SPECIAL_SCRIPTS as u64;
        if raw_size > MAX_SCRIPT_SIZE as u64 {
            // Consume the bytes from the stream, then return OP_RETURN —
            // Core replaces oversize scripts with a sentinel rather than
            // failing the whole snapshot.
            io::copy(&mut r.take(raw_size), &mut io::sink())?;
            return Ok(ScriptBuf::from_bytes(vec![0x6a]));
        }
        let mut bytes = vec![0u8; raw_size as usize];
        r.read_exact(&mut bytes)?;
        Ok(ScriptBuf::from_bytes(bytes))
    }
}

// ---------------------------------------------------------------------------
// Outpoint serialization
// ---------------------------------------------------------------------------

/// Write a 36-byte outpoint: 32-byte txid (raw inner bytes) + 4-byte
/// vout little-endian. Matches Core's `COutPoint::SERIALIZE_METHODS`.
pub fn write_outpoint<W: Write>(w: &mut W, op: &OutPoint) -> io::Result<()> {
    w.write_all(&op.txid[..])?;
    w.write_all(&op.vout.to_le_bytes())?;
    Ok(())
}

/// Read a 36-byte outpoint.
pub fn read_outpoint<R: Read>(r: &mut R) -> Result<OutPoint, CodecError> {
    let mut txid_bytes = [0u8; 32];
    r.read_exact(&mut txid_bytes)?;
    let txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes));
    let mut vout_bytes = [0u8; 4];
    r.read_exact(&mut vout_bytes)?;
    Ok(OutPoint {
        txid,
        vout: u32::from_le_bytes(vout_bytes),
    })
}

// ---------------------------------------------------------------------------
// Coin serialization
// ---------------------------------------------------------------------------

/// Serialize a [`Coin`] in Core's snapshot wire format:
/// `varint(height<<1 | coinbase) || varint(compress_amount(value)) ||
/// compressed_script`. Matches Core's `Coin::Serialize` (the
/// `TxOutCompression` wrapper around amount + script).
pub fn serialize_coin<W: Write>(w: &mut W, coin: &Coin) -> io::Result<()> {
    let code = (u64::from(coin.height) << 1) | u64::from(coin.coinbase);
    write_varint(w, code)?;
    write_varint(w, compress_amount(coin.amount))?;
    write_compressed_script(w, &coin.script_pubkey)?;
    Ok(())
}

/// Serialize a `(outpoint, coin)` pair into Bitcoin Core's `TxOutSer`
/// stream format from `src/kernel/coinstats.cpp`. This is the per-coin
/// contribution to the **HASH_SERIALIZED_3** UTXO set hash — the value
/// Core reports as `txoutset_hash` from `dumptxoutset` and the value
/// stored in `m_assumeutxo_data.hash_serialized`. The contract is:
///
/// > Concatenate `write_txout_ser(outpoint, coin)` for every coin in
/// > the UTXO set (in `(txid_bytes, vout_le)` ascending key order) and
/// > finalize with Core's `HashWriter::GetHash()` — a **double**
/// > SHA-256, byte-reversed to the `uint256` display form. That value
/// > matches Core's `hash_serialized_3`. (A single SHA-256, or the
/// > un-reversed digest, will not match.)
///
/// Wire layout (per coin, ~50–100 bytes typical):
///
/// - `outpoint` (36 bytes: 32-byte txid + 4-byte vout LE)
/// - `uint32 LE: (height << 1) | coinbase` — note: **fixed-width LE u32**,
///   not a varint. Different from the `code` field used in
///   [`serialize_coin`].
/// - `CTxOut`: `int64 LE amount` + `CompactSize(script.len())` + raw
///   script bytes (no script compression, no `TxOutCompression`).
///
/// This is a **completely different serialization** from
/// [`serialize_coin`] — same input, different bytes, different
/// purpose. The snapshot **file** uses `serialize_coin`; the
/// snapshot **hash** uses `write_txout_ser`.
pub fn write_txout_ser<W: Write>(
    w: &mut W,
    outpoint: &OutPoint,
    coin: &Coin,
) -> io::Result<()> {
    write_outpoint(w, outpoint)?;
    let code = (coin.height << 1) | (u32::from(coin.coinbase));
    w.write_all(&code.to_le_bytes())?;
    // CTxOut: signed 64-bit LE amount + CompactSize-prefixed raw script.
    w.write_all(&(coin.amount as i64).to_le_bytes())?;
    let script_bytes = coin.script_pubkey.as_bytes();
    write_compact_size(w, script_bytes.len() as u64)?;
    w.write_all(script_bytes)?;
    Ok(())
}

/// Deserialize a [`Coin`] in Core's snapshot wire format.
pub fn deserialize_coin<R: Read>(r: &mut R) -> Result<Coin, CodecError> {
    let code = read_varint(r)?;
    let coinbase = (code & 1) != 0;
    let height_u64 = code >> 1;
    if height_u64 > u64::from(u32::MAX) {
        return Err(CodecError::HeightOverflow);
    }
    let height = height_u64 as u32;
    let amount = decompress_amount(read_varint(r)?);
    let script_pubkey = read_compressed_script(r)?;
    Ok(Coin {
        amount,
        script_pubkey,
        height,
        coinbase,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_varint(n: u64) {
        let mut buf = Vec::new();
        write_varint(&mut buf, n).unwrap();
        let mut cursor = &buf[..];
        let decoded = read_varint(&mut cursor).unwrap();
        assert_eq!(decoded, n, "varint round-trip failed for {n}");
        assert!(cursor.is_empty(), "varint decoder left {} trailing bytes", cursor.len());
    }

    #[test]
    fn varint_boundaries() {
        // Single-byte values: 0..=0x7F
        for n in [0u64, 1, 0x7E, 0x7F] {
            roundtrip_varint(n);
        }
        // Two-byte boundary: 0x80 is the first multi-byte value
        for n in [0x80u64, 0x81, 0xFF, 0x100, 0x7FFF, 0x8000] {
            roundtrip_varint(n);
        }
        // Larger values
        for n in [
            0xFFFFu64,
            0x10000,
            0xFFFFFFFF,
            0x100000000,
            u64::MAX - 1,
            u64::MAX,
        ] {
            roundtrip_varint(n);
        }
    }

    #[test]
    fn varint_zero_is_single_byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0).unwrap();
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn varint_max_byte_value_is_single_byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x7F).unwrap();
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn varint_truncated_input_errors() {
        // A two-byte encoding with only one byte available
        let buf = [0x80u8];
        let mut cursor = &buf[..];
        assert!(read_varint(&mut cursor).is_err());
    }

    // CompactSize tests --------------------------------------------------

    fn roundtrip_compact_size(n: u64, expected_len: usize) {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, n).unwrap();
        assert_eq!(buf.len(), expected_len, "compact_size({n}) wrong width");
        let mut cursor = &buf[..];
        let decoded = read_compact_size(&mut cursor).unwrap();
        assert_eq!(decoded, n);
        assert!(cursor.is_empty());
    }

    #[test]
    fn compact_size_boundary_widths() {
        // 1-byte range: 0..=252
        for &n in &[0u64, 1, 252] {
            roundtrip_compact_size(n, 1);
        }
        // 3-byte range: 253..=u16::MAX
        for &n in &[253u64, 254, 1_000, u16::MAX as u64] {
            roundtrip_compact_size(n, 3);
        }
        // 5-byte range: u16::MAX + 1 ..= u32::MAX
        for &n in &[0x1_0000u64, 0xff_ffff, u32::MAX as u64] {
            roundtrip_compact_size(n, 5);
        }
        // 9-byte range
        for &n in &[u64::from(u32::MAX) + 1, u64::MAX] {
            roundtrip_compact_size(n, 9);
        }
    }

    #[test]
    fn compact_size_layout_matches_core() {
        // Specific byte patterns to pin the wire format.
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (252, &[0xfc]),
            (253, &[0xfd, 0xfd, 0x00]),
            (0x1234, &[0xfd, 0x34, 0x12]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x1_0000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (
                0x1_0000_0000,
                &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
        ];
        for (n, expected) in cases {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, *n).unwrap();
            assert_eq!(&buf[..], *expected, "compact_size({n}) bytes mismatch");
        }
    }

    #[test]
    fn compact_size_rejects_non_canonical() {
        // 0xfd prefix with value < 253: non-canonical (should have been 1 byte).
        let buf = [0xfd, 0x10, 0x00];
        let mut cursor = &buf[..];
        let err = read_compact_size(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::NonCanonicalCompactSize));

        // 0xfe prefix with value <= u16::MAX: non-canonical.
        let buf = [0xfe, 0xff, 0xff, 0x00, 0x00];
        let mut cursor = &buf[..];
        let err = read_compact_size(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::NonCanonicalCompactSize));

        // 0xff prefix with value <= u32::MAX: non-canonical.
        let buf = [0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = &buf[..];
        let err = read_compact_size(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::NonCanonicalCompactSize));
    }

    #[test]
    fn compact_size_truncated_input_errors() {
        // 0xfd prefix promises 2 more bytes — only 1 provided.
        let buf = [0xfd, 0x10];
        let mut cursor = &buf[..];
        assert!(read_compact_size(&mut cursor).is_err());
    }

    #[test]
    fn varint_oversize_overflows() {
        // Many continuation bytes — should overflow rather than panic
        let buf = [0xFFu8; 12];
        let mut cursor = &buf[..];
        let err = read_varint(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::VarintOverflow));
    }

    // Golden vectors from Bitcoin Core's src/test/compress_tests.cpp.
    // These pairs are the contract that defines snapshot compatibility —
    // if any of them break, the codec is incompatible with Core.
    #[test]
    fn compress_amount_golden_vectors() {
        // (uncompressed, compressed)
        let vectors: &[(u64, u64)] = &[
            (0, 0x0),
            (1, 0x1),
            (1_000_000, 0x7),       // CENT
            (100_000_000, 0x9),     // COIN
            (5_000_000_000, 0x32),  // 50 * COIN
            (2_100_000_000_000_000, 0x1406F40), // 21_000_000 * COIN
        ];
        for &(dec, enc) in vectors {
            assert_eq!(
                compress_amount(dec),
                enc,
                "compress_amount({dec}) should equal {enc:#x}"
            );
            assert_eq!(
                decompress_amount(enc),
                dec,
                "decompress_amount({enc:#x}) should equal {dec}"
            );
        }
    }

    #[test]
    fn compress_amount_exponent_boundaries() {
        // Every exponent from 0..=9 must round-trip cleanly.
        for e in 0..=9 {
            let n = 10u64.pow(e);
            assert_eq!(decompress_amount(compress_amount(n)), n);
        }
    }

    #[test]
    fn compress_amount_dense_range() {
        // 0..=10_000: every value round-trips.
        for n in 0..=10_000u64 {
            assert_eq!(decompress_amount(compress_amount(n)), n);
        }
    }

    #[test]
    fn compress_amount_coin_intervals() {
        // 1 to 420_000 in steps of 50 COIN — Core's test exercises this range.
        for k in 1..=420_000u64 {
            let n = k * 5_000_000_000;
            assert_eq!(decompress_amount(compress_amount(n)), n);
        }
    }

    #[test]
    fn compress_amount_does_not_panic_on_u64_max() {
        // Defense in depth: adversarial input (corrupt UTXO entry with
        // an out-of-consensus amount) must NOT panic the codec, even
        // though real coin amounts can never reach u64::MAX. We use
        // wrapping arithmetic to match Core's C++ overflow semantics.
        let _ = compress_amount(u64::MAX);
        let _ = compress_amount(u64::MAX - 1);
        let _ = compress_amount(u64::MAX / 2);
    }

    #[test]
    fn decompress_amount_does_not_panic_on_any_input() {
        // Adversarial varint input (e.g. from a corrupt snapshot file
        // that survived header validation but has bogus per-coin data)
        // must not panic. The validation contract is the snapshot
        // hash, not the codec.
        let _ = decompress_amount(u64::MAX);
        let _ = decompress_amount(u64::MAX - 1);
        // 9 in the e-position with the max mantissa is the worst-case
        // overflow path through the for-loop multiplication.
        let _ = decompress_amount(u64::MAX - 9);
    }

    fn roundtrip_script(script: ScriptBuf) {
        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &script).unwrap();
        let mut cursor = &buf[..];
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert!(cursor.is_empty(), "trailing {} bytes", cursor.len());
        assert_eq!(decoded, script);
    }

    fn p2pkh_script(hash: &[u8; 20]) -> ScriptBuf {
        let mut s = Vec::with_capacity(25);
        s.extend_from_slice(&[0x76, 0xa9, 0x14]);
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        ScriptBuf::from_bytes(s)
    }

    fn p2sh_script(hash: &[u8; 20]) -> ScriptBuf {
        let mut s = Vec::with_capacity(23);
        s.extend_from_slice(&[0xa9, 0x14]);
        s.extend_from_slice(hash);
        s.push(0x87);
        ScriptBuf::from_bytes(s)
    }

    fn p2pk_compressed_script(prefix: u8, x: &[u8; 32]) -> ScriptBuf {
        let mut s = Vec::with_capacity(35);
        s.push(33);
        s.push(prefix);
        s.extend_from_slice(x);
        s.push(0xac);
        ScriptBuf::from_bytes(s)
    }

    // Returns (uncompressed_script, expected_type_byte) for a generator-derived pubkey.
    fn p2pk_uncompressed_script() -> (ScriptBuf, u8) {
        // secp256k1 generator point in uncompressed form
        let g_compressed: [u8; 33] = [
            0x02,
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        let pk = PublicKey::from_slice(&g_compressed).unwrap();
        let uncomp = pk.serialize_uncompressed();
        let mut s = Vec::with_capacity(67);
        s.push(65);
        s.extend_from_slice(&uncomp);
        s.push(0xac);
        let parity = uncomp[64] & 0x01;
        (ScriptBuf::from_bytes(s), 0x04 | parity)
    }

    #[test]
    fn script_p2pkh_roundtrip() {
        let s = p2pkh_script(&[0xab; 20]);
        roundtrip_script(s);
    }

    #[test]
    fn script_p2pkh_compressed_size_is_21() {
        let s = p2pkh_script(&[0xab; 20]);
        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &s).unwrap();
        assert_eq!(buf.len(), 21);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn script_p2sh_roundtrip() {
        let s = p2sh_script(&[0xcd; 20]);
        roundtrip_script(s);
    }

    #[test]
    fn script_p2sh_compressed_size_is_21() {
        let s = p2sh_script(&[0xcd; 20]);
        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &s).unwrap();
        assert_eq!(buf.len(), 21);
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn script_p2pk_compressed_even_roundtrip() {
        let x = [0x33u8; 32];
        // 0x02 prefix won't always parse as a valid point — use generator's x instead
        let g_x: [u8; 32] = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        let _ = x;
        let s = p2pk_compressed_script(0x02, &g_x);
        roundtrip_script(s);
    }

    #[test]
    fn script_p2pk_compressed_odd_roundtrip() {
        let g_x: [u8; 32] = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        let s = p2pk_compressed_script(0x03, &g_x);
        roundtrip_script(s);
    }

    #[test]
    fn script_p2pk_uncompressed_roundtrip() {
        let (s, expected_type) = p2pk_uncompressed_script();
        // Verify the compression produces the expected type byte
        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &s).unwrap();
        assert_eq!(buf.len(), 33);
        assert_eq!(buf[0], expected_type);
        // And round-trips back to the same script
        let mut cursor = &buf[..];
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn script_p2pk_uncompressed_invalid_falls_through_to_raw() {
        // 67 bytes, leading 0x41 + 0x04 + bogus 64 bytes + 0xac. Not on
        // the curve → compression must NOT recognize this as a special
        // script, falling through to raw encoding.
        let mut s = Vec::with_capacity(67);
        s.push(65);
        s.push(0x04);
        s.extend_from_slice(&[0xff; 64]);
        s.push(0xac);
        let script = ScriptBuf::from_bytes(s);
        let mut buf = Vec::new();
        write_compressed_script(&mut buf, &script).unwrap();
        // Raw encoding: varint(67 + 6 = 73) || 67 bytes = 1 + 67 = 68 bytes
        // (varint(73) is a single byte since 73 < 0x80)
        assert_eq!(buf.len(), 68);
        assert_eq!(buf[0], 73);
        let mut cursor = &buf[..];
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded, script);
    }

    #[test]
    fn script_raw_op_return_roundtrip() {
        // OP_RETURN <40-byte data> — non-standard, exercises the raw path
        let mut s = vec![0x6a, 40];
        s.extend_from_slice(&[0xde; 40]);
        let script = ScriptBuf::from_bytes(s);
        roundtrip_script(script);
    }

    #[test]
    fn script_empty_roundtrip() {
        roundtrip_script(ScriptBuf::new());
    }

    #[test]
    fn script_oversize_decodes_to_op_return() {
        // Construct a buffer that claims raw_size = MAX_SCRIPT_SIZE + 1.
        // The decoder must replace with OP_RETURN and consume the bytes.
        let oversize_payload_len = (MAX_SCRIPT_SIZE as u64) + 1;
        let n_size = oversize_payload_len + u64::from(NUM_SPECIAL_SCRIPTS);
        let mut buf = Vec::new();
        write_varint(&mut buf, n_size).unwrap();
        buf.extend(std::iter::repeat_n(0xab, oversize_payload_len as usize));
        let mut cursor = &buf[..];
        let decoded = read_compressed_script(&mut cursor).unwrap();
        assert_eq!(decoded.as_bytes(), &[0x6a]);
        assert!(cursor.is_empty(), "trailing bytes after oversize consume");
    }

    fn sample_coin() -> Coin {
        Coin {
            amount: 5_000_000_000,
            script_pubkey: p2pkh_script(&[0xab; 20]),
            height: 800_000,
            coinbase: false,
        }
    }

    #[test]
    fn coin_roundtrip_p2pkh() {
        let coin = sample_coin();
        let mut buf = Vec::new();
        serialize_coin(&mut buf, &coin).unwrap();
        let mut cursor = &buf[..];
        let decoded = deserialize_coin(&mut cursor).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(decoded.amount, coin.amount);
        assert_eq!(decoded.height, coin.height);
        assert_eq!(decoded.coinbase, coin.coinbase);
        assert_eq!(decoded.script_pubkey, coin.script_pubkey);
    }

    #[test]
    fn coin_roundtrip_coinbase() {
        let coin = Coin {
            amount: 6_250_000_000,
            script_pubkey: p2pkh_script(&[0x11; 20]),
            height: 1,
            coinbase: true,
        };
        let mut buf = Vec::new();
        serialize_coin(&mut buf, &coin).unwrap();
        let mut cursor = &buf[..];
        let decoded = deserialize_coin(&mut cursor).unwrap();
        assert!(decoded.coinbase);
        assert_eq!(decoded.height, 1);
        assert_eq!(decoded.amount, 6_250_000_000);
    }

    #[test]
    fn coin_roundtrip_height_max() {
        // u32::MAX height + coinbase=true packs into u33 — must round-trip
        let coin = Coin {
            amount: 1,
            script_pubkey: p2pkh_script(&[0x00; 20]),
            height: u32::MAX,
            coinbase: true,
        };
        let mut buf = Vec::new();
        serialize_coin(&mut buf, &coin).unwrap();
        let mut cursor = &buf[..];
        let decoded = deserialize_coin(&mut cursor).unwrap();
        assert_eq!(decoded.height, u32::MAX);
        assert!(decoded.coinbase);
    }

    #[test]
    fn coin_height_overflow_rejected() {
        // Construct a code varint that decodes to (u32::MAX as u64 + 1) << 1,
        // which when interpreted as height after the bit-shift exceeds u32.
        // varint encoding of 2^33 (the smallest such overflow value):
        let overflow_height: u64 = u64::from(u32::MAX) + 1;
        let code = overflow_height << 1;
        let mut buf = Vec::new();
        write_varint(&mut buf, code).unwrap();
        // Add a valid amount + script so the decoder reaches the height check
        write_varint(&mut buf, 0).unwrap();
        buf.push(0x00); // P2PKH type
        buf.extend_from_slice(&[0u8; 20]);
        let mut cursor = &buf[..];
        let err = deserialize_coin(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::HeightOverflow));
    }

    #[test]
    fn outpoint_roundtrip() {
        let op = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
            ),
            vout: 0x12345678,
        };
        let mut buf = Vec::new();
        write_outpoint(&mut buf, &op).unwrap();
        assert_eq!(buf.len(), 36);
        // Verify the trailing 4 bytes are vout LE
        assert_eq!(&buf[32..36], &[0x78, 0x56, 0x34, 0x12]);
        let mut cursor = &buf[..];
        let decoded = read_outpoint(&mut cursor).unwrap();
        assert_eq!(decoded, op);
    }

    // write_txout_ser tests ---------------------------------------------

    #[test]
    fn txout_ser_pins_byte_layout() {
        // Core's TxOutSer:
        //   outpoint (36 bytes)
        //   uint32 LE: (height << 1) | coinbase   -- NOT a varint
        //   int64 LE: amount
        //   CompactSize(script.len())
        //   script bytes
        //
        // For a non-coinbase coin at height 1 with amount 5_000_000_000
        // and a 3-byte script, the layout is:
        //   txid(32) + vout_le(4) + code_le_u32(4) + amount_le_i64(8) +
        //   cs(3=0x03) + script(3) = 52 bytes.
        let op = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
            ),
            vout: 0x00000001,
        };
        let coin = Coin {
            amount: 5_000_000_000,
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            height: 1,
            coinbase: false,
        };
        let mut buf = Vec::new();
        write_txout_ser(&mut buf, &op, &coin).unwrap();
        assert_eq!(buf.len(), 52);
        assert_eq!(&buf[0..32], &[0xaa; 32]);
        assert_eq!(&buf[32..36], &1u32.to_le_bytes()); // vout LE
        // code = height(1) << 1 | coinbase(0) = 2
        assert_eq!(&buf[36..40], &2u32.to_le_bytes());
        assert_eq!(&buf[40..48], &5_000_000_000i64.to_le_bytes());
        assert_eq!(buf[48], 3); // CompactSize(3)
        assert_eq!(&buf[49..52], &[0x76, 0xa9, 0x14]);
    }

    #[test]
    fn txout_ser_coinbase_packs_correctly() {
        // height=10, coinbase=true → code = 10 << 1 | 1 = 21
        let op = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xff; 32]),
            ),
            vout: 0,
        };
        let coin = Coin {
            amount: 0,
            script_pubkey: ScriptBuf::new(),
            height: 10,
            coinbase: true,
        };
        let mut buf = Vec::new();
        write_txout_ser(&mut buf, &op, &coin).unwrap();
        // 32 + 4 + 4 + 8 + 1 (cs=0) = 49 bytes
        assert_eq!(buf.len(), 49);
        assert_eq!(&buf[36..40], &21u32.to_le_bytes());
        // amount=0, 8 LE bytes
        assert_eq!(&buf[40..48], &[0u8; 8]);
        // empty script: CompactSize(0) = 0
        assert_eq!(buf[48], 0);
    }

    #[test]
    fn txout_ser_amount_is_signed_i64() {
        // Core uses CAmount = int64_t. Our `coin.amount` is u64 but the
        // serialization casts to i64, so values above i64::MAX as u64
        // appear as negative. Real Bitcoin amounts can't reach this
        // range (capped at 21M BTC = 2.1e15 sat), but if a corrupt
        // entry has amount > i64::MAX, the bytes should match what a
        // C++ reinterpret would produce.
        let op = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0; 32]),
            ),
            vout: 0,
        };
        let coin = Coin {
            amount: u64::MAX, // wraps to -1 as i64
            script_pubkey: ScriptBuf::new(),
            height: 0,
            coinbase: false,
        };
        let mut buf = Vec::new();
        write_txout_ser(&mut buf, &op, &coin).unwrap();
        assert_eq!(&buf[40..48], &[0xff; 8]);
    }

    #[test]
    fn snapshot_metadata_roundtrip() {
        let meta = SnapshotMetadata {
            version: SNAPSHOT_VERSION,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            base_blockhash: BlockHash::from_byte_array([0xab; 32]),
            coins_count: 123_456_789,
        };
        let mut buf = Vec::new();
        meta.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 51);
        // Verify header layout byte-by-byte
        assert_eq!(&buf[0..5], &SNAPSHOT_MAGIC_BYTES);
        assert_eq!(&buf[5..7], &SNAPSHOT_VERSION.to_le_bytes());
        assert_eq!(&buf[7..11], &[0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(&buf[11..43], &[0xab; 32]);
        assert_eq!(&buf[43..51], &123_456_789u64.to_le_bytes());
        let mut cursor = &buf[..];
        let decoded = SnapshotMetadata::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn snapshot_metadata_bad_magic_rejected() {
        let mut buf = vec![b'b', b'a', b'd', b'!', b'!'];
        buf.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        buf.extend_from_slice(&[0u8; 44]);
        let mut cursor = &buf[..];
        let err = SnapshotMetadata::deserialize(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::BadMagic(_)));
    }

    #[test]
    fn snapshot_metadata_unsupported_version_rejected() {
        let mut buf = SNAPSHOT_MAGIC_BYTES.to_vec();
        buf.extend_from_slice(&999u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 44]);
        let mut cursor = &buf[..];
        let err = SnapshotMetadata::deserialize(&mut cursor).unwrap_err();
        assert!(matches!(err, CodecError::UnsupportedVersion(999)));
    }

    /// Integration test that streams a real Bitcoin Core mainnet UTXO
    /// snapshot file and verifies the codec parses every record cleanly
    /// and reaches EOF at exactly the declared `coins_count`.
    ///
    /// Run manually with the path to a downloaded snapshot:
    ///   `SATD_TEST_CORE_SNAPSHOT=/path/to/utxo-840000.dat \
    ///    cargo test -- --ignored core_mainnet_snapshot_streaming`
    ///
    /// To verify the file's integrity against Core's published hash,
    /// run `sha256sum` on the file separately and compare against the
    /// value in Core's `kernel/chainparams.cpp m_assumeutxo_data`.
    ///
    /// See `CONTRIBUTING.md` for snapshot acquisition.
    #[test]
    #[ignore = "requires real Bitcoin Core mainnet snapshot file"]
    fn core_mainnet_snapshot_streaming() {
        use std::fs::File;
        use std::io::BufReader;

        let path = match std::env::var("SATD_TEST_CORE_SNAPSHOT") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("set SATD_TEST_CORE_SNAPSHOT to run this test");
                return;
            }
        };
        let f = File::open(&path).expect("open snapshot file");
        let total_size = f.metadata().unwrap().len();
        let mut reader = BufReader::new(f);

        let meta = SnapshotMetadata::deserialize(&mut reader).expect("parse header");
        eprintln!(
            "snapshot: base={} count={} version={} file_size={}",
            meta.base_blockhash, meta.coins_count, meta.version, total_size
        );

        let mut coins_read = 0u64;
        while coins_read < meta.coins_count {
            let _op = read_outpoint(&mut reader).expect("outpoint");
            let _coin = deserialize_coin(&mut reader).expect("coin");
            coins_read += 1;
            if coins_read.is_multiple_of(1_000_000) {
                eprintln!("  {coins_read} / {} coins", meta.coins_count);
            }
        }
        assert_eq!(coins_read, meta.coins_count);

        // EOF check: reader must be exhausted now. Any trailing bytes
        // mean either the file format changed or our codec under-reads.
        let mut tail = [0u8; 1];
        let trailing = reader.read(&mut tail).expect("trailing read");
        assert_eq!(trailing, 0, "snapshot has unexpected trailing bytes");
        eprintln!("OK: consumed all {coins_read} coins to EOF");
    }
}
