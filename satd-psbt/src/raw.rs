//! The lossless raw-map layer.
//!
//! A PSBT is a magic prefix followed by a global map and then one map per
//! input and per output, each map a sequence of `<key><value>` pairs ended by
//! a zero-length key. This module keeps every pair exactly as it arrived, in
//! the order it arrived, so that
//!
//! ```text
//! RawPsbt::parse(bytes)?.serialize() == bytes
//! ```
//!
//! for every input that parses. That is stronger than BIP 174 requires and it
//! is the whole reason this layer exists: it is what lets satd prove it
//! carries fields it does not understand — BIP 375's among them — through
//! `combinepsbt`, `joinpsbts` and `utxoupdatepsbt` untouched.
//!
//! Byte-identity needs one rule about encodings: compact sizes must be
//! minimally encoded. Bitcoin Core's `ReadCompactSize` enforces the same rule
//! ("non-canonical ReadCompactSize()"), so rejecting a non-minimal length is
//! Core-compatible as well as convenient; `serialize` can then re-encode
//! minimally and still reproduce the original bytes.
//!
//! Everything here runs on untrusted input from a read-only RPC method, so
//! there is no recursion, no `unwrap`, no `expect`, and no allocation sized
//! by a declared length that has not first been checked against the bytes
//! actually remaining.

use std::collections::HashSet;

use crate::error::{MapId, PsbtError};
use crate::keys::{self, MAGIC};

/// One `<key><value>` pair, exactly as it appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPair {
    /// The key type, itself a compact size (BIP 174).
    pub key_type: u64,
    /// Whatever followed the key type inside the key.
    pub key_data: Vec<u8>,
    pub value: Vec<u8>,
}

impl RawPair {
    pub fn new(key_type: u64, key_data: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        RawPair {
            key_type,
            key_data: key_data.into(),
            value: value.into(),
        }
    }

    fn serialize_into(&self, out: &mut Vec<u8>) {
        let key_len = compact_size_len(self.key_type) + self.key_data.len();
        write_compact_size(out, key_len as u64);
        write_compact_size(out, self.key_type);
        out.extend_from_slice(&self.key_data);
        write_compact_size(out, self.value.len() as u64);
        out.extend_from_slice(&self.value);
    }
}

/// One map's pairs, in the order they were read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawMap(Vec<RawPair>);

impl RawMap {
    pub fn new() -> Self {
        RawMap(Vec::new())
    }

    pub fn pairs(&self) -> &[RawPair] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value of the pair with this exact key, if present.
    pub fn get(&self, key_type: u64, key_data: &[u8]) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|p| p.key_type == key_type && p.key_data == key_data)
            .map(|p| p.value.as_slice())
    }

    /// The value of a keyless field (one whose key is just the type).
    pub fn get_single(&self, key_type: u64) -> Option<&[u8]> {
        self.get(key_type, &[])
    }

    /// Every pair of this type, as `(key_data, value)`, in order.
    pub fn get_all(&self, key_type: u64) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.0
            .iter()
            .filter(move |p| p.key_type == key_type)
            .map(|p| (p.key_data.as_slice(), p.value.as_slice()))
    }

    pub fn contains(&self, key_type: u64, key_data: &[u8]) -> bool {
        self.get(key_type, key_data).is_some()
    }

    pub fn contains_type(&self, key_type: u64) -> bool {
        self.0.iter().any(|p| p.key_type == key_type)
    }

    /// Append a pair. Errors if the key is already present, which is what
    /// BIP 174 requires of a map.
    pub fn insert(&mut self, pair: RawPair) -> Result<(), PsbtError> {
        if self.contains(pair.key_type, &pair.key_data) {
            return Err(PsbtError::DuplicateInsert(pair.key_type));
        }
        self.0.push(pair);
        Ok(())
    }

    /// Replace a pair's value in place, or append it if it is not there.
    /// Every other pair keeps its bytes and its position.
    pub fn set(&mut self, pair: RawPair) {
        match self
            .0
            .iter_mut()
            .find(|p| p.key_type == pair.key_type && p.key_data == pair.key_data)
        {
            Some(existing) => existing.value = pair.value,
            None => self.0.push(pair),
        }
    }

    /// Remove one pair by its exact key.
    pub fn remove(&mut self, key_type: u64, key_data: &[u8]) -> Option<RawPair> {
        let idx = self
            .0
            .iter()
            .position(|p| p.key_type == key_type && p.key_data == key_data)?;
        Some(self.0.remove(idx))
    }

    /// Remove every pair of a type. Returns how many went.
    pub fn remove_type(&mut self, key_type: u64) -> usize {
        let before = self.0.len();
        self.0.retain(|p| p.key_type != key_type);
        before - self.0.len()
    }

    /// Keep only the pairs a predicate accepts, in place.
    pub fn retain(&mut self, keep: impl FnMut(&RawPair) -> bool) {
        self.0.retain(keep);
    }

    fn serialize_into(&self, out: &mut Vec<u8>) {
        for pair in &self.0 {
            pair.serialize_into(out);
        }
        out.push(0x00);
    }
}

impl FromIterator<RawPair> for RawMap {
    fn from_iter<T: IntoIterator<Item = RawPair>>(iter: T) -> Self {
        RawMap(iter.into_iter().collect())
    }
}

/// A whole PSBT, still as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPsbt {
    pub global: RawMap,
    pub inputs: Vec<RawMap>,
    pub outputs: Vec<RawMap>,
}

impl RawPsbt {
    /// Parse a PSBT of either version.
    ///
    /// The version decides where the input and output counts come from, so it
    /// is read from the global map before the per-input and per-output maps
    /// are cut out of the buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, PsbtError> {
        let mut r = Reader::new(bytes);
        r.expect_magic()?;
        let global = r.read_map(MapId::Global)?;

        let version = version_from_global(&global)?;
        let (n_in, n_out) = match version {
            PsbtVersion::V0 => counts_from_unsigned_tx(&global)?,
            PsbtVersion::V2 => {
                if global.contains_type(keys::global::UNSIGNED_TX) {
                    return Err(PsbtError::UnsignedTxInV2);
                }
                let n_in = read_count(&global, keys::global::INPUT_COUNT, "PSBT_GLOBAL_INPUT_COUNT")?;
                let n_out =
                    read_count(&global, keys::global::OUTPUT_COUNT, "PSBT_GLOBAL_OUTPUT_COUNT")?;
                (n_in, n_out)
            }
        };

        if version == PsbtVersion::V0 {
            for ty in keys::global::V2_ONLY {
                if global.contains_type(ty) {
                    return Err(PsbtError::V2FieldInV0(ty));
                }
            }
        }

        // Each map costs at least its one-byte separator, so a count larger
        // than the bytes left cannot be honest. Checking before allocating is
        // what keeps a `10^9` count from reserving a gigabyte.
        let total = n_in.saturating_add(n_out);
        if total > r.remaining() as u64 {
            return Err(PsbtError::ImplausibleCount {
                kind: "inputs and outputs",
                declared: total,
                remaining: r.remaining(),
            });
        }
        // `total <= remaining` above makes both casts lossless.
        let (n_in, n_out) = (n_in as usize, n_out as usize);

        let mut inputs = Vec::with_capacity(n_in);
        for i in 0..n_in {
            inputs.push(r.read_map(MapId::Input(i))?);
        }
        let mut outputs = Vec::with_capacity(n_out);
        for i in 0..n_out {
            outputs.push(r.read_map(MapId::Output(i))?);
        }

        if r.remaining() != 0 {
            return Err(PsbtError::TrailingData(r.remaining()));
        }

        if version == PsbtVersion::V0 {
            for (i, map) in inputs.iter().enumerate() {
                for ty in keys::input::V2_ONLY {
                    if map.contains_type(ty) {
                        return Err(PsbtError::V2FieldInV0Map {
                            map: MapId::Input(i),
                            key_type: ty,
                        });
                    }
                }
            }
            for (i, map) in outputs.iter().enumerate() {
                for ty in keys::output::V2_ONLY {
                    if map.contains_type(ty) {
                        return Err(PsbtError::V2FieldInV0Map {
                            map: MapId::Output(i),
                            key_type: ty,
                        });
                    }
                }
            }
        }

        Ok(RawPsbt {
            global,
            inputs,
            outputs,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&MAGIC);
        self.global.serialize_into(&mut out);
        for map in &self.inputs {
            map.serialize_into(&mut out);
        }
        for map in &self.outputs {
            map.serialize_into(&mut out);
        }
        out
    }

    pub fn from_base64(s: &str) -> Result<Self, PsbtError> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| PsbtError::BadMagic)?;
        Self::parse(&bytes)
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.serialize())
    }

    pub fn version(&self) -> Result<PsbtVersion, PsbtError> {
        version_from_global(&self.global)
    }
}

/// Which PSBT version a set of bytes declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtVersion {
    V0,
    V2,
}

impl PsbtVersion {
    pub fn as_u32(self) -> u32 {
        match self {
            PsbtVersion::V0 => 0,
            PsbtVersion::V2 => 2,
        }
    }
}

/// The version a parsed PSBT declares.
pub fn sniff_version(raw: &RawPsbt) -> Result<PsbtVersion, PsbtError> {
    version_from_global(&raw.global)
}

/// The version a byte string declares, reading only the global map.
///
/// This is what the RPC layer dispatches on. It deliberately stops after the
/// global map: a version 0 PSBT must keep reaching `bitcoin::Psbt` with its
/// own error message, so nothing this crate says about the rest of the buffer
/// may get in the way.
pub fn version_of_bytes(bytes: &[u8]) -> Result<PsbtVersion, PsbtError> {
    let mut r = Reader::new(bytes);
    r.expect_magic()?;
    let global = r.read_map(MapId::Global)?;
    version_from_global(&global)
}

fn version_from_global(global: &RawMap) -> Result<PsbtVersion, PsbtError> {
    match global.get_single(keys::global::VERSION) {
        None => Ok(PsbtVersion::V0),
        Some(v) if v.len() == 4 => {
            let n = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            match n {
                0 => Ok(PsbtVersion::V0),
                2 => Ok(PsbtVersion::V2),
                other => Err(PsbtError::UnsupportedVersion(other)),
            }
        }
        Some(v) => Err(PsbtError::BadFieldLength {
            map: MapId::Global,
            key_type: keys::global::VERSION,
            len: v.len(),
            expected: "4",
        }),
    }
}

fn read_count(global: &RawMap, key_type: u64, name: &'static str) -> Result<u64, PsbtError> {
    let raw = global
        .get_single(key_type)
        .ok_or(PsbtError::MissingGlobal(name))?;
    let mut r = Reader::new(raw);
    let n = r.compact_size()?;
    if r.remaining() != 0 {
        return Err(PsbtError::BadFieldLength {
            map: MapId::Global,
            key_type,
            len: raw.len(),
            expected: "a single compact size",
        });
    }
    Ok(n)
}

fn counts_from_unsigned_tx(global: &RawMap) -> Result<(u64, u64), PsbtError> {
    let raw = global
        .get_single(keys::global::UNSIGNED_TX)
        .ok_or(PsbtError::MissingUnsignedTx)?;
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(raw).map_err(|_| PsbtError::MalformedUnsignedTx)?;
    Ok((tx.input.len() as u64, tx.output.len() as u64))
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn expect_magic(&mut self) -> Result<(), PsbtError> {
        if self.remaining() < MAGIC.len() || self.buf[self.pos..self.pos + MAGIC.len()] != MAGIC {
            return Err(PsbtError::BadMagic);
        }
        self.pos += MAGIC.len();
        Ok(())
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], PsbtError> {
        if self.remaining() < n {
            return Err(PsbtError::UnexpectedEof(what));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn byte(&mut self, what: &'static str) -> Result<u8, PsbtError> {
        Ok(self.take(1, what)?[0])
    }

    /// A minimally encoded compact size. Non-minimal encodings are rejected;
    /// see the module comment.
    fn compact_size(&mut self) -> Result<u64, PsbtError> {
        let first = self.byte("a compact size")?;
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => {
                let b = self.take(2, "a compact size")?;
                let v = u16::from_le_bytes([b[0], b[1]]) as u64;
                if v < 0xfd {
                    return Err(PsbtError::NonMinimalCompactSize);
                }
                Ok(v)
            }
            0xfe => {
                let b = self.take(4, "a compact size")?;
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(PsbtError::NonMinimalCompactSize);
                }
                Ok(v)
            }
            _ => {
                let b = self.take(8, "a compact size")?;
                let v = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= 0xffff_ffff {
                    return Err(PsbtError::NonMinimalCompactSize);
                }
                Ok(v)
            }
        }
    }

    /// A length-prefixed byte string, bounded by what is actually left.
    fn length_prefixed(&mut self, what: &'static str) -> Result<&'a [u8], PsbtError> {
        let len = self.compact_size()?;
        if len > self.remaining() as u64 {
            return Err(PsbtError::LengthOverrun {
                declared: len,
                remaining: self.remaining(),
            });
        }
        self.take(len as usize, what)
    }

    fn read_map(&mut self, id: MapId) -> Result<RawMap, PsbtError> {
        let mut map = RawMap::new();
        // A set beside the vec, purely to keep the duplicate check off the
        // pair count. Scanning the map per pair is quadratic, and a single
        // map inside the 20 MiB request limit holds over a million pairs.
        let mut seen: HashSet<(u64, Vec<u8>)> = HashSet::new();
        loop {
            if self.remaining() == 0 {
                return Err(PsbtError::UnterminatedMap(id));
            }
            let key_len = self.compact_size()?;
            if key_len == 0 {
                return Ok(map);
            }
            if key_len > self.remaining() as u64 {
                return Err(PsbtError::LengthOverrun {
                    declared: key_len,
                    remaining: self.remaining(),
                });
            }
            let key = self.take(key_len as usize, "a PSBT key")?;
            let mut kr = Reader::new(key);
            let key_type = kr.compact_size()?;
            let key_data = key[kr.pos..].to_vec();
            let value = self.length_prefixed("a PSBT value")?.to_vec();

            if !seen.insert((key_type, key_data.clone())) {
                return Err(PsbtError::DuplicateKey { map: id, key_type });
            }
            map.0.push(RawPair {
                key_type,
                key_data,
                value,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Compact size writing
// ---------------------------------------------------------------------------

/// The number of bytes a minimally encoded compact size takes.
pub fn compact_size_len(v: u64) -> usize {
    match v {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Append a minimally encoded compact size.
pub fn write_compact_size(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0xfc => out.push(v as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}
