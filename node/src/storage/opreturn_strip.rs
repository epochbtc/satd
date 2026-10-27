//! OP_RETURN payload stripping: where the payloads sit inside a stored
//! block, the record that keeps a stripped block's identity, and the
//! [`StoredBlock`] a reader gets back.
//!
//! Stripping zeroes the scriptPubKey bytes after the leading `OP_RETURN`
//! (`0x6a`) of each eligible output, in place in `blk*.dat`. No length
//! changes, so every offset, size and weight stays as it was and the
//! transaction still deserializes with every vout index unchanged. What
//! no longer follows from the bytes is the txid and wtxid of each
//! stripped transaction, so the record keeps the originals, plus a hash
//! of the block's *filled form* (the stored bytes with every stripped span
//! set to zero) that pins the record to the bytes it describes.
//!
//! The filled form is the one in-memory representation of a stripped
//! block. Whatever the disk holds in a span (zeros after a punch, XOR key
//! bytes after decoding, or the original bytes if a crash landed between
//! the record write and the punch), [`fill_spans`] overwrites it with
//! zeros, so every reader sees the same bytes.
//!
//! This module is pure code: nothing here reads or writes the store.

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Block, BlockHash, Txid, Wtxid};

use crate::storage::coinview::{decode_varint, encode_varint};

// ---------------------------------------------------------------------------
// Span parser
// ---------------------------------------------------------------------------

/// Where one output's scriptPubKey sits in the block bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputSpan {
    /// Offset of the script's first byte (after its length prefix).
    pub script_offset: usize,
    pub script_len: usize,
}

impl OutputSpan {
    /// The bytes stripping zeroes: everything after the leading opcode.
    /// Empty for an empty or one-byte script.
    pub fn strip_range(&self) -> std::ops::Range<usize> {
        if self.script_len <= 1 {
            return self.script_offset..self.script_offset;
        }
        self.script_offset + 1..self.script_offset + self.script_len
    }
}

/// Where one transaction and its output scripts sit in the block bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxSpans {
    pub offset: usize,
    pub len: usize,
    /// One per output, in vout order.
    pub outputs: Vec<OutputSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpanError {
    #[error("block bytes end inside {0}")]
    Truncated(&'static str),
    #[error("non-minimal CompactSize at offset {0}")]
    NonMinimalCompactSize(usize),
    #[error("unsupported segwit flag {flag:#x} at offset {offset}")]
    UnsupportedSegwitFlag { flag: u8, offset: usize },
    #[error("segwit transaction at offset {0} carries no witness")]
    EmptyWitness(usize),
    #[error("{0} trailing bytes after the last transaction")]
    TrailingBytes(usize),
    #[error("count {count} at offset {offset} cannot fit in the remaining bytes")]
    CountTooLarge { count: u64, offset: usize },
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], SpanError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(SpanError::Truncated(what))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn skip(&mut self, n: u64, what: &'static str) -> Result<(), SpanError> {
        let n = usize::try_from(n).map_err(|_| SpanError::Truncated(what))?;
        self.take(n, what).map(|_| ())
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, SpanError> {
        Ok(self.take(1, what)?[0])
    }

    /// A Bitcoin CompactSize, refusing non-minimal encodings as
    /// rust-bitcoin's `VarInt` decoder does.
    fn compact_size(&mut self, what: &'static str) -> Result<u64, SpanError> {
        let at = self.pos;
        let first = self.u8(what)?;
        let (v, min) = match first {
            0xfd => (u16::from_le_bytes(self.take(2, what)?.try_into().unwrap()) as u64, 0xfd),
            0xfe => (u32::from_le_bytes(self.take(4, what)?.try_into().unwrap()) as u64, 0x1_0000),
            0xff => (u64::from_le_bytes(self.take(8, what)?.try_into().unwrap()), 0x1_0000_0000),
            n => return Ok(n as u64),
        };
        if v < min {
            return Err(SpanError::NonMinimalCompactSize(at));
        }
        Ok(v)
    }

    /// A count of items each at least `min_item` bytes long, refused when
    /// the remaining bytes cannot hold that many (so a hostile count never
    /// drives an allocation).
    fn count(&mut self, min_item: usize, what: &'static str) -> Result<u64, SpanError> {
        let at = self.pos;
        let n = self.compact_size(what)?;
        let room = (self.buf.len() - self.pos) as u64;
        if n.saturating_mul(min_item as u64) > room {
            return Err(SpanError::CountTooLarge { count: n, offset: at });
        }
        Ok(n)
    }
}

/// Walk a serialized block and record where every transaction and every
/// output script sits. Mirrors rust-bitcoin 0.32's `Block` and
/// `Transaction` decoders: the BIP144 marker and flag (flag `1` only),
/// minimal CompactSize, the "witness flag set but no witnesses" refusal,
/// and no trailing bytes.
pub fn tx_spans(block: &[u8]) -> Result<Vec<TxSpans>, SpanError> {
    let mut c = Cursor { buf: block, pos: 0 };
    c.take(80, "the header")?;
    // A transaction is at least 10 bytes (version, two counts, locktime).
    let n_tx = c.count(10, "the transaction count")?;
    let mut txs = Vec::with_capacity(n_tx as usize);
    for _ in 0..n_tx {
        txs.push(tx(&mut c)?);
    }
    if c.pos != block.len() {
        return Err(SpanError::TrailingBytes(block.len() - c.pos));
    }
    Ok(txs)
}

fn inputs(c: &mut Cursor<'_>) -> Result<u64, SpanError> {
    // An input is at least 41 bytes (outpoint, script length, sequence).
    let n = c.count(41, "an input count")?;
    for _ in 0..n {
        c.take(36, "an outpoint")?;
        let len = c.compact_size("a scriptSig length")?;
        c.skip(len, "a scriptSig")?;
        c.take(4, "a sequence")?;
    }
    Ok(n)
}

fn outputs(c: &mut Cursor<'_>) -> Result<Vec<OutputSpan>, SpanError> {
    // An output is at least 9 bytes (value, script length).
    let n = c.count(9, "an output count")?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        c.take(8, "an output value")?;
        let len = c.compact_size("a scriptPubKey length")?;
        let script_offset = c.pos;
        c.skip(len, "a scriptPubKey")?;
        out.push(OutputSpan {
            script_offset,
            script_len: len as usize,
        });
    }
    Ok(out)
}

fn tx(c: &mut Cursor<'_>) -> Result<TxSpans, SpanError> {
    let offset = c.pos;
    c.take(4, "a transaction version")?;
    let n_in = inputs(c)?;
    let outs = if n_in == 0 {
        let at = c.pos;
        let flag = c.u8("a segwit flag")?;
        if flag != 1 {
            return Err(SpanError::UnsupportedSegwitFlag { flag, offset: at });
        }
        let n_in = inputs(c)?;
        let outs = outputs(c)?;
        let mut any_witness = false;
        for _ in 0..n_in {
            let items = c.count(1, "a witness item count")?;
            any_witness |= items > 0;
            for _ in 0..items {
                let len = c.compact_size("a witness item length")?;
                c.skip(len, "a witness item")?;
            }
        }
        if n_in > 0 && !any_witness {
            return Err(SpanError::EmptyWitness(offset));
        }
        outs
    } else {
        outputs(c)?
    };
    c.take(4, "a locktime")?;
    Ok(TxSpans {
        offset,
        len: c.pos - offset,
        outputs: outs,
    })
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/// Whether an output of transaction `tx_index` is stripped under
/// `threshold`: never the coinbase (its OP_RETURN carries the BIP141
/// witness commitment), only an OP_RETURN script, and only at or above the
/// threshold length. A threshold of 0 takes every OP_RETURN.
pub fn output_is_eligible(tx_index: usize, script: &bitcoin::Script, threshold: u64) -> bool {
    tx_index >= 1 && script.is_op_return() && script.len() as u64 >= threshold
}

/// The eligible outputs of `block`, as `(tx_index, vouts)` for each
/// transaction with at least one, in block order.
pub fn eligible_outputs(block: &Block, threshold: u64) -> Vec<(usize, Vec<u32>)> {
    block
        .txdata
        .iter()
        .enumerate()
        .filter_map(|(i, tx)| {
            let vouts: Vec<u32> = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| output_is_eligible(i, &o.script_pubkey, threshold))
                .map(|(v, _)| v as u32)
                .collect();
            (!vouts.is_empty()).then_some((i, vouts))
        })
        .collect()
}

/// Whether any non-coinbase output of `block` looks stripped: an OP_RETURN
/// whose payload after the opcode is non-empty and is what a punch leaves.
/// A punch leaves zeros on disk, and a block read decodes each byte through
/// the blocks-dir obfuscation key (`xor.dat`), so the payload reads back as
/// `xor_key` repeated from some phase: all zero for the zero key.
///
/// A block read with no record that has one may be a stripped block whose
/// record was lost. It may also be a genuine payload of that shape, which is
/// why a hit only calls for a merkle check.
pub fn has_punched_op_return(block: &Block, xor_key: &[u8; 8]) -> bool {
    block.txdata.iter().skip(1).any(|tx| {
        tx.output.iter().any(|o| {
            let script = o.script_pubkey.as_bytes();
            script.len() >= 2
                && script[0] == 0x6a
                && (0..8).any(|phase| {
                    script[1..].iter().enumerate().all(|(j, b)| *b == xor_key[(phase + j) % 8])
                })
        })
    })
}

// ---------------------------------------------------------------------------
// The strip record
// ---------------------------------------------------------------------------

pub const RECORD_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrippedOutput {
    pub vout: u32,
    /// The original scriptPubKey length; must equal the on-disk prefix.
    pub script_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrippedTx {
    pub tx_index: u32,
    pub txid: Txid,
    /// `Some` iff the transaction has a witness (its wtxid differs).
    pub wtxid: Option<Wtxid>,
    pub outputs: Vec<StrippedOutput>,
}

/// What a stripped block keeps in the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StripRecord {
    /// SHA-256 of the block's filled form.
    pub filled_sha256: [u8; 32],
    /// Ascending `tx_index`, at least one.
    pub txs: Vec<StrippedTx>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordDecodeError {
    #[error("strip record: empty")]
    Empty,
    #[error("strip record: unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("strip record: truncated in {0}")]
    Truncated(&'static str),
    #[error("strip record: non-minimal varint in {0}")]
    NonMinimalVarint(&'static str),
    #[error("strip record: {0} out of range")]
    OutOfRange(&'static str),
    #[error("strip record: zero {0}")]
    ZeroCount(&'static str),
    #[error("strip record: {0} not strictly ascending")]
    NotAscending(&'static str),
    #[error("strip record: tx_index 0 (the coinbase is never stripped)")]
    Coinbase,
    #[error("strip record: unknown flag bits {0:#x}")]
    UnknownFlags(u8),
    #[error("strip record: {0} trailing bytes")]
    TrailingBytes(usize),
}

const FLAG_HAS_WITNESS: u8 = 0x01;

impl StripRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 1 + self.txs.len() * 80);
        buf.push(RECORD_VERSION);
        buf.extend_from_slice(&self.filled_sha256);
        encode_varint(self.txs.len() as u64, &mut buf);
        for tx in &self.txs {
            encode_varint(tx.tx_index as u64, &mut buf);
            buf.extend_from_slice(tx.txid.as_byte_array());
            match &tx.wtxid {
                Some(w) => {
                    buf.push(FLAG_HAS_WITNESS);
                    buf.extend_from_slice(w.as_byte_array());
                }
                None => buf.push(0),
            }
            encode_varint(tx.outputs.len() as u64, &mut buf);
            for o in &tx.outputs {
                encode_varint(o.vout as u64, &mut buf);
                encode_varint(o.script_len, &mut buf);
            }
        }
        buf
    }

    /// Strict decode: unknown versions and flags, zero counts, indexes
    /// that are not strictly ascending, the coinbase, non-minimal varints
    /// and trailing bytes are all errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let mut r = RecordReader { buf: bytes, pos: 0 };
        let version = *bytes.first().ok_or(RecordDecodeError::Empty)?;
        r.pos = 1;
        if version != RECORD_VERSION {
            return Err(RecordDecodeError::UnsupportedVersion(version));
        }
        let filled_sha256: [u8; 32] = r.take(32, "filled_sha256")?.try_into().unwrap();
        // A stripped tx takes at least 35 bytes (index, txid, flags, output
        // count). That bound only stops a hostile count from driving the
        // allocation; the per-field checks below give the precise error.
        let n_txs = r.count(35, "n_txs")?;
        let mut txs = Vec::with_capacity(n_txs);
        let mut last_tx: Option<u32> = None;
        for _ in 0..n_txs {
            let tx_index = r.u32("tx_index")?;
            if tx_index == 0 {
                return Err(RecordDecodeError::Coinbase);
            }
            if last_tx.is_some_and(|l| tx_index <= l) {
                return Err(RecordDecodeError::NotAscending("tx_index"));
            }
            last_tx = Some(tx_index);
            let txid = Txid::from_byte_array(r.take(32, "txid")?.try_into().unwrap());
            let flags = r.take(1, "flags")?[0];
            if flags & !FLAG_HAS_WITNESS != 0 {
                return Err(RecordDecodeError::UnknownFlags(flags));
            }
            let wtxid = if flags & FLAG_HAS_WITNESS != 0 {
                Some(Wtxid::from_byte_array(r.take(32, "wtxid")?.try_into().unwrap()))
            } else {
                None
            };
            let n_out = r.count(2, "n_outputs")?;
            let mut outputs = Vec::with_capacity(n_out);
            let mut last_vout: Option<u32> = None;
            for _ in 0..n_out {
                let vout = r.u32("vout")?;
                if last_vout.is_some_and(|l| vout <= l) {
                    return Err(RecordDecodeError::NotAscending("vout"));
                }
                last_vout = Some(vout);
                let script_len = r.varint("script_len")?;
                outputs.push(StrippedOutput { vout, script_len });
            }
            txs.push(StrippedTx {
                tx_index,
                txid,
                wtxid,
                outputs,
            });
        }
        if r.pos != bytes.len() {
            return Err(RecordDecodeError::TrailingBytes(bytes.len() - r.pos));
        }
        Ok(Self { filled_sha256, txs })
    }

    pub fn tx(&self, tx_index: usize) -> Option<&StrippedTx> {
        let i = u32::try_from(tx_index).ok()?;
        self.txs
            .binary_search_by_key(&i, |t| t.tx_index)
            .ok()
            .map(|p| &self.txs[p])
    }

    /// Build the record for stripping `block` (whose serialization is
    /// `bytes`) under `threshold`. `None` when nothing is eligible. The
    /// returned buffer is the filled form.
    ///
    /// `bytes` must be exactly `block`'s serialization: the record's txids
    /// come from `block` and the filled form from `bytes`, so a mismatch
    /// would build a record no read could ever verify, and the punch that
    /// follows would leave the block unreadable for good.
    pub fn build(bytes: &[u8], block: &Block, threshold: u64) -> Result<Option<(Self, Vec<u8>)>, FillError> {
        if bitcoin::consensus::encode::serialize(block) != bytes {
            return Err(FillError::BytesNotBlock);
        }
        let eligible = eligible_outputs(block, threshold);
        if eligible.is_empty() {
            return Ok(None);
        }
        let txs = eligible
            .into_iter()
            .map(|(i, vouts)| {
                let tx = &block.txdata[i];
                let wtxid = tx.compute_wtxid();
                let txid = tx.compute_txid();
                StrippedTx {
                    tx_index: i as u32,
                    txid,
                    wtxid: (wtxid.to_raw_hash() != txid.to_raw_hash()).then_some(wtxid),
                    outputs: vouts
                        .into_iter()
                        .map(|v| StrippedOutput {
                            vout: v,
                            script_len: tx.output[v as usize].script_pubkey.len() as u64,
                        })
                        .collect(),
                }
            })
            .collect();
        let mut record = Self {
            filled_sha256: [0; 32],
            txs,
        };
        let spans = tx_spans(bytes).map_err(FillError::Spans)?;
        let mut filled = bytes.to_vec();
        fill_spans(&mut filled, &record, &spans)?;
        record.filled_sha256 = sha256::Hash::hash(&filled).to_byte_array();
        Ok(Some((record, filled)))
    }
}

struct RecordReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> RecordReader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], RecordDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(RecordDecodeError::Truncated(what))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn varint(&mut self, what: &'static str) -> Result<u64, RecordDecodeError> {
        let (v, n) = decode_varint(&self.buf[self.pos..]).ok_or(RecordDecodeError::Truncated(what))?;
        let mut canonical = Vec::with_capacity(10);
        encode_varint(v, &mut canonical);
        if canonical.len() != n {
            return Err(RecordDecodeError::NonMinimalVarint(what));
        }
        self.pos += n;
        Ok(v)
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, RecordDecodeError> {
        u32::try_from(self.varint(what)?).map_err(|_| RecordDecodeError::OutOfRange(what))
    }

    fn count(&mut self, min_item: usize, what: &'static str) -> Result<usize, RecordDecodeError> {
        let n = self.varint(what)?;
        if n == 0 {
            return Err(RecordDecodeError::ZeroCount(what));
        }
        let room = (self.buf.len() - self.pos) as u64;
        if n.saturating_mul(min_item as u64) > room {
            return Err(RecordDecodeError::Truncated(what));
        }
        Ok(n as usize)
    }
}

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FillError {
    #[error("strip record: block bytes do not parse: {0}")]
    Spans(SpanError),
    #[error("strip record: the block bytes are not the block's serialization")]
    BytesNotBlock,
    #[error("strip record names tx {0}, which the block does not have")]
    NoSuchTx(u32),
    #[error("strip record names output {vout} of tx {tx_index}, which does not exist")]
    NoSuchOutput { tx_index: u32, vout: u32 },
    #[error("strip record: output {vout} of tx {tx_index} is {on_disk} bytes on disk, record says {recorded}")]
    LengthMismatch {
        tx_index: u32,
        vout: u32,
        on_disk: usize,
        recorded: u64,
    },
    #[error("strip record: output {vout} of tx {tx_index} is not an OP_RETURN script")]
    NotOpReturn { tx_index: u32, vout: u32 },
}

/// Zero every span `record` names in `buf` (the block bytes `spans` was
/// parsed from), after checking that each named output exists, has the
/// recorded length and starts with `OP_RETURN`.
///
/// Every named output is checked before any byte is written, so on an error
/// `buf` is unchanged.
pub fn fill_spans(buf: &mut [u8], record: &StripRecord, spans: &[TxSpans]) -> Result<(), FillError> {
    for range in strip_ranges(buf, record, spans)? {
        buf[range].fill(0);
    }
    Ok(())
}

/// The byte ranges of `buf` (the block bytes `spans` was parsed from) that
/// `record` strips, in record order, after the checks [`fill_spans`] makes.
pub fn strip_ranges(
    buf: &[u8],
    record: &StripRecord,
    spans: &[TxSpans],
) -> Result<Vec<std::ops::Range<usize>>, FillError> {
    let mut ranges = Vec::new();
    for tx in &record.txs {
        let tx_spans = spans
            .get(tx.tx_index as usize)
            .ok_or(FillError::NoSuchTx(tx.tx_index))?;
        for o in &tx.outputs {
            let span = tx_spans
                .outputs
                .get(o.vout as usize)
                .ok_or(FillError::NoSuchOutput {
                    tx_index: tx.tx_index,
                    vout: o.vout,
                })?;
            if span.script_len as u64 != o.script_len {
                return Err(FillError::LengthMismatch {
                    tx_index: tx.tx_index,
                    vout: o.vout,
                    on_disk: span.script_len,
                    recorded: o.script_len,
                });
            }
            if span.script_len == 0 || buf[span.script_offset] != 0x6a {
                return Err(FillError::NotOpReturn {
                    tx_index: tx.tx_index,
                    vout: o.vout,
                });
            }
            ranges.push(span.strip_range());
        }
    }
    Ok(ranges)
}

// ---------------------------------------------------------------------------
// Configuration and the worker's cursor
// ---------------------------------------------------------------------------

/// The shallowest `-pruneopreturn` depth: Core's `MIN_BLOCKS_TO_KEEP` and
/// `NODE_NETWORK_LIMITED_MIN_BLOCKS`. `-pruneopreturn=1` (or `all`) means
/// this.
pub const MIN_STRIP_DEPTH: u32 = 288;

/// The default `-pruneopreturnsize`: one common filesystem block. Smaller
/// payloads free little or no disk under hole punching.
pub const DEFAULT_STRIP_SIZE: u64 = 4096;

/// What a node with stripped blocks serves to peers (`-pruneopreturnpeers`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrunePeers {
    /// As a pruned Core node: only the last 288 blocks.
    #[default]
    Limited,
    /// Any block still held intact, at any depth; `notfound` for a stripped
    /// one. Advertises `NODE_INTACT_BLOCKS`.
    Intact,
}

impl PrunePeers {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Limited => "limited",
            Self::Intact => "intact",
        }
    }
}

/// The strip worker's cursor, stored under the `meta` key of the strip CF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripMeta {
    /// Every active height below this has been examined under `size_threshold`.
    pub next_height: u32,
    pub size_threshold: u64,
    pub depth: u32,
}

const META_VERSION: u8 = 1;

impl StripMeta {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.push(META_VERSION);
        out.extend_from_slice(&self.next_height.to_le_bytes());
        out.extend_from_slice(&self.size_threshold.to_le_bytes());
        out.extend_from_slice(&self.depth.to_le_bytes());
        out
    }

    /// Strict: an unknown version or a wrong length is `None`, and the worker
    /// then starts its scan over, which only costs time.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 17 || bytes[0] != META_VERSION {
            return None;
        }
        Some(Self {
            next_height: u32::from_le_bytes(bytes[1..5].try_into().ok()?),
            size_threshold: u64::from_le_bytes(bytes[5..13].try_into().ok()?),
            depth: u32::from_le_bytes(bytes[13..17].try_into().ok()?),
        })
    }
}

/// What the strip records add up to (`getopreturnpruneinfo`,
/// `getblockchaininfo`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StripSummary {
    pub blocks: u64,
    pub transactions: u64,
    pub outputs: u64,
    /// Bytes zeroed: each stripped script's length less its `0x6a`.
    pub bytes_zeroed: u64,
    /// The whole filesystem blocks every span is sure to contain, wherever it
    /// starts: a cautious minimum of what the punches gave back. The records
    /// do not keep file offsets, so the exact figure cannot be rebuilt from
    /// them; the block files' allocated size is the measurement.
    pub bytes_freed_estimate: u64,
}

impl StripSummary {
    /// Add one record, for a filesystem block of `fs_block` bytes.
    pub fn add(&mut self, record: &StripRecord, fs_block: u64) {
        let bs = fs_block.max(1);
        self.blocks += 1;
        self.transactions += record.txs.len() as u64;
        for tx in &record.txs {
            self.outputs += tx.outputs.len() as u64;
            for o in &tx.outputs {
                let span = o.script_len.saturating_sub(1);
                self.bytes_zeroed += span;
                // A span of `span` bytes holds at least this many whole
                // blocks at its worst alignment.
                self.bytes_freed_estimate += span.saturating_sub(bs - 1) / bs * bs;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StoredBlock
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoredBlockError {
    #[error(transparent)]
    Fill(#[from] FillError),
    #[error("strip record: filled block does not match the recorded hash")]
    FilledHashMismatch,
    #[error("block bytes do not deserialize: {0}")]
    Deserialize(String),
    #[error("block hash {got} is not the expected {expected}")]
    WrongHash { expected: BlockHash, got: BlockHash },
    #[error("strip record: txids do not reproduce the header's merkle root")]
    MerkleMismatch,
}

/// A block as read from storage: intact, or stripped with its record.
#[derive(Clone, Debug)]
pub struct StoredBlock {
    /// The filled form for a stripped block; sizes equal the original.
    pub block: Block,
    strip: Option<StripRecord>,
}

impl StoredBlock {
    pub fn intact(block: Block) -> Self {
        Self { block, strip: None }
    }

    /// Decode stored block bytes, applying `record` when the block is
    /// stripped. For a stripped block the spans are zero-filled, the
    /// filled form must hash to the recorded value, and the recorded and
    /// computed txids must reproduce the header's merkle root. The header
    /// must hash to `expected` either way.
    pub fn from_bytes(
        mut bytes: Vec<u8>,
        record: Option<StripRecord>,
        expected: &BlockHash,
    ) -> Result<Self, StoredBlockError> {
        if let Some(rec) = &record {
            let spans = tx_spans(&bytes).map_err(FillError::Spans)?;
            fill_spans(&mut bytes, rec, &spans)?;
            if sha256::Hash::hash(&bytes).to_byte_array() != rec.filled_sha256 {
                return Err(StoredBlockError::FilledHashMismatch);
            }
        }
        let block: Block = deserialize(&bytes).map_err(|e| StoredBlockError::Deserialize(e.to_string()))?;
        let got = block.block_hash();
        if got != *expected {
            return Err(StoredBlockError::WrongHash {
                expected: *expected,
                got,
            });
        }
        let stored = Self { block, strip: record };
        if stored.strip.is_some() && !stored.verify_merkle() {
            return Err(StoredBlockError::MerkleMismatch);
        }
        Ok(stored)
    }

    pub fn is_stripped(&self) -> bool {
        self.strip.is_some()
    }

    pub fn record(&self) -> Option<&StripRecord> {
        self.strip.as_ref()
    }

    fn stripped_tx(&self, i: usize) -> Option<&StrippedTx> {
        self.strip.as_ref().and_then(|r| r.tx(i))
    }

    pub fn tx_is_stripped(&self, i: usize) -> bool {
        self.stripped_tx(i).is_some()
    }

    /// The transaction's txid: the recorded one for a stripped tx,
    /// computed otherwise.
    pub fn txid(&self, i: usize) -> Txid {
        match self.stripped_tx(i) {
            Some(t) => t.txid,
            None => self.block.txdata[i].compute_txid(),
        }
    }

    pub fn wtxid(&self, i: usize) -> Wtxid {
        match self.stripped_tx(i) {
            Some(t) => t.wtxid.unwrap_or_else(|| Wtxid::from_raw_hash(t.txid.to_raw_hash())),
            None => self.block.txdata[i].compute_wtxid(),
        }
    }

    pub fn txids(&self) -> Vec<Txid> {
        (0..self.block.txdata.len()).map(|i| self.txid(i)).collect()
    }

    pub fn wtxids(&self) -> Vec<Wtxid> {
        (0..self.block.txdata.len()).map(|i| self.wtxid(i)).collect()
    }

    /// The indices of the stripped transactions, whose scripts a replay
    /// cannot verify: their signatures commit to the bytes that are gone.
    pub fn stripped_tx_indices(&self) -> std::collections::HashSet<usize> {
        self.strip
            .iter()
            .flat_map(|r| r.txs.iter().map(|t| t.tx_index as usize))
            .collect()
    }

    /// `(vout, original script length)` of each stripped output of tx `i`.
    pub fn stripped_outputs(&self, i: usize) -> Vec<(u32, u64)> {
        self.stripped_tx(i)
            .map(|t| t.outputs.iter().map(|o| (o.vout, o.script_len)).collect())
            .unwrap_or_default()
    }

    /// The block, only if nothing in it is stripped.
    pub fn into_intact(self) -> Option<Block> {
        self.strip.is_none().then_some(self.block)
    }

    /// Whether the txids reproduce the header's merkle root.
    pub fn verify_merkle(&self) -> bool {
        let hashes = self.txids().into_iter().map(|t| t.to_raw_hash());
        bitcoin::merkle_tree::calculate_root(hashes)
            .is_some_and(|root| root == self.block.header.merkle_root.to_raw_hash())
    }
}

// ---------------------------------------------------------------------------
// Replay reads
// ---------------------------------------------------------------------------

/// Why [`decode_for_replay`] produced no block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayReadError {
    #[error("block bytes do not deserialize: {0}")]
    Deserialize(String),
    /// The block has a strip record that cannot be read or does not match
    /// its bytes. A replay cannot connect it: the record is the only source
    /// of its txids.
    #[error("its OP_RETURN strip record {0}")]
    Record(String),
}

/// Decode block bytes that a replay read straight from its block file,
/// applying the block's strip record if it has one.
///
/// The bytes are read before the record is looked up, as in
/// `ChainState::get_stored_block`, and for the same reason. With no record
/// this is a plain deserialize, and checking that the bytes are the block
/// `hash` names is left to the caller, as it was, except for the lost-record
/// check `get_stored_block` also makes: an OP_RETURN payload that reads as
/// punched through `xor_key`, and txids that miss the merkle root, are a
/// record error rather than a block that fails validation. With a record the
/// zero-filled bytes must hash to the recorded value and the txids must
/// reproduce the merkle root, which ties the record to these bytes.
pub fn decode_for_replay(
    store: &dyn super::Store,
    bytes: Vec<u8>,
    hash: &BlockHash,
    xor_key: &[u8; 8],
) -> Result<StoredBlock, ReplayReadError> {
    let record = match store.get_opreturn_strip(hash) {
        Ok(None) => {
            let stored = deserialize(&bytes)
                .map(StoredBlock::intact)
                .map_err(|e| ReplayReadError::Deserialize(e.to_string()))?;
            if has_punched_op_return(&stored.block, xor_key) && !stored.verify_merkle() {
                return Err(ReplayReadError::Record(
                    "is missing: an OP_RETURN payload reads as punched and the txids miss the \
                     merkle root"
                        .to_string(),
                ));
            }
            return Ok(stored);
        }
        Ok(Some(raw)) => StripRecord::decode(&raw)
            .map_err(|e| ReplayReadError::Record(format!("does not decode: {e}")))?,
        Err(e) => return Err(ReplayReadError::Record(format!("could not be read: {e}"))),
    };
    StoredBlock::from_bytes(bytes, Some(record), hash)
        .map_err(|e| ReplayReadError::Record(format!("does not match the stored bytes: {e}")))
}

#[cfg(test)]
#[path = "opreturn_strip_tests.rs"]
mod tests;
