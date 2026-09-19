//! Key/row encoding for the address-history index column families.
//!
//! All multi-byte integer fields are big-endian so RocksDB byte-order
//! iteration ascends by `(scripthash_prefix, height, txid, vout/vin)`
//! for a fixed scripthash prefix. The prefix leads every key so a
//! `prefix_iterator_cf` over a single scripthash produces a sorted
//! stream of that script's history without an in-memory sort step.
//!
//! Keys carry only the first 16 bytes of the scripthash (the v2
//! schema; the suffix is fossilized in the on-disk CF names
//! `addr_funding_v2` / `addr_spending_v2`). The 16-byte truncation
//! saves ~16 bytes per row vs a full 32-byte scripthash — the bulk of
//! the disk-size delta against Bitcoin Core + electrs.
//!
//! ## Collision posture
//!
//! Scripthashes are `sha256(scriptPubKey)`. A 16-byte prefix gives
//! 2^128 codomain; birthday collision probability at 2^32 entries is
//! ~2^-64 — vanishingly small for honest workloads. A deliberate
//! collision is feasible at ~2^64 hashing work, but the attack outcome
//! is "querying scripthash X also returns events for scripthash Y" —
//! both X and Y are public on-chain data, so no privacy or correctness
//! violation results for the address-index use case.
//!
//! Schema layout:
//!
//! ```text
//! addr_funding_v3  key: scripthash_prefix[16] || txseq[5] || vout_be[3]                  (24 bytes)
//!                  value: amount_sat_be[8]                                               (8 bytes)
//!
//! addr_spending_v2 key: scripthash_prefix[16] || height_be[4] || txid[32] || vin_be[4]   (56 bytes)
//!                  value: prev_outpoint_txid[32] || prev_outpoint_vout_be[4]             (36 bytes)
//! ```
//!
//! The v3 funding key replaces a 4-byte height and a 32-byte txid with a
//! 5-byte chain-order ordinal, from which both are recoverable: the
//! `txseq_txid` family maps back to the txid and `txseq_block` to the
//! height. Thirty-two bytes a row against sixty-four, and the identifier
//! is stored once, in one place, instead of once per index that mentions
//! the transaction.
//!
//! An ordinal never leaves the storage layer. The store resolves each row
//! to the public [`AddrFundingKey`] — which still carries `height` and
//! `txid` — before returning it, and sorts the resolved rows into
//! `(height, txid, vout)`, so the documented iteration order and every
//! consumer above it are unchanged. Byte order within one scripthash
//! prefix is chain order either way; the two differ only in how
//! transactions of the *same* block tie-break, which is what the sort
//! settles.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{OutPoint, Script, Txid};

use crate::txseq::{TXSEQ_LEN, TxSeq, VOUT_LEN, decode_txseq, decode_u24, encode_txseq, encode_u24};

/// `sha256(scriptPubKey)`. Modern Electrum convention; we do not
/// implement the legacy `hash160` variant.
pub type Scripthash = [u8; 32];

/// Encoded length of a v2 spending key. The funding side moved to the
/// v3 layout; this stays until the spending side follows.
pub const KEY_LEN_V2: usize = 56;

/// Encoded length of a v3 funding key: the 16-byte scripthash prefix,
/// the transaction's 5-byte chain-order ordinal, and a 3-byte vout.
///
/// u24 for the vout, not u16: a 1 MB transaction can carry more than
/// 65,535 outputs (the minimum output is 9 bytes serialized) and
/// consensus does not forbid it. u32 would cost a byte a row across
/// every address family for range no transaction can reach.
pub const KEY_LEN_V3: usize = SCRIPTHASH_PREFIX_LEN + TXSEQ_LEN + VOUT_LEN;

/// Number of scripthash bytes carried in a key.
pub const SCRIPTHASH_PREFIX_LEN: usize = 16;

/// Encoded length of a funding value.
pub const FUNDING_VALUE_LEN: usize = 8;

/// Encoded length of a spending value.
pub const SPENDING_VALUE_LEN: usize = 36;

const HEIGHT_LEN: usize = 4;
const TXID_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddrFundingKey {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Clone, Debug)]
pub struct AddrFundingRow {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vout: u32,
    pub amount_sat: u64,
}

impl AddrFundingRow {
    pub fn key(&self) -> AddrFundingKey {
        AddrFundingKey {
            scripthash: self.scripthash,
            height: self.height,
            txid: self.txid,
            vout: self.vout,
        }
    }
}

/// A funding row's key as it sits on disk.
///
/// The public [`AddrFundingKey`] is what leaves the storage layer: the
/// store resolves the ordinal to `(height, txid)` before returning a
/// row, so every consumer above it is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddrFundingKeyV3 {
    pub scripthash: Scripthash,
    pub txseq: u64,
    pub vout: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrFundingRowV3 {
    pub scripthash: Scripthash,
    pub txseq: u64,
    pub vout: u32,
    pub amount_sat: u64,
}

impl AddrFundingRowV3 {
    pub fn key(&self) -> AddrFundingKeyV3 {
        AddrFundingKeyV3 {
            scripthash: self.scripthash,
            txseq: self.txseq,
            vout: self.vout,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddrSpendingKey {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
}

#[derive(Clone, Debug)]
pub struct AddrSpendingRow {
    pub scripthash: Scripthash,
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
    pub prev_outpoint: OutPoint,
}

impl AddrSpendingRow {
    pub fn key(&self) -> AddrSpendingKey {
        AddrSpendingKey {
            scripthash: self.scripthash,
            height: self.height,
            txid: self.txid,
            vin: self.vin,
        }
    }
}

#[inline]
pub fn scripthash_of(spk: &Script) -> Scripthash {
    sha256::Hash::hash(spk.as_bytes()).to_byte_array()
}

/// Per-row payload recovered from a funding key. The 16-byte
/// scripthash prefix is discarded by the decoder because the caller
/// already knows the full scripthash they queried — see
/// [`reconstruct_funding_key_v3`] for the trivial recombination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrFundingKeyV3Payload {
    pub txseq: u64,
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpendingKeyV2Payload {
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
}

pub fn encode_funding_key_v3(k: &AddrFundingKeyV3) -> [u8; KEY_LEN_V3] {
    let mut buf = [0u8; KEY_LEN_V3];
    buf[..SCRIPTHASH_PREFIX_LEN].copy_from_slice(&k.scripthash[..SCRIPTHASH_PREFIX_LEN]);
    let mut o = SCRIPTHASH_PREFIX_LEN;
    buf[o..o + TXSEQ_LEN].copy_from_slice(&encode_txseq(TxSeq(k.txseq)));
    o += TXSEQ_LEN;
    buf[o..].copy_from_slice(&encode_u24(k.vout));
    buf
}

pub fn decode_funding_key_v3(b: &[u8]) -> Option<AddrFundingKeyV3Payload> {
    if b.len() != KEY_LEN_V3 {
        return None;
    }
    let o = SCRIPTHASH_PREFIX_LEN;
    let txseq = decode_txseq(&b[o..o + TXSEQ_LEN])?.0;
    let vout = decode_u24(&b[o + TXSEQ_LEN..])?;
    Some(AddrFundingKeyV3Payload { txseq, vout })
}

pub fn encode_spending_key_v2(k: &AddrSpendingKey) -> [u8; KEY_LEN_V2] {
    let mut buf = [0u8; KEY_LEN_V2];
    buf[..SCRIPTHASH_PREFIX_LEN].copy_from_slice(&k.scripthash[..SCRIPTHASH_PREFIX_LEN]);
    let mut o = SCRIPTHASH_PREFIX_LEN;
    buf[o..o + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    o += HEIGHT_LEN;
    buf[o..o + TXID_LEN].copy_from_slice(k.txid.as_ref());
    o += TXID_LEN;
    buf[o..o + 4].copy_from_slice(&k.vin.to_be_bytes());
    buf
}

pub fn decode_spending_key_v2(b: &[u8]) -> Option<AddrSpendingKeyV2Payload> {
    if b.len() != KEY_LEN_V2 {
        return None;
    }
    let mut o = SCRIPTHASH_PREFIX_LEN;
    let height = u32::from_be_bytes(b[o..o + HEIGHT_LEN].try_into().ok()?);
    o += HEIGHT_LEN;
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[o..o + TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    o += TXID_LEN;
    let vin = u32::from_be_bytes(b[o..].try_into().ok()?);
    Some(AddrSpendingKeyV2Payload { height, txid, vin })
}

/// Recombine the caller's full scripthash with a decoded payload to
/// produce the canonical in-memory key. The first 16 bytes of
/// `caller_sh` must match the prefix in the on-disk row — callers are
/// expected to filter mismatches if collision-tolerance matters to
/// them (the address-index use case doesn't, see module doc).
pub fn reconstruct_funding_key_v3(
    caller_sh: &Scripthash,
    payload: AddrFundingKeyV3Payload,
) -> AddrFundingKeyV3 {
    AddrFundingKeyV3 {
        scripthash: *caller_sh,
        txseq: payload.txseq,
        vout: payload.vout,
    }
}

pub fn reconstruct_spending_key(
    caller_sh: &Scripthash,
    payload: AddrSpendingKeyV2Payload,
) -> AddrSpendingKey {
    AddrSpendingKey {
        scripthash: *caller_sh,
        height: payload.height,
        txid: payload.txid,
        vin: payload.vin,
    }
}

pub fn encode_funding_value(amount_sat: u64) -> [u8; FUNDING_VALUE_LEN] {
    amount_sat.to_be_bytes()
}

pub fn decode_funding_value(b: &[u8]) -> Option<u64> {
    if b.len() != FUNDING_VALUE_LEN {
        return None;
    }
    Some(u64::from_be_bytes(b.try_into().ok()?))
}

pub fn encode_spending_value(prev: &OutPoint) -> [u8; SPENDING_VALUE_LEN] {
    let mut buf = [0u8; SPENDING_VALUE_LEN];
    buf[..TXID_LEN].copy_from_slice(prev.txid.as_ref());
    buf[TXID_LEN..].copy_from_slice(&prev.vout.to_be_bytes());
    buf
}

pub fn decode_spending_value(b: &[u8]) -> Option<OutPoint> {
    if b.len() != SPENDING_VALUE_LEN {
        return None;
    }
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[..TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vout = u32::from_be_bytes(b[TXID_LEN..].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    fn fixture_scripthash(byte: u8) -> Scripthash {
        [byte; 32]
    }

    #[test]
    fn funding_value_roundtrip() {
        let amount: u64 = 5_000_000_000;
        let encoded = encode_funding_value(amount);
        assert_eq!(decode_funding_value(&encoded), Some(amount));
    }

    #[test]
    fn spending_value_roundtrip() {
        let outpoint = OutPoint {
            txid: fixture_txid(0x55),
            vout: 99,
        };
        let encoded = encode_spending_value(&outpoint);
        let decoded = decode_spending_value(&encoded).expect("decode");
        assert_eq!(decoded, outpoint);
    }

    #[test]
    fn funding_key_roundtrip_via_reconstruct() {
        let sh = fixture_scripthash(0xab);
        let key = AddrFundingKeyV3 {
            scripthash: sh,
            txseq: 700_000,
            vout: 3,
        };
        let encoded = encode_funding_key_v3(&key);
        assert_eq!(encoded.len(), KEY_LEN_V3);
        // The prefix in the key must match the first 16 bytes of the
        // source scripthash.
        assert_eq!(&encoded[..SCRIPTHASH_PREFIX_LEN], &sh[..SCRIPTHASH_PREFIX_LEN]);
        let payload = decode_funding_key_v3(&encoded).expect("decode");
        let recovered = reconstruct_funding_key_v3(&sh, payload);
        assert_eq!(recovered, key);
    }

    /// The claim the footprint rests on: 24 bytes of key and 8 of value.
    #[test]
    fn funding_row_bytes_are_32() {
        let key = AddrFundingKeyV3 {
            scripthash: fixture_scripthash(0x01),
            txseq: crate::txseq::TXSEQ_MAX,
            vout: (1 << 24) - 1,
        };
        assert_eq!(encode_funding_key_v3(&key).len(), 24);
        assert_eq!(encode_funding_value(u64::MAX).len(), 8);
    }

    /// Decoding is exact-length. A 56-byte v2 row fed to the v3 decoder
    /// would otherwise read a height and half a txid as an ordinal and
    /// a vout, producing a row that looks well-formed and points at a
    /// transaction that has nothing to do with it.
    #[test]
    fn funding_key_v3_decode_rejects_a_v2_length_row() {
        assert!(decode_funding_key_v3(&[0u8; KEY_LEN_V2]).is_none());
        assert!(decode_funding_key_v3(&[0u8; KEY_LEN_V3 - 1]).is_none());
        assert!(decode_funding_key_v3(&[0u8; KEY_LEN_V3 + 1]).is_none());
        assert!(decode_funding_key_v3(&[]).is_none());
    }

    #[test]
    fn spending_key_roundtrip_via_reconstruct() {
        let sh = fixture_scripthash(0x33);
        let key = AddrSpendingKey {
            scripthash: sh,
            height: 800_000,
            txid: fixture_txid(0x22),
            vin: 17,
        };
        let encoded = encode_spending_key_v2(&key);
        assert_eq!(encoded.len(), KEY_LEN_V2);
        assert_eq!(&encoded[..SCRIPTHASH_PREFIX_LEN], &sh[..SCRIPTHASH_PREFIX_LEN]);
        let payload = decode_spending_key_v2(&encoded).expect("decode");
        let recovered = reconstruct_spending_key(&sh, payload);
        assert_eq!(recovered, key);
    }

    #[test]
    fn funding_key_sort_order_ordinal_ascending() {
        // For a fixed scripthash, byte-order sorts must mirror
        // ordinal-ascending — and since ordinals are assigned in chain
        // order, that is height-ascending too. This is the invariant
        // that lets a RocksDB `prefix_iterator_cf` produce a
        // near-ordered stream.
        let sh = fixture_scripthash(0x42);
        let keys = [10u64, 5, 7, 1_000_000, 1, 1 << 33].map(|seq| AddrFundingKeyV3 {
            scripthash: sh,
            txseq: seq,
            vout: 0,
        });
        let mut encoded: Vec<[u8; KEY_LEN_V3]> = keys.iter().map(encode_funding_key_v3).collect();
        encoded.sort();
        let decoded: Vec<u64> = encoded
            .iter()
            .map(|k| decode_funding_key_v3(k).unwrap().txseq)
            .collect();
        assert_eq!(decoded, vec![1, 5, 7, 10, 1_000_000, 1 << 33]);
    }

    #[test]
    fn prefix_iterates_only_matching_rows_in_sort_order() {
        // Two distinct full scripthashes that share the same first 16
        // bytes produce keys that interleave under a 16-byte prefix
        // iterator (the index can't distinguish them — the collision-
        // tolerant trade-off documented at the top of this module).
        // Two scripthashes whose first 16 bytes differ must NOT
        // interleave.
        let sh_a = {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&[0x10; 16]);
            sh[16..].copy_from_slice(&[0xAA; 16]);
            sh
        };
        let sh_b = {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&[0x10; 16]); // same prefix as sh_a
            sh[16..].copy_from_slice(&[0xBB; 16]);
            sh
        };
        let sh_c = {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&[0x20; 16]); // different prefix
            sh[16..].copy_from_slice(&[0xCC; 16]);
            sh
        };
        let mk = |sh, seq| AddrFundingKeyV3 {
            scripthash: sh,
            txseq: seq,
            vout: 0,
        };
        let mut all = [
            encode_funding_key_v3(&mk(sh_a, 5)),
            encode_funding_key_v3(&mk(sh_b, 3)),
            encode_funding_key_v3(&mk(sh_c, 1)),
        ];
        all.sort();
        let prefixes: Vec<[u8; 16]> = all
            .iter()
            .map(|k| {
                let mut p = [0u8; 16];
                p.copy_from_slice(&k[..16]);
                p
            })
            .collect();
        assert_eq!(prefixes[0], [0x10; 16]);
        assert_eq!(prefixes[1], [0x10; 16]);
        assert_eq!(prefixes[2], [0x20; 16]);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_funding_key_v3(&[0u8; KEY_LEN_V3 - 1]).is_none());
        assert!(decode_funding_key_v3(&[0u8; KEY_LEN_V3 + 1]).is_none());
        assert!(decode_spending_key_v2(&[0u8; 0]).is_none());
        assert!(decode_funding_value(&[0u8; 7]).is_none());
        assert!(decode_spending_value(&[0u8; 35]).is_none());
    }

    #[test]
    fn scripthash_of_p2wpkh_known_vector() {
        // P2WPKH scriptPubKey: OP_0 <20-byte pubkey-hash>. Verify the
        // helper is sha256(serialized_script) and not, e.g., sha256d
        // or hash160.
        let pkh = [0x42u8; 20];
        let mut spk_bytes = vec![0x00, 0x14]; // OP_0 PUSH(20)
        spk_bytes.extend_from_slice(&pkh);
        let spk = ScriptBuf::from(spk_bytes.clone());

        let got = scripthash_of(&spk);
        let expected = sha256::Hash::hash(&spk_bytes).to_byte_array();
        assert_eq!(got, expected);
    }
}
