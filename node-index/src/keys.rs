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
//! addr_funding_v2  key: scripthash_prefix[16] || height_be[4] || txid[32] || vout_be[4]  (56 bytes)
//!                  value: amount_sat_be[8]                                               (8 bytes)
//!
//! addr_spending_v2 key: scripthash_prefix[16] || height_be[4] || txid[32] || vin_be[4]   (56 bytes)
//!                  value: prev_outpoint_txid[32] || prev_outpoint_vout_be[4]             (36 bytes)
//! ```

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{OutPoint, Script, Txid};

/// `sha256(scriptPubKey)`. Modern Electrum convention; we do not
/// implement the legacy `hash160` variant.
pub type Scripthash = [u8; 32];

/// Encoded length of a funding/spending key.
pub const KEY_LEN_V2: usize = 56;

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
/// [`reconstruct_funding_key`] for the trivial recombination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrFundingKeyV2Payload {
    pub height: u32,
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSpendingKeyV2Payload {
    pub height: u32,
    pub txid: Txid,
    pub vin: u32,
}

pub fn encode_funding_key_v2(k: &AddrFundingKey) -> [u8; KEY_LEN_V2] {
    let mut buf = [0u8; KEY_LEN_V2];
    buf[..SCRIPTHASH_PREFIX_LEN].copy_from_slice(&k.scripthash[..SCRIPTHASH_PREFIX_LEN]);
    let mut o = SCRIPTHASH_PREFIX_LEN;
    buf[o..o + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    o += HEIGHT_LEN;
    buf[o..o + TXID_LEN].copy_from_slice(k.txid.as_ref());
    o += TXID_LEN;
    buf[o..o + 4].copy_from_slice(&k.vout.to_be_bytes());
    buf
}

pub fn decode_funding_key_v2(b: &[u8]) -> Option<AddrFundingKeyV2Payload> {
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
    let vout = u32::from_be_bytes(b[o..].try_into().ok()?);
    Some(AddrFundingKeyV2Payload { height, txid, vout })
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
pub fn reconstruct_funding_key(
    caller_sh: &Scripthash,
    payload: AddrFundingKeyV2Payload,
) -> AddrFundingKey {
    AddrFundingKey {
        scripthash: *caller_sh,
        height: payload.height,
        txid: payload.txid,
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
        let key = AddrFundingKey {
            scripthash: sh,
            height: 700_000,
            txid: fixture_txid(0xcd),
            vout: 3,
        };
        let encoded = encode_funding_key_v2(&key);
        assert_eq!(encoded.len(), KEY_LEN_V2);
        // The prefix in the key must match the first 16 bytes of the
        // source scripthash.
        assert_eq!(&encoded[..SCRIPTHASH_PREFIX_LEN], &sh[..SCRIPTHASH_PREFIX_LEN]);
        let payload = decode_funding_key_v2(&encoded).expect("decode");
        let recovered = reconstruct_funding_key(&sh, payload);
        assert_eq!(recovered, key);
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
    fn funding_key_sort_order_height_ascending() {
        // For a fixed scripthash, byte-order sorts must mirror
        // height-ascending — this is the invariant that lets us use a
        // RocksDB `prefix_iterator_cf` without an in-memory re-sort.
        let sh = fixture_scripthash(0x42);
        let keys = [10u32, 5, 7, 1_000_000, 1].map(|h| AddrFundingKey {
            scripthash: sh,
            height: h,
            txid: fixture_txid(0),
            vout: 0,
        });
        let mut encoded: Vec<[u8; KEY_LEN_V2]> =
            keys.iter().map(encode_funding_key_v2).collect();
        encoded.sort();
        let decoded_heights: Vec<u32> = encoded
            .iter()
            .map(|k| decode_funding_key_v2(k).unwrap().height)
            .collect();
        assert_eq!(decoded_heights, vec![1, 5, 7, 10, 1_000_000]);
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
        let mk = |sh, h| AddrFundingKey {
            scripthash: sh,
            height: h,
            txid: fixture_txid(0),
            vout: 0,
        };
        let mut all = [
            encode_funding_key_v2(&mk(sh_a, 5)),
            encode_funding_key_v2(&mk(sh_b, 3)),
            encode_funding_key_v2(&mk(sh_c, 1)),
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
        assert!(decode_funding_key_v2(&[0u8; KEY_LEN_V2 - 1]).is_none());
        assert!(decode_funding_key_v2(&[0u8; KEY_LEN_V2 + 1]).is_none());
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
