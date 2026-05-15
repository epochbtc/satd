//! Key/row encoding for the address-history index column families.
//!
//! All multi-byte integer fields are big-endian so RocksDB byte-order
//! iteration ascends by `(scripthash, height, txid, vout/vin)` for a
//! fixed scripthash prefix. The scripthash (or 16-byte prefix of it)
//! leads every key so a `prefix_iterator_cf` over a single
//! scripthash produces a sorted stream of that script's history
//! without an in-memory sort step.
//!
//! ## Two on-disk formats coexist
//!
//! * **v1** (legacy CFs `addr_funding`, `addr_spending`): full 32-byte
//!   scripthash in the key. 72-byte fixed key length.
//! * **v2** (new CFs `addr_funding_v2`, `addr_spending_v2`): only the
//!   first 16 bytes of the scripthash live in the key. 56-byte fixed
//!   key length — saves ~16 bytes per row, which is the bulk of the
//!   ~80 GB difference observed against a typical Bitcoin Core +
//!   electrs deployment.
//!
//! All new writes target v2. Reads consult both CFs and concatenate
//! the results (the lookups layer already sorts post-fetch). After
//! the offline migrator runs (planned PR E), v1 will be empty and
//! can be dropped in a later cleanup.
//!
//! ## Collision posture (v2)
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
//! addr_funding     v1 key: scripthash[32]        || height_be[4] || txid[32] || vout_be[4]  (72 bytes)
//! addr_funding_v2  v2 key: scripthash_prefix[16] || height_be[4] || txid[32] || vout_be[4]  (56 bytes)
//!                  value:  amount_sat_be[8]                                                 (8 bytes)
//!
//! addr_spending    v1 key: scripthash[32]        || height_be[4] || txid[32] || vin_be[4]   (72 bytes)
//! addr_spending_v2 v2 key: scripthash_prefix[16] || height_be[4] || txid[32] || vin_be[4]   (56 bytes)
//!                  value:  prev_outpoint_txid[32] || prev_outpoint_vout_be[4]               (36 bytes)
//! ```

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{OutPoint, Script, Txid};

/// `sha256(scriptPubKey)`. Modern Electrum convention; we do not
/// implement the legacy `hash160` variant.
pub type Scripthash = [u8; 32];

/// Encoded length of a v1 funding/spending key (full 32-byte
/// scripthash + height + txid + vout/vin).
pub const KEY_LEN: usize = 72;

/// Encoded length of a v2 funding/spending key (16-byte scripthash
/// prefix + height + txid + vout/vin). See the module docstring for
/// the collision-posture rationale.
pub const KEY_LEN_V2: usize = 56;

/// Number of scripthash bytes carried in a v2 key.
pub const SCRIPTHASH_PREFIX_LEN: usize = 16;

/// Encoded length of a funding value.
pub const FUNDING_VALUE_LEN: usize = 8;

/// Encoded length of a spending value.
pub const SPENDING_VALUE_LEN: usize = 36;

const SCRIPTHASH_LEN: usize = 32;
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

pub fn encode_funding_key(k: &AddrFundingKey) -> [u8; KEY_LEN] {
    let mut buf = [0u8; KEY_LEN];
    buf[..SCRIPTHASH_LEN].copy_from_slice(&k.scripthash);
    buf[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]
        .copy_from_slice(k.txid.as_ref());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].copy_from_slice(&k.vout.to_be_bytes());
    buf
}

pub fn decode_funding_key(b: &[u8]) -> Option<AddrFundingKey> {
    if b.len() != KEY_LEN {
        return None;
    }
    let mut scripthash = [0u8; SCRIPTHASH_LEN];
    scripthash.copy_from_slice(&b[..SCRIPTHASH_LEN]);
    let height = u32::from_be_bytes(
        b[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN]
            .try_into()
            .ok()?,
    );
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vout = u32::from_be_bytes(b[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].try_into().ok()?);
    Some(AddrFundingKey {
        scripthash,
        height,
        txid,
        vout,
    })
}

pub fn encode_spending_key(k: &AddrSpendingKey) -> [u8; KEY_LEN] {
    // Same layout as funding; vin replaces vout. Encode via the funding
    // helper to avoid duplicate code, then patch the trailing 4 bytes.
    let mut buf = [0u8; KEY_LEN];
    buf[..SCRIPTHASH_LEN].copy_from_slice(&k.scripthash);
    buf[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN].copy_from_slice(&k.height.to_be_bytes());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]
        .copy_from_slice(k.txid.as_ref());
    buf[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].copy_from_slice(&k.vin.to_be_bytes());
    buf
}

pub fn decode_spending_key(b: &[u8]) -> Option<AddrSpendingKey> {
    if b.len() != KEY_LEN {
        return None;
    }
    let mut scripthash = [0u8; SCRIPTHASH_LEN];
    scripthash.copy_from_slice(&b[..SCRIPTHASH_LEN]);
    let height = u32::from_be_bytes(
        b[SCRIPTHASH_LEN..SCRIPTHASH_LEN + HEIGHT_LEN]
            .try_into()
            .ok()?,
    );
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[SCRIPTHASH_LEN + HEIGHT_LEN..SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vin = u32::from_be_bytes(b[SCRIPTHASH_LEN + HEIGHT_LEN + TXID_LEN..].try_into().ok()?);
    Some(AddrSpendingKey {
        scripthash,
        height,
        txid,
        vin,
    })
}

// ---------------------------------------------------------------------------
// v2 encoding (16-byte scripthash prefix).
// ---------------------------------------------------------------------------

/// Per-row payload recovered from a v2 funding key. The 16-byte
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

/// Recombine the caller's full scripthash with a decoded v2 payload
/// to produce the canonical in-memory key. The first 16 bytes of
/// `caller_sh` must match the prefix in the on-disk row — callers
/// are expected to filter mismatches if collision-tolerance matters
/// to them (the address-index use case doesn't, see module doc).
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
    fn test_address_index_funding_key_roundtrip() {
        let key = AddrFundingKey {
            scripthash: fixture_scripthash(0xab),
            height: 700_000,
            txid: fixture_txid(0xcd),
            vout: 3,
        };
        let encoded = encode_funding_key(&key);
        assert_eq!(encoded.len(), KEY_LEN);
        let decoded = decode_funding_key(&encoded).expect("decode");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_address_index_spending_key_roundtrip() {
        let key = AddrSpendingKey {
            scripthash: fixture_scripthash(0x11),
            height: 800_000,
            txid: fixture_txid(0x22),
            vin: 17,
        };
        let encoded = encode_spending_key(&key);
        assert_eq!(encoded.len(), KEY_LEN);
        let decoded = decode_spending_key(&encoded).expect("decode");
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_address_index_funding_value_roundtrip() {
        let amount: u64 = 5_000_000_000;
        let encoded = encode_funding_value(amount);
        assert_eq!(decode_funding_value(&encoded), Some(amount));
    }

    #[test]
    fn test_address_index_spending_value_roundtrip() {
        let outpoint = OutPoint {
            txid: fixture_txid(0x55),
            vout: 99,
        };
        let encoded = encode_spending_value(&outpoint);
        let decoded = decode_spending_value(&encoded).expect("decode");
        assert_eq!(decoded, outpoint);
    }

    #[test]
    fn test_address_index_funding_key_sort_order_height_ascending() {
        // For a fixed scripthash, byte-order sorts must mirror height-ascending.
        let sh = fixture_scripthash(0x42);
        let keys = [10u32, 5, 7, 1_000_000, 1].map(|h| AddrFundingKey {
            scripthash: sh,
            height: h,
            txid: fixture_txid(0),
            vout: 0,
        });
        let mut encoded: Vec<[u8; KEY_LEN]> = keys.iter().map(encode_funding_key).collect();
        encoded.sort();
        let decoded_heights: Vec<u32> = encoded
            .iter()
            .map(|k| decode_funding_key(k).unwrap().height)
            .collect();
        assert_eq!(decoded_heights, vec![1, 5, 7, 10, 1_000_000]);
    }

    #[test]
    fn test_address_index_funding_key_sort_within_height_by_txid_then_vout() {
        let sh = fixture_scripthash(0xff);
        let h = 100u32;
        let keys = [
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0xaa),
                vout: 5,
            },
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0xaa),
                vout: 1,
            },
            AddrFundingKey {
                scripthash: sh,
                height: h,
                txid: fixture_txid(0x01),
                vout: 0,
            },
        ];
        let mut encoded: Vec<[u8; KEY_LEN]> = keys.iter().map(encode_funding_key).collect();
        encoded.sort();
        // Expect: txid 0x01 first, then 0xaa with vout 1, then 0xaa with vout 5.
        let decoded: Vec<AddrFundingKey> = encoded
            .iter()
            .map(|k| decode_funding_key(k).unwrap())
            .collect();
        assert_eq!(decoded[0].txid, fixture_txid(0x01));
        assert_eq!(decoded[1].txid, fixture_txid(0xaa));
        assert_eq!(decoded[1].vout, 1);
        assert_eq!(decoded[2].vout, 5);
    }

    #[test]
    fn test_address_index_funding_key_prefix_isolates_scripthash() {
        // Two different scripthashes' rows must never interleave under
        // a 32-byte prefix iterator.
        let sh_a = fixture_scripthash(0x10);
        let sh_b = fixture_scripthash(0x20);
        let mut all = Vec::new();
        for h in [1u32, 2, 3] {
            all.push(encode_funding_key(&AddrFundingKey {
                scripthash: sh_a,
                height: h,
                txid: fixture_txid(0),
                vout: 0,
            }));
            all.push(encode_funding_key(&AddrFundingKey {
                scripthash: sh_b,
                height: h,
                txid: fixture_txid(0),
                vout: 0,
            }));
        }
        all.sort();
        // First three rows are sh_a; next three are sh_b.
        for k in &all[..3] {
            assert_eq!(&k[..SCRIPTHASH_LEN], &sh_a[..]);
        }
        for k in &all[3..] {
            assert_eq!(&k[..SCRIPTHASH_LEN], &sh_b[..]);
        }
    }

    #[test]
    fn test_address_index_decode_rejects_wrong_length() {
        assert!(decode_funding_key(&[0u8; 71]).is_none());
        assert!(decode_funding_key(&[0u8; 73]).is_none());
        assert!(decode_spending_key(&[0u8; 0]).is_none());
        assert!(decode_funding_value(&[0u8; 7]).is_none());
        assert!(decode_spending_value(&[0u8; 35]).is_none());
    }

    // ----------------------------------------------------------------
    // v2 encoding tests.
    // ----------------------------------------------------------------

    #[test]
    fn v2_funding_key_roundtrip_via_reconstruct() {
        let sh = fixture_scripthash(0xab);
        let key = AddrFundingKey {
            scripthash: sh,
            height: 700_000,
            txid: fixture_txid(0xcd),
            vout: 3,
        };
        let encoded = encode_funding_key_v2(&key);
        assert_eq!(encoded.len(), KEY_LEN_V2);
        // The v2 prefix in the key must match the first 16 bytes of
        // the source scripthash.
        assert_eq!(&encoded[..SCRIPTHASH_PREFIX_LEN], &sh[..SCRIPTHASH_PREFIX_LEN]);
        let payload = decode_funding_key_v2(&encoded).expect("decode");
        let recovered = reconstruct_funding_key(&sh, payload);
        assert_eq!(recovered, key);
    }

    #[test]
    fn v2_spending_key_roundtrip_via_reconstruct() {
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
    fn v2_funding_key_sort_order_height_ascending() {
        // For a fixed scripthash, byte-order sorts must mirror
        // height-ascending — same invariant as v1, but at v2 length.
        let sh = fixture_scripthash(0x42);
        let keys = [10u32, 5, 7, 1_000_000, 1].map(|h| AddrFundingKey {
            scripthash: sh,
            height: h,
            txid: fixture_txid(0),
            vout: 0,
        });
        let mut encoded: Vec<[u8; KEY_LEN_V2]> = keys.iter().map(encode_funding_key_v2).collect();
        encoded.sort();
        let decoded_heights: Vec<u32> = encoded
            .iter()
            .map(|k| decode_funding_key_v2(k).unwrap().height)
            .collect();
        assert_eq!(decoded_heights, vec![1, 5, 7, 10, 1_000_000]);
    }

    #[test]
    fn v2_prefix_iterates_only_matching_rows_in_sort_order() {
        // Two distinct full scripthashes that share the same first 16
        // bytes must produce keys that interleave under a 16-byte
        // prefix iterator (the index can't distinguish them — that's
        // the collision-tolerant trade-off documented at the top of
        // this module). Two scripthashes whose first 16 bytes differ
        // must NOT interleave.
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
        // sh_c with prefix 0x20 sorts after sh_a/sh_b with prefix 0x10.
        // sh_a and sh_b share the prefix and sort by height.
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
    fn v2_decode_rejects_wrong_length() {
        assert!(decode_funding_key_v2(&[0u8; KEY_LEN_V2 - 1]).is_none());
        assert!(decode_funding_key_v2(&[0u8; KEY_LEN_V2 + 1]).is_none());
        // A v1-length input must NOT accidentally decode as v2 (different schema).
        assert!(decode_funding_key_v2(&[0u8; KEY_LEN]).is_none());
        assert!(decode_spending_key_v2(&[0u8; 0]).is_none());
    }

    // Documents the disk win: per-row key savings = KEY_LEN - KEY_LEN_V2.
    // Compile-time check so the relationship can't drift under accidental
    // const edits.
    const _: () = assert!(KEY_LEN_V2 < KEY_LEN);
    const _: () = assert!(KEY_LEN - KEY_LEN_V2 == 16);

    #[test]
    fn test_address_index_scripthash_of_p2wpkh_known_vector() {
        // P2WPKH scriptPubKey: OP_0 <20-byte pubkey-hash>. We pick a
        // fixed pubkey-hash so the hash is reproducible. Compute the
        // expected sha256 with the same library so the test verifies
        // the helper is doing sha256(serialized_script) and not, e.g.,
        // sha256d or hash160.
        let pkh = [0x42u8; 20];
        let mut spk_bytes = vec![0x00, 0x14]; // OP_0 PUSH(20)
        spk_bytes.extend_from_slice(&pkh);
        let spk = ScriptBuf::from(spk_bytes.clone());

        let got = scripthash_of(&spk);
        let expected = sha256::Hash::hash(&spk_bytes).to_byte_array();
        assert_eq!(got, expected);
    }
}
