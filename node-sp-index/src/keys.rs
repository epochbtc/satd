//! Key + row codec for the `sp_tweaks` column family.
//!
//! Layout (design §3.2), one row per block from taproot activation
//! upward — present even when empty, so row-presence distinguishes
//! "indexed, no eligible txs" from "not indexed":
//!
//! ```text
//! cf sp_tweaks   key:   height_be[4]
//!                value: version[1]=0x01 || block_hash[32] || count_be[4] || count × entry
//!                entry: txid[32] || tweak[33] || max_value_be[8]        (73 B)
//! ```
//!
//! Big-endian heights so byte-order iteration ascends by height (point
//! lookups / range scans, like the filter CF — no prefix extractor).
//!
//! The embedded `block_hash` makes each row **self-authenticating**: any
//! reader (the D4 rescan fast path, streaming replay, the fallback RPC)
//! verifies the row describes the block it expects without consulting the
//! height→hash index — which this codebase has learned never to treat as
//! truth (the #322 accept_header clobber, the testnet4 MTP wedge). A
//! mid-read reorg surfaces as a hash mismatch and the reader falls back
//! or rejects rather than trusting height alone.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, BlockHash, Txid};

use crate::compute::TweakEntry;
use crate::types::SpCodecError;

/// Column-family name for the tweak index. Created unconditionally
/// alongside the other index CFs (no prefix extractor).
pub const CF_SP_TWEAKS: &str = "sp_tweaks";

/// Row format version. Bumped only on an incompatible on-disk change.
pub const SP_TWEAKS_VERSION: u8 = 0x01;

/// Encoded length of a `sp_tweaks` key (`height_be[4]`).
pub const SP_KEY_LEN: usize = 4;

/// Per-entry length: `txid[32] || tweak[33] || max_value_be[8]`.
const ENTRY_LEN: usize = 32 + 33 + 8;
/// Fixed header length: `version[1] || block_hash[32] || count_be[4]`.
const HEADER_LEN: usize = 1 + 32 + 4;

#[inline]
pub fn encode_sp_key(height: u32) -> [u8; SP_KEY_LEN] {
    height.to_be_bytes()
}

#[inline]
pub fn decode_sp_key(buf: &[u8]) -> Option<u32> {
    if buf.len() != SP_KEY_LEN {
        return None;
    }
    Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// A decoded `sp_tweaks` row: the block it describes plus its eligible
/// transactions' tweak entries (possibly empty for an indexed block with
/// no eligible txs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpBlockRow {
    pub block_hash: BlockHash,
    pub entries: Vec<TweakEntry>,
}

impl SpBlockRow {
    pub fn new(block_hash: BlockHash, entries: Vec<TweakEntry>) -> Self {
        Self {
            block_hash,
            entries,
        }
    }

    /// Serialize to the on-disk row value.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.entries.len() * ENTRY_LEN);
        out.push(SP_TWEAKS_VERSION);
        out.extend_from_slice(&self.block_hash.to_byte_array());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.txid.to_byte_array());
            out.extend_from_slice(&e.tweak.serialize());
            out.extend_from_slice(&e.max_taproot_value.to_sat().to_be_bytes());
        }
        out
    }

    /// Deserialize an on-disk row value.
    pub fn decode(buf: &[u8]) -> Result<Self, SpCodecError> {
        if buf.len() < HEADER_LEN {
            return Err(SpCodecError::TooShort(buf.len()));
        }
        if buf[0] != SP_TWEAKS_VERSION {
            return Err(SpCodecError::UnknownVersion(buf[0]));
        }
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&buf[1..33]);
        let block_hash = BlockHash::from_byte_array(block_hash_bytes);
        let count = u32::from_be_bytes([buf[33], buf[34], buf[35], buf[36]]);

        let body = &buf[HEADER_LEN..];
        if body.len() != count as usize * ENTRY_LEN {
            return Err(SpCodecError::LengthMismatch {
                len: buf.len(),
                count,
            });
        }

        let mut entries = Vec::with_capacity(count as usize);
        for (i, chunk) in body.chunks_exact(ENTRY_LEN).enumerate() {
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(&chunk[0..32]);
            let txid = Txid::from_byte_array(txid_bytes);
            let tweak = PublicKey::from_slice(&chunk[32..65])
                .map_err(|_| SpCodecError::InvalidTweak(i as u32))?;
            let mut val = [0u8; 8];
            val.copy_from_slice(&chunk[65..73]);
            let max_taproot_value = Amount::from_sat(u64::from_be_bytes(val));
            entries.push(TweakEntry {
                txid,
                tweak,
                max_taproot_value,
            });
        }
        Ok(Self {
            block_hash,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_and_ascending_order() {
        let heights = [0u32, 1, 709_632, 1_000_000, u32::MAX];
        for &h in &heights {
            assert_eq!(decode_sp_key(&encode_sp_key(h)), Some(h));
        }
        let mut encoded: Vec<[u8; SP_KEY_LEN]> =
            heights.iter().map(|&h| encode_sp_key(h)).collect();
        encoded.sort();
        let sorted: Vec<u32> = encoded.iter().map(|k| decode_sp_key(k).unwrap()).collect();
        assert_eq!(sorted, vec![0, 1, 709_632, 1_000_000, u32::MAX]);
    }

    #[test]
    fn key_decode_rejects_wrong_length() {
        assert!(decode_sp_key(&[]).is_none());
        assert!(decode_sp_key(&[0u8; 3]).is_none());
        assert!(decode_sp_key(&[0u8; 5]).is_none());
    }

    fn sample_tweak() -> PublicKey {
        // Generator point G — a stable valid compressed point for codec tests.
        PublicKey::from_slice(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap()
    }

    #[test]
    fn empty_row_roundtrips() {
        let row = SpBlockRow::new(BlockHash::from_byte_array([0xab; 32]), vec![]);
        let bytes = row.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(SpBlockRow::decode(&bytes).unwrap(), row);
    }

    #[test]
    fn multi_entry_row_roundtrips() {
        let row = SpBlockRow::new(
            BlockHash::from_byte_array([0x11; 32]),
            vec![
                TweakEntry {
                    txid: Txid::from_byte_array([0x22; 32]),
                    tweak: sample_tweak(),
                    max_taproot_value: Amount::from_sat(1_000),
                },
                TweakEntry {
                    txid: Txid::from_byte_array([0x33; 32]),
                    tweak: sample_tweak(),
                    max_taproot_value: Amount::from_sat(2_100_000_000_000_000),
                },
            ],
        );
        let bytes = row.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 * ENTRY_LEN);
        assert_eq!(SpBlockRow::decode(&bytes).unwrap(), row);
    }

    #[test]
    fn decode_rejects_bad_version_and_length() {
        let mut bytes = SpBlockRow::new(BlockHash::all_zeros(), vec![]).encode();
        assert!(SpBlockRow::decode(&bytes[..HEADER_LEN - 1]).is_err());
        bytes[0] = 0x02;
        assert_eq!(
            SpBlockRow::decode(&bytes),
            Err(SpCodecError::UnknownVersion(0x02))
        );
        // Claim one entry but supply no body.
        let mut short = SpBlockRow::new(BlockHash::all_zeros(), vec![]).encode();
        short[33..37].copy_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            SpBlockRow::decode(&short),
            Err(SpCodecError::LengthMismatch { .. })
        ));
    }
}
