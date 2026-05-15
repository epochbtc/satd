//! Undo data for connected blocks.
//!
//! Two on-disk formats coexist while the migration runs:
//!
//! * **v0** — bincode-encoded `Vec<(OutPointSer, Coin)>`. Every entry pays
//!   for a 32-byte txid + 4-byte vout (the outpoint) plus a bincode-encoded
//!   coin (~43 bytes for typical P2WPKH). Historical default; what's on
//!   disk pre-PR.
//! * **v1** — explicit framing: a 9-byte header (8-byte magic + 1-byte
//!   version) followed by a varint count and back-to-back
//!   `Coin::serialize_compact` records. Drops the outpoint entirely —
//!   the disconnect path recovers each outpoint from the block's tx
//!   inputs (the connect-order invariant guarantees
//!   `undo.spent_coins[i]` belongs to the i-th non-coinbase input).
//!   Per-spend: ~28 bytes typical, vs ~79 in v0.
//!
//! All new writes are v1. Reads transparently dispatch on the magic —
//! anything that doesn't start with `V1_MAGIC` is decoded as v0 (and
//! its stored outpoints are discarded, since the in-memory shape is now
//! `Vec<Coin>` regardless of source format). The forthcoming
//! `migrate-undo` subcommand rewrites every v0 row as v1 in one batch.
//!
//! **Magic safety.** The v1 magic is 8 bytes whose little-endian `u64`
//! interpretation (`0xC0DECAFE_C0DECAFE` ≈ 1.39 × 10^19) is far above
//! any conceivable `Vec` count, so it cannot collide with a legacy
//! bincode length prefix. (A 2-byte magic was tried first and rejected
//! in review: `[0xFE 0x01]` collides with a legacy row whose
//! `spent_coins.len()` is exactly 510 — completely plausible on
//! mainnet.)

use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

use crate::storage::coinview::{Coin, decode_varint, encode_varint};

/// Undo data for a connected block — the coins that were spent, one per
/// non-coinbase input in connect order. The outpoint for each entry is
/// recoverable from the block's `tx.input[i].previous_output`, so we no
/// longer store it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UndoData {
    pub spent_coins: Vec<Coin>,
}

/// 8-byte v1 magic. Chosen so that the bytes interpreted as a
/// little-endian `u64` (`0xC0DECAFE_C0DECAFE`) exceed any plausible
/// `Vec` count by orders of magnitude — there is no realistic legacy
/// bincode row whose length prefix matches.
pub(crate) const V1_MAGIC: [u8; 8] = [0xFE, 0xCA, 0xDE, 0xC0, 0xFE, 0xCA, 0xDE, 0xC0];

/// Single-byte version, written immediately after [`V1_MAGIC`]. The
/// magic+version split lets future format revisions reuse the same
/// magic and bump only this byte.
pub(crate) const V1_VERSION: u8 = 0x01;

const V1_HEADER_LEN: usize = V1_MAGIC.len() + 1;

/// Hard cap on spent-coin count when decoding v1. Bitcoin's 4 MWU block
/// weight at ~41 bytes/input bounds inputs per block to under ~100k.
/// 1M is a 10× safety margin and keeps a corrupt count from triggering
/// an unbounded `Vec::with_capacity` allocation. The on-disk write
/// path never exceeds this because the writer's count is the block's
/// non-coinbase input count.
pub(crate) const MAX_UNDO_SPENT_COINS: usize = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum UndoDecodeError {
    #[error("undo: truncated v1 header")]
    Truncated,
    #[error("undo: unsupported v1 version byte {0:#x}")]
    UnsupportedVersion(u8),
    #[error("undo: v1 count overflowed usize")]
    CountOverflow,
    #[error("undo: v1 count {count} exceeds cap {cap}")]
    CountTooLarge { count: u64, cap: usize },
    #[error("undo: failed to decode v1 coin {index}")]
    CoinDecode { index: usize },
    #[error("undo: trailing bytes after v1 stream ({remaining} bytes)")]
    TrailingBytes { remaining: usize },
    #[error("undo: legacy bincode decode failed: {0}")]
    LegacyBincode(String),
}

impl UndoData {
    /// Encode as v1: `[V1_MAGIC][V1_VERSION][varint count][compact Coin]*count`.
    /// New on-disk writes always use this format.
    pub fn serialize_v1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(V1_HEADER_LEN + 4 + self.spent_coins.len() * 32);
        buf.extend_from_slice(&V1_MAGIC);
        buf.push(V1_VERSION);
        encode_varint(self.spent_coins.len() as u64, &mut buf);
        for coin in &self.spent_coins {
            // The compact encoding is self-delimiting, so we can pack
            // records back-to-back without per-record length prefixes.
            buf.extend_from_slice(&coin.serialize_compact());
        }
        buf
    }

    /// Decode either v1 (preferred) or legacy v0 bincode based on an
    /// 8-byte magic peek. v0 entries' stored outpoints are discarded
    /// — disconnect_block recovers outpoints from the block itself.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, UndoDecodeError> {
        if bytes.len() >= V1_MAGIC.len() && bytes[..V1_MAGIC.len()] == V1_MAGIC {
            let after_magic = &bytes[V1_MAGIC.len()..];
            let version = *after_magic.first().ok_or(UndoDecodeError::Truncated)?;
            if version != V1_VERSION {
                return Err(UndoDecodeError::UnsupportedVersion(version));
            }
            Self::deserialize_v1(&after_magic[1..])
        } else {
            Self::deserialize_v0(bytes)
        }
    }

    fn deserialize_v1(payload: &[u8]) -> Result<Self, UndoDecodeError> {
        let (raw_count, consumed) = decode_varint(payload).ok_or(UndoDecodeError::Truncated)?;
        if raw_count > MAX_UNDO_SPENT_COINS as u64 {
            return Err(UndoDecodeError::CountTooLarge {
                count: raw_count,
                cap: MAX_UNDO_SPENT_COINS,
            });
        }
        let count = usize::try_from(raw_count).map_err(|_| UndoDecodeError::CountOverflow)?;
        let mut rest = &payload[consumed..];
        // Safe to pre-allocate now: `count` is bounded by MAX_UNDO_SPENT_COINS.
        let mut spent_coins = Vec::with_capacity(count);
        for index in 0..count {
            let (coin, n) = Coin::deserialize_compact_stream(rest)
                .ok_or(UndoDecodeError::CoinDecode { index })?;
            spent_coins.push(coin);
            rest = &rest[n..];
        }
        if !rest.is_empty() {
            return Err(UndoDecodeError::TrailingBytes {
                remaining: rest.len(),
            });
        }
        Ok(Self { spent_coins })
    }

    fn deserialize_v0(bytes: &[u8]) -> Result<Self, UndoDecodeError> {
        let legacy: LegacyUndoData = bincode::deserialize(bytes)
            .map_err(|e| UndoDecodeError::LegacyBincode(e.to_string()))?;
        Ok(Self {
            spent_coins: legacy.spent_coins.into_iter().map(|(_op, c)| c).collect(),
        })
    }
}

/// Wire-compatible serde proxy for the legacy v0 bincode format. Kept
/// only for read-side compatibility with on-disk data written before
/// this PR; we never serialize this shape again.
#[derive(Serialize, Deserialize)]
struct LegacyUndoData {
    spent_coins: Vec<(OutPointSer, Coin)>,
}

/// Serializable OutPoint. Only used by [`LegacyUndoData`] for decoding
/// pre-v1 entries. New code carries outpoints as `bitcoin::OutPoint`
/// directly; the v1 undo format does not store them at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutPointSer {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl From<&OutPoint> for OutPointSer {
    fn from(op: &OutPoint) -> Self {
        Self {
            txid: op.txid[..].try_into().unwrap(),
            vout: op.vout,
        }
    }
}

impl OutPointSer {
    pub fn to_outpoint(&self) -> OutPoint {
        use bitcoin::hashes::Hash;
        let inner = bitcoin::hashes::sha256d::Hash::from_byte_array(self.txid);
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(inner),
            vout: self.vout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let inner = bitcoin::hashes::sha256d::Hash::from_byte_array([txid_byte; 32]);
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(inner),
            vout,
        }
    }

    fn make_coin(amount: u64, height: u32) -> Coin {
        Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            height,
            coinbase: false,
        }
    }

    #[test]
    fn v1_roundtrip_preserves_coins() {
        let undo = UndoData {
            spent_coins: vec![
                make_coin(5_000_000_000, 100),
                make_coin(123_456, 200),
                make_coin(0, 0),
            ],
        };
        let encoded = undo.serialize_v1();
        // Magic + version must be present and correct.
        assert_eq!(&encoded[..V1_MAGIC.len()], &V1_MAGIC);
        assert_eq!(encoded[V1_MAGIC.len()], V1_VERSION);
        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded, undo);
    }

    #[test]
    fn v1_empty_roundtrip() {
        let undo = UndoData::default();
        let encoded = undo.serialize_v1();
        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins.len(), 0);
        // Minimum: 8 magic + 1 version + 1 varint zero = 10 bytes.
        assert_eq!(encoded.len(), V1_MAGIC.len() + 1 + 1);
    }

    #[test]
    fn v0_legacy_bincode_decodes_to_same_coins() {
        // Pin-test: write the historical bincode format with outpoints,
        // verify the new decoder produces the same `spent_coins` (and
        // discards the outpoints, since the in-memory shape no longer
        // carries them).
        let op = make_outpoint(0x01, 0);
        let coin = make_coin(7_777_777, 99);
        let legacy = LegacyUndoData {
            spent_coins: vec![(OutPointSer::from(&op), coin.clone())],
        };
        let encoded = bincode::serialize(&legacy).unwrap();
        // First bytes must NOT collide with the v1 magic — bincode
        // length-prefixes a Vec with a u64 LE, so the first byte is the
        // low byte of `len` (= 0x01). The 8-byte magic was chosen so
        // that no plausible legacy length can match.
        assert_ne!(&encoded[..V1_MAGIC.len()], &V1_MAGIC);

        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins, vec![coin]);
    }

    #[test]
    fn v0_legacy_510_coins_does_not_collide_with_v1_magic() {
        // Regression for the H1 finding in the 2026-05-15 review: a
        // legacy bincode row whose `spent_coins.len()` is exactly 510
        // serializes its u64 LE length prefix as `FE 01 00 00 00 00
        // 00 00`. With a 2-byte magic of `[0xFE, 0x01]`, that row's
        // first two bytes would have been mis-dispatched to the v1
        // decoder and the row would have appeared corrupt. The 8-byte
        // magic resolves the collision — exercise it directly.
        let coin = make_coin(42, 1);
        let legacy = LegacyUndoData {
            spent_coins: (0..510u32)
                .map(|i| (OutPointSer::from(&make_outpoint(0x10, i)), coin.clone()))
                .collect(),
        };
        let encoded = bincode::serialize(&legacy).unwrap();
        assert_eq!(
            &encoded[..8],
            &[0xFE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "preconditions of the regression: 510u64 LE prefix",
        );
        // The 8-byte magic must NOT match this prefix.
        assert_ne!(&encoded[..V1_MAGIC.len()], &V1_MAGIC);
        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins.len(), 510);
        assert!(decoded.spent_coins.iter().all(|c| *c == coin));
    }

    #[test]
    fn v1_unsupported_version_errs() {
        // Magic OK, but version byte is something we don't know.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(0x99);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, UndoDecodeError::UnsupportedVersion(0x99)),
            "expected UnsupportedVersion(0x99), got {:?}",
            err,
        );
    }

    #[test]
    fn v1_count_above_cap_rejected() {
        // Construct a v1 header that claims a count well above the cap.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(V1_VERSION);
        encode_varint((MAX_UNDO_SPENT_COINS as u64) + 1, &mut bytes);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, UndoDecodeError::CountTooLarge { .. }),
            "expected CountTooLarge, got {:?}",
            err,
        );
    }

    #[test]
    fn v1_huge_count_rejected_without_alloc() {
        // u64::MAX must fail with CountTooLarge before any allocation
        // is attempted — this is the M1 protection from the review.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(V1_VERSION);
        encode_varint(u64::MAX, &mut bytes);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, UndoDecodeError::CountTooLarge { count, .. } if count == u64::MAX),
            "expected CountTooLarge(u64::MAX), got {:?}",
            err,
        );
    }

    #[test]
    fn v1_size_is_smaller_than_v0() {
        // Sanity-check the actual savings claim from the PR description:
        // for a typical block-worth of spends (say 1000 P2WPKH coins),
        // the v1 encoding is roughly half the size of v0 bincode. Keeps
        // the format from silently regressing.
        let coins: Vec<Coin> = (0..1000)
            .map(|i| Coin {
                amount: 100_000 + i,
                // 22-byte typical P2WPKH script (OP_0 + 20-byte hash).
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0u8; 22]),
                height: 500_000 + i as u32,
                coinbase: false,
            })
            .collect();
        let undo = UndoData {
            spent_coins: coins.clone(),
        };
        let v1 = undo.serialize_v1();
        let legacy = LegacyUndoData {
            spent_coins: coins
                .into_iter()
                .enumerate()
                .map(|(i, c)| (OutPointSer::from(&make_outpoint(0x42, i as u32)), c))
                .collect(),
        };
        let v0 = bincode::serialize(&legacy).unwrap();
        assert!(
            v1.len() * 2 < v0.len(),
            "v1 should be <50% of v0 size: v1={} v0={}",
            v1.len(),
            v0.len()
        );
    }

    #[test]
    fn v1_truncated_after_version_errs_truncated() {
        // Magic + version present, but no count varint at all.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(V1_VERSION);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::Truncated));
    }

    #[test]
    fn v1_truncated_after_magic_errs_truncated() {
        // Magic but no version byte — must surface as Truncated, not
        // accidentally fall through to v0.
        let bytes = V1_MAGIC.to_vec();
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::Truncated));
    }

    #[test]
    fn v1_truncated_coin_errs_decode() {
        // Magic + version + count=1 but only enough bytes for half a coin.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(V1_VERSION);
        bytes.push(0x01); // varint(1)
        bytes.push(0x10); // single byte, can't form a coin
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, UndoDecodeError::CoinDecode { index: 0 }),
            "expected CoinDecode at index 0, got {:?}",
            err
        );
    }

    #[test]
    fn v1_trailing_bytes_err() {
        let undo = UndoData {
            spent_coins: vec![make_coin(1, 1)],
        };
        let mut bytes = undo.serialize_v1();
        bytes.push(0xAA);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::TrailingBytes { .. }));
    }

    #[test]
    fn outpointser_roundtrip() {
        let op = make_outpoint(0xAB, 42);
        let ser = OutPointSer::from(&op);
        let recovered = ser.to_outpoint();
        assert_eq!(op.txid, recovered.txid);
        assert_eq!(op.vout, recovered.vout);
    }
}
