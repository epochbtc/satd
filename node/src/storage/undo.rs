//! Undo data for connected blocks.
//!
//! On-disk format: an 8-byte magic, a 1-byte version, a varint count,
//! then back-to-back `Coin::serialize_compact` records. The outpoint
//! for each spend is recoverable from the block's tx inputs (the
//! connect-order invariant guarantees `undo.spent_coins[i]` belongs to
//! the i-th non-coinbase input), so we don't store it. Per-spend cost
//! is ~28 bytes for typical P2WPKH.
//!
//! The magic/version split lets future schema revisions reuse the
//! magic and bump only the version byte.

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
    #[error("undo: missing or wrong magic")]
    InvalidMagic,
    #[error("undo: truncated header")]
    Truncated,
    #[error("undo: unsupported version byte {0:#x}")]
    UnsupportedVersion(u8),
    #[error("undo: count overflowed usize")]
    CountOverflow,
    #[error("undo: count {count} exceeds cap {cap}")]
    CountTooLarge { count: u64, cap: usize },
    #[error("undo: failed to decode coin {index}")]
    CoinDecode { index: usize },
    #[error("undo: trailing bytes after stream ({remaining} bytes)")]
    TrailingBytes { remaining: usize },
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

    /// Decode an undo entry. Requires the [`V1_MAGIC`] header — any
    /// row not starting with it is rejected as `InvalidMagic`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, UndoDecodeError> {
        if bytes.len() < V1_MAGIC.len() || bytes[..V1_MAGIC.len()] != V1_MAGIC {
            return Err(UndoDecodeError::InvalidMagic);
        }
        let after_magic = &bytes[V1_MAGIC.len()..];
        let version = *after_magic.first().ok_or(UndoDecodeError::Truncated)?;
        if version != V1_VERSION {
            return Err(UndoDecodeError::UnsupportedVersion(version));
        }
        let payload = &after_magic[1..];
        let (raw_count, consumed) = decode_varint(payload).ok_or(UndoDecodeError::Truncated)?;
        if raw_count > MAX_UNDO_SPENT_COINS as u64 {
            return Err(UndoDecodeError::CountTooLarge {
                count: raw_count,
                cap: MAX_UNDO_SPENT_COINS,
            });
        }
        let count = usize::try_from(raw_count).map_err(|_| UndoDecodeError::CountOverflow)?;
        let mut rest = &payload[consumed..];
        // Safe to pre-allocate: `count` is bounded by MAX_UNDO_SPENT_COINS.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn missing_magic_rejected() {
        // Anything not starting with V1_MAGIC must be rejected outright
        // rather than silently misdecoded.
        let bytes = [0x00u8; 16];
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::InvalidMagic));
    }

    #[test]
    fn short_input_rejected_as_invalid_magic() {
        // Shorter than the magic itself: still InvalidMagic, not Truncated.
        let err = UndoData::deserialize(&[0xFE, 0xCA]).unwrap_err();
        assert!(matches!(err, UndoDecodeError::InvalidMagic));
    }

    #[test]
    fn unsupported_version_errs() {
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
    fn count_above_cap_rejected() {
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
    fn huge_count_rejected_without_alloc() {
        // u64::MAX must fail with CountTooLarge before any allocation
        // is attempted.
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
    fn truncated_after_version_errs_truncated() {
        // Magic + version present, but no count varint at all.
        let mut bytes = V1_MAGIC.to_vec();
        bytes.push(V1_VERSION);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::Truncated));
    }

    #[test]
    fn truncated_after_magic_errs_truncated() {
        // Magic but no version byte.
        let bytes = V1_MAGIC.to_vec();
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::Truncated));
    }

    #[test]
    fn truncated_coin_errs_decode() {
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
    fn trailing_bytes_err() {
        let undo = UndoData {
            spent_coins: vec![make_coin(1, 1)],
        };
        let mut bytes = undo.serialize_v1();
        bytes.push(0xAA);
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::TrailingBytes { .. }));
    }
}
