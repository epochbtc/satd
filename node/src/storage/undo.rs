//! Undo data for connected blocks.
//!
//! Two on-disk formats coexist while the migration runs:
//!
//! * **v0** — bincode-encoded `Vec<(OutPointSer, Coin)>`. Every entry pays
//!   for a 32-byte txid + 4-byte vout (the outpoint) plus a bincode-encoded
//!   coin (~43 bytes for typical P2WPKH). Historical default; what's on
//!   disk pre-PR.
//! * **v1** — explicit framing: a two-byte magic `[0xFE 0x01]` followed by
//!   a varint count and back-to-back `Coin::serialize_compact` records.
//!   Drops the outpoint entirely — the disconnect path recovers each
//!   outpoint from the block's tx inputs (the connect-order invariant
//!   guarantees `undo.spent_coins[i]` belongs to the i-th non-coinbase
//!   input). Per-spend: ~28 bytes typical, vs ~79 in v0.
//!
//! All new writes are v1. Reads transparently dispatch on the first two
//! bytes — anything that doesn't start with the v1 magic is decoded as
//! v0 (and its stored outpoints are discarded, since the in-memory shape
//! is now `Vec<Coin>` regardless of source format). The forthcoming
//! `migrate-undo` subcommand rewrites every v0 row as v1 in one batch.

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

const V1_MAGIC: [u8; 2] = [0xFE, 0x01];

#[derive(Debug, thiserror::Error)]
pub enum UndoDecodeError {
    #[error("undo: truncated v1 header")]
    Truncated,
    #[error("undo: v1 count overflowed usize")]
    CountOverflow,
    #[error("undo: failed to decode v1 coin {index}")]
    CoinDecode { index: usize },
    #[error("undo: trailing bytes after v1 stream ({remaining} bytes)")]
    TrailingBytes { remaining: usize },
    #[error("undo: legacy bincode decode failed: {0}")]
    LegacyBincode(String),
}

impl UndoData {
    /// Encode as v1: `[0xFE 0x01][varint count][compact Coin]*count`.
    /// New on-disk writes always use this format.
    pub fn serialize_v1(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 4 + self.spent_coins.len() * 32);
        buf.extend_from_slice(&V1_MAGIC);
        encode_varint(self.spent_coins.len() as u64, &mut buf);
        for coin in &self.spent_coins {
            // The compact encoding is self-delimiting, so we can pack
            // records back-to-back without per-record length prefixes.
            buf.extend_from_slice(&coin.serialize_compact());
        }
        buf
    }

    /// Decode either v1 (preferred) or legacy v0 bincode based on a
    /// two-byte magic peek. v0 entries' stored outpoints are discarded
    /// — disconnect_block recovers outpoints from the block itself.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, UndoDecodeError> {
        if bytes.len() >= 2 && bytes[0] == V1_MAGIC[0] && bytes[1] == V1_MAGIC[1] {
            Self::deserialize_v1(&bytes[2..])
        } else {
            Self::deserialize_v0(bytes)
        }
    }

    fn deserialize_v1(payload: &[u8]) -> Result<Self, UndoDecodeError> {
        let (count, consumed) = decode_varint(payload).ok_or(UndoDecodeError::Truncated)?;
        let count = usize::try_from(count).map_err(|_| UndoDecodeError::CountOverflow)?;
        let mut rest = &payload[consumed..];
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
        // Magic bytes must be present and correct.
        assert_eq!(&encoded[..2], &V1_MAGIC);
        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded, undo);
    }

    #[test]
    fn v1_empty_roundtrip() {
        let undo = UndoData::default();
        let encoded = undo.serialize_v1();
        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins.len(), 0);
        // Minimum: 2 magic + 1 varint zero = 3 bytes.
        assert_eq!(encoded.len(), 3);
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
        // First two bytes must NOT collide with the v1 magic — bincode
        // length-prefixes a Vec with a u64 LE, so the first byte is the
        // low byte of `len` (= 0x01). That's guaranteed not to be
        // `0xFE 0x01`, but assert it explicitly so a future bincode
        // version change doesn't quietly hijack v0 data into the v1
        // path.
        assert_ne!(encoded[0..2], V1_MAGIC);

        let decoded = UndoData::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins, vec![coin]);
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
    fn v1_truncated_count_errs_truncated() {
        let bytes = [0xFE, 0x01]; // magic only, no count varint
        let err = UndoData::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, UndoDecodeError::Truncated));
    }

    #[test]
    fn v1_truncated_coin_errs_decode() {
        // Magic + count=1 but only enough bytes for half a coin.
        let mut bytes = vec![0xFE, 0x01, 0x01]; // magic + varint(1)
        bytes.extend_from_slice(&[0x10]); // a single byte, can't form a coin
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
