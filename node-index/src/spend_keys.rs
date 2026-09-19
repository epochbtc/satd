//! Key/value encoding for the `spent` column family.
//!
//! Schema layout:
//!
//! ```text
//! spent  key:   funding_txseq[5] || vout_be[3]      (8 bytes)
//!        value: spending_txseq[5] || vin_be[3]      (8 bytes)
//! ```
//!
//! The key is the spent output, named by the ordinal of the transaction
//! that created it; the value is the input that consumed it, named the
//! same way. One row per consumed UTXO; `connect_block` writes it,
//! `disconnect_block` deletes it.
//!
//! Sixteen bytes where the txid-keyed predecessor took seventy-six. The
//! two 32-byte hashes it carried are recoverable from the ordinals
//! through the `txseq_txid` column family, which the storage layer
//! resolves in one batched lookup per scan — so this family stores each
//! identifier once, in one place, instead of once per index that
//! mentions it. The height the old value carried is likewise derivable,
//! from `txseq_block`.
//!
//! The 5-byte ordinal prefix is what makes "every spend of transaction
//! N" a prefix scan, replacing the 32-byte txid prefix the old layout
//! used for the same query.
//!
//! Multi-byte fields are big-endian, so the byte order of a key is chain
//! order — the same property the rest of the index schema relies on.

use bitcoin::Txid;

use crate::txseq::{TXSEQ_LEN, TxSeq, VOUT_LEN, decode_txseq, decode_u24, encode_txseq, encode_u24};

/// Encoded key length (ordinal 5 + vout BE 3).
pub const SPENT_KEY_LEN: usize = TXSEQ_LEN + VOUT_LEN;

/// Encoded value length (ordinal 5 + vin BE 3).
pub const SPENT_VALUE_LEN: usize = TXSEQ_LEN + VOUT_LEN;

/// Reference to the input that spent a given outpoint.
///
/// The resolved, public shape: ordinals are a storage encoding, and the
/// store turns them back into a txid and a height before a row leaves
/// it. Unchanged from the txid-keyed layout, so every consumer is
/// unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpendingRef {
    pub spending_txid: Txid,
    pub spending_vin: u32,
    pub height: u32,
}

/// One row of the `spent` family, as it sits on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpentRow {
    pub funding_txseq: u64,
    pub vout: u32,
    pub spending_txseq: u64,
    pub vin: u32,
}

impl SpentRow {
    pub fn key(&self) -> (u64, u32) {
        (self.funding_txseq, self.vout)
    }
}

pub fn encode_spent_key(funding_txseq: u64, vout: u32) -> [u8; SPENT_KEY_LEN] {
    let mut buf = [0u8; SPENT_KEY_LEN];
    buf[..TXSEQ_LEN].copy_from_slice(&encode_txseq(TxSeq(funding_txseq)));
    buf[TXSEQ_LEN..].copy_from_slice(&encode_u24(vout));
    buf
}

pub fn decode_spent_key(b: &[u8]) -> Option<(u64, u32)> {
    if b.len() != SPENT_KEY_LEN {
        return None;
    }
    let seq = decode_txseq(&b[..TXSEQ_LEN])?.0;
    let vout = decode_u24(&b[TXSEQ_LEN..])?;
    Some((seq, vout))
}

pub fn encode_spent_value(spending_txseq: u64, vin: u32) -> [u8; SPENT_VALUE_LEN] {
    let mut buf = [0u8; SPENT_VALUE_LEN];
    buf[..TXSEQ_LEN].copy_from_slice(&encode_txseq(TxSeq(spending_txseq)));
    buf[TXSEQ_LEN..].copy_from_slice(&encode_u24(vin));
    buf
}

pub fn decode_spent_value(b: &[u8]) -> Option<(u64, u32)> {
    if b.len() != SPENT_VALUE_LEN {
        return None;
    }
    let seq = decode_txseq(&b[..TXSEQ_LEN])?.0;
    let vin = decode_u24(&b[TXSEQ_LEN..])?;
    Some((seq, vin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spent_key_roundtrip() {
        for (seq, vout) in [(0u64, 0u32), (1, 7), (1 << 32, 65_536), (super::super::txseq::TXSEQ_MAX, (1 << 24) - 1)]
        {
            let encoded = encode_spent_key(seq, vout);
            assert_eq!(encoded.len(), SPENT_KEY_LEN);
            assert_eq!(decode_spent_key(&encoded), Some((seq, vout)));
        }
    }

    #[test]
    fn test_spent_value_roundtrip() {
        let encoded = encode_spent_value(800_000, 3);
        assert_eq!(encoded.len(), SPENT_VALUE_LEN);
        assert_eq!(decode_spent_value(&encoded), Some((800_000, 3)));
    }

    #[test]
    fn test_spent_key_decode_rejects_wrong_length() {
        assert!(decode_spent_key(&[0u8; 7]).is_none());
        assert!(decode_spent_key(&[0u8; 9]).is_none());
        assert!(decode_spent_key(&[]).is_none());
        assert!(decode_spent_value(&[0u8; 7]).is_none());
        assert!(decode_spent_value(&[0u8; 9]).is_none());
    }

    /// The 5-byte ordinal prefix is what makes "every spend of
    /// transaction N" a prefix scan. Two different funding transactions
    /// must not share it, and every output of one transaction must.
    #[test]
    fn test_spent_key_prefix_isolates_the_funding_transaction() {
        let a = encode_spent_key(100, 0);
        let b = encode_spent_key(100, 99);
        let c = encode_spent_key(101, 0);
        assert_eq!(&a[..TXSEQ_LEN], &b[..TXSEQ_LEN]);
        assert_ne!(&a[..TXSEQ_LEN], &c[..TXSEQ_LEN]);
    }

    /// Byte order is chain order, so a scan over the family visits
    /// spends in the order the spent outputs were created.
    #[test]
    fn test_spent_keys_sort_in_chain_order() {
        let mut keys = [
            encode_spent_key(2, 0),
            encode_spent_key(1, 5),
            encode_spent_key(1, 0),
            encode_spent_key(1 << 33, 0),
        ];
        let expected = [
            encode_spent_key(1, 0),
            encode_spent_key(1, 5),
            encode_spent_key(2, 0),
            encode_spent_key(1 << 33, 0),
        ];
        keys.sort_unstable();
        assert_eq!(keys, expected);
    }
}
