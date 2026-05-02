//! Key/value encoding for the `outpoint_spend` column family.
//!
//! Schema layout:
//!
//! ```text
//! outpoint_spend  key:   prev_txid[32] || prev_vout_be[4]                          (36 bytes)
//!                 value: spending_txid[32] || spending_vin_be[4] || height_be[4]   (40 bytes)
//! ```
//!
//! The key is the spent outpoint; the value is the (txid, vin, height)
//! that consumed it. One row per consumed UTXO; `connect_block` writes
//! it, `disconnect_block` deletes it.
//!
//! Multi-byte fields are big-endian for byte-order iteration parity
//! with the rest of the address-index schema.

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};

/// Encoded key length (txid 32 + vout BE 4).
pub const OUTPOINT_KEY_LEN: usize = 36;

/// Encoded value length (txid 32 + vin BE 4 + height BE 4).
pub const SPEND_VALUE_LEN: usize = 40;

const TXID_LEN: usize = 32;

/// Reference to the input that spent a given outpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpendingRef {
    pub spending_txid: Txid,
    pub spending_vin: u32,
    pub height: u32,
}

pub fn encode_outpoint_key(op: &OutPoint) -> [u8; OUTPOINT_KEY_LEN] {
    let mut buf = [0u8; OUTPOINT_KEY_LEN];
    buf[..TXID_LEN].copy_from_slice(op.txid.as_ref());
    buf[TXID_LEN..].copy_from_slice(&op.vout.to_be_bytes());
    buf
}

pub fn decode_outpoint_key(b: &[u8]) -> Option<OutPoint> {
    if b.len() != OUTPOINT_KEY_LEN {
        return None;
    }
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[..TXID_LEN]);
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let vout = u32::from_be_bytes(b[TXID_LEN..].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

pub fn encode_spend_value(s: &SpendingRef) -> [u8; SPEND_VALUE_LEN] {
    let mut buf = [0u8; SPEND_VALUE_LEN];
    buf[..TXID_LEN].copy_from_slice(s.spending_txid.as_ref());
    buf[TXID_LEN..TXID_LEN + 4].copy_from_slice(&s.spending_vin.to_be_bytes());
    buf[TXID_LEN + 4..].copy_from_slice(&s.height.to_be_bytes());
    buf
}

pub fn decode_spend_value(b: &[u8]) -> Option<SpendingRef> {
    if b.len() != SPEND_VALUE_LEN {
        return None;
    }
    let mut txid_arr = [0u8; TXID_LEN];
    txid_arr.copy_from_slice(&b[..TXID_LEN]);
    let spending_txid =
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(txid_arr));
    let spending_vin = u32::from_be_bytes(b[TXID_LEN..TXID_LEN + 4].try_into().ok()?);
    let height = u32::from_be_bytes(b[TXID_LEN + 4..].try_into().ok()?);
    Some(SpendingRef {
        spending_txid,
        spending_vin,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn test_outpoint_key_roundtrip() {
        let op = OutPoint {
            txid: fixture_txid(0x42),
            vout: 7,
        };
        let encoded = encode_outpoint_key(&op);
        assert_eq!(encoded.len(), OUTPOINT_KEY_LEN);
        assert_eq!(decode_outpoint_key(&encoded), Some(op));
    }

    #[test]
    fn test_spend_value_roundtrip() {
        let s = SpendingRef {
            spending_txid: fixture_txid(0xab),
            spending_vin: 3,
            height: 800_000,
        };
        let encoded = encode_spend_value(&s);
        assert_eq!(encoded.len(), SPEND_VALUE_LEN);
        assert_eq!(decode_spend_value(&encoded), Some(s));
    }

    #[test]
    fn test_outpoint_key_decode_rejects_wrong_length() {
        assert!(decode_outpoint_key(&[0u8; 35]).is_none());
        assert!(decode_outpoint_key(&[0u8; 37]).is_none());
        assert!(decode_outpoint_key(&[]).is_none());
    }

    #[test]
    fn test_spend_value_decode_rejects_wrong_length() {
        assert!(decode_spend_value(&[0u8; 39]).is_none());
        assert!(decode_spend_value(&[0u8; 41]).is_none());
    }

    #[test]
    fn test_outpoint_key_prefix_isolates_txid() {
        let a = OutPoint { txid: fixture_txid(0x10), vout: 99 };
        let b = OutPoint { txid: fixture_txid(0x20), vout: 0 };
        let ka = encode_outpoint_key(&a);
        let kb = encode_outpoint_key(&b);
        assert_ne!(&ka[..TXID_LEN], &kb[..TXID_LEN]);
    }
}
