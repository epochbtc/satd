//! Dense chain-order transaction ordinals.
//!
//! Every index in satd used to key on a 32-byte txid. A txid is a hash:
//! incompressible, and repeated once per index that mentions the
//! transaction. On a fully indexed mainnet node that repetition was the
//! single largest line in the chainstate — the same ~1.2 billion txids
//! written five to seven times over.
//!
//! An *ordinal* replaces it. Transactions are numbered in chain order
//! starting from the genesis coinbase at 0, so for a block `h` holding
//! transactions `t_0..t_{n-1}`:
//!
//! ```text
//! txseq(t_i) = nchaintx(parent(h)) + i
//! ```
//!
//! where `nchaintx` is the cumulative transaction count satd already
//! persists per block in the `chain_tx` column family for
//! `getchaintxstats`. Nothing new has to be counted; the series was
//! already there.
//!
//! Five bytes big-endian holds 2^40 transactions — roughly 880 times the
//! chain's current count, and big-endian so the byte order of a key is
//! the chain order of the transaction, which is what makes a prefix scan
//! over one script's history return rows in the order they were mined.
//!
//! The ordinal is not a substitute for the txid on any public surface. It
//! is a storage encoding: the `txseq_txid` column family maps back, and
//! the store resolves ordinals to txids before any row leaves the storage
//! layer.

/// Dense chain-order transaction ordinal. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxSeq(pub u64);

/// On-disk width of an ordinal, in bytes.
pub const TXSEQ_LEN: usize = 5;

/// Largest ordinal the 5-byte encoding can hold. Mainnet is around
/// 1.2e9, so this is ~880x headroom; connect fails closed rather than
/// wrapping if a chain ever reaches it.
pub const TXSEQ_MAX: u64 = (1 << 40) - 1;

/// `Coin.txseq` sentinel: the funding transaction's ordinal is not known.
///
/// Only coins loaded from an AssumeUTXO snapshot carry this — the
/// snapshot format is Bitcoin Core's and has no ordinal in it. 0 is safe
/// as a sentinel because the one transaction with ordinal 0 is the
/// genesis coinbase, whose output is unspendable and never enters the
/// UTXO set, so no real coin can claim it.
pub const TXSEQ_UNKNOWN: u64 = 0;

/// On-disk width of a vout/vin index, in bytes.
///
/// u24, not u16: a 1 MB transaction can carry more than 65,535 outputs
/// (the minimum output is 9 bytes serialized), and consensus does not
/// forbid it. u32 would cost a byte per row across three families for
/// range no transaction can reach.
pub const VOUT_LEN: usize = 3;

/// Largest vout/vin index the 3-byte encoding can hold.
pub const VOUT_MAX: u32 = (1 << 24) - 1;

/// Encode an ordinal as 5 bytes big-endian.
///
/// Callers are expected to have range-checked against [`TXSEQ_MAX`] at
/// the point where a useful error can be returned (`connect_block`);
/// this truncates to the low 40 bits rather than panicking in release,
/// and the debug assertion catches a miss in tests.
pub fn encode_txseq(s: TxSeq) -> [u8; TXSEQ_LEN] {
    debug_assert!(
        s.0 <= TXSEQ_MAX,
        "ordinal {} exceeds the 5-byte encoding; connect_block must reject it first",
        s.0
    );
    let b = s.0.to_be_bytes();
    [b[3], b[4], b[5], b[6], b[7]]
}

/// Decode a 5-byte big-endian ordinal. `None` for any other length —
/// a short or long slice is a corrupt key, not a small number.
pub fn decode_txseq(b: &[u8]) -> Option<TxSeq> {
    if b.len() != TXSEQ_LEN {
        return None;
    }
    Some(TxSeq(
        (b[0] as u64) << 32
            | (b[1] as u64) << 24
            | (b[2] as u64) << 16
            | (b[3] as u64) << 8
            | (b[4] as u64),
    ))
}

/// Encode a vout/vin index as 3 bytes big-endian.
pub fn encode_u24(v: u32) -> [u8; VOUT_LEN] {
    debug_assert!(v <= VOUT_MAX, "output index {v} exceeds the 3-byte encoding");
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

/// Decode a 3-byte big-endian vout/vin index. `None` for any other length.
pub fn decode_u24(b: &[u8]) -> Option<u32> {
    if b.len() != VOUT_LEN {
        return None;
    }
    Some((b[0] as u32) << 16 | (b[1] as u32) << 8 | (b[2] as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txseq_roundtrip_all_widths() {
        for v in [0u64, 1, 255, 256, 65_535, 1 << 24, 1 << 32, TXSEQ_MAX] {
            let encoded = encode_txseq(TxSeq(v));
            assert_eq!(encoded.len(), TXSEQ_LEN);
            assert_eq!(
                decode_txseq(&encoded),
                Some(TxSeq(v)),
                "ordinal {v} must survive a round trip"
            );
        }
    }

    /// Big-endian is load-bearing: a lexicographic scan over encoded
    /// ordinals must visit transactions in the order they were mined,
    /// because that is what makes a scripthash prefix scan return chain
    /// order without a sort.
    #[test]
    fn txseq_encoding_is_order_preserving() {
        let encoded: Vec<[u8; TXSEQ_LEN]> = [0u64, 1, 255, 256, 70_000, 1 << 32, TXSEQ_MAX]
            .iter()
            .map(|v| encode_txseq(TxSeq(*v)))
            .collect();
        let mut sorted = encoded.clone();
        sorted.sort_unstable();
        assert_eq!(encoded, sorted, "byte order must equal numeric order");
    }

    #[test]
    fn txseq_rejects_wrong_length() {
        assert_eq!(decode_txseq(&[]), None);
        assert_eq!(decode_txseq(&[0; 4]), None);
        assert_eq!(decode_txseq(&[0; 6]), None);
        assert_eq!(decode_txseq(&[0; 8]), None);
    }

    #[test]
    fn u24_roundtrip_and_rejects_overflow() {
        for v in [0u32, 1, 255, 256, 65_535, 65_536, VOUT_MAX] {
            assert_eq!(decode_u24(&encode_u24(v)), Some(v));
        }
        assert_eq!(decode_u24(&[0; 2]), None);
        assert_eq!(decode_u24(&[0; 4]), None);
    }

    /// A vout that does not fit in 3 bytes is unreachable on any valid
    /// block, but the encoder must not silently alias one output onto
    /// another if it ever happens.
    #[test]
    #[should_panic(expected = "exceeds the 3-byte encoding")]
    fn u24_encode_panics_in_debug_on_overflow() {
        let _ = encode_u24(VOUT_MAX + 1);
    }
}
