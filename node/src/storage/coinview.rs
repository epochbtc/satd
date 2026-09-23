use serde::{Deserialize, Serialize};

/// A single unspent transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub amount: u64,
    #[serde(with = "script_serde")]
    pub script_pubkey: bitcoin::ScriptBuf,
    pub height: u32,
    pub coinbase: bool,
    /// Chain-order ordinal of the transaction that created this output.
    ///
    /// The spend indexes key on it, and this is where `connect_block`
    /// gets it: the connect path already resolves every input's coin, so
    /// carrying the ordinal inside the coin means the hot path never
    /// looks one up. The alternative — a point read per input against a
    /// bloom-filtered ~45 GB family — would be paid once for every input
    /// in the chain.
    ///
    /// [`TXSEQ_UNKNOWN`](node_index::TXSEQ_UNKNOWN) for coins loaded from
    /// an AssumeUTXO snapshot: Bitcoin Core's snapshot format carries no
    /// ordinal, and the history those coins came from has not been
    /// validated yet. Spending such a coin falls back to one lookup.
    #[serde(default)]
    pub txseq: u64,
}

/// Serialize an OutPoint to a fixed 36-byte key (txid LE + vout LE).
pub fn outpoint_to_key(outpoint: &bitcoin::OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&outpoint.txid[..]);
    key[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
    key
}

/// Deserialize an OutPoint from a 36-byte key.
pub fn key_to_outpoint(key: &[u8; 36]) -> bitcoin::OutPoint {
    use bitcoin::hashes::Hash;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&key[..32]);
    let inner = bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes);
    let txid = bitcoin::Txid::from_raw_hash(inner);
    let vout = u32::from_le_bytes([key[32], key[33], key[34], key[35]]);
    bitcoin::OutPoint { txid, vout }
}

/// Custom serde for ScriptBuf as raw bytes.
mod script_serde {
    use bitcoin::ScriptBuf;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        script: &ScriptBuf,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        script.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ScriptBuf, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(ScriptBuf::from_bytes(bytes))
    }
}

// ---------------------------------------------------------------------------
// Compact serialization for RocksDB coins CF.
// Format: [varint(height<<1 | coinbase)] [varint(txseq)] [varint(amount)]
//         [varint(script_len)] [script]
// ~28 bytes for P2WPKH vs ~43 with bincode (35% smaller).
//
// There is no per-coin version byte. The chainstate schema version is
// the format gate: a binary that reads this layout refuses a datadir
// written in any other, and undo rows embed compact coins so both change
// shape at the same schema step.
// ---------------------------------------------------------------------------

/// Encode a u64 as a variable-length integer (7 bits per byte, MSB = more).
pub(crate) fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    loop {
        if val < 0x80 {
            buf.push(val as u8);
            return;
        }
        buf.push((val as u8 & 0x7F) | 0x80);
        val >>= 7;
    }
}

/// Decode a varint from a byte slice, returning (value, bytes_consumed).
pub(crate) fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        val |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((val, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

impl Coin {
    /// Compact binary serialization: ~28 bytes for typical P2WPKH coin.
    pub fn serialize_compact(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        // Pack height and coinbase into a single varint
        let height_cb = ((self.height as u64) << 1) | (self.coinbase as u64);
        encode_varint(height_cb, &mut buf);
        encode_varint(self.txseq, &mut buf);
        encode_varint(self.amount, &mut buf);
        let script = self.script_pubkey.as_bytes();
        encode_varint(script.len() as u64, &mut buf);
        buf.extend_from_slice(script);
        buf
    }

    /// Deserialize from compact binary format. Rejects trailing bytes.
    pub fn deserialize_compact(data: &[u8]) -> Option<Self> {
        let (coin, consumed) = Self::deserialize_compact_stream(data)?;
        if consumed != data.len() {
            return None;
        }
        Some(coin)
    }

    /// The creation height of a compact-encoded coin, decoding nothing
    /// else. The height is the leading varint (packed with the coinbase
    /// flag), so a full UTXO-set walk that only needs heights skips the
    /// script copy [`Coin::deserialize_compact`] makes. `None` for the same
    /// out-of-range heights `deserialize_compact` rejects.
    pub fn peek_height(data: &[u8]) -> Option<u32> {
        let (height_cb, _) = decode_varint(data)?;
        u32::try_from(height_cb >> 1).ok()
    }

    /// Streaming variant of [`Coin::deserialize_compact`]: returns the
    /// decoded coin and the number of bytes consumed, so the caller can
    /// pack multiple coins back-to-back without an outer length prefix.
    /// Used by the undo v1 format. Returns `None` if the bytes are
    /// truncated or the varints overflow.
    pub fn deserialize_compact_stream(data: &[u8]) -> Option<(Self, usize)> {
        let (height_cb, n1) = decode_varint(data)?;
        // Reject corrupt records whose encoded height would not fit in u32.
        // Without this guard, `height_cb >> 1 as u32` would silently wrap
        // and we'd restore a coin at the wrong height during disconnect.
        let height_u64 = height_cb >> 1;
        if height_u64 > u32::MAX as u64 {
            return None;
        }
        let height = height_u64 as u32;
        let coinbase = (height_cb & 1) != 0;
        // No default on a short read. A record that ends here was
        // written in a layout this binary does not read, and the schema
        // gate is supposed to have refused the datadir before anything
        // reached this function — so treat it as corruption rather than
        // silently producing a coin with ordinal 0, which is the genesis
        // coinbase's ordinal and would key spend rows onto it.
        let (txseq, n2) = decode_varint(data.get(n1..)?)?;
        let (amount, n3) = decode_varint(data.get(n1 + n2..)?)?;
        let (script_len, n4) = decode_varint(data.get(n1 + n2 + n3..)?)?;
        let script_start = n1 + n2 + n3 + n4;
        let script_end = script_start.checked_add(script_len as usize)?;
        if script_end > data.len() {
            return None;
        }
        let script_pubkey = bitcoin::ScriptBuf::from_bytes(data[script_start..script_end].to_vec());
        Some((
            Coin {
                amount,
                script_pubkey,
                height,
                coinbase,
                txseq,
            },
            script_end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_height_reads_the_height_of_a_compact_coin() {
        for (height, coinbase) in [(0u32, false), (1, true), (967_000, false), (u32::MAX, true)] {
            let coin = Coin {
                amount: 5_000,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                height,
                coinbase,
                txseq: 42,
            };
            let bytes = coin.serialize_compact();
            assert_eq!(Coin::peek_height(&bytes), Some(height));
            assert_eq!(
                Coin::deserialize_compact(&bytes).map(|c| c.height),
                Some(height)
            );
        }
        assert_eq!(Coin::peek_height(&[]), None);
    }

    #[test]
    fn test_outpoint_key_roundtrip() {
        use bitcoin::hashes::Hash;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
            ),
            vout: 42,
        };
        let key = outpoint_to_key(&outpoint);
        let recovered = key_to_outpoint(&key);
        assert_eq!(outpoint, recovered);
    }

    #[test]
    fn test_coin_bincode_roundtrip() {
        let coin = Coin {
            amount: 5_000_000_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            height: 100,
            coinbase: true,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let encoded = bincode::serialize(&coin).unwrap();
        let decoded: Coin = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.amount, coin.amount);
        assert_eq!(decoded.height, coin.height);
        assert_eq!(decoded.coinbase, coin.coinbase);
        assert_eq!(decoded.script_pubkey, coin.script_pubkey);
    }

    #[test]
    fn test_outpoint_key_zero_vout() {
        use bitcoin::hashes::Hash;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
            ),
            vout: 0,
        };
        let key = outpoint_to_key(&outpoint);
        let recovered = key_to_outpoint(&key);
        assert_eq!(outpoint, recovered);
        // Verify that the last 4 bytes encode vout=0
        assert_eq!(&key[32..36], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_outpoint_key_max_vout() {
        use bitcoin::hashes::Hash;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xff; 32]),
            ),
            vout: u32::MAX,
        };
        let key = outpoint_to_key(&outpoint);
        let recovered = key_to_outpoint(&key);
        assert_eq!(outpoint, recovered);
        // Verify that the last 4 bytes encode u32::MAX in little-endian
        assert_eq!(&key[32..36], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_coin_empty_script() {
        let coin = Coin {
            amount: 0,
            script_pubkey: bitcoin::ScriptBuf::new(), // empty script
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let encoded = bincode::serialize(&coin).unwrap();
        let decoded: Coin = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.amount, 0);
        assert_eq!(decoded.height, 0);
        assert!(!decoded.coinbase);
        assert!(decoded.script_pubkey.is_empty());
    }

    #[test]
    fn test_compact_roundtrip_p2wpkh() {
        let coin = Coin {
            amount: 5_000_000_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab]),
            height: 800_000,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let encoded = coin.serialize_compact();
        assert!(encoded.len() < 35, "compact should be <35 bytes, got {}", encoded.len());
        let decoded = Coin::deserialize_compact(&encoded).unwrap();
        assert_eq!(decoded.amount, coin.amount);
        assert_eq!(decoded.height, coin.height);
        assert_eq!(decoded.coinbase, coin.coinbase);
        assert_eq!(decoded.script_pubkey, coin.script_pubkey);
    }

    #[test]
    fn test_compact_roundtrip_coinbase() {
        let coin = Coin {
            amount: 625_000_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            height: 100,
            coinbase: true,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let encoded = coin.serialize_compact();
        let decoded = Coin::deserialize_compact(&encoded).unwrap();
        assert_eq!(decoded.amount, coin.amount);
        assert_eq!(decoded.height, coin.height);
        assert!(decoded.coinbase);
        assert_eq!(decoded.script_pubkey, coin.script_pubkey);
    }

    #[test]
    fn test_compact_roundtrip_zero() {
        let coin = Coin {
            amount: 0,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let encoded = coin.serialize_compact();
        // 1 byte each for height_cb, txseq, amount, script_len.
        assert_eq!(encoded.len(), 4);
        let decoded = Coin::deserialize_compact(&encoded).unwrap();
        assert_eq!(decoded.amount, 0);
        assert_eq!(decoded.height, 0);
        assert!(!decoded.coinbase);
    }

    /// The ordinal has to survive the round trip, and a record that
    /// ends before it must be rejected rather than defaulted.
    ///
    /// Defaulting would produce ordinal 0 — the genesis coinbase's —
    /// so every spend of such a coin would key its `spent` row onto
    /// genesis. The chainstate schema version is supposed to make a
    /// short record unreachable; this is what happens if it ever is.
    #[test]
    fn coin_compact_roundtrip_carries_txseq_and_rejects_truncation() {
        for txseq in [0u64, 1, 127, 128, 1 << 20, node_index::TXSEQ_MAX] {
            let coin = Coin {
                amount: 12_345,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                height: 700_000,
                coinbase: false,
                txseq,
            };
            let encoded = coin.serialize_compact();
            let decoded = Coin::deserialize_compact(&encoded).expect("must decode");
            assert_eq!(decoded, coin, "ordinal {txseq} must survive the round trip");
        }

        // A record in the pre-ordinal shape: height_cb, amount,
        // script_len, script. The ordinal varint reads the amount, the
        // amount reads the length, and the length reads the script —
        // so the truncation has to be caught by a bounds check, not by
        // a length mismatch alone.
        let mut short = Vec::new();
        encode_varint(2, &mut short); // height_cb
        encode_varint(5_000, &mut short); // amount, read as the ordinal
        encode_varint(1, &mut short); // script_len, read as the amount
        short.push(0x51); // script, read as the length
        assert!(
            Coin::deserialize_compact(&short).is_none(),
            "a record written in the previous layout must be rejected, not \
             silently re-interpreted"
        );

        // And the genuinely truncated case: nothing at all after the
        // height.
        let mut truncated = Vec::new();
        encode_varint(2, &mut truncated);
        assert!(Coin::deserialize_compact(&truncated).is_none());
    }

    #[test]
    fn test_compact_height_overflow_rejected() {
        // Manually craft a record whose encoded height_cb is large enough
        // that `height_cb >> 1` does not fit in a u32. Pre-fix the code
        // wrapped silently; the M2 review finding required this rejection.
        // height_cb = (u64::MAX >> 0) — covers the full top of the range.
        let mut buf = Vec::new();
        encode_varint(u64::MAX, &mut buf); // height_cb
        encode_varint(0, &mut buf); // amount
        encode_varint(0, &mut buf); // script_len
        assert!(
            Coin::deserialize_compact(&buf).is_none(),
            "deserialize should reject a height that doesn't fit in u32",
        );
    }

    #[test]
    fn test_compact_height_just_above_u32_max_rejected() {
        // height = (u32::MAX as u64 + 1), encoded as height_cb = height << 1.
        let height_cb = ((u32::MAX as u64) + 1) << 1;
        let mut buf = Vec::new();
        encode_varint(height_cb, &mut buf);
        encode_varint(0, &mut buf);
        encode_varint(0, &mut buf);
        assert!(
            Coin::deserialize_compact(&buf).is_none(),
            "deserialize should reject a height that doesn't fit in u32",
        );
    }

    #[test]
    fn test_compact_height_at_u32_max_accepted() {
        // u32::MAX is the boundary — must still decode.
        let height_cb = (u32::MAX as u64) << 1;
        let mut buf = Vec::new();
        encode_varint(height_cb, &mut buf);
        encode_varint(0, &mut buf); // txseq
        encode_varint(1, &mut buf); // amount
        encode_varint(0, &mut buf); // script_len
        let coin = Coin::deserialize_compact(&buf).expect("u32::MAX height should decode");
        assert_eq!(coin.height, u32::MAX);
    }

    #[test]
    fn test_compact_smaller_than_bincode() {
        let coin = Coin {
            amount: 100_000_000, // 1 BTC
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab]),
            height: 500_000,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };
        let compact = coin.serialize_compact();
        let bincode_encoded = bincode::serialize(&coin).unwrap();
        assert!(compact.len() < bincode_encoded.len(),
            "compact {} should be smaller than bincode {}", compact.len(), bincode_encoded.len());
    }
}
