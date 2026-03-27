use serde::{Deserialize, Serialize};

/// A single unspent transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub amount: u64,
    #[serde(with = "script_serde")]
    pub script_pubkey: bitcoin::ScriptBuf,
    pub height: u32,
    pub coinbase: bool,
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
// Format: [varint(height<<1 | coinbase)] [varint(amount)] [varint(script_len)] [script]
// ~28 bytes for P2WPKH vs ~43 with bincode (35% smaller).
// ---------------------------------------------------------------------------

/// Encode a u64 as a variable-length integer (7 bits per byte, MSB = more).
fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
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
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
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
        encode_varint(self.amount, &mut buf);
        let script = self.script_pubkey.as_bytes();
        encode_varint(script.len() as u64, &mut buf);
        buf.extend_from_slice(script);
        buf
    }

    /// Deserialize from compact binary format. Rejects trailing bytes.
    pub fn deserialize_compact(data: &[u8]) -> Option<Self> {
        let (height_cb, n1) = decode_varint(data)?;
        let height = (height_cb >> 1) as u32;
        let coinbase = (height_cb & 1) != 0;
        let (amount, n2) = decode_varint(&data[n1..])?;
        let (script_len, n3) = decode_varint(&data[n1 + n2..])?;
        let script_start = n1 + n2 + n3;
        let script_end = script_start + script_len as usize;
        // Strict: exact length match, reject trailing garbage
        if script_end != data.len() {
            return None;
        }
        let script_pubkey = bitcoin::ScriptBuf::from_bytes(data[script_start..script_end].to_vec());
        Some(Coin {
            amount,
            script_pubkey,
            height,
            coinbase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let encoded = coin.serialize_compact();
        assert_eq!(encoded.len(), 3); // 1 byte each for height_cb, amount, script_len
        let decoded = Coin::deserialize_compact(&encoded).unwrap();
        assert_eq!(decoded.amount, 0);
        assert_eq!(decoded.height, 0);
        assert!(!decoded.coinbase);
    }

    #[test]
    fn test_compact_smaller_than_bincode() {
        let coin = Coin {
            amount: 100_000_000, // 1 BTC
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab]),
            height: 500_000,
            coinbase: false,
        };
        let compact = coin.serialize_compact();
        let bincode_encoded = bincode::serialize(&coin).unwrap();
        assert!(compact.len() < bincode_encoded.len(),
            "compact {} should be smaller than bincode {}", compact.len(), bincode_encoded.len());
    }
}
