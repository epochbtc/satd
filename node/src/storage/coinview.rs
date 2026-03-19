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
}
