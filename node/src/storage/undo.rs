use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

use crate::storage::coinview::Coin;

/// Undo data for a connected block — stores all coins that were spent.
/// Used to restore the UTXO set when disconnecting a block during reorg.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UndoData {
    pub spent_coins: Vec<(OutPointSer, Coin)>,
}

/// Serializable OutPoint (bitcoin::OutPoint doesn't impl serde by default for bincode).
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
    fn test_outpointser_roundtrip() {
        let op = make_outpoint(0xAB, 42);
        let ser = OutPointSer::from(&op);
        let recovered = ser.to_outpoint();
        assert_eq!(op.txid, recovered.txid);
        assert_eq!(op.vout, recovered.vout);
    }

    #[test]
    fn test_undo_data_bincode_roundtrip() {
        let op = make_outpoint(0x01, 0);
        let coin = make_coin(5_000_000_000, 100);
        let undo = UndoData {
            spent_coins: vec![(OutPointSer::from(&op), coin)],
        };
        let encoded = bincode::serialize(&undo).unwrap();
        let decoded: UndoData = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins.len(), 1);
        assert_eq!(decoded.spent_coins[0].1.amount, 5_000_000_000);
        assert_eq!(decoded.spent_coins[0].0.vout, 0);
    }

    #[test]
    fn test_undo_data_empty() {
        let undo = UndoData::default();
        assert!(undo.spent_coins.is_empty());
        let encoded = bincode::serialize(&undo).unwrap();
        let decoded: UndoData = bincode::deserialize(&encoded).unwrap();
        assert!(decoded.spent_coins.is_empty());
    }

    #[test]
    fn test_undo_data_multiple_coins() {
        let coins: Vec<(OutPointSer, Coin)> = (0..3)
            .map(|i| {
                let op = make_outpoint(i as u8 + 1, i);
                let coin = make_coin((i as u64 + 1) * 1_000_000, i * 10);
                (OutPointSer::from(&op), coin)
            })
            .collect();
        let undo = UndoData {
            spent_coins: coins,
        };
        let encoded = bincode::serialize(&undo).unwrap();
        let decoded: UndoData = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.spent_coins.len(), 3);
        for (i, (ser, coin)) in decoded.spent_coins.iter().enumerate() {
            assert_eq!(coin.amount, (i as u64 + 1) * 1_000_000);
            assert_eq!(ser.vout, i as u32);
        }
    }

    #[test]
    fn test_outpointser_different_vout() {
        let ser_a = OutPointSer {
            txid: [0xCC; 32],
            vout: 0,
        };
        let ser_b = OutPointSer {
            txid: [0xCC; 32],
            vout: 1,
        };
        let op_a = ser_a.to_outpoint();
        let op_b = ser_b.to_outpoint();
        assert_eq!(op_a.txid, op_b.txid);
        assert_ne!(op_a.vout, op_b.vout);
    }
}
