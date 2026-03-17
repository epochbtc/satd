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
