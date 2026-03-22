use bitcoin::{BlockHash, OutPoint, Txid};

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError};

/// In-memory storage backend for testing.
pub struct InMemoryStore {
    block_index:
        std::sync::RwLock<std::collections::HashMap<BlockHash, BlockIndexEntry>>,
    coins: std::sync::RwLock<std::collections::HashMap<OutPoint, Coin>>,
    tip: std::sync::RwLock<Option<BlockHash>>,
    height_index: std::sync::RwLock<std::collections::HashMap<u32, BlockHash>>,
    undo: std::sync::RwLock<std::collections::HashMap<BlockHash, UndoData>>,
    tx_index: std::sync::RwLock<std::collections::HashMap<Txid, BlockHash>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            block_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            coins: std::sync::RwLock::new(std::collections::HashMap::new()),
            tip: std::sync::RwLock::new(None),
            height_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            undo: std::sync::RwLock::new(std::collections::HashMap::new()),
            tx_index: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Store for InMemoryStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.block_index.read().unwrap().get(hash).cloned()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.read().unwrap().get(outpoint).cloned()
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.coins.read().unwrap().contains_key(outpoint)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        *self.tip.read().unwrap()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.height_index.read().unwrap().get(&height).copied()
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut bi = self.block_index.write().unwrap();
        let mut coins = self.coins.write().unwrap();
        let mut tip = self.tip.write().unwrap();
        let mut hi = self.height_index.write().unwrap();
        let mut undo = self.undo.write().unwrap();
        let mut txi = self.tx_index.write().unwrap();

        for (hash, entry) in batch.block_index_puts {
            bi.insert(hash, entry);
        }
        for (outpoint, coin) in batch.coin_puts {
            coins.insert(outpoint, coin);
        }
        for (outpoint, _amount) in batch.coin_removes {
            coins.remove(&outpoint);
        }
        if let Some(hash) = batch.tip {
            *tip = Some(hash);
        }
        for (height, hash) in batch.height_hash_puts {
            hi.insert(height, hash);
        }
        for height in batch.height_hash_removes {
            hi.remove(&height);
        }
        for (hash, data) in batch.undo_puts {
            undo.insert(hash, data);
        }
        for (txid, block_hash) in batch.tx_index_puts {
            txi.insert(txid, block_hash);
        }
        for txid in batch.tx_index_removes {
            txi.remove(&txid);
        }

        Ok(())
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.undo.read().unwrap().get(hash).cloned()
    }

    fn coin_count(&self) -> u64 {
        self.coins.read().unwrap().len() as u64
    }

    fn coin_total_amount(&self) -> u64 {
        self.coins
            .read()
            .unwrap()
            .values()
            .map(|c| c.amount)
            .sum()
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        let coins = self.coins.read().unwrap();
        let mut hist: Vec<u64> = Vec::new();
        for coin in coins.values() {
            let bucket = (coin.height / 1000) as usize;
            if bucket >= hist.len() {
                hist.resize(bucket + 1, 0);
            }
            hist[bucket] += 1;
        }
        hist
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.tx_index.read().unwrap().get(txid).copied()
    }

    fn has_txindex(&self) -> bool {
        true // always enabled in tests
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.coins.write().unwrap().clear();
        self.undo.write().unwrap().clear();
        self.tx_index.write().unwrap().clear();
        *self.tip.write().unwrap() = None;
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        self.block_index.write().unwrap().clear();
        self.height_index.write().unwrap().clear();
        self.coins.write().unwrap().clear();
        self.undo.write().unwrap().clear();
        self.tx_index.write().unwrap().clear();
        *self.tip.write().unwrap() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{BlockStatus, work_for_bits};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;

    fn make_test_entry() -> BlockIndexEntry {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: work_for_bits(CompactTarget::from_consensus(0x207fffff)),
        }
    }

    #[test]
    fn test_inmemory_block_index_roundtrip() {
        let store = InMemoryStore::new();
        let entry = make_test_entry();
        let hash = entry.header.block_hash();

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry.clone()));
        batch.tip = Some(hash);
        batch.height_hash_puts.push((0, hash));
        store.write_batch(batch).unwrap();

        assert_eq!(store.get_tip().unwrap(), hash);
        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(recovered.height, 0);
        assert_eq!(store.get_block_hash_by_height(0).unwrap(), hash);
    }

    #[test]
    fn test_inmemory_coin_roundtrip() {
        let store = InMemoryStore::new();
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
            ),
            vout: 0,
        };
        let coin = Coin {
            amount: 5_000_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: true,
        };

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin.clone()));
        store.write_batch(batch).unwrap();

        assert!(store.has_coin(&outpoint));
        let recovered = store.get_coin(&outpoint).unwrap();
        assert_eq!(recovered.amount, 5_000_000_000);

        // Remove
        let mut batch2 = StoreBatch::default();
        batch2.coin_removes.push((outpoint, 42));
        store.write_batch(batch2).unwrap();
        assert!(!store.has_coin(&outpoint));
    }
}
