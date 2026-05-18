use bitcoin::{BlockHash, OutPoint, Txid};

use crate::index::address::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, Scripthash,
};
#[cfg(feature = "block-filter-index")]
use crate::index::filter::FilterKey;
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError};
use node_index::SpendingRef;

/// In-memory storage backend for testing.
pub struct InMemoryStore {
    block_index: parking_lot::RwLock<std::collections::HashMap<BlockHash, BlockIndexEntry>>,
    coins: parking_lot::RwLock<std::collections::HashMap<OutPoint, Coin>>,
    tip: parking_lot::RwLock<Option<BlockHash>>,
    height_index: parking_lot::RwLock<std::collections::HashMap<u32, BlockHash>>,
    undo: parking_lot::RwLock<std::collections::HashMap<BlockHash, UndoData>>,
    tx_index: parking_lot::RwLock<std::collections::HashMap<Txid, BlockHash>>,
    addr_funding: parking_lot::RwLock<Vec<AddrFundingRow>>,
    addr_spending: parking_lot::RwLock<Vec<AddrSpendingRow>>,
    outpoint_spend: parking_lot::RwLock<std::collections::HashMap<OutPoint, SpendingRef>>,
    #[cfg(feature = "block-filter-index")]
    filter: parking_lot::RwLock<std::collections::HashMap<FilterKey, Vec<u8>>>,
    #[cfg(feature = "block-filter-index")]
    filter_header: parking_lot::RwLock<std::collections::HashMap<FilterKey, [u8; 32]>>,
    #[cfg(feature = "block-filter-index")]
    filter_complete: parking_lot::RwLock<bool>,
    #[cfg(feature = "block-filter-index")]
    filter_backfill_cursor: parking_lot::RwLock<node_filter_index::cursor::BackfillCursor>,
    #[cfg(feature = "block-filter-index")]
    filter_backfill_last_error: parking_lot::RwLock<Option<String>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            block_index: parking_lot::RwLock::new(std::collections::HashMap::new()),
            coins: parking_lot::RwLock::new(std::collections::HashMap::new()),
            tip: parking_lot::RwLock::new(None),
            height_index: parking_lot::RwLock::new(std::collections::HashMap::new()),
            undo: parking_lot::RwLock::new(std::collections::HashMap::new()),
            tx_index: parking_lot::RwLock::new(std::collections::HashMap::new()),
            addr_funding: parking_lot::RwLock::new(Vec::new()),
            addr_spending: parking_lot::RwLock::new(Vec::new()),
            outpoint_spend: parking_lot::RwLock::new(std::collections::HashMap::new()),
            #[cfg(feature = "block-filter-index")]
            filter: parking_lot::RwLock::new(std::collections::HashMap::new()),
            #[cfg(feature = "block-filter-index")]
            filter_header: parking_lot::RwLock::new(std::collections::HashMap::new()),
            // Match the RocksDb default: tests that drive the filter index
            // and want a complete marker stamp it explicitly via
            // `mark_block_filter_index_complete`.
            #[cfg(feature = "block-filter-index")]
            filter_complete: parking_lot::RwLock::new(true),
            #[cfg(feature = "block-filter-index")]
            filter_backfill_cursor: parking_lot::RwLock::new(
                node_filter_index::cursor::BackfillCursor::idle(),
            ),
            #[cfg(feature = "block-filter-index")]
            filter_backfill_last_error: parking_lot::RwLock::new(None),
        }
    }
}

impl Store for InMemoryStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.block_index.read().get(hash).cloned()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.read().get(outpoint).cloned()
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.coins.read().contains_key(outpoint)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        *self.tip.read()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.height_index.read().get(&height).copied()
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut bi = self.block_index.write();
        let mut coins = self.coins.write();
        let mut tip = self.tip.write();
        let mut hi = self.height_index.write();
        let mut undo = self.undo.write();
        let mut txi = self.tx_index.write();

        for (hash, entry) in batch.block_index_puts {
            bi.insert(hash, entry);
        }
        for (outpoint, coin) in batch.coin_puts {
            coins.insert(outpoint, coin);
        }
        for (outpoint, _amount, _height) in batch.coin_removes {
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
        if !batch.addr_funding_puts.is_empty() || !batch.addr_funding_removes.is_empty() {
            let mut af = self.addr_funding.write();
            af.extend(batch.addr_funding_puts);
            for k in batch.addr_funding_removes {
                af.retain(|r| r.key() != k);
            }
        }
        if !batch.addr_spending_puts.is_empty() || !batch.addr_spending_removes.is_empty() {
            let mut as_ = self.addr_spending.write();
            as_.extend(batch.addr_spending_puts);
            for k in batch.addr_spending_removes {
                as_.retain(|r| r.key() != k);
            }
        }
        if !batch.outpoint_spend_puts.is_empty() || !batch.outpoint_spend_removes.is_empty() {
            let mut os = self.outpoint_spend.write();
            for (op, sref) in batch.outpoint_spend_puts {
                os.insert(op, sref);
            }
            for op in batch.outpoint_spend_removes {
                os.remove(&op);
            }
        }

        #[cfg(feature = "block-filter-index")]
        {
            if !batch.filter_puts.is_empty() {
                let mut f = self.filter.write();
                for row in batch.filter_puts {
                    f.insert(row.key, row.filter);
                }
            }
            if !batch.filter_header_puts.is_empty() {
                let mut fh = self.filter_header.write();
                for row in batch.filter_header_puts {
                    fh.insert(row.key, row.header);
                }
            }
            if !batch.filter_removes.is_empty() {
                let mut f = self.filter.write();
                let mut fh = self.filter_header.write();
                for k in batch.filter_removes {
                    f.remove(&k);
                    fh.remove(&k);
                }
            }
            if let Some(adv) = batch.filter_backfill_cursor_advance {
                let mut cur = self.filter_backfill_cursor.write();
                cur.state = adv.state;
                cur.cursor_height = adv.cursor_height;
                cur.snapshot_height = adv.snapshot_height;
                cur.started_at_unix = adv.started_at_unix;
                if adv.snapshot_tip_hash != [0u8; 32] {
                    cur.snapshot_tip_hash = adv.snapshot_tip_hash;
                }
            }
        }

        Ok(())
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.undo.read().get(hash).cloned()
    }

    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<crate::storage::BlockIndexScanStats, StoreError> {
        let bi = self.block_index.read();
        for (hash, entry) in bi.iter() {
            visit(*hash, entry.clone());
        }
        // In-memory map can't carry corrupt rows; stats are always zero.
        Ok(crate::storage::BlockIndexScanStats::default())
    }

    fn coin_count(&self) -> u64 {
        self.coins.read().len() as u64
    }

    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<u64, StoreError> {
        // For deterministic iteration order (matching Core's key sort),
        // collect into a sorted vector before yielding. Tests use this
        // backend so consistency with the RocksDB path matters.
        let coins = self.coins.read();
        let mut entries: Vec<(OutPoint, Coin)> = coins
            .iter()
            .map(|(op, c)| (*op, c.clone()))
            .collect();
        drop(coins);
        entries.sort_by(|(a, _), (b, _)| {
            let ak = crate::storage::coinview::outpoint_to_key(a);
            let bk = crate::storage::coinview::outpoint_to_key(b);
            ak.cmp(&bk)
        });
        let mut written = 0u64;
        for (op, coin) in &entries {
            f(op, coin)?;
            written += 1;
        }
        Ok(written)
    }

    fn coin_total_amount(&self) -> u64 {
        self.coins.read().values().map(|c| c.amount).sum()
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        let coins = self.coins.read();
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
        self.tx_index.read().get(txid).copied()
    }

    fn has_txindex(&self) -> bool {
        true // always enabled in tests
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.coins.write().clear();
        self.undo.write().clear();
        self.tx_index.write().clear();
        self.addr_funding.write().clear();
        self.addr_spending.write().clear();
        self.outpoint_spend.write().clear();
        #[cfg(feature = "block-filter-index")]
        {
            self.filter.write().clear();
            self.filter_header.write().clear();
            *self.filter_complete.write() = true;
        }
        *self.tip.write() = None;
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        self.block_index.write().clear();
        self.height_index.write().clear();
        self.coins.write().clear();
        self.undo.write().clear();
        self.tx_index.write().clear();
        self.addr_funding.write().clear();
        self.addr_spending.write().clear();
        self.outpoint_spend.write().clear();
        #[cfg(feature = "block-filter-index")]
        {
            self.filter.write().clear();
            self.filter_header.write().clear();
            *self.filter_complete.write() = true;
        }
        *self.tip.write() = None;
        Ok(())
    }

    fn iter_addr_funding(&self, sh: &Scripthash) -> Vec<(AddrFundingKey, u64)> {
        let mut rows: Vec<(AddrFundingKey, u64)> = self
            .addr_funding
            .read()
            
            .iter()
            .filter(|r| &r.scripthash == sh)
            .map(|r| (r.key(), r.amount_sat))
            .collect();
        rows.sort_by(|(a, _), (b, _)| {
            crate::index::address::encode_funding_key_v2(a)
                .cmp(&crate::index::address::encode_funding_key_v2(b))
        });
        rows
    }

    fn iter_addr_spending(&self, sh: &Scripthash) -> Vec<(AddrSpendingKey, OutPoint)> {
        let mut rows: Vec<(AddrSpendingKey, OutPoint)> = self
            .addr_spending
            .read()
            
            .iter()
            .filter(|r| &r.scripthash == sh)
            .map(|r| (r.key(), r.prev_outpoint))
            .collect();
        rows.sort_by(|(a, _), (b, _)| {
            crate::index::address::encode_spending_key_v2(a)
                .cmp(&crate::index::address::encode_spending_key_v2(b))
        });
        rows
    }

    fn lookup_spend(&self, outpoint: &OutPoint) -> Result<Option<SpendingRef>, StoreError> {
        Ok(self.outpoint_spend.read().get(outpoint).copied())
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter(&self, filter_type: u8, height: u32) -> Option<Vec<u8>> {
        self.filter
            .read()
            
            .get(&FilterKey {
                filter_type,
                height,
            })
            .cloned()
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter_header(&self, filter_type: u8, height: u32) -> Option<[u8; 32]> {
        self.filter_header
            .read()
            
            .get(&FilterKey {
                filter_type,
                height,
            })
            .copied()
    }

    #[cfg(feature = "block-filter-index")]
    fn block_filter_index_complete(&self) -> bool {
        *self.filter_complete.read()
    }

    #[cfg(feature = "block-filter-index")]
    fn mark_block_filter_index_complete(&self) -> Result<(), StoreError> {
        *self.filter_complete.write() = true;
        Ok(())
    }

    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_cursor(&self) -> node_filter_index::cursor::BackfillCursor {
        *self.filter_backfill_cursor.read()
    }

    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_last_error(&self) -> Option<String> {
        self.filter_backfill_last_error.read().clone()
    }

    #[cfg(feature = "block-filter-index")]
    fn write_filter_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        let mut slot = self.filter_backfill_last_error.write();
        if msg.is_empty() {
            *slot = None;
        } else {
            *slot = Some(msg.to_string());
        }
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
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [0x42; 32],
            )),
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
        batch2.coin_removes.push((outpoint, 42, 0));
        store.write_batch(batch2).unwrap();
        assert!(!store.has_coin(&outpoint));
    }
}
