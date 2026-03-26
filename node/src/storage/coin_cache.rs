use bitcoin::{BlockHash, OutPoint, Txid};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Mutex, RwLock};

use super::blockindex::BlockIndexEntry;
use super::coinview::Coin;
use super::undo::UndoData;
use super::{Store, StoreBatch, StoreError};

/// Default dbcache size in MB (matches Bitcoin Core).
const DEFAULT_DBCACHE_MB: u64 = 450;

/// Dirty coin entry — must be flushed to backing store before eviction.
enum DirtyEntry {
    Present(Coin),
    Spent(u64),
}

/// In-memory write cache wrapping a persistent Store.
///
/// Two-tier coin cache:
/// - **Dirty map**: unbounded HashMap, flushed periodically to backing store.
/// - **Clean LRU**: bounded LruCache, auto-evicts coldest entries.
///
/// All overlay caches (block_index, height_hash, undo, tx_index) are
/// bounded LRU caches to prevent unbounded memory growth.
pub struct CoinCache {
    inner: Box<dyn Store>,
    dirty: RwLock<HashMap<OutPoint, DirtyEntry>>,
    clean: Mutex<LruCache<OutPoint, Coin>>,
    dirty_count: AtomicU32,
    pending_tip: Mutex<Option<BlockHash>>,
    count_delta: AtomicI64,
    amount_delta: AtomicI64,
    pending_batch: Mutex<StoreBatch>,
    block_index_cache: Mutex<LruCache<BlockHash, BlockIndexEntry>>,
    height_hash_cache: Mutex<LruCache<u32, BlockHash>>,
    undo_cache: Mutex<LruCache<BlockHash, UndoData>>,
    tx_index_cache: Mutex<LruCache<Txid, BlockHash>>,
    /// Dirty coin flush threshold (~25% of clean coin cap).
    flush_threshold: u32,
}

fn lru<K: std::hash::Hash + Eq, V>(cap: usize) -> LruCache<K, V> {
    LruCache::new(NonZeroUsize::new(cap).unwrap())
}

impl CoinCache {
    /// Create a CoinCache with the given dbcache budget in MB.
    ///
    /// LRU caps are derived from the budget:
    /// - Clean coins: 80% of budget (at ~200 bytes/entry)
    /// - Height hash: fixed 2M entries (~72 MB, must cover full chain)
    /// - Block index: 2% of budget (at ~300 bytes/entry)
    /// - Undo: fixed 1000 entries (large per-block, recent only)
    /// - Tx index: 5% of budget (at ~64 bytes/entry)
    /// - Dirty flush threshold: ~25% of clean coin cap
    pub fn new(inner: Box<dyn Store>, dbcache_mb: u64) -> Self {
        let budget = dbcache_mb as usize * 1_000_000;

        let clean_cap = (budget * 80 / 100) / 200; // 80% at ~200 bytes/entry
        let height_hash_cap = 2_000_000; // fixed — must cover full chain
        let block_index_cap = (budget * 2 / 100) / 300; // 2% at ~300 bytes/entry
        let undo_cap = 1_000; // fixed — recent blocks only
        let tx_index_cap = (budget * 5 / 100) / 64; // 5% at ~64 bytes/entry
        let flush_threshold = (clean_cap / 4) as u32; // 25% of clean cap

        Self {
            inner,
            dirty: RwLock::new(HashMap::new()),
            clean: Mutex::new(lru(clean_cap.max(1))),
            dirty_count: AtomicU32::new(0),
            pending_tip: Mutex::new(None),
            count_delta: AtomicI64::new(0),
            amount_delta: AtomicI64::new(0),
            pending_batch: Mutex::new(StoreBatch::default()),
            block_index_cache: Mutex::new(lru(block_index_cap.max(1))),
            height_hash_cache: Mutex::new(lru(height_hash_cap)),
            undo_cache: Mutex::new(lru(undo_cap)),
            tx_index_cache: Mutex::new(lru(tx_index_cap.max(1))),
            flush_threshold,
        }
    }

    /// Create a CoinCache with the default 450 MB budget (for tests).
    pub fn default(inner: Box<dyn Store>) -> Self {
        Self::new(inner, DEFAULT_DBCACHE_MB)
    }

    /// Flush all dirty coins and buffered non-coin writes to the inner store.
    pub fn flush(&self) -> Result<(), StoreError> {
        let mut dirty = self.dirty.write().unwrap();
        let mut batch = {
            let mut pending = self.pending_batch.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        for (outpoint, entry) in dirty.drain() {
            match entry {
                DirtyEntry::Present(coin) => {
                    batch.coin_puts.push((outpoint, coin));
                }
                DirtyEntry::Spent(amount) => {
                    batch.coin_removes.push((outpoint, amount));
                }
            }
        }

        batch.tip = self.pending_tip.lock().unwrap().take();

        let puts = batch.coin_puts.len();
        let removes = batch.coin_removes.len();
        let index_puts = batch.block_index_puts.len();
        let undo_puts = batch.undo_puts.len();

        drop(dirty);
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);

        let has_data = puts > 0
            || removes > 0
            || batch.tip.is_some()
            || !batch.block_index_puts.is_empty()
            || !batch.height_hash_puts.is_empty()
            || !batch.undo_puts.is_empty()
            || !batch.tx_index_puts.is_empty();

        if has_data {
            tracing::info!(
                coin_puts = puts,
                coin_removes = removes,
                block_index = index_puts,
                undo = undo_puts,
                "Flushing write cache to disk"
            );
            self.inner.write_batch(batch)?;
        }

        Ok(())
    }

    /// Number of dirty entries pending flush.
    pub fn dirty_count(&self) -> u32 {
        self.dirty_count.load(Ordering::Relaxed)
    }

    /// Approximate total cache size (dirty + clean coins).
    pub fn cache_size(&self) -> usize {
        self.dirty_count.load(Ordering::Relaxed) as usize
            + self.clean.lock().unwrap().len()
    }

    /// Dirty coin count threshold at which the cache should be flushed.
    /// This is ~25% of the clean coin LRU cap.
    pub fn flush_threshold(&self) -> u32 {
        self.flush_threshold
    }
}

impl Store for CoinCache {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        // 1. Check dirty map
        {
            let dirty = self.dirty.read().unwrap();
            if let Some(entry) = dirty.get(outpoint) {
                return match entry {
                    DirtyEntry::Present(coin) => Some(coin.clone()),
                    DirtyEntry::Spent(_) => None,
                };
            }
        }

        // 2. Check clean LRU
        {
            let mut clean = self.clean.lock().unwrap();
            if let Some(coin) = clean.get(outpoint) {
                return Some(coin.clone());
            }
        }

        // 3. Cache miss — read from backing store, populate LRU (auto-evicts if full)
        let coin = self.inner.get_coin(outpoint)?;
        self.clean.lock().unwrap().put(*outpoint, coin.clone());
        Some(coin)
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        {
            let dirty = self.dirty.read().unwrap();
            if let Some(entry) = dirty.get(outpoint) {
                return matches!(entry, DirtyEntry::Present(_));
            }
        }
        {
            let mut clean = self.clean.lock().unwrap();
            if clean.get(outpoint).is_some() {
                return true;
            }
        }
        self.inner.has_coin(outpoint)
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        // Absorb coin operations into dirty map
        let coin_dirty = batch.coin_puts.len() + batch.coin_removes.len();
        if coin_dirty > 0 {
            let mut dirty = self.dirty.write().unwrap();
            let mut clean = self.clean.lock().unwrap();

            for (outpoint, coin) in batch.coin_puts {
                self.amount_delta.fetch_add(coin.amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_add(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                dirty.insert(outpoint, DirtyEntry::Present(coin));
            }

            for (outpoint, spent_amount) in batch.coin_removes {
                self.amount_delta.fetch_sub(spent_amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_sub(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                dirty.insert(outpoint, DirtyEntry::Spent(spent_amount));
            }

            self.dirty_count
                .fetch_add(coin_dirty as u32, Ordering::Relaxed);
        }

        if batch.tip.is_some() {
            *self.pending_tip.lock().unwrap() = batch.tip;
        }

        // Populate overlay LRU caches
        {
            let mut bi = self.block_index_cache.lock().unwrap();
            for (hash, entry) in &batch.block_index_puts {
                bi.put(*hash, entry.clone());
            }
        }
        {
            let mut hh = self.height_hash_cache.lock().unwrap();
            for &(height, hash) in &batch.height_hash_puts {
                hh.put(height, hash);
            }
            for &height in &batch.height_hash_removes {
                hh.pop(&height);
            }
        }
        {
            let mut uc = self.undo_cache.lock().unwrap();
            for (hash, undo) in &batch.undo_puts {
                uc.put(*hash, undo.clone());
            }
        }
        {
            let mut ti = self.tx_index_cache.lock().unwrap();
            for &(txid, hash) in &batch.tx_index_puts {
                ti.put(txid, hash);
            }
            for txid in &batch.tx_index_removes {
                ti.pop(txid);
            }
        }

        // Non-coin operations:
        // - Without coins (store_block, accept_headers): write to backing store immediately
        // - With coins (connect_block): buffer for flush
        let has_non_coin = !batch.block_index_puts.is_empty()
            || !batch.height_hash_puts.is_empty()
            || !batch.height_hash_removes.is_empty()
            || !batch.undo_puts.is_empty()
            || !batch.tx_index_puts.is_empty()
            || !batch.tx_index_removes.is_empty();

        if has_non_coin {
            if coin_dirty == 0 {
                let pass_through = StoreBatch {
                    block_index_puts: batch.block_index_puts,
                    coin_puts: Vec::new(),
                    coin_removes: Vec::new(),
                    tip: None,
                    height_hash_puts: batch.height_hash_puts,
                    height_hash_removes: batch.height_hash_removes,
                    undo_puts: batch.undo_puts,
                    tx_index_puts: batch.tx_index_puts,
                    tx_index_removes: batch.tx_index_removes,
                };
                self.inner.write_batch(pass_through)?;
            } else {
                let mut pending = self.pending_batch.lock().unwrap();
                pending.block_index_puts.extend(batch.block_index_puts);
                pending.height_hash_puts.extend(batch.height_hash_puts);
                pending.height_hash_removes.extend(batch.height_hash_removes);
                pending.undo_puts.extend(batch.undo_puts);
                pending.tx_index_puts.extend(batch.tx_index_puts);
                pending.tx_index_removes.extend(batch.tx_index_removes);
            }
        }

        Ok(())
    }

    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        if let Some(entry) = self.block_index_cache.lock().unwrap().get(hash) {
            return Some(entry.clone());
        }
        self.inner.get_block_index(hash)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        if let Some(tip) = *self.pending_tip.lock().unwrap() {
            return Some(tip);
        }
        self.inner.get_tip()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        if let Some(&hash) = self.height_hash_cache.lock().unwrap().get(&height) {
            return Some(hash);
        }
        self.inner.get_block_hash_by_height(height)
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        if let Some(undo) = self.undo_cache.lock().unwrap().get(hash) {
            return Some(undo.clone());
        }
        self.inner.get_undo(hash)
    }

    fn coin_count(&self) -> u64 {
        let base = self.inner.coin_count() as i64;
        let delta = self.count_delta.load(Ordering::Relaxed);
        (base + delta).max(0) as u64
    }

    fn coin_total_amount(&self) -> u64 {
        let base = self.inner.coin_total_amount() as i64;
        let delta = self.amount_delta.load(Ordering::Relaxed);
        (base + delta).max(0) as u64
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        self.inner.utxo_height_hist()
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        if let Some(&hash) = self.tx_index_cache.lock().unwrap().get(txid) {
            return Some(hash);
        }
        self.inner.get_tx_location(txid)
    }

    fn has_txindex(&self) -> bool {
        self.inner.has_txindex()
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.dirty.write().unwrap().clear();
        self.clean.lock().unwrap().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock().unwrap() = None;
        *self.pending_batch.lock().unwrap() = StoreBatch::default();
        self.block_index_cache.lock().unwrap().clear();
        self.height_hash_cache.lock().unwrap().clear();
        self.undo_cache.lock().unwrap().clear();
        self.tx_index_cache.lock().unwrap().clear();
        self.inner.clear_chainstate()
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        self.dirty.write().unwrap().clear();
        self.clean.lock().unwrap().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock().unwrap() = None;
        *self.pending_batch.lock().unwrap() = StoreBatch::default();
        self.block_index_cache.lock().unwrap().clear();
        self.height_hash_cache.lock().unwrap().clear();
        self.undo_cache.lock().unwrap().clear();
        self.tx_index_cache.lock().unwrap().clear();
        self.inner.clear_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::db::InMemoryStore;
    use super::super::blockindex::{BlockIndexEntry, BlockStatus, work_for_bits};
    use super::super::undo::{OutPointSer, UndoData};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;

    fn make_cache(dbcache_mb: u64) -> CoinCache {
        CoinCache::new(Box::new(InMemoryStore::new()), dbcache_mb)
    }

    fn make_coin(amount: u64, height: u32) -> Coin {
        Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height,
            coinbase: false,
        }
    }

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([txid_byte; 32]),
            ),
            vout,
        }
    }

    fn make_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    fn make_test_entry(height: u32) -> BlockIndexEntry {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        BlockIndexEntry {
            header: genesis.header,
            height,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: work_for_bits(CompactTarget::from_consensus(0x207fffff)),
        }
    }

    // ---------------------------------------------------------------
    // 1. get_coin read-through: inner store hit populates clean LRU
    // ---------------------------------------------------------------
    #[test]
    fn test_get_coin_read_through() {
        let inner = InMemoryStore::new();
        let op = make_outpoint(0x01, 0);
        let coin = make_coin(1000, 1);

        // Seed the inner store directly.
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, coin.clone()));
        inner.write_batch(batch).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);

        // First get_coin — cache miss, reads from inner.
        let c1 = cache.get_coin(&op).unwrap();
        assert_eq!(c1.amount, 1000);

        // Second get_coin — should hit the clean LRU. dirty_count stays 0
        // because read-through only populates clean, not dirty.
        let c2 = cache.get_coin(&op).unwrap();
        assert_eq!(c2.amount, 1000);
        assert_eq!(cache.dirty_count(), 0);
    }

    // ---------------------------------------------------------------
    // 2. Dirty coin takes priority over inner store
    // ---------------------------------------------------------------
    #[test]
    fn test_get_coin_dirty_takes_priority() {
        let inner = InMemoryStore::new();
        let op = make_outpoint(0x02, 0);

        // Seed inner with amount=500.
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((op, make_coin(500, 1)));
        inner.write_batch(seed).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);

        // Write a dirty coin with amount=999.
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, make_coin(999, 2)));
        cache.write_batch(batch).unwrap();

        let c = cache.get_coin(&op).unwrap();
        assert_eq!(c.amount, 999);
    }

    // ---------------------------------------------------------------
    // 3. Spent coin returns None
    // ---------------------------------------------------------------
    #[test]
    fn test_get_coin_spent_returns_none() {
        let cache = make_cache(10);
        let op = make_outpoint(0x03, 0);

        // Add then spend.
        let mut b1 = StoreBatch::default();
        b1.coin_puts.push((op, make_coin(100, 1)));
        cache.write_batch(b1).unwrap();

        let mut b2 = StoreBatch::default();
        b2.coin_removes.push((op, 100));
        cache.write_batch(b2).unwrap();

        assert!(cache.get_coin(&op).is_none());
    }

    // ---------------------------------------------------------------
    // 4. has_coin returns true for dirty Present
    // ---------------------------------------------------------------
    #[test]
    fn test_has_coin_dirty_present() {
        let cache = make_cache(10);
        let op = make_outpoint(0x04, 0);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, make_coin(50, 1)));
        cache.write_batch(batch).unwrap();

        assert!(cache.has_coin(&op));
    }

    // ---------------------------------------------------------------
    // 5. has_coin returns false for dirty Spent
    // ---------------------------------------------------------------
    #[test]
    fn test_has_coin_dirty_spent() {
        let cache = make_cache(10);
        let op = make_outpoint(0x05, 0);

        let mut b1 = StoreBatch::default();
        b1.coin_puts.push((op, make_coin(50, 1)));
        cache.write_batch(b1).unwrap();

        let mut b2 = StoreBatch::default();
        b2.coin_removes.push((op, 50));
        cache.write_batch(b2).unwrap();

        assert!(!cache.has_coin(&op));
    }

    // ---------------------------------------------------------------
    // 6. write_batch absorbs coins into dirty map
    // ---------------------------------------------------------------
    #[test]
    fn test_write_batch_absorbs_coins() {
        let cache = make_cache(10);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x10, 0), make_coin(100, 1)));
        batch.coin_puts.push((make_outpoint(0x11, 0), make_coin(200, 2)));
        cache.write_batch(batch).unwrap();

        assert_eq!(cache.dirty_count(), 2);
    }

    // ---------------------------------------------------------------
    // 7. write_batch tracks count_delta and amount_delta
    // ---------------------------------------------------------------
    #[test]
    fn test_write_batch_tracks_deltas() {
        let cache = make_cache(10);

        // Add two coins: amounts 1000 and 2000.
        let mut b1 = StoreBatch::default();
        b1.coin_puts.push((make_outpoint(0x20, 0), make_coin(1000, 1)));
        b1.coin_puts.push((make_outpoint(0x21, 0), make_coin(2000, 2)));
        cache.write_batch(b1).unwrap();

        assert_eq!(cache.count_delta.load(Ordering::Relaxed), 2);
        assert_eq!(cache.amount_delta.load(Ordering::Relaxed), 3000);

        // Remove one coin (spent amount = 1000).
        let mut b2 = StoreBatch::default();
        b2.coin_removes.push((make_outpoint(0x20, 0), 1000));
        cache.write_batch(b2).unwrap();

        assert_eq!(cache.count_delta.load(Ordering::Relaxed), 1);
        assert_eq!(cache.amount_delta.load(Ordering::Relaxed), 2000);
    }

    // ---------------------------------------------------------------
    // 8. flush writes coins to inner store
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_writes_to_inner() {
        let inner = InMemoryStore::new();
        let cache = CoinCache::new(Box::new(inner), 10);

        let op = make_outpoint(0x30, 0);
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, make_coin(7777, 5)));
        cache.write_batch(batch).unwrap();

        // Before flush — inner should NOT have the coin (it's only in dirty).
        // We can't easily access inner through CoinCache, but after flush
        // we can verify via the cache itself (which will read-through).
        cache.flush().unwrap();

        // After flush, dirty is empty. get_coin should read-through from inner.
        assert_eq!(cache.dirty_count(), 0);
        let c = cache.get_coin(&op).unwrap();
        assert_eq!(c.amount, 7777);
    }

    // ---------------------------------------------------------------
    // 9. flush clears dirty count
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_clears_dirty() {
        let cache = make_cache(10);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x40, 0), make_coin(100, 1)));
        batch.coin_puts.push((make_outpoint(0x41, 0), make_coin(200, 2)));
        batch.coin_removes.push((make_outpoint(0x42, 0), 300));
        cache.write_batch(batch).unwrap();

        assert_eq!(cache.dirty_count(), 3);
        cache.flush().unwrap();
        assert_eq!(cache.dirty_count(), 0);
    }

    // ---------------------------------------------------------------
    // 10. flush resets deltas to zero
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_resets_deltas() {
        let cache = make_cache(10);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x50, 0), make_coin(500, 1)));
        cache.write_batch(batch).unwrap();

        assert_ne!(cache.count_delta.load(Ordering::Relaxed), 0);
        assert_ne!(cache.amount_delta.load(Ordering::Relaxed), 0);

        cache.flush().unwrap();

        assert_eq!(cache.count_delta.load(Ordering::Relaxed), 0);
        assert_eq!(cache.amount_delta.load(Ordering::Relaxed), 0);
    }

    // ---------------------------------------------------------------
    // 11. flush includes pending tip
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_includes_pending_tip() {
        let cache = make_cache(10);
        let tip_hash = make_block_hash(0xAA);

        // Set tip via write_batch (needs a coin to trigger buffering path,
        // but tip is set regardless).
        let batch = StoreBatch {
            tip: Some(tip_hash),
            coin_puts: vec![(make_outpoint(0x60, 0), make_coin(1, 1))],
            ..Default::default()
        };
        cache.write_batch(batch).unwrap();

        // pending_tip is set, but inner store doesn't have it yet.
        // After flush, inner should have it, and get_tip reads through.
        cache.flush().unwrap();
        assert_eq!(cache.get_tip().unwrap(), tip_hash);
    }

    // ---------------------------------------------------------------
    // 12. flush includes pending non-coin batch data
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_includes_pending_batch() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xBB);
        let entry = make_test_entry(10);

        // Batch with coins + block_index — non-coins are buffered.
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x70, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        // Before flush: block_index is in overlay cache but check that
        // after flush it's persisted by clearing the overlay and re-reading.
        cache.flush().unwrap();
        cache.block_index_cache.lock().unwrap().clear();
        let recovered = cache.get_block_index(&bh).unwrap();
        assert_eq!(recovered.height, 10);
    }

    // ---------------------------------------------------------------
    // 13. Non-coin batch passes through immediately
    // ---------------------------------------------------------------
    #[test]
    fn test_no_coin_batch_passes_through() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xCC);
        let entry = make_test_entry(20);

        // Batch with block_index only (no coins).
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        // Should be in inner immediately — clear overlay and verify.
        cache.block_index_cache.lock().unwrap().clear();
        let recovered = cache.get_block_index(&bh).unwrap();
        assert_eq!(recovered.height, 20);
    }

    // ---------------------------------------------------------------
    // 14. Coin batch buffers non-coin data until flush
    // ---------------------------------------------------------------
    #[test]
    fn test_coin_batch_buffers_non_coins() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xDD);
        let entry = make_test_entry(30);

        // Batch with coins + block_index.
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x80, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        // Before flush: clear overlay — inner should NOT have it yet.
        cache.block_index_cache.lock().unwrap().clear();
        // The inner doesn't have the block_index entry yet because it was buffered.
        // get_block_index falls through to inner, which returns None.
        // But wait — CoinCache::get_block_index checks overlay first, then inner.
        // We cleared the overlay, so it should go to inner. Since the batch with
        // coins buffers non-coin ops, inner should not have it.
        assert!(cache.inner.get_block_index(&bh).is_none());

        cache.flush().unwrap();

        // After flush, inner should have it.
        let recovered = cache.inner.get_block_index(&bh).unwrap();
        assert_eq!(recovered.height, 30);
    }

    // ---------------------------------------------------------------
    // 15. Overlay block_index cache
    // ---------------------------------------------------------------
    #[test]
    fn test_overlay_block_index() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xE0);
        let entry = make_test_entry(40);

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        let recovered = cache.get_block_index(&bh).unwrap();
        assert_eq!(recovered.height, 40);
    }

    // ---------------------------------------------------------------
    // 16. Overlay height_hash cache
    // ---------------------------------------------------------------
    #[test]
    fn test_overlay_height_hash() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xE1);

        let mut batch = StoreBatch::default();
        batch.height_hash_puts.push((100, bh));
        cache.write_batch(batch).unwrap();

        assert_eq!(cache.get_block_hash_by_height(100).unwrap(), bh);
    }

    // ---------------------------------------------------------------
    // 17. Overlay undo cache
    // ---------------------------------------------------------------
    #[test]
    fn test_overlay_undo() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xE2);
        let undo = UndoData {
            spent_coins: vec![(
                OutPointSer {
                    txid: [0xAB; 32],
                    vout: 0,
                },
                make_coin(42, 1),
            )],
        };

        let mut batch = StoreBatch::default();
        batch.undo_puts.push((bh, undo));
        cache.write_batch(batch).unwrap();

        let recovered = cache.get_undo(&bh).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
        assert_eq!(recovered.spent_coins[0].1.amount, 42);
    }

    // ---------------------------------------------------------------
    // 18. Empty flush is a no-op (no error)
    // ---------------------------------------------------------------
    #[test]
    fn test_empty_flush_is_noop() {
        let cache = make_cache(10);
        // Flush with nothing dirty — should succeed without error.
        cache.flush().unwrap();
        assert_eq!(cache.dirty_count(), 0);
    }

    // ---------------------------------------------------------------
    // 19. clear_chainstate clears everything
    // ---------------------------------------------------------------
    #[test]
    fn test_clear_chainstate() {
        let cache = make_cache(10);
        let op = make_outpoint(0xF0, 0);

        // Add a coin, set tip, add block_index overlay.
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, make_coin(500, 1)));
        batch.tip = Some(make_block_hash(0xF1));
        batch.block_index_puts.push((make_block_hash(0xF2), make_test_entry(50)));
        batch.height_hash_puts.push((50, make_block_hash(0xF2)));
        cache.write_batch(batch).unwrap();

        assert!(cache.has_coin(&op));
        assert_eq!(cache.dirty_count(), 1);

        cache.clear_chainstate().unwrap();

        assert!(!cache.has_coin(&op));
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.count_delta.load(Ordering::Relaxed), 0);
        assert_eq!(cache.amount_delta.load(Ordering::Relaxed), 0);
        assert!(cache.get_tip().is_none());
        // Overlay caches are cleared.
        assert!(cache.block_index_cache.lock().unwrap().is_empty());
        assert!(cache.height_hash_cache.lock().unwrap().is_empty());
        assert!(cache.undo_cache.lock().unwrap().is_empty());
    }

    // ---------------------------------------------------------------
    // 20. default() uses 450 MB budget
    // ---------------------------------------------------------------
    #[test]
    fn test_default_uses_450mb() {
        let cache = CoinCache::default(Box::new(InMemoryStore::new()));
        // 450 MB budget: clean_cap = (450_000_000 * 80 / 100) / 200 = 1_800_000
        // flush_threshold = 1_800_000 / 4 = 450_000
        assert_eq!(cache.flush_threshold(), 450_000);
    }

    // ---------------------------------------------------------------
    // 21. Larger dbcache produces larger flush_threshold
    // ---------------------------------------------------------------
    #[test]
    fn test_dbcache_scales_caps() {
        let small = make_cache(100);
        let large = make_cache(1000);
        assert!(
            large.flush_threshold() > small.flush_threshold(),
            "large.flush_threshold ({}) should be > small.flush_threshold ({})",
            large.flush_threshold(),
            small.flush_threshold()
        );
    }

    // ---------------------------------------------------------------
    // 22. coin_count() = inner count + delta
    // ---------------------------------------------------------------
    #[test]
    fn test_coin_count_with_delta() {
        let inner = InMemoryStore::new();

        // Seed inner with 3 coins.
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((make_outpoint(0xA0, 0), make_coin(100, 1)));
        seed.coin_puts.push((make_outpoint(0xA1, 0), make_coin(200, 2)));
        seed.coin_puts.push((make_outpoint(0xA2, 0), make_coin(300, 3)));
        inner.write_batch(seed).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);
        assert_eq!(cache.coin_count(), 3);

        // Add one dirty coin.
        let mut b1 = StoreBatch::default();
        b1.coin_puts.push((make_outpoint(0xA3, 0), make_coin(400, 4)));
        cache.write_batch(b1).unwrap();
        assert_eq!(cache.coin_count(), 4);

        // Remove one coin.
        let mut b2 = StoreBatch::default();
        b2.coin_removes.push((make_outpoint(0xA0, 0), 100));
        cache.write_batch(b2).unwrap();
        assert_eq!(cache.coin_count(), 3);
    }

    // ---------------------------------------------------------------
    // 23. coin_total_amount() = inner total + delta
    // ---------------------------------------------------------------
    #[test]
    fn test_coin_total_amount_with_delta() {
        let inner = InMemoryStore::new();

        // Seed inner with total = 100 + 200 = 300.
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((make_outpoint(0xB0, 0), make_coin(100, 1)));
        seed.coin_puts.push((make_outpoint(0xB1, 0), make_coin(200, 2)));
        inner.write_batch(seed).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);
        assert_eq!(cache.coin_total_amount(), 300);

        // Add coin with amount 500.
        let mut b1 = StoreBatch::default();
        b1.coin_puts.push((make_outpoint(0xB2, 0), make_coin(500, 3)));
        cache.write_batch(b1).unwrap();
        assert_eq!(cache.coin_total_amount(), 800);

        // Remove coin with spent_amount 200.
        let mut b2 = StoreBatch::default();
        b2.coin_removes.push((make_outpoint(0xB1, 0), 200));
        cache.write_batch(b2).unwrap();
        assert_eq!(cache.coin_total_amount(), 600);
    }
}
