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

/// Dirty coin entry — must be flushed to redb before eviction.
enum DirtyEntry {
    Present(Coin),
    Spent(u64),
}

/// In-memory write cache wrapping a persistent Store.
///
/// Two-tier coin cache:
/// - **Dirty map**: unbounded HashMap, flushed periodically to redb.
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

        // 3. Cache miss — read from redb, populate LRU (auto-evicts if full)
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
        // - Without coins (store_block, accept_headers): write to redb immediately
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
