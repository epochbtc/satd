use bitcoin::{BlockHash, OutPoint, Txid};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Mutex, RwLock};

use super::blockindex::BlockIndexEntry;
use super::coinview::Coin;
use super::undo::UndoData;
use super::{Store, StoreBatch, StoreError};

/// Cache entry state.
enum CacheEntry {
    /// Coin exists (may or may not be dirty relative to redb).
    Present { coin: Coin, dirty: bool },
    /// Coin was spent (needs to be removed from redb on flush).
    Spent { dirty: bool },
}

/// In-memory UTXO cache wrapping a persistent Store.
///
/// Absorbs coin reads and writes in a HashMap. Non-coin operations
/// (block index, undo, height index) pass through to the inner store
/// immediately. Coin changes accumulate until `flush()` writes them
/// to the inner store in a single large batch.
///
/// This dramatically reduces redb write transactions during IBD —
/// instead of one per block, coins are flushed every N blocks.
pub struct CoinCache {
    inner: Box<dyn Store>,
    coins: RwLock<HashMap<OutPoint, CacheEntry>>,
    dirty_count: AtomicU32,
    /// Pending tip — only written to the inner store on flush.
    pending_tip: Mutex<Option<BlockHash>>,
    count_delta: AtomicI64,
    amount_delta: AtomicI64,
}

impl CoinCache {
    pub fn new(inner: Box<dyn Store>) -> Self {
        Self {
            inner,
            coins: RwLock::new(HashMap::new()),
            dirty_count: AtomicU32::new(0),
            pending_tip: Mutex::new(None),
            count_delta: AtomicI64::new(0),
            amount_delta: AtomicI64::new(0),
        }
    }

    /// Flush all dirty coin entries to the inner store in a single batch.
    /// Also writes the pending tip.
    pub fn flush(&self) -> Result<(), StoreError> {
        let mut cache = self.coins.write().unwrap();
        let mut batch = StoreBatch::default();

        for (outpoint, entry) in cache.iter_mut() {
            match entry {
                CacheEntry::Present { coin, dirty } if *dirty => {
                    batch.coin_puts.push((*outpoint, coin.clone()));
                    *dirty = false;
                }
                CacheEntry::Spent { dirty } if *dirty => {
                    batch.coin_removes.push(*outpoint);
                    *dirty = false;
                }
                _ => {}
            }
        }

        // Evict clean Spent entries to free memory
        cache.retain(|_, entry| !matches!(entry, CacheEntry::Spent { dirty: false }));

        // Write pending tip
        batch.tip = self.pending_tip.lock().unwrap().take();

        let puts = batch.coin_puts.len();
        let removes = batch.coin_removes.len();

        drop(cache);
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);

        if puts > 0 || removes > 0 || batch.tip.is_some() {
            tracing::info!(puts, removes, "Flushing UTXO cache to disk");
            self.inner.write_batch(batch)?;
        }

        Ok(())
    }

    /// Number of dirty entries pending flush.
    pub fn dirty_count(&self) -> u32 {
        self.dirty_count.load(Ordering::Relaxed)
    }
}

impl Store for CoinCache {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        // Check cache first
        {
            let cache = self.coins.read().unwrap();
            if let Some(entry) = cache.get(outpoint) {
                return match entry {
                    CacheEntry::Present { coin, .. } => Some(coin.clone()),
                    CacheEntry::Spent { .. } => None,
                };
            }
        }

        // Cache miss — read from inner store
        let coin = self.inner.get_coin(outpoint)?;

        // Populate cache (read-through)
        let mut cache = self.coins.write().unwrap();
        cache.entry(*outpoint).or_insert(CacheEntry::Present {
            coin: coin.clone(),
            dirty: false,
        });

        Some(coin)
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        // Check cache first
        {
            let cache = self.coins.read().unwrap();
            if let Some(entry) = cache.get(outpoint) {
                return matches!(entry, CacheEntry::Present { .. });
            }
        }
        self.inner.has_coin(outpoint)
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        // Absorb coin operations into cache
        let coin_dirty = batch.coin_puts.len() + batch.coin_removes.len();
        if coin_dirty > 0 {
            let mut cache = self.coins.write().unwrap();

            // Track deltas for puts
            for (outpoint, coin) in batch.coin_puts {
                self.amount_delta.fetch_add(coin.amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_add(1, Ordering::Relaxed);
                cache.insert(outpoint, CacheEntry::Present { coin, dirty: true });
            }

            // Track deltas for removes
            for outpoint in batch.coin_removes {
                // Look up the amount of the coin being spent
                let spent_amount = match cache.get(&outpoint) {
                    Some(CacheEntry::Present { coin, .. }) => coin.amount,
                    _ => {
                        // Not in cache, look up from inner store
                        self.inner.get_coin(&outpoint).map(|c| c.amount).unwrap_or(0)
                    }
                };
                self.amount_delta.fetch_sub(spent_amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_sub(1, Ordering::Relaxed);
                cache.insert(outpoint, CacheEntry::Spent { dirty: true });
            }

            self.dirty_count
                .fetch_add(coin_dirty as u32, Ordering::Relaxed);
        }

        // Stash tip for flush
        if batch.tip.is_some() {
            *self.pending_tip.lock().unwrap() = batch.tip;
        }

        // Forward non-coin operations to inner store immediately
        let pass_through = StoreBatch {
            block_index_puts: batch.block_index_puts,
            coin_puts: Vec::new(),
            coin_removes: Vec::new(),
            tip: None, // deferred to flush
            height_hash_puts: batch.height_hash_puts,
            height_hash_removes: batch.height_hash_removes,
            undo_puts: batch.undo_puts,
            tx_index_puts: batch.tx_index_puts,
            tx_index_removes: batch.tx_index_removes,
        };

        let has_data = !pass_through.block_index_puts.is_empty()
            || !pass_through.height_hash_puts.is_empty()
            || !pass_through.height_hash_removes.is_empty()
            || !pass_through.undo_puts.is_empty()
            || !pass_through.tx_index_puts.is_empty()
            || !pass_through.tx_index_removes.is_empty();

        if has_data {
            self.inner.write_batch(pass_through)?;
        }

        Ok(())
    }

    // All non-coin operations delegate directly to inner store

    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.inner.get_block_index(hash)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        // Return pending tip if available, otherwise inner store's tip
        if let Some(tip) = *self.pending_tip.lock().unwrap() {
            return Some(tip);
        }
        self.inner.get_tip()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.inner.get_block_hash_by_height(height)
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
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
        // Delegate to inner — the histogram is maintained in the inner store's metadata.
        // Cache-level deltas are small and short-lived, so this is accurate enough.
        self.inner.utxo_height_hist()
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.inner.get_tx_location(txid)
    }

    fn has_txindex(&self) -> bool {
        self.inner.has_txindex()
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.coins.write().unwrap().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock().unwrap() = None;
        self.inner.clear_chainstate()
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        self.coins.write().unwrap().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock().unwrap() = None;
        self.inner.clear_all()
    }
}
