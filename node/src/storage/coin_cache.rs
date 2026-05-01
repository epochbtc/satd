use bitcoin::{BlockHash, OutPoint, Txid};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use super::blockindex::{BlockIndexEntry, BlockStatus};
use super::coinview::Coin;
use super::undo::UndoData;
use super::{Store, StoreBatch, StoreError, WriteMode};

/// Default dbcache size in MB (matches Bitcoin Core).
const DEFAULT_DBCACHE_MB: u64 = 450;

/// Dirty coin entry — must be flushed to backing store before eviction.
enum DirtyEntry {
    /// Coin exists in backing store and was modified/added. `fresh` = true means
    /// the coin was created in this flush window (never written to backing store).
    Present { coin: Coin, fresh: bool },
    /// Coin was spent. Carries (amount, height) for counter/histogram updates.
    /// If `fresh` = true, the coin was created and spent in the same flush window
    /// and can be discarded without touching the backing store.
    Spent { amount: u64, height: u32, fresh: bool },
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
    // Perf counters (atomic, zero overhead)
    pub perf_dirty_hits: AtomicU64,
    pub perf_clean_hits: AtomicU64,
    pub perf_store_misses: AtomicU64,
    height_hash_cache: Mutex<LruCache<u32, BlockHash>>,
    undo_cache: Mutex<LruCache<BlockHash, UndoData>>,
    tx_index_cache: Mutex<LruCache<Txid, BlockHash>>,
    /// Dirty coin flush threshold (~25% of clean coin cap). Atomic so that
    /// `resize_clean()` can update it live — otherwise the node would keep
    /// accumulating dirty entries up to the original high-water mark after
    /// an adaptive-cache shrink, defeating the point of the shrink.
    flush_threshold: AtomicU32,
    /// Current write-durability mode. 0 = Normal (WAL enabled), 1 = BulkLoad
    /// (WAL disabled — only safe during IBD where loss on crash can be
    /// replayed from the flat-file block store). Set via `set_write_mode`.
    write_mode: AtomicU8,
    /// Number of times `flush()` has successfully drained the dirty set.
    /// Used by tests to assert the periodic-flush policy in reindex and
    /// the normal connect loop actually fires — without this counter a
    /// regression that stops flushing would be silent until memory
    /// exhaustion.
    pub flush_count: AtomicU64,
}

fn decode_write_mode(v: u8) -> WriteMode {
    if v == 1 {
        WriteMode::BulkLoad
    } else {
        WriteMode::Normal
    }
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
            flush_threshold: AtomicU32::new(flush_threshold),
            perf_dirty_hits: AtomicU64::new(0),
            perf_clean_hits: AtomicU64::new(0),
            perf_store_misses: AtomicU64::new(0),
            write_mode: AtomicU8::new(0),
            flush_count: AtomicU64::new(0),
        }
    }

    /// Switch the underlying-store write mode for subsequent writes and
    /// flushes. Use `BulkLoad` during IBD (when crash-recovery replay is
    /// cheap relative to WAL overhead); `Normal` otherwise.
    pub fn set_write_mode(&self, mode: WriteMode) {
        let v = match mode {
            WriteMode::Normal => 0,
            WriteMode::BulkLoad => 1,
        };
        self.write_mode.store(v, Ordering::Relaxed);
    }

    fn current_write_mode(&self) -> WriteMode {
        decode_write_mode(self.write_mode.load(Ordering::Relaxed))
    }

    /// Create a CoinCache with the default 450 MB budget (for tests).
    pub fn default(inner: Box<dyn Store>) -> Self {
        Self::new(inner, DEFAULT_DBCACHE_MB)
    }

    /// Flush dirty coins to the backing store.
    ///
    /// Optimizations:
    /// - **FRESH elision**: coins created and spent in the same flush window never
    ///   touch the backing store (Core PR #17487 insight).
    /// - **Move semantics**: flushed coins are moved (not cloned) to the clean LRU,
    ///   avoiding the allocation burst that caused glibc malloc fragmentation.
    pub fn flush(&self) -> Result<(), StoreError> {
        let mut dirty = self.dirty.write().unwrap();
        let mut batch = {
            let mut pending = self.pending_batch.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        // Pre-allocate batch vectors based on dirty map size
        batch.coin_puts.reserve(dirty.len());

        let mut fresh_elided = 0u64;
        // Drain dirty map: build batch and collect surviving coins for LRU promotion
        let mut promote: Vec<(OutPoint, Coin)> = Vec::with_capacity(dirty.len());

        for (outpoint, entry) in dirty.drain() {
            match entry {
                DirtyEntry::Present { coin, .. } => {
                    // Serialize for RocksDB batch (needs owned Coin)
                    batch.coin_puts.push((outpoint, coin.clone()));
                    // Move (not clone) into promote list for LRU insertion
                    promote.push((outpoint, coin));
                }
                DirtyEntry::Spent { fresh: true, .. } => {
                    fresh_elided += 1;
                }
                DirtyEntry::Spent { amount, height, .. } => {
                    batch.coin_removes.push((outpoint, amount, height));
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
            let mode = self.current_write_mode();
            tracing::info!(
                coin_puts = puts,
                coin_removes = removes,
                fresh_elided = fresh_elided,
                block_index = index_puts,
                undo = undo_puts,
                ?mode,
                "Flushing write cache to disk"
            );
            self.inner.write_batch_mode(batch, mode)?;
        }

        // Move flushed coins to clean LRU (cache warming)
        if !promote.is_empty() {
            let mut clean = self.clean.lock().unwrap();
            for (outpoint, coin) in promote {
                clean.put(outpoint, coin);
            }
        }

        self.flush_count.fetch_add(1, Ordering::Relaxed);
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
    /// This is ~25% of the clean coin LRU cap — and tracks it live across
    /// `resize_clean` calls.
    pub fn flush_threshold(&self) -> u32 {
        self.flush_threshold.load(Ordering::Relaxed)
    }

    /// Resize the clean-coins LRU capacity. Used by adaptive cache sizing.
    ///
    /// `new_cap` is clamped to a minimum of 1 (NonZeroUsize constraint of the
    /// underlying LRU). Shrinking evicts the coldest entries to fit; growing
    /// is O(1) rehash. Dirty coins are unaffected — those live in a separate
    /// HashMap until flushed.
    ///
    /// Updates the derived dirty-flush threshold (25% of the new clean cap)
    /// so subsequent dirty accumulation stays within the new budget.
    pub fn resize_clean(&self, new_cap: usize) {
        let cap = std::num::NonZeroUsize::new(new_cap.max(1)).unwrap();
        let mut clean = self.clean.lock().unwrap();
        if clean.cap() != cap {
            clean.resize(cap);
        }
        // Track the new threshold on the same shrink so dirty accumulation
        // honors the new clean cap. Never below 1 to keep `flush` reachable.
        let new_threshold = ((new_cap / 4) as u32).max(1);
        self.flush_threshold.store(new_threshold, Ordering::Relaxed);
    }

    /// Current clean-LRU capacity (entry count).
    pub fn clean_cap(&self) -> usize {
        self.clean.lock().unwrap().cap().get()
    }
}

impl Store for CoinCache {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        // 1. Check dirty map
        {
            let dirty = self.dirty.read().unwrap();
            if let Some(entry) = dirty.get(outpoint) {
                return match entry {
                    DirtyEntry::Present { coin, .. } => Some(coin.clone()),
                    DirtyEntry::Spent { .. } => None,
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
                return matches!(entry, DirtyEntry::Present { .. });
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
                // Mark as fresh if this coin doesn't exist in the backing store
                // (not already in dirty map as a non-fresh entry)
                let fresh = !dirty.contains_key(&outpoint);
                dirty.insert(outpoint, DirtyEntry::Present { coin, fresh });
            }

            for (outpoint, spent_amount, spent_height) in batch.coin_removes {
                self.amount_delta.fetch_sub(spent_amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_sub(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                // If the coin was fresh (created in this flush window), mark the
                // spend as fresh too — it can be elided entirely during flush.
                let was_fresh = dirty
                    .get(&outpoint)
                    .is_some_and(|e| matches!(e, DirtyEntry::Present { fresh: true, .. }));
                dirty.insert(outpoint, DirtyEntry::Spent {
                    amount: spent_amount,
                    height: spent_height,
                    fresh: was_fresh,
                });
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
                // Don't downgrade: if cache has DataStored/Valid, don't overwrite with HeaderOnly.
                // This prevents a race where accept_headers' batch write clobbers a concurrent
                // store_block's DataStored update, causing has_block_data() to return false
                // and permanently stalling the connect loop.
                let dominated = if let Some(existing) = bi.peek(hash) {
                    entry.status == BlockStatus::HeaderOnly
                        && matches!(existing.status, BlockStatus::DataStored | BlockStatus::Valid)
                } else {
                    false
                };
                if !dominated {
                    bi.put(*hash, entry.clone());
                }
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
            || !batch.tx_index_removes.is_empty()
            || !batch.addr_funding_puts.is_empty()
            || !batch.addr_spending_puts.is_empty()
            || !batch.addr_funding_removes.is_empty()
            || !batch.addr_spending_removes.is_empty()
            || !batch.addr_backfill_temp_puts.is_empty()
            || batch.backfill_cursor_advance.is_some();

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
                    addr_funding_puts: batch.addr_funding_puts,
                    addr_spending_puts: batch.addr_spending_puts,
                    addr_funding_removes: batch.addr_funding_removes,
                    addr_spending_removes: batch.addr_spending_removes,
                    addr_backfill_temp_puts: batch.addr_backfill_temp_puts,
                    backfill_cursor_advance: batch.backfill_cursor_advance,
                };
                self.inner.write_batch_mode(pass_through, self.current_write_mode())?;
            } else {
                let mut pending = self.pending_batch.lock().unwrap();
                pending.block_index_puts.extend(batch.block_index_puts);
                pending.height_hash_puts.extend(batch.height_hash_puts);
                pending.height_hash_removes.extend(batch.height_hash_removes);
                pending.undo_puts.extend(batch.undo_puts);
                pending.tx_index_puts.extend(batch.tx_index_puts);
                pending.tx_index_removes.extend(batch.tx_index_removes);
                // Address-index puts and removes need last-writer-wins
                // dedup by key (so connect→disconnect→connect or
                // disconnect→connect sequences before flush land on the
                // correct final state). Build a small StoreBatch carrying
                // only the addr-* fields and route it through `merge`
                // — the rest of `batch` was already extended above.
                let addr_only = StoreBatch {
                    addr_funding_puts: batch.addr_funding_puts,
                    addr_spending_puts: batch.addr_spending_puts,
                    addr_funding_removes: batch.addr_funding_removes,
                    addr_spending_removes: batch.addr_spending_removes,
                    addr_backfill_temp_puts: batch.addr_backfill_temp_puts,
                    backfill_cursor_advance: batch.backfill_cursor_advance,
                    ..Default::default()
                };
                pending.merge(addr_only);
            }
        }

        Ok(())
    }

    fn flush_durable(&self) -> Result<(), StoreError> {
        // First drain the cache's dirty map to the inner store, then ask the
        // inner store to flush its memtables to SST files. After this returns,
        // the on-disk state includes every write observed so far even with
        // the WAL disabled (BulkLoad mode).
        self.flush()?;
        self.inner.flush_durable()
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

    fn get_coins_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        if outpoints.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<Option<Coin>> = vec![None; outpoints.len()];
        let mut misses: Vec<(usize, OutPoint)> = Vec::new();

        // 1. Check dirty map (single lock acquisition for all keys)
        {
            let dirty = self.dirty.read().unwrap();
            let mut clean = self.clean.lock().unwrap();
            for (i, outpoint) in outpoints.iter().enumerate() {
                if let Some(entry) = dirty.get(outpoint) {
                    self.perf_dirty_hits.fetch_add(1, Ordering::Relaxed);
                    results[i] = match entry {
                        DirtyEntry::Present { coin, .. } => Some(coin.clone()),
                        DirtyEntry::Spent { .. } => None,
                    };
                } else if let Some(coin) = clean.get(outpoint) {
                    self.perf_clean_hits.fetch_add(1, Ordering::Relaxed);
                    results[i] = Some(coin.clone());
                } else {
                    misses.push((i, *outpoint));
                }
            }
        }

        // 2. Batch fetch misses from backing store
        if !misses.is_empty() {
            self.perf_store_misses.fetch_add(misses.len() as u64, Ordering::Relaxed);
            let miss_outpoints: Vec<OutPoint> = misses.iter().map(|(_, op)| *op).collect();
            let fetched = self.inner.get_coins_batch(&miss_outpoints);
            let mut clean = self.clean.lock().unwrap();
            for ((idx, outpoint), coin_opt) in misses.into_iter().zip(fetched) {
                if let Some(coin) = &coin_opt {
                    clean.put(outpoint, coin.clone());
                }
                results[idx] = coin_opt;
            }
        }

        results
    }

    fn resize_block_cache(&self, bytes: usize) {
        self.inner.resize_block_cache(bytes);
    }

    fn block_cache_capacity_bytes(&self) -> usize {
        self.inner.block_cache_capacity_bytes()
    }

    fn iter_addr_funding(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrFundingKey, u64)> {
        // Reads see committed-to-inner-store rows merged with the
        // pending (not-yet-flushed) write batch. Without this merge,
        // queries between a connect_block and the next flush would
        // miss the latest blocks' rows — the address index is
        // chainstate-bound, not flush-bound.
        //
        // RocksDB applies puts-then-removes per CF in
        // `write_batch_mode`, so if a key has both a pending put and a
        // pending remove (e.g. connect-then-disconnect before flush),
        // the on-disk outcome is "removed". We mirror that here so the
        // pre-flush read view matches the post-flush state.
        let pending = self.pending_batch.lock().unwrap();
        let pending_removes: std::collections::HashSet<crate::index::address::AddrFundingKey> =
            pending
                .addr_funding_removes
                .iter()
                .filter(|k| &k.scripthash == sh)
                .cloned()
                .collect();
        let pending_puts: Vec<(crate::index::address::AddrFundingKey, u64)> = pending
            .addr_funding_puts
            .iter()
            .filter(|r| &r.scripthash == sh)
            .filter_map(|r| {
                let k = r.key();
                if pending_removes.contains(&k) {
                    None
                } else {
                    Some((k, r.amount_sat))
                }
            })
            .collect();
        drop(pending);

        let inner_rows = self.inner.iter_addr_funding(sh);
        // Dedupe by key with pending taking precedence over inner.
        // Without this, an inner row that also has a matching pending
        // put (e.g. a write that bypassed the pending-batch path via
        // the no-coin pass-through, while a coincident pending entry
        // is still buffered) would surface twice in the merged result.
        // Backfill is the first writer that goes through the no-coin
        // pass-through alongside a non-empty pending_batch.
        let pending_keys: std::collections::HashSet<crate::index::address::AddrFundingKey> =
            pending_puts.iter().map(|(k, _)| k.clone()).collect();
        let mut all: Vec<(crate::index::address::AddrFundingKey, u64)> = inner_rows
            .into_iter()
            .filter(|(k, _)| !pending_removes.contains(k) && !pending_keys.contains(k))
            .chain(pending_puts)
            .collect();
        all.sort_by(|(a, _), (b, _)| {
            crate::index::address::encode_funding_key(a)
                .cmp(&crate::index::address::encode_funding_key(b))
        });
        all
    }

    fn iter_addr_spending(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrSpendingKey, OutPoint)> {
        // See iter_addr_funding for the put/remove netting rationale.
        let pending = self.pending_batch.lock().unwrap();
        let pending_removes: std::collections::HashSet<crate::index::address::AddrSpendingKey> =
            pending
                .addr_spending_removes
                .iter()
                .filter(|k| &k.scripthash == sh)
                .cloned()
                .collect();
        let pending_puts: Vec<(crate::index::address::AddrSpendingKey, OutPoint)> = pending
            .addr_spending_puts
            .iter()
            .filter(|r| &r.scripthash == sh)
            .filter_map(|r| {
                let k = r.key();
                if pending_removes.contains(&k) {
                    None
                } else {
                    Some((k, r.prev_outpoint))
                }
            })
            .collect();
        drop(pending);

        let inner_rows = self.inner.iter_addr_spending(sh);
        // Dedupe by key with pending taking precedence over inner.
        // See `iter_addr_funding` for the rationale.
        let pending_keys: std::collections::HashSet<crate::index::address::AddrSpendingKey> =
            pending_puts.iter().map(|(k, _)| k.clone()).collect();
        let mut all: Vec<(crate::index::address::AddrSpendingKey, OutPoint)> = inner_rows
            .into_iter()
            .filter(|(k, _)| !pending_removes.contains(k) && !pending_keys.contains(k))
            .chain(pending_puts)
            .collect();
        all.sort_by(|(a, _), (b, _)| {
            crate::index::address::encode_spending_key(a)
                .cmp(&crate::index::address::encode_spending_key(b))
        });
        all
    }

    fn create_backfill_temp_cf(&self) -> Result<(), StoreError> {
        self.inner.create_backfill_temp_cf()
    }

    fn drop_backfill_temp_cf(&self) -> Result<(), StoreError> {
        self.inner.drop_backfill_temp_cf()
    }

    fn backfill_temp_cf_exists(&self) -> bool {
        self.inner.backfill_temp_cf_exists()
    }

    fn lookup_backfill_temp(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<crate::index::address::Scripthash>, StoreError> {
        self.inner.lookup_backfill_temp(outpoint)
    }

    fn read_backfill_cursor(&self) -> crate::index::address::cursor::BackfillCursor {
        self.inner.read_backfill_cursor()
    }

    fn read_backfill_last_error(&self) -> Option<String> {
        self.inner.read_backfill_last_error()
    }

    fn write_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        self.inner.write_backfill_last_error(msg)
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
        b2.coin_removes.push((op, 100, 0));
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
        b2.coin_removes.push((op, 50, 0));
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
        b2.coin_removes.push((make_outpoint(0x20, 0), 1000, 0));
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
        batch.coin_removes.push((make_outpoint(0x42, 0), 300, 0));
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
    // 22. resize_clean updates BOTH the LRU cap AND the flush threshold
    // ---------------------------------------------------------------
    #[test]
    fn test_resize_clean_updates_flush_threshold() {
        let cache = CoinCache::default(Box::new(InMemoryStore::new()));
        let initial_threshold = cache.flush_threshold();
        assert!(initial_threshold > 0);

        // Shrink to 100_000 entries: new threshold should be 25_000.
        cache.resize_clean(100_000);
        assert_eq!(cache.clean_cap(), 100_000);
        assert_eq!(
            cache.flush_threshold(),
            25_000,
            "threshold should shrink with clean LRU"
        );

        // Grow back: threshold tracks the new cap.
        cache.resize_clean(2_000_000);
        assert_eq!(cache.flush_threshold(), 500_000);

        // Shrink to 0 clamps to minimum 1 (never lose reachability of flush).
        cache.resize_clean(0);
        assert_eq!(cache.flush_threshold(), 1);
        assert_eq!(cache.clean_cap(), 1);
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
        b2.coin_removes.push((make_outpoint(0xA0, 0), 100, 0));
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
        b2.coin_removes.push((make_outpoint(0xB1, 0), 200, 0));
        cache.write_batch(b2).unwrap();
        assert_eq!(cache.coin_total_amount(), 600);
    }

    // ---------------------------------------------------------------
    // Regression: flush must complete under concurrent read pressure
    // ---------------------------------------------------------------
    //
    // Before the fix, flush() reacquired dirty.write() for shrink_to_fit()
    // after dropping the initial write lock. With multiple threads
    // continuously holding dirty.read() via get_coins_batch(), the
    // writer was starved indefinitely on reader-preferring RwLock
    // implementations (Linux pthreads default).
    //
    // This test spawns reader threads that hammer get_coin() and
    // get_coins_batch() while the main thread flushes. The flush must
    // complete within a reasonable timeout — if it deadlocks/starves,
    // the test fails.
    #[test]
    fn test_flush_completes_under_concurrent_read_pressure() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering as AOrdering}};
        use std::time::{Duration, Instant};

        let cache = Arc::new(make_cache(450));

        // Populate dirty map with enough coins to make flush non-trivial
        let num_coins = 10_000;
        let mut batch = StoreBatch::default();
        for i in 0..num_coins {
            let op = make_outpoint((i % 256) as u8, i as u32);
            batch.coin_puts.push((op, make_coin(1000 + i as u64, 1)));
        }
        cache.write_batch(batch).unwrap();

        // Also populate some coins in the backing store so get_coin has
        // work to do (read-through path)
        {
            let inner_batch = StoreBatch {
                coin_puts: (0..1000u32)
                    .map(|i| (make_outpoint(0xFF, i), make_coin(500, 0)))
                    .collect(),
                ..StoreBatch::default()
            };
            cache.inner.write_batch(inner_batch).unwrap();
        }

        let stop = Arc::new(AtomicBool::new(false));

        // Spawn reader threads that continuously take dirty.read() via
        // get_coin() and get_coins_batch() — this is the exact access
        // pattern that caused write starvation in the old code.
        let num_readers = 8;
        let readers: Vec<_> = (0..num_readers)
            .map(|t| {
                let cache = Arc::clone(&cache);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut i = 0u32;
                    while !stop.load(AOrdering::Relaxed) {
                        // Alternate between single get_coin and batch lookups
                        if i.is_multiple_of(3) {
                            let ops: Vec<_> = (0..100)
                                .map(|j| make_outpoint((t * 31 + j) as u8, j))
                                .collect();
                            let _ = cache.get_coins_batch(&ops);
                        } else {
                            let op = make_outpoint((t * 31 + i % 256) as u8, i);
                            let _ = cache.get_coin(&op);
                        }
                        i = i.wrapping_add(1);
                    }
                })
            })
            .collect();

        // Give readers time to saturate the read lock
        std::thread::sleep(Duration::from_millis(50));

        // Flush must complete promptly despite continuous read pressure.
        // The old code would deadlock here trying to reacquire dirty.write()
        // for shrink_to_fit() while readers hold dirty.read().
        let start = Instant::now();
        cache.flush().expect("flush should succeed");
        let flush_duration = start.elapsed();

        // Signal readers to stop
        stop.store(true, AOrdering::Relaxed);
        for handle in readers {
            handle.join().unwrap();
        }

        // Flush should complete in well under 5 seconds.
        // In practice it takes <100ms. A deadlock would hang forever.
        assert!(
            flush_duration < Duration::from_secs(5),
            "flush took {:?} — possible write starvation",
            flush_duration,
        );

        // Verify flush actually worked: dirty map should be empty
        assert_eq!(cache.dirty_count(), 0);

        // Coins should be accessible via clean LRU after flush
        let op = make_outpoint(0, 0);
        assert!(cache.get_coin(&op).is_some());
    }

    // ---------------------------------------------------------------
    // Write-mode toggle propagates to inner store and is round-trippable.
    // Regression: IBD uses BulkLoad (WAL disabled) during sync and must
    // restore Normal on exit. Since CoinCache mediates the mode via an
    // AtomicU8, this test pins that round-trip.
    // ---------------------------------------------------------------
    #[test]
    fn test_write_mode_round_trip() {
        let cache = make_cache(16);

        // Default is Normal
        assert_eq!(cache.current_write_mode(), WriteMode::Normal);

        // Flip to BulkLoad, confirm visible
        cache.set_write_mode(WriteMode::BulkLoad);
        assert_eq!(cache.current_write_mode(), WriteMode::BulkLoad);

        // Writes succeed in BulkLoad mode (InMemoryStore ignores mode,
        // but this exercises the write_batch_mode path without error)
        let op = make_outpoint(9, 0);
        let coin = make_coin(1_000, 1);
        let batch = StoreBatch {
            coin_puts: vec![(op, coin)],
            ..Default::default()
        };
        cache.write_batch(batch).unwrap();

        // Restore Normal, confirm visible
        cache.set_write_mode(WriteMode::Normal);
        assert_eq!(cache.current_write_mode(), WriteMode::Normal);
    }

    // ---------------------------------------------------------------
    // flush_durable is idempotent and safe to call with no dirty data.
    // Regression: IBD calls flush_durable on completion and every 1000
    // blocks. Must not error on an empty cache.
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_durable_empty_is_ok() {
        let cache = make_cache(16);
        cache.flush_durable().expect("empty flush_durable must succeed");
        cache.flush_durable().expect("repeated flush_durable must succeed");
    }

    // ---------------------------------------------------------------
    // Pending put + remove for the same address row must net to
    // "removed" on read, matching the puts-then-removes order used
    // when the batch eventually flushes to RocksDB. Otherwise
    // connect+disconnect of an address-touching block before flush
    // would leak stale rows to confirmed_history / status hashes.
    // ---------------------------------------------------------------
    #[test]
    fn test_pending_addr_funding_put_then_remove_nets_to_empty() {
        use crate::index::address::{AddrFundingRow, scripthash_of};

        let cache = make_cache(16);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x99; 32]),
        );

        // Connect-side: stage a funding row in the pending batch.
        let mut connect = StoreBatch::default();
        connect.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid,
            vout: 0,
            amount_sat: 1_000,
        });
        cache.write_batch(connect).unwrap();

        assert_eq!(
            cache.iter_addr_funding(&sh).len(),
            1,
            "pending put must be visible before disconnect"
        );

        // Disconnect-side: stage the matching remove in the same
        // pending batch (no flush in between).
        let mut disconnect = StoreBatch::default();
        disconnect.addr_funding_removes.push(
            crate::index::address::AddrFundingKey { scripthash: sh, height: 1, txid, vout: 0 },
        );
        cache.write_batch(disconnect).unwrap();

        assert!(
            cache.iter_addr_funding(&sh).is_empty(),
            "pending put + pending remove for same key must net to empty"
        );

        // After flush the on-disk state must agree.
        cache.flush_durable().unwrap();
        assert!(
            cache.iter_addr_funding(&sh).is_empty(),
            "post-flush funding rows must remain empty"
        );
    }

    #[test]
    fn test_pending_addr_funding_remove_then_put_keeps_row() {
        // Disconnect-then-reconnect of a block (e.g. an A→B→A reorg
        // before flush) should leave the row present. The previous
        // implementation's per-key netting only handled the
        // put-then-remove direction; remove-then-put would have
        // dropped the new put.
        use crate::index::address::{AddrFundingRow, scripthash_of};

        let cache = make_cache(16);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x55; 32]),
        );

        // Stage a remove for the row first (e.g. disconnecting block A).
        let mut disconnect = StoreBatch::default();
        disconnect.addr_funding_removes.push(
            crate::index::address::AddrFundingKey { scripthash: sh, height: 1, txid, vout: 0 },
        );
        cache.write_batch(disconnect).unwrap();

        // Now stage a put for the same key (reconnecting the same block
        // or an alternate block at the same height that reuses the row).
        let mut reconnect = StoreBatch::default();
        reconnect.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid,
            vout: 0,
            amount_sat: 7_777,
        });
        cache.write_batch(reconnect).unwrap();

        let rows = cache.iter_addr_funding(&sh);
        assert_eq!(rows.len(), 1, "remove-then-put must leave the row present");
        assert_eq!(rows[0].1, 7_777);

        // Survives the flush.
        cache.flush_durable().unwrap();
        let after = cache.iter_addr_funding(&sh);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].1, 7_777);
    }

    #[test]
    fn test_pending_addr_spending_remove_then_put_keeps_row() {
        use crate::index::address::{AddrSpendingRow, scripthash_of};

        let cache = make_cache(16);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x66; 32]),
        );
        let prev = make_outpoint(0xdd, 1);

        let mut disconnect = StoreBatch::default();
        disconnect.addr_spending_removes.push(
            crate::index::address::AddrSpendingKey {
                scripthash: sh,
                height: 1,
                txid,
                vin: 0,
            },
        );
        cache.write_batch(disconnect).unwrap();

        let mut reconnect = StoreBatch::default();
        reconnect.addr_spending_puts.push(AddrSpendingRow {
            scripthash: sh,
            height: 1,
            txid,
            vin: 0,
            prev_outpoint: prev,
        });
        cache.write_batch(reconnect).unwrap();

        let rows = cache.iter_addr_spending(&sh);
        assert_eq!(rows.len(), 1, "remove-then-put must leave the row present");

        cache.flush_durable().unwrap();
        let after = cache.iter_addr_spending(&sh);
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn test_pending_addr_spending_put_then_remove_nets_to_empty() {
        use crate::index::address::{AddrSpendingRow, scripthash_of};

        let cache = make_cache(16);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let spending_txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x77; 32]),
        );
        let prev = make_outpoint(0xaa, 0);

        let mut connect = StoreBatch::default();
        connect.addr_spending_puts.push(AddrSpendingRow {
            scripthash: sh,
            height: 1,
            txid: spending_txid,
            vin: 0,
            prev_outpoint: prev,
        });
        cache.write_batch(connect).unwrap();
        assert_eq!(cache.iter_addr_spending(&sh).len(), 1);

        let mut disconnect = StoreBatch::default();
        disconnect.addr_spending_removes.push(
            crate::index::address::AddrSpendingKey {
                scripthash: sh,
                height: 1,
                txid: spending_txid,
                vin: 0,
            },
        );
        cache.write_batch(disconnect).unwrap();

        assert!(
            cache.iter_addr_spending(&sh).is_empty(),
            "pending spending put + remove for same key must net to empty"
        );

        cache.flush_durable().unwrap();
        assert!(cache.iter_addr_spending(&sh).is_empty());
    }
}
