use bitcoin::{BlockHash, OutPoint, Txid};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, AtomicU64, Ordering};

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
    Spent {
        amount: u64,
        height: u32,
        fresh: bool,
    },
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
    /// Read-through cache for cumulative tx counts written by the current
    /// connect run but not yet flushed to the inner store, so
    /// `getchaintxstats` sees the tip's count immediately after a block
    /// connects. Falls back to the inner store on miss.
    chain_tx_cache: Mutex<LruCache<BlockHash, u64>>,
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
    /// Serializes cache flushes against a reorg's multi-step cache mutation
    /// (issue #262 follow-up). A reorg applies disconnect + reconnect +
    /// triggering connect to the cache only, then commits with a flush or
    /// discards on failure; the in-memory discard cannot undo an on-disk
    /// write. Block connection runs on one thread, but `flush()` /
    /// `flush_durable()` are also reachable from other threads
    /// (`gettxoutsetinfo`, `dumptxoutset`, the block-filter backfill
    /// runner). The reorg holds this lock for its window (via
    /// `FlushExclusion`) so no such external flush can persist a
    /// partially-applied reorg. The reorg's own checkpoint flush goes
    /// through the held handle (`flush_inner`) and never re-acquires, so
    /// the lock is non-reentrant by construction.
    flush_guard: Mutex<()>,
}

/// RAII flush-exclusion held by a reorg for the duration of its cache
/// mutation. While alive, external `CoinCache::flush` / `flush_durable`
/// calls block. The holder flushes via [`FlushExclusion::flush`], which
/// does NOT re-acquire the guard (avoiding self-deadlock).
///
/// Crate-internal: this is a reorg-coordination primitive, not part of the
/// public API. Exposing the ability to freeze all cache flushes to library
/// consumers would be a footgun.
pub(crate) struct FlushExclusion<'a> {
    cache: &'a CoinCache,
    _guard: parking_lot::MutexGuard<'a, ()>,
}

impl FlushExclusion<'_> {
    /// Flush while already holding the exclusion lock — used for the
    /// reorg's own pre-reorg checkpoint flush. Equivalent to `flush()`
    /// minus the guard acquisition.
    pub(crate) fn flush(&self) -> Result<(), StoreError> {
        self.cache.flush_inner()
    }
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
        let chain_tx_cap = 8_192; // fixed — only the unflushed-block window
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
            chain_tx_cache: Mutex::new(lru(chain_tx_cap)),
            flush_threshold: AtomicU32::new(flush_threshold),
            perf_dirty_hits: AtomicU64::new(0),
            perf_clean_hits: AtomicU64::new(0),
            perf_store_misses: AtomicU64::new(0),
            write_mode: AtomicU8::new(0),
            flush_count: AtomicU64::new(0),
            flush_guard: Mutex::new(()),
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

    /// Test-only direct access to the wrapped backing store. Lets tests
    /// simulate the historical block-index corruption (a HeaderOnly
    /// write reaching the inner store without going through the cache
    /// dominance filter) so the repair pass has something to repair.
    /// Never use outside `#[cfg(test)]` — bypassing the cache means
    /// none of its invariants hold.
    #[cfg(test)]
    pub fn inner_for_test(&self) -> &dyn Store {
        &*self.inner
    }

    /// Test-only: drop a single hash from the block-index LRU. After
    /// corrupting the inner store directly, the cache may still serve a
    /// stale (correct) entry from the LRU — invalidating it forces the
    /// next read to fall through to the (now-corrupted) inner store,
    /// matching what a real post-restart cache would do.
    #[cfg(test)]
    pub fn invalidate_block_index_cache(&self, hash: &BlockHash) {
        self.block_index_cache.lock().pop(hash);
    }

    /// Flush dirty coins to the backing store.
    ///
    /// Acquires the flush-exclusion lock so a concurrent reorg (which holds
    /// it via [`CoinCache::lock_flush_exclusion`]) cannot have this
    /// thread persist a partially-applied reorg. See `flush_guard`.
    pub fn flush(&self) -> Result<(), StoreError> {
        let _g = self.flush_guard.lock();
        self.flush_inner()
    }

    /// Acquire the flush-exclusion lock for the duration of a reorg's
    /// multi-step cache mutation. Hold the returned guard from the
    /// pre-reorg checkpoint flush until the cache holds a *consistent*
    /// full-reorg delta (i.e. through the triggering block's commit) or
    /// until the reorg is discarded — whichever comes first. While held,
    /// external `flush` / `flush_durable` block. Flush the checkpoint via
    /// `FlushExclusion::flush` (no re-acquire). See `flush_guard`.
    ///
    /// Crate-internal: only the reorg path in `chain::state` may hold this.
    pub(crate) fn lock_flush_exclusion(&self) -> FlushExclusion<'_> {
        FlushExclusion {
            cache: self,
            _guard: self.flush_guard.lock(),
        }
    }

    /// Flush dirty coins to the backing store. Caller must hold the
    /// flush-exclusion lock (via `flush` or `FlushExclusion`).
    ///
    /// Optimizations:
    /// - **FRESH elision**: coins created and spent in the same flush window never
    ///   touch the backing store (Core PR #17487 insight).
    /// - **Move semantics**: flushed coins are moved (not cloned) to the clean LRU,
    ///   avoiding the allocation burst that caused glibc malloc fragmentation.
    fn flush_inner(&self) -> Result<(), StoreError> {
        let mut dirty = self.dirty.write();
        let mut batch = {
            let mut pending = self.pending_batch.lock();
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

        batch.tip = self.pending_tip.lock().take();

        let puts = batch.coin_puts.len();
        let removes = batch.coin_removes.len();
        let index_puts = batch.block_index_puts.len();
        let undo_puts = batch.undo_puts.len();

        drop(dirty);
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);

        #[cfg(feature = "block-filter-index")]
        let has_filter_rows = !batch.filter_puts.is_empty()
            || !batch.filter_header_puts.is_empty()
            || !batch.filter_removes.is_empty();
        #[cfg(not(feature = "block-filter-index"))]
        let has_filter_rows = false;
        let has_data = puts > 0
            || removes > 0
            || batch.tip.is_some()
            || !batch.block_index_puts.is_empty()
            || !batch.height_hash_puts.is_empty()
            || !batch.undo_puts.is_empty()
            || !batch.tx_index_puts.is_empty()
            || !batch.chain_tx_puts.is_empty()
            || has_filter_rows;

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
            let mut clean = self.clean.lock();
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
        self.dirty_count.load(Ordering::Relaxed) as usize + self.clean.lock().len()
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
        let mut clean = self.clean.lock();
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
        self.clean.lock().cap().get()
    }

    /// Discard every uncommitted (un-flushed) cache mutation, returning the
    /// cache to exactly the last-flushed on-disk state held by the inner
    /// store. Does NOT touch the inner store.
    ///
    /// This is the rollback primitive for the atomic-reorg path (issue
    /// #262). The reorg driver flushes the pre-reorg active chain to the
    /// inner store first, then applies the whole reorg (disconnect +
    /// reconnect + triggering connect) to this cache *only*. On any failure
    /// it calls this to drop the partial reorg wholesale — no block-body
    /// replay, and it cannot itself fail. Because the inner store already
    /// holds the pre-reorg chain, clearing the dirty map, the buffered
    /// non-coin batch, the pending tip, the running deltas, and the
    /// non-coin read-through overlays is sufficient and exact: every
    /// subsequent read resolves to the inner store's pre-reorg state.
    ///
    /// Caller contract: block connection and cache flushing must be
    /// serialized (satd connects on a single thread; see the connect loop
    /// in `net::manager`). The atomicity relies on no flush landing the
    /// partial reorg on disk between the pre-reorg checkpoint flush and
    /// this call — an in-memory discard cannot undo an on-disk write.
    ///
    /// Mirrors `clear_chainstate` but deliberately omits the
    /// `inner.clear_chainstate()` call — the inner store must be preserved.
    pub fn discard_uncommitted(&self) {
        self.dirty.write().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock() = None;
        *self.pending_batch.lock() = StoreBatch::default();
        // The non-coin overlays receive reorg-tentative values
        // unconditionally in `write_batch_mode` (the side-chain blocks'
        // index/height/undo/tx/chain-tx rows), so they MUST be cleared —
        // otherwise a stale height->side-hash mapping would survive the
        // abort. Reads then fall through to the inner store's pre-reorg
        // state.
        self.block_index_cache.lock().clear();
        self.height_hash_cache.lock().clear();
        self.undo_cache.lock().clear();
        self.tx_index_cache.lock().clear();
        self.chain_tx_cache.lock().clear();
        // The clean coin LRU is deliberately NOT cleared. During a reorg
        // it only ever loses entries — `write_batch_mode` pops every coin
        // it touches — and gains none with a reorg-tentative value (coins
        // enter `clean` solely via flush-promotion, which does not run
        // mid-reorg, or via read-through, which serves the inner store's
        // pre-reorg value). So every entry remaining in `clean` already
        // agrees with the restored inner state. Clearing a multi-million-
        // entry LRU on every failed reorg would impose a cold-cache stall
        // for no correctness gain, so we keep it warm.
    }
}

impl Store for CoinCache {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        // 1. Check dirty map
        {
            let dirty = self.dirty.read();
            if let Some(entry) = dirty.get(outpoint) {
                return match entry {
                    DirtyEntry::Present { coin, .. } => Some(coin.clone()),
                    DirtyEntry::Spent { .. } => None,
                };
            }
        }

        // 2. Check clean LRU
        {
            let mut clean = self.clean.lock();
            if let Some(coin) = clean.get(outpoint) {
                return Some(coin.clone());
            }
        }

        // 3. Cache miss — read from backing store, populate LRU (auto-evicts if full)
        let coin = self.inner.get_coin(outpoint)?;
        self.clean.lock().put(*outpoint, coin.clone());
        Some(coin)
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        {
            let dirty = self.dirty.read();
            if let Some(entry) = dirty.get(outpoint) {
                return matches!(entry, DirtyEntry::Present { .. });
            }
        }
        {
            let mut clean = self.clean.lock();
            if clean.get(outpoint).is_some() {
                return true;
            }
        }
        self.inner.has_coin(outpoint)
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        // Use the cache's currently-configured mode; the explicit-mode
        // path runs through `write_batch_mode` instead.
        self.write_batch_mode(batch, self.current_write_mode())
    }

    fn write_batch_mode(&self, mut batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        // Honor the caller's explicit mode for the inner-store call.
        // The default trait impl ignores `mode` and delegates to
        // `write_batch`, which would then use `current_write_mode()`
        // — defeating the backfill runner's intent of forcing
        // WriteMode::Normal mid-IBD. See PR #93 review finding #4.
        // Absorb coin operations into dirty map
        let coin_dirty = batch.coin_puts.len() + batch.coin_removes.len();
        if coin_dirty > 0 {
            let mut dirty = self.dirty.write();
            let mut clean = self.clean.lock();

            for (outpoint, coin) in batch.coin_puts {
                self.amount_delta
                    .fetch_add(coin.amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_add(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                // Mark as fresh if this coin doesn't exist in the backing store
                // (not already in dirty map as a non-fresh entry)
                let fresh = !dirty.contains_key(&outpoint);
                dirty.insert(outpoint, DirtyEntry::Present { coin, fresh });
            }

            for (outpoint, spent_amount, spent_height) in batch.coin_removes {
                self.amount_delta
                    .fetch_sub(spent_amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_sub(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                // If the coin was fresh (created in this flush window), mark the
                // spend as fresh too — it can be elided entirely during flush.
                let was_fresh = dirty
                    .get(&outpoint)
                    .is_some_and(|e| matches!(e, DirtyEntry::Present { fresh: true, .. }));
                dirty.insert(
                    outpoint,
                    DirtyEntry::Spent {
                        amount: spent_amount,
                        height: spent_height,
                        fresh: was_fresh,
                    },
                );
            }

            self.dirty_count
                .fetch_add(coin_dirty as u32, Ordering::Relaxed);
        }

        if batch.tip.is_some() {
            *self.pending_tip.lock() = batch.tip;
        }

        // Update overlay LRU AND filter dominated entries OUT of the batch.
        //
        // Dominance rule: a HeaderOnly write must not clobber an existing
        // DataStored or Valid entry. Without this filter, accept_headers'
        // batch (which checks `get_block_index` before deciding to write
        // but cannot lock across that check + the inner write) can clobber
        // a concurrent store_block's DataStored update — leaving
        // `has_block_data()` permanently false and permanently stalling the
        // connect loop. (Reproduced on mainnet, 2026-05-12; ~435 holes
        // observed in a single IBD range.)
        //
        // The previous incarnation filtered only the cache LRU put, leaving
        // the dominated entry in the batch we forwarded to the inner store.
        // The inner-store dominance check (`rocksdb_store::write_batch_mode`)
        // is the second line of defense but it consults on-disk state, not
        // the in-flight cache — so cache-only writes still leaked through.
        // Filtering the batch here keeps the cache and the forwarded batch
        // in agreement, and the inner-store check stays as defense-in-depth.
        //
        // `seen` tracks within-batch dominance so a HeaderOnly entry can't
        // be saved by appearing earlier in the same batch as a DataStored
        // entry for the same hash — keep highest-status per hash.
        {
            let mut bi = self.block_index_cache.lock();
            let mut seen: HashMap<BlockHash, BlockStatus> = HashMap::new();
            let original = std::mem::take(&mut batch.block_index_puts);
            let mut filtered = Vec::with_capacity(original.len());
            for (hash, entry) in original {
                let dominant_status = seen
                    .get(&hash)
                    .copied()
                    .or_else(|| bi.peek(&hash).map(|e| e.status));
                let dominated = entry.status == BlockStatus::HeaderOnly
                    && matches!(
                        dominant_status,
                        Some(BlockStatus::DataStored) | Some(BlockStatus::Valid)
                    );
                if dominated {
                    continue;
                }
                bi.put(hash, entry.clone());
                seen.insert(hash, entry.status);
                filtered.push((hash, entry));
            }
            batch.block_index_puts = filtered;
        }
        {
            let mut hh = self.height_hash_cache.lock();
            for &(height, hash) in &batch.height_hash_puts {
                hh.put(height, hash);
            }
            for &height in &batch.height_hash_removes {
                hh.pop(&height);
            }
        }
        {
            let mut uc = self.undo_cache.lock();
            for (hash, undo) in &batch.undo_puts {
                uc.put(*hash, undo.clone());
            }
        }
        {
            let mut ti = self.tx_index_cache.lock();
            for &(txid, hash) in &batch.tx_index_puts {
                ti.put(txid, hash);
            }
            for txid in &batch.tx_index_removes {
                ti.pop(txid);
            }
        }
        {
            let mut ctx = self.chain_tx_cache.lock();
            for &(hash, count) in &batch.chain_tx_puts {
                ctx.put(hash, count);
            }
        }

        // Non-coin operations:
        // - Without coins (store_block, accept_headers): write to backing store immediately
        // - With coins (connect_block): buffer for flush
        #[cfg(feature = "block-filter-index")]
        let has_filter = !batch.filter_puts.is_empty()
            || !batch.filter_header_puts.is_empty()
            || !batch.filter_removes.is_empty();
        #[cfg(not(feature = "block-filter-index"))]
        let has_filter = false;
        let has_non_coin = !batch.block_index_puts.is_empty()
            || !batch.height_hash_puts.is_empty()
            || !batch.height_hash_removes.is_empty()
            || !batch.undo_puts.is_empty()
            || !batch.tx_index_puts.is_empty()
            || !batch.tx_index_removes.is_empty()
            || !batch.chain_tx_puts.is_empty()
            || !batch.addr_funding_puts.is_empty()
            || !batch.addr_spending_puts.is_empty()
            || !batch.addr_funding_removes.is_empty()
            || !batch.addr_spending_removes.is_empty()
            || !batch.outpoint_spend_puts.is_empty()
            || !batch.outpoint_spend_removes.is_empty()
            || !batch.addr_backfill_temp_puts.is_empty()
            || batch.backfill_cursor_advance.is_some()
            || has_filter
            || {
                #[cfg(feature = "block-filter-index")]
                {
                    batch.filter_backfill_cursor_advance.is_some()
                }
                #[cfg(not(feature = "block-filter-index"))]
                {
                    false
                }
            };

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
                    chain_tx_puts: batch.chain_tx_puts,
                    addr_funding_puts: batch.addr_funding_puts,
                    addr_spending_puts: batch.addr_spending_puts,
                    addr_funding_removes: batch.addr_funding_removes,
                    addr_spending_removes: batch.addr_spending_removes,
                    outpoint_spend_puts: batch.outpoint_spend_puts,
                    outpoint_spend_removes: batch.outpoint_spend_removes,
                    addr_backfill_temp_puts: batch.addr_backfill_temp_puts,
                    backfill_cursor_advance: batch.backfill_cursor_advance,
                    #[cfg(feature = "block-filter-index")]
                    filter_puts: batch.filter_puts,
                    #[cfg(feature = "block-filter-index")]
                    filter_header_puts: batch.filter_header_puts,
                    #[cfg(feature = "block-filter-index")]
                    filter_removes: batch.filter_removes,
                    #[cfg(feature = "block-filter-index")]
                    filter_backfill_cursor_advance: batch.filter_backfill_cursor_advance,
                };
                self.inner.write_batch_mode(pass_through, mode)?;
            } else {
                let mut pending = self.pending_batch.lock();
                pending.block_index_puts.extend(batch.block_index_puts);
                pending.height_hash_puts.extend(batch.height_hash_puts);
                pending
                    .height_hash_removes
                    .extend(batch.height_hash_removes);
                pending.undo_puts.extend(batch.undo_puts);
                pending.tx_index_puts.extend(batch.tx_index_puts);
                pending.tx_index_removes.extend(batch.tx_index_removes);
                pending.chain_tx_puts.extend(batch.chain_tx_puts);
                // Address-index, outpoint-spend, backfill-temp, and
                // filter-index puts and removes all need last-writer-wins
                // dedup by key (so connect→disconnect→connect or
                // disconnect→connect sequences before flush land on the
                // correct final state). Build a small StoreBatch carrying
                // only those fields and route it through `merge` — the
                // rest of `batch` was already extended above.
                let addr_only = StoreBatch {
                    addr_funding_puts: batch.addr_funding_puts,
                    addr_spending_puts: batch.addr_spending_puts,
                    addr_funding_removes: batch.addr_funding_removes,
                    addr_spending_removes: batch.addr_spending_removes,
                    outpoint_spend_puts: batch.outpoint_spend_puts,
                    outpoint_spend_removes: batch.outpoint_spend_removes,
                    addr_backfill_temp_puts: batch.addr_backfill_temp_puts,
                    backfill_cursor_advance: batch.backfill_cursor_advance,
                    #[cfg(feature = "block-filter-index")]
                    filter_puts: batch.filter_puts,
                    #[cfg(feature = "block-filter-index")]
                    filter_header_puts: batch.filter_header_puts,
                    #[cfg(feature = "block-filter-index")]
                    filter_removes: batch.filter_removes,
                    #[cfg(feature = "block-filter-index")]
                    filter_backfill_cursor_advance: batch.filter_backfill_cursor_advance,
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
        //
        // Hold the flush-exclusion lock across BOTH steps — and call
        // `flush_inner` rather than `self.flush()` so the single
        // acquisition is non-reentrant — so a concurrent reorg can neither
        // have its partial cache drained here nor have the inner store
        // sync'd to disk mid-reorg. See `flush_guard`.
        let _g = self.flush_guard.lock();
        self.flush_inner()?;
        self.inner.flush_durable()
    }

    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        if let Some(entry) = self.block_index_cache.lock().get(hash) {
            return Some(entry.clone());
        }
        self.inner.get_block_index(hash)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        if let Some(tip) = *self.pending_tip.lock() {
            return Some(tip);
        }
        self.inner.get_tip()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        if let Some(&hash) = self.height_hash_cache.lock().get(&height) {
            return Some(hash);
        }
        self.inner.get_block_hash_by_height(height)
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        if let Some(undo) = self.undo_cache.lock().get(hash) {
            return Some(undo.clone());
        }
        self.inner.get_undo(hash)
    }

    fn get_cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        if let Some(&count) = self.chain_tx_cache.lock().get(hash) {
            return Some(count);
        }
        self.inner.get_cumulative_tx_count(hash)
    }

    fn chain_tx_backfill_complete(&self) -> bool {
        self.inner.chain_tx_backfill_complete()
    }

    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_chain_tx_backfill_complete()
    }

    /// Diagnostic delegation. The trait default returns Ok with zero
    /// rows, so without this passthrough the blockfile audit would
    /// silently report an empty `block_index` (same shape bug as
    /// PR #193's per-CF diagnostics).
    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<crate::storage::BlockIndexScanStats, StoreError> {
        self.inner.for_each_block_index(visit)
    }

    fn coin_count(&self) -> u64 {
        let base = self.inner.coin_count() as i64;
        let delta = self.count_delta.load(Ordering::Relaxed);
        (base + delta).max(0) as u64
    }

    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<crate::storage::CoinSnapshotBase, StoreError> {
        // Pure delegation: the caller is required to flush dirty entries
        // before invoking this (see ChainState::dump_utxo_snapshot), so
        // the inner Store's snapshot already contains every coin and its
        // consistent base.
        self.inner.for_each_coin_snapshot(f)
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
        if let Some(&hash) = self.tx_index_cache.lock().get(txid) {
            return Some(hash);
        }
        self.inner.get_tx_location(txid)
    }

    fn has_txindex(&self) -> bool {
        self.inner.has_txindex()
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.dirty.write().clear();
        self.clean.lock().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock() = None;
        *self.pending_batch.lock() = StoreBatch::default();
        self.block_index_cache.lock().clear();
        self.height_hash_cache.lock().clear();
        self.undo_cache.lock().clear();
        self.tx_index_cache.lock().clear();
        self.chain_tx_cache.lock().clear();
        self.inner.clear_chainstate()
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        self.dirty.write().clear();
        self.clean.lock().clear();
        self.dirty_count.store(0, Ordering::Relaxed);
        self.count_delta.store(0, Ordering::Relaxed);
        self.amount_delta.store(0, Ordering::Relaxed);
        *self.pending_tip.lock() = None;
        *self.pending_batch.lock() = StoreBatch::default();
        self.block_index_cache.lock().clear();
        self.height_hash_cache.lock().clear();
        self.undo_cache.lock().clear();
        self.tx_index_cache.lock().clear();
        self.chain_tx_cache.lock().clear();
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
            let dirty = self.dirty.read();
            let mut clean = self.clean.lock();
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
            self.perf_store_misses
                .fetch_add(misses.len() as u64, Ordering::Relaxed);
            let miss_outpoints: Vec<OutPoint> = misses.iter().map(|(_, op)| *op).collect();
            let fetched = self.inner.get_coins_batch(&miss_outpoints);
            let mut clean = self.clean.lock();
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

    fn chainstate_l0_files(&self) -> u64 {
        self.inner.chainstate_l0_files()
    }

    fn chainstate_pending_compaction_bytes(&self) -> u64 {
        self.inner.chainstate_pending_compaction_bytes()
    }

    fn pending_compaction_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        self.inner.pending_compaction_bytes_by_cf()
    }

    fn sst_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        self.inner.sst_bytes_by_cf()
    }

    fn compact_chainstate(&self) -> Result<(), StoreError> {
        // Drain pending writes before forcing a compaction so the dirty
        // overlay's contents are visible to the compaction range and
        // included in the resulting SSTs. Without this, a subsequent
        // flush would re-introduce L0 files immediately after the manual
        // compaction completed, making the periodic compactor's effort
        // wasted.
        self.flush()?;
        self.inner.compact_chainstate()
    }

    fn iter_addr_funding(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrFundingKey, u64)> {
        self.iter_addr_funding_limited(sh, usize::MAX)
    }

    fn iter_addr_funding_limited(
        &self,
        sh: &crate::index::address::Scripthash,
        limit: usize,
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
        let pending = self.pending_batch.lock();
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

        // Round-1 review M4: bound the inner scan. The handler only
        // needs to know "is there more than `cap`?", so asking inner
        // for `limit + 1` rows is enough — pending puts may displace
        // some, but the merged total is still <= limit + 1 + |pending
        // puts|, which the handler then checks against its cap.
        // `limit = usize::MAX` (the unbounded wrapper above) preserves
        // the original "scan everything" behaviour for callers that
        // need a complete view (Esplora's address-balance summing path).
        let inner_limit = limit.saturating_add(1);
        let inner_rows = self.inner.iter_addr_funding_limited(sh, inner_limit);
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
            crate::index::address::encode_funding_key_v2(a)
                .cmp(&crate::index::address::encode_funding_key_v2(b))
        });
        // Round-2 review M3: honor the trait contract — return at
        // most `limit` rows. Without this truncate a large in-flight
        // pending batch could push the merged result past `limit + 1`,
        // weakening the `cap + 1` sentinel handlers rely on.
        // `limit = usize::MAX` (the unbounded wrapper above) is a
        // no-op truncate.
        all.truncate(limit);
        all
    }

    fn iter_addr_spending(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrSpendingKey, OutPoint)> {
        self.iter_addr_spending_limited(sh, usize::MAX)
    }

    fn iter_addr_spending_limited(
        &self,
        sh: &crate::index::address::Scripthash,
        limit: usize,
    ) -> Vec<(crate::index::address::AddrSpendingKey, OutPoint)> {
        // See iter_addr_funding_limited for the limit + 1 + |pending|
        // bounding rationale.
        let pending = self.pending_batch.lock();
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

        let inner_limit = limit.saturating_add(1);
        let inner_rows = self.inner.iter_addr_spending_limited(sh, inner_limit);
        // Dedupe by key with pending taking precedence over inner.
        // See `iter_addr_funding_limited` for the rationale.
        let pending_keys: std::collections::HashSet<crate::index::address::AddrSpendingKey> =
            pending_puts.iter().map(|(k, _)| k.clone()).collect();
        let mut all: Vec<(crate::index::address::AddrSpendingKey, OutPoint)> = inner_rows
            .into_iter()
            .filter(|(k, _)| !pending_removes.contains(k) && !pending_keys.contains(k))
            .chain(pending_puts)
            .collect();
        all.sort_by(|(a, _), (b, _)| {
            crate::index::address::encode_spending_key_v2(a)
                .cmp(&crate::index::address::encode_spending_key_v2(b))
        });
        // Round-2 review M3: honor the trait contract — see
        // iter_addr_funding_limited for the rationale.
        all.truncate(limit);
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

    // Index-completeness marker forwarders. Without these, the
    // trait defaults (return `true`) leak through and mask the
    // upgrade-gap detection done at store-open time.
    fn outpoint_spend_complete(&self) -> bool {
        self.inner.outpoint_spend_complete()
    }

    fn mark_outpoint_spend_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_outpoint_spend_complete()
    }

    fn tx_index_complete(&self) -> bool {
        self.inner.tx_index_complete()
    }

    fn address_index_complete(&self) -> bool {
        self.inner.address_index_complete()
    }

    fn mark_address_index_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_address_index_complete()
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter(&self, filter_type: u8, height: u32) -> Option<Vec<u8>> {
        // Pending-batch peek first: the filter row may have been
        // pushed by `connect_block` but not yet flushed to the inner
        // store. The BIP 157 P2P arms and `getblockfilter` need
        // up-to-the-second freshness so the latest mined block
        // becomes queryable as soon as it's connected — without this
        // peek, they would silently 404 until the CoinCache hit a
        // flush threshold. Last-writer-wins by `(filter_type, height)`
        // mirrors `StoreBatch::merge`'s semantics.
        use node_filter_index::FilterKey;
        let key = FilterKey {
            filter_type,
            height,
        };
        let pending = self.pending_batch.lock();
        if pending.filter_removes.contains(&key) {
            return None;
        }
        if let Some(row) = pending.filter_puts.iter().rev().find(|r| r.key == key) {
            return Some(row.filter.clone());
        }
        drop(pending);
        self.inner.get_filter(filter_type, height)
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter_header(&self, filter_type: u8, height: u32) -> Option<[u8; 32]> {
        use node_filter_index::FilterKey;
        let key = FilterKey {
            filter_type,
            height,
        };
        let pending = self.pending_batch.lock();
        if pending.filter_removes.contains(&key) {
            return None;
        }
        if let Some(row) = pending.filter_header_puts.iter().rev().find(|r| r.key == key) {
            return Some(row.header);
        }
        drop(pending);
        self.inner.get_filter_header(filter_type, height)
    }

    #[cfg(feature = "block-filter-index")]
    fn block_filter_index_complete(&self) -> bool {
        self.inner.block_filter_index_complete()
    }

    #[cfg(feature = "block-filter-index")]
    fn mark_block_filter_index_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_block_filter_index_complete()
    }

    fn lookup_spend(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<node_index::SpendingRef>, StoreError> {
        // Same active-chain-not-flush-bound semantics as
        // `iter_addr_spending`: a just-connected block's spend may
        // be sitting in `pending_batch` until flush, so consult it
        // before forwarding to the inner store. Without this,
        // `RocksSpendIndex::spend_of` could return `Ok(None)` for an
        // outpoint that was just spent — and with `outpoint_spend.complete`
        // true (fresh datadir), the round-3 H2 enforcement would
        // surface that as definitive "unspent". (Round-4 M1.)
        let pending = self.pending_batch.lock();
        // Pending remove takes precedence: the on-disk net effect of
        // remove-then-put is the put (last-writer-wins), but
        // remove-only flips a previously-set entry off. Mirror that.
        let pending_remove = pending
            .outpoint_spend_removes
            .iter()
            .any(|op| op == outpoint);
        let pending_put = pending
            .outpoint_spend_puts
            .iter()
            .find(|(op, _)| op == outpoint)
            .map(|(_, sref)| *sref);
        drop(pending);
        if let Some(sref) = pending_put {
            return Ok(Some(sref));
        }
        if pending_remove {
            return Ok(None);
        }
        self.inner.lookup_spend(outpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::super::blockindex::{BlockIndexEntry, BlockStatus, work_for_bits};
    use super::super::db::InMemoryStore;
    use super::super::undo::UndoData;
    use super::*;
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
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [txid_byte; 32],
            )),
            vout,
        }
    }

    fn make_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
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
        batch
            .coin_puts
            .push((make_outpoint(0x10, 0), make_coin(100, 1)));
        batch
            .coin_puts
            .push((make_outpoint(0x11, 0), make_coin(200, 2)));
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
        b1.coin_puts
            .push((make_outpoint(0x20, 0), make_coin(1000, 1)));
        b1.coin_puts
            .push((make_outpoint(0x21, 0), make_coin(2000, 2)));
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
        batch
            .coin_puts
            .push((make_outpoint(0x40, 0), make_coin(100, 1)));
        batch
            .coin_puts
            .push((make_outpoint(0x41, 0), make_coin(200, 2)));
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
        batch
            .coin_puts
            .push((make_outpoint(0x50, 0), make_coin(500, 1)));
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
        batch
            .coin_puts
            .push((make_outpoint(0x70, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        // Before flush: block_index is in overlay cache but check that
        // after flush it's persisted by clearing the overlay and re-reading.
        cache.flush().unwrap();
        cache.block_index_cache.lock().clear();
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
        cache.block_index_cache.lock().clear();
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
        batch
            .coin_puts
            .push((make_outpoint(0x80, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, entry.clone()));
        cache.write_batch(batch).unwrap();

        // Before flush: clear overlay — inner should NOT have it yet.
        cache.block_index_cache.lock().clear();
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
            spent_coins: vec![make_coin(42, 1)],
        };

        let mut batch = StoreBatch::default();
        batch.undo_puts.push((bh, undo));
        cache.write_batch(batch).unwrap();

        let recovered = cache.get_undo(&bh).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
        assert_eq!(recovered.spent_coins[0].amount, 42);
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
        batch
            .block_index_puts
            .push((make_block_hash(0xF2), make_test_entry(50)));
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
        assert!(cache.block_index_cache.lock().is_empty());
        assert!(cache.height_hash_cache.lock().is_empty());
        assert!(cache.undo_cache.lock().is_empty());
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
        seed.coin_puts
            .push((make_outpoint(0xA0, 0), make_coin(100, 1)));
        seed.coin_puts
            .push((make_outpoint(0xA1, 0), make_coin(200, 2)));
        seed.coin_puts
            .push((make_outpoint(0xA2, 0), make_coin(300, 3)));
        inner.write_batch(seed).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);
        assert_eq!(cache.coin_count(), 3);

        // Add one dirty coin.
        let mut b1 = StoreBatch::default();
        b1.coin_puts
            .push((make_outpoint(0xA3, 0), make_coin(400, 4)));
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
        seed.coin_puts
            .push((make_outpoint(0xB0, 0), make_coin(100, 1)));
        seed.coin_puts
            .push((make_outpoint(0xB1, 0), make_coin(200, 2)));
        inner.write_batch(seed).unwrap();

        let cache = CoinCache::new(Box::new(inner), 10);
        assert_eq!(cache.coin_total_amount(), 300);

        // Add coin with amount 500.
        let mut b1 = StoreBatch::default();
        b1.coin_puts
            .push((make_outpoint(0xB2, 0), make_coin(500, 3)));
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
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering as AOrdering},
        };
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
        cache
            .flush_durable()
            .expect("empty flush_durable must succeed");
        cache
            .flush_durable()
            .expect("repeated flush_durable must succeed");
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
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0x99; 32],
        ));

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
        disconnect
            .addr_funding_removes
            .push(crate::index::address::AddrFundingKey {
                scripthash: sh,
                height: 1,
                txid,
                vout: 0,
            });
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
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0x55; 32],
        ));

        // Stage a remove for the row first (e.g. disconnecting block A).
        let mut disconnect = StoreBatch::default();
        disconnect
            .addr_funding_removes
            .push(crate::index::address::AddrFundingKey {
                scripthash: sh,
                height: 1,
                txid,
                vout: 0,
            });
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
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0x66; 32],
        ));
        let prev = make_outpoint(0xdd, 1);

        let mut disconnect = StoreBatch::default();
        disconnect
            .addr_spending_removes
            .push(crate::index::address::AddrSpendingKey {
                scripthash: sh,
                height: 1,
                txid,
                vin: 0,
            });
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
        disconnect
            .addr_spending_removes
            .push(crate::index::address::AddrSpendingKey {
                scripthash: sh,
                height: 1,
                txid: spending_txid,
                vin: 0,
            });
        cache.write_batch(disconnect).unwrap();

        assert!(
            cache.iter_addr_spending(&sh).is_empty(),
            "pending spending put + remove for same key must net to empty"
        );

        cache.flush_durable().unwrap();
        assert!(cache.iter_addr_spending(&sh).is_empty());
    }

    #[test]
    fn test_pending_lookup_spend_visible_before_flush() {
        // A just-connected block buffers outpoint_spend rows in the
        // pending batch; lookup_spend must see them before flush
        // (round-4 M1).
        let cache = make_cache(16);
        let prev = make_outpoint(0x11, 0);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0x22, 0).txid,
            spending_vin: 3,
            height: 50,
        };
        let mut batch = StoreBatch::default();
        batch.outpoint_spend_puts.push((prev, sref));
        // Force the connect-shape (coin_puts non-empty) so the cache
        // takes the pending-buffered path.
        batch.coin_puts.push((
            make_outpoint(0x33, 0),
            crate::storage::coinview::Coin {
                amount: 50_000_000,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 50,
                coinbase: false,
            },
        ));
        cache.write_batch(batch).unwrap();

        // Pre-flush lookup must see the buffered spend.
        assert_eq!(
            cache.lookup_spend(&prev).unwrap(),
            Some(sref),
            "pending outpoint_spend put must be visible before flush"
        );

        cache.flush_durable().unwrap();
        assert_eq!(cache.lookup_spend(&prev).unwrap(), Some(sref));
    }

    #[test]
    fn test_pending_lookup_spend_remove_hides_inner_row() {
        // Pre-existing on-disk row, then a disconnect-shape pending
        // remove → lookup must report None even before flush.
        let cache = make_cache(16);
        let prev = make_outpoint(0x77, 0);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0x99, 0).txid,
            spending_vin: 1,
            height: 100,
        };
        let mut commit = StoreBatch::default();
        commit.outpoint_spend_puts.push((prev, sref));
        cache.write_batch(commit).unwrap();
        cache.flush_durable().unwrap();
        assert_eq!(cache.lookup_spend(&prev).unwrap(), Some(sref));

        // Now buffer a remove via the connect-shape path.
        let mut disconnect = StoreBatch::default();
        disconnect.outpoint_spend_removes.push(prev);
        disconnect.coin_puts.push((
            make_outpoint(0x88, 0),
            crate::storage::coinview::Coin {
                amount: 1_000,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 101,
                coinbase: false,
            },
        ));
        cache.write_batch(disconnect).unwrap();

        assert_eq!(
            cache.lookup_spend(&prev).unwrap(),
            None,
            "pending outpoint_spend remove must hide the inner row"
        );

        cache.flush_durable().unwrap();
        assert_eq!(cache.lookup_spend(&prev).unwrap(), None);
    }

    #[test]
    fn test_pending_lookup_spend_put_after_remove_takes_precedence() {
        // remove-then-put in the same pending batch (e.g. reorg
        // disconnect followed by reconnect) must end up visible.
        let cache = make_cache(16);
        let prev = make_outpoint(0xee, 2);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0xff, 0).txid,
            spending_vin: 0,
            height: 200,
        };

        let mut step1 = StoreBatch::default();
        step1.outpoint_spend_removes.push(prev);
        step1.coin_puts.push((
            make_outpoint(0xab, 0),
            crate::storage::coinview::Coin {
                amount: 1,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 200,
                coinbase: false,
            },
        ));
        cache.write_batch(step1).unwrap();

        let mut step2 = StoreBatch::default();
        step2.outpoint_spend_puts.push((prev, sref));
        step2.coin_puts.push((
            make_outpoint(0xcd, 0),
            crate::storage::coinview::Coin {
                amount: 1,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 201,
                coinbase: false,
            },
        ));
        cache.write_batch(step2).unwrap();

        // After remove-then-put, the put must win (it's the latest
        // operation against `prev`).
        assert_eq!(cache.lookup_spend(&prev).unwrap(), Some(sref));
    }

    // ---------------------------------------------------------------
    // Block-index dominance filter: cache layer drops dominated entries
    // OUT of the batch before forwarding to the inner store.
    // ---------------------------------------------------------------
    #[test]
    fn cache_filter_drops_header_only_clobbering_data_stored() {
        let inner = Box::new(InMemoryStore::new());
        let cache = CoinCache::new(inner, 10);
        let hash = make_block_hash(0x77);

        // First batch: write DataStored (e.g. via store_block).
        let mut batch1 = StoreBatch::default();
        let mut entry_ds = make_test_entry(100);
        entry_ds.status = BlockStatus::DataStored;
        entry_ds.file_number = 9;
        entry_ds.data_pos = 4242;
        batch1.block_index_puts.push((hash, entry_ds.clone()));
        cache.write_batch(batch1).unwrap();

        // Second batch: a HeaderOnly write for the same hash
        // (simulating a late accept_headers batch). Must be DROPPED —
        // not just skipped at the LRU but also stripped from what we
        // forward to the inner store, so the wedge cannot recur on a
        // cache-evicted hash.
        let mut batch2 = StoreBatch::default();
        let entry_ho = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            ..entry_ds.clone()
        };
        batch2.block_index_puts.push((hash, entry_ho));
        cache.write_batch(batch2).unwrap();

        // Cache lookup: still DataStored.
        let cached = cache.get_block_index(&hash).unwrap();
        assert_eq!(cached.status, BlockStatus::DataStored);
        assert_eq!(cached.file_number, 9);

        // Force a flush and re-check: inner store must also be
        // DataStored. (The whole point of filtering the batch — not
        // just the LRU — is that the inner store agrees with the cache.)
        cache.flush().unwrap();
        // Drop the cache LRU so the next read falls through to inner.
        cache.block_index_cache.lock().clear();
        let from_inner = cache.get_block_index(&hash).unwrap();
        assert_eq!(
            from_inner.status,
            BlockStatus::DataStored,
            "inner store must reflect the dominance filter — not just the LRU"
        );
        assert_eq!(from_inner.file_number, 9);
    }

    #[test]
    fn cache_filter_in_batch_keeps_highest_status() {
        // A single batch carrying both (X, DataStored) and (X, HeaderOnly)
        // for the same hash. The HeaderOnly entry must be stripped from
        // the batch the cache forwards to the inner store, regardless
        // of order. (RocksDB WriteBatch keeps last-put-wins per key, so
        // an unfiltered batch in HeaderOnly-second order produces a
        // HeaderOnly disk state — the wedge mechanism.)
        let inner = Box::new(InMemoryStore::new());
        let cache = CoinCache::new(inner, 10);
        let hash = make_block_hash(0x99);

        let mut ds = make_test_entry(200);
        ds.status = BlockStatus::DataStored;
        ds.file_number = 3;
        ds.data_pos = 999;
        let ho = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            ..ds.clone()
        };

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, ds.clone()));
        batch.block_index_puts.push((hash, ho));
        cache.write_batch(batch).unwrap();

        cache.flush().unwrap();
        cache.block_index_cache.lock().clear();
        let from_inner = cache.get_block_index(&hash).unwrap();
        assert_eq!(from_inner.status, BlockStatus::DataStored);
        assert_eq!(from_inner.file_number, 3);
    }

    // ---------------------------------------------------------------
    // discard_uncommitted: the atomic-reorg rollback primitive (#262)
    // ---------------------------------------------------------------
    #[test]
    fn test_discard_uncommitted_restores_flushed_state() {
        let cache = make_cache(10);

        // Committed (flushed) baseline: coin X exists on disk.
        let x = make_outpoint(0xC0, 0);
        let mut base = StoreBatch::default();
        base.coin_puts.push((x, make_coin(5_000, 1)));
        base.tip = Some(make_block_hash(0x01));
        cache.write_batch(base).unwrap();
        cache.flush().unwrap();
        assert_eq!(cache.dirty_count(), 0);
        let base_count = cache.coin_count();

        // Uncommitted reorg-style delta: create a FRESH coin Y, spend the
        // committed coin X, and advance the pending tip — none flushed.
        let y = make_outpoint(0xC1, 0);
        let mut delta = StoreBatch::default();
        delta.coin_puts.push((y, make_coin(7_000, 2)));
        delta.coin_removes.push((x, 5_000, 1));
        delta.tip = Some(make_block_hash(0x02));
        cache.write_batch(delta).unwrap();
        assert!(cache.dirty_count() > 0, "delta is dirty before discard");
        assert!(cache.get_coin(&y).is_some(), "fresh coin visible pre-discard");
        assert!(cache.get_coin(&x).is_none(), "X spent in the delta pre-discard");
        assert_eq!(cache.get_tip(), Some(make_block_hash(0x02)));

        // Discard the delta: cache returns to exactly the flushed state.
        cache.discard_uncommitted();
        assert_eq!(cache.dirty_count(), 0, "no dirty entries after discard");
        assert!(
            cache.get_coin(&y).is_none(),
            "FRESH coin from the discarded delta must be gone"
        );
        assert!(
            cache.get_coin(&x).is_some(),
            "committed coin X must be restored (the spend was discarded)"
        );
        assert_eq!(cache.get_tip(), Some(make_block_hash(0x01)), "tip back to flushed");
        assert_eq!(cache.coin_count(), base_count, "coin_count back to baseline");

        // A subsequent flush must NOT elide or drop the restored coin —
        // the exact failure the fix prevents.
        cache.flush().unwrap();
        assert!(
            cache.get_coin(&x).is_some(),
            "committed coin survives the post-discard flush"
        );
        assert!(cache.get_coin(&y).is_none(), "discarded coin stays gone after flush");
        assert_eq!(cache.coin_count(), base_count);
    }

    // ---------------------------------------------------------------
    // Flush-exclusion lock: a held FlushExclusion (a reorg in progress)
    // blocks a concurrent flush from another thread until released, so no
    // external flush can persist a partially-applied reorg (#262 followup).
    // ---------------------------------------------------------------
    #[test]
    fn test_flush_exclusion_blocks_concurrent_flush() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let cache = Arc::new(make_cache(10));

        // Stage a dirty coin so the other thread's flush has real work.
        let op = make_outpoint(0xE0, 0);
        let mut b = StoreBatch::default();
        b.coin_puts.push((op, make_coin(4_242, 1)));
        cache.write_batch(b).unwrap();

        // Hold the exclusion on this thread (simulating a reorg window).
        let excl = cache.lock_flush_exclusion();

        let other_started = Arc::new(AtomicBool::new(false));
        let other_done = Arc::new(AtomicBool::new(false));
        let handle = {
            let cache = Arc::clone(&cache);
            let other_started = Arc::clone(&other_started);
            let other_done = Arc::clone(&other_done);
            std::thread::spawn(move || {
                // Signal that we have reached the flush call, then block on
                // flush_guard until the exclusion is released.
                other_started.store(true, Ordering::SeqCst);
                cache.flush().unwrap();
                other_done.store(true, Ordering::SeqCst);
            })
        };

        // Wait until the other thread has actually reached the flush call
        // (so the assertion below provably exercises the block, not a
        // not-yet-started thread), then give it time to park on the lock.
        while !other_started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !other_done.load(Ordering::SeqCst),
            "concurrent flush must be blocked while the reorg exclusion is held"
        );

        // The reorg's own checkpoint-style flush works through the held
        // handle without re-acquiring (would deadlock otherwise).
        excl.flush().unwrap();

        // Release the exclusion; the blocked flush now completes.
        drop(excl);
        handle.join().expect("other flush thread");
        assert!(
            other_done.load(Ordering::SeqCst),
            "flush must complete once the exclusion is released"
        );

        // No deadlock / lock left poisoned: ordinary flush + durable flush
        // still work after the exclusion lifecycle.
        cache.flush().unwrap();
        cache.flush_durable().unwrap();
        assert_eq!(cache.get_coin(&op).unwrap().amount, 4_242);
    }
}
