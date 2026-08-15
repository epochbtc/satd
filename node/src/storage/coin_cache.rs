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
    /// Thread that currently holds the flush exclusion, i.e. the one thread
    /// entitled to mutate this cache for the duration of a reorg. `None`
    /// outside a reorg. Read only when `exclusive_active` says there is
    /// something to read, so the ordinary write path never takes this lock.
    exclusive_owner: Mutex<Option<std::thread::ThreadId>>,
    /// Fast-path gate for `exclusive_owner`: true exactly while a
    /// [`FlushExclusion`] is alive.
    exclusive_active: std::sync::atomic::AtomicBool,
    /// Set when some thread other than the exclusion holder mutated this
    /// cache while the exclusion was held. That is a broken invariant, not a
    /// recoverable condition: see [`CoinCache::discard_uncommitted`].
    foreign_write_during_exclusion: std::sync::atomic::AtomicBool,
}

/// Why [`CoinCache::discard_uncommitted`] refused to discard.
///
/// Both variants mean the same thing operationally — the cache does not hold
/// only the aborting reorg's own work, so throwing it away would destroy
/// someone else's — and neither is recoverable in-process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscardRefused {
    /// Another thread wrote to the cache after the reorg took the exclusion.
    ForeignWrite,
    /// The exclusion handle presented belongs to a different `CoinCache`.
    WrongCache,
}

impl std::fmt::Display for DiscardRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignWrite => write!(
                f,
                "another thread mutated the coin cache while a reorg held the flush exclusion"
            ),
            Self::WrongCache => write!(
                f,
                "the flush exclusion presented belongs to a different coin cache"
            ),
        }
    }
}

/// RAII flush-exclusion held by a reorg for the duration of its cache
/// mutation. While alive, external `CoinCache::flush` / `flush_durable`
/// calls block. The holder flushes via [`FlushExclusion::flush`], which
/// does NOT re-acquire the guard (avoiding self-deadlock).
///
/// It doubles as the reorg's claim to be the *only* thread mutating the
/// cache: the holding thread's id is recorded for as long as this is alive,
/// and any write arriving from another thread meanwhile is remembered. That
/// is what makes [`CoinCache::discard_uncommitted`]'s caller contract
/// checkable rather than merely documented — see its doc comment.
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

impl Drop for FlushExclusion<'_> {
    fn drop(&mut self) {
        // Order matters: close the gate before releasing ownership, so a
        // write racing the drop is either attributed to the still-recorded
        // owner or not examined at all — never examined against `None`.
        self.cache
            .exclusive_active
            .store(false, std::sync::atomic::Ordering::Release);
        *self.cache.exclusive_owner.lock() = None;
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
            exclusive_owner: Mutex::new(None),
            exclusive_active: std::sync::atomic::AtomicBool::new(false),
            foreign_write_during_exclusion: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Switch the underlying-store write mode for subsequent writes and
    /// flushes. Use `BulkLoad` during IBD (when crash-recovery replay is
    /// cheap relative to WAL overhead); `Normal` otherwise.
    ///
    /// Leaving `BulkLoad` performs a durable flush *before* the switch,
    /// by construction: WAL-less writes are volatile until their memtables
    /// reach SST files, so restoring `Normal` without flushing strands
    /// acknowledged writes in memory where the next process exit silently
    /// drops them (the mainnet-952978 bug shape). Fail-closed callers
    /// (reindex, IBD completion) should still call `flush_durable`
    /// explicitly so errors propagate; this transition flush is the
    /// backstop and only logs on failure.
    pub fn set_write_mode(&self, mode: WriteMode) {
        if self.current_write_mode() == WriteMode::BulkLoad
            && mode == WriteMode::Normal
            && let Err(e) = Store::flush_durable(self)
        {
            tracing::error!(
                error = %e,
                "durable flush on BulkLoad->Normal transition failed; \
                 WAL-less writes may be lost if the process exits before \
                 the next successful flush"
            );
        }
        let v = match mode {
            WriteMode::Normal => 0,
            WriteMode::BulkLoad => 1,
        };
        self.write_mode.store(v, Ordering::Relaxed);
    }

    /// The active write-durability mode.
    ///
    /// Deliberately private: it describes RocksDB batching only. It was
    /// briefly `pub` so `ChainState::write_block_durable` could skip the
    /// flat-file fsync in `BulkLoad` — an exemption that was wrong (a
    /// WAL-less write still lands via automatic memtable flush, so IBD is the
    /// *more* exposed path, not the safe one) and has been removed. Nothing
    /// outside this module should gate durability on it.
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

    /// Test-only: drop the non-coin read-through overlays so subsequent
    /// reads resolve against the inner store.
    ///
    /// Tests reached for `discard_uncommitted` to do this, which worked
    /// because they flushed first and so had nothing left to discard. It is
    /// no longer the same operation: `discard_uncommitted` is a reorg
    /// rollback that requires the flush exclusion and can refuse. This is the
    /// thing those tests actually wanted.
    ///
    /// Note what it does *not* drop: the clean coin LRU, which `flush`
    /// promotes into. Coin reads still answer from memory afterwards.
    #[cfg(test)]
    pub(crate) fn drop_read_overlays(&self) {
        self.block_index_cache.lock().clear();
        self.height_hash_cache.lock().clear();
        self.undo_cache.lock().clear();
        self.tx_index_cache.lock().clear();
        self.chain_tx_cache.lock().clear();
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
    ///
    /// Also claims exclusive mutation rights for the calling thread until the
    /// handle drops. Nothing *prevents* another thread from writing — the
    /// lock that does that is `ChainState::accept_lock` — but such a write is
    /// recorded, and `discard_uncommitted` refuses to run afterwards.
    pub(crate) fn lock_flush_exclusion(&self) -> FlushExclusion<'_> {
        use std::sync::atomic::Ordering;
        let guard = self.flush_guard.lock();
        // Under `flush_guard`, so no other exclusion can be alive and these
        // three stores cannot interleave with another scope's setup.
        *self.exclusive_owner.lock() = Some(std::thread::current().id());
        self.foreign_write_during_exclusion
            .store(false, Ordering::Relaxed);
        self.exclusive_active.store(true, Ordering::Release);
        FlushExclusion {
            cache: self,
            _guard: guard,
        }
    }

    /// Record a mutation arriving from a thread that is not the current
    /// exclusion holder.
    ///
    /// Costs one relaxed atomic load on the ordinary write path, which is
    /// once per block, not once per coin. The mutex is only touched while a
    /// reorg is actually in progress.
    fn note_mutation(&self) {
        use std::sync::atomic::Ordering;
        if !self.exclusive_active.load(Ordering::Acquire) {
            return;
        }
        let owner = *self.exclusive_owner.lock();
        let Some(owner) = owner else { return };
        if owner == std::thread::current().id() {
            return;
        }
        if !self
            .foreign_write_during_exclusion
            .swap(true, Ordering::AcqRel)
        {
            // Once per scope: the point is to name the condition, and a
            // thread that wrote once usually writes repeatedly.
            tracing::error!(
                owner = ?owner,
                writer = ?std::thread::current().id(),
                "A thread wrote to the coin cache while a reorg held exclusive \
                 mutation rights. Every chain mutator must hold accept_lock; \
                 one of them does not."
            );
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
            // Removes need their own terms. `take` above has already emptied
            // `pending`, so anything this gate misses is DISCARDED, not
            // deferred. A removes-only pending batch became materially more
            // likely once `merge` started retaining away the put that used to
            // keep this gate true; today it is still covered incidentally
            // because `disconnect_block` always sets `tip`, which is an
            // accident of that emitter rather than a guarantee.
            || !batch.height_hash_removes.is_empty()
            || !batch.undo_puts.is_empty()
            || !batch.tx_index_puts.is_empty()
            || !batch.tx_index_removes.is_empty()
            || !batch.addr_funding_removes.is_empty()
            || !batch.addr_spending_removes.is_empty()
            || !batch.outpoint_spend_removes.is_empty()
            || !batch.chain_tx_puts.is_empty()
            // Silent-payment tweak rows ride the chainstate batch. They only
            // ever enter `pending` alongside a connect/disconnect (which set
            // block_index/tip), so today this is redundant — but guarding it
            // here means a future path that buffers SP rows without a
            // co-occurring block-index/tip write can't silently drop them.
            || !batch.sp_tweak_puts.is_empty()
            || !batch.sp_tweak_removes.is_empty()
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
            if let Err((returned, e)) = self.inner.write_batch_recoverable(batch, mode) {
                match returned {
                    Some(batch) => self.restore_after_failed_flush(*batch),
                    // The inner store cannot say what it applied, so replaying
                    // could double-apply. Nothing to do but say so: the delta
                    // is gone and the caller's error is the only signal.
                    None => tracing::error!(
                        error = %e,
                        coin_puts = puts,
                        coin_removes = removes,
                        "Flush failed and the backing store could not return the \
                         batch; the in-memory delta is lost and this chainstate \
                         must be rebuilt"
                    ),
                }
                return Err(e);
            }
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

    /// Put back what [`Self::flush_inner`] drained to build a batch the
    /// backing store then refused to write.
    ///
    /// `flush_inner` empties the dirty map, takes the buffered non-coin rows
    /// and the pending tip, and zeroes the counters *before* the inner write,
    /// so that readers are not held behind a multi-second RocksDB call. That
    /// is fine when the write succeeds and silent data loss when it does not:
    /// a transient ENOSPC or I/O error would discard an entire flush window's
    /// UTXO delta — the shape of #567 with no reorg involved.
    ///
    /// Two deliberate imprecisions, both safe:
    ///
    /// - Restored coins come back with `fresh: false` regardless of what they
    ///   were. `fresh` means "absent from the backing store", which licenses
    ///   eliding a later spend; after a failed write that is exactly what we
    ///   can no longer be sure of for anything in the batch, and `false` is
    ///   the conservative direction. The cost is that a later spend of such a
    ///   coin emits a real remove for a key the store may not hold — a RocksDB
    ///   delete of a missing key, which is a no-op.
    /// - Coins created *and* spent inside the failed window were elided from
    ///   the batch entirely, so they are not restored, and that is correct:
    ///   they have no row in the backing store (the write failed, and it would
    ///   not have written them anyway), none in `clean` (`write_batch_mode`
    ///   pops every outpoint it touches), and none in `dirty`. Every read
    ///   misses, which is the truth — the coin was created and spent. Their
    ///   contribution to the counters is likewise zero, restored or not.
    ///
    /// Entries written by another thread between the drain and here win:
    /// their value is newer. The counters are additive rather than restored
    /// wholesale for the same reason.
    fn restore_after_failed_flush(&self, mut batch: StoreBatch) {
        let coin_puts = std::mem::take(&mut batch.coin_puts);
        let coin_removes = std::mem::take(&mut batch.coin_removes);
        let tip = batch.tip.take();

        // `dirty_count` mirrors the map's population, so only ops actually
        // inserted may count — an entry re-dirtied since the drain was
        // already counted by its newer writer, and adding it again drifts
        // the gauge high, triggering premature flushes. The value deltas
        // below are different: they are per-op linear sums, correct to add
        // unconditionally even on a collision (the newer writer's delta and
        // this op's delta both describe real not-yet-on-disk movement).
        let mut restored = 0u32;
        let mut count_delta = 0i64;
        let mut amount_delta = 0i64;
        {
            use std::collections::hash_map::Entry;
            let mut dirty = self.dirty.write();
            for (outpoint, coin) in coin_puts {
                count_delta += 1;
                amount_delta += coin.amount as i64;
                if let Entry::Vacant(slot) = dirty.entry(outpoint) {
                    slot.insert(DirtyEntry::Present { coin, fresh: false });
                    restored += 1;
                }
            }
            for (outpoint, amount, height) in coin_removes {
                count_delta -= 1;
                amount_delta -= amount as i64;
                if let Entry::Vacant(slot) = dirty.entry(outpoint) {
                    slot.insert(DirtyEntry::Spent {
                        amount,
                        height,
                        fresh: false,
                    });
                    restored += 1;
                }
            }
        }
        self.dirty_count.fetch_add(restored, Ordering::Relaxed);
        self.count_delta.fetch_add(count_delta, Ordering::Relaxed);
        self.amount_delta.fetch_add(amount_delta, Ordering::Relaxed);

        if let Some(tip) = tip {
            let mut pending = self.pending_tip.lock();
            if pending.is_none() {
                *pending = Some(tip);
            }
        }

        // Non-coin rows go back into the pending batch *underneath* anything
        // buffered since the drain, so a newer write still wins.
        let mut pending = self.pending_batch.lock();
        let newer = std::mem::take(&mut *pending);
        batch.merge(newer);
        *pending = batch;

        tracing::error!(
            restored_coins = restored,
            "Flush to the backing store failed; the in-memory delta has been \
             restored and will be retried on the next flush"
        );
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
    /// Caller contract, now checked at the boundaries rather than assumed:
    /// the aborting reorg must hold this cache's [`FlushExclusion`], and no
    /// other thread may have mutated the discardable delta since it took
    /// that exclusion. "Checked", not "proved": `note_mutation` is
    /// check-then-act, so a foreign write that straddles the exclusion's
    /// start or this discard can escape the flag. What the check does
    /// deliver is detection of any *repeat* writer — the #567 connector
    /// wrote eight blocks into the window — and a second look at the flag
    /// after the clears below narrows the far boundary too. The atomicity
    /// relies on both — on no flush landing the partial reorg on disk (an
    /// in-memory discard cannot undo an on-disk write), and on everything
    /// buffered belonging to the reorg doing the discarding.
    ///
    /// The second half used to read "satd connects on a single thread; see
    /// the connect loop in `net::manager`". satd connects on one thread and
    /// reorgs on another, and issue #567 is what that cost: an
    /// `invalidateblock` reorg aborted and this method threw away eight
    /// blocks the connector had committed into the same cache, destroying
    /// their UTXOs and resurrecting the invalidated branch's spends. The
    /// lock that makes the claim true is `ChainState::accept_lock`, which
    /// every chain mutator including the connector now takes. This check is
    /// what stops a future mutator that forgets from corrupting a UTXO set
    /// silently: a refusal is returned instead, and the caller fail-stops.
    ///
    /// Returning `Err` means nothing was discarded — the cache is left
    /// exactly as it was, which is the only safe thing to do when its
    /// contents cannot be attributed.
    ///
    /// Mirrors `clear_chainstate` but deliberately omits the
    /// `inner.clear_chainstate()` call — the inner store must be preserved.
    pub(crate) fn discard_uncommitted(
        &self,
        excl: &FlushExclusion<'_>,
    ) -> Result<(), DiscardRefused> {
        use std::sync::atomic::Ordering;
        if !std::ptr::eq(excl.cache, self) {
            return Err(DiscardRefused::WrongCache);
        }
        if self.foreign_write_during_exclusion.load(Ordering::Acquire) {
            return Err(DiscardRefused::ForeignWrite);
        }
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
        // Second look: a foreign writer whose `note_mutation` check
        // interleaved the start of this discard can have landed (and
        // flagged) mid-clear. Its write is already destroyed — that cannot
        // be helped from here — but returning refused turns silent
        // destruction into the caller's fail-stop, which is the contract.
        if self
            .foreign_write_during_exclusion
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(DiscardRefused::ForeignWrite);
        }
        // The clean coin LRU is deliberately NOT cleared. During a reorg
        // it only ever loses entries — `write_batch_mode` pops every coin
        // it touches — and gains none with a reorg-tentative value (coins
        // enter `clean` solely via flush-promotion, which does not run
        // mid-reorg, or via read-through, which serves the inner store's
        // pre-reorg value). So every entry remaining in `clean` already
        // agrees with the restored inner state. Clearing a multi-million-
        // entry LRU on every failed reorg would impose a cold-cache stall
        // for no correctness gain, so we keep it warm.
        Ok(())
    }
}

impl CoinCache {
    /// Absorb a batch into the cache, forwarding to the inner store only
    /// what does not belong to a reorg's retractable state.
    ///
    /// The recoverable form is the primitive because the only failure point —
    /// the pass-through forward below — can hand its rows back, and a caller
    /// that drained state to build the batch needs them. See
    /// `Store::write_batch_recoverable`.
    fn absorb_batch(
        &self,
        mut batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        // Every chainstate mutation funnels through here — `write_batch`,
        // `write_batch_mode` and `write_batch_recoverable` all delegate to
        // this one function — so this is the one place that can notice a
        // writer trespassing on a reorg's exclusive window. But only a batch
        // that touches the *discardable delta* — coins staged into the dirty
        // map, a buffered tip — counts as trespassing. A coin-free, tip-less
        // batch takes the pass-through branch below, straight into the inner
        // store, where `discard_uncommitted` cannot touch it: an index
        // backfill or a prune running beside a reorg is not a hole in the
        // reorg's rollback, and flagging it would turn a safe discard into a
        // spurious process fail-stop.
        let coin_dirty = batch.coin_puts.len() + batch.coin_removes.len();
        if coin_dirty > 0 || batch.tip.is_some() {
            self.note_mutation();
        }
        // Honor the caller's explicit mode for the inner-store call.
        // The default trait impl ignores `mode` and delegates to
        // `write_batch`, which would then use `current_write_mode()`
        // — defeating the backfill runner's intent of forcing
        // WriteMode::Normal mid-IBD. See PR #93 review finding #4.
        // Absorb coin operations into dirty map
        if coin_dirty > 0 {
            let mut dirty = self.dirty.write();
            let mut clean = self.clean.lock();

            for (outpoint, coin) in batch.coin_puts {
                self.amount_delta
                    .fetch_add(coin.amount as i64, Ordering::Relaxed);
                self.count_delta.fetch_add(1, Ordering::Relaxed);
                clean.pop(&outpoint);
                // `fresh` means "absent from the backing store", which is what
                // licenses eliding a later spend: if the store never had it,
                // create-then-spend inside one window needs no write at all.
                //
                // The test below is not that, though — it is "no dirty entry
                // for this outpoint". The two agree only because of an
                // invariant on the callers, which is worth stating since
                // nothing enforces it: a `coin_put` is only ever issued for an
                // outpoint the store does not hold. Connection creates outputs
                // under txids that have never existed, and disconnection
                // re-adds only coins it is simultaneously removing from the
                // store's view. So "not in dirty" implies "not in the store":
                // an outpoint the store holds and that was spent in this
                // window is in `dirty` as `Spent`, giving `fresh = false` and
                // a real remove at flush.
                //
                // Break that invariant and the failure is a phantom UTXO — an
                // elided remove leaving a spent coin in the store — not a lost
                // one. Worth knowing which direction it fails in.
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
            || !batch.sp_tweak_puts.is_empty()
            || !batch.sp_tweak_removes.is_empty()
            || batch.sp_backfill_cursor_advance.is_some()
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

        // A batch with no coins goes straight to the backing store, bypassing
        // both the flush-exclusion and `discard_uncommitted`. That looks
        // alarming next to the reorg atomicity `discard_uncommitted` promises,
        // so it is worth writing down why it is not a hole.
        //
        // The routing is per batch, not global. Everything a reorg writes
        // tentatively — every disconnect, every reconnect — carries coins, so
        // `coin_dirty > 0` and it is buffered and therefore discardable. What
        // takes this branch is writes that are not part of the reorg's
        // tentative state and must not be rolled back with it: `store_block`
        // recording an arriving block, `accept_header(s)`, `mark_subtree_invalid`
        // stamping an invalidation. Those are durable facts about blocks, not
        // about which chain is active, and a reorg aborting should not undo
        // them.
        //
        // The one thing to preserve when touching this: nothing that a failed
        // reorg must be able to retract may reach here. The `coin_dirty == 0`
        // test is what enforces that, and it is *nearly* — not entirely —
        // implied by "connection and disconnection always move coins".
        //
        // The exception is a block whose every output is unspendable and which
        // spends nothing: `connect_block` and `disconnect_block` both skip
        // unspendable outputs, so such a block yields empty `coin_puts` and
        // empty `coin_removes`. A coinbase-only block whose sole output is an
        // OP_RETURN is exactly that, and it is a block a miner can produce (or
        // a fork-feeder can craft). Its index writes would then pass straight
        // through and survive a reorg abort that should have retracted them —
        // the height-row pollution shape of #322/#564. It is a narrow case and
        // no such block is known on mainnet, but the invariant is not airtight
        // and this comment should not claim it is. Routing on "a reorg is in
        // flight" rather than on `coin_dirty` would close it properly.
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
                    sp_tweak_puts: batch.sp_tweak_puts,
                    sp_tweak_removes: batch.sp_tweak_removes,
                    sp_backfill_cursor_advance: batch.sp_backfill_cursor_advance,
                };
                // A pass-through write is *newer* than anything still buffered
                // for the same hash, and it lands in the inner store directly.
                // Drop the superseded pending entries first, before the write:
                // leaving them would let `flush_inner` replay a stale `Valid`
                // over the `Invalid` that `mark_subtree_invalid` just wrote, or
                // over `prune_blocks`' `Pruned`, resurrecting a status the node
                // deliberately retired. It also keeps `get_block_index`'s
                // pending lookup from shadowing the newer inner value.
                //
                // Ordering matters: clearing before the write means a reader in
                // the gap sees the inner store's older value, which is what it
                // would have seen anyway. Clearing after would briefly serve
                // the buffered value, which is strictly older.
                if !pass_through.block_index_puts.is_empty() {
                    let superseded: std::collections::HashSet<BlockHash> = pass_through
                        .block_index_puts
                        .iter()
                        .map(|(h, _)| *h)
                        .collect();
                    let mut pending = self.pending_batch.lock();
                    pending
                        .block_index_puts
                        .retain(|(h, _)| !superseded.contains(h));
                }
                self.inner.write_batch_recoverable(pass_through, mode)?;
            } else {
                let mut pending = self.pending_batch.lock();
                pending.block_index_puts.extend(batch.block_index_puts);
                pending.undo_puts.extend(batch.undo_puts);
                pending.chain_tx_puts.extend(batch.chain_tx_puts);
                // Every keyed index's puts and removes need last-writer-wins
                // dedup by key (so connect→disconnect→connect or
                // disconnect→connect sequences before flush land on the
                // correct final state). Build a StoreBatch carrying only
                // those fields and route it through `merge` — the fields
                // extended above are put-only, or hash-keyed with no
                // corresponding remove, so ordering alone resolves them.
                let keyed = StoreBatch {
                    height_hash_puts: batch.height_hash_puts,
                    height_hash_removes: batch.height_hash_removes,
                    tx_index_puts: batch.tx_index_puts,
                    tx_index_removes: batch.tx_index_removes,
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
                    sp_tweak_puts: batch.sp_tweak_puts,
                    sp_tweak_removes: batch.sp_tweak_removes,
                    sp_backfill_cursor_advance: batch.sp_backfill_cursor_advance,
                    ..Default::default()
                };
                pending.merge(keyed);
            }
        }

        Ok(())
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

    fn write_batch_mode(&self, batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        self.absorb_batch(batch, mode).map_err(|(_, e)| e)
    }

    /// Layered-store caveat (see the trait doc): on a pass-through failure
    /// the returned batch is the *filtered pass-through remainder*, not the
    /// caller's original — coins and the tip were already absorbed into the
    /// cache (where they are safe: the failure did not touch them), overlay
    /// LRUs were updated, dominated entries were filtered out, and
    /// superseded pending rows were cleared. Replaying the returned batch
    /// restores the correct final state; comparing it to the input does
    /// not.
    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        self.absorb_batch(batch, mode)
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
        // The LRU is a cache, not the record. `write_batch` mirrors a
        // coin-carrying batch's `block_index_puts` into it *and* buffers them
        // in `pending_batch`; only the second survives eviction. Falling
        // straight through to `inner` on an LRU miss therefore reads the
        // *pre-connect* status — `store_block`'s `DataStored` — for a block
        // `connect_block` has already stamped `Valid`, because that upgrade
        // is still buffered.
        //
        // That is not a stale-read nuisance: `require_connected_parent` reads
        // exactly this to decide whether a parent was ever connected, so an
        // eviction between two connects turns a healthy parent into
        // `ParentNeverConnected` and refuses to extend the chain. Eviction is
        // cheap to provoke — every `store_block` and every `accept_headers`
        // batch puts to the same LRU, up to 2000 entries per `headers`
        // message, against a capacity of `dbcache_mb * 66.7`.
        //
        // Header and `store_block` batches carry no coins, so they take the
        // `coin_dirty == 0` pass-through and never land here; the pending vec
        // holds one entry per connect/disconnect since the last flush. The
        // scan runs backwards because the buffer is append-only and the last
        // write for a hash wins, matching how `flush_inner` replays it.
        if let Some((_, entry)) = self
            .pending_batch
            .lock()
            .block_index_puts
            .iter()
            .rev()
            .find(|(h, _)| h == hash)
        {
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

    /// Scans the inner store with the pending batch overlaid.
    ///
    /// Rows still buffered here have not reached the inner store, so a bare
    /// passthrough would report a height as absent that this cache is about
    /// to write — and the one caller that exists reads "absent" as "damaged,
    /// rewrite it". Snapshot the pending state and drop the lock before the
    /// scan: it can be long, and holding the batch lock across it would stall
    /// every writer.
    fn for_each_height_hash(
        &self,
        visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<crate::storage::HeightHashScanStats, StoreError> {
        let (removed, overlaid) = {
            let pending = self.pending_batch.lock();
            let removed: std::collections::HashSet<u32> =
                pending.height_hash_removes.iter().copied().collect();
            let overlaid: std::collections::HashMap<u32, BlockHash> =
                pending.height_hash_puts.iter().copied().collect();
            (removed, overlaid)
        };
        let stats = self.inner.for_each_height_hash(&mut |height, hash| {
            if removed.contains(&height) || overlaid.contains_key(&height) {
                return;
            }
            visit(height, hash);
        })?;
        for (height, hash) in overlaid {
            visit(height, hash);
        }
        Ok(stats)
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
        self.note_mutation();
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
        self.note_mutation();
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

    // BIP 352 SP-index forwarders. Always compiled (the SP index follows
    // the address-index model). Without these, the trait defaults
    // (`silent_payment_index_complete` → true, `read_sp_backfill_cursor`
    // → idle) would leak through the CoinCache wrapper and mask both the
    // upgrade-gap detection done at store-open and the persisted backfill
    // cursor, so `getindexinfo` would wrongly report synced and the
    // supervisor would never auto-resume.
    fn get_sp_tweaks_row(&self, height: u32) -> Option<node_sp_index::SpBlockRow> {
        // Pending-batch peek first: a just-connected block's tweak row may
        // not have flushed to the inner store yet. Last-writer-wins by
        // height mirrors `StoreBatch::merge`.
        let pending = self.pending_batch.lock();
        if pending.sp_tweak_removes.contains(&height) {
            return None;
        }
        if let Some((_, row)) = pending
            .sp_tweak_puts
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
        {
            return Some(row.clone());
        }
        drop(pending);
        self.inner.get_sp_tweaks_row(height)
    }

    fn get_sp_tweaks_row_checked(
        &self,
        height: u32,
    ) -> Result<Option<node_sp_index::SpBlockRow>, StoreError> {
        // Mirror `get_sp_tweaks_row`'s pending-batch peek so the wrapper cannot
        // fake an empty height for a row still buffered — then delegate to the
        // inner checked read so a storage/decode error is preserved rather than
        // swallowed into `None` (which would silently gap an unclamped replay).
        let pending = self.pending_batch.lock();
        if pending.sp_tweak_removes.contains(&height) {
            return Ok(None);
        }
        if let Some((_, row)) = pending.sp_tweak_puts.iter().rev().find(|(h, _)| *h == height) {
            return Ok(Some(row.clone()));
        }
        drop(pending);
        self.inner.get_sp_tweaks_row_checked(height)
    }

    fn silent_payment_index_complete(&self) -> bool {
        self.inner.silent_payment_index_complete()
    }

    fn mark_silent_payment_index_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_silent_payment_index_complete()
    }

    fn read_sp_backfill_cursor(&self) -> node_sp_index::cursor::BackfillCursor {
        self.inner.read_sp_backfill_cursor()
    }

    fn read_sp_backfill_last_error(&self) -> Option<String> {
        self.inner.read_sp_backfill_last_error()
    }

    fn write_sp_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        self.inner.write_sp_backfill_last_error(msg)
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
    // 0. FRESH elision: the two sides of the invariant it depends on
    // ---------------------------------------------------------------

    /// A coin created and spent inside one flush window must not be in the
    /// store afterwards.
    ///
    /// This pins the observable contract, not the elision. Skipping the write
    /// pair entirely and writing both then removing both reach the same end
    /// state, which is exactly why the `fresh` flag is safe to have — it is an
    /// optimisation underneath a contract, not the contract itself. What would
    /// break the contract is eliding a remove for a coin the store *does*
    /// hold, which is the next test.
    #[test]
    fn fresh_coin_created_and_spent_in_one_window_never_reaches_the_store() {
        let cache = make_cache(10);
        let op = make_outpoint(0x5a, 0);

        let mut put = StoreBatch::default();
        put.coin_puts.push((op, make_coin(7_000, 9)));
        cache.write_batch(put).unwrap();

        let mut spend = StoreBatch::default();
        spend.coin_removes.push((op, 7_000, 9));
        cache.write_batch(spend).unwrap();

        cache.flush().unwrap();
        cache.drop_read_overlays(); // read the store itself

        assert!(
            cache.get_coin(&op).is_none(),
            "the coin must not be in the store"
        );
    }

    /// The other side, and the one that matters: spending a coin the store
    /// already holds must remove it. `fresh` must be false here — were the
    /// caller invariant in `write_batch_mode` ever broken so that it were
    /// true, the remove would be elided and the store would keep a spent coin.
    /// A phantom UTXO rather than a lost one.
    #[test]
    fn spending_a_store_resident_coin_emits_a_real_remove() {
        let inner = InMemoryStore::new();
        let op = make_outpoint(0x5b, 0);
        let mut seed = StoreBatch::default();
        seed.coin_puts.push((op, make_coin(4_200, 3)));
        inner.write_batch(seed).unwrap();
        let cache = CoinCache::new(Box::new(inner), 10);

        assert!(cache.get_coin(&op).is_some(), "seeded into the store");

        let mut spend = StoreBatch::default();
        spend.coin_removes.push((op, 4_200, 3));
        cache.write_batch(spend).unwrap();

        cache.flush().unwrap();
        cache.drop_read_overlays();

        assert!(
            cache.get_coin(&op).is_none(),
            "a spend of a store-resident coin must not be elided"
        );
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

    /// An evicted LRU entry must not resurrect the pre-connect status.
    ///
    /// `store_block` writes `DataStored` through the coin-less pass-through,
    /// so it lands in the inner store. `connect_block` upgrades it to `Valid`
    /// in a batch that carries coins, so that upgrade is buffered and only
    /// *mirrored* into the LRU. If the LRU drops it before the flush,
    /// `get_block_index` must still report `Valid` — `require_connected_parent`
    /// reads this to decide whether a parent was ever connected, and reading
    /// the inner store's stale `DataStored` refuses to extend a healthy chain.
    #[test]
    fn buffered_block_index_survives_lru_eviction() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xDE);

        // store_block: no coins, so this passes through to the inner store.
        let mut stored = make_test_entry(41);
        stored.status = BlockStatus::DataStored;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((bh, stored));
        cache.write_batch(batch).unwrap();
        assert_eq!(
            cache.inner.get_block_index(&bh).unwrap().status,
            BlockStatus::DataStored,
        );

        // connect_block: carries coins, so the Valid upgrade is buffered.
        let mut batch = StoreBatch::default();
        batch
            .coin_puts
            .push((make_outpoint(0x81, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, make_test_entry(41)));
        cache.write_batch(batch).unwrap();

        // The inner store still holds the pre-connect status...
        assert_eq!(
            cache.inner.get_block_index(&bh).unwrap().status,
            BlockStatus::DataStored,
        );
        // ...so once the LRU evicts the mirrored copy, the pending batch is
        // the only remaining witness that this block was connected.
        cache.block_index_cache.lock().clear();
        assert_eq!(
            cache.get_block_index(&bh).unwrap().status,
            BlockStatus::Valid,
            "an evicted LRU entry fell through to the inner store's pre-connect status",
        );
    }

    /// A flush must not resurrect a status the node deliberately retired.
    ///
    /// `mark_subtree_invalid` and `prune_blocks` write block-index entries with
    /// no coins attached, so they take the pass-through and land in the inner
    /// store immediately. If the buffered `Valid` from the earlier connect were
    /// left in place, `flush_inner` would replay it afterwards and put the
    /// block back to `Valid` — undoing an invalidate or a prune at the next
    /// flush.
    #[test]
    fn a_passthrough_write_supersedes_the_buffered_entry() {
        let cache = make_cache(10);
        let bh = make_block_hash(0xDF);

        // connect_block: coins attached, so the Valid entry is buffered.
        let mut batch = StoreBatch::default();
        batch
            .coin_puts
            .push((make_outpoint(0x82, 0), make_coin(1, 1)));
        batch.block_index_puts.push((bh, make_test_entry(42)));
        cache.write_batch(batch).unwrap();

        // invalidate_block: no coins, so this goes straight to the inner store.
        let mut invalid = make_test_entry(42);
        invalid.status = BlockStatus::Invalid;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((bh, invalid));
        cache.write_batch(batch).unwrap();
        assert_eq!(
            cache.get_block_index(&bh).unwrap().status,
            BlockStatus::Invalid,
        );

        cache.flush().unwrap();
        assert_eq!(
            cache.inner.get_block_index(&bh).unwrap().status,
            BlockStatus::Invalid,
            "the flush replayed a stale buffered entry over a newer write",
        );
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

    /// A reorg's remove and the replacement block's put for the SAME height
    /// coalesce into one pending batch. They must not annihilate each other:
    /// the put is the later op, so the replacement block's hash has to
    /// survive the flush.
    ///
    /// This was a real defect. Two heights in the middle of a healthy active
    /// chain answered `-8: Block height out of range` on a synced mainnet
    /// node — but only after a restart, because the warm in-memory height
    /// cache sees the ops in correct per-call order and masks the loss for as
    /// long as the process lives.
    #[test]
    fn height_hash_put_after_remove_in_one_pending_batch_survives_flush() {
        let cache = make_cache(10);
        let new_hash = make_block_hash(0xB1);
        const H: u32 = 956337;

        // Coins dirty => non-coin ops are BUFFERED into `pending_batch`
        // rather than passed straight through to the store.
        let mut warm = StoreBatch::default();
        warm.coin_puts.push((make_outpoint(0x01, 0), make_coin(50, 1)));
        cache.write_batch(warm).unwrap();

        // 1. The reorg disconnects the old block at height H.
        let mut disconnect = StoreBatch::default();
        disconnect
            .coin_puts
            .push((make_outpoint(0x02, 0), make_coin(51, 1)));
        disconnect.height_hash_removes.push(H);
        cache.write_batch(disconnect).unwrap();

        // 2. The replacement block connects at the SAME height.
        let mut connect = StoreBatch::default();
        connect
            .coin_puts
            .push((make_outpoint(0x03, 0), make_coin(52, 1)));
        connect.height_hash_puts.push((H, new_hash));
        cache.write_batch(connect).unwrap();

        // The merge resolved the collision in favour of the later op, so the
        // pending batch no longer carries both.
        {
            let pending = cache.pending_batch.lock();
            assert!(!pending.height_hash_removes.contains(&H));
            assert!(pending.height_hash_puts.iter().any(|(h, _)| *h == H));
        }

        assert_eq!(
            cache.get_block_hash_by_height(H),
            Some(new_hash),
            "warm cache"
        );

        cache.flush_durable().unwrap();

        // Read as a restarted node does: nothing in the in-memory height
        // cache, straight through to whatever actually persisted.
        cache.height_hash_cache.lock().pop(&H);
        assert_eq!(
            cache.get_block_hash_by_height(H),
            Some(new_hash),
            "height {H} lost: a put and a remove for the same height survived \
             into one batch, and `write_batch` applies every put before every \
             remove"
        );
    }

    /// The height-index scan must see rows that are still buffered here.
    ///
    /// Its only caller reads "no row" as "damaged, rederive it", so a bare
    /// passthrough to the inner store would have the audit rebuild heights
    /// this cache was about to write anyway — and, worse, miss that a pending
    /// remove had already retired a row the inner store still holds.
    #[test]
    fn height_hash_scan_overlays_the_pending_batch() {
        let cache = make_cache(10);
        let committed = make_block_hash(0xC0);
        let buffered = make_block_hash(0xC1);

        // Land one row in the inner store with no coins dirty (pass-through).
        let mut through = StoreBatch::default();
        through.height_hash_puts.push((100, committed));
        cache.write_batch(through).unwrap();

        // Now dirty the coins so subsequent index ops buffer instead.
        let mut warm = StoreBatch::default();
        warm.coin_puts.push((make_outpoint(0x41, 0), make_coin(50, 1)));
        cache.write_batch(warm).unwrap();

        let mut buffered_batch = StoreBatch::default();
        buffered_batch
            .coin_puts
            .push((make_outpoint(0x42, 0), make_coin(51, 1)));
        buffered_batch.height_hash_puts.push((101, buffered));
        buffered_batch.height_hash_removes.push(100);
        cache.write_batch(buffered_batch).unwrap();

        let mut seen: std::collections::HashMap<u32, BlockHash> =
            std::collections::HashMap::new();
        cache
            .for_each_height_hash(&mut |h, hash| {
                seen.insert(h, hash);
            })
            .unwrap();

        assert_eq!(
            seen.get(&101),
            Some(&buffered),
            "a buffered put must be visible or the audit rewrites it"
        );
        assert_eq!(
            seen.get(&100),
            None,
            "a buffered remove must hide the inner store's row"
        );
    }

    /// The mirror case, which is what stops the fix from being "apply removes
    /// before puts". Connect then disconnect at the same height inside one
    /// pending batch has to leave the row GONE — the remove is the later op.
    #[test]
    fn height_hash_remove_after_put_in_one_pending_batch_leaves_no_row() {
        let cache = make_cache(10);
        const H: u32 = 956337;

        let mut warm = StoreBatch::default();
        warm.coin_puts.push((make_outpoint(0x21, 0), make_coin(50, 1)));
        cache.write_batch(warm).unwrap();

        let mut connect = StoreBatch::default();
        connect
            .coin_puts
            .push((make_outpoint(0x22, 0), make_coin(51, 1)));
        connect.height_hash_puts.push((H, make_block_hash(0xB3)));
        cache.write_batch(connect).unwrap();

        let mut disconnect = StoreBatch::default();
        disconnect
            .coin_puts
            .push((make_outpoint(0x23, 0), make_coin(52, 1)));
        disconnect.height_hash_removes.push(H);
        cache.write_batch(disconnect).unwrap();

        cache.flush_durable().unwrap();
        cache.height_hash_cache.lock().pop(&H);
        assert_eq!(
            cache.get_block_hash_by_height(H),
            None,
            "height {H} resurrected: the disconnect was the later op"
        );
    }

    /// Same defect on the txindex, with a more routine trigger: a reorg
    /// removes the displaced block's txids and the replacement chain re-mines
    /// the same transactions, so put and remove collide on one txid. Losing
    /// the row makes `getrawtransaction` report a transaction that IS in the
    /// chain as unknown.
    #[test]
    fn tx_index_put_after_remove_in_one_pending_batch_survives_flush() {
        let cache = make_cache(10);
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0x77; 32],
        ));
        let new_block = make_block_hash(0xB2);

        let mut warm = StoreBatch::default();
        warm.coin_puts.push((make_outpoint(0x11, 0), make_coin(50, 1)));
        cache.write_batch(warm).unwrap();

        let mut disconnect = StoreBatch::default();
        disconnect
            .coin_puts
            .push((make_outpoint(0x12, 0), make_coin(51, 1)));
        disconnect.tx_index_removes.push(txid);
        cache.write_batch(disconnect).unwrap();

        let mut connect = StoreBatch::default();
        connect
            .coin_puts
            .push((make_outpoint(0x13, 0), make_coin(52, 1)));
        connect.tx_index_puts.push((txid, new_block));
        cache.write_batch(connect).unwrap();

        cache.flush_durable().unwrap();
        cache.tx_index_cache.lock().pop(&txid);
        assert_eq!(
            cache.get_tx_location(&txid),
            Some(new_block),
            "txindex entry lost: `getrawtransaction` would report a tx that IS \
             in the chain as unknown"
        );
    }

    /// The txindex mirror: a tx that the replacement chain does *not* re-mine
    /// must stay gone.
    #[test]
    fn tx_index_remove_after_put_in_one_pending_batch_leaves_no_row() {
        let cache = make_cache(10);
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0x78; 32],
        ));

        let mut warm = StoreBatch::default();
        warm.coin_puts.push((make_outpoint(0x31, 0), make_coin(50, 1)));
        cache.write_batch(warm).unwrap();

        let mut connect = StoreBatch::default();
        connect
            .coin_puts
            .push((make_outpoint(0x32, 0), make_coin(51, 1)));
        connect.tx_index_puts.push((txid, make_block_hash(0xB4)));
        cache.write_batch(connect).unwrap();

        let mut disconnect = StoreBatch::default();
        disconnect
            .coin_puts
            .push((make_outpoint(0x33, 0), make_coin(52, 1)));
        disconnect.tx_index_removes.push(txid);
        cache.write_batch(disconnect).unwrap();

        cache.flush_durable().unwrap();
        cache.tx_index_cache.lock().pop(&txid);
        assert_eq!(
            cache.get_tx_location(&txid),
            None,
            "txindex row resurrected: the disconnect was the later op"
        );
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
    // flush failure atomicity
    // ---------------------------------------------------------------

    /// A flush that the backing store refuses must lose nothing.
    ///
    /// `flush_inner` drains the dirty map, takes the buffered non-coin rows
    /// and the pending tip, and zeroes the counters before calling the inner
    /// store, so readers are not held behind a multi-second RocksDB write.
    /// That made a transient write fault — ENOSPC, an IO error — destroy the
    /// whole flush window's delta: the same silent UTXO loss as #567 with no
    /// reorg involved, and with the node carrying on as if nothing had
    /// happened.
    ///
    /// Every read must answer as it did before the attempt, and the retry
    /// must write the complete delta.
    #[test]
    fn a_failed_flush_leaves_the_cache_exactly_as_it_was() {
        use crate::storage::test_store::ControllableStore;

        let store = ControllableStore::new();
        let controls = store.controls();
        let cache = CoinCache::new(Box::new(store), 10);

        // Committed baseline: X on disk.
        let x = make_outpoint(0xF0, 0);
        let mut base = StoreBatch::default();
        base.coin_puts.push((x, make_coin(5_000, 1)));
        base.tip = Some(make_block_hash(0x01));
        cache.write_batch(base).unwrap();
        cache.flush().unwrap();
        let base_count = cache.coin_count();
        let base_amount = cache.coin_total_amount();

        // An unflushed window: create Y, spend X, create and spend Z (the
        // FRESH-elision case), plus non-coin rows and a new tip.
        let y = make_outpoint(0xF1, 0);
        let z = make_outpoint(0xF2, 0);
        let block = make_block_hash(0x02);
        let mut delta = StoreBatch::default();
        delta.coin_puts.push((y, make_coin(7_000, 2)));
        delta.coin_puts.push((z, make_coin(1_000, 2)));
        delta.coin_removes.push((x, 5_000, 1));
        delta.block_index_puts.push((block, make_test_entry(2)));
        delta.height_hash_puts.push((2, block));
        delta.undo_puts.push((block, UndoData::default()));
        delta.chain_tx_puts.push((block, 42));
        delta.tip = Some(block);
        cache.write_batch(delta).unwrap();
        let mut spend_z = StoreBatch::default();
        spend_z.coin_removes.push((z, 1_000, 2));
        cache.write_batch(spend_z).unwrap();

        let expect_cache_state = |cache: &CoinCache, when: &str| {
            assert!(cache.get_coin(&y).is_some(), "Y unspent {when}");
            assert!(cache.get_coin(&x).is_none(), "X spent {when}");
            assert!(cache.get_coin(&z).is_none(), "Z created and spent {when}");
            assert_eq!(cache.get_tip(), Some(block), "tip {when}");
            assert!(cache.get_block_index(&block).is_some(), "index row {when}");
            assert_eq!(cache.get_block_hash_by_height(2), Some(block), "height row {when}");
            assert!(cache.get_undo(&block).is_some(), "undo {when}");
            assert_eq!(cache.get_cumulative_tx_count(&block), Some(42), "chain_tx {when}");
            assert_eq!(cache.coin_count(), base_count, "coin_count {when}");
            assert_eq!(
                cache.coin_total_amount(),
                base_amount - 5_000 + 7_000,
                "total amount {when}"
            );
        };
        expect_cache_state(&cache, "before the flush");

        controls.fail_next_write();
        let err = cache.flush().expect_err("the injected fault must surface");
        assert!(err.to_string().contains("injected write fault"), "{err}");

        expect_cache_state(&cache, "after the failed flush");
        assert!(
            cache.dirty_count() > 0,
            "the delta is still pending, not silently dropped"
        );

        // The retry writes everything, and the state survives being read cold.
        cache.flush().expect("retry succeeds");
        expect_cache_state(&cache, "after the successful retry");
        // Drop the read-through overlays so the checks below hit the store.
        // Safe as a pure overlay drop because the flush above already drained
        // the dirty map and pending batch. The exclusion is taken here purely
        // to satisfy the discard's caller contract; no foreign write can have
        // landed inside a window this test opens and closes in one statement.
        let excl = cache.lock_flush_exclusion();
        assert_eq!(cache.discard_uncommitted(&excl), Ok(()));
        drop(excl);
        assert!(cache.get_block_index(&block).is_some(), "index row reached disk");
        assert_eq!(cache.get_block_hash_by_height(2), Some(block));
        assert!(cache.get_undo(&block).is_some());
        assert_eq!(cache.get_cumulative_tx_count(&block), Some(42));
    }

    /// The restore must not overwrite a write that arrived while the failed
    /// flush was in flight — that write is newer, and the whole reason the
    /// dirty lock is dropped before the inner call is to let it happen.
    #[test]
    fn a_failed_flush_does_not_clobber_writes_made_since_the_drain() {
        use crate::storage::test_store::ControllableStore;

        let store = ControllableStore::new();
        let controls = store.controls();
        let cache = CoinCache::new(Box::new(store), 10);

        let y = make_outpoint(0xF3, 0);
        let mut delta = StoreBatch::default();
        delta.coin_puts.push((y, make_coin(7_000, 2)));
        cache.write_batch(delta).unwrap();

        // Simulate the interleaving directly: the batch the flush drained is
        // handed back after a newer spend of the same coin has landed.
        let mut drained = StoreBatch::default();
        drained.coin_puts.push((y, make_coin(7_000, 2)));
        let mut spend = StoreBatch::default();
        spend.coin_removes.push((y, 7_000, 2));
        cache.write_batch(spend).unwrap();
        let gauge_before = cache.dirty_count();
        cache.restore_after_failed_flush(drained);

        assert!(
            cache.get_coin(&y).is_none(),
            "the newer spend wins over the restored create"
        );
        // The restored put collided with the newer spend's entry and was not
        // inserted, so it must not move the population gauge either — an
        // unconditional add here drifts it high and triggers premature
        // flushes. (The gauge itself counts absorb ops, not map entries, so
        // only the delta across the restore is meaningful.)
        assert_eq!(
            cache.dirty_count(),
            gauge_before,
            "a fully-colliding restore must leave dirty_count unchanged"
        );
        let _ = controls;
    }

    /// Pins the load-bearing merge polarity in `restore_after_failed_flush`:
    /// the restored (older) batch must sit *under* rows buffered since the
    /// drain, and the pending tip must keep its newer value. Reversing
    /// either — `newer.merge(older)`, or an unconditional pending-tip
    /// overwrite — resurrects stale height/index rows on the next flush,
    /// the #564 shape, and this test fails.
    #[test]
    fn a_restored_batch_sits_under_newer_noncoin_rows_not_over_them() {
        use crate::storage::test_store::ControllableStore;

        let store = ControllableStore::new();
        let cache = CoinCache::new(Box::new(store), 10);

        let hash_a = make_block_hash(0xA1);
        let hash_b = make_block_hash(0xB1);
        let hash_c = make_block_hash(0xC1);
        let tip_new = make_block_hash(0xEE);
        let tip_old = make_block_hash(0xDD);

        // Newer state, written "since the drain": height 2 -> B, height 3 -> C,
        // and a new tip. The coin makes the batch buffer (coin-free batches
        // pass through and would not model the pending-batch collision).
        let mut newer = StoreBatch::default();
        newer.coin_puts.push((make_outpoint(0xF4, 0), make_coin(1_000, 2)));
        newer.height_hash_puts.push((2, hash_b));
        newer.height_hash_puts.push((3, hash_c));
        newer.tip = Some(tip_new);
        cache.write_batch(newer).unwrap();

        // The drained (older) batch handed back by a failed flush: a stale
        // height 2 -> A put, a stale remove of height 3, and the old tip.
        let mut older = StoreBatch::default();
        older.height_hash_puts.push((2, hash_a));
        older.height_hash_removes.push(3);
        older.tip = Some(tip_old);
        cache.restore_after_failed_flush(older);

        // Newer values win immediately...
        assert_eq!(cache.get_block_hash_by_height(2), Some(hash_b));
        assert_eq!(cache.get_tip(), Some(tip_new));

        // ...and, decisively, in what the next flush writes to the store.
        cache.flush().unwrap();
        // Pure overlay drop after a full flush; see the note on the same
        // pattern above for why an exclusion is taken around it.
        let excl = cache.lock_flush_exclusion();
        assert_eq!(cache.discard_uncommitted(&excl), Ok(()));
        drop(excl);
        assert_eq!(
            cache.get_block_hash_by_height(2),
            Some(hash_b),
            "the newer height row must reach the store, not the restored stale one"
        );
        assert_eq!(
            cache.get_block_hash_by_height(3),
            Some(hash_c),
            "the newer put must survive the restored stale remove"
        );
        assert_eq!(cache.get_tip(), Some(tip_new), "the newer tip must win");
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
        {
            let excl = cache.lock_flush_exclusion();
            cache.discard_uncommitted(&excl).expect("no foreign writer");
        }
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

    /// The rollback primitive must not run over another thread's writes.
    ///
    /// Issue #567: `discard_uncommitted` throws away everything unflushed on
    /// the assumption that the aborting reorg put it all there. When that was
    /// false — the connector was committing blocks into the same cache with
    /// no lock — the discard destroyed eight blocks of UTXOs. The assumption
    /// is now checked, and a discard that would destroy someone else's work
    /// refuses instead. Refusing changes nothing about the cache: the caller
    /// fail-stops, and the last consistent state on disk is the reorg's own
    /// pre-reorg checkpoint.
    #[test]
    fn discard_uncommitted_refuses_after_a_foreign_write() {
        let cache = make_cache(10);

        let x = make_outpoint(0xD0, 0);
        let mut base = StoreBatch::default();
        base.coin_puts.push((x, make_coin(5_000, 1)));
        cache.write_batch(base).unwrap();
        cache.flush().unwrap();

        // A reorg takes the exclusion and stages a delta of its own.
        let excl = cache.lock_flush_exclusion();
        let mine = make_outpoint(0xD1, 0);
        let mut delta = StoreBatch::default();
        delta.coin_puts.push((mine, make_coin(6_000, 2)));
        cache.write_batch(delta).unwrap();

        // Another thread writes anyway — the defect this guards against.
        let theirs = make_outpoint(0xD2, 0);
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut b = StoreBatch::default();
                b.coin_puts.push((theirs, make_coin(9_000, 3)));
                cache.write_batch(b).unwrap();
            });
        });

        assert_eq!(
            cache.discard_uncommitted(&excl),
            Err(DiscardRefused::ForeignWrite)
        );
        assert!(
            cache.get_coin(&theirs).is_some(),
            "a refused discard destroys nothing"
        );
        assert!(cache.get_coin(&mine).is_some());
        assert!(cache.dirty_count() > 0);
    }

    /// The exclusion is a claim about one specific cache. Presenting another
    /// cache's handle proves nothing about this one, so it is refused rather
    /// than accepted on the strength of having the right type.
    #[test]
    fn discard_uncommitted_refuses_an_exclusion_from_another_cache() {
        let cache = make_cache(10);
        let other = make_cache(10);

        let op = make_outpoint(0xD3, 0);
        let mut b = StoreBatch::default();
        b.coin_puts.push((op, make_coin(1_000, 1)));
        cache.write_batch(b).unwrap();

        let foreign_excl = other.lock_flush_exclusion();
        assert_eq!(
            cache.discard_uncommitted(&foreign_excl),
            Err(DiscardRefused::WrongCache)
        );
        assert!(cache.get_coin(&op).is_some(), "nothing was discarded");
    }

    /// The owning thread's own writes are not foreign writes — otherwise the
    /// guard would refuse every real reorg abort, which is the failure mode
    /// that turns a safety check into an outage.
    #[test]
    fn a_reorgs_own_writes_do_not_trip_the_discard_guard() {
        let cache = make_cache(10);
        let excl = cache.lock_flush_exclusion();
        for i in 0..4u8 {
            let mut b = StoreBatch::default();
            b.coin_puts.push((make_outpoint(0xD4, i as u32), make_coin(100, 1)));
            cache.write_batch(b).unwrap();
        }
        assert_eq!(cache.discard_uncommitted(&excl), Ok(()));
        assert_eq!(cache.dirty_count(), 0);
    }

    /// A coin-free, tip-less batch — an index backfill's rows, a prune's
    /// status stamps, `store_block` recording an arrival — takes the
    /// pass-through branch straight into the inner store, where
    /// `discard_uncommitted` cannot touch it. It is therefore not a foreign
    /// write, and must not turn an aborted reorg into a process fail-stop:
    /// a multi-hour address backfill beside an operator `invalidateblock`
    /// is a supported combination, not corruption. Removing the
    /// discardable-content gate on the `note_mutation` call makes this
    /// fail.
    #[test]
    fn a_coin_free_pass_through_write_is_not_a_foreign_write() {
        let cache = make_cache(10);

        // A reorg takes the exclusion and stages a delta of its own.
        let excl = cache.lock_flush_exclusion();
        let mine = make_outpoint(0xD7, 0);
        let mut delta = StoreBatch::default();
        delta.coin_puts.push((mine, make_coin(6_000, 2)));
        cache.write_batch(delta).unwrap();

        // Another thread lands a coin-free pass-through write mid-window —
        // the shape of every backfill and prune batch.
        let entry = make_test_entry(9);
        let hash = entry.header.block_hash();
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut b = StoreBatch::default();
                b.block_index_puts.push((hash, entry));
                cache.write_batch(b).unwrap();
            });
        });

        // The discard is refused by nothing: the pass-through write is not
        // part of the discardable delta.
        assert_eq!(cache.discard_uncommitted(&excl), Ok(()));
        // And it survived the discard — it was never in the delta.
        assert!(
            cache.get_block_index(&hash).is_some(),
            "the pass-through row must survive a discard untouched"
        );
        // A tip-carrying batch, by contrast, IS discardable state and does
        // trip the guard even with no coins aboard. (Drop the first
        // exclusion before taking the second: shadowing would run the
        // non-reentrant acquisition while the old guard is still alive.)
        drop(excl);
        let excl = cache.lock_flush_exclusion();
        std::thread::scope(|s| {
            s.spawn(|| {
                let b = StoreBatch {
                    tip: Some(bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash()),
                    ..Default::default()
                };
                cache.write_batch(b).unwrap();
            });
        });
        assert_eq!(
            cache.discard_uncommitted(&excl),
            Err(DiscardRefused::ForeignWrite),
            "a foreign tip write is discardable state and must be flagged"
        );
    }

    /// `write_batch_recoverable` is a second public door into the cache, and
    /// it must be as guarded as `write_batch`. Both delegate to
    /// `absorb_batch`, which is where the flag is raised — so this is a
    /// regression pin on that placement: move the `note_mutation` gate up
    /// into `write_batch_mode` (where it originally lived, before the
    /// recoverable path existed) and a foreign write arriving through the
    /// recoverable door becomes invisible to the discard, which is the
    /// silent-destruction shape the guard exists to stop.
    #[test]
    fn a_foreign_recoverable_write_trips_the_discard_guard() {
        let cache = make_cache(10);

        // A reorg takes the exclusion and stages its own delta.
        let excl = cache.lock_flush_exclusion();
        let mut delta = StoreBatch::default();
        delta
            .coin_puts
            .push((make_outpoint(0xD9, 0), make_coin(7_000, 3)));
        cache.write_batch(delta).unwrap();

        // Another thread writes discardable state through the *recoverable*
        // door — the door `SplitStore` and the flush-restore path use.
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut b = StoreBatch::default();
                b.coin_puts
                    .push((make_outpoint(0xD9, 1), make_coin(8_000, 3)));
                cache
                    .write_batch_recoverable(b, WriteMode::Normal)
                    .map_err(|(_, e)| e)
                    .expect("the foreign write itself succeeds");
            });
        });

        assert_eq!(
            cache.discard_uncommitted(&excl),
            Err(DiscardRefused::ForeignWrite),
            "a foreign write through write_batch_recoverable must be flagged"
        );
    }

    /// The guard is scoped to the exclusion, not to the life of the process:
    /// writes from other threads before it is taken, or after it is dropped,
    /// say nothing about whether a later reorg owns the cache.
    #[test]
    fn the_discard_guard_only_looks_inside_the_exclusion_window() {
        let cache = make_cache(10);

        // Before: another thread writes with no reorg in progress.
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut b = StoreBatch::default();
                b.coin_puts.push((make_outpoint(0xD5, 0), make_coin(100, 1)));
                cache.write_batch(b).unwrap();
            });
        });

        // A first reorg comes and goes with a foreign write inside it.
        {
            let excl = cache.lock_flush_exclusion();
            std::thread::scope(|s| {
                s.spawn(|| {
                    let mut b = StoreBatch::default();
                    b.coin_puts.push((make_outpoint(0xD5, 1), make_coin(100, 1)));
                    cache.write_batch(b).unwrap();
                });
            });
            assert_eq!(
                cache.discard_uncommitted(&excl),
                Err(DiscardRefused::ForeignWrite)
            );
        }

        // A second reorg with a clean window discards normally.
        let excl = cache.lock_flush_exclusion();
        let mut b = StoreBatch::default();
        b.coin_puts.push((make_outpoint(0xD5, 2), make_coin(100, 1)));
        cache.write_batch(b).unwrap();
        assert_eq!(cache.discard_uncommitted(&excl), Ok(()));
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

    /// Restoring `Normal` from `BulkLoad` must durably flush, by
    /// construction: WAL-less writes still in memtables are silently lost
    /// on process exit, so the transition itself has to checkpoint them —
    /// no caller can be trusted to remember (mainnet-952978 regression).
    #[test]
    fn bulkload_to_normal_transition_flushes_durably() {
        let inner = InMemoryStore::new();
        let durable_flushes = inner.flush_durable_counter();
        let cache = CoinCache::new(Box::new(inner), 64);

        cache.set_write_mode(WriteMode::BulkLoad);
        let mut batch = StoreBatch::default();
        batch
            .coin_puts
            .push((make_outpoint(0xEE, 0), make_coin(9_999, 7)));
        cache.write_batch(batch).unwrap();
        assert_eq!(
            durable_flushes.load(Ordering::Relaxed),
            0,
            "entering/holding BulkLoad must not flush on its own"
        );

        cache.set_write_mode(WriteMode::Normal);
        assert_eq!(
            durable_flushes.load(Ordering::Relaxed),
            1,
            "leaving BulkLoad must durably flush the backing store"
        );
        // The transition drained the cache's dirty map too (flush_durable
        // flushes the cache before the inner store), so the write survived.
        assert_eq!(cache.get_coin(&make_outpoint(0xEE, 0)).unwrap().amount, 9_999);

        // Normal -> Normal and Normal -> BulkLoad are not transitions out
        // of BulkLoad and must not flush.
        cache.set_write_mode(WriteMode::Normal);
        cache.set_write_mode(WriteMode::BulkLoad);
        assert_eq!(durable_flushes.load(Ordering::Relaxed), 1);
    }
}
