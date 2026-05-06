pub mod blockindex;
pub mod coin_cache;
pub mod coinview;
pub mod db;
pub mod flatfile;
pub mod rocksdb_store;
pub mod undo;

use bitcoin::{BlockHash, OutPoint, Txid};

use crate::index::address::cursor::BackfillState;
use crate::index::address::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, Scripthash,
};
#[cfg(feature = "block-filter-index")]
use crate::index::filter::{FilterHeaderRow, FilterKey, FilterRow};
use crate::index::outpoint_spend::SpendingRef;
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomic batch of writes for a single block connection/disconnection.
#[derive(Default)]
pub struct StoreBatch {
    pub block_index_puts: Vec<(BlockHash, BlockIndexEntry)>,
    pub coin_puts: Vec<(OutPoint, Coin)>,
    /// (outpoint, spent_amount, spent_height) — carried for O(1) counter/histogram updates.
    pub coin_removes: Vec<(OutPoint, u64, u32)>,
    pub tip: Option<BlockHash>,
    pub height_hash_puts: Vec<(u32, BlockHash)>,
    pub height_hash_removes: Vec<u32>,
    pub undo_puts: Vec<(BlockHash, UndoData)>,
    pub tx_index_puts: Vec<(Txid, BlockHash)>,
    pub tx_index_removes: Vec<Txid>,
    /// Address-history index funding rows. Populated in M2.
    pub addr_funding_puts: Vec<AddrFundingRow>,
    /// Address-history index spending rows. Populated in M2.
    pub addr_spending_puts: Vec<AddrSpendingRow>,
    /// Address-history funding keys to remove (used by `disconnect_block`).
    pub addr_funding_removes: Vec<AddrFundingKey>,
    /// Address-history spending keys to remove (used by `disconnect_block`).
    pub addr_spending_removes: Vec<AddrSpendingKey>,
    /// `outpoint_spend` rows: `(spent_outpoint, SpendingRef)`. Written by
    /// `connect_block` for every input on the active chain so Esplora's
    /// `outspend` and `gettxspendingprevout` (confirmed-side) can answer
    /// in O(1).
    pub outpoint_spend_puts: Vec<(OutPoint, SpendingRef)>,
    /// Outpoints to remove from `outpoint_spend` (used by `disconnect_block`).
    pub outpoint_spend_removes: Vec<OutPoint>,
    /// `(outpoint -> scripthash)` rows for the deferred backfill's pass-1
    /// temp CF. Empty for live `connect_block` writes.
    pub addr_backfill_temp_puts: Vec<(OutPoint, Scripthash)>,
    /// Persist a backfill cursor advance atomically with the rows it
    /// describes. `None` for non-backfill writes.
    pub backfill_cursor_advance: Option<BackfillCursorWrite>,
    /// BIP 158 compact-block-filter rows. Populated by
    /// `connect_block`'s end-of-loop emit when the filter index is
    /// runtime-enabled.
    #[cfg(feature = "block-filter-index")]
    pub filter_puts: Vec<FilterRow>,
    /// BIP 157 chained filter-header rows. Same emission point as
    /// `filter_puts`; one row per connected block.
    #[cfg(feature = "block-filter-index")]
    pub filter_header_puts: Vec<FilterHeaderRow>,
    /// `(filter_type, height)` keys to drop from both `cf_filter` and
    /// `cf_filter_header`. Used by `disconnect_block` when reversing a
    /// connected block's filter rows.
    #[cfg(feature = "block-filter-index")]
    pub filter_removes: Vec<FilterKey>,
    /// Persist a filter-index backfill cursor advance atomically with
    /// the filter rows it describes. `None` for non-backfill writes.
    /// Mirrors `backfill_cursor_advance` for the address-index family.
    #[cfg(feature = "block-filter-index")]
    pub filter_backfill_cursor_advance: Option<FilterBackfillCursorWrite>,
}

/// Atomic cursor update emitted by the backfill task at each batch boundary.
/// Persisted in the metadata CF using the keys declared in
/// `crate::index::address::cursor`. Bundling the advance into the same
/// `StoreBatch` as the rows it describes guarantees we never observe a
/// half-advanced cursor on resume.
#[derive(Debug, Clone, Copy)]
pub struct BackfillCursorWrite {
    pub state: BackfillState,
    pub pass: u8,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    /// Active-chain anchor recorded at `start()` time. Persisted as
    /// 32 raw bytes under `META_KEY_SNAPSHOT_HASH`. All-zero is
    /// permitted (e.g. for resume-time updates that don't change the
    /// anchor) and skips the metadata write when the on-disk value
    /// already matches.
    pub snapshot_tip_hash: [u8; 32],
}

/// Atomic cursor update for the BIP 158 filter-index backfill task.
/// Persisted in CF_METADATA under the `filterindex.backfill.*`
/// namespace. Single-pass walk so there is no `pass` field. Bundling
/// the advance into the same `StoreBatch` as the filter rows it
/// describes guarantees we never observe a half-advanced cursor on
/// resume.
#[cfg(feature = "block-filter-index")]
#[derive(Debug, Clone, Copy)]
pub struct FilterBackfillCursorWrite {
    pub state: node_filter_index::cursor::BackfillState,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    /// Active-chain anchor recorded at `start()` time. Same all-zero
    /// "don't care" sentinel semantics as the address-index variant.
    pub snapshot_tip_hash: [u8; 32],
}

impl StoreBatch {
    /// Merge another batch into this one (for atomic multi-block operations).
    ///
    /// Address-index puts and removes are merged with last-writer-wins
    /// semantics by key: an incoming remove drops any prior put for
    /// the same key, and an incoming put drops any prior remove. This
    /// keeps the merged batch's puts/removes vectors disjoint by key,
    /// so a CoinCache pending batch correctly reflects the most-recent
    /// op for each address-index key — important for connect→
    /// disconnect→connect (e.g. A→B→A reorgs) and disconnect→connect
    /// (alternate block at the same height containing the same row)
    /// sequences before flush.
    pub fn merge(&mut self, other: StoreBatch) {
        self.block_index_puts.extend(other.block_index_puts);
        self.coin_puts.extend(other.coin_puts);
        self.coin_removes.extend(other.coin_removes);
        if other.tip.is_some() {
            self.tip = other.tip;
        }
        self.height_hash_puts.extend(other.height_hash_puts);
        self.height_hash_removes.extend(other.height_hash_removes);
        self.undo_puts.extend(other.undo_puts);
        self.tx_index_puts.extend(other.tx_index_puts);
        self.tx_index_removes.extend(other.tx_index_removes);

        // addr_funding: incoming removes invalidate any prior put for
        // the same key, and incoming puts invalidate any prior remove.
        if !other.addr_funding_removes.is_empty() {
            let drop: std::collections::HashSet<AddrFundingKey> =
                other.addr_funding_removes.iter().cloned().collect();
            self.addr_funding_puts.retain(|p| !drop.contains(&p.key()));
        }
        if !other.addr_funding_puts.is_empty() {
            let drop: std::collections::HashSet<AddrFundingKey> =
                other.addr_funding_puts.iter().map(|p| p.key()).collect();
            self.addr_funding_removes.retain(|k| !drop.contains(k));
        }
        self.addr_funding_puts.extend(other.addr_funding_puts);
        self.addr_funding_removes.extend(other.addr_funding_removes);

        // addr_spending: same last-writer-wins by key.
        if !other.addr_spending_removes.is_empty() {
            let drop: std::collections::HashSet<AddrSpendingKey> =
                other.addr_spending_removes.iter().cloned().collect();
            self.addr_spending_puts.retain(|p| !drop.contains(&p.key()));
        }
        if !other.addr_spending_puts.is_empty() {
            let drop: std::collections::HashSet<AddrSpendingKey> =
                other.addr_spending_puts.iter().map(|p| p.key()).collect();
            self.addr_spending_removes.retain(|k| !drop.contains(k));
        }
        self.addr_spending_puts.extend(other.addr_spending_puts);
        self.addr_spending_removes
            .extend(other.addr_spending_removes);

        // outpoint_spend: same last-writer-wins by outpoint.
        if !other.outpoint_spend_removes.is_empty() {
            let drop: std::collections::HashSet<OutPoint> =
                other.outpoint_spend_removes.iter().copied().collect();
            self.outpoint_spend_puts
                .retain(|(op, _)| !drop.contains(op));
        }
        if !other.outpoint_spend_puts.is_empty() {
            let drop: std::collections::HashSet<OutPoint> = other
                .outpoint_spend_puts
                .iter()
                .map(|(op, _)| *op)
                .collect();
            self.outpoint_spend_removes.retain(|op| !drop.contains(op));
        }
        self.outpoint_spend_puts.extend(other.outpoint_spend_puts);
        self.outpoint_spend_removes
            .extend(other.outpoint_spend_removes);

        // Backfill temp-CF rows. Last-writer-wins semantics by outpoint
        // would matter only if a single coalesced batch covered both
        // pass-1 emission and a hypothetical pass-1-rerun for the same
        // height, which the runner never does. Plain extend is correct.
        self.addr_backfill_temp_puts
            .extend(other.addr_backfill_temp_puts);

        // Cursor advance: incoming wins. The runner emits at most one
        // advance per WriteBatch; merging is exercised only by the
        // CoinCache's pending-batch coalescing path, which the backfill
        // never feeds into (it writes through `Store::write_batch`
        // directly).
        if other.backfill_cursor_advance.is_some() {
            self.backfill_cursor_advance = other.backfill_cursor_advance;
        }

        // Filter index: same last-writer-wins by `(type, height)`.
        // Connect → disconnect → connect at the same height (an A→B→A
        // reorg) must end with the put winning, and connect at a
        // height whose row is in the prior batch's removes must drop
        // the remove. Mirrors the addr_funding / addr_spending merge.
        #[cfg(feature = "block-filter-index")]
        {
            if !other.filter_removes.is_empty() {
                let drop: std::collections::HashSet<FilterKey> =
                    other.filter_removes.iter().copied().collect();
                self.filter_puts.retain(|p| !drop.contains(&p.key));
                self.filter_header_puts.retain(|p| !drop.contains(&p.key));
            }
            if !other.filter_puts.is_empty() {
                let drop: std::collections::HashSet<FilterKey> =
                    other.filter_puts.iter().map(|p| p.key).collect();
                self.filter_removes.retain(|k| !drop.contains(k));
            }
            self.filter_puts.extend(other.filter_puts);
            self.filter_header_puts.extend(other.filter_header_puts);
            self.filter_removes.extend(other.filter_removes);

            // Filter-index backfill cursor advance: incoming wins.
            // Same shape as the address-index advance — the runner emits
            // at most one advance per WriteBatch, so we only ever need
            // last-writer-wins for the CoinCache pending-batch coalesce
            // path (which the backfill never feeds into; it writes
            // through `Store::write_batch` directly).
            if other.filter_backfill_cursor_advance.is_some() {
                self.filter_backfill_cursor_advance = other.filter_backfill_cursor_advance;
            }
        }
    }
}

/// Write-durability mode for `Store::write_batch`.
///
/// `Normal` is the safe default: writes go through the WAL so a crash
/// recovers to the last committed write. `BulkLoad` disables the WAL
/// for IBD, trading some crash-recovery latency for ~20-50% less write
/// I/O during the sync. A `Store::flush()` must be called periodically
/// in this mode (and before switching back to `Normal`) to bound the
/// amount of work replayed after a crash.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum WriteMode {
    #[default]
    Normal,
    BulkLoad,
}

/// Abstract storage backend for block index, UTXO set, and metadata.
pub trait Store: Send + Sync {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry>;
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
    fn has_coin(&self, outpoint: &OutPoint) -> bool;
    fn get_tip(&self) -> Option<BlockHash>;
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash>;
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError>;
    /// Write with the given durability mode. Default delegates to
    /// `write_batch` (ignoring the mode) — concrete backends that can honor
    /// `BulkLoad` should override.
    fn write_batch_mode(&self, batch: StoreBatch, _mode: WriteMode) -> Result<(), StoreError> {
        self.write_batch(batch)
    }
    /// Force any in-memory state to durable storage. Used after a run of
    /// `BulkLoad` writes to ensure crash recovery is bounded.
    /// Default: no-op (in-memory or always-synchronous backends).
    fn flush_durable(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData>;
    fn coin_count(&self) -> u64;
    /// Sum the total amount (in satoshis) across all UTXOs.
    fn coin_total_amount(&self) -> u64;
    /// UTXO creation height histogram. Each element is the count of UTXOs created
    /// in a 1000-block range: index 0 = heights 0-999, index 1 = 1000-1999, etc.
    fn utxo_height_hist(&self) -> Vec<u64>;
    /// Look up which block contains a transaction (txindex).
    /// Returns None if txindex is disabled or the txid is not found.
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash>;
    /// Whether this store has txindex enabled.
    fn has_txindex(&self) -> bool;
    /// Clear UTXO set, undo data, tx index, and tip. Keep block index intact.
    /// Used by `-reindex-chainstate`.
    fn clear_chainstate(&self) -> Result<(), StoreError>;
    /// Clear everything: block index, UTXO set, undo data, tx index, height index, tip.
    /// Used by `-reindex`.
    fn clear_all(&self) -> Result<(), StoreError>;

    /// Batch lookup of multiple coins. Default implementation calls get_coin() in a loop.
    /// RocksDB overrides with multi_get_cf() for significantly better I/O scheduling.
    fn get_coins_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        outpoints.iter().map(|op| self.get_coin(op)).collect()
    }

    /// Live-resize the block cache (e.g. RocksDB's shared LRU). Called by
    /// the adaptive-dbcache controller. Default: no-op for backends without
    /// a resizable cache.
    fn resize_block_cache(&self, _bytes: usize) {}

    /// Current block-cache capacity in bytes if observable. Default: 0.
    fn block_cache_capacity_bytes(&self) -> usize {
        0
    }

    /// Number of L0 SST files in the chainstate (coins) column family. Used
    /// by the IBD connector for backpressure: when the count exceeds the
    /// configured pause threshold, the connector pauses to let compaction
    /// catch up. Default: 0 (backends without leveled storage report no
    /// pressure, so the connector never pauses).
    fn chainstate_l0_files(&self) -> u64 {
        0
    }

    /// Estimated bytes of pending compaction work for the chainstate (coins)
    /// column family. Diagnostic signal logged alongside the L0 file count;
    /// the periodic compactor consults it to decide whether a forced
    /// compaction is overdue. Default: 0.
    fn chainstate_pending_compaction_bytes(&self) -> u64 {
        0
    }

    /// Force a full compaction of the chainstate (coins) column family.
    /// Called by the periodic compactor when the L0 file count or pending-
    /// compaction backlog has stayed above its threshold for too long, and
    /// by operators via RPC if exposed. Synchronous: returns once RocksDB
    /// has finished the compaction range. Default: no-op (Ok) for backends
    /// without compaction.
    fn compact_chainstate(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// All committed `addr_funding` rows for `sh`, ordered ascending by
    /// `(height, txid, vout)` (i.e. ascending by encoded key — the BE
    /// layout in `keys::encode_funding_key`). Returns the value
    /// `amount_sat` alongside the decoded key. Default: empty (backends
    /// that don't carry the address index produce no rows).
    fn iter_addr_funding(&self, _sh: &Scripthash) -> Vec<(AddrFundingKey, u64)> {
        Vec::new()
    }

    /// Like [`iter_addr_funding`](Self::iter_addr_funding), but stops
    /// after collecting `limit` rows. Used by streaming-cap callers
    /// (Electrum / Esplora `get_history`, `listunspent`) so a
    /// pathologically large scripthash can't force a full RocksDB
    /// scan + Vec allocation just to fail the per-request cap check.
    /// Round-1 review M4. Default: forwards to the unlimited
    /// variant + truncates (correct but unoptimized).
    fn iter_addr_funding_limited(
        &self,
        sh: &Scripthash,
        limit: usize,
    ) -> Vec<(AddrFundingKey, u64)> {
        let mut v = self.iter_addr_funding(sh);
        v.truncate(limit);
        v
    }

    /// All committed `addr_spending` rows for `sh`, ordered ascending by
    /// `(height, txid, vin)`. Default: empty.
    fn iter_addr_spending(&self, _sh: &Scripthash) -> Vec<(AddrSpendingKey, bitcoin::OutPoint)> {
        Vec::new()
    }

    /// Like [`iter_addr_spending`](Self::iter_addr_spending), but
    /// stops after collecting `limit` rows. Round-1 review M4.
    fn iter_addr_spending_limited(
        &self,
        sh: &Scripthash,
        limit: usize,
    ) -> Vec<(AddrSpendingKey, bitcoin::OutPoint)> {
        let mut v = self.iter_addr_spending(sh);
        v.truncate(limit);
        v
    }

    /// Look up the input that spent `outpoint` on the active chain.
    /// Returns `Ok(None)` when the outpoint is unspent (still in
    /// `coins`) or has never existed; `Err` only on backend I/O
    /// failure. Default: `Ok(None)` so non-Rocks backends don't claim
    /// they have a spend index.
    fn lookup_spend(&self, _outpoint: &OutPoint) -> Result<Option<SpendingRef>, StoreError> {
        Ok(None)
    }

    /// True when the `outpoint_spend` index is fully populated for
    /// every input on the active chain. Set on fresh datadir
    /// creation, after `clear_chainstate`/`clear_all`, and after
    /// address-backfill `mark_completed`. False when an upgraded
    /// datadir still has historical `addr_spending` rows that
    /// pre-date this index. Default: `true` for non-Rocks backends.
    fn outpoint_spend_complete(&self) -> bool {
        true
    }

    /// Stamp `outpoint_spend.complete` true. Called by the runner
    /// when address backfill finishes pass 2 (which writes
    /// outpoint_spend rows alongside addr_spending rows). Default:
    /// no-op for backends that don't track the marker.
    fn mark_outpoint_spend_complete(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// True when the `tx_index` CF is fully populated for every tx
    /// on the active chain. Round-3 H1: required for Esplora's tx
    /// endpoints to give correct answers. False on upgraded
    /// datadirs that previously ran with `--txindex=0`. Default:
    /// `true` for non-Rocks backends.
    fn tx_index_complete(&self) -> bool {
        true
    }

    /// True when the address-history CFs are fully populated for the
    /// active chain. Required before binding any address-surface
    /// service (Electrum's `blockchain.scripthash.*`, Esplora's
    /// `/address/*`). False on upgraded datadirs that previously ran
    /// with `--addressindex=0`, or when a backfill is incomplete.
    /// Cleared atomically when a block connects with addressindex
    /// disabled. Default: `true` for non-Rocks backends. Round-1
    /// review H2.
    fn address_index_complete(&self) -> bool {
        true
    }

    /// Set the persisted `address_index.complete` marker to `true`.
    /// Called by the address-index backfill when it finishes pass 2
    /// (every row written, snapshot covered). Default: error so
    /// non-Rocks backends fail loud rather than silently no-op.
    /// Round-1 review H2.
    fn mark_address_index_complete(&self) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "mark_address_index_complete not supported on this backend".into(),
        ))
    }

    /// Lazily create the deferred-backfill temp CF
    /// (`addr_backfill_outpoint_to_scripthash`). Idempotent: succeeds if
    /// the CF already exists. Default: error so non-Rocks backends fail
    /// loud rather than silently no-op.
    fn create_backfill_temp_cf(&self) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "create_backfill_temp_cf not supported on this backend".into(),
        ))
    }

    /// Drop the deferred-backfill temp CF. Idempotent: succeeds if the
    /// CF doesn't exist. Default: error.
    fn drop_backfill_temp_cf(&self) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "drop_backfill_temp_cf not supported on this backend".into(),
        ))
    }

    /// Whether the deferred-backfill temp CF currently exists. Default: false.
    fn backfill_temp_cf_exists(&self) -> bool {
        false
    }

    /// Look up `(outpoint -> scripthash)` from the temp CF. Returns
    /// `Ok(None)` when the CF doesn't exist or the key isn't present;
    /// `Err` only on backend I/O failure. Default: `Ok(None)`.
    fn lookup_backfill_temp(&self, _outpoint: &OutPoint) -> Result<Option<Scripthash>, StoreError> {
        Ok(None)
    }

    /// Read a BIP 158 filter blob for `(filter_type, height)`. Returns
    /// `None` when the row doesn't exist (height not connected, or
    /// filter index never populated this height). Default: `None` for
    /// backends without filter-index storage.
    #[cfg(feature = "block-filter-index")]
    fn get_filter(&self, _filter_type: u8, _height: u32) -> Option<Vec<u8>> {
        None
    }

    /// Read a BIP 157 chained filter header for `(filter_type, height)`.
    /// Default: `None`.
    #[cfg(feature = "block-filter-index")]
    fn get_filter_header(&self, _filter_type: u8, _height: u32) -> Option<[u8; 32]> {
        None
    }

    /// True when the BIP 158 filter index is fully populated for the
    /// active chain. Symmetric to `address_index_complete` /
    /// `tx_index_complete`. Default: `true` for non-Rocks backends.
    #[cfg(feature = "block-filter-index")]
    fn block_filter_index_complete(&self) -> bool {
        true
    }

    /// Stamp `block_filter_index.complete` true. Called by the filter
    /// backfill (PR-3) when it finishes the snapshot range. Default:
    /// error so non-Rocks backends fail loud rather than silently
    /// no-op.
    #[cfg(feature = "block-filter-index")]
    fn mark_block_filter_index_complete(&self) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "mark_block_filter_index_complete not supported on this backend".into(),
        ))
    }

    /// Read the persisted backfill cursor from metadata. Default: idle.
    fn read_backfill_cursor(&self) -> crate::index::address::cursor::BackfillCursor {
        crate::index::address::cursor::BackfillCursor::idle()
    }

    /// Read the persisted last-error message that goes with
    /// `BackfillState::Failed`. Returns `None` when no error is
    /// recorded. Default: `None`.
    fn read_backfill_last_error(&self) -> Option<String> {
        None
    }

    /// Write or clear the persisted last-error message. Pass an empty
    /// string to clear (treated equivalently to a delete). Stored in
    /// the metadata CF so it survives restart.
    fn write_backfill_last_error(&self, _msg: &str) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "write_backfill_last_error not supported on this backend".into(),
        ))
    }

    /// Read the persisted filter-index backfill cursor from metadata.
    /// Default: idle. Mirrors `read_backfill_cursor` for the address
    /// family but reads the `filterindex.backfill.*` keyspace.
    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_cursor(&self) -> node_filter_index::cursor::BackfillCursor {
        node_filter_index::cursor::BackfillCursor::idle()
    }

    /// Read the persisted last-error message that goes with
    /// `filter_index` `BackfillState::Failed`. Default: `None`.
    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_last_error(&self) -> Option<String> {
        None
    }

    /// Write or clear the persisted filter-backfill last-error
    /// message. Pass an empty string to clear.
    #[cfg(feature = "block-filter-index")]
    fn write_filter_backfill_last_error(&self, _msg: &str) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "write_filter_backfill_last_error not supported on this backend".into(),
        ))
    }
}
