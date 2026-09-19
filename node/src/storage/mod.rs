pub mod blockfile_audit;
pub mod blockindex;
pub mod coin_cache;
pub mod coinview;
pub mod compressed_coin;
pub mod db;
pub mod flatfile;
pub mod profile;
pub mod rocksdb_store;
pub mod split_store;
#[cfg(test)]
pub(crate) mod test_store;
pub mod undo;

use bitcoin::{BlockHash, OutPoint, Txid};

use crate::index::address::cursor::BackfillState;
use crate::index::address::{
    AddrFundingKey, AddrFundingKeyV3, AddrFundingRowV3, AddrSpendingKey, AddrSpendingKeyV3,
    AddrSpendingRowV3, Scripthash,
};
#[cfg(feature = "block-filter-index")]
use crate::index::filter::{FilterHeaderRow, FilterKey, FilterRow};
use crate::index::outpoint_spend::SpendingRef;
use node_index::SpentRow;
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;

/// Self-consistent base captured during [`Store::for_each_coin_snapshot`].
///
/// All four fields are read from the **same** point-in-time view as the
/// coin iteration (for RocksDB, one `Snapshot` across every column
/// family). Because each chainstate commit writes the tip pointer, the
/// UTXO-count metadata, and the coin rows in a single atomic
/// `WriteBatch`, a single snapshot always observes a consistent
/// `(base_hash, base_height, coin_count)` triple together with the coins
/// it iterates — even if block connection commits concurrently. Callers
/// must therefore take `base_hash`/`base_height` from here, never from a
/// separately-locked in-memory tip, or the snapshot's advertised base
/// can drift from its contents.
#[derive(Debug, Clone, Copy)]
pub struct CoinSnapshotBase {
    /// Block hash the snapshot's UTXO set corresponds to.
    pub base_hash: BlockHash,
    /// Height of `base_hash`.
    pub base_height: u32,
    /// UTXO count recorded in metadata at the snapshot point-in-time.
    pub coin_count: u64,
    /// Coins actually yielded by the iteration. Equals `coin_count`
    /// unless the chainstate is corrupt (both are from the same view,
    /// so a mismatch is no longer a benign race).
    pub coins_written: u64,
}

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
///
/// **Remove-wins contract:** if the same key appears in both a family's
/// puts and removes within one batch, the key must end ABSENT. Both
/// emitters rely on this: `connect_block` carries a put+remove pair for
/// an output created and spent within the same block, and
/// `disconnect_block` carries the mirror pair (undo-restore put +
/// created-output remove) — in both shapes the correct final state is
/// absent. Implementations must apply puts before removes (or net the
/// pairs); regression tests pin this for `RocksDbStore` and
/// `InMemoryStore`.
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
    /// `first ordinal of the block -> height`. One row per connected
    /// block; `seek_for_prev` over this family turns any transaction
    /// ordinal back into the block that holds it, and the difference is
    /// the transaction's position within the block. Ungated: it is four
    /// bytes per block and every ordinal read needs it.
    pub txseq_block_puts: Vec<(u64, u32)>,
    pub txseq_block_removes: Vec<u64>,
    /// `txid -> ordinal`. Written for every transaction of every
    /// connected block when either `-txindex` or `-addressindex` is on.
    /// Replaces the old `tx_index` (`txid -> block_hash`): the ordinal
    /// carries the block *and* the position, so `getrawtransaction` can
    /// index into `txdata` instead of scanning the block for its txid.
    pub tx_loc_puts: Vec<(Txid, u64)>,
    pub tx_loc_removes: Vec<Txid>,
    /// `ordinal -> txid`, the inverse of `tx_loc`. This is what lets
    /// every other index drop its txid copies: the index rows key on
    /// ordinals and the storage layer resolves them back to txids in one
    /// batched `multi_get` before any row leaves it.
    pub txseq_txid_puts: Vec<(u64, Txid)>,
    pub txseq_txid_removes: Vec<u64>,
    /// Cumulative transaction count through each connected block:
    /// `(block_hash, nchaintx)` where `nchaintx = nchaintx(parent) + num_tx`.
    /// Written by `connect_block` for active-chain blocks and by the
    /// AssumeUTXO snapshot seed; consumed by `getchaintxstats`. Hash-keyed,
    /// so reorgs need no removal (a stale block's value stays correct for
    /// that block and is simply off the active chain).
    pub chain_tx_puts: Vec<(BlockHash, u64)>,
    /// Address-history index funding rows. Populated in M2.
    ///
    /// Keyed on the creating transaction's chain-order ordinal rather
    /// than its height and txid: 32 bytes a row against 64, with both
    /// recoverable through the ordinal families. The store resolves them
    /// before a row leaves it, so the public [`AddrFundingKey`] and
    /// every consumer above are unchanged.
    pub addr_funding_puts: Vec<AddrFundingRowV3>,
    /// Address-history index spending rows. Populated in M2.
    ///
    /// Keyed on the spending transaction's ordinal, and valued by the
    /// consumed output named the same way: 32 bytes a row against 92,
    /// with both txids the old row carried recoverable through the
    /// ordinal families. The store resolves them before a row leaves it.
    pub addr_spending_puts: Vec<AddrSpendingRowV3>,
    /// Address-history funding keys to remove (used by `disconnect_block`).
    pub addr_funding_removes: Vec<AddrFundingKeyV3>,
    /// Address-history spending keys to remove (used by `disconnect_block`).
    pub addr_spending_removes: Vec<AddrSpendingKeyV3>,
    /// `spent` rows. Written by `connect_block` for every input on the
    /// active chain so Esplora's `outspend` can answer in O(1).
    ///
    /// Both ends are named by transaction ordinal rather than txid: 16
    /// bytes a row where the txid-keyed predecessor took 76, and the
    /// identifiers it repeated are recoverable through `txseq_txid`.
    pub spent_puts: Vec<SpentRow>,
    /// `(funding ordinal, vout)` keys to remove from `spent` (used by
    /// `disconnect_block`).
    pub spent_removes: Vec<(u64, u32)>,
    /// `(outpoint -> (scripthash, funding ordinal))` rows for the
    /// deferred backfill's pass-1 temp CF. Empty for live
    /// `connect_block` writes.
    pub addr_backfill_temp_puts: Vec<(OutPoint, Scripthash, u64)>,
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
    /// BIP 352 silent-payment tweak rows, `(height, row)`. Populated by
    /// `connect_block`'s end-of-loop emit when the SP index is
    /// runtime-enabled and the height is at/above taproot activation.
    /// Always compiled (runtime opt-in, not a cargo feature) — the SP
    /// index follows the address-index model, so these fields are never
    /// `cfg`-gated.
    pub sp_tweak_puts: Vec<(u32, node_sp_index::SpBlockRow)>,
    /// Heights whose `sp_tweaks` row should be dropped. Used by
    /// `disconnect_block` when reversing a connected block. One row per
    /// height (keyed by `height_be`), so a single entry drops the block's
    /// tweak row; a subsequent connect at the same height overwrites it.
    pub sp_tweak_removes: Vec<u32>,
    /// Persist a silent-payment-index backfill cursor advance atomically
    /// with the tweak rows it describes. `None` for non-backfill writes.
    /// Always compiled (the SP index follows the address-index model, not
    /// a cargo feature), so this field is never `cfg`-gated. Mirrors
    /// `filter_backfill_cursor_advance` for the filter family.
    pub sp_backfill_cursor_advance: Option<SpBackfillCursorWrite>,
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

/// Atomic cursor update for the BIP 352 silent-payment-index backfill
/// task. Persisted in CF_METADATA under the `spindex.backfill.*`
/// namespace. Single-pass walk so there is no `pass` field. Bundling the
/// advance into the same `StoreBatch` as the tweak rows it describes
/// guarantees we never observe a half-advanced cursor on resume. Always
/// compiled (runtime opt-in, not a cargo feature).
#[derive(Debug, Clone, Copy)]
pub struct SpBackfillCursorWrite {
    pub state: node_sp_index::cursor::BackfillState,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub started_at_unix: u64,
    /// Active-chain anchor recorded at `start()` time. Same all-zero
    /// "don't care" sentinel semantics as the filter/address variants:
    /// per-block advances write the sentinel so the anchor recorded by
    /// `start()` is preserved.
    pub snapshot_tip_hash: [u8; 32],
}

impl StoreBatch {
    /// Merge another batch into this one (for atomic multi-block operations).
    ///
    /// Every keyed index's puts and removes are merged with
    /// last-writer-wins semantics by key: an incoming remove drops any
    /// prior put for the same key, and an incoming put drops any prior
    /// remove. This keeps the merged batch's puts/removes vectors
    /// disjoint by key, so a CoinCache pending batch correctly reflects
    /// the most-recent op for each key — important for connect→
    /// disconnect→connect (e.g. A→B→A reorgs) and disconnect→connect
    /// (alternate block at the same height containing the same row)
    /// sequences before flush.
    ///
    /// Each dedup block is guarded on BOTH vectors being non-empty. Guarding
    /// only the incoming one would build a set of every txid in the block on
    /// each connect — `connect_block` fills `tx_loc_puts` regardless of
    /// whether `-txindex` is on, so that is the default path — purely to
    /// filter a `tx_loc_removes` that is empty outside a reorg.
    ///
    /// Disjointness is what makes the merged batch order-independent at
    /// apply time. `Store` implementations write every put and then
    /// every remove within one `WriteBatch`, so a put and a remove that
    /// survived for the same key would resolve to "removed" regardless
    /// of which one the caller issued last. Any keyed field added here
    /// in future needs the same treatment; a plain `extend` silently
    /// turns a disconnect→connect sequence into a lost row.
    pub fn merge(&mut self, other: StoreBatch) {
        self.block_index_puts.extend(other.block_index_puts);
        self.coin_puts.extend(other.coin_puts);
        self.coin_removes.extend(other.coin_removes);
        if other.tip.is_some() {
            self.tip = other.tip;
        }

        // height→hash: last-writer-wins by height. A reorg disconnects
        // the displaced block (remove at H) and connects the replacement
        // (put at H) in separate `write_batch` calls that coalesce into
        // one pending batch, so without this the replacement's row is
        // annihilated by the earlier remove and `getblockhash H` fails
        // for a height in the middle of the active chain.
        if !other.height_hash_removes.is_empty() && !self.height_hash_puts.is_empty() {
            let drop: std::collections::HashSet<u32> =
                other.height_hash_removes.iter().copied().collect();
            self.height_hash_puts.retain(|(h, _)| !drop.contains(h));
        }
        if !other.height_hash_puts.is_empty() && !self.height_hash_removes.is_empty() {
            let drop: std::collections::HashSet<u32> =
                other.height_hash_puts.iter().map(|(h, _)| *h).collect();
            self.height_hash_removes.retain(|h| !drop.contains(h));
        }
        self.height_hash_puts.extend(other.height_hash_puts);
        self.height_hash_removes.extend(other.height_hash_removes);

        self.undo_puts.extend(other.undo_puts);

        // tx_loc: last-writer-wins by txid, same shape as the height
        // index. The trigger here is routine rather than incidental — a
        // reorg removes the displaced block's txids and the replacement
        // chain re-mines the same transactions, so put and remove collide
        // on one txid and `getrawtransaction` reports a transaction that
        // IS in the chain as unknown.
        if !other.tx_loc_removes.is_empty() && !self.tx_loc_puts.is_empty() {
            let drop: std::collections::HashSet<Txid> =
                other.tx_loc_removes.iter().copied().collect();
            self.tx_loc_puts.retain(|(txid, _)| !drop.contains(txid));
        }
        if !other.tx_loc_puts.is_empty() && !self.tx_loc_removes.is_empty() {
            let drop: std::collections::HashSet<Txid> =
                other.tx_loc_puts.iter().map(|(txid, _)| *txid).collect();
            self.tx_loc_removes.retain(|txid| !drop.contains(txid));
        }
        self.tx_loc_puts.extend(other.tx_loc_puts);
        self.tx_loc_removes.extend(other.tx_loc_removes);

        // txseq_txid and txseq_block: ordinal-keyed, and the same
        // collision applies. A reorg frees a range of ordinals and the
        // replacement chain reuses them immediately, so a remove from the
        // disconnect and a put from the reconnect land on the same key
        // inside one pending batch. Without the dedup the remove would
        // annihilate the replacement's row and every index keyed on that
        // ordinal would resolve to nothing.
        if !other.txseq_txid_removes.is_empty() && !self.txseq_txid_puts.is_empty() {
            let drop: std::collections::HashSet<u64> =
                other.txseq_txid_removes.iter().copied().collect();
            self.txseq_txid_puts.retain(|(seq, _)| !drop.contains(seq));
        }
        if !other.txseq_txid_puts.is_empty() && !self.txseq_txid_removes.is_empty() {
            let drop: std::collections::HashSet<u64> =
                other.txseq_txid_puts.iter().map(|(seq, _)| *seq).collect();
            self.txseq_txid_removes.retain(|seq| !drop.contains(seq));
        }
        self.txseq_txid_puts.extend(other.txseq_txid_puts);
        self.txseq_txid_removes.extend(other.txseq_txid_removes);

        if !other.txseq_block_removes.is_empty() && !self.txseq_block_puts.is_empty() {
            let drop: std::collections::HashSet<u64> =
                other.txseq_block_removes.iter().copied().collect();
            self.txseq_block_puts.retain(|(seq, _)| !drop.contains(seq));
        }
        if !other.txseq_block_puts.is_empty() && !self.txseq_block_removes.is_empty() {
            let drop: std::collections::HashSet<u64> =
                other.txseq_block_puts.iter().map(|(seq, _)| *seq).collect();
            self.txseq_block_removes.retain(|seq| !drop.contains(seq));
        }
        self.txseq_block_puts.extend(other.txseq_block_puts);
        self.txseq_block_removes.extend(other.txseq_block_removes);
        // chain_tx is hash-keyed; extend like block_index_puts (last write
        // for a given hash wins at flush time).
        self.chain_tx_puts.extend(other.chain_tx_puts);

        // addr_funding: incoming removes invalidate any prior put for
        // the same key, and incoming puts invalidate any prior remove.
        if !other.addr_funding_removes.is_empty() {
            let drop: std::collections::HashSet<AddrFundingKeyV3> =
                other.addr_funding_removes.iter().copied().collect();
            self.addr_funding_puts.retain(|p| !drop.contains(&p.key()));
        }
        if !other.addr_funding_puts.is_empty() {
            let drop: std::collections::HashSet<AddrFundingKeyV3> =
                other.addr_funding_puts.iter().map(|p| p.key()).collect();
            self.addr_funding_removes.retain(|k| !drop.contains(k));
        }
        self.addr_funding_puts.extend(other.addr_funding_puts);
        self.addr_funding_removes.extend(other.addr_funding_removes);

        // addr_spending: same last-writer-wins by key.
        if !other.addr_spending_removes.is_empty() {
            let drop: std::collections::HashSet<AddrSpendingKeyV3> =
                other.addr_spending_removes.iter().copied().collect();
            self.addr_spending_puts.retain(|p| !drop.contains(&p.key()));
        }
        if !other.addr_spending_puts.is_empty() {
            let drop: std::collections::HashSet<AddrSpendingKeyV3> =
                other.addr_spending_puts.iter().map(|p| p.key()).collect();
            self.addr_spending_removes.retain(|k| !drop.contains(k));
        }
        self.addr_spending_puts.extend(other.addr_spending_puts);
        self.addr_spending_removes
            .extend(other.addr_spending_removes);

        // spent: same last-writer-wins, now by (funding ordinal, vout).
        if !other.spent_removes.is_empty() {
            let drop: std::collections::HashSet<(u64, u32)> =
                other.spent_removes.iter().copied().collect();
            self.spent_puts.retain(|r| !drop.contains(&r.key()));
        }
        if !other.spent_puts.is_empty() {
            let drop: std::collections::HashSet<(u64, u32)> =
                other.spent_puts.iter().map(|r| r.key()).collect();
            self.spent_removes.retain(|k| !drop.contains(k));
        }
        self.spent_puts.extend(other.spent_puts);
        self.spent_removes.extend(other.spent_removes);

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

        // SP index: last-writer-wins by height. A connect → disconnect →
        // connect at the same height (an A→B→A reorg) must end with the
        // put winning, and a connect at a height whose row is in the prior
        // batch's removes must drop the remove. Mirrors the filter merge,
        // keyed by `u32` height instead of `(type, height)`.
        if !other.sp_tweak_removes.is_empty() {
            let drop: std::collections::HashSet<u32> =
                other.sp_tweak_removes.iter().copied().collect();
            self.sp_tweak_puts.retain(|(h, _)| !drop.contains(h));
        }
        if !other.sp_tweak_puts.is_empty() {
            let drop: std::collections::HashSet<u32> =
                other.sp_tweak_puts.iter().map(|(h, _)| *h).collect();
            self.sp_tweak_removes.retain(|h| !drop.contains(h));
        }
        self.sp_tweak_puts.extend(other.sp_tweak_puts);
        self.sp_tweak_removes.extend(other.sp_tweak_removes);

        // SP-index backfill cursor advance: incoming wins. Same shape as
        // the filter/address advance — the runner emits at most one
        // advance per WriteBatch, so we only ever need last-writer-wins
        // for the CoinCache pending-batch coalesce path (which the
        // backfill never feeds into; it writes through
        // `Store::write_batch` directly).
        if other.sp_backfill_cursor_advance.is_some() {
            self.sp_backfill_cursor_advance = other.sp_backfill_cursor_advance;
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

/// Counts of corruption surfaced during a `for_each_block_index` scan.
/// Diagnostics that consume this iterator (the blockfile audit, future
/// `block_index` integrity checks) surface these as separate fields
/// rather than silently treating bad rows as nonexistent — the
/// `block_index` is consensus-critical local state, and an unexpected
/// non-zero count here usually indicates the index itself needs repair.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockIndexScanStats {
    /// Rows whose key was not a valid 32-byte block hash.
    pub skipped_bad_key: u64,
    /// Rows whose value failed to bincode-decode as a `BlockIndexEntry`.
    pub skipped_bad_value: u64,
}

/// Counts of corruption surfaced during a `for_each_height_hash` scan.
/// Mirrors [`BlockIndexScanStats`]: a bad row is reported rather than
/// silently treated as absent, because the caller's whole purpose is
/// deciding which heights have no row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeightHashScanStats {
    /// Rows whose key was not a 4-byte height.
    pub skipped_bad_key: u64,
    /// Rows whose value was not a 32-byte block hash.
    pub skipped_bad_value: u64,
}

/// Abstract storage backend for block index, UTXO set, and metadata.
pub trait Store: Send + Sync {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry>;
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
    fn has_coin(&self, outpoint: &OutPoint) -> bool;
    fn get_tip(&self) -> Option<BlockHash>;
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash>;
    /// Cumulative number of transactions in the chain through (and
    /// including) the given block, as written by `connect_block` /
    /// the AssumeUTXO seed. `None` if not yet recorded for this block
    /// (e.g. a pre-snapshot block whose background validation hasn't
    /// reached it). Consumed by `getchaintxstats`. Default: `None` for
    /// backends that don't track it.
    fn get_cumulative_tx_count(&self, _hash: &BlockHash) -> Option<u64> {
        None
    }
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError>;
    /// Write with the given durability mode. Default delegates to
    /// `write_batch` (ignoring the mode) — concrete backends that can honor
    /// `BulkLoad` should override.
    fn write_batch_mode(&self, batch: StoreBatch, _mode: WriteMode) -> Result<(), StoreError> {
        self.write_batch(batch)
    }
    /// Write a batch, handing it back if the write fails.
    ///
    /// `write_batch`'s contract says nothing about the batch on error, and
    /// every implementation consumes it. That is fine for a caller that still
    /// owns the state the batch describes, and wrong for `CoinCache::flush`,
    /// which drains its dirty map, its buffered non-coin rows and its pending
    /// tip to *build* one: a transient write error there destroys the whole
    /// delta with nothing left to retry from. This is the variant it uses.
    ///
    /// On failure, `Err((Some(returned), e))` hands back the **unapplied
    /// remainder**: replaying `returned` (plus anything written since)
    /// produces the correct final state. For a single-store backend that is
    /// the whole batch, untouched — the write either landed atomically or
    /// not at all. A layered store may return less than it was given when
    /// part of the batch *did* land durably and must not be replayed:
    /// `SplitStore` returns only the coins half when its block half is
    /// already in, and `CoinCache` absorbs what it buffers before passing
    /// the rest through, so its returned batch is the filtered pass-through
    /// remainder, not the caller's original. Callers restore state from the
    /// returned batch; they must not assume it is byte-identical to what
    /// they passed in.
    ///
    /// `Err((None, e))` means the write may be **partially applied** in a
    /// way that cannot be described for replay, and nothing may be
    /// restored. The batch is boxed so the error variant stays small on the
    /// success path, which is every call but the failing one.
    ///
    /// Deliberately without a default implementation. A default would have to
    /// either consume the batch (turning every non-overriding store's caller
    /// restore path into a silent no-op — the exact shape of bug this method
    /// exists to prevent) or clone it (a per-flush copy of the UTXO delta).
    /// Neither is a reasonable thing to inherit by omission.
    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)>;
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
    ///
    /// Composed from the two ordinal families: `tx_loc` gives the
    /// transaction's ordinal, `txseq_block` the block that holds it. A
    /// caller that also wants the position inside the block should use
    /// [`get_tx_seq`](Self::get_tx_seq) and [`block_of_seq`](Self::block_of_seq)
    /// directly rather than scanning the block for the txid.
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash>;
    /// Whether this store has txindex enabled.
    ///
    /// This is the `-txindex` *flag*, i.e. Core's `getrawtransaction`
    /// capability — not whether the ordinal families hold rows. The
    /// address index populates them too, so a node with
    /// `-txindex=0 -addressindex=1` answers `false` here while
    /// [`get_tx_seq`](Self::get_tx_seq) still resolves.
    fn has_txindex(&self) -> bool;

    /// A transaction's chain-order ordinal, or `None` when the ordinal
    /// families are empty for it.
    ///
    /// Ungated by the `-txindex` flag, unlike `get_tx_location`: the rows
    /// exist whenever either `-txindex` or `-addressindex` is on, and the
    /// address index needs them regardless of what `-txindex` says.
    /// Default: `None` for backends with no ordinal index.
    fn get_tx_seq(&self, _txid: &Txid) -> Option<u64> {
        None
    }

    /// Resolve ordinals back to txids, in the order given.
    ///
    /// Batched on purpose: this is the read-side inverse of every index
    /// row that dropped its txid copy, so it runs once per scan over
    /// hundreds of rows rather than once per row. `None` in a slot means
    /// the ordinal has no row, which on a healthy chainstate cannot
    /// happen for an ordinal that came out of an index row — callers
    /// treat it as local corruption, skip the row and log.
    /// Default: all `None`.
    fn txids_of_seqs(&self, seqs: &[u64]) -> Vec<Option<Txid>> {
        vec![None; seqs.len()]
    }

    /// The block holding an ordinal: `(first ordinal of that block,
    /// height)`. The ordinal's position inside the block is
    /// `seq - first_txseq`.
    ///
    /// `None` when no block covers the ordinal — including an ordinal
    /// past the tip, which `seek_for_prev` would otherwise answer with
    /// the last block. Default: `None`.
    fn block_of_seq(&self, _seq: u64) -> Option<(u64, u32)> {
        None
    }
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

    /// Stream every `(OutPoint, Coin)` pair in the UTXO set, in
    /// `(txid_bytes, vout_le_bytes)` ascending key order, through the
    /// callback `f`. Returns the total number of coins iterated.
    ///
    /// Backends that can take a point-in-time view (e.g. RocksDB
    /// `Snapshot`) MUST use one so the iteration is isolated from
    /// concurrent writes. Callers are responsible for flushing any
    /// in-memory caches (e.g. `CoinCache::flush`) before calling, so
    /// that pending writes are visible to the snapshot.
    ///
    /// Returns a [`CoinSnapshotBase`] whose `base_hash`/`base_height`/
    /// `coin_count` are read from the **same** point-in-time view as the
    /// iteration. `dumptxoutset` must use that base for the snapshot
    /// header rather than the in-memory chain tip: block connection
    /// commits the coin batch before publishing the in-memory tip, so a
    /// base read from the in-memory tip can name a different block than
    /// the coins the snapshot actually contains.
    ///
    /// Used by `dumptxoutset` to emit AssumeUTXO snapshot files. The
    /// closure receives borrowed references so backends don't have to
    /// heap-allocate per coin.
    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<CoinSnapshotBase, StoreError>;

    /// Live-resize the block cache (e.g. RocksDB's shared LRU). Called by
    /// the adaptive-dbcache controller. Default: no-op for backends without
    /// a resizable cache.
    fn resize_block_cache(&self, _bytes: usize) {}

    /// Current block-cache capacity in bytes if observable. Default: 0.
    fn block_cache_capacity_bytes(&self) -> usize {
        0
    }

    /// Byte budget of the in-memory *coin* cache, behind `getchainstates`'
    /// `coins_tip_cache_bytes`. `None` for a backend with no such cache.
    ///
    /// The figure is the configured budget, not measured usage — which is
    /// also what Core reports, so the two are comparable. satd's cache is
    /// bounded by entry count; this is the byte budget that count was
    /// derived from.
    fn coins_tip_cache_bytes(&self) -> Option<u64> {
        None
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

    /// Per-column-family pending-compaction-bytes breakdown. Used by the
    /// diagnostic logger to surface which CF is falling behind — the
    /// chainstate-wide `coins`-only number missed the actual culprits
    /// during the mainnet IBD incident (addr_funding, addr_spending,
    /// outpoint_spend, undo accumulated ~370 GB combined while `coins`
    /// stayed healthy at 8.6 GB). Returns `(cf_name, bytes)` pairs in
    /// declaration order. Default: empty (non-RocksDB backends have no
    /// pending-compaction concept).
    fn pending_compaction_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }

    /// Per-column-family total on-disk SST size in bytes. Companion to
    /// [`pending_compaction_bytes_by_cf`](Self::pending_compaction_bytes_by_cf):
    /// the pending number tells you *whether* the LSM is keeping up;
    /// this tells you *where* the bytes actually live. Surfaced at
    /// startup and inside the 60s diagnostic snapshot so operators
    /// can answer "is my chainstate footprint dominated by coins,
    /// tx_index, or one of the address indexes?" without an offline
    /// `ldb` dump. Default: empty.
    fn sst_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }

    /// Per-column-family estimated live key count. Third leg of the
    /// footprint diagnostics: `sst_bytes_by_cf` says how much disk a
    /// family occupies, this says across how many rows, and their
    /// quotient is the effective post-compression bytes per row — the
    /// number that decides whether a family is worth re-encoding.
    /// Default: empty.
    fn estimated_keys_by_cf(&self) -> Vec<(&'static str, u64)> {
        Vec::new()
    }

    /// Iterate every `block_index` entry, invoking `visit` once per row.
    /// Used by the blockfile slack audit (and any other diagnostic that
    /// needs the full block_index set). Order is unspecified. Returning
    /// is non-cancellable — visitors must accept all rows.
    ///
    /// Rows whose key fails to decode as a 32-byte hash or whose value
    /// fails bincode decode are NOT passed to `visit`; their counts are
    /// returned in [`BlockIndexScanStats`] so diagnostics can surface
    /// (and not silently mask) `block_index` corruption.
    ///
    /// Default: no-op for backends that don't carry a block_index (in-
    /// memory test store, etc.) — returns zero stats.
    fn for_each_block_index(
        &self,
        _visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<BlockIndexScanStats, StoreError> {
        Ok(BlockIndexScanStats::default())
    }

    /// Visit every persisted height→hash row.
    ///
    /// `get_block_hash_by_height` answers one height; this walks the whole
    /// index sequentially, which is the cheap way to find heights that have
    /// no row at all. Rows arrive in the index's own key order — the key is
    /// a little-endian height, so that order is not numeric and callers must
    /// not assume it is.
    ///
    /// The default refuses rather than reporting an empty scan. A caller that
    /// read "no rows" as "every height is missing" would set about rewriting
    /// the entire index, so an unimplemented backend has to be distinguishable
    /// from a genuinely empty one.
    fn for_each_height_hash(
        &self,
        _visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<HeightHashScanStats, StoreError> {
        Err(StoreError::Database(
            "height→hash scan not supported by this store".into(),
        ))
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
    /// layout in `keys::encode_funding_key_v2`). Returns the value
    /// `amount_sat` alongside the decoded key. Default: empty (backends
    /// that don't carry the address index produce no rows).
    fn iter_addr_funding(&self, _sh: &Scripthash) -> Vec<(AddrFundingKey, u64)> {
        Vec::new()
    }

    /// Like [`iter_addr_funding`](Self::iter_addr_funding), but bounds
    /// the work to at most `limit` rows. Used by streaming-cap
    /// callers (Electrum / Esplora `get_history`, `listunspent`) so a
    /// pathologically large scripthash can't force a full RocksDB
    /// scan + Vec allocation just to fail the per-request cap check.
    ///
    /// Default: forwards to the unlimited variant + truncates
    /// (correct but unoptimized).
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
    /// bounds the work per source-format CF. See
    /// [`iter_addr_funding_limited`](Self::iter_addr_funding_limited)
    /// for the per-CF vs total cap contract. Round-1 review M4.
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

    /// True when the `spent` index is fully populated for every input
    /// on the active chain. Set on fresh datadir creation, after
    /// `clear_chainstate`/`clear_all`, and after address-backfill
    /// `mark_completed`. False when an upgraded datadir still has
    /// historical `addr_spending` rows that pre-date this index, and
    /// after an AssumeUTXO snapshot load. Default: `true` for non-Rocks
    /// backends.
    ///
    /// The public JSON names that report it — `txospenderindex` in
    /// `getindexinfo`, `address.outpoint_spend.complete` in
    /// `getsatdindexinfo` — are unchanged; they name the capability, not
    /// the column family behind it.
    fn spent_complete(&self) -> bool {
        true
    }

    /// Stamp `spent.complete` true. Called by the runner when address
    /// backfill finishes pass 2 (which writes `spent` rows alongside
    /// addr_spending rows). Default: no-op for backends that don't
    /// track the marker.
    fn mark_spent_complete(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// Stamp the address and spend completeness markers false after an
    /// AssumeUTXO snapshot load.
    ///
    /// A snapshot brings a UTXO set with no history behind it: the
    /// address and spend indexes hold nothing for anything below the
    /// snapshot base, and the operator's documented remedy is
    /// `backfillindex address` once background validation has reached
    /// it. Leaving the markers true would let those surfaces answer
    /// "unspent" and "no history" for outputs whose history the node
    /// simply does not have yet. Default: no-op.
    fn mark_index_incomplete_after_snapshot(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// Every spend of the transaction with ordinal `funding_txseq`, as
    /// `(vout, SpendingRef)` pairs.
    ///
    /// One prefix scan over `spent`, which is what the 5-byte ordinal
    /// prefix is for. Esplora's `/tx/:txid/outspends` uses it so an
    /// N-output transaction costs one txid lookup rather than N.
    /// Default: empty.
    fn lookup_spends_of_tx(&self, _txid: &bitcoin::Txid) -> Result<Vec<(u32, SpendingRef)>, StoreError> {
        Ok(Vec::new())
    }

    /// True when the `tx_index` CF is fully populated for every tx
    /// on the active chain. Round-3 H1: required for Esplora's tx
    /// endpoints to give correct answers. False on upgraded
    /// datadirs that previously ran with `--txindex=0`. Default:
    /// `true` for non-Rocks backends.
    fn tx_index_complete(&self) -> bool {
        true
    }

    /// True when the `chain_tx` cumulative-count CF has been backfilled
    /// for the active chain (the one-shot startup migration ran). False
    /// on an upgraded datadir before the backfill. Default: `true` for
    /// non-Rocks backends (in-memory stores are always freshly built).
    fn chain_tx_backfill_complete(&self) -> bool {
        true
    }

    /// Stamp the `chain_tx.backfill_complete` marker true. Called once
    /// the startup backfill has populated the cumulative-count CF for
    /// the active chain. Default: no-op for backends that don't track it.
    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// Lowest height whose block data is still on disk — Core's
    /// `pruneheight`. `None` when the node has never pruned, which is what
    /// makes the RPC field absent rather than zero: Core emits `pruneheight`
    /// only for a node that has actually deleted something, and a `0` would
    /// claim "everything from genesis is here" on a node that had pruned.
    ///
    /// Persisted rather than derived. Deriving it means finding the lowest
    /// height whose block is not `Pruned`, and pruning deletes whole *files*
    /// while `repair_block_data` can append an old-height block to the
    /// current one — so the pruned set is not reliably a prefix and a binary
    /// search over it can land on the wrong side. Default: `None` for
    /// backends that don't track it.
    fn prune_height(&self) -> Option<u32> {
        None
    }

    /// Record the new prune floor. Default: no-op for backends that don't
    /// track it.
    fn set_prune_height(&self, _height: u32) -> Result<(), StoreError> {
        Ok(())
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

    /// Look up `(outpoint -> (scripthash, funding ordinal))` from the
    /// temp CF. Returns `Ok(None)` when the CF doesn't exist or the key
    /// isn't present; `Err` only on backend I/O failure. Default:
    /// `Ok(None)`.
    ///
    /// Pass 1 records the ordinal alongside the scripthash because pass
    /// 2 needs both and cannot recompute either: the scripthash lives in
    /// the funding output's block, and the ordinal in that block's
    /// position in the chain. Looking each up again would mean a second
    /// read per input over the whole chain.
    fn lookup_backfill_temp(
        &self,
        _outpoint: &OutPoint,
    ) -> Result<Option<(Scripthash, u64)>, StoreError> {
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

    /// Read the decoded BIP 352 tweak row for the block at `height`.
    /// `None` when the row doesn't exist (below taproot activation, above
    /// tip, or a not-yet-backfilled range) or the backend has no SP-index
    /// storage. The row carries the hash of the block it describes
    /// (§3.2), so callers verify identity without a height→hash lookup.
    /// Default: `None`.
    fn get_sp_tweaks_row(&self, _height: u32) -> Option<node_sp_index::SpBlockRow> {
        None
    }

    /// Like [`Store::get_sp_tweaks_row`] but distinguishes a genuine absence
    /// (`Ok(None)` — below activation, above tip, not-yet-backfilled) from a
    /// storage read or decode failure (`Err`). The serving path uses this so a
    /// transient read error or an on-disk-corrupt row is surfaced to the client
    /// rather than silently skipped as an empty height — which, in an unclamped
    /// tweaks-only cold-sync, would be an undetectable gap that makes a scanning
    /// client miss payments. Default: best-effort via
    /// [`Store::get_sp_tweaks_row`] (backends without SP storage cannot fail
    /// distinctly from "absent").
    fn get_sp_tweaks_row_checked(
        &self,
        height: u32,
    ) -> Result<Option<node_sp_index::SpBlockRow>, StoreError> {
        Ok(self.get_sp_tweaks_row(height))
    }

    /// True when the BIP 352 tweak index is fully populated for the
    /// active chain (`sp_index.complete` marker set). Symmetric to
    /// `block_filter_index_complete`. Default: `true` for backends
    /// without SP-index storage.
    fn silent_payment_index_complete(&self) -> bool {
        true
    }

    /// Stamp `sp_index.complete` true. Called by the SP-index backfill
    /// runner when it finishes the snapshot range. Default: error so
    /// non-Rocks backends fail loud rather than silently no-op.
    fn mark_silent_payment_index_complete(&self) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "mark_silent_payment_index_complete not supported on this backend".into(),
        ))
    }

    /// Read the persisted SP-index backfill cursor from metadata.
    /// Default: idle. Mirrors `read_filter_backfill_cursor` but reads the
    /// `spindex.backfill.*` keyspace.
    fn read_sp_backfill_cursor(&self) -> node_sp_index::cursor::BackfillCursor {
        node_sp_index::cursor::BackfillCursor::idle()
    }

    /// Read the persisted last-error message that goes with the SP-index
    /// `BackfillState::Failed`. Default: `None`.
    fn read_sp_backfill_last_error(&self) -> Option<String> {
        None
    }

    /// Write or clear the persisted SP-index-backfill last-error message.
    /// Pass an empty string to clear.
    fn write_sp_backfill_last_error(&self, _msg: &str) -> Result<(), StoreError> {
        Err(StoreError::Database(
            "write_sp_backfill_last_error not supported on this backend".into(),
        ))
    }
}
