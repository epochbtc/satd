use bitcoin::{BlockHash, OutPoint, Txid};

use crate::index::address::{
    AddrFundingKey, AddrFundingRowV3, AddrSpendingKey, AddrSpendingRow, Scripthash,
};
#[cfg(feature = "block-filter-index")]
use crate::index::filter::FilterKey;
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError, WriteMode};
use node_index::SpendingRef;

/// In-memory storage backend for testing.
pub struct InMemoryStore {
    /// Counts `flush_durable` calls. Shared (`Arc`) so tests can keep a
    /// handle after boxing the store behind `dyn Store` and assert that
    /// durability checkpoints actually reached the backing store.
    flush_durable_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    block_index: parking_lot::RwLock<std::collections::HashMap<BlockHash, BlockIndexEntry>>,
    coins: parking_lot::RwLock<std::collections::HashMap<OutPoint, Coin>>,
    tip: parking_lot::RwLock<Option<BlockHash>>,
    height_index: parking_lot::RwLock<std::collections::HashMap<u32, BlockHash>>,
    undo: parking_lot::RwLock<std::collections::HashMap<BlockHash, UndoData>>,
    /// `txid -> ordinal`, and its inverse. `BTreeMap` for the
    /// ordinal-keyed side so `block_of_seq`'s "largest first_txseq not
    /// greater than this" has the same shape here as RocksDB's
    /// `seek_for_prev`.
    tx_loc: parking_lot::RwLock<std::collections::HashMap<Txid, u64>>,
    txseq_txid: parking_lot::RwLock<std::collections::BTreeMap<u64, Txid>>,
    /// `first ordinal of a block -> height`.
    txseq_block: parking_lot::RwLock<std::collections::BTreeMap<u64, u32>>,
    chain_tx: parking_lot::RwLock<std::collections::HashMap<BlockHash, u64>>,
    chain_tx_backfill_complete: parking_lot::RwLock<bool>,
    /// Lowest height whose block data is still held (Core's `pruneheight`).
    /// `None` until something is actually pruned.
    prune_height: parking_lot::RwLock<Option<u32>>,
    addr_funding: parking_lot::RwLock<Vec<AddrFundingRowV3>>,
    addr_spending: parking_lot::RwLock<Vec<AddrSpendingRow>>,
    /// `spent` rows, keyed `(funding ordinal, vout)` and valued
    /// `(spending ordinal, vin)` — the on-disk shape, so the in-memory
    /// backend exercises the same resolution path the real one does.
    /// `BTreeMap` so `lookup_spends_of_tx` can range over one funding
    /// transaction's outputs, as the RocksDB prefix scan does.
    spent: parking_lot::RwLock<std::collections::BTreeMap<(u64, u32), (u64, u32)>>,
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
    /// BIP 352 tweak rows, keyed by height. Always compiled (runtime
    /// opt-in), mirroring the always-present `outpoint_spend` map.
    sp_tweaks: parking_lot::RwLock<std::collections::HashMap<u32, node_sp_index::SpBlockRow>>,
    sp_complete: parking_lot::RwLock<bool>,
    /// Address- and spend-index completeness. The trait defaults both to
    /// `true` for non-Rocks backends, which is the right answer for a
    /// freshly built in-memory chain — but it makes the one transition
    /// that clears them, an AssumeUTXO snapshot load, unobservable from
    /// any in-memory test. Modelling them here is what lets a test see
    /// that a snapshot leaves the indexes marked incomplete.
    address_index_complete: parking_lot::RwLock<bool>,
    spent_complete: parking_lot::RwLock<bool>,
    sp_backfill_cursor: parking_lot::RwLock<node_sp_index::cursor::BackfillCursor>,
    sp_backfill_last_error: parking_lot::RwLock<Option<String>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            flush_durable_calls: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            block_index: parking_lot::RwLock::new(std::collections::HashMap::new()),
            coins: parking_lot::RwLock::new(std::collections::HashMap::new()),
            tip: parking_lot::RwLock::new(None),
            height_index: parking_lot::RwLock::new(std::collections::HashMap::new()),
            undo: parking_lot::RwLock::new(std::collections::HashMap::new()),
            tx_loc: parking_lot::RwLock::new(std::collections::HashMap::new()),
            txseq_txid: parking_lot::RwLock::new(std::collections::BTreeMap::new()),
            txseq_block: parking_lot::RwLock::new(std::collections::BTreeMap::new()),
            chain_tx: parking_lot::RwLock::new(std::collections::HashMap::new()),
            // Default false so a manually-populated InMemoryStore behaves
            // like an upgraded datadir (backfill runs); connect-driven test
            // chains populate chain_tx directly, so the backfill is a no-op
            // there regardless.
            chain_tx_backfill_complete: parking_lot::RwLock::new(false),
            prune_height: parking_lot::RwLock::new(None),
            addr_funding: parking_lot::RwLock::new(Vec::new()),
            addr_spending: parking_lot::RwLock::new(Vec::new()),
            spent: parking_lot::RwLock::new(std::collections::BTreeMap::new()),
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
            sp_tweaks: parking_lot::RwLock::new(std::collections::HashMap::new()),
            // Match the RocksDb default: tests that want a complete marker
            // stamp it explicitly (or drive a from-genesis connect chain,
            // which needs no backfill).
            sp_complete: parking_lot::RwLock::new(true),
            address_index_complete: parking_lot::RwLock::new(true),
            spent_complete: parking_lot::RwLock::new(true),
            sp_backfill_cursor: parking_lot::RwLock::new(
                node_sp_index::cursor::BackfillCursor::idle(),
            ),
            sp_backfill_last_error: parking_lot::RwLock::new(None),
        }
    }

    /// Handle to the `flush_durable` call counter; survives boxing the
    /// store behind `dyn Store`.
    pub fn flush_durable_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.flush_durable_calls.clone()
    }
}

impl Store for InMemoryStore {
    fn flush_durable(&self) -> Result<(), StoreError> {
        self.flush_durable_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

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

    fn get_cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        self.chain_tx.read().get(hash).copied()
    }

    fn chain_tx_backfill_complete(&self) -> bool {
        *self.chain_tx_backfill_complete.read()
    }

    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        *self.chain_tx_backfill_complete.write() = true;
        Ok(())
    }

    fn prune_height(&self) -> Option<u32> {
        *self.prune_height.read()
    }

    fn set_prune_height(&self, height: u32) -> Result<(), StoreError> {
        *self.prune_height.write() = Some(height);
        Ok(())
    }

    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        // Infallible: every operation below is a map insert or removal, so
        // the error arm is unreachable and there is never a batch to hand
        // back. Written this way rather than `unreachable!()` so a future
        // fallible operation degrades to "cannot restore" rather than a panic.
        self.write_batch_mode(batch, mode).map_err(|e| (None, e))
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut bi = self.block_index.write();
        let mut coins = self.coins.write();
        let mut tip = self.tip.write();
        let mut hi = self.height_index.write();
        let mut undo = self.undo.write();
        let mut txl = self.tx_loc.write();
        let mut tst = self.txseq_txid.write();
        let mut tsb = self.txseq_block.write();
        let mut ctx = self.chain_tx.write();

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
        for (txid, seq) in batch.tx_loc_puts {
            txl.insert(txid, seq);
        }
        for txid in batch.tx_loc_removes {
            txl.remove(&txid);
        }
        for (seq, txid) in batch.txseq_txid_puts {
            tst.insert(seq, txid);
        }
        for seq in batch.txseq_txid_removes {
            tst.remove(&seq);
        }
        for (first_txseq, height) in batch.txseq_block_puts {
            tsb.insert(first_txseq, height);
        }
        for first_txseq in batch.txseq_block_removes {
            tsb.remove(&first_txseq);
        }
        for (hash, count) in batch.chain_tx_puts {
            ctx.insert(hash, count);
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
        if !batch.spent_puts.is_empty() || !batch.spent_removes.is_empty() {
            let mut sp = self.spent.write();
            for row in batch.spent_puts {
                sp.insert(row.key(), (row.spending_txseq, row.vin));
            }
            for key in batch.spent_removes {
                sp.remove(&key);
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

        // BIP 352 tweak rows — always compiled. Puts then removes; a
        // height present in both is dropped (removes win), matching the
        // RocksDB WriteBatch's last-op-per-key semantics for a disconnect
        // that follows a connect in the same coalesced batch.
        if !batch.sp_tweak_puts.is_empty() || !batch.sp_tweak_removes.is_empty() {
            let mut sp = self.sp_tweaks.write();
            for (height, row) in batch.sp_tweak_puts {
                sp.insert(height, row);
            }
            for height in batch.sp_tweak_removes {
                sp.remove(&height);
            }
        }
        if let Some(adv) = batch.sp_backfill_cursor_advance {
            let mut cur = self.sp_backfill_cursor.write();
            cur.state = adv.state;
            cur.cursor_height = adv.cursor_height;
            cur.snapshot_height = adv.snapshot_height;
            cur.started_at_unix = adv.started_at_unix;
            if adv.snapshot_tip_hash != [0u8; 32] {
                cur.snapshot_tip_hash = adv.snapshot_tip_hash;
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

    fn for_each_height_hash(
        &self,
        visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<crate::storage::HeightHashScanStats, StoreError> {
        let hi = self.height_index.read();
        for (height, hash) in hi.iter() {
            visit(*height, *hash);
        }
        // In-memory map can't carry corrupt rows; stats are always zero.
        Ok(crate::storage::HeightHashScanStats::default())
    }

    fn coin_count(&self) -> u64 {
        self.coins.read().len() as u64
    }

    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<crate::storage::CoinSnapshotBase, StoreError> {
        // Capture the base and the coins under the same coins read lock so
        // the in-memory backend matches the RocksDB snapshot's consistency
        // guarantee (tests rely on the base matching the iterated coins).
        let coins = self.coins.read();
        let base_hash = self.tip.read().unwrap_or_else(|| {
            use bitcoin::hashes::Hash;
            BlockHash::all_zeros()
        });
        let base_height = self
            .block_index
            .read()
            .get(&base_hash)
            .map(|e| e.height)
            .unwrap_or(0);
        let coin_count = coins.len() as u64;
        // For deterministic iteration order (matching Core's key sort),
        // collect into a sorted vector before yielding. Tests use this
        // backend so consistency with the RocksDB path matters.
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
        let mut coins_written = 0u64;
        for (op, coin) in &entries {
            f(op, coin)?;
            coins_written += 1;
        }
        Ok(crate::storage::CoinSnapshotBase {
            base_hash,
            base_height,
            coin_count,
            coins_written,
        })
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
        let seq = self.get_tx_seq(txid)?;
        let (_first, height) = self.block_of_seq(seq)?;
        self.get_block_hash_by_height(height)
    }

    fn has_txindex(&self) -> bool {
        true // always enabled in tests
    }

    fn get_tx_seq(&self, txid: &Txid) -> Option<u64> {
        self.tx_loc.read().get(txid).copied()
    }

    fn txids_of_seqs(&self, seqs: &[u64]) -> Vec<Option<Txid>> {
        let map = self.txseq_txid.read();
        seqs.iter().map(|s| map.get(s).copied()).collect()
    }

    fn block_of_seq(&self, seq: u64) -> Option<(u64, u32)> {
        let (&first_txseq, &height) = self.txseq_block.read().range(..=seq).next_back()?;
        // Same bound as the RocksDB impl: the nearest-preceding block row
        // matches any larger ordinal, including one past the tip, so it
        // is only an answer if the block actually holds that many
        // transactions.
        let num_tx = self
            .get_block_hash_by_height(height)
            .and_then(|h| self.get_block_index(&h))
            .map(|e| e.num_tx as u64)?;
        if seq >= first_txseq + num_tx {
            return None;
        }
        Some((first_txseq, height))
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.coins.write().clear();
        self.undo.write().clear();
        self.tx_loc.write().clear();
        self.txseq_txid.write().clear();
        self.txseq_block.write().clear();
        self.chain_tx.write().clear();
        self.addr_funding.write().clear();
        self.addr_spending.write().clear();
        self.spent.write().clear();
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
        self.tx_loc.write().clear();
        self.txseq_txid.write().clear();
        self.txseq_block.write().clear();
        self.chain_tx.write().clear();
        self.addr_funding.write().clear();
        self.addr_spending.write().clear();
        self.spent.write().clear();
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
        // The on-disk shape, resolved and ordered exactly as the RocksDB
        // backend does — an in-memory store that skipped the resolution
        // would let a test pass against rows the real one cannot serve.
        let mut raw: Vec<(u64, u32, u64)> = self
            .addr_funding
            .read()
            .iter()
            .filter(|r| &r.scripthash == sh)
            .map(|r| (r.txseq, r.vout, r.amount_sat))
            .collect();
        raw.sort_unstable();
        let seqs: Vec<u64> = raw.iter().map(|(seq, _, _)| *seq).collect();
        let resolved = crate::index::resolve::resolve_txseqs(self, &seqs);
        let mut rows: Vec<(AddrFundingKey, u64)> = raw
            .into_iter()
            .zip(resolved)
            .filter_map(|((_, vout, amount), r)| {
                let r = r?;
                Some((
                    AddrFundingKey {
                        scripthash: *sh,
                        height: r.height,
                        txid: r.txid,
                        vout,
                    },
                    amount,
                ))
            })
            .collect();
        rows.sort_by(|(a, _), (b, _)| {
            (a.height, a.txid, a.vout).cmp(&(b.height, b.txid, b.vout))
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
        let Some(funding_txseq) = self.get_tx_seq(&outpoint.txid) else {
            return Ok(None);
        };
        let Some((spending_txseq, vin)) = self
            .spent
            .read()
            .get(&(funding_txseq, outpoint.vout))
            .copied()
        else {
            return Ok(None);
        };
        Ok(
            crate::index::resolve::resolve_txseqs(self, &[spending_txseq])
                .into_iter()
                .next()
                .flatten()
                .map(|r| SpendingRef {
                    spending_txid: r.txid,
                    spending_vin: vin,
                    height: r.height,
                }),
        )
    }

    fn lookup_spends_of_tx(&self, txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, StoreError> {
        let Some(funding_txseq) = self.get_tx_seq(txid) else {
            return Ok(Vec::new());
        };
        let rows: Vec<(u32, u64, u32)> = self
            .spent
            .read()
            .range((funding_txseq, 0)..=(funding_txseq, u32::MAX))
            .map(|(&(_, vout), &(seq, vin))| (vout, seq, vin))
            .collect();
        let seqs: Vec<u64> = rows.iter().map(|(_, seq, _)| *seq).collect();
        let resolved = crate::index::resolve::resolve_txseqs(self, &seqs);
        Ok(rows
            .into_iter()
            .zip(resolved)
            .filter_map(|((vout, _, vin), r)| {
                let r = r?;
                Some((
                    vout,
                    SpendingRef {
                        spending_txid: r.txid,
                        spending_vin: vin,
                        height: r.height,
                    },
                ))
            })
            .collect())
    }

    fn get_sp_tweaks_row(&self, height: u32) -> Option<node_sp_index::SpBlockRow> {
        self.sp_tweaks.read().get(&height).cloned()
    }

    fn address_index_complete(&self) -> bool {
        *self.address_index_complete.read()
    }

    fn mark_address_index_complete(&self) -> Result<(), StoreError> {
        *self.address_index_complete.write() = true;
        Ok(())
    }

    fn spent_complete(&self) -> bool {
        *self.spent_complete.read()
    }

    fn mark_spent_complete(&self) -> Result<(), StoreError> {
        *self.spent_complete.write() = true;
        Ok(())
    }

    fn mark_index_incomplete_after_snapshot(&self) -> Result<(), StoreError> {
        *self.address_index_complete.write() = false;
        *self.spent_complete.write() = false;
        Ok(())
    }

    fn silent_payment_index_complete(&self) -> bool {
        *self.sp_complete.read()
    }

    fn mark_silent_payment_index_complete(&self) -> Result<(), StoreError> {
        *self.sp_complete.write() = true;
        Ok(())
    }

    fn read_sp_backfill_cursor(&self) -> node_sp_index::cursor::BackfillCursor {
        *self.sp_backfill_cursor.read()
    }

    fn read_sp_backfill_last_error(&self) -> Option<String> {
        self.sp_backfill_last_error.read().clone()
    }

    fn write_sp_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        let mut slot = self.sp_backfill_last_error.write();
        if msg.is_empty() {
            *slot = None;
        } else {
            *slot = Some(msg.to_string());
        }
        Ok(())
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

    /// StoreBatch remove-wins contract (see the StoreBatch docs): a key
    /// in BOTH coin_puts and coin_removes of one batch nets to absent.
    /// Pins the trait-level semantics for the in-memory reference
    /// implementation, mirroring the RocksDbStore test.
    #[test]
    fn write_batch_remove_wins_for_put_remove_pairs() {
        let store = InMemoryStore::new();
        let mk_op = |seed: u8| OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [seed; 32],
            )),
            vout: 0,
        };
        let mk_coin = |amount: u64| Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 7,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };

        let paired = mk_op(1);
        let kept = mk_op(2);
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((paired, mk_coin(1_000)));
        batch.coin_puts.push((kept, mk_coin(2_000)));
        batch.coin_removes.push((paired, 1_000, 7));
        store.write_batch(batch).unwrap();

        assert!(
            store.get_coin(&paired).is_none(),
            "put+remove pair must net to absent — the remove wins"
        );
        assert!(store.get_coin(&kept).is_some(), "unpaired put must survive");
    }

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
            txseq: node_index::TXSEQ_UNKNOWN,
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
