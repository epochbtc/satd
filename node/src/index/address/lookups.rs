//! Read-side implementation of `AddressIndex` backed by the chainstate
//! `Store`. Mempool history (M4) and the subscription registry (M5)
//! attach in later milestones.

use std::sync::Arc;

use bitcoin::OutPoint;
use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::Scripthash;
use crate::index::address::mempool::MempoolAddrIndex;
use crate::index::address::subscribe::{SubscribeError, SubscriptionRegistry};
use crate::index::address::trait_def::AddressIndex;
use crate::index::address::types::{
    HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo,
};
use crate::storage::Store;

/// `AddressIndex` over a chainstate `Store`. The store iterator returns
/// rows in `(scripthash, height, txid, vout/vin)` order; we re-shape
/// into the public `HistoryEntry` enum without further sorting.
///
/// The `cfg.enabled` gate is consulted on every read so a runtime
/// disable surfaces as `IndexError::Disabled` to callers (operator
/// RPCs, future protocol layers) — distinguishable from "no rows for
/// this scripthash" (`Ok(empty)`).
pub struct RocksAddressIndex {
    store: Arc<dyn Store>,
    cfg: AddressIndexConfig,
    /// Mempool variant of the index. Populated by `mempool_index_task`
    /// (M4); reads merge into `mempool_history` and the unconfirmed
    /// component of `balance`.
    mempool: Arc<RwLock<MempoolAddrIndex>>,
    /// Subscription registry. Populated lazily so test harnesses
    /// without a tokio runtime can construct a working trait impl.
    subs: Arc<SubscriptionRegistry>,
}

impl RocksAddressIndex {
    pub fn new(store: Arc<dyn Store>, cfg: AddressIndexConfig) -> Self {
        let subs = Arc::new(SubscriptionRegistry::new(
            cfg.max_subscriptions,
            cfg.per_channel_capacity,
        ));
        Self {
            store,
            cfg,
            mempool: Arc::new(RwLock::new(MempoolAddrIndex::new())),
            subs,
        }
    }

    /// Construct with a shared `MempoolAddrIndex` handle so the same
    /// index instance is observed by the background task (in
    /// `main.rs`) and the read surface here.
    pub fn with_mempool_index(
        store: Arc<dyn Store>,
        cfg: AddressIndexConfig,
        mempool: Arc<RwLock<MempoolAddrIndex>>,
    ) -> Self {
        let subs = Arc::new(SubscriptionRegistry::new(
            cfg.max_subscriptions,
            cfg.per_channel_capacity,
        ));
        Self {
            store,
            cfg,
            mempool,
            subs,
        }
    }

    /// Get the shared mempool-index handle so the background task can
    /// share writes with read-side queries.
    pub fn mempool_index_handle(&self) -> Arc<RwLock<MempoolAddrIndex>> {
        self.mempool.clone()
    }

    /// Get the shared subscription registry so the M5 notifier task
    /// can fire status updates on the same channels that subscribers
    /// hold receivers for.
    pub fn subscription_registry(&self) -> Arc<SubscriptionRegistry> {
        self.subs.clone()
    }

    fn check_enabled(&self) -> Result<(), IndexError> {
        if self.cfg.enabled {
            Ok(())
        } else {
            Err(IndexError::Disabled)
        }
    }
}

impl AddressIndex for RocksAddressIndex {
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        self.confirmed_history_limited(sh, usize::MAX)
    }

    fn confirmed_history_limited(
        &self,
        sh: &Scripthash,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, IndexError> {
        self.check_enabled()?;

        // Round-2 review M3: honor the trait contract — return at
        // most `limit` rows.
        //
        // The two underlying iterators (funding + spending) each
        // return up to `limit` rows in scripthash-ascending key
        // order. Concatenating them and sorting can produce up to
        // `2 * limit` rows, so the previous implementation was
        // leakier than the doc-comment claimed. We now scan each
        // side at `limit`, merge, sort, and truncate to `limit`
        // total rows. The `usize::MAX` sentinel propagates through
        // saturating_add so unbounded callers (`confirmed_history`)
        // still see all rows.
        let funding = self.store.iter_addr_funding_limited(sh, limit);
        let spending = self.store.iter_addr_spending_limited(sh, limit);

        // Two pre-sorted streams (by encoded key, both prefixed with
        // the same scripthash → height-ascending). Merge by height
        // then by txid; on equal `(height, txid)`, funding rows come
        // before spending so a same-block fund-and-spend reads as
        // create-then-consume.
        let mut out: Vec<HistoryEntry> = Vec::with_capacity(funding.len() + spending.len());
        for (k, amount) in funding {
            out.push(HistoryEntry::Funding {
                height: k.height,
                txid: k.txid,
                vout: k.vout,
                amount_sat: amount,
            });
        }
        for (k, prev) in spending {
            out.push(HistoryEntry::Spending {
                height: k.height,
                txid: k.txid,
                vin: k.vin,
                prev_outpoint: prev,
            });
        }
        out.sort_by(|a, b| {
            let key_a = (
                a.height(),
                a.txid().to_string(),
                matches!(a, HistoryEntry::Spending { .. }),
            );
            let key_b = (
                b.height(),
                b.txid().to_string(),
                matches!(b, HistoryEntry::Spending { .. }),
            );
            key_a.cmp(&key_b)
        });
        // M3 truncate-after-merge so the public contract is exact.
        // Saturating math guards `limit = usize::MAX` (unbounded).
        out.truncate(limit);
        Ok(out)
    }

    fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        if !self.cfg.enabled {
            return Vec::new();
        }
        self.mempool
            .read()
            
            .entries_for(sh)
            .into_iter()
            .map(|txid| MempoolHistoryEntry { txid })
            .collect()
    }

    fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        self.check_enabled()?;

        // Confirmed balance = sum of live UTXOs. We walk the funding
        // rows for `sh` and ask the coins CF whether each outpoint is
        // still unspent. The bloom-filtered point-lookup makes this
        // tolerable even for large histories — but the cost is still
        // O(history). M6 quantifies; v2 may add a per-scripthash
        // running-sum cache.
        let funding = self.store.iter_addr_funding(sh);
        let mut confirmed: u64 = 0;
        for (k, amount) in funding {
            let outpoint = OutPoint {
                txid: k.txid,
                vout: k.vout,
            };
            if self.store.has_coin(&outpoint) {
                confirmed = confirmed.saturating_add(amount);
            }
        }

        let unconfirmed = self.mempool.read().delta(sh);
        Ok((confirmed, unconfirmed))
    }

    fn confirmed_distinct_history_limited(
        &self,
        sh: &Scripthash,
        limit: usize,
    ) -> Result<Vec<(u32, bitcoin::Txid)>, IndexError> {
        // Round-3 review H1: stream/merge funding + spending CFs into
        // distinct (height, txid) pairs, stopping ONLY at storage
        // exhaustion or `limit` distinct pairs. The previous
        // `confirmed_history_limited` + post-hoc dedupe relied on a
        // fixed duplicate factor of 2 (one funding + one spending row
        // per tx), which the schema doesn't enforce — a single tx can
        // contribute multiple funding rows (one per matching output)
        // and multiple spending rows (one per matching input). A
        // pathological scripthash could therefore see the raw scan
        // truncate before reaching `limit` distinct entries, returning
        // a silent partial history.
        //
        // Implementation: both `iter_addr_funding` and
        // `iter_addr_spending` return their rows in
        // `(scripthash, height, txid, vout/vin)` ascending order. A
        // lockstep merge by `(height, txid)` plus a "last seen"
        // dedupe is enough.
        //
        // Memory: the underlying `iter_addr_*` methods materialize
        // the full per-scripthash history into Vec; the M4 raw-row
        // bound is intentionally NOT applied here because shrinking
        // the scan window would re-introduce the silent-truncation
        // bug. Tighter bounding would need a streaming Store API,
        // which is queued as a separate cleanup.
        self.check_enabled()?;

        let funding = self.store.iter_addr_funding(sh);
        let spending = self.store.iter_addr_spending(sh);
        let mut funding_iter = funding.into_iter().peekable();
        let mut spending_iter = spending.into_iter().peekable();

        let mut out: Vec<(u32, bitcoin::Txid)> = Vec::new();
        let mut last: Option<(u32, bitcoin::Txid)> = None;

        while out.len() < limit {
            let f_key = funding_iter.peek().map(|(k, _)| (k.height, k.txid));
            let s_key = spending_iter.peek().map(|(k, _)| (k.height, k.txid));

            let next = match (f_key, s_key) {
                (None, None) => break,
                (Some(fk), None) => {
                    funding_iter.next();
                    fk
                }
                (None, Some(sk)) => {
                    spending_iter.next();
                    sk
                }
                (Some(fk), Some(sk)) => {
                    if fk <= sk {
                        funding_iter.next();
                        fk
                    } else {
                        spending_iter.next();
                        sk
                    }
                }
            };

            if last.as_ref() != Some(&next) {
                out.push(next);
                last = Some(next);
            }
        }

        Ok(out)
    }

    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        self.utxos_limited(sh, usize::MAX)
    }

    fn utxos_limited(&self, sh: &Scripthash, limit: usize) -> Result<Vec<Utxo>, IndexError> {
        self.check_enabled()?;

        // Same iteration shape as `balance`: walk funding rows, keep
        // those whose outpoint is still in the coins CF. Returns in
        // funding-key order (height ascending, txid then vout).
        //
        // Round-1 review M4: stop once we have `limit` UTXOs. We
        // can't bound the funding scan by `limit` directly because
        // each funding row needs a `has_coin` filter — most rows
        // may have already been spent — so we keep iterating
        // funding until `out.len() == limit`. Worst case is when
        // the live UTXO set is a small tail of a long history; then
        // we still scan most of the funding rows. That's an
        // acceptable trade — the cap is the wire-size guard, not a
        // pathological-scripthash CPU guard. (CPU bounding belongs
        // with rate limiting / per-peer caps.)
        let funding = self.store.iter_addr_funding(sh);
        let mut out = Vec::new();
        for (k, amount) in funding {
            if out.len() >= limit {
                break;
            }
            let outpoint = OutPoint {
                txid: k.txid,
                vout: k.vout,
            };
            if self.store.has_coin(&outpoint) {
                out.push(Utxo {
                    txid: k.txid,
                    vout: k.vout,
                    height: k.height,
                    amount_sat: amount,
                });
            }
        }
        Ok(out)
    }

    fn subscribe(
        &self,
        sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        self.subs.subscribe(sh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::address::keys::{AddrFundingRowV3, AddrSpendingRow};
    use crate::storage::StoreBatch;
    use crate::storage::db::InMemoryStore;

    fn fixture_txid(byte: u8) -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    /// Assign each `(height, txid)` a chain-order ordinal and write the
    /// families a v3 index row resolves through: `tx_loc`,
    /// `txseq_txid`, `txseq_block`, plus the block-index and
    /// height-index rows `block_of_seq` bounds its answer with.
    ///
    /// A funding row on disk names its transaction by ordinal alone, so
    /// a fixture that writes rows without this scaffolding writes rows
    /// nothing can read back — which is exactly what a real chainstate
    /// would call corruption.
    ///
    /// Transactions are numbered in the order given, which must be
    /// non-decreasing in height for the numbering to be chain order.
    /// Returns the ordinal assigned to each.
    fn seed_ordinals(store: &InMemoryStore, txs: &[(u32, bitcoin::Txid)]) -> Vec<u64> {
        use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
        use bitcoin::hashes::Hash;

        let g = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let mut batch = StoreBatch::default();
        let mut seqs = Vec::with_capacity(txs.len());
        let mut per_height: std::collections::BTreeMap<u32, (u64, u32)> = Default::default();

        for (i, (height, txid)) in txs.iter().enumerate() {
            let seq = i as u64;
            seqs.push(seq);
            batch.tx_loc_puts.push((*txid, seq));
            batch.txseq_txid_puts.push((seq, *txid));
            per_height
                .entry(*height)
                .and_modify(|(_, n)| *n += 1)
                .or_insert((seq, 1));
        }

        for (height, (first_txseq, num_tx)) in per_height {
            let hash = bitcoin::BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([height as u8; 32]),
            );
            batch.block_index_puts.push((
                hash,
                BlockIndexEntry {
                    header: g.header,
                    height,
                    status: BlockStatus::Valid,
                    num_tx,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                },
            ));
            batch.height_hash_puts.push((height, hash));
            batch.txseq_block_puts.push((first_txseq, height));
        }
        store.write_batch(batch).unwrap();
        seqs
    }

    fn make_coin(amount: u64, height: u32) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        }
    }

    #[test]
    fn test_address_index_unknown_scripthash_returns_empty_not_error() {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0u8; 32];
        assert_eq!(idx.confirmed_history(&sh).unwrap(), Vec::new());
        assert_eq!(idx.balance(&sh).unwrap(), (0, 0));
        assert_eq!(idx.utxos(&sh).unwrap(), Vec::new());
    }

    #[test]
    fn test_address_index_disabled_lookup_returns_descriptive_error() {
        let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
        let cfg = AddressIndexConfig {
            enabled: false,
            ..Default::default()
        };
        let idx = RocksAddressIndex::new(store, cfg);
        let sh = [0u8; 32];
        assert!(matches!(
            idx.confirmed_history(&sh),
            Err(IndexError::Disabled)
        ));
        assert!(matches!(idx.balance(&sh), Err(IndexError::Disabled)));
        assert!(matches!(idx.utxos(&sh), Err(IndexError::Disabled)));
    }

    #[test]
    fn test_address_index_confirmed_history_height_order() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0xab; 32];

        // Three funding rows at heights 5, 7, 10, written out of order.
        // The store iterator returns them sorted; confirmed_history
        // must too.
        let seqs = seed_ordinals(
            &store_inner,
            &[
                (5, fixture_txid(5)),
                (7, fixture_txid(7)),
                (10, fixture_txid(10)),
            ],
        );
        let mut batch = StoreBatch::default();
        for (i, _) in [10u32, 5, 7].iter().enumerate() {
            // Push in an order that does not match the ordinals, so a
            // store that returned insertion order would fail.
            let seq = seqs[[2usize, 0, 1][i]];
            batch.addr_funding_puts.push(AddrFundingRowV3 {
                scripthash: sh,
                txseq: seq,
                vout: 0,
                amount_sat: 100,
            });
        }
        store_inner.write_batch(batch).unwrap();

        let history = idx.confirmed_history(&sh).unwrap();
        let heights: Vec<u32> = history.iter().map(|e| e.height()).collect();
        assert_eq!(heights, vec![5, 7, 10]);
    }

    /// The documented order is `(height, txid, vout)`. On disk the rows
    /// are ordinal-keyed, and ordinal order is *block position*, not
    /// txid order — so within one block the two disagree. The store
    /// sorts before returning, which is what keeps every consumer
    /// (Electrum's `listunspent`, the lockstep merge in
    /// `confirmed_distinct_history_limited`) working unchanged.
    ///
    /// This builds a block whose transactions are in the opposite txid
    /// order from their positions, so a store that returned raw scan
    /// order would fail.
    #[test]
    fn test_address_index_utxos_order_matches_the_documented_contract() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0x5a; 32];

        // Three transactions in ONE block. Positions 0,1,2 carry txids
        // that sort 0xcc, 0xbb, 0xaa — the reverse.
        let txids = [fixture_txid(0xcc), fixture_txid(0xbb), fixture_txid(0xaa)];
        let seqs = seed_ordinals(
            &store_inner,
            &[(7, txids[0]), (7, txids[1]), (7, txids[2])],
        );
        assert!(
            txids[0] > txids[1] && txids[1] > txids[2],
            "fixture premise: block position and txid order disagree"
        );

        let mut batch = StoreBatch::default();
        for (i, seq) in seqs.iter().enumerate() {
            batch.addr_funding_puts.push(AddrFundingRowV3 {
                scripthash: sh,
                txseq: *seq,
                vout: 0,
                amount_sat: 100 + i as u64,
            });
            batch.coin_puts.push((
                OutPoint { txid: txids[i], vout: 0 },
                make_coin(100 + i as u64, 7),
            ));
        }
        store_inner.write_batch(batch).unwrap();

        let got: Vec<bitcoin::Txid> = idx.utxos(&sh).unwrap().iter().map(|u| u.txid).collect();
        let mut expected = txids.to_vec();
        expected.sort_by_key(|t| t.to_string());
        assert_eq!(
            got, expected,
            "utxos must come back in (height, txid, vout) order, not block order"
        );

        // Same for history.
        let hist: Vec<bitcoin::Txid> = idx
            .confirmed_history(&sh)
            .unwrap()
            .iter()
            .map(|e| e.txid())
            .collect();
        assert_eq!(hist, expected);
    }

    /// A funding row whose ordinal has no reverse-map entry is local
    /// corruption: the rows are written in the same atomic batch as the
    /// ordinal families, so one cannot exist without the other on a
    /// healthy chainstate. It must be skipped, not emitted with an
    /// invented txid that a consumer would read as a real transaction.
    #[test]
    fn test_address_index_skips_a_row_whose_ordinal_does_not_resolve() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0x6b; 32];

        let good = fixture_txid(0x11);
        let seqs = seed_ordinals(&store_inner, &[(3, good)]);

        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[0],
            vout: 0,
            amount_sat: 500,
        });
        // An ordinal nothing ever indexed.
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: 9_999,
            vout: 0,
            amount_sat: 600,
        });
        store_inner.write_batch(batch).unwrap();

        let history = idx.confirmed_history(&sh).unwrap();
        assert_eq!(history.len(), 1, "the unresolvable row must be dropped");
        assert_eq!(history[0].txid(), good);
    }

    #[test]
    fn test_address_index_balance_simple() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0x01; 32];

        // Two funding rows; both unspent → balance is the sum.
        let txid_a = fixture_txid(0x10);
        let txid_b = fixture_txid(0x11);
        let seqs = seed_ordinals(&store_inner, &[(1, txid_a), (2, txid_b)]);
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[0],
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[1],
            vout: 1,
            amount_sat: 2500,
        });
        batch.coin_puts.push((
            OutPoint { txid: txid_a, vout: 0 },
            make_coin(1000, 1),
        ));
        batch.coin_puts.push((
            OutPoint { txid: txid_b, vout: 1 },
            make_coin(2500, 2),
        ));
        store_inner.write_batch(batch).unwrap();

        assert_eq!(idx.balance(&sh).unwrap(), (3500, 0));
    }

    #[test]
    fn test_address_index_balance_after_spend() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0x02; 32];

        let txid_a = fixture_txid(0x20);
        let txid_b = fixture_txid(0x21);
        // Fund two outpoints, then spend one.
        let seqs = seed_ordinals(&store_inner, &[(1, txid_a), (2, txid_b)]);
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[0],
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[1],
            vout: 0,
            amount_sat: 4000,
        });
        batch.coin_puts.push((
            OutPoint { txid: txid_a, vout: 0 },
            make_coin(1000, 1),
        ));
        batch.coin_puts.push((
            OutPoint { txid: txid_b, vout: 0 },
            make_coin(4000, 2),
        ));
        store_inner.write_batch(batch).unwrap();

        // Spend txid_a:0
        let mut spend_batch = StoreBatch::default();
        spend_batch.coin_removes.push((
            OutPoint { txid: txid_a, vout: 0 },
            1000,
            1,
        ));
        store_inner.write_batch(spend_batch).unwrap();

        assert_eq!(idx.balance(&sh).unwrap(), (4000, 0));
    }

    #[test]
    fn test_address_index_utxos_excludes_spent() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0x03; 32];

        let txid_a = fixture_txid(0x30);
        let txid_b = fixture_txid(0x31);
        let seqs = seed_ordinals(&store_inner, &[(1, txid_a), (2, txid_b)]);
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[0],
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seqs[1],
            vout: 0,
            amount_sat: 2000,
        });
        batch.coin_puts.push((
            OutPoint { txid: txid_a, vout: 0 },
            make_coin(1000, 1),
        ));
        batch.coin_puts.push((
            OutPoint { txid: txid_b, vout: 0 },
            make_coin(2000, 2),
        ));
        store_inner.write_batch(batch).unwrap();

        // Spend txid_a:0
        let mut spend_batch = StoreBatch::default();
        spend_batch.coin_removes.push((
            OutPoint { txid: txid_a, vout: 0 },
            1000,
            1,
        ));
        store_inner.write_batch(spend_batch).unwrap();

        let utxos = idx.utxos(&sh).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, txid_b);
        assert_eq!(utxos[0].amount_sat, 2000);
    }

    /// Round-3 review H1: `confirmed_distinct_history_limited` must
    /// stop ONLY at storage exhaustion or `limit` distinct pairs —
    /// never silently truncate due to a raw-row duplicate factor.
    /// Before this fix, the handler computed `raw_limit = 2*(cap+1)`
    /// and trusted the duplicate factor to be at most 2. The schema
    /// emits one row per matching output + one per matching input, so
    /// a tx with 3+ outputs to the same scripthash could push the raw
    /// scan past the cap before reaching `cap + 1` distinct (height,
    /// txid) pairs.
    #[test]
    fn test_address_index_confirmed_distinct_history_handles_high_duplicate_factor() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0xab; 32];

        // 4 distinct txs, each with 5 funding outputs to `sh`. That
        // yields 20 raw funding rows for 4 distinct (height, txid)
        // pairs — duplicate factor 5, above the previous fixed-2
        // assumption.
        let txs: Vec<(u32, bitcoin::Txid)> =
            (0..4u32).map(|i| (i, fixture_txid(0x10 + i as u8))).collect();
        let seqs = seed_ordinals(&store_inner, &txs);
        let mut batch = StoreBatch::default();
        for (i, seq) in seqs.iter().enumerate() {
            let _ = i;
            for vout in 0..5u32 {
                batch.addr_funding_puts.push(AddrFundingRowV3 {
                    scripthash: sh,
                    txseq: *seq,
                    vout,
                    amount_sat: 100,
                });
            }
        }
        store_inner.write_batch(batch).unwrap();

        // Asking for 3 distinct entries should return exactly 3 (not
        // truncated mid-tx). And the 3 should be the first 3 in
        // (height, txid) order.
        let limited = idx.confirmed_distinct_history_limited(&sh, 3).unwrap();
        assert_eq!(limited.len(), 3);
        // Heights 0, 1, 2 (the first three blocks).
        assert_eq!(
            limited.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        // Asking for 100 (more than exists) returns 4 — storage
        // exhausted before limit reached.
        let full = idx.confirmed_distinct_history_limited(&sh, 100).unwrap();
        assert_eq!(full.len(), 4);
    }

    /// Round-3 review H1, regression case: with cap=3 and a
    /// scripthash containing 4 distinct txs each with 5 funding
    /// outputs, asking for cap+1=4 distinct entries must return 4
    /// (so the handler errors with `history_too_large`), not silently
    /// truncate to 3 because the raw scan window was exhausted.
    #[test]
    fn test_address_index_confirmed_distinct_history_no_silent_truncation() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0xfe; 32];

        // 4 txs × 5 outputs each = 20 raw funding rows.
        let txs: Vec<(u32, bitcoin::Txid)> =
            (0..4u32).map(|i| (i, fixture_txid(0x80 + i as u8))).collect();
        let seqs = seed_ordinals(&store_inner, &txs);
        let mut batch = StoreBatch::default();
        for (i, seq) in seqs.iter().enumerate() {
            let _ = i;
            for vout in 0..5u32 {
                batch.addr_funding_puts.push(AddrFundingRowV3 {
                    scripthash: sh,
                    txseq: *seq,
                    vout,
                    amount_sat: 100,
                });
            }
        }
        store_inner.write_batch(batch).unwrap();

        // Cap = 3, ask for cap + 1 = 4 distinct entries. The
        // handler-side check is `len > cap` → 4 > 3 → error.
        // Pre-fix this returned at most 3 because raw_limit = 8 was
        // exhausted before reaching 4 distinct pairs (duplicate
        // factor 5 > 2).
        let pairs = idx.confirmed_distinct_history_limited(&sh, 4).unwrap();
        assert_eq!(
            pairs.len(),
            4,
            "must return cap+1 distinct pairs so handler can detect over-cap"
        );
    }

    /// Round-2 review M3: `confirmed_history_limited` honors its
    /// trait contract — at most `limit` rows after merge + sort.
    /// Before this fix, a scripthash with N funding + N spending
    /// rows could return up to `2 * limit` rows when the caller
    /// asked for `limit`, weakening the `cap + 1` sentinel pattern.
    #[test]
    fn test_address_index_confirmed_history_limited_truncates_to_limit() {
        let store_inner = Arc::new(InMemoryStore::new());
        let store: Arc<dyn Store> = store_inner.clone();
        let idx = RocksAddressIndex::new(store, AddressIndexConfig::default());
        let sh = [0xab; 32];

        // 10 funding + 10 spending rows for the same scripthash.
        // With limit=12, the unfixed code would have returned ~20
        // (10 + 10 from each side); the fixed code truncates to 12.
        let txs: Vec<(u32, bitcoin::Txid)> =
            (0..10u32).map(|i| (i, fixture_txid(i as u8))).collect();
        let seqs = seed_ordinals(&store_inner, &txs);
        let mut batch = StoreBatch::default();
        for i in 0..10u32 {
            batch.addr_funding_puts.push(AddrFundingRowV3 {
                scripthash: sh,
                txseq: seqs[i as usize],
                vout: 0,
                amount_sat: 100,
            });
            batch.addr_spending_puts.push(AddrSpendingRow {
                scripthash: sh,
                height: i + 100,
                txid: fixture_txid(0x80 + i as u8),
                vin: 0,
                prev_outpoint: OutPoint {
                    txid: fixture_txid(0xff),
                    vout: i,
                },
            });
        }
        store_inner.write_batch(batch).unwrap();

        for limit in [3, 5, 12, 19] {
            let history = idx.confirmed_history_limited(&sh, limit).unwrap();
            assert!(
                history.len() <= limit,
                "limit={limit} returned {} rows (must be <= limit)",
                history.len()
            );
        }
        // Unbounded path returns the full 20 rows.
        let full = idx.confirmed_history_limited(&sh, usize::MAX).unwrap();
        assert_eq!(full.len(), 20);
    }
}
