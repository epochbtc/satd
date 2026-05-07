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
    use crate::index::address::keys::{AddrFundingRow, AddrSpendingRow};
    use crate::storage::StoreBatch;
    use crate::storage::db::InMemoryStore;

    fn fixture_txid(byte: u8) -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    fn make_coin(amount: u64, height: u32) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height,
            coinbase: false,
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

        // Three funding rows at heights 10, 5, 7. The store iterator
        // returns them sorted; confirmed_history must too.
        let mut batch = StoreBatch::default();
        for h in [10u32, 5, 7] {
            batch.addr_funding_puts.push(AddrFundingRow {
                scripthash: sh,
                height: h,
                txid: fixture_txid(h as u8),
                vout: 0,
                amount_sat: 100,
            });
        }
        store_inner.write_batch(batch).unwrap();

        let history = idx.confirmed_history(&sh).unwrap();
        let heights: Vec<u32> = history.iter().map(|e| e.height()).collect();
        assert_eq!(heights, vec![5, 7, 10]);
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
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid: txid_a,
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 2,
            txid: txid_b,
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
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid: txid_a,
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 2,
            txid: txid_b,
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
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid: txid_a,
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 2,
            txid: txid_b,
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
        let mut batch = StoreBatch::default();
        for i in 0..4u32 {
            let txid = fixture_txid(0x10 + i as u8);
            for vout in 0..5u32 {
                batch.addr_funding_puts.push(AddrFundingRow {
                    scripthash: sh,
                    height: i,
                    txid,
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
        let mut batch = StoreBatch::default();
        for i in 0..4u32 {
            let txid = fixture_txid(0x80 + i as u8);
            for vout in 0..5u32 {
                batch.addr_funding_puts.push(AddrFundingRow {
                    scripthash: sh,
                    height: i,
                    txid,
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
        let mut batch = StoreBatch::default();
        for i in 0..10u32 {
            batch.addr_funding_puts.push(AddrFundingRow {
                scripthash: sh,
                height: i,
                txid: fixture_txid(i as u8),
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
