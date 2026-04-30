//! Read-side implementation of `AddressIndex` backed by the chainstate
//! `Store`. Mempool history (M4) and the subscription registry (M5)
//! attach in later milestones.

use std::sync::Arc;

use bitcoin::OutPoint;

use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::Scripthash;
use crate::index::address::trait_def::AddressIndex;
use crate::index::address::types::{HistoryEntry, IndexError, MempoolHistoryEntry, Utxo};
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
}

impl RocksAddressIndex {
    pub fn new(store: Arc<dyn Store>, cfg: AddressIndexConfig) -> Self {
        Self { store, cfg }
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
        self.check_enabled()?;

        let funding = self.store.iter_addr_funding(sh);
        let spending = self.store.iter_addr_spending(sh);

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
        Ok(out)
    }

    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        // M4 fills the mempool variant. Returning an empty vec rather
        // than panicking keeps the trait surface honest and lets M3-era
        // RPC callers ship without conditional logic.
        Vec::new()
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

        // M4 will populate the unconfirmed delta from the mempool
        // variant; for now it is always zero.
        Ok((confirmed, 0))
    }

    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        self.check_enabled()?;

        // Same iteration shape as `balance`: walk funding rows, keep
        // those whose outpoint is still in the coins CF. Returns in
        // funding-key order (height ascending, txid then vout).
        let funding = self.store.iter_addr_funding(sh);
        let mut out = Vec::new();
        for (k, amount) in funding {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::address::keys::AddrFundingRow;
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
}
