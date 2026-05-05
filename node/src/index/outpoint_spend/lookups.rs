//! `RocksSpendIndex` — read adapter implementing `SpendIndex` over
//! the `Store::lookup_spend` method.

use std::sync::Arc;

use bitcoin::OutPoint;

use crate::index::address::config::AddressIndexConfig;
use crate::index::outpoint_spend::{SpendIndex, SpendingRef};
use crate::storage::Store;

pub struct RocksSpendIndex {
    pub store: Arc<dyn Store>,
    pub cfg: Arc<AddressIndexConfig>,
}

impl RocksSpendIndex {
    pub fn new(store: Arc<dyn Store>, cfg: Arc<AddressIndexConfig>) -> Self {
        Self { store, cfg }
    }
}

impl SpendIndex for RocksSpendIndex {
    fn spend_of(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRef>, node_index::IndexError> {
        if !self.cfg.enabled {
            return Err(node_index::IndexError::Disabled);
        }
        let result = self
            .store
            .lookup_spend(outpoint)
            .map_err(|e| node_index::IndexError::Storage(e.to_string()))?;
        match result {
            Some(spend) => Ok(Some(spend)),
            None => {
                // `Ok(None)` is only safe to surface when the index
                // is known complete for the active chain. Without
                // the marker an upgraded datadir could report a
                // historically-spent outpoint as unspent, which is
                // worse than refusing to answer (round-3 H2).
                if self.store.outpoint_spend_complete() {
                    Ok(None)
                } else {
                    Err(node_index::IndexError::Incomplete)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreBatch;
    use crate::storage::rocksdb_store::RocksDbStore;
    use bitcoin::hashes::Hash;
    use node_index::SpendingRef;
    use tempfile::TempDir;

    fn fresh_store() -> (RocksSpendIndex, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap())
            as Arc<dyn Store>;
        let cfg = Arc::new(AddressIndexConfig {
            enabled: true,
            ..Default::default()
        });
        (RocksSpendIndex::new(store, cfg), dir)
    }

    fn fixture_outpoint(byte: u8) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]),
            ),
            vout: 0,
        }
    }

    #[test]
    fn test_spend_of_complete_unknown_returns_ok_none() {
        // Fresh datadir → marker is true; an unknown outpoint is
        // definitively unspent.
        let (idx, _dir) = fresh_store();
        assert!(idx.store.outpoint_spend_complete());
        let op = fixture_outpoint(0x11);
        assert_eq!(idx.spend_of(&op).unwrap(), None);
    }

    #[test]
    fn test_spend_of_disabled_returns_err_disabled() {
        let (mut idx, _dir) = fresh_store();
        idx.cfg = Arc::new(AddressIndexConfig {
            enabled: false,
            ..Default::default()
        });
        match idx.spend_of(&fixture_outpoint(0x11)) {
            Err(node_index::IndexError::Disabled) => {}
            other => panic!("expected Disabled, got {other:?}"),
        }
    }

    #[test]
    fn test_spend_of_complete_known_returns_ok_some() {
        let (idx, _dir) = fresh_store();
        let prev = fixture_outpoint(0x77);
        let sref = SpendingRef {
            spending_txid: fixture_outpoint(0xab).txid,
            spending_vin: 4,
            height: 100,
        };
        let mut batch = StoreBatch::default();
        batch.outpoint_spend_puts.push((prev, sref));
        idx.store.write_batch(batch).unwrap();
        assert_eq!(idx.spend_of(&prev).unwrap(), Some(sref));
    }
}
