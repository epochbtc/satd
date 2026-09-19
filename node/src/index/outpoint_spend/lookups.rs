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
                if self.store.spent_complete() {
                    Ok(None)
                } else {
                    Err(node_index::IndexError::Incomplete)
                }
            }
        }
    }

    fn spends_of_tx(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Vec<(u32, SpendingRef)>, node_index::IndexError> {
        if !self.cfg.enabled {
            return Err(node_index::IndexError::Disabled);
        }
        // Same completeness contract as `spend_of`, applied to the whole
        // transaction: an empty result on an index that is not known
        // complete would read as "none of these outputs are spent",
        // which is the false-unspent answer the marker exists to stop.
        let rows = self
            .store
            .lookup_spends_of_tx(txid)
            .map_err(|e| node_index::IndexError::Storage(e.to_string()))?;
        if rows.is_empty() && !self.store.spent_complete() {
            return Err(node_index::IndexError::Incomplete);
        }
        Ok(rows)
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
        assert!(idx.store.spent_complete());
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

    /// Seed the ordinal rows a `spent` lookup resolves through, so a
    /// fixture can produce the same shape a connected block would.
    fn seed_ordinal_block(
        store: &dyn crate::storage::Store,
        height: u32,
        first_txseq: u64,
        txids: &[bitcoin::Txid],
    ) {
        use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
        let g = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = bitcoin::BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x50 + height as u8; 32]),
        );
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            hash,
            BlockIndexEntry {
                header: g.header,
                height,
                status: BlockStatus::Valid,
                num_tx: txids.len() as u32,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            },
        ));
        batch.height_hash_puts.push((height, hash));
        batch.txseq_block_puts.push((first_txseq, height));
        for (i, txid) in txids.iter().enumerate() {
            batch.tx_loc_puts.push((*txid, first_txseq + i as u64));
            batch.txseq_txid_puts.push((first_txseq + i as u64, *txid));
        }
        store.write_batch(batch).unwrap();
    }

    #[test]
    fn test_spend_of_complete_known_returns_ok_some() {
        let (idx, _dir) = fresh_store();
        let prev = fixture_outpoint(0x77);
        let spender = fixture_outpoint(0xab).txid;
        seed_ordinal_block(&*idx.store, 1, 5, &[prev.txid]);
        seed_ordinal_block(&*idx.store, 100, 40, &[spender]);

        let mut batch = StoreBatch::default();
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 5,
            vout: prev.vout,
            spending_txseq: 40,
            vin: 4,
        });
        idx.store.write_batch(batch).unwrap();

        assert_eq!(
            idx.spend_of(&prev).unwrap(),
            Some(SpendingRef {
                spending_txid: spender,
                spending_vin: 4,
                height: 100,
            })
        );
    }

    /// The whole-transaction form has the same completeness contract as
    /// the single-outpoint one: an empty result on an index that is not
    /// known complete is the false-unspent answer the marker exists to
    /// stop, so it refuses instead.
    #[test]
    fn test_spends_of_tx_returns_every_spent_output() {
        let (idx, _dir) = fresh_store();
        let funding = fixture_outpoint(0x31).txid;
        let spender = fixture_outpoint(0x32).txid;
        seed_ordinal_block(&*idx.store, 1, 70, &[funding]);
        seed_ordinal_block(&*idx.store, 9, 80, &[spender]);

        let mut batch = StoreBatch::default();
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 70,
            vout: 1,
            spending_txseq: 80,
            vin: 0,
        });
        idx.store.write_batch(batch).unwrap();

        assert_eq!(
            idx.spends_of_tx(&funding).unwrap(),
            vec![(
                1,
                SpendingRef {
                    spending_txid: spender,
                    spending_vin: 0,
                    height: 9,
                }
            )]
        );
    }

    /// The whole-transaction lookup must agree with asking per output.
    ///
    /// It takes a different path — one prefix scan over the `spent`
    /// family and one batched ordinal resolution, rather than N point
    /// reads each re-deriving the funding ordinal from the txid — so
    /// the two could diverge on the vout ordering, on unspent outputs,
    /// or on how a spender resolves. The batching itself is pinned
    /// where it lives, in `resolve_txseqs_costs_one_reverse_lookup_per_call`.
    #[test]
    fn spends_of_tx_agrees_with_asking_each_outpoint() {
        let (idx, _dir) = fresh_store();
        let funding = fixture_outpoint(0x61).txid;
        let spender_a = fixture_outpoint(0x62).txid;
        let spender_b = fixture_outpoint(0x63).txid;
        seed_ordinal_block(&*idx.store, 1, 500, &[funding]);
        seed_ordinal_block(&*idx.store, 2, 600, &[spender_a, spender_b]);

        // Twenty outputs, every third one left unspent, and the
        // spenders alternating so the rows do not all resolve alike.
        let mut batch = StoreBatch::default();
        let spent_vouts: Vec<u32> = (0..20u32).filter(|v| v % 3 != 0).collect();
        for (i, vout) in spent_vouts.iter().enumerate() {
            batch.spent_puts.push(node_index::SpentRow {
                funding_txseq: 500,
                vout: *vout,
                spending_txseq: 600 + (i as u64 % 2),
                vin: *vout,
            });
        }
        idx.store.write_batch(batch).unwrap();

        let bulk = idx.spends_of_tx(&funding).unwrap();
        let one_at_a_time: Vec<(u32, SpendingRef)> = (0..20u32)
            .filter_map(|vout| {
                let op = OutPoint { txid: funding, vout };
                idx.spend_of(&op).unwrap().map(|sref| (vout, sref))
            })
            .collect();

        assert_eq!(
            bulk, one_at_a_time,
            "the whole-transaction form must answer exactly as the \
             per-outpoint form does, in the same vout order"
        );
        assert_eq!(bulk.len(), spent_vouts.len(), "unspent outputs are absent");
    }

    #[test]
    fn test_spends_of_tx_disabled_returns_err_disabled() {
        let (mut idx, _dir) = fresh_store();
        idx.cfg = Arc::new(AddressIndexConfig {
            enabled: false,
            ..Default::default()
        });
        match idx.spends_of_tx(&fixture_outpoint(0x11).txid) {
            Err(node_index::IndexError::Disabled) => {}
            other => panic!("expected Disabled, got {other:?}"),
        }
    }
}
