//! `FilterIndex` impl backed by the `Store` trait. The `getblockfilter`
//! RPC and the BIP 157 P2P arms (PR-4 / PR-5) hold an
//! `Arc<dyn FilterIndex>` so the protocol-side code never has to know
//! whether the underlying storage is RocksDB or the in-memory test
//! backend — both implement the same `Store` accessors.

use std::sync::Arc;

use bitcoin::hashes::Hash;

use node_filter_index::{FilterIndex, IndexError, FILTER_TYPE_BASIC};

use crate::storage::Store;

/// Maximum range a single `getcfheaders` / `getcfilters` request can
/// span, per BIP 157 ("a value of 1000 or fewer"). Enforced inside
/// `headers_range`. Public so the P2P handler arms can short-circuit
/// before calling into the store.
pub const MAX_FILTER_RANGE: u32 = 1000;

pub struct RocksFilterIndex {
    store: Arc<dyn Store>,
    config: node_filter_index::FilterIndexConfig,
}

impl RocksFilterIndex {
    pub fn new(store: Arc<dyn Store>, config: node_filter_index::FilterIndexConfig) -> Self {
        Self { store, config }
    }
}

impl FilterIndex for RocksFilterIndex {
    fn filter_at(&self, filter_type: u8, height: u32) -> Result<Vec<u8>, IndexError> {
        if !self.config.enabled {
            return Err(IndexError::Disabled);
        }
        if filter_type != FILTER_TYPE_BASIC {
            return Err(IndexError::NotFound(height));
        }
        if !self.store.block_filter_index_complete() {
            return Err(IndexError::Incomplete);
        }
        self.store
            .get_filter(filter_type, height)
            .ok_or(IndexError::NotFound(height))
    }

    fn header_at(&self, filter_type: u8, height: u32) -> Result<[u8; 32], IndexError> {
        if !self.config.enabled {
            return Err(IndexError::Disabled);
        }
        if filter_type != FILTER_TYPE_BASIC {
            return Err(IndexError::NotFound(height));
        }
        if !self.store.block_filter_index_complete() {
            return Err(IndexError::Incomplete);
        }
        self.store
            .get_filter_header(filter_type, height)
            .ok_or(IndexError::NotFound(height))
    }

    fn headers_range(
        &self,
        filter_type: u8,
        start_height: u32,
        stop_height: u32,
    ) -> Result<Vec<[u8; 32]>, IndexError> {
        if !self.config.enabled {
            return Err(IndexError::Disabled);
        }
        if filter_type != FILTER_TYPE_BASIC {
            return Err(IndexError::InvalidRange {
                start_height,
                stop_height,
            });
        }
        if stop_height < start_height
            || stop_height.saturating_sub(start_height) >= MAX_FILTER_RANGE
        {
            return Err(IndexError::InvalidRange {
                start_height,
                stop_height,
            });
        }
        if !self.store.block_filter_index_complete() {
            return Err(IndexError::Incomplete);
        }
        let mut out = Vec::with_capacity((stop_height - start_height + 1) as usize);
        for h in start_height..=stop_height {
            let header = self
                .store
                .get_filter_header(filter_type, h)
                .ok_or(IndexError::NotFound(h))?;
            out.push(header);
        }
        Ok(out)
    }

    fn checkpoints_to(
        &self,
        filter_type: u8,
        stop_height: u32,
    ) -> Result<Vec<[u8; 32]>, IndexError> {
        if !self.config.enabled {
            return Err(IndexError::Disabled);
        }
        if filter_type != FILTER_TYPE_BASIC {
            return Err(IndexError::NotFound(stop_height));
        }
        if !self.store.block_filter_index_complete() {
            return Err(IndexError::Incomplete);
        }
        // BIP 157: filter headers at every 1000-block boundary up to
        // (but not including) the stop height. We return heights
        // 1000, 2000, ... ≤ stop_height. Genesis (height 0) is never
        // a checkpoint per the spec.
        let max_idx = stop_height / MAX_FILTER_RANGE;
        let mut out = Vec::with_capacity(max_idx as usize);
        for i in 1..=max_idx {
            let h = i * MAX_FILTER_RANGE;
            // A clamp for the strict "< stop_height" rule: the spec
            // says intervals strictly less than the stop. The
            // canonical reading from Bitcoin Core's implementation is
            // ≤ stop_height; we follow that to stay compatible.
            if h > stop_height {
                break;
            }
            let header = self
                .store
                .get_filter_header(filter_type, h)
                .ok_or(IndexError::NotFound(h))?;
            out.push(header);
        }
        Ok(out)
    }

    fn is_complete(&self) -> bool {
        self.config.enabled && self.store.block_filter_index_complete()
    }
}

/// Compute the BIP 158 filter hash (`sha256d(filter_bytes)`) used to
/// build a filter header. `getcfheaders` recomputes this on the fly
/// instead of storing a third CF (see plan §"Filter-hash CF for
/// getcfheaders recompute").
pub fn filter_hash(filter_bytes: &[u8]) -> [u8; 32] {
    bitcoin::hashes::sha256d::Hash::hash(filter_bytes).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::StoreBatch;
    use node_filter_index::{
        FilterHeaderRow, FilterIndexConfig, FilterKey, FilterRow, FILTER_TYPE_BASIC,
    };

    fn enabled() -> FilterIndexConfig {
        FilterIndexConfig {
            enabled: true,
            peer_serve: false,
        }
    }

    fn write_row(store: &InMemoryStore, height: u32, filter: Vec<u8>, header: [u8; 32]) {
        let key = FilterKey {
            filter_type: FILTER_TYPE_BASIC,
            height,
        };
        let mut batch = StoreBatch::default();
        batch.filter_puts.push(FilterRow { key, filter });
        batch
            .filter_header_puts
            .push(FilterHeaderRow { key, header });
        store.write_batch(batch).unwrap();
    }

    #[test]
    fn test_disabled_returns_disabled() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        let cfg = FilterIndexConfig::default();
        let idx = RocksFilterIndex::new(store, cfg);
        assert!(matches!(
            idx.filter_at(FILTER_TYPE_BASIC, 0),
            Err(IndexError::Disabled)
        ));
        assert!(matches!(
            idx.header_at(FILTER_TYPE_BASIC, 0),
            Err(IndexError::Disabled)
        ));
        assert!(matches!(
            idx.headers_range(FILTER_TYPE_BASIC, 0, 5),
            Err(IndexError::Disabled)
        ));
        assert!(matches!(
            idx.checkpoints_to(FILTER_TYPE_BASIC, 5_000),
            Err(IndexError::Disabled)
        ));
        assert!(!idx.is_complete());
    }

    #[test]
    fn test_invalid_range_rejected() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        let idx = RocksFilterIndex::new(store, enabled());
        // stop < start
        assert!(matches!(
            idx.headers_range(FILTER_TYPE_BASIC, 100, 50),
            Err(IndexError::InvalidRange { .. })
        ));
        // range == 1000 (BIP 157 says strictly less than 1000 difference).
        assert!(matches!(
            idx.headers_range(FILTER_TYPE_BASIC, 0, 1000),
            Err(IndexError::InvalidRange { .. })
        ));
    }

    #[test]
    fn test_filter_at_roundtrip_via_store() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        // Stamp a couple of filter rows directly through StoreBatch.
        let f1: Vec<u8> = vec![0x01, 0x02, 0x03];
        let h1 = [0x42u8; 32];
        let f2: Vec<u8> = vec![0xfe, 0xfd];
        let h2 = [0x99u8; 32];
        write_row(&store, 0, f1.clone(), h1);
        write_row(&store, 1, f2.clone(), h2);
        // InMemoryStore::filter_complete defaults to true.
        let idx = RocksFilterIndex::new(store, enabled());
        assert!(idx.is_complete());
        assert_eq!(idx.filter_at(FILTER_TYPE_BASIC, 0).unwrap(), f1);
        assert_eq!(idx.filter_at(FILTER_TYPE_BASIC, 1).unwrap(), f2);
        assert_eq!(idx.header_at(FILTER_TYPE_BASIC, 0).unwrap(), h1);
        assert_eq!(idx.header_at(FILTER_TYPE_BASIC, 1).unwrap(), h2);
        // Range read of headers.
        let r = idx.headers_range(FILTER_TYPE_BASIC, 0, 1).unwrap();
        assert_eq!(r, vec![h1, h2]);
    }

    #[test]
    fn test_not_found_height_above_tip() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        write_row(&store, 0, vec![0u8; 1], [0u8; 32]);
        let idx = RocksFilterIndex::new(store, enabled());
        assert!(matches!(
            idx.filter_at(FILTER_TYPE_BASIC, 100),
            Err(IndexError::NotFound(100))
        ));
    }

    #[test]
    fn test_checkpoints_to_returns_thousand_block_intervals() {
        let store = std::sync::Arc::new(InMemoryStore::new());
        for i in 0..=2_500u32 {
            // Every 1000th height carries a real header so checkpoints_to works.
            let header = if i.is_multiple_of(MAX_FILTER_RANGE) {
                [(i % 256) as u8; 32]
            } else {
                [0u8; 32]
            };
            write_row(&store, i, vec![0u8; 1], header);
        }
        let idx = RocksFilterIndex::new(store, enabled());
        let checkpoints = idx.checkpoints_to(FILTER_TYPE_BASIC, 2_499).unwrap();
        // BIP 157 returns intervals at 1000, 2000 (genesis is excluded;
        // the next post-stop boundary 3000 is past the stop).
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0], [(1000u32 % 256) as u8; 32]);
        assert_eq!(checkpoints[1], [(2000u32 % 256) as u8; 32]);
    }

    #[test]
    fn test_filter_hash_helper_matches_bitcoin_sha256d() {
        let payload = b"hello bip 158";
        let got = filter_hash(payload);
        let expected = bitcoin::hashes::sha256d::Hash::hash(payload).to_byte_array();
        assert_eq!(got, expected);
    }
}
