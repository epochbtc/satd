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
        self.store
            .lookup_spend(outpoint)
            .map_err(|e| node_index::IndexError::Storage(e.to_string()))
    }
}
