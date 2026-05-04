//! Shared application state passed to every method handler.
//!
//! Mirrors the `EsploraState` shape: `Arc` handles to the chainstate,
//! mempool, fee estimator, plus the trait-object index surfaces from
//! `node-index` and the [`ElectrumExtras`](crate::ElectrumExtras)
//! adapter from this crate. Cloned per-request handler invocation;
//! the underlying `Arc`s are cheap.

use std::sync::Arc;

use bitcoin::Network;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node_index::{AddressIndex, SpendIndex};

use crate::config::ElectrumConfig;
use crate::extras::ElectrumExtras;

#[derive(Clone)]
pub struct ElectrumState {
    pub chain: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub address_index: Arc<dyn AddressIndex>,
    pub spend_index: Arc<dyn SpendIndex>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub electrum_extras: Arc<dyn ElectrumExtras>,
    pub network: Network,
    pub config: Arc<ElectrumConfig>,
}
