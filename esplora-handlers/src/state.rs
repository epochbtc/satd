//! Shared application state passed to every handler. Holds Arc
//! handles to the daemon's chainstate, mempool, fee estimator, and
//! the address-index / outpoint-spend trait objects from `node-index`.

use std::sync::Arc;

use bitcoin::Network;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node_index::{AddressIndex, SpendIndex};

use crate::config::EsploraConfig;

#[derive(Clone)]
pub struct EsploraState {
    pub chain: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub address_index: Arc<dyn AddressIndex>,
    pub spend_index: Arc<dyn SpendIndex>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub network: Network,
    pub config: Arc<EsploraConfig>,
}
