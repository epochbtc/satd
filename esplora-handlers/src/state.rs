//! Shared application state passed to every handler. Holds Arc
//! handles to the daemon's chainstate, mempool, fee estimator, and
//! the address-index / outpoint-spend trait objects from `node-index`.

use std::sync::Arc;

use bitcoin::Network;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::net::manager::TxBroadcaster;
use node_index::{AddressIndex, SpendIndex};
use tokio::sync::Semaphore;

use crate::config::EsploraConfig;

#[derive(Clone)]
pub struct EsploraState {
    pub chain: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    /// Accepts + announces a broadcast tx (`POST /tx`) so it reaches the
    /// network — a bare mempool accept never leaves this node.
    pub tx_broadcaster: Arc<dyn TxBroadcaster>,
    pub address_index: Arc<dyn AddressIndex>,
    pub spend_index: Arc<dyn SpendIndex>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub network: Network,
    pub config: Arc<EsploraConfig>,
    /// Hard cap on concurrent SSE streams. Each handler acquires an
    /// `OwnedSemaphorePermit` and holds it inside the response stream;
    /// the permit drops when the stream is dropped (client disconnect
    /// or shutdown). Sized from `EsploraConfig::max_sse_conns` at
    /// startup. Separate from tower's `ConcurrencyLimitLayer` because
    /// that layer only bounds request *handling*, not the lifetime of
    /// long-lived streaming bodies (review M2).
    pub sse_semaphore: Arc<Semaphore>,
}
