use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::net::manager::PeerManager;
use std::sync::Arc;

/// Shared state for MCP tool handlers — mirrors RpcContext but decoupled from jsonrpsee.
pub struct McpContext {
    pub chain_state: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub start_time: std::time::Instant,
    pub network: bitcoin::Network,
}
