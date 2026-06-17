use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::history::MempoolHistory;
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
    /// Post-merge effective config snapshot (secrets already redacted).
    /// Rendered at startup; reads are cheap clones of the cached JSON.
    pub effective_config: serde_json::Value,
    /// Mempool history ring — may be `None` in tests that bypass main.rs.
    pub mempool_history: Option<Arc<MempoolHistory>>,
    /// Whether the address-history index is enabled at runtime. Mirrors
    /// `MetricsContext::addr_enabled` so the `get_metrics_snapshot` tool
    /// reports the same `satd_addrindex_enabled` value as the HTTP scrape.
    pub addr_enabled: bool,
    /// Subscription registry handle for the active-subscribers gauge.
    /// `None` in tests that bypass main.rs.
    pub addr_subs: Option<Arc<node::index::address::SubscriptionRegistry>>,
}
