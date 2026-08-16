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
    /// Whether the silent-payment tweak index is enabled at runtime. Mirrors
    /// `MetricsContext::sp_enabled` for the same reason as `addr_enabled`: the
    /// `get_metrics_snapshot` tool must report the same `satd_spindex_enabled`
    /// value as the HTTP scrape, not a hardcoded zero.
    pub sp_enabled: bool,
    /// Whether the BIP 158 block-filter index is enabled at runtime.
    /// Mirrors `MetricsContext::filter_enabled` (#558) for the same
    /// reason as the other two `enabled` bits.
    pub filter_enabled: bool,
    /// Subscription registry handle for the active-subscribers gauge.
    /// `None` in tests that bypass main.rs.
    pub addr_subs: Option<Arc<node::index::address::SubscriptionRegistry>>,
    /// Health-detector readings, so `get_metrics_snapshot` renders the same
    /// health gauges as the HTTP scrape. `None` in tests that bypass main.rs.
    pub health: Option<Arc<node::health::HealthState>>,
    /// Webhook delivery counters, for the same reason. `None` in tests.
    pub webhooks: Option<Arc<node::metrics::WebhookMetrics>>,
}
