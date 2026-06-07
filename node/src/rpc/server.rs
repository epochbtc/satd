use crate::chain::state::ChainState;
use crate::index::address::{AddressIndex, BackfillCommand, BackfillHandle};
use crate::mempool::fee::FeeEstimator;
use crate::mempool::history::MempoolHistory;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::rpc::amounts::{
    annotate_units, default_unit, format_amount, format_feerate_sat_per_kvb,
};
use crate::rpc::admission::{AdmissionLayer, AdmissionState};
use crate::rpc::auth::{AuthLayer, RpcAuth};
use crate::rpc::compat::JsonRpcCompatLayer;
use crate::rpc::capability::CapabilityLayer;
use crate::rpc::readonly::ReadOnlyLayer;
use crate::rpc::{access, address, blockchain, indexes, mining, network, psbt, rawtx, util};
use crate::storage::Store;
use jsonrpsee::server::middleware::rpc::RpcServiceBuilder;
use jsonrpsee::server::{
    Methods, RpcModule, ServerBuilder, ServerConfig, ServerHandle, serve_with_graceful_shutdown,
    stop_channel,
};
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Max concurrent RPC connections per listener. Mirrors jsonrpsee's own
/// `ServerConfig` default (100). Used both as the inner `ConnectionGuard`
/// limit and as the plain-HTTP accept-level semaphore size, so the two
/// bounds can't drift. Also passed to the startup-status RPC.
pub const RPC_MAX_CONNECTIONS: u32 = 100;

/// Shared, mutable record of which optional listeners actually bound
/// at startup. Updated by the listener wiring after each successful
/// bind; read by `getserverstatus` to report runtime — not config —
/// status.
///
/// Why this exists: config intent and runtime reality diverge in two
/// cases the operator cares about. (1) The Esplora startup gate
/// silently skips binding when `--addressindex=0` is set with the
/// default `--esplora=1`; the daemon keeps running with no Esplora
/// listener. (2) The Electrum / Esplora completeness-marker gates can
/// fail in production datadirs even after the daemon comes up. A
/// status RPC that reads from `effective_config` would lie about both.
#[derive(Default)]
pub struct ServerListenerStatus {
    inner: RwLock<ServerListenerStatusInner>,
}

#[derive(Default, Clone)]
struct ServerListenerStatusInner {
    esplora: Option<String>,
    electrum: Option<String>,
    electrum_tls: Option<String>,
    rpc_tls: Option<String>,
    events_grpc: Option<String>,
    streamws: Option<String>,
}

impl ServerListenerStatus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn set_esplora(&self, bind: String) {
        self.inner.write().esplora = Some(bind);
    }
    pub fn set_electrum(&self, bind: String) {
        self.inner.write().electrum = Some(bind);
    }
    pub fn set_electrum_tls(&self, bind: String) {
        self.inner.write().electrum_tls = Some(bind);
    }
    pub fn set_rpc_tls(&self, bind: String) {
        self.inner.write().rpc_tls = Some(bind);
    }
    pub fn set_events_grpc(&self, bind: String) {
        self.inner.write().events_grpc = Some(bind);
    }
    pub fn set_streamws(&self, bind: String) {
        self.inner.write().streamws = Some(bind);
    }
    fn snapshot(&self) -> ServerListenerStatusInner {
        self.inner.read().clone()
    }
}

/// TLS settings for the JSON-RPC server.
///
/// Operator-supplied PEM cert + key paths. Bitcoin Core's RPC is
/// HTTP-only; this is a satd-specific addition for operators who want
/// native TLS without a reverse proxy. Mirrors the Electrum / Esplora
/// TLS surfaces for ergonomic consistency.
///
/// `mtls_enabled` opts in to mutual TLS on this surface. When `true`,
/// `mtls_client_ca` MUST be `Some`; the rustls verifier rejects any
/// client without a CA-signed cert at handshake time. The mTLS path
/// is strictly additive — the existing HTTP Basic auth keeps running
/// on top unless the operator separately passes `--rpcdisableauth=1`
/// (which only takes effect on this TLS surface; the plain-HTTP
/// surface always keeps full auth).
#[derive(Debug, Clone)]
pub struct RpcTlsConfig {
    pub bind_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub mtls_enabled: bool,
    pub mtls_client_ca: Option<PathBuf>,
    pub mtls_client_allow: Vec<String>,
    /// Per-handshake wall-clock cap. Defaults to 10s (set by satd
    /// when constructing this struct); shorter than Electrum/Esplora
    /// (30s) because JSON-RPC clients are typically local or
    /// short-haul and a slow handshake is more likely a probe than a
    /// real client. Configurable via `--rpctlshandshaketimeout` so an
    /// operator behind a high-latency link can raise it.
    pub handshake_timeout: Duration,
    /// Hard cap on concurrent TLS connections (held until the
    /// connection closes). Defaults to 100, matching jsonrpsee's
    /// `ServerConfig::max_connections` so the TLS surface doesn't
    /// silently lose the cap the plain-HTTP path enforces via
    /// jsonrpsee's own Server::start path. (Review C1.)
    pub max_connections: usize,
}

/// Composite handle that stops every plain-HTTP listener and the
/// optional TLS surface. Returned by [`start`] so callers see a single
/// `.stop()` call regardless of how many plain-HTTP binds were
/// requested or whether TLS is enabled. Mirrors the shutdown
/// semantics of the plain-HTTP [`ServerHandle`] (i.e. an already-
/// stopped surface is not an error).
#[derive(Clone)]
pub struct RpcServerHandle {
    /// One handle per `--rpcbind` value. All share the same Methods +
    /// auth middleware; per-bind listeners exist purely so a node can
    /// bind several interfaces (the Bitcoin Core convention).
    plain: Vec<ServerHandle>,
    tls: Option<ServerHandle>,
    /// Handles for the opt-in read-only listener(s) (`-rpcreadonlybind`),
    /// one per bind. These run the same `Methods` behind the
    /// [`ReadOnlyLayer`] method filter, on the bounded API runtime rather
    /// than the consensus core. Empty when the read-only listener is not
    /// configured.
    readonly: Vec<ServerHandle>,
}

impl RpcServerHandle {
    /// Tell every plain-HTTP listener, the optional TLS surface, and any
    /// read-only listener to stop. Ignores `AlreadyStopped` errors so a
    /// previously-fired bridge or test teardown does not propagate to the
    /// caller.
    pub fn stop(&self) -> Result<(), jsonrpsee::server::AlreadyStoppedError> {
        if let Some(tls) = &self.tls {
            let _ = tls.stop();
        }
        // Stop every plain listener, ignoring `AlreadyStopped`. Each
        // plain surface has a bridge task that stops it as soon as the
        // process-wide shutdown watch fires (so it quits accepting
        // before the flush phase), which means by the time main's
        // explicit `stop()` runs the handle is usually already stopped.
        // `AlreadyStoppedError` is the only error this can yield and it
        // means the desired end state (stopped) already holds, so
        // swallowing it keeps `stop()` idempotent — callers `.expect()`
        // success here during shutdown.
        for h in &self.plain {
            let _ = h.stop();
        }
        // Read-only listeners get the same idempotent stop. They also
        // carry a shutdown-watch bridge, so they are usually already
        // stopped by the time this runs.
        for h in &self.readonly {
            let _ = h.stop();
        }
        Ok(())
    }
}

/// Configuration for the opt-in read-only JSON-RPC listener.
///
/// When `Some(..)` is passed to [`start`], satd binds one additional
/// listener per `bind_addr` that serves the **same** `Methods` as the main
/// listener but behind the [`ReadOnlyLayer`] method filter — only read and
/// mempool-submit methods are dispatched (see [`crate::rpc::access`]). These
/// listeners run on `api_handle` (the bounded API runtime) rather than the
/// consensus core, so a flood of consumer read traffic cannot starve block
/// connection. They reuse the main listener's auth (same credentials) and
/// have their own admission budget.
pub struct ReadOnlyListener {
    /// Bind addresses (`-rpcreadonlybind`). Non-empty enables the listener.
    pub bind_addrs: Vec<SocketAddr>,
    /// Source-address allowlist (`-rpcreadonlyallowip`), independent of the
    /// main listener's `-rpcallowip`.
    pub allowip: Vec<crate::rpc::allowip::IpAllowEntry>,
    /// Admission concurrency / backlog for this listener
    /// (`-rpcreadonlythreads` / `-rpcreadonlyworkqueue`), independent of the
    /// main listener's `-rpcthreads`/`-rpcworkqueue` budget.
    pub rpc_threads: usize,
    pub rpc_workqueue: usize,
    /// Optional TLS surface for the read-only listener (`-rpcreadonlytls*` /
    /// `-rpcreadonlymtls*`). `None` = plain-HTTP only. Serves the same
    /// read-only-filtered methods over TLS (and optional mTLS) on the API
    /// runtime, mirroring the main listener's TLS surface.
    pub tls: Option<RpcTlsConfig>,
    /// Handle to the bounded API runtime the listener's accept loop and
    /// per-connection tasks run on.
    pub api_handle: tokio::runtime::Handle,
}

/// Shared state for RPC handlers.
pub struct RpcContext {
    pub chain_state: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub shutdown_tx: watch::Sender<bool>,
    pub start_time: std::time::Instant,
    /// Observed at startup from the clean-shutdown marker. `true` if the
    /// previous process wrote the marker during a successful flush; `false`
    /// on first boot or after a crash / timed-out shutdown.
    pub last_shutdown_clean: bool,
    /// Pre-rendered effective-config view for the `getconfig` RPC.
    /// Computed once at startup (the server does not hot-reload config).
    /// Secret fields (passwords) are already redacted by the producer.
    pub effective_config: serde_json::Value,
    /// Ring of periodic mempool snapshots for `getmempoolhistory`.
    /// `None` when the history log failed to open at startup — in that
    /// case the RPC returns an empty snapshot list rather than lying
    /// with a synthetic fallback store.
    pub mempool_history: Option<Arc<MempoolHistory>>,
    /// Address-history index. Read surface for the `getaddress*` RPCs
    /// and (in M+1 milestones) the Electrum / Esplora handlers.
    pub address_index: Arc<dyn AddressIndex>,
    /// Whether the address-history index is enabled at runtime —
    /// used by `getindexinfo` to populate the `enabled` field.
    pub address_index_enabled: bool,
    /// Optional handle to the deferred-backfill task (M7). Drives
    /// `getindexinfo`, `backfillindex`, `pause/resume/cancel`. Tests
    /// without a backfill thread skip wiring; the RPCs return
    /// "not initialized" errors in that case.
    pub backfill: Option<Arc<BackfillHandle>>,
    /// Channel to the backfill supervisor task. `Some` when the
    /// supervisor is running; `None` when the binary was built without
    /// the supervisor wired (tests, embedded uses).
    pub backfill_cmd_tx: Option<tokio::sync::mpsc::Sender<BackfillCommand>>,
    /// Runtime listener status — read by `getserverstatus`. Mutated by
    /// the satd binary after each optional listener (Esplora,
    /// Electrum, Electrum TLS) successfully binds.
    pub listener_status: Arc<ServerListenerStatus>,
    /// Whether the BIP 158 filter index is enabled at runtime — used
    /// by `getindexinfo` and `getserverstatus` to populate the
    /// `block_filter_index.enabled` field.
    #[cfg(feature = "block-filter-index")]
    pub blockfilterindex_enabled: bool,
    /// Read-side handle for the BIP 158 compact-block-filter index.
    /// `getblockfilter` reads through this. `None` when the binary
    /// was constructed without the filter index wired.
    #[cfg(feature = "block-filter-index")]
    pub filter_index: Option<Arc<dyn node_filter_index::FilterIndex>>,
    /// Filter-index backfill handle. `Some` when the filter-index
    /// supervisor is wired (default in production); `None` for tests
    /// without a backfill thread.
    #[cfg(feature = "block-filter-index")]
    pub filter_backfill: Option<Arc<crate::index::filter::BackfillHandle>>,
    /// Channel to the filter-index backfill supervisor task.
    #[cfg(feature = "block-filter-index")]
    pub filter_backfill_cmd_tx:
        Option<tokio::sync::mpsc::Sender<crate::index::filter::BackfillCommand>>,
    /// Single-flight guard for `getblockfileaudit`. The audit performs a
    /// full `block_index` scan plus an 8-byte seek+read per indexed
    /// block — ~minute-scale on mainnet — so concurrent invocations
    /// would multiply the disk pressure and tie up `spawn_blocking`
    /// workers. Set to `true` while an audit is in flight; released by
    /// the RAII guard `AuditInflightGuard`.
    pub blockfile_audit_running: Arc<std::sync::atomic::AtomicBool>,
}

/// RAII guard that releases the [`RpcContext::blockfile_audit_running`]
/// flag on drop. Acquire via
/// [`try_acquire_blockfile_audit`]; the only correct way to release the
/// flag is letting the guard drop, so a panic mid-audit doesn't strand
/// the flag in `true` (which would lock out the RPC for the lifetime
/// of the process).
struct AuditInflightGuard {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for AuditInflightGuard {
    fn drop(&mut self) {
        self.flag.store(false, std::sync::atomic::Ordering::Release);
    }
}

fn try_acquire_blockfile_audit(
    flag: &Arc<std::sync::atomic::AtomicBool>,
) -> Option<AuditInflightGuard> {
    flag.compare_exchange(
        false,
        true,
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    )
    .ok()
    .map(|_| AuditInflightGuard { flag: flag.clone() })
}

/// Which data source `estimatesmartfee` / `estimatefees` draws from.
///
/// - `Historical` (default for `estimatesmartfee`): percentile of recent
///   confirmed-block feerates. Exactly matches pre-mempool-sim behavior
///   and Bitcoin Core's `estimatesmartfee` semantics.
/// - `Mempool`: simulate the next N block templates from the live
///   mempool and use the ancestor-feerate of the lowest admitted tx.
///   Responds faster to sudden congestion than historical.
/// - `Blend` (default for `estimatefees`): mempool estimate when
///   confidence >= medium; fall back to historical otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateMode {
    Historical,
    Mempool,
    Blend,
}

impl EstimateMode {
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s?.trim().to_ascii_lowercase().as_str() {
            "historical" | "conservative" | "economical" | "unset" => Some(Self::Historical),
            "mempool" => Some(Self::Mempool),
            "blend" => Some(Self::Blend),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Historical => "historical",
            Self::Mempool => "mempool",
            Self::Blend => "blend",
        }
    }
}

/// Resolve a single `estimatesmartfee` target into a feerate (sat/kvB).
///
/// Isolated so `estimatesmartfee` can stay Core-compatible: the response
/// shape never changes; only the source of the number does.
fn resolve_feerate_sat_per_kvb<F>(
    mode: EstimateMode,
    target: u32,
    historical: Option<u64>,
    floor_sat_per_kvb: u64,
    snapshot_fn: F,
) -> u64
where
    F: FnOnce() -> Vec<(bitcoin::Txid, crate::mempool::pool::MempoolEntry)>,
{
    match mode {
        EstimateMode::Historical => historical.unwrap_or(floor_sat_per_kvb),
        EstimateMode::Mempool => {
            let est =
                crate::mempool::estimate::estimate_from_mempool(snapshot_fn(), target as usize);
            let (rate, _) =
                crate::mempool::estimate::target_estimate(&est, target, floor_sat_per_kvb);
            rate
        }
        EstimateMode::Blend => {
            let est =
                crate::mempool::estimate::estimate_from_mempool(snapshot_fn(), target as usize);
            let (mp_rate, mp_conf) =
                crate::mempool::estimate::target_estimate(&est, target, floor_sat_per_kvb);
            if matches!(
                mp_conf,
                crate::mempool::estimate::Confidence::High
                    | crate::mempool::estimate::Confidence::Medium
            ) {
                mp_rate
            } else {
                historical.unwrap_or(floor_sat_per_kvb)
            }
        }
    }
}

/// Start the JSON-RPC HTTP server with authentication.
///
/// `bind_addrs` is the list of plain-HTTP bind addresses (one or more,
/// per `--rpcbind`). Each gets its own listener task; all share the
/// same auth + Methods (Arc-backed, cheap to clone). When `tls` is
/// `Some`, also binds a parallel HTTPS listener using the supplied
/// PEM cert + key. The plain-HTTP path is unchanged from the no-TLS
/// configuration; TLS is purely additive. The returned
/// [`RpcServerHandle`] stops every plain listener AND the TLS surface
/// on `.stop()`.
///
/// `allowip` is the parsed `-rpcallowip` source-address allowlist and is
/// ENFORCED per request: each plain-HTTP listener runs a manual accept
/// loop (jsonrpsee's high-level `Server::start()` never surfaces the
/// peer `SocketAddr` to the HTTP middleware, so a tower layer can't see
/// it). A connection whose source IP is neither loopback nor inside a
/// listed CIDR is answered with `403 Forbidden` and never reaches the
/// RPC methods. An empty allowlist means loopback-only; the static
/// "must allowlist before exposing" check in `Config::load` keeps a
/// non-loopback bind from ever running without an allowlist.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    bind_addrs: Vec<SocketAddr>,
    allowip: Vec<crate::rpc::allowip::IpAllowEntry>,
    tls: Option<RpcTlsConfig>,
    auth: Arc<RpcAuth>,
    // `tls_auth` is applied to the TLS surface only. `None` (the
    // common case) means "same as `auth`". `Some(Arc::new(RpcAuth::
    // Disabled))` is the mTLS escape hatch: clients prove identity
    // via the rustls handshake and the AuthLayer becomes a pass-
    // through. The plain-HTTP surface always uses `auth` unchanged —
    // disabling on plain HTTP would open a no-auth port. satd's
    // config-load validation enforces "Disabled requires mTLS"; this
    // layer accepts whatever the caller passes.
    tls_auth: Option<Arc<RpcAuth>>,
    // Unified-auth bearer-token store, `Some` only when `-rpcauthbearer` is set
    // (which requires `authfile`). When present, the full read/write listeners
    // (plain + TLS) additionally accept `Authorization: Bearer <token>` and
    // enforce per-method capabilities; the operator credential keeps full
    // access. `None` is today's behavior (operator-only, no capability filter).
    bearer: Option<Arc<satd_auth::TokenStore>>,
    // RPC admission control (Bitcoin Core `-rpcthreads` / `-rpcworkqueue`).
    // Bounds concurrent in-flight method calls and the backlog allowed to
    // wait before shedding with HTTP 429. Shared across the plain-HTTP and
    // TLS surfaces as a single node-wide RPC work budget.
    rpc_threads: usize,
    rpc_workqueue: usize,
    chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
    peer_manager: Arc<PeerManager>,
    fee_estimator: Arc<FeeEstimator>,
    shutdown_tx: watch::Sender<bool>,
    last_shutdown_clean: bool,
    effective_config: serde_json::Value,
    mempool_history: Option<Arc<MempoolHistory>>,
    address_index: Arc<dyn AddressIndex>,
    address_index_enabled: bool,
    backfill: Option<Arc<BackfillHandle>>,
    backfill_cmd_tx: Option<tokio::sync::mpsc::Sender<BackfillCommand>>,
    listener_status: Arc<ServerListenerStatus>,
    #[cfg(feature = "block-filter-index")] blockfilterindex_enabled: bool,
    #[cfg(feature = "block-filter-index")] filter_index: Option<
        Arc<dyn node_filter_index::FilterIndex>,
    >,
    #[cfg(feature = "block-filter-index")] filter_backfill: Option<
        Arc<crate::index::filter::BackfillHandle>,
    >,
    #[cfg(feature = "block-filter-index")] filter_backfill_cmd_tx: Option<
        tokio::sync::mpsc::Sender<crate::index::filter::BackfillCommand>,
    >,
    // Opt-in read-only listener (`-rpcreadonlybind`). `None` (the default)
    // means only the full read/write listener on the consensus runtime is
    // served — the Core-compatible single-listener behavior.
    readonly: Option<ReadOnlyListener>,
) -> Result<RpcServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    // Listener-status + shutdown_tx are needed both inside the RPC
    // context (so the `stop` RPC + `getserverstatus` can use them) AND
    // by the TLS surface wiring below. Clone the Arcs / watch::Sender
    // here so the eventual `RpcModule::new(ctx)` consumption below
    // doesn't strand us without a handle to those values.
    let listener_status_outer = listener_status.clone();
    let shutdown_tx_outer = shutdown_tx.clone();

    let ctx = Arc::new(RpcContext {
        chain_state,
        mempool,
        peer_manager,
        fee_estimator,
        shutdown_tx,
        start_time: std::time::Instant::now(),
        last_shutdown_clean,
        effective_config,
        mempool_history,
        address_index,
        address_index_enabled,
        backfill,
        backfill_cmd_tx,
        listener_status,
        #[cfg(feature = "block-filter-index")]
        blockfilterindex_enabled,
        #[cfg(feature = "block-filter-index")]
        filter_index,
        #[cfg(feature = "block-filter-index")]
        filter_backfill,
        #[cfg(feature = "block-filter-index")]
        filter_backfill_cmd_tx,
        blockfile_audit_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    let mut module = RpcModule::new(ctx);

    // --- Blockchain RPCs ---

    module.register_method("getblockchaininfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_blockchain_info(&ctx.chain_state))
    })?;

    module.register_method("getnetworkinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(network::get_network_info(&ctx.peer_manager))
    })?;

    module.register_method("getbestblockhash", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_best_block_hash(&ctx.chain_state))
    })?;

    module.register_method("getblockcount", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_block_count(&ctx.chain_state))
    })?;

    module.register_method("getblockhash", |params, ctx, _extensions| {
        let height: u32 = params.one().map_err(|e| {
            crate::rpc::error::RpcError::new(-1, "rpc.input.parse", e.to_string())
                .with_suggestion("Pass a single integer block height argument.")
                .into_error_object()
        })?;
        let tip = ctx.chain_state.tip_height();
        blockchain::get_block_hash(&ctx.chain_state, height).map_err(|e| {
            crate::rpc::error::RpcError::new(-8, "rpc.input.range", e)
                .with_suggestion(format!(
                    "Chain tip is at height {}. Request a height in [0, {}].",
                    tip, tip
                ))
                .with_debug(serde_json::json!({"requested_height": height, "tip_height": tip}))
                .into_error_object()
        })
    })?;

    module.register_method("getblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hash: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let verbosity: u32 = seq.optional_next().unwrap_or(Some(1)).unwrap_or(1);
        blockchain::get_block(&ctx.chain_state, &hash, verbosity)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getblockheader", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hash: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(true)).unwrap_or(true);
        blockchain::get_block_header(&ctx.chain_state, &hash, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getdifficulty", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_difficulty(&ctx.chain_state))
    })?;

    module.register_method("getblockstats", |params, ctx, _extensions| {
        let hash_or_height: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::get_block_stats(&ctx.chain_state, &hash_or_height)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getchaintips", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_chain_tips(&ctx.chain_state))
    })?;

    module.register_method("getchainstates", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_chain_states(&ctx.chain_state))
    })?;

    module.register_method("getchaintxstats", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let nblocks: Option<u32> = seq.optional_next().unwrap_or(None);
        // Core's optional second arg: the block that ends the window.
        let blockhash_str: Option<String> = seq.optional_next().unwrap_or(None);
        let final_blockhash = match blockhash_str {
            Some(s) => Some(s.parse::<bitcoin::BlockHash>().map_err(|e| {
                ErrorObjectOwned::owned(-8, format!("invalid blockhash: {e}"), None::<()>)
            })?),
            None => None,
        };
        blockchain::get_chain_tx_stats(&ctx.chain_state, nblocks, final_blockhash)
            .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))
    })?;

    module.register_method("getmempoolancestors", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        blockchain::get_mempool_ancestors(&ctx.mempool, &txid, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getmempooldescendants", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        blockchain::get_mempool_descendants(&ctx.mempool, &txid, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getmempoolentry", |params, ctx, _extensions| {
        // Accepts either a single txid string (Core-compat) or an array
        // of txids (bulk). On bulk, returns a map of txid → entry | null.
        let mut seq = params.sequence();
        let first: serde_json::Value = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        match first {
            serde_json::Value::Array(arr) => {
                let mut txids: Vec<String> = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        serde_json::Value::String(s) => txids.push(s),
                        other => {
                            return Err(ErrorObjectOwned::owned(
                                -1,
                                format!("expected string txid, got {}", other),
                                None::<()>,
                            ));
                        }
                    }
                }
                Ok::<_, ErrorObjectOwned>(blockchain::get_mempool_entries_bulk(
                    &ctx.mempool,
                    &txids,
                ))
            }
            serde_json::Value::String(s) => blockchain::get_mempool_entry(&ctx.mempool, &s)
                .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>)),
            other => Err(ErrorObjectOwned::owned(
                -1,
                format!("expected string txid or array of txids, got {}", other),
                None::<()>,
            )),
        }
    })?;

    module.register_method("preciousblock", |params, _ctx, _extensions| {
        let hash: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::precious_block(&hash).map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))
    })?;

    module.register_method("invalidateblock", |params, ctx, _extensions| {
        let hash: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::invalidate_block(&ctx.chain_state, &hash)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("reconsiderblock", |params, ctx, _extensions| {
        let hash: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::reconsider_block(&ctx.chain_state, &hash)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("verifychain", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let check_level: u32 = seq.optional_next().unwrap_or(Some(3)).unwrap_or(3);
        let nblocks: u32 = seq.optional_next().unwrap_or(Some(6)).unwrap_or(6);
        Ok::<_, ErrorObjectOwned>(blockchain::verify_chain(
            &ctx.chain_state,
            check_level,
            nblocks,
        ))
    })?;

    module.register_method("savemempool", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::save_mempool())
    })?;

    module.register_method("dumptxoutset", |params, ctx, _extensions| {
        let path: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::dump_txout_set(&ctx.chain_state, &path)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("loadtxoutset", |params, ctx, _extensions| {
        let path: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        // Network datadir (parent of chainstate/) and prune target from
        // the effective config. For mainnet — the only network with
        // AssumeUTXO anchors — the network datadir is the base datadir.
        let datadir = ctx
            .effective_config
            .get("datadir")
            .and_then(|v| v.as_str())
            .map(std::path::PathBuf::from)
            .ok_or_else(|| {
                ErrorObjectOwned::owned(-1, "datadir not available in config", None::<()>)
            })?;
        let prune_target = ctx
            .effective_config
            .get("prune")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Background coins-DB cache: honor the operator's configured
        // dbcache (the background is transient and dropped at handoff),
        // falling back to a modest default.
        let dbcache_mb = ctx
            .effective_config
            .get("dbcache")
            .and_then(|v| v.as_u64())
            .unwrap_or(256);
        blockchain::load_txout_set(&ctx.chain_state, &datadir, prune_target, dbcache_mb, &path)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- Address-history index RPCs (M3) ---

    module.register_method("getaddressbalance", |params, ctx, _extensions| {
        let v: serde_json::Value = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        address::get_address_balance(&ctx.address_index, &v, ctx.chain_state.network)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getaddresshistory", |params, ctx, _extensions| {
        let v: serde_json::Value = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        address::get_address_history(&ctx.address_index, &v, ctx.chain_state.network)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getaddressutxos", |params, ctx, _extensions| {
        let v: serde_json::Value = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        address::get_address_utxos(&ctx.address_index, &v, ctx.chain_state.network)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- Index control RPCs (M7) ---

    #[cfg(feature = "block-filter-index")]
    module.register_method("getblockfilter", |params, ctx, _extensions| {
        // `getblockfilter <blockhash> [filtertype]`. Bitcoin-Core-compatible.
        let mut seq = params.sequence();
        let block_hash: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-8, e.to_string(), None::<()>))?;
        let filter_type: Option<String> = seq
            .optional_next()
            .map_err(|e| ErrorObjectOwned::owned(-8, e.to_string(), None::<()>))?;
        indexes::get_block_filter(
            &ctx.chain_state,
            ctx.filter_index.as_ref(),
            &block_hash,
            filter_type.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getindexinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(indexes::get_index_info(
            ctx.backfill.as_ref(),
            &ctx.chain_state,
            ctx.address_index_enabled,
            ctx.chain_state.tip_height(),
            #[cfg(feature = "block-filter-index")]
            ctx.blockfilterindex_enabled,
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
        ))
    })?;

    module.register_method("backfillindex", |params, ctx, _extensions| {
        let target: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        indexes::backfill_index(
            ctx.backfill.as_ref(),
            ctx.backfill_cmd_tx.as_ref(),
            &ctx.chain_state,
            ctx.address_index_enabled,
            &target,
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill_cmd_tx.as_ref(),
            #[cfg(feature = "block-filter-index")]
            ctx.blockfilterindex_enabled,
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("pauseindex", |params, ctx, _extensions| {
        let target: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        indexes::pause_index(
            ctx.backfill.as_ref(),
            &target,
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("resumeindex", |params, ctx, _extensions| {
        let target: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        indexes::resume_index(
            ctx.backfill.as_ref(),
            &target,
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("cancelindex", |params, ctx, _extensions| {
        let target: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        indexes::cancel_index(
            ctx.backfill.as_ref(),
            &target,
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- Mining RPCs ---

    module.register_method("submitblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_block: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        Ok::<_, ErrorObjectOwned>(mining::submit_block(
            &ctx.chain_state,
            &ctx.mempool,
            &hex_block,
        ))
    })?;

    module.register_method("generatetoaddress", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let nblocks: u32 = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let address: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        mining::generate_to_address(&ctx.chain_state, &ctx.mempool, nblocks, &address)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("generateblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let address: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        mining::generate_block(&ctx.chain_state, &ctx.mempool, &address)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getblocktemplate", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(mining::get_block_template(&ctx.chain_state, &ctx.mempool))
    })?;

    module.register_method("getmininginfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(mining::get_mining_info(&ctx.chain_state))
    })?;

    module.register_method("getnetworkhashps", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let nblocks: Option<u32> = seq.optional_next().unwrap_or(None);
        let height: Option<u32> = seq.optional_next().unwrap_or(None);
        Ok::<_, ErrorObjectOwned>(serde_json::json!(mining::get_network_hash_ps(
            &ctx.chain_state,
            nblocks,
            height,
        )))
    })?;

    module.register_method("submitheader", |params, ctx, _extensions| {
        let hex_header: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        mining::submit_header(&ctx.chain_state, &hex_header)
            .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))
    })?;

    // --- Transaction / Mempool RPCs ---

    module.register_method("sendrawtransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_tx: String = seq.next().map_err(|e| {
            crate::rpc::error::RpcError::new(-1, "rpc.input.parse", e.to_string())
                .with_suggestion("Pass the raw transaction as a hex string in the first argument.")
                .into_error_object()
        })?;
        let result = rawtx::send_raw_transaction(&ctx.chain_state, &ctx.mempool, &hex_tx).map_err(
            |(code, msg)| {
                // Classify the mempool error by its code (Core taxonomy):
                // -22 = decode failed, -25 = mempool acceptance failure.
                let (category, suggestion) = match code {
                    -22 => (
                        "rpc.input.parse",
                        "Transaction hex failed to decode. Ensure it's a valid raw tx (no 0x prefix, no whitespace).",
                    ),
                    -25 => (
                        "mempool.rejected",
                        "Mempool rejected the tx. Check feerate (--minrelaytxfee), dust thresholds, and conflicts with existing mempool contents.",
                    ),
                    _ => ("rpc.unknown", ""),
                };
                let mut err = crate::rpc::error::RpcError::new(code, category, msg);
                if !suggestion.is_empty() {
                    err = err.with_suggestion(suggestion);
                }
                err.into_error_object()
            },
        )?;
        // Announce the just-accepted tx to peers so an RPC broadcast
        // actually propagates to the network. `send_raw_transaction`
        // only enters it into the mempool; without this it would sit
        // there unannounced (the relay path only fires for txs received
        // from another peer).
        if let Some(txid) = result.as_str().and_then(|s| s.parse().ok()) {
            ctx.peer_manager.announce_tx(txid);
        }
        Ok::<_, ErrorObjectOwned>(result)
    })?;

    module.register_method("getmempoolinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(rawtx::get_mempool_info(&ctx.mempool))
    })?;

    module.register_method("getorphaninfo", |_params, ctx, _extensions| {
        let orphanage = ctx.peer_manager.orphanage();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "size": orphanage.len(),
            "bytes": orphanage.bytes(),
            "max_size": orphanage.config().max_count,
        }))
    })?;

    module.register_method("getrawmempool", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        Ok::<_, ErrorObjectOwned>(rawtx::get_raw_mempool(&ctx.mempool, verbose))
    })?;

    module.register_method("getrawtransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        let blockhash: Option<String> = seq.optional_next().unwrap_or(None);
        rawtx::get_raw_transaction(
            &ctx.chain_state,
            &ctx.mempool,
            &txid,
            verbose,
            blockhash.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decoderawtransaction", |params, _ctx, _extensions| {
        let hex_tx: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        rawtx::decode_raw_transaction(&hex_tx)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("createrawtransaction", |params, _ctx, _extensions| {
        let mut seq = params.sequence();
        let inputs: Vec<serde_json::Value> = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let outputs: serde_json::Value = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let locktime: Option<u32> = seq.optional_next().unwrap_or(None);
        rawtx::create_raw_transaction(&inputs, &outputs, locktime)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("combinerawtransaction", |params, _ctx, _extensions| {
        let hex_txs: Vec<String> = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        rawtx::combine_raw_transaction(&hex_txs)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decodescript", |params, _ctx, _extensions| {
        let hex_script: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        rawtx::decode_script(&hex_script)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("signrawtransactionwithkey", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_tx: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let privkeys: Vec<String> = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let prevtxs: Option<Vec<serde_json::Value>> = seq.optional_next().unwrap_or(None);
        let sighash_type: Option<String> = seq.optional_next().unwrap_or(None);
        rawtx::sign_raw_transaction_with_key(
            &ctx.chain_state,
            &hex_tx,
            &privkeys,
            prevtxs.as_deref(),
            sighash_type.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("testmempoolaccept", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let rawtxs: Vec<String> = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let mut results = Vec::new();
        for hex_tx in &rawtxs {
            let tx_bytes = hex::decode(hex_tx)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            match ctx
                .mempool
                .test_accept(&tx, &ctx.chain_state, ctx.chain_state.script_verifier())
            {
                Ok((txid, vsize, fees)) => {
                    results.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "allowed": true,
                        "vsize": vsize,
                        "fees": {
                            "base": format_amount(fees, default_unit()),
                        },
                    }));
                }
                Err(e) => {
                    let txid = tx.compute_txid();
                    results.push(serde_json::json!({
                        "txid": txid.to_string(),
                        "allowed": false,
                        "reject-reason": e.to_string(),
                    }));
                }
            }
        }
        Ok::<_, ErrorObjectOwned>(serde_json::json!(results))
    })?;

    // --- PSBT RPCs ---

    module.register_method("createpsbt", |params, _ctx, _extensions| {
        let mut seq = params.sequence();
        let inputs: Vec<serde_json::Value> = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let outputs: serde_json::Value = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let locktime: Option<u32> = seq.optional_next().unwrap_or(None);
        psbt::create_psbt(&inputs, &outputs, locktime)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decodepsbt", |params, _ctx, _extensions| {
        let psbt_b64: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::decode_psbt(&psbt_b64)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("analyzepsbt", |params, _ctx, _extensions| {
        let psbt_b64: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::analyze_psbt(&psbt_b64)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("combinepsbt", |params, _ctx, _extensions| {
        let psbt_b64s: Vec<String> = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::combine_psbt(&psbt_b64s)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("finalizepsbt", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let psbt_b64: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let extract: bool = seq.optional_next().unwrap_or(Some(true)).unwrap_or(true);
        let _ = &ctx; // suppress unused
        psbt::finalize_psbt(&psbt_b64, extract)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("converttopsbt", |params, _ctx, _extensions| {
        let hex_tx: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::convert_to_psbt(&hex_tx)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("joinpsbts", |params, _ctx, _extensions| {
        let psbt_b64s: Vec<String> = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::join_psbts(&psbt_b64s)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("utxoupdatepsbt", |params, ctx, _extensions| {
        let psbt_b64: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        psbt::utxo_update_psbt(&ctx.chain_state, &psbt_b64)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- UTXO / Chain RPCs ---

    module.register_method("gettxout", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let vout: u32 = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        blockchain::get_tx_out(&ctx.chain_state, &txid, vout)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("gettxoutsetinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_tx_out_set_info(&ctx.chain_state))
    })?;

    module.register_method("estimatesmartfee", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let conf_target: u32 = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        // Optional trailing `mode` string. Core-compat vocabulary
        // (ECONOMICAL/CONSERVATIVE/UNSET) is accepted and treated as
        // Historical; our own vocabulary is historical/mempool/blend.
        let mode_str: Option<String> = seq.optional_next().unwrap_or(None);
        let mode = EstimateMode::parse(mode_str.as_deref()).unwrap_or(EstimateMode::Historical);

        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        let historical = ctx.fee_estimator.estimate_fee(conf_target);
        let sat_per_kvb =
            resolve_feerate_sat_per_kvb(mode, conf_target, historical, floor_sat_per_kvb, || {
                ctx.mempool.get_all_entries()
            });
        let mut response = serde_json::json!({
            "feerate": format_feerate_sat_per_kvb(sat_per_kvb, unit),
            "blocks": conf_target,
            "errors": [],
        });
        annotate_units(&mut response, unit);
        Ok::<_, ErrorObjectOwned>(response)
    })?;

    module.register_method("estimatefees", |params, ctx, _extensions| {
        // `estimatefees [targets] [mode]` — both optional.
        // `targets`: array of confirmation targets in blocks. Default
        // `[1, 3, 6, 12, 24]`. `mode` (default "blend") selects the data
        // source.
        let mut seq = params.sequence();
        let targets: Vec<u32> = seq
            .optional_next()
            .unwrap_or(None)
            .unwrap_or_else(|| vec![1u32, 3, 6, 12, 24]);
        let mode_str: Option<String> = seq.optional_next().unwrap_or(None);
        let mode = EstimateMode::parse(mode_str.as_deref()).unwrap_or(EstimateMode::Blend);

        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        let max_target = targets.iter().copied().max().unwrap_or(24).max(1);
        let snapshot = ctx.mempool.get_all_entries();
        let mempool_est =
            crate::mempool::estimate::estimate_from_mempool(snapshot, max_target as usize);

        let mut targets_obj = serde_json::Map::new();
        let mut any_fallback = false;
        for t in &targets {
            let (rate_kvb, conf) = match mode {
                EstimateMode::Historical => {
                    let h = ctx.fee_estimator.estimate_fee(*t);
                    let r = h.unwrap_or(floor_sat_per_kvb);
                    let c = if h.is_some() {
                        crate::mempool::estimate::Confidence::Medium
                    } else {
                        any_fallback = true;
                        crate::mempool::estimate::Confidence::Low
                    };
                    (r, c)
                }
                EstimateMode::Mempool => {
                    crate::mempool::estimate::target_estimate(&mempool_est, *t, floor_sat_per_kvb)
                }
                EstimateMode::Blend => {
                    let (mp_rate, mp_conf) = crate::mempool::estimate::target_estimate(
                        &mempool_est,
                        *t,
                        floor_sat_per_kvb,
                    );
                    if matches!(
                        mp_conf,
                        crate::mempool::estimate::Confidence::High
                            | crate::mempool::estimate::Confidence::Medium
                    ) {
                        (mp_rate, mp_conf)
                    } else if let Some(h) = ctx.fee_estimator.estimate_fee(*t) {
                        any_fallback = true;
                        (h, crate::mempool::estimate::Confidence::Medium)
                    } else {
                        any_fallback = true;
                        (floor_sat_per_kvb, crate::mempool::estimate::Confidence::Low)
                    }
                }
            };
            let conf_str = match conf {
                crate::mempool::estimate::Confidence::High => "high",
                crate::mempool::estimate::Confidence::Medium => "medium",
                crate::mempool::estimate::Confidence::Low => "low",
            };
            targets_obj.insert(
                t.to_string(),
                serde_json::json!({
                    "feerate": format_feerate_sat_per_kvb(rate_kvb, unit),
                    "confidence": conf_str,
                }),
            );
        }

        let histogram: Vec<serde_json::Value> = mempool_est
            .histogram
            .iter()
            .map(|b| {
                serde_json::json!({
                    "feerate": format_feerate_sat_per_kvb(b.feerate_sat_per_kvb, unit),
                    "weight": b.weight,
                })
            })
            .collect();

        // economyFee: "cheap but reasonable" — clamp hour rate between
        // min-relay floor and 2× floor. Hour rate = the deepest target
        // the caller asked for.
        let hour_target = targets.iter().copied().max().unwrap_or(24);
        let hour_rate = match mode {
            EstimateMode::Historical => ctx
                .fee_estimator
                .estimate_fee(hour_target)
                .unwrap_or(floor_sat_per_kvb),
            _ => {
                let (r, _) = crate::mempool::estimate::target_estimate(
                    &mempool_est,
                    hour_target,
                    floor_sat_per_kvb,
                );
                r
            }
        };
        let economy_rate =
            crate::mempool::estimate::economy_feerate_sat_per_kvb(floor_sat_per_kvb, hour_rate);
        let thin_block = crate::mempool::estimate::is_thin_block(&mempool_est);

        let mut response = serde_json::json!({
            "targets": targets_obj,
            "histogram": histogram,
            "mode": mode.as_str(),
            "fallback": any_fallback,
            "mempool_weight": mempool_est.mempool_weight,
            "economy_feerate": format_feerate_sat_per_kvb(economy_rate, unit),
            "thin_block": thin_block,
        });
        annotate_units(&mut response, unit);
        Ok::<_, ErrorObjectOwned>(response)
    })?;

    // --- P2P RPCs ---

    module.register_method("getpeerinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.get_peer_info()))
    })?;

    module.register_method("getconnectioncount", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.connection_count()))
    })?;

    module.register_method("getibdprogress", |_params, ctx, _extensions| {
        match ctx.peer_manager.get_ibd_progress() {
            Some(progress) => Ok::<_, ErrorObjectOwned>(progress),
            None => Ok::<_, ErrorObjectOwned>(serde_json::json!({"active": false})),
        }
    })?;

    module.register_async_method("addnode", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let addr_str: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let command: String = seq
            .optional_next()
            .unwrap_or(Some("onetry".to_string()))
            .unwrap_or("onetry".to_string());

        // Parse via PeerAddr so `.onion:port` targets are accepted, not just
        // `SocketAddr`s — Bitcoin Core's addnode takes onion addresses, and a
        // SocketAddr can't represent a hostname. Onion peers are dialed through
        // the configured SOCKS proxy by `connect_peer_addr`.
        match command.as_str() {
            "add" => {
                // Register for auto-reconnect and return immediately, matching
                // Core (and the `-addnode` config path): `add` records the peer;
                // the reconnect loop dials it. Blocking here would stall the RPC
                // for the whole connect timeout — up to the 20s onion floor — and
                // wrongly report a transient dial failure as an addnode error.
                let addr = crate::net::peer::PeerAddr::parse(&addr_str)
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                ctx.peer_manager.add_peer_addr(addr.clone());
                let pm = ctx.peer_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::debug!(%addr, "addnode add: initial dial failed: {e}");
                    }
                });
            }
            "onetry" => {
                // A single, un-remembered attempt — block on it and surface the
                // result, matching the prior satd behavior (now onion-capable).
                let addr = crate::net::peer::PeerAddr::parse(&addr_str)
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                ctx.peer_manager
                    .connect_peer_addr(&addr)
                    .await
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
            }
            "remove" => {
                let addr = crate::net::peer::PeerAddr::parse(&addr_str)
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                ctx.peer_manager.remove_peer_addr(&addr);
            }
            other => {
                return Err(ErrorObjectOwned::owned(
                    -1,
                    format!("addnode: unknown command '{other}' (expected add/onetry/remove)"),
                    None::<()>,
                ));
            }
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("getaddednodeinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.get_added_node_info()))
    })?;

    module.register_method("getnettotals", |_params, ctx, _extensions| {
        let totals = ctx.peer_manager.net_totals();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "totalbytesrecv": totals.bytes_recv(),
            "totalbytessent": totals.bytes_sent(),
            "timemillis": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }))
    })?;

    module.register_method("listbanned", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.list_banned()))
    })?;

    module.register_method("setban", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let addr_str: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let command: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let addr: std::net::SocketAddr =
            addr_str.parse().map_err(|e: std::net::AddrParseError| {
                ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
            })?;
        match command.as_str() {
            "add" => ctx.peer_manager.set_ban(addr, true),
            "remove" => ctx.peer_manager.set_ban(addr, false),
            _ => return Err(ErrorObjectOwned::owned(-1, "Invalid command", None::<()>)),
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("clearbanned", |_params, ctx, _extensions| {
        ctx.peer_manager.clear_banned();
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("ping", |_params, ctx, _extensions| {
        ctx.peer_manager.ping_all();
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("setnetworkactive", |params, ctx, _extensions| {
        let active: bool = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        ctx.peer_manager.set_network_active(active);
        // Core returns the resulting state.
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.is_network_active()))
    })?;

    module.register_method("prioritisetransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid_str: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let _dummy: Option<f64> = seq.optional_next().unwrap_or(None); // ignored (Core compat)
        let fee_delta: i64 = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let txid: bitcoin::Txid = txid_str
            .parse()
            .map_err(|_| ErrorObjectOwned::owned(-8, "Invalid txid", None::<()>))?;
        let found = ctx.mempool.prioritise_transaction(&txid, fee_delta);
        Ok::<_, ErrorObjectOwned>(serde_json::json!(found))
    })?;

    module.register_method("disconnectnode", |params, ctx, _extensions| {
        let addr_str: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let addr: std::net::SocketAddr =
            addr_str.parse().map_err(|e: std::net::AddrParseError| {
                ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
            })?;
        ctx.peer_manager.disconnect(&addr);
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    // --- Control RPCs ---

    module.register_method("help", |_params, _ctx, _extensions| {
        let methods = vec![
            "addnode",
            "clearbanned",
            "decoderawtransaction",
            "decodescript",
            "disconnectnode",
            "dumptxoutset",
            "estimatefees",
            "estimatesmartfee",
            "generateblock",
            "generatetoaddress",
            "getaddednodeinfo",
            "getbestblockhash",
            "getblock",
            "getblockchaininfo",
            "getblockcount",
            "getblockhash",
            "getblockheader",
            "getblockstats",
            "getblocktemplate",
            "getchaintips",
            "getchaintxstats",
            "getconfig",
            "getconnectioncount",
            "getdifficulty",
            "getibdprogress",
            "getmempoolancestors",
            "getmempooldescendants",
            "getmempoolentry",
            "getmempoolhistory",
            "getmempoolinfo",
            "getmemoryinfo",
            "getmininginfo",
            "getnettotals",
            "getnetworkhashps",
            "getnetworkinfo",
            "getorphaninfo",
            "getpeerinfo",
            "getrawmempool",
            "getrawtransaction",
            "getreorghistory",
            "getrpcinfo",
            "getserverstatus",
            "getsysteminfo",
            "gettxout",
            "getwarnings",
            "gettxoutsetinfo",
            "help",
            "invalidateblock",
            "listbanned",
            "logging",
            "ping",
            "preciousblock",
            "prioritisetransaction",
            "reconsiderblock",
            "savemempool",
            "sendrawtransaction",
            "setban",
            "signrawtransactionwithkey",
            "setnetworkactive",
            "stop",
            "submitblock",
            "submitheader",
            "subscribemempool",
            "testmempoolaccept",
            "unsubscribemempool",
            "uptime",
            "verifychain",
        ];
        Ok::<_, ErrorObjectOwned>(serde_json::json!(methods.join("\n")))
    })?;

    module.register_method("uptime", |_params, ctx, _extensions| {
        let uptime = ctx.start_time.elapsed().as_secs();
        Ok::<_, ErrorObjectOwned>(serde_json::json!(uptime))
    })?;

    module.register_method("getconfig", |_params, ctx, _extensions| {
        // Effective node configuration — computed at startup. Passwords
        // and cookie values are redacted. This is advisory, not a
        // machine-consumable API: field names track satd internals.
        Ok::<_, ErrorObjectOwned>(ctx.effective_config.clone())
    })?;

    module.register_method("getserverstatus", |_params, ctx, _extensions| {
        // Compact runtime listener status for monitoring (sat-tui).
        // Reads the live `ServerListenerStatus` populated as each
        // optional server binds during startup — not the operator's
        // configuration — so silent skips (e.g. Esplora skipped when
        // `--addressindex=0` is paired with the default `--esplora=1`)
        // surface accurately as `null`.
        //
        // Wire shape: each listener is either `null` (not bound) or
        // `{"bind": "..."}` (bound and serving). `addressindex` rides
        // its own shape because it is an in-process index, not a
        // listener: `enabled` reflects the configured runtime, and
        // `complete` reflects the on-disk completeness marker the
        // wallet servers gate their bind on.
        let snap = ctx.listener_status.snapshot();
        let listener = |bind: Option<String>| -> serde_json::Value {
            match bind {
                Some(b) => serde_json::json!({ "bind": b }),
                None => serde_json::Value::Null,
            }
        };
        // Build the response with optional blockfilterindex sibling.
        // The BIP 158 filter index rides the same shape as the
        // address-index (an in-process index, not a listener) so a
        // future sat-tui `bf-idx` column matches the existing
        // `addr-idx` rendering.
        let mut resp = serde_json::Map::new();
        resp.insert(
            "addressindex".into(),
            serde_json::json!({
                "enabled": ctx.address_index_enabled,
                "complete": ctx.chain_state.store_ref().address_index_complete(),
            }),
        );
        resp.insert("esplora".into(), listener(snap.esplora));
        resp.insert("electrum".into(), listener(snap.electrum));
        resp.insert("electrum_tls".into(), listener(snap.electrum_tls));
        resp.insert("rpc_tls".into(), listener(snap.rpc_tls));
        // Streaming Consumption API listeners — same `null | {"bind": ...}`
        // shape as the wallet servers above. Reports the runtime-bound
        // address (so an OS-assigned `:0` port surfaces concretely), which
        // also lets the streaming E2E harness discover the port without a
        // fixed-port TOCTOU.
        resp.insert("events_grpc".into(), listener(snap.events_grpc));
        resp.insert("streamws".into(), listener(snap.streamws));
        #[cfg(feature = "block-filter-index")]
        {
            let state_label = ctx
                .filter_backfill
                .as_ref()
                .map(|h| h.cursor().state.label().to_string())
                .unwrap_or_else(|| "idle".to_string());
            resp.insert(
                "blockfilterindex".into(),
                serde_json::json!({
                    "enabled": ctx.blockfilterindex_enabled,
                    "complete": ctx.chain_state.store_ref().block_filter_index_complete(),
                    "backfill_state": state_label,
                }),
            );
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Object(resp))
    })?;

    module.register_method("getwarnings", |_params, ctx, _extensions| {
        // Active operational warnings: connect failures, storage issues,
        // shadow-verifier mismatches, etc. Each entry is an active
        // condition keyed by a stable `id`; same-id repeats increment
        // `count`. Warnings clear when the emitting site detects the
        // condition resolved.
        let warnings: Vec<serde_json::Value> = ctx
            .chain_state
            .warnings()
            .list()
            .into_iter()
            .map(|w| serde_json::to_value(w).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "warnings": warnings,
        }))
    })?;

    module.register_async_method(
        "getblockfileaudit",
        |_params, ctx, _extensions| async move {
            // Slack audit: compares every `block_index` reference against
            // the actual on-disk size of `blk*.dat` files. Read-only
            // diagnostic, safe to run on a live node, but expensive —
            // ~minute on mainnet for the 8-byte-header reads per indexed
            // block. Two operational hardening points relative to the
            // initial implementation (review findings from 2026-05-15):
            //   1. The work runs on the blocking pool via
            //      `tokio::task::spawn_blocking` so it doesn't tie up a
            //      Tokio worker thread that other RPCs share.
            //   2. A single-flight `AtomicBool` guard prevents concurrent
            //      invocations from multiplying disk pressure. A second
            //      caller sees a deterministic BUSY error rather than
            //      queueing behind another minute-scale scan.
            let guard = try_acquire_blockfile_audit(&ctx.blockfile_audit_running)
                .ok_or_else(|| {
                    ErrorObjectOwned::owned(
                        -32000,
                        "blockfile audit already running",
                        None::<()>,
                    )
                })?;
            let chain_state = ctx.chain_state.clone();
            let report = tokio::task::spawn_blocking(move || {
                let r = chain_state.audit_block_files();
                drop(guard); // explicit: release flag once the work returns
                r
            })
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32603,
                    format!("blockfile audit task join error: {}", e),
                    None::<()>,
                )
            })?
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    -32000,
                    format!("blockfile audit failed: {}", e),
                    None::<()>,
                )
            })?;
            let value = serde_json::to_value(&report).map_err(|e| {
                ErrorObjectOwned::owned(
                    -32603,
                    format!("blockfile audit serialization failed: {}", e),
                    None::<()>,
                )
            })?;
            Ok::<_, ErrorObjectOwned>(value)
        },
    )?;

    module.register_method("getreorghistory", |params, ctx, _extensions| {
        // `getreorghistory [since_secs]` — default 86400 (24 h).
        let mut seq = params.sequence();
        let since_secs: u64 = seq
            .optional_next()
            .unwrap_or(Some(86_400))
            .unwrap_or(86_400);
        let records = match ctx.chain_state.reorg_log() {
            Some(log) => log.history(since_secs),
            None => Vec::new(),
        };
        let arr: Vec<serde_json::Value> = records
            .into_iter()
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "since_secs": since_secs,
            "records": arr,
        }))
    })?;

    module.register_method("getmempoolhistory", |params, ctx, _extensions| {
        // `getmempoolhistory [since_secs]` — default 3600 (1 h).
        // Returns `available: false` with an empty list when the history
        // log failed to open at startup, so operators can tell a
        // temporarily-empty ring apart from a disabled feature.
        let mut seq = params.sequence();
        let since_secs: u64 = seq.optional_next().unwrap_or(Some(3_600)).unwrap_or(3_600);
        let (snapshots, available) = match &ctx.mempool_history {
            Some(h) => (h.history(since_secs), true),
            None => (Vec::new(), false),
        };
        let arr: Vec<serde_json::Value> = snapshots
            .into_iter()
            .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
            .collect();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "since_secs": since_secs,
            "available": available,
            "snapshots": arr,
        }))
    })?;

    module.register_subscription(
        "subscribemempool",
        "mempoolevent",
        "unsubscribemempool",
        |_params, pending, ctx, _ext| async move {
            use jsonrpsee::core::SubscriptionError;
            // Reject the subscription cleanly if the mempool wasn't
            // wired with an event sender (tests / startup race).
            let Some(mut rx) = ctx.mempool.subscribe_events() else {
                pending
                    .reject(ErrorObjectOwned::owned(
                        -32603,
                        "mempool event channel not wired",
                        None::<()>,
                    ))
                    .await;
                return Ok::<(), SubscriptionError>(());
            };
            let sink = pending.accept().await.map_err(SubscriptionError::from)?;
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let raw = jsonrpsee::core::to_json_raw_value(&event)
                            .map_err(SubscriptionError::from)?;
                        if sink.send(raw).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Subscriber fell behind; skip ahead — the
                        // docs advertise best-effort semantics.
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Ok(())
        },
    )?;

    module.register_method("getsysteminfo", |_params, ctx, _extensions| {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let rss_bytes = status
            .lines()
            .find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0)
            * 1024;
        let threads = status
            .lines()
            .find(|l| l.starts_with("Threads:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u32>().ok())
            })
            .unwrap_or(0);
        let uptime = ctx.start_time.elapsed().as_secs();
        let cache_dirty = ctx.chain_state.cache_dirty_count();
        let cache_clean = ctx
            .chain_state
            .cache_size()
            .saturating_sub(cache_dirty as usize);
        let pid = std::process::id();
        let dbcache_bytes = ctx.chain_state.store_ref().block_cache_capacity_bytes();
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "pid": pid,
            "rss_bytes": rss_bytes,
            "threads": threads,
            "uptime": uptime,
            "cache_dirty": cache_dirty,
            "cache_clean": cache_clean,
            "last_shutdown": if ctx.last_shutdown_clean { "clean" } else { "dirty" },
            "dbcache_rocksdb_bytes": dbcache_bytes,
        }))
    })?;

    module.register_method("getmemoryinfo", |_params, _ctx, _extensions| {
        // Read process memory from /proc/self/status on Linux
        let rss = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
            })
            .unwrap_or(0)
            * 1024; // kB to bytes
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "locked": {
                "used": rss,
                "free": 0,
                "total": rss,
                "locked": 0,
                "chunks_used": 0,
                "chunks_free": 0,
            }
        }))
    })?;

    module.register_method("getrpcinfo", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "active_commands": [],
            "logpath": "",
        }))
    })?;

    module.register_method("logging", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "net": true,
            "mempool": true,
            "validation": true,
            "rpc": true,
        }))
    })?;

    module.register_method("validateaddress", |params, _ctx, _extensions| {
        let address: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        Ok::<_, ErrorObjectOwned>(util::validate_address(&address))
    })?;

    // --- Long-polling RPCs ---

    module.register_async_method(
        "waitforblockheight",
        |params, ctx, _extensions| async move {
            let mut seq = params.sequence();
            let target_height: u32 = seq
                .next()
                .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
            let timeout_ms: u64 = seq.optional_next().unwrap_or(Some(0)).unwrap_or(0);
            let timeout = if timeout_ms > 0 {
                std::time::Duration::from_millis(timeout_ms)
            } else {
                std::time::Duration::from_secs(300) // default 5 min
            };
            let deadline = std::time::Instant::now() + timeout;

            loop {
                let height = ctx.chain_state.tip_height();
                if height >= target_height {
                    let hash = ctx.chain_state.tip_hash();
                    return Ok::<_, ErrorObjectOwned>(serde_json::json!({
                        "hash": hash.to_string(),
                        "height": height,
                    }));
                }
                if std::time::Instant::now() >= deadline {
                    let hash = ctx.chain_state.tip_hash();
                    return Ok(serde_json::json!({
                        "hash": hash.to_string(),
                        "height": height,
                    }));
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        },
    )?;

    module.register_async_method("waitfornewblock", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let timeout_ms: u64 = seq.optional_next().unwrap_or(Some(0)).unwrap_or(0);
        let timeout = if timeout_ms > 0 {
            std::time::Duration::from_millis(timeout_ms)
        } else {
            std::time::Duration::from_secs(300)
        };
        let deadline = std::time::Instant::now() + timeout;
        let initial_hash = ctx.chain_state.tip_hash();

        loop {
            let current_hash = ctx.chain_state.tip_hash();
            if current_hash != initial_hash {
                let height = ctx.chain_state.tip_height();
                return Ok::<_, ErrorObjectOwned>(serde_json::json!({
                    "hash": current_hash.to_string(),
                    "height": height,
                }));
            }
            if std::time::Instant::now() >= deadline {
                let height = ctx.chain_state.tip_height();
                return Ok(serde_json::json!({
                    "hash": current_hash.to_string(),
                    "height": height,
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    })?;

    module.register_async_method("waitforblock", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let blockhash: String = seq
            .next()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        let target_hash: bitcoin::BlockHash = blockhash
            .parse()
            .map_err(|_| ErrorObjectOwned::owned(-1, "Invalid block hash", None::<()>))?;
        let timeout_ms: u64 = seq.optional_next().unwrap_or(Some(0)).unwrap_or(0);
        let timeout = if timeout_ms > 0 {
            std::time::Duration::from_millis(timeout_ms)
        } else {
            std::time::Duration::from_secs(300)
        };
        let deadline = std::time::Instant::now() + timeout;

        loop {
            if let Some(entry) = ctx.chain_state.get_block_index(&target_hash) {
                return Ok::<_, ErrorObjectOwned>(serde_json::json!({
                    "hash": target_hash.to_string(),
                    "height": entry.height,
                }));
            }
            if std::time::Instant::now() >= deadline {
                let height = ctx.chain_state.tip_height();
                return Ok(serde_json::json!({
                    "hash": ctx.chain_state.tip_hash().to_string(),
                    "height": height,
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    })?;

    module.register_async_method("stop", |_params, ctx, _extensions| async move {
        tracing::info!("Received stop RPC, shutting down");
        let _ = ctx.shutdown_tx.send(true);
        Ok::<_, ErrorObjectOwned>(serde_json::Value::String("satd stopping".to_string()))
    })?;

    // Plain-HTTP server. AuthLayer wraps the RPC stack at the tower
    // layer, so TLS (when enabled) inherits the same auth transparently
    // — the auth middleware runs after HTTP parsing, not at the socket.
    //
    // `server_cfg` is built once and shared with the TLS path below so
    // both surfaces enforce the same jsonrpsee core limits (connection
    // cap, request/response size, batch config, etc.). We set
    // `max_connections` explicitly to [`RPC_MAX_CONNECTIONS`] so the
    // plain path's accept-level semaphore (which bounds raw sockets,
    // including denied/idle ones, before the per-request ConnectionGuard
    // is reached) is provably the same number rather than coupled to
    // jsonrpsee's library default.
    let server_cfg = ServerConfig::builder()
        .max_connections(RPC_MAX_CONNECTIONS)
        .build();
    // Methods is Arc-backed and cheap to clone — one copy is consumed
    // by each per-bind `Server::start()` call below, plus one to feed
    // the TLS path's per-connection service builder if TLS is enabled.
    let methods: Methods = module.into();
    if bind_addrs.is_empty() {
        return Err("rpc::server::start: bind_addrs is empty".into());
    }
    // `-rpcallowip` is enforced at the TCP accept boundary, so the
    // plain-HTTP path uses a manual accept loop (one per bind) rather
    // than jsonrpsee's `Server::start()`: the high-level flow never
    // exposes the peer `SocketAddr` to the HTTP middleware. The
    // allowlist is shared (read-only) across every listener task.
    let allowip = Arc::new(allowip);
    // One shared admission budget (`-rpcthreads` / `-rpcworkqueue`) across
    // every plain-HTTP and TLS surface: a single node-wide RPC work queue.
    let admission = AdmissionState::new(rpc_threads, rpc_workqueue);
    let mut plain_handles: Vec<ServerHandle> = Vec::with_capacity(bind_addrs.len());
    for bind_addr in &bind_addrs {
        let handle = spawn_plain_surface(
            *bind_addr,
            server_cfg.clone(),
            auth.clone(),
            allowip.clone(),
            methods.clone(),
            Some(shutdown_tx_outer.subscribe()),
            RPC_MAX_CONNECTIONS as usize,
            admission.clone(),
            bearer.clone(),
            None,
        )
        .await?;
        plain_handles.push(handle);
    }

    let tls_handle = if let Some(tls_cfg) = tls {
        let mut shutdown_rx_for_tls = shutdown_tx_outer.subscribe();
        // Caller-supplied TLS-only auth lets the satd binary opt the
        // TLS surface into auth-disabled mode behind mTLS without
        // affecting the plain-HTTP path. Defaults to the same auth
        // as plain when not specified.
        let surface_auth = tls_auth.unwrap_or_else(|| auth.clone());
        Some(
            spawn_tls_surface(
                tls_cfg,
                server_cfg.clone(),
                surface_auth,
                methods.clone(),
                listener_status_outer,
                &mut shutdown_rx_for_tls,
                admission.clone(),
                bearer.clone(),
                None,
            )
            .await?,
        )
    } else {
        None
    };

    // Opt-in read-only listener(s). Same `Methods`, on the bounded API
    // runtime, behind the read-only method filter, with their own admission
    // budget and source-address allowlist.
    let readonly_handles = if let Some(ro) = readonly {
        spawn_readonly_listeners(ro, &server_cfg, &auth, &methods, &shutdown_tx_outer).await?
    } else {
        Vec::new()
    };

    Ok(RpcServerHandle {
        plain: plain_handles,
        tls: tls_handle,
        readonly: readonly_handles,
    })
}

/// Bind the opt-in read-only listener(s) on the API runtime.
///
/// Each bind runs the same `Methods` as the main listener but behind the
/// [`ReadOnlyLayer`] method filter and with its own admission budget. The
/// accept loop and all per-connection tasks must run on the **API runtime**,
/// not the consensus core: we therefore drive each `spawn_plain_surface`
/// from inside an `api_handle.spawn(..)` task and recover the resulting
/// `ServerHandle` over a oneshot. A bind failure (e.g. port conflict) is
/// surfaced as a startup-fatal error, matching the main listener.
async fn spawn_readonly_listeners(
    ro: ReadOnlyListener,
    server_cfg: &ServerConfig,
    auth: &Arc<RpcAuth>,
    methods: &Methods,
    shutdown_tx: &watch::Sender<bool>,
) -> Result<Vec<ServerHandle>, Box<dyn std::error::Error + Send + Sync>> {
    // Fail-closed completeness audit: every registered method must be
    // classified in `rpc::access`, otherwise it would be silently rejected
    // on the read-only listener. The filter is safe either way (unclassified
    // → rejected), but an unclassified *read* would be an unintended feature
    // gap, so flag it. `debug_assert` turns this into a hard gate in the test
    // suite (which runs debug builds with the read-only listener enabled).
    let unclassified: Vec<&str> = methods
        .method_names()
        .filter(|m| access::classify(m).is_none())
        .collect();
    if !unclassified.is_empty() {
        tracing::warn!(
            ?unclassified,
            "read-only RPC listener enabled but these registered methods are unclassified in \
             rpc::access; they will be REJECTED on the read-only listener (fail-closed). Classify \
             them to expose them."
        );
        debug_assert!(
            unclassified.is_empty(),
            "unclassified RPC methods (classify in rpc::access): {unclassified:?}"
        );
    }

    let allowip = Arc::new(ro.allowip);
    // Independent admission budget so read-only load is bounded separately
    // from the main listener's `-rpcthreads`/`-rpcworkqueue`.
    let admission = AdmissionState::new(ro.rpc_threads, ro.rpc_workqueue);
    let mut handles: Vec<ServerHandle> = Vec::with_capacity(ro.bind_addrs.len());
    for bind_addr in ro.bind_addrs {
        let server_cfg = server_cfg.clone();
        let auth = auth.clone();
        let allowip = allowip.clone();
        let methods = methods.clone();
        let admission = admission.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        // Run the bind + accept loop on the API runtime: the inner
        // `tokio::spawn` calls in `spawn_plain_surface` inherit whichever
        // runtime drives this task.
        let (tx, rx) = tokio::sync::oneshot::channel();
        ro.api_handle.spawn(async move {
            let res = spawn_plain_surface(
                bind_addr,
                server_cfg,
                auth,
                allowip,
                methods,
                Some(shutdown_rx),
                RPC_MAX_CONNECTIONS as usize,
                admission,
                // The read-only listener does not honor bearer tokens (it is a
                // read-scoped surface already); operator auth only.
                None,
                Some(ReadOnlyLayer::new()),
            )
            .await;
            let _ = tx.send(res);
        });
        let handle = rx
            .await
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "read-only RPC listener task cancelled before bind".into()
            })??;
        tracing::info!(%bind_addr, "read-only RPC listener bound");
        handles.push(handle);
    }

    // Optional read-only TLS surface (`-rpcreadonlytls*` / `-rpcreadonlymtls*`).
    // Same Methods + read-only filter + admission budget as the plain
    // read-only surface, just over TLS (with optional mTLS), on the API
    // runtime. Reuses the main listener's HTTP auth.
    if let Some(tls_cfg) = ro.tls {
        let bind_addr = tls_cfg.bind_addr;
        let server_cfg = server_cfg.clone();
        let auth = auth.clone();
        let methods = methods.clone();
        let admission = admission.clone();
        // Throwaway status: the read-only TLS surface reports via the log
        // below rather than the main `getserverstatus` `rpc_tls` slot, which
        // it must not clobber. (getserverstatus visibility for the read-only
        // listener is a follow-up.)
        let status = Arc::new(ServerListenerStatus::default());
        let mut shutdown_rx = shutdown_tx.subscribe();
        let (tx, rx) = tokio::sync::oneshot::channel();
        ro.api_handle.spawn(async move {
            let res = spawn_tls_surface(
                tls_cfg,
                server_cfg,
                auth,
                methods,
                status,
                &mut shutdown_rx,
                admission,
                None,
                Some(ReadOnlyLayer::new()),
            )
            .await;
            let _ = tx.send(res);
        });
        let handle = rx
            .await
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "read-only RPC TLS listener task cancelled before bind".into()
            })??;
        tracing::info!(%bind_addr, "read-only RPC TLS listener bound");
        handles.push(handle);
    }

    Ok(handles)
}

/// Bind the TLS listener and spawn the per-connection accept loop.
///
/// The accept loop terminates when the returned [`ServerHandle`] is
/// stopped — either by the composite [`RpcServerHandle::stop`] call
/// from main shutdown, or by a bridge task wired here that forwards
/// the global `shutdown_tx` watch into the TLS stop handle so a
/// process-level shutdown also terminates this surface.
#[allow(clippy::too_many_arguments)]
async fn spawn_tls_surface(
    cfg: RpcTlsConfig,
    server_cfg: ServerConfig,
    auth: Arc<RpcAuth>,
    methods: Methods,
    listener_status: Arc<ServerListenerStatus>,
    shutdown_rx: &mut watch::Receiver<bool>,
    admission: Arc<AdmissionState>,
    // `Some` only on a bearer-enabled surface: the AuthLayer also accepts
    // `Authorization: Bearer` and a capability filter is installed at the RPC
    // layer. `None` is operator-only (no capability filter, zero cost).
    bearer: Option<Arc<satd_auth::TokenStore>>,
    // `Some` only for a read-only TLS listener. `None` keeps this a zero-cost
    // identity, matching `spawn_plain_surface`.
    rpc_filter: Option<ReadOnlyLayer>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    // mTLS policy: `Required` when the operator opted in via
    // `--rpcmtls=1`; otherwise `Disabled` (plain server-auth TLS).
    // The startup validation in satd/main.rs already enforced that a
    // CA path is set whenever mTLS is on, but be defensive here too.
    let policy = match (cfg.mtls_enabled, cfg.mtls_client_ca.as_ref()) {
        (true, Some(ca)) => tls_config::ClientAuthPolicy::Required {
            ca_path: ca.clone(),
        },
        (true, None) => return Err("rpc mtls enabled without CA path".into()),
        (false, _) => tls_config::ClientAuthPolicy::Disabled,
    };
    let acceptor = tls_config::build_acceptor(&cfg.cert_path, &cfg.key_path, &policy)?;
    let allow = tls_config::ClientAllowList::new(cfg.mtls_client_allow.iter().cloned());
    // Bind synchronously so a port conflict becomes a startup-fatal
    // error rather than a silently-dropped tokio task that never
    // accepts a connection.
    let tcp = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    let bound = tcp.local_addr()?;
    listener_status.set_rpc_tls(bound.to_string());

    // jsonrpsee's stop_channel lets us drive the manual accept loop
    // and per-connection `serve_with_graceful_shutdown` with the same
    // shutdown future. The returned ServerHandle is what composite
    // shutdown will use.
    let (stop_handle, server_handle) = stop_channel();

    // Per-connection tower service. AuthLayer holds Arc<RpcAuth> so
    // cloning it is cheap; we hand a fresh ServiceBuilder to this
    // surface so the plain-HTTP path's middleware chain stays isolated.
    // We build the `TowerService` here (once) and clone it per
    // connection — this mirrors jsonrpsee's own test helper (see
    // `jsonrpsee-server/src/tests/helpers.rs::ws_server_with_stats`).
    // Building once side-steps an HRTB inference quirk that bites if
    // you defer the `.build()` call into the per-connection `async`
    // block.
    // AdmissionLayer is outermost so an over-budget request is shed (429)
    // before any auth/compat work. AuthLayer is next so an unauthenticated
    // request is rejected before the compat layer buffers its body;
    // JsonRpcCompatLayer then normalizes Core-style (`jsonrpc` 1.0/1.1/
    // absent) requests to 2.0 so jsonrpsee accepts them (see `compat.rs`).
    // When the surface honors bearer tokens, install the capability filter at
    // the RPC layer so scoped tokens are gated per method; the operator
    // principal has all capabilities, so this is a no-op for legacy clients.
    let capability_filter = bearer.as_ref().map(|_| CapabilityLayer::new());
    let tls_middleware = tower::ServiceBuilder::new()
        .layer(AdmissionLayer::new(admission))
        .layer(AuthLayer::new(auth, bearer))
        .layer(JsonRpcCompatLayer::new());
    let rpc_svc = ServerBuilder::new()
        .set_config(server_cfg)
        .set_http_middleware(tls_middleware)
        .set_rpc_middleware(
            RpcServiceBuilder::new()
                .option_layer(rpc_filter)
                .option_layer(capability_filter),
        )
        .to_service_builder()
        .build(methods, stop_handle.clone());

    // Bridge: when the process-wide `shutdown_tx` fires (Ctrl-C,
    // SIGTERM, or the `stop` RPC), also stop this surface. main.rs
    // additionally calls `RpcServerHandle::stop()` after the flush
    // phase, which idempotently re-fires the same stop — both paths
    // are safe (AlreadyStopped is ignored).
    let bridge_handle = server_handle.clone();
    let mut bridge_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let _ = bridge_rx.changed().await;
        let _ = bridge_handle.stop();
    });

    // Per-handshake timeout from the cfg (review H2). Matches the
    // shape Electrum/Esplora use, just with a tighter default.
    let handshake_timeout = cfg.handshake_timeout;
    // Connection cap (review C1). The plain-HTTP RPC path runs
    // through `Server::start()` which enforces jsonrpsee's
    // `ServerConfig::max_connections`. The manual accept loop here
    // bypasses that, so we mirror the cap with a tokio Semaphore.
    // The permit is held by the per-connection task and released on
    // drop, so the cap covers handshake + steady-state serving.
    let conn_cap = std::sync::Arc::new(tokio::sync::Semaphore::new(
        cfg.max_connections.max(1),
    ));
    let max_connections = cfg.max_connections;
    let accept_stop = stop_handle.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                res = tcp.accept() => match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "RPC TLS accept error");
                        // Match esplora/electrum: brief sleep on
                        // transient accept errors so an EMFILE storm
                        // doesn't busy-loop.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                _ = accept_stop.clone().shutdown() => break,
            };

            // try_acquire_owned: if the semaphore is at capacity,
            // drop the connection here (pre-handshake, so we can't
            // even send a JSON-RPC error body — TLS hasn't started).
            // The client will see a TCP-level connection reset.
            let permit = match conn_cap.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        peer = %peer,
                        "RPC TLS at-capacity rejection ({} max)",
                        max_connections,
                    );
                    drop(stream);
                    continue;
                }
            };

            let acceptor = acceptor.clone();
            let rpc_svc = rpc_svc.clone();
            let conn_stop = accept_stop.clone();
            let allow = allow.clone();
            let mtls_enabled = cfg.mtls_enabled;
            tokio::spawn(async move {
                let _permit = permit;
                let tls_stream =
                    match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::debug!(
                                peer = %peer,
                                error = %e,
                                "RPC TLS handshake failed",
                            );
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(
                                peer = %peer,
                                timeout_secs = handshake_timeout.as_secs(),
                                "RPC TLS handshake timed out — closing connection",
                            );
                            return;
                        }
                    };
                // mTLS post-handshake hooks (audit log + allowlist
                // check) only run when mTLS is enabled (review C2).
                // Without an mTLS handshake there is no peer cert; a
                // non-empty allowlist would reject every connection.
                // Config-load validation (review C3) refuses that
                // combination, but this gate is also defense-in-depth.
                if mtls_enabled {
                    let (_, server_conn) = tls_stream.get_ref();
                    if let Some(subject) = tls_config::peer_subject_label(server_conn) {
                        tracing::info!(
                            peer = %peer,
                            subject = %subject,
                            "RPC mTLS client accepted",
                        );
                    }
                    if let Err(rej) = tls_config::check_peer_allowed(server_conn, &allow) {
                        tracing::warn!(
                            peer = %peer,
                            subject = %rej.subject_label,
                            "RPC mTLS client rejected by allowlist",
                        );
                        return;
                    }
                }

                // service_fn returns a `Box::pin`-ed future explicitly
                // so the spawn site sees a `Send + 'static` future and
                // sidesteps the HRTB-inference quirk that bites if you
                // return `async move { ... }` directly.
                let svc = tower::service_fn(
                    move |req: jsonrpsee::server::HttpRequest<hyper::body::Incoming>| {
                        let mut rpc_svc = rpc_svc.clone();
                        Box::pin(async move {
                            tower::Service::<
                                jsonrpsee::server::HttpRequest<hyper::body::Incoming>,
                            >::call(&mut rpc_svc, req)
                            .await
                        })
                            as std::pin::Pin<
                                Box<
                                    dyn std::future::Future<
                                            Output = Result<
                                                jsonrpsee::server::HttpResponse<
                                                    jsonrpsee::server::HttpBody,
                                                >,
                                                tower::BoxError,
                                            >,
                                        > + Send,
                                >,
                            >
                    },
                );

                // Spawn the serve future directly (no wrapping async
                // block) — this matches the doc example and helper
                // pattern that types correctly under HRTB inference.
                tokio::spawn(serve_with_graceful_shutdown(
                    tls_stream,
                    svc,
                    conn_stop.shutdown(),
                ));
            });
        }
    });

    Ok(server_handle)
}

/// Bind one plain-HTTP RPC listener and spawn its accept loop, enforcing
/// the `-rpcallowip` source-address allowlist at accept time.
///
/// We do NOT use jsonrpsee's high-level `Server::start()` here because it
/// never surfaces the peer `SocketAddr` to the HTTP middleware (it only
/// inserts `ConnectionId`/`ConnectionGuard` into the request extensions),
/// so a tower layer cannot make an allow/deny decision on the source IP.
/// Instead we mirror the TLS surface's manual loop: accept the TCP
/// connection (where the peer addr IS known), decide allow/deny once for
/// the whole connection, and either serve the real RPC stack or answer
/// every request on that connection with `403 Forbidden`.
///
/// Batch limits, WebSocket upgrades and graceful shutdown are preserved
/// because the per-connection service is the same `to_service_builder()
/// .build()` stack jsonrpsee uses internally. That stack's inner
/// `ConnectionGuard` only acquires a permit per *request*, though, so it
/// does NOT bound raw sockets that are denied (403), idle, or slow before
/// a request is dispatched. To make `rpcallowip`-on-a-public-bind actually
/// safe we add an accept-level `Semaphore` (sized `max_connections`,
/// mirroring the TLS surface): the permit is taken at accept — before the
/// allow/deny decision and before any serve task is spawned — and held
/// for the whole connection, so floods of denied/idle connections can't
/// exhaust fds/tasks. At capacity the socket is dropped (TCP reset).
///
/// `max_connections` MUST match `server_cfg`'s connection cap; callers
/// pass [`RPC_MAX_CONNECTIONS`], which `server_cfg` is also built from.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_plain_surface(
    bind_addr: SocketAddr,
    server_cfg: ServerConfig,
    auth: Arc<RpcAuth>,
    allowip: Arc<Vec<crate::rpc::allowip::IpAllowEntry>>,
    methods: Methods,
    shutdown_rx: Option<watch::Receiver<bool>>,
    max_connections: usize,
    admission: Arc<AdmissionState>,
    // `Some` only on a bearer-enabled surface: the AuthLayer also accepts
    // `Authorization: Bearer` and a capability filter is installed at the RPC
    // layer. `None` is operator-only (no capability filter, zero cost).
    bearer: Option<Arc<satd_auth::TokenStore>>,
    // `Some` only for read-only listeners: an RPC-layer method filter that
    // rejects non-read methods before dispatch. `None` (the default
    // read/write listener) is a zero-cost identity in the middleware chain.
    rpc_filter: Option<ReadOnlyLayer>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    // Bind synchronously so a port conflict is a startup-fatal error
    // rather than a silently-dropped task that never accepts.
    let tcp = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to bind RPC server on {bind_addr}: {e}").into()
        })?;

    let (stop_handle, server_handle) = stop_channel();

    let capability_filter = bearer.as_ref().map(|_| CapabilityLayer::new());
    let plain_middleware = tower::ServiceBuilder::new()
        .layer(AdmissionLayer::new(admission))
        .layer(AuthLayer::new(auth, bearer))
        .layer(JsonRpcCompatLayer::new());
    let rpc_svc = ServerBuilder::new()
        .set_config(server_cfg)
        .set_http_middleware(plain_middleware)
        // `option_layer(None)` is `Identity` — the read/write listener pays
        // nothing; the read-only listener gets the method filter, and a
        // bearer-enabled listener gets the capability filter, at the RPC layer
        // (after jsonrpsee has parsed the method + split batches).
        .set_rpc_middleware(
            RpcServiceBuilder::new()
                .option_layer(rpc_filter)
                .option_layer(capability_filter),
        )
        .to_service_builder()
        .build(methods, stop_handle.clone());

    // Optionally bridge the process-wide shutdown watch into this
    // surface's stop handle, mirroring the TLS path: the listener quits
    // accepting as soon as shutdown fires rather than waiting for the
    // owner's explicit `stop()`. Callers whose handle is stopped
    // directly (e.g. the startup RPC, torn down on the IBD→full
    // transition) pass `None`.
    if let Some(mut bridge_rx) = shutdown_rx {
        let bridge_handle = server_handle.clone();
        tokio::spawn(async move {
            let _ = bridge_rx.changed().await;
            let _ = bridge_handle.stop();
        });
    }

    // Accept-level connection cap (covers denied/idle/slow sockets that
    // never reach the per-request ConnectionGuard). Permit is acquired at
    // accept and held for the connection's lifetime.
    let conn_cap = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections.max(1)));

    let accept_stop = stop_handle.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                res = tcp.accept() => match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "RPC accept error");
                        // Brief backoff so an EMFILE storm can't busy-loop.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                _ = accept_stop.clone().shutdown() => break,
            };

            // Take a connection permit BEFORE the allow/deny check, so a
            // flood of non-allowlisted (or idle) sockets is bounded too.
            // At capacity we drop the socket (the client sees a TCP
            // reset) rather than queueing unbounded work.
            let permit = match conn_cap.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        peer = %peer,
                        "RPC at-capacity rejection ({} max connections)",
                        max_connections,
                    );
                    drop(stream);
                    continue;
                }
            };

            // One allow/deny decision per connection — the source IP is
            // fixed for the connection's lifetime. Loopback is always
            // allowed (keeps sat-cli working); otherwise the IP must fall
            // inside a configured CIDR.
            let allowed = crate::rpc::allowip::is_allowed(peer.ip(), &allowip);
            if !allowed {
                tracing::warn!(
                    peer = %peer,
                    "RPC connection rejected: source IP not permitted by -rpcallowip",
                );
            }

            let rpc_svc = rpc_svc.clone();
            let conn_stop = accept_stop.clone();
            // `service_fn` returns an explicitly boxed future so the
            // spawn site sees a `Send + 'static` future (sidesteps the
            // HRTB-inference quirk the TLS path documents).
            let svc = tower::service_fn(
                move |req: jsonrpsee::server::HttpRequest<hyper::body::Incoming>| {
                    let mut rpc_svc = rpc_svc.clone();
                    Box::pin(async move {
                        if !allowed {
                            let mut resp = jsonrpsee::server::HttpResponse::new(
                                jsonrpsee::server::HttpBody::from(
                                    "403 Forbidden: source IP not permitted by -rpcallowip\n",
                                ),
                            );
                            *resp.status_mut() = hyper::StatusCode::FORBIDDEN;
                            return Ok(resp);
                        }
                        tower::Service::<
                            jsonrpsee::server::HttpRequest<hyper::body::Incoming>,
                        >::call(&mut rpc_svc, req)
                        .await
                    })
                        as std::pin::Pin<
                            Box<
                                dyn std::future::Future<
                                        Output = Result<
                                            jsonrpsee::server::HttpResponse<
                                                jsonrpsee::server::HttpBody,
                                            >,
                                            tower::BoxError,
                                        >,
                                    > + Send,
                            >,
                        >
                },
            );

            // Spawn the serve future DIRECTLY (no wrapping async block) —
            // wrapping it bites an HRTB-inference quirk on the service's
            // request lifetime (the TLS path documents the same). To hold
            // the connection permit for the connection's lifetime without
            // re-triggering that quirk, a separate task owns the permit
            // and awaits the serve task's JoinHandle (whose type doesn't
            // name the service's HRTB lifetime); the permit drops when the
            // connection ends.
            let serve = tokio::spawn(serve_with_graceful_shutdown(
                stream,
                svc,
                conn_stop.shutdown(),
            ));
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve.await;
            });
        }
    });

    Ok(server_handle)
}
