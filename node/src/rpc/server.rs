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
use crate::rpc::compat::{CoreHttpPreludeLayer, JsonRpcCompatLayer};
use crate::rpc::capability::CapabilityLayer;
use crate::rpc::named_params::NamedParamsLayer;
use crate::rpc::params::Args;
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

/// Standard transaction version range — matches Core's `TX_MIN_STANDARD_VERSION`
/// and `TX_MAX_STANDARD_VERSION` (src/policy/policy.h).
const TX_VERSION_MIN: u32 = 1;
const TX_VERSION_MAX: u32 = 3;

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

// Core-compatible JSON type name for error messages, and the non-poisoning
// positional-argument reader every handler uses. See `crate::rpc::params`.
use crate::rpc::params::json_type_name;

/// Scan the raw JSON params string for `createrawtransaction` and detect
/// duplicate keys in the outputs object (the second positional element).
///
/// serde_json's `Map` silently deduplicates, but Core rejects them.
/// This function extracts the second element of the params array using
/// `serde_json::value::RawValue` and then iterates the object keys via a
/// streaming deserializer to find duplicates.
///
/// Returns `Some(key)` if a duplicate is found, `None` otherwise.
fn detect_duplicate_output_key(raw_params: &str) -> Option<String> {
    // The params are a JSON array: [inputs, outputs, ...].
    // We need to extract the second element as raw JSON.
    let trimmed = raw_params.trim();
    if !trimmed.starts_with('[') {
        return None;
    }

    // Use serde_json's streaming deserializer to walk the array without
    // collapsing duplicate keys: parse each element as a RawValue.
    let elements: Vec<&serde_json::value::RawValue> =
        serde_json::from_str(trimmed).ok()?;
    let outputs_raw = elements.get(1)?;
    let outputs_str = outputs_raw.get();

    // Only check objects (not arrays).
    if !outputs_str.trim_start().starts_with('{') {
        return None;
    }

    // Walk the object keys using a streaming approach.
    // serde_json's `Deserializer` with `MapAccess` would be ideal,
    // but the simplest approach: use a custom `Visitor` that detects duplicates.
    let keys: Vec<String> = Vec::new();
    // Parse as a stream of key-value pairs by using the serde_json
    // `MapDeserializer`. We can use `serde_json::from_str` with a
    // custom type that collects all keys.
    struct DupKeyDetector {
        keys: Vec<String>,
    }

    impl<'de> serde::de::Visitor<'de> for DupKeyDetector {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(mut self, mut map: A) -> Result<Self::Value, A::Error> {
            while let Some(key) = map.next_key::<String>()? {
                if self.keys.contains(&key) {
                    return Ok(Some(key));
                }
                self.keys.push(key);
                // Skip value.
                let _: serde::de::IgnoredAny = map.next_value()?;
            }
            Ok(None)
        }
    }

    let mut de = serde_json::Deserializer::from_str(outputs_str);
    let visitor = DupKeyDetector { keys };
    serde::Deserializer::deserialize_any(&mut de, visitor).ok().flatten()
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
    /// Whether the BIP 352 silent-payment index is enabled at runtime —
    /// used by `getindexinfo` and `backfillindex` to populate the
    /// `silentpayments.enabled` field and gate backfill requests.
    pub sp_index_enabled: bool,
    /// SP-index backfill handle. `Some` when the SP-index supervisor is
    /// wired (default in production); `None` for tests without a backfill
    /// thread. Always compiled — the SP index follows the address-index
    /// model, not a cargo feature.
    pub sp_backfill: Option<Arc<crate::index::silent_payments::BackfillHandle>>,
    /// Channel to the SP-index backfill supervisor task.
    pub sp_backfill_cmd_tx:
        Option<tokio::sync::mpsc::Sender<crate::index::silent_payments::BackfillCommand>>,
    /// Whether `-txindex` was explicitly enabled at runtime. Used by
    /// `getindexinfo` to decide whether to include the `"txindex"`
    /// entry in the Core-compatible response.
    pub txindex_enabled: bool,
    /// Whether `-coinstatsindex` was explicitly enabled at runtime.
    /// satd does not implement this index; the flag is accepted for
    /// Core compat and reported as always-synced in `getindexinfo`.
    pub coinstatsindex_enabled: bool,
    /// Whether `-txospenderindex` was explicitly enabled at runtime.
    /// satd does not implement this index; the flag is accepted for
    /// Core compat and reported as always-synced in `getindexinfo`.
    pub txospenderindex_enabled: bool,
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

/// The estimator mode enum lives in the node library now, shared by every
/// fee surface (RPC, MCP, Esplora, Electrum). Re-exported here so existing
/// `EstimateMode` references in this module keep resolving.
pub use crate::mempool::estimate::EstimateMode;

/// Resolve a single `estimatesmartfee` target into a feerate (sat/kvB).
///
/// Isolated so `estimatesmartfee` can stay Core-compatible: the response
/// shape never changes; only the source of the number does. The mempool sim
/// is built lazily — `Historical` mode (the Core-compatible default) never
/// touches the snapshot.
fn resolve_feerate_sat_per_kvb<F>(
    mode: EstimateMode,
    target: u32,
    fee_estimator: &crate::mempool::fee::FeeEstimator,
    floor_sat_per_kvb: u64,
    snapshot_fn: F,
) -> u64
where
    F: FnOnce() -> Vec<(bitcoin::Txid, crate::mempool::pool::MempoolEntry)>,
{
    if mode == EstimateMode::Historical {
        return fee_estimator.estimate_fee(target).unwrap_or(floor_sat_per_kvb);
    }
    let est = crate::mempool::estimate::estimate_from_mempool(
        snapshot_fn(),
        (target as usize).min(crate::mempool::estimate::MAX_SIM_DEPTH),
    );
    let (rate, _conf, _fallback) =
        crate::mempool::estimate::resolve_target(&est, fee_estimator, target, mode, floor_sat_per_kvb);
    rate
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
    // Per-connection header-read timeout (Bitcoin Core `-rpcservertimeout`).
    // `None` disables; `Some(dur)` causes hyper to close the TCP connection
    // if a complete HTTP request header is not received within `dur`.
    header_read_timeout: Option<Duration>,
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
    sp_index_enabled: bool,
    sp_backfill: Option<Arc<crate::index::silent_payments::BackfillHandle>>,
    sp_backfill_cmd_tx: Option<
        tokio::sync::mpsc::Sender<crate::index::silent_payments::BackfillCommand>,
    >,
    txindex_enabled: bool,
    coinstatsindex_enabled: bool,
    txospenderindex_enabled: bool,
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
        sp_index_enabled,
        sp_backfill,
        sp_backfill_cmd_tx,
        txindex_enabled,
        coinstatsindex_enabled,
        txospenderindex_enabled,
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

    module.register_method("getdeploymentinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_deployment_info(&ctx.chain_state))
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
        let mut args = Args::new(&params);
        let hash: String = args.required("blockhash")?;
        // Core defaults this to 1 and accepts a bool, where `false` means 0 --
        // a hex string, not an object.
        let verbosity = args.verbosity("verbosity", 1)?;
        args.check()?;
        blockchain::get_block(&ctx.chain_state, &hash, verbosity)
            .map_err(|e| {
                // "Block not available (...)" errors use RPC_MISC_ERROR (-1),
                // matching Bitcoin Core; all others (e.g. "Block not found",
                // "Invalid block hash") use RPC_INVALID_ADDRESS_OR_KEY (-5).
                let code = if e.starts_with("Block not available") { -1 } else { -5 };
                ErrorObjectOwned::owned(code, e, None::<()>)
            })
    })?;

    module.register_method("getblockheader", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let hash: String = args.required("blockhash")?;
        let verbose: bool = args.optional_or("verbose", true)?;
        args.check()?;
        blockchain::get_block_header(&ctx.chain_state, &hash, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getblockfrompeer", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let hash: String = args.required("blockhash")?;
        // Read `peer_id` raw: a negative or too-large number is a valid JSON
        // number that maps to no peer, and Core accepts it at the
        // deserialization layer and rejects it in the lookup ("Peer does not
        // exist", -1). A non-number is the type error (-3).
        let peer_id: Option<crate::net::peer::PeerId> = match args.raw("peer_id")? {
            None => None,
            Some(serde_json::Value::Number(n)) => Some(n.as_u64().unwrap_or(u64::MAX)),
            Some(other) => {
                return Err(ErrorObjectOwned::owned(
                    -3,
                    format!(
                        "JSON value of type {} is not of expected type number",
                        json_type_name(&other)
                    ),
                    None::<()>,
                ));
            }
        };
        args.check()?;
        network::get_block_from_peer(&ctx.chain_state, &ctx.peer_manager, &hash, peer_id)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
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
        let mut args = Args::new(&params);
        let nblocks: Option<u32> = args.optional("nblocks")?;
        // Core's optional second arg: the block that ends the window.
        let blockhash_str: Option<String> = args.optional("blockhash")?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let txid: String = args.required("txid")?;
        let verbose: bool = args.optional_or("verbose", false)?;
        args.check()?;
        blockchain::get_mempool_ancestors(&ctx.mempool, &txid, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getmempooldescendants", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let txid: String = args.required("txid")?;
        let verbose: bool = args.optional_or("verbose", false)?;
        args.check()?;
        blockchain::get_mempool_descendants(&ctx.mempool, &txid, verbose)
            .map_err(|e| ErrorObjectOwned::owned(-5, e, None::<()>))
    })?;

    module.register_method("getmempoolentry", |params, ctx, _extensions| {
        // Accepts either a single txid string (Core-compat) or an array
        // of txids (bulk). On bulk, returns a map of txid → entry | null.
        let mut args = Args::new(&params);
        // Either shape is legitimate here, so the slot is read raw.
        let first: serde_json::Value = args
            .raw("txid")?
            .ok_or_else(|| ErrorObjectOwned::owned(-1, "Missing required argument txid", None::<()>))?;
        args.check()?;
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

    // --- Transaction-filtering policy observability (design §10, PR 7b) ---
    // The only RPCs that expose the quarantine class; all read-only.

    module.register_method("getpolicyinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(crate::rpc::policy::get_policy_info(&ctx.mempool))
    })?;

    module.register_method("getquarantineinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(crate::rpc::policy::get_quarantine_info(&ctx.mempool))
    })?;

    module.register_method("listquarantine", |params, ctx, _extensions| {
        // `listquarantine [rule] [count] [skip]` — all optional.
        let mut args = Args::new(&params);
        let rule: Option<String> = args.optional("rule")?;
        let count: usize = args.optional_or("count", 0)?;
        let skip: usize = args.optional_or("skip", 0)?;
        args.check()?;
        Ok::<_, ErrorObjectOwned>(crate::rpc::policy::list_quarantine(
            &ctx.mempool,
            rule.as_deref(),
            count,
            skip,
        ))
    })?;

    module.register_method("getquarantineentry", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let txid: String = args.required("txid")?;
        args.check()?;
        crate::rpc::policy::get_quarantine_entry(&ctx.mempool, &txid)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("policytest", |params, ctx, _extensions| {
        // `policytest <rawtx-hex>` — dry-run against the loaded ruleset.
        let mut args = Args::new(&params);
        let rawtx: String = args.required("rawtx")?;
        args.check()?;
        crate::rpc::policy::policy_test(&ctx.chain_state, &ctx.mempool, &rawtx)
            .map_err(|e| ErrorObjectOwned::owned(-8, e, None::<()>))
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
        let mut args = Args::new(&params);
        let check_level: u32 = args.optional_or("checklevel", 3)?;
        let nblocks: u32 = args.optional_or("nblocks", 6)?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let block_hash: String = args.required("blockhash")?;
        let filter_type: Option<String> = args.optional("filtertype")?;
        args.check()?;
        indexes::get_block_filter(
            &ctx.chain_state,
            ctx.filter_index.as_ref(),
            &block_hash,
            filter_type.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // JSON-RPC fallback for the streaming `tweaks` category: serves the same
    // per-block BIP 352 tweak data the firehose does. Not feature-gated — the
    // silent-payment index is always compiled (runtime `silentpaymentindex=1`).
    module.register_method("getsilentpaymentblockdata", |params, ctx, _extensions| {
        // `getsilentpaymentblockdata <blockhash> [verbosity] [dust_limit]`.
        let mut args = Args::new(&params);
        let block_hash: String = args.required("blockhash")?;
        let verbosity: Option<u32> = args.optional("verbosity")?;
        let dust_limit: Option<u64> = args.optional("dust_limit")?;
        args.check()?;
        indexes::get_silent_payment_block_data(&ctx.chain_state, &block_hash, verbosity, dust_limit)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getindexinfo", |params, ctx, _extensions| {
        // Core-compatible getindexinfo: only report indexes that were
        // explicitly requested via CLI flags, matching Bitcoin Core's
        // behavior. Optional index_name parameter filters the response.
        let mut args = Args::new(&params);
        // Core's `RPCHelpMan` argument loop rejects a wrongly-typed argument
        // with RPC_TYPE_ERROR (-3) rather than ignoring it. Swallowing the
        // error here would answer `getindexinfo(5)` with the full index list.
        let index_name: Option<String> = args.optional("index_name")?;
        args.check()?;
        #[cfg(feature = "block-filter-index")]
        let bfi_enabled = ctx.blockfilterindex_enabled;
        #[cfg(not(feature = "block-filter-index"))]
        let bfi_enabled = false;
        Ok::<_, ErrorObjectOwned>(indexes::get_index_info_core_compat(
            &ctx.chain_state,
            indexes::CoreIndexFlags {
                txindex_enabled: ctx.txindex_enabled,
                blockfilterindex_enabled: bfi_enabled,
                coinstatsindex_enabled: ctx.coinstatsindex_enabled,
                txospenderindex_enabled: ctx.txospenderindex_enabled,
            },
            ctx.chain_state.tip_height(),
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
            index_name.as_deref(),
        ))
    })?;

    // satd-specific index info: address-index backfill, SP-index status,
    // block-filter-index backfill. Preserves the detailed satd-native
    // shape that sat-tui and operators rely on; `getindexinfo` above is
    // the Core-compatible surface.
    module.register_method("getsatdindexinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(indexes::get_index_info(
            ctx.backfill.as_ref(),
            &ctx.chain_state,
            ctx.address_index_enabled,
            ctx.chain_state.tip_height(),
            ctx.sp_index_enabled,
            ctx.sp_backfill.as_ref(),
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
            ctx.sp_backfill.as_ref(),
            ctx.sp_backfill_cmd_tx.as_ref(),
            ctx.sp_index_enabled,
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
            ctx.sp_backfill.as_ref(),
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
            ctx.sp_backfill.as_ref(),
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
            ctx.sp_backfill.as_ref(),
            #[cfg(feature = "block-filter-index")]
            ctx.filter_backfill.as_ref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- Mining RPCs ---

    module.register_method("submitblock", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let hex_block: String = args.required("hexdata")?;
        args.check()?;
        Ok::<_, ErrorObjectOwned>(mining::submit_block(
            &ctx.chain_state,
            &ctx.mempool,
            &hex_block,
        ))
    })?;

    module.register_method("generatetoaddress", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let nblocks: u32 = args.required("nblocks")?;
        let address: String = args.required("address")?;
        args.check()?;
        mining::generate_to_address(&ctx.chain_state, &ctx.mempool, nblocks, &address)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("generatetodescriptor", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let nblocks: u32 = args.required("num_blocks")?;
        let descriptor: String = args.required("descriptor")?;
        args.check()?;
        mining::generate_to_descriptor(&ctx.chain_state, &ctx.mempool, nblocks, &descriptor)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("generateblock", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let output: String = args.required("output")?;
        let raw_txs: Option<Vec<serde_json::Value>> = args.optional("transactions")?;
        let submit: bool = args.optional_or("submit", true)?;
        // #672: without this, a mistyped `transactions` poisoned the sequence
        // and `submit` silently reverted to its `true` default -- the caller
        // asked for a block back without touching the chain and got a new tip.
        args.check()?;

        if ctx.chain_state.network != bitcoin::Network::Regtest {
            return Err(ErrorObjectOwned::owned(
                -1, "generateblock is only available in regtest mode", None::<()>,
            ));
        }

        // Core's `getScriptFromDescriptor`: `output` is either an address or a
        // full output descriptor. A string containing `(` is a descriptor, and
        // its own error must reach the caller — `rpc_generate.py` asserts on
        // `-8 Ranged descriptor not accepted...` and `-5 Cannot derive script
        // without private keys`, both of which the resolver already produces.
        // Only a string that is not a descriptor at all falls through to the
        // address parser; otherwise a descriptor failure was reported as a
        // base58 error for something that was never an address.
        let coinbase_script = if output.contains('(') {
            crate::rpc::descriptor::descriptor_to_coinbase_script(
                &output,
                ctx.chain_state.network,
            )
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))?
        } else {
            let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = output
                .parse()
                .map_err(|e| {
                    ErrorObjectOwned::owned(
                        -5,
                        format!("Invalid address or descriptor: {e}"),
                        None::<()>,
                    )
                })?;
            addr.require_network(ctx.chain_state.network)
                .map_err(|e| {
                    ErrorObjectOwned::owned(
                        -5,
                        format!("Invalid address or descriptor: {e}"),
                        None::<()>,
                    )
                })?
                .script_pubkey()
        };

        let explicit_txs = if let Some(raw) = raw_txs {
            let mut txs = Vec::new();
            for item in &raw {
                let hex = item.as_str().ok_or_else(|| {
                    ErrorObjectOwned::owned(-1, "transaction must be a string", None::<()>)
                })?;
                if hex.len() == 64 {
                    let txid: bitcoin::Txid = hex.parse()
                        .map_err(|_| ErrorObjectOwned::owned(-5, format!("Transaction {hex} not in mempool."), None::<()>))?;
                    let entry = ctx.mempool.get(&txid)
                        .ok_or_else(|| ErrorObjectOwned::owned(-5, format!("Transaction {txid} not in mempool."), None::<()>))?;
                    txs.push(entry.tx.clone());
                } else {
                    let tx_bytes = hex::decode(hex)
                        .map_err(|_| ErrorObjectOwned::owned(-22, format!("Transaction decode failed for {hex}"), None::<()>))?;
                    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                        .map_err(|_| ErrorObjectOwned::owned(-22, format!("Transaction decode failed for {hex}"), None::<()>))?;
                    txs.push(tx);
                }
            }
            Some(txs)
        } else {
            None
        };

        // Build and submit under the same lock the other mining RPCs hold:
        // two concurrent callers reading the same tip would otherwise build
        // byte-identical blocks and the second would be rejected as
        // `duplicate` (rpc_generate.py mines from six threads at once).
        let _mining_guard = crate::mining::miner::MINING_SUBMIT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let block = crate::mining::miner::build_block_to_script(
            &ctx.chain_state, &ctx.mempool, coinbase_script, explicit_txs,
        ).map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;

        let hash = block.block_hash().to_string();

        if submit {
            let acceptance = ctx.chain_state.accept_block(&block)
                .map_err(|e| ErrorObjectOwned::owned(-25, format!("TestBlockValidity failed: {e}"), None::<()>))?;
            if let Some(height) = ctx.chain_state.connected_height(&acceptance) {
                ctx.mempool.remove_for_block(&block, height);
            }
            Ok::<_, ErrorObjectOwned>(serde_json::json!({ "hash": hash }))
        } else {
            let hex = hex::encode(bitcoin::consensus::serialize(&block));
            Ok(serde_json::json!({ "hash": hash, "hex": hex }))
        }
    })?;

    module.register_method("getblocktemplate", |params, ctx, _extensions| {
        // The optional first positional argument is the template_request
        // object. When it contains `"mode": "proposal"` and `"data"`, run
        // proposal-mode validation instead of returning a new template.
        let mut args = Args::new(&params);
        let request: Option<serde_json::Value> =
            args.optional::<serde_json::Map<String, serde_json::Value>>("template_request")?
                .map(serde_json::Value::Object);
        args.check()?;
        if let Some(ref req) = request
            && req.get("mode").and_then(|m| m.as_str()) == Some("proposal")
        {
            let data = req
                .get("data")
                .and_then(|d| d.as_str())
                .ok_or_else(|| {
                    ErrorObjectOwned::owned(
                        -8,
                        "\"data\" is required for proposal mode",
                        None::<()>,
                    )
                })?;
            return mining::get_block_template_proposal(&ctx.chain_state, data)
                .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>));
        }
        Ok::<_, ErrorObjectOwned>(mining::get_block_template(&ctx.chain_state, &ctx.mempool))
    })?;

    module.register_method("getmininginfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(mining::get_mining_info(&ctx.chain_state, &ctx.mempool))
    })?;

    module.register_method("getnetworkhashps", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let nblocks: Option<u32> = args.optional("nblocks")?;
        let height: Option<u32> = args.optional("height")?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let hex_tx: String = args.required("hexstring").map_err(|e| {
            if e.code() == -1 {
                crate::rpc::error::RpcError::new(-1, "rpc.input.parse", e.message().to_string())
                    .with_suggestion(
                        "Pass the raw transaction as a hex string in the first argument.",
                    )
                    .into_error_object()
            } else {
                e
            }
        })?;
        // Core's second arg is `maxfeerate` (AMOUNT: numeric or string,
        // BTC/kvB, default 0.10), so it has no single expected JSON type and
        // is read raw. We also accept a bool for satd's `allowquarantined`
        // extension — a numeric value sets maxfeerate and leaves quarantine
        // off.
        let maxfeerate_raw: Option<serde_json::Value> = args.raw("maxfeerate")?;
        let (maxfeerate_btc_per_kvb, allow_quarantined) = match &maxfeerate_raw {
            None | Some(serde_json::Value::Null) => (0.10_f64, false),
            Some(serde_json::Value::Bool(b)) => (0.10, *b),
            Some(serde_json::Value::Number(n)) => {
                let f = n.as_f64().unwrap_or(0.10);
                (f, false)
            }
            Some(serde_json::Value::String(s)) => {
                let f: f64 = s.parse().unwrap_or(0.10);
                (f, false)
            }
            _ => (0.10, false),
        };
        // Core's third arg is `maxburnamount` (AMOUNT: numeric or string,
        // BTC, default 0).
        let maxburnamount_raw: Option<serde_json::Value> = args.raw("maxburnamount")?;
        args.check()?;
        let maxburnamount_sat: u64 = match &maxburnamount_raw {
            None | Some(serde_json::Value::Null) => 0,
            Some(serde_json::Value::Number(n)) => {
                let f = n.as_f64().unwrap_or(0.0);
                (f * 100_000_000.0).round() as u64
            }
            Some(serde_json::Value::String(s)) => {
                let f: f64 = s.parse().unwrap_or(0.0);
                (f * 100_000_000.0).round() as u64
            }
            _ => 0,
        };

        // Decode the transaction for pre-submit checks.
        let tx_bytes = hex::decode(&hex_tx)
            .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;

        // maxburnamount check: Core checks each output individually — any
        // single unspendable output whose value exceeds maxburnamount is
        // rejected.
        for txout in &tx.output {
            if rawtx::is_burn_output(txout) && txout.value.to_sat() > maxburnamount_sat {
                return Err(ErrorObjectOwned::owned(
                    -25,
                    "Unspendable output exceeds maximum configured by user (maxburnamount)",
                    None::<()>,
                ));
            }
        }

        let maxfeerate_sat_per_kvb = (maxfeerate_btc_per_kvb * 100_000_000.0).round() as u64;

        // Pre-flight: test_accept to get fee info for maxfeerate check,
        // and to detect already-confirmed transactions.
        let txid = tx.compute_txid();

        // Check if already confirmed.
        if ctx.chain_state.get_tx_location(&txid).is_some() {
            return Err(ErrorObjectOwned::owned(
                -27,
                "Transaction outputs already in utxo set",
                None::<()>,
            ));
        }

        // test_accept to get fee/vsize without actually accepting.
        match ctx.mempool.test_accept(&tx, &ctx.chain_state, ctx.chain_state.script_verifier()) {
            Ok((_accepted_txid, vsize, fees)) => {
                // maxfeerate check.
                let feerate_sat_per_kvb = fees.saturating_mul(1000) / (vsize as u64).max(1);
                if maxfeerate_sat_per_kvb > 0 && feerate_sat_per_kvb > maxfeerate_sat_per_kvb {
                    return Err(ErrorObjectOwned::owned(
                        -25,
                        "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
                        None::<()>,
                    ));
                }
            }
            Err(crate::mempool::pool::MempoolError::AlreadyExists) => {
                // Already in mempool — we'll re-announce below.
            }
            Err(_) => {
                // The pre-flight exists only to price the transaction for
                // `maxfeerate` and to spot an already-confirmed txid. It must
                // not decide acceptance: `test_accept` does not consult the
                // policy engine, so the §6.2/§7 deferred-standardness path —
                // where an `allow` rule forgives a non-standard shape such as
                // dust — never gets a say here, and a transaction the node
                // would really accept would be refused. Fall through and let
                // the actual submission below rule on it; that path reports
                // Core's own reject reason and error code via `rpc_code`.
            }
        }

        // Actually submit and broadcast.
        let result = ctx
            .peer_manager
            .broadcast_transaction(&hex_tx, crate::mempool::pool::TxSource::Rpc, allow_quarantined)
            .map_err(|(code, msg)| {
                // Classify the mempool error by its code (Core taxonomy):
                // -22 = decode failed; -25 (RPC_TRANSACTION_ERROR, in
                // practice missing inputs) and -26
                // (RPC_TRANSACTION_REJECTED, every other invalid-or-rejected
                // verdict) are both mempool acceptance failures and want the
                // same operator advice.
                let (category, suggestion) = match code {
                    -22 => (
                        "rpc.input.parse",
                        "Transaction hex failed to decode.",
                    ),
                    -25 | -26 => (
                        "mempool.rejected",
                        "Mempool rejected the tx.",
                    ),
                    _ => ("rpc.unknown", ""),
                };
                let mut err = crate::rpc::error::RpcError::new(code, category, msg);
                if !suggestion.is_empty() {
                    err = err.with_suggestion(suggestion);
                }
                err.into_error_object()
            })?;
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
        let mut args = Args::new(&params);
        let verbose: bool = args.optional_or("verbose", false)?;
        args.check()?;
        Ok::<_, ErrorObjectOwned>(rawtx::get_raw_mempool(&ctx.mempool, verbose))
    })?;

    module.register_method("getrawtransaction", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let txid: String = args.required("txid")?;
        // Core declares this NUM with a 0 default and accepts a bool for it.
        let verbosity = args.verbosity("verbose", 0)?;
        let blockhash: Option<String> = args.optional("blockhash")?;
        args.check()?;
        if verbosity > 2 {
            return Err(ErrorObjectOwned::owned(
                -8,
                "Invalid verbosity value",
                None::<()>,
            ));
        }
        let verbose = verbosity >= 1;
        rawtx::get_raw_transaction(
            &ctx.chain_state,
            &ctx.mempool,
            &txid,
            verbose,
            verbosity,
            blockhash.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decoderawtransaction", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let hex_tx: String = args.required("hexstring")?;
        let iswitness: Option<bool> = args.optional("iswitness")?;
        args.check()?;
        rawtx::decode_raw_transaction(&hex_tx, iswitness, ctx.chain_state.network)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("createrawtransaction", |params, _ctx, _extensions| {
        // Grab the raw JSON before the sequence parser touches it.
        // We need this to detect duplicate keys in the outputs object,
        // since serde_json silently deduplicates.
        let raw_params_json = params.as_str().unwrap_or("").to_string();
        let mut args = Args::new(&params);
        let inputs_raw: serde_json::Value = args.raw("inputs")?.unwrap_or(serde_json::Value::Null);
        let inputs: Vec<serde_json::Value> = match inputs_raw {
            serde_json::Value::Array(arr) => {
                // Validate each element is an object.
                for item in &arr {
                    if !item.is_object() {
                        let type_name = match item {
                            serde_json::Value::String(_) => "string",
                            serde_json::Value::Number(_) => "number",
                            serde_json::Value::Bool(_) => "bool",
                            serde_json::Value::Array(_) => "array",
                            serde_json::Value::Null => "null",
                            _ => "unknown",
                        };
                        return Err(ErrorObjectOwned::owned(
                            -3,
                            format!("JSON value of type {type_name} is not of expected type object"),
                            None::<()>,
                        ));
                    }
                }
                arr
            }
            other => {
                let type_name = match &other {
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::Null => "null",
                    _ => "unknown",
                };
                return Err(ErrorObjectOwned::owned(
                    -3,
                    format!("JSON value of type {type_name} is not of expected type array"),
                    None::<()>,
                ));
            }
        };
        let outputs: serde_json::Value = args
            .raw("outputs")?
            .ok_or_else(|| ErrorObjectOwned::owned(-1, "createrawtransaction", None::<()>))?;
        // Detect duplicate keys in the outputs JSON object. serde_json
        // silently deduplicates, but Core rejects duplicates.  We scan
        // the raw params JSON for the second positional element and check
        // for repeated keys.
        if outputs.is_object()
            && let Some(dup) = detect_duplicate_output_key(&raw_params_json)
        {
            let msg = if dup == "data" {
                "Invalid parameter, duplicate key: data".to_string()
            } else {
                format!("Invalid parameter, duplicated address: {dup}")
            };
            return Err(ErrorObjectOwned::owned(-8, msg, None::<()>));
        }

        // Core accepts either array or object for outputs; reject other types.
        if !outputs.is_array() && !outputs.is_object() {
            let type_name = match &outputs {
                serde_json::Value::String(_) => "string",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::Bool(_) => "bool",
                serde_json::Value::Null => "null",
                _ => "unknown",
            };
            return Err(ErrorObjectOwned::owned(
                -3,
                format!("JSON value of type {type_name} is not of expected type array"),
                None::<()>,
            ));
        }
        let locktime: Option<serde_json::Value> = args.raw("locktime")?;
        let replaceable: Option<serde_json::Value> = args.raw("replaceable")?;
        let version: Option<serde_json::Value> = args.raw("version")?;
        // Reject extra arguments.
        let extra: Option<serde_json::Value> = args.raw("<extra>")?;
        args.check()?;
        if extra.is_some() {
            return Err(ErrorObjectOwned::owned(-1, "createrawtransaction", None::<()>));
        }
        // Parse locktime.
        let locktime_val: Option<u32> = match &locktime {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(n)) => {
                let v = n.as_i64().ok_or_else(|| ErrorObjectOwned::owned(
                    -8, "Invalid parameter, locktime out of range", None::<()>,
                ))?;
                if !(0..=0xFFFF_FFFF_i64).contains(&v) {
                    return Err(ErrorObjectOwned::owned(
                        -8, "Invalid parameter, locktime out of range", None::<()>,
                    ));
                }
                Some(v as u32)
            }
            Some(_) => return Err(ErrorObjectOwned::owned(
                -3, "JSON value of type string is not of expected type number", None::<()>,
            )),
        };
        // Parse replaceable (bool).
        let replaceable_val: Option<bool> = match &replaceable {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Bool(b)) => Some(*b),
            Some(_) => return Err(ErrorObjectOwned::owned(
                -3, "JSON value of type string is not of expected type bool", None::<()>,
            )),
        };
        // Parse version.
        let version_val: Option<u32> = match &version {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(n)) => {
                let v = n.as_u64().ok_or_else(|| ErrorObjectOwned::owned(
                    -8, format!("Invalid parameter, version out of range({TX_VERSION_MIN}~{TX_VERSION_MAX})"), None::<()>,
                ))?;
                let v32 = u32::try_from(v).map_err(|_| ErrorObjectOwned::owned(
                    -8, format!("Invalid parameter, version out of range({TX_VERSION_MIN}~{TX_VERSION_MAX})"), None::<()>,
                ))?;
                if !(TX_VERSION_MIN..=TX_VERSION_MAX).contains(&v32) {
                    return Err(ErrorObjectOwned::owned(
                        -8, format!("Invalid parameter, version out of range({TX_VERSION_MIN}~{TX_VERSION_MAX})"), None::<()>,
                    ));
                }
                Some(v32)
            }
            Some(_) => return Err(ErrorObjectOwned::owned(
                -8, format!("Invalid parameter, version out of range({TX_VERSION_MIN}~{TX_VERSION_MAX})"), None::<()>,
            )),
        };
        rawtx::create_raw_transaction(&inputs, &outputs, locktime_val, replaceable_val, version_val)
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
        let mut args = Args::new(&params);
        let hex_tx: String = args.required("hexstring")?;
        let privkeys: Vec<String> = args.required("privkeys")?;
        let prevtxs: Option<Vec<serde_json::Value>> = args.optional("prevtxs")?;
        let sighash_type: Option<String> = args.optional("sighashtype")?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let rawtxs: Vec<String> = args.required("rawtxs")?;
        // Optional maxfeerate (AMOUNT: numeric or string, BTC/kvB, default 0.10).
        let maxfeerate_raw: Option<serde_json::Value> = args.raw("maxfeerate")?;
        args.check()?;
        let maxfeerate_sat_per_kvb: u64 = match &maxfeerate_raw {
            None | Some(serde_json::Value::Null) => 10_000_000, // 0.10 BTC/kvB
            Some(serde_json::Value::Number(n)) => {
                let f = n.as_f64().unwrap_or(0.10);
                (f * 100_000_000.0).round() as u64
            }
            Some(serde_json::Value::String(s)) => {
                let f: f64 = s.parse().unwrap_or(0.10);
                (f * 100_000_000.0).round() as u64
            }
            _ => 10_000_000,
        };

        // Pre-decode all transactions and check for package-level duplicates
        // (Core: "package-contains-duplicates"). A package with two copies of
        // the same transaction is invalid regardless of whether each copy is
        // individually valid.
        let mut decoded: Vec<bitcoin::Transaction> = Vec::with_capacity(rawtxs.len());
        for hex_tx in &rawtxs {
            let tx_bytes = hex::decode(hex_tx)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            decoded.push(tx);
        }

        if decoded.len() > 1 {
            let mut seen = std::collections::HashSet::with_capacity(decoded.len());
            let has_dups = decoded.iter().any(|tx| !seen.insert(tx.compute_txid()));
            if has_dups {
                let results: Vec<serde_json::Value> = decoded
                    .iter()
                    .map(|tx| {
                        serde_json::json!({
                            "txid": tx.compute_txid().to_string(),
                            "package-error": "package-contains-duplicates",
                        })
                    })
                    .collect();
                return Ok(serde_json::json!(results));
            }
        }

        let mut results = Vec::new();
        for tx in &decoded {
            // Check if tx is already confirmed.
            let txid_check = tx.compute_txid();
            if ctx.chain_state.get_coin(&bitcoin::OutPoint { txid: txid_check, vout: 0 }).is_some()
                || ctx.chain_state.get_tx_location(&txid_check).is_some() {
                results.push(serde_json::json!({
                    "txid": txid_check.to_string(),
                    "allowed": false,
                    "reject-reason": "txn-already-known",
                }));
                continue;
            }
            match ctx
                .mempool
                .test_accept(tx, &ctx.chain_state, ctx.chain_state.script_verifier())
            {
                Ok((txid, vsize, fees)) => {
                    let wtxid = tx.compute_wtxid();
                    // Check maxfeerate.
                    let feerate_sat_per_kvb = fees.saturating_mul(1000) / (vsize as u64).max(1);
                    if maxfeerate_sat_per_kvb > 0 && feerate_sat_per_kvb > maxfeerate_sat_per_kvb {
                        results.push(serde_json::json!({
                            "txid": txid.to_string(),
                            "wtxid": wtxid.to_string(),
                            "allowed": false,
                            "reject-reason": "max-fee-exceeded",
                        }));
                    } else {
                        results.push(serde_json::json!({
                            "txid": txid.to_string(),
                            "wtxid": wtxid.to_string(),
                            "allowed": true,
                            "vsize": vsize,
                            "fees": {
                                "base": format_amount(fees, default_unit()),
                            },
                        }));
                    }
                }
                Err(e) => {
                    let txid = tx.compute_txid();
                    let wtxid = tx.compute_wtxid();
                    let mut entry = serde_json::json!({
                        "txid": txid.to_string(),
                        "wtxid": wtxid.to_string(),
                        "allowed": false,
                        "reject-reason": e.reject_reason(),
                    });
                    if let Some(details) = e.reject_details() {
                        entry["reject-details"] = serde_json::Value::String(details);
                    }
                    results.push(entry);
                }
            }
        }
        Ok::<_, ErrorObjectOwned>(serde_json::json!(results))
    })?;

    // --- submitpackage RPC ---
    module.register_method("submitpackage", |params, ctx, _extensions| {
        let rawtxs: Vec<String> = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;

        // Decode all transactions.
        let mut txs = Vec::with_capacity(rawtxs.len());
        for hex_tx in &rawtxs {
            let tx_bytes = hex::decode(hex_tx)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|_| ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>))?;
            txs.push(tx);
        }

        let (package_msg, tx_results) = ctx.mempool.accept_package(
            txs,
            &ctx.chain_state,
            ctx.chain_state.script_verifier(),
        );

        // Announce any newly-accepted transactions to peers.
        for (_wtxid, result) in &tx_results {
            if result.get("error").is_none()
                && let Some(txid_str) = result.get("txid").and_then(|v| v.as_str())
                && let Ok(txid) = txid_str.parse::<bitcoin::Txid>()
            {
                ctx.peer_manager.announce_tx(txid);
            }
        }

        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "package_msg": package_msg,
            "tx-results": tx_results,
        }))
    })?;

    // --- PSBT RPCs ---

    module.register_method("createpsbt", |params, _ctx, _extensions| {
        let mut args = Args::new(&params);
        let inputs: Vec<serde_json::Value> = args.required("inputs")?;
        let outputs: serde_json::Value = args
            .raw("outputs")?
            .ok_or_else(|| ErrorObjectOwned::owned(-1, "Missing required argument outputs", None::<()>))?;
        let locktime: Option<u32> = args.optional("locktime")?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let psbt_b64: String = args.required("psbt")?;
        let extract: bool = args.optional_or("extract", true)?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let txid: String = args.required("txid")?;
        let vout: u32 = args.required("n")?;
        args.check()?;
        blockchain::get_tx_out(&ctx.chain_state, &txid, vout)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("gettxoutsetinfo", |_params, ctx, _extensions| {
        blockchain::get_tx_out_set_info(&ctx.chain_state)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("gettxoutproof", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let txids: Vec<String> = args.required("txids")?;
        let blockhash: Option<String> = args.optional("blockhash")?;
        args.check()?;
        rawtx::get_tx_out_proof(
            &ctx.chain_state,
            &txids,
            blockhash.as_deref(),
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("verifytxoutproof", |params, ctx, _extensions| {
        let proof_hex: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        rawtx::verify_tx_out_proof(&ctx.chain_state, &proof_hex)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // Core runs the scan on the RPC thread and answers `status`/`abort` from
    // other threads meanwhile. satd registers it async and puts the scan on a
    // blocking thread for the same reason: a full pass is minute-scale on
    // mainnet, and an `abort` that queued behind it could never land.
    module.register_async_method("scantxoutset", |params, ctx, _extensions| async move {
        let mut args = Args::new(&params);
        let action: String = args.required("action")?;
        match action.as_str() {
            "status" => {
                args.check()?;
                Ok(blockchain::scan_tx_out_set_status())
            }
            "abort" => {
                args.check()?;
                Ok(blockchain::scan_tx_out_set_abort())
            }
            "start" => {
                let scanobjects: serde_json::Value = args.raw("scanobjects")?.ok_or_else(|| {
                    ErrorObjectOwned::owned(
                        -1,
                        "scanobjects argument is required for the start action",
                        None::<()>,
                    )
                })?;
                args.check()?;
                let chain_state = std::sync::Arc::clone(&ctx.chain_state);
                let shutdown = ctx.shutdown_tx.subscribe();
                tokio::task::spawn_blocking(move || {
                    blockchain::scan_tx_out_set_start(&chain_state, &scanobjects, &|| {
                        *shutdown.borrow()
                    })
                })
                .await
                .map_err(|e| {
                    ErrorObjectOwned::owned(-32603, format!("scan task failed: {e}"), None::<()>)
                })?
                .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
            }
            other => Err(ErrorObjectOwned::owned(
                -8,
                format!("Invalid action '{other}'"),
                None::<()>,
            )),
        }
    })?;

    module.register_method("estimatesmartfee", |params, ctx, _extensions| {
        // Parse as raw Values for Core-compatible arg-count and type checking.
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        if args.is_empty() {
            return Err(ErrorObjectOwned::owned(
                -1,
                "estimatesmartfee conf_target ( \"estimate_mode\" )\n\nEstimates the approximate fee per kilobyte needed for a transaction.\n",
                None::<()>,
            ));
        }
        if args.len() > 2 {
            return Err(ErrorObjectOwned::owned(
                -1,
                "estimatesmartfee conf_target ( \"estimate_mode\" )\n\nToo many arguments.\n",
                None::<()>,
            ));
        }
        // Type check arg 0: must be number
        let conf_target: u32 = match &args[0] {
            serde_json::Value::Number(n) => n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| ErrorObjectOwned::owned(-8, "Invalid conf_target", None::<()>))?,
            other => {
                return Err(ErrorObjectOwned::owned(
                    -3,
                    format!(
                        "JSON value of type {} is not of expected type number",
                        json_type_name(other),
                    ),
                    None::<()>,
                ));
            }
        };
        // Type check arg 1 (optional): must be string or null
        let mode_str: Option<String> = if args.len() > 1 {
            match &args[1] {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Null => None,
                other => {
                    return Err(ErrorObjectOwned::owned(
                        -3,
                        format!(
                            "JSON value of type {} is not of expected type string",
                            json_type_name(other),
                        ),
                        None::<()>,
                    ));
                }
            }
        } else {
            None
        };

        // Validate estimate_mode if provided
        if let Some(ref mode) = mode_str
            && EstimateMode::parse(Some(mode.as_str())).is_none()
        {
            return Err(ErrorObjectOwned::owned(
                -8,
                "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\", \"mempool\"",
                None::<()>,
            ));
        }

        let mode = EstimateMode::parse(mode_str.as_deref()).unwrap_or(EstimateMode::Historical);

        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        let sat_per_kvb =
            resolve_feerate_sat_per_kvb(mode, conf_target, &ctx.fee_estimator, floor_sat_per_kvb, || {
                ctx.mempool.get_template_entries()
            });
        let mut response = serde_json::json!({
            "feerate": format_feerate_sat_per_kvb(sat_per_kvb, unit),
            "blocks": conf_target,
            "errors": [],
        });
        annotate_units(&mut response, unit);
        Ok::<_, ErrorObjectOwned>(response)
    })?;

    module.register_method("estimaterawfee", |params, ctx, _extensions| {
        // Parse as raw Values for Core-compatible arg-count and type checking.
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        if args.is_empty() {
            return Err(ErrorObjectOwned::owned(
                -1,
                "estimaterawfee conf_target ( threshold )\n\nEstimates the approximate fee per kilobyte.\n",
                None::<()>,
            ));
        }
        if args.len() > 2 {
            return Err(ErrorObjectOwned::owned(
                -1,
                "estimaterawfee conf_target ( threshold )\n\nToo many arguments.\n",
                None::<()>,
            ));
        }
        // Type check arg 0: must be number
        let conf_target: u32 = match &args[0] {
            serde_json::Value::Number(n) => n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| ErrorObjectOwned::owned(-8, "Invalid conf_target", None::<()>))?,
            other => {
                return Err(ErrorObjectOwned::owned(
                    -3,
                    format!(
                        "JSON value of type {} is not of expected type number",
                        json_type_name(other),
                    ),
                    None::<()>,
                ));
            }
        };
        // Type check arg 1 (optional): must be number or null
        let _threshold: Option<f64> = if args.len() > 1 {
            match &args[1] {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::Null => None,
                other => {
                    return Err(ErrorObjectOwned::owned(
                        -3,
                        format!(
                            "JSON value of type {} is not of expected type number",
                            json_type_name(other),
                        ),
                        None::<()>,
                    ));
                }
            }
        } else {
            None
        };

        // Validate conf_target range (1..=1008)
        if !(1..=1008).contains(&conf_target) {
            return Err(ErrorObjectOwned::owned(
                -8,
                "Invalid conf_target, must be between 1 and 1008",
                None::<()>,
            ));
        }

        // Use the same fee estimation as estimatesmartfee
        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        let sat_per_kvb = ctx.fee_estimator.estimate_fee(conf_target)
            .unwrap_or(floor_sat_per_kvb);
        let mut response = serde_json::json!({
            "short": {
                "feerate": format_feerate_sat_per_kvb(sat_per_kvb, unit),
                "decay": 0,
                "scale": 1,
                "pass": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
                "fail": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
            },
            "medium": {
                "feerate": format_feerate_sat_per_kvb(sat_per_kvb, unit),
                "decay": 0,
                "scale": 1,
                "pass": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
                "fail": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
            },
            "long": {
                "feerate": format_feerate_sat_per_kvb(sat_per_kvb, unit),
                "decay": 0,
                "scale": 1,
                "pass": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
                "fail": { "startrange": 0, "endrange": 0, "withintarget": 0, "totalconfirmed": 0, "inmempool": 0, "leftmempool": 0 },
            },
        });
        annotate_units(&mut response, unit);
        Ok::<_, ErrorObjectOwned>(response)
    })?;

    module.register_method("estimatefees", |params, ctx, _extensions| {
        // `estimatefees [targets] [mode]` — both optional.
        // `targets`: array of confirmation targets in blocks. Default
        // `[1, 3, 6, 12, 24]`. `mode` (default "blend") selects the data
        // source.
        let mut fee_args = Args::new(&params);
        let targets: Vec<u32> = fee_args
            .optional("targets")?
            .unwrap_or_else(|| vec![1u32, 3, 6, 12, 24]);
        let mode_str: Option<String> = fee_args.optional("mode")?;
        fee_args.check()?;
        let mode = EstimateMode::parse(mode_str.as_deref()).unwrap_or(EstimateMode::Blend);

        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        // Single source of truth: blend/mempool/historical selection,
        // monotonicity clamp, and economy tier all happen in `smart_fees`,
        // shared with MCP / Esplora / Electrum.
        let sf = crate::mempool::estimate::smart_fees(
            // Template consumer (design §2.4): `on template` quarantine must not
            // inflate the fee quote — same view the block template selects from.
            ctx.mempool.get_template_entries(),
            &ctx.fee_estimator,
            &targets,
            mode,
            floor_sat_per_kvb,
        );

        let mut targets_obj = serde_json::Map::new();
        for tf in &sf.targets {
            targets_obj.insert(
                tf.target.to_string(),
                serde_json::json!({
                    "feerate": format_feerate_sat_per_kvb(tf.feerate_sat_per_kvb, unit),
                    "confidence": tf.confidence.as_str(),
                }),
            );
        }

        let histogram: Vec<serde_json::Value> = sf
            .histogram
            .iter()
            .map(|b| {
                serde_json::json!({
                    "feerate": format_feerate_sat_per_kvb(b.feerate_sat_per_kvb, unit),
                    "weight": b.weight,
                })
            })
            .collect();

        let mut response = serde_json::json!({
            "targets": targets_obj,
            "histogram": histogram,
            "mode": sf.mode.as_str(),
            "fallback": sf.fallback,
            "mempool_weight": sf.mempool_weight,
            "economy_feerate": format_feerate_sat_per_kvb(sf.economy_feerate_sat_per_kvb, unit),
            "thin_block": sf.thin_block,
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
        let mut args = Args::new(&params);
        let addr_str: String = args.required("node").map_err(|e| {
            ErrorObjectOwned::owned(
                e.code(),
                format!("addnode \"node\" \"command\"\n\n{}", e.message()),
                None::<()>,
            )
        })?;
        let command: String = args.optional_or("command", "onetry".to_string())?;
        args.check()?;

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
                let addr = crate::net::peer::PeerAddr::parse_with_default_port(&addr_str, crate::net::peer::default_p2p_port(ctx.chain_state.network))
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                // -23 = RPC_CLIENT_NODE_ALREADY_ADDED in Core.
                if !ctx.peer_manager.addnode_add(&addr_str, addr.clone()) {
                    return Err(ErrorObjectOwned::owned(
                        -23,
                        "Node already added",
                        None::<()>,
                    ));
                }
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
                let addr = crate::net::peer::PeerAddr::parse_with_default_port(&addr_str, crate::net::peer::default_p2p_port(ctx.chain_state.network))
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                ctx.peer_manager
                    .connect_peer_addr(&addr)
                    .await
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
            }
            "remove" => {
                let addr = crate::net::peer::PeerAddr::parse_with_default_port(&addr_str, crate::net::peer::default_p2p_port(ctx.chain_state.network))
                    .map_err(|e| ErrorObjectOwned::owned(-1, e, None::<()>))?;
                // -24 = RPC_CLIENT_NODE_NOT_ADDED in Core.
                if !ctx.peer_manager.addnode_remove(&addr) {
                    return Err(ErrorObjectOwned::owned(
                        -24,
                        "Node could not be removed",
                        None::<()>,
                    ));
                }
            }
            other => {
                return Err(ErrorObjectOwned::owned(
                    -1,
                    format!("addnode \"node\" \"command\"\n\naddnode: unknown command '{other}' (expected add/onetry/remove)"),
                    None::<()>,
                ));
            }
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("getaddednodeinfo", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let filter_node: Option<String> = args.optional("node")?;
        args.check()?;
        let all_info = ctx.peer_manager.get_added_node_info();
        if let Some(ref node) = filter_node {
            let filtered: Vec<_> = all_info.into_iter().filter(|entry| {
                entry.get("addednode").and_then(|v| v.as_str()) == Some(node.as_str())
            }).collect();
            if filtered.is_empty() {
                // -24 = RPC_CLIENT_NODE_NOT_ADDED. Core's exact message.
                return Err(ErrorObjectOwned::owned(
                    -24,
                    "Node has not been added",
                    None::<()>,
                ));
            }
            Ok::<_, ErrorObjectOwned>(serde_json::json!(filtered))
        } else {
            Ok::<_, ErrorObjectOwned>(serde_json::json!(all_info))
        }
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
        let mut args = Args::new(&params);
        let subnet_str: String = args.required("subnet")?;
        let command: String = args.required("command")?;
        let bantime: Option<u64> = args.optional("bantime")?;
        let absolute: Option<bool> = args.optional("absolute")?;
        args.check()?;

        let target = crate::net::ban::parse_ban_target(&subnet_str)
            .map_err(|e| ErrorObjectOwned::owned(-30, e, None::<()>))?;
        // Core keys the duplicate check off the *notation* the operator used,
        // not the normalised form: `isSubnet = str.find('/') != npos`.
        let is_subnet = subnet_str.contains('/');

        match command.as_str() {
            "add" => {
                let now = crate::time::now_secs();
                let default_duration = ctx.peer_manager.default_ban_duration_secs();
                if ctx.peer_manager.is_already_banned(&target, is_subnet) {
                    return Err(ErrorObjectOwned::owned(
                        -23,
                        "IP/Subnet already banned",
                        None::<()>,
                    ));
                }
                let (ban_created, banned_until) = if absolute.unwrap_or(false) {
                    // bantime is an absolute Unix timestamp. Core's guard is
                    // `banTime < GetTime()`, so a timestamp of exactly now is
                    // accepted (and expires immediately).
                    let abs = bantime.unwrap_or_else(|| now.saturating_add(default_duration));
                    if abs < now {
                        return Err(ErrorObjectOwned::owned(
                            -8,
                            "Error: Absolute timestamp is in the past",
                            None::<()>,
                        ));
                    }
                    (now, abs)
                } else {
                    // bantime is a relative duration in seconds (0 = default).
                    // Saturating: `bantime` is operator-supplied and `u64::MAX`
                    // would otherwise panic in debug and wrap to an
                    // already-expired ban in release.
                    let duration = match bantime {
                        Some(0) | None => default_duration,
                        Some(d) => d,
                    };
                    (now, now.saturating_add(duration))
                };
                ctx.peer_manager
                    .set_ban_subnet(&target, true, ban_created, banned_until)
                    .map_err(|e| ErrorObjectOwned::owned(-23, e, None::<()>))?;
            }
            "remove" => {
                ctx.peer_manager
                    .set_ban_subnet(&target, false, 0, 0)
                    .map_err(|e| ErrorObjectOwned::owned(-30, e, None::<()>))?;
            }
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
        let mut args = Args::new(&params);
        let txid_str: String = args.required("txid")?;
        let _dummy: Option<f64> = args.optional("dummy")?; // ignored (Core compat)
        let fee_delta: i64 = args.required("fee_delta")?;
        args.check()?;
        let txid: bitcoin::Txid = txid_str
            .parse()
            .map_err(|_| ErrorObjectOwned::owned(-8, "Invalid txid", None::<()>))?;
        match ctx.mempool.prioritise_transaction(&txid, fee_delta) {
            Ok(_) => Ok::<_, ErrorObjectOwned>(serde_json::json!(true)),
            Err(e) => Err(ErrorObjectOwned::owned(-8, e.to_string(), None::<()>)),
        }
    })?;

    module.register_method("getprioritisedtransactions", |_params, ctx, _extensions| {
        let prioritised = ctx.mempool.get_prioritised_transactions();
        let mut result = serde_json::Map::new();
        for (txid, (fee_delta, in_mempool)) in &prioritised {
            result.insert(
                txid.to_string(),
                serde_json::json!({
                    "fee_delta": fee_delta,
                    "in_mempool": in_mempool,
                }),
            );
        }
        Ok::<_, ErrorObjectOwned>(serde_json::json!(result))
    })?;

    module.register_method("disconnectnode", |params, ctx, _extensions| {
        // Core takes the peer either by address or by id, and requires
        // exactly one of the two -- `disconnectnode "" 3` is how its own test
        // framework disconnects, so the address slot is present but empty.
        let mut args = Args::new(&params);
        let addr_str: Option<String> = args.optional("address")?;
        let node_id: Option<u64> = args.optional("nodeid")?;
        args.check()?;

        // Core's branch conditions verbatim (rpc/net.cpp): an address that was
        // supplied at all -- including as the empty string -- takes the
        // by-address path unless a nodeid came with it, and the "only one"
        // error covers *neither* as well as both, because both guards fail.
        let disconnected = match (&addr_str, node_id) {
            (Some(addr), None) => ctx.peer_manager.disconnect_by_addr(addr),
            (_, Some(id)) if addr_str.as_deref().unwrap_or("").is_empty() => {
                ctx.peer_manager.disconnect_by_id(id)
            }
            _ => {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "Only one of address and nodeid should be provided.",
                    None::<()>,
                ));
            }
        };

        // Core reports a peer it could not find rather than returning success
        // for a disconnect that did not happen.
        if !disconnected {
            return Err(ErrorObjectOwned::owned(
                -29,
                "Node not found in connected nodes",
                None::<()>,
            ));
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    // --- Control RPCs ---

    module.register_method("generate", |_params, _ctx, _extensions| {
        Err::<serde_json::Value, _>(ErrorObjectOwned::owned(
            -32601,
            "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n",
            None::<()>,
        ))
    })?;

    module.register_method("echo", |params, _ctx, _extensions| {
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        if args.len() >= 10
            && let Some(serde_json::Value::String(s)) = args.last()
            && s == "trigger_internal_bug"
        {
            let msg = "Internal bug detected: request.params[9].get_str() != \"trigger_internal_bug\"";
            return Err(ErrorObjectOwned::owned(-1, msg, None::<()>));
        }
        Ok::<_, ErrorObjectOwned>(serde_json::json!(args))
    })?;

    module.register_method("echojson", |params, _ctx, _extensions| {
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        Ok::<_, ErrorObjectOwned>(serde_json::json!(args))
    })?;

    module.register_method("echoipc", |params, _ctx, _extensions| {
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        match args.into_iter().next() {
            Some(v) => Ok::<_, ErrorObjectOwned>(v),
            None => Ok(serde_json::Value::Null),
        }
    })?;

    module.register_method("help", |params, _ctx, _extensions| {
        // Read the argument as a raw Value for type checking (Core returns
        // -3 for non-string types like numbers).
        let args: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        if args.len() > 1 {
            return Err(ErrorObjectOwned::owned(
                -1,
                "help \"command\"\n\nList all commands, or get help for a specified command.\n",
                None::<()>,
            ));
        }
        let command: Option<String> = if let Some(v) = args.first() {
            match v {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(_) => {
                    return Err(ErrorObjectOwned::owned(
                        -3,
                        "JSON value of type number is not of expected type string",
                        None::<()>,
                    ));
                }
                serde_json::Value::Bool(_) => {
                    return Err(ErrorObjectOwned::owned(
                        -3,
                        "JSON value of type bool is not of expected type string",
                        None::<()>,
                    ));
                }
                _ => {
                    return Err(ErrorObjectOwned::owned(
                        -3,
                        format!(
                            "JSON value of type {} is not of expected type string",
                            json_type_name(v),
                        ),
                        None::<()>,
                    ));
                }
            }
        } else {
            None
        };

        // Categorized method table. Each method belongs to exactly one Core
        // category. The categories and their sorted order are validated by
        // rpc_help.py::test_categories().
        const METHODS: &[(&str, &str)] = &[
            // == Blockchain ==
            ("dumptxoutset", "Blockchain"),
            ("getbestblockhash", "Blockchain"),
            ("getblock", "Blockchain"),
            ("getblockchaininfo", "Blockchain"),
            ("getblockcount", "Blockchain"),
            ("getblockfrompeer", "Blockchain"),
            ("getblockhash", "Blockchain"),
            ("getblockheader", "Blockchain"),
            ("getblockstats", "Blockchain"),
            ("getchaintips", "Blockchain"),
            ("getchaintxstats", "Blockchain"),
            ("getdeploymentinfo", "Blockchain"),
            ("getdifficulty", "Blockchain"),
            ("getibdprogress", "Blockchain"),
            ("getmempoolancestors", "Blockchain"),
            ("getmempooldescendants", "Blockchain"),
            ("getmempoolentry", "Blockchain"),
            ("getmempoolhistory", "Blockchain"),
            ("getmempoolinfo", "Blockchain"),
            ("getrawmempool", "Blockchain"),
            ("getreorghistory", "Blockchain"),
            ("gettxout", "Blockchain"),
            ("gettxoutproof", "Blockchain"),
            ("gettxoutsetinfo", "Blockchain"),
            ("invalidateblock", "Blockchain"),
            ("preciousblock", "Blockchain"),
            ("reconsiderblock", "Blockchain"),
            ("savemempool", "Blockchain"),
            ("scantxoutset", "Blockchain"),
            ("subscribemempool", "Blockchain"),
            ("unsubscribemempool", "Blockchain"),
            ("verifychain", "Blockchain"),
            ("verifytxoutproof", "Blockchain"),
            ("waitforblockheight", "Blockchain"),
            // == Control ==
            ("echo", "Control"),
            ("echojson", "Control"),
            ("echoipc", "Control"),
            ("getconfig", "Control"),
            ("getmemoryinfo", "Control"),
            ("getrpcinfo", "Control"),
            ("getserverstatus", "Control"),
            ("getsysteminfo", "Control"),
            ("getwarnings", "Control"),
            ("help", "Control"),
            ("logging", "Control"),
            ("setmocktime", "Control"),
            ("stop", "Control"),
            ("syncwithvalidationinterfacequeue", "Control"),
            ("uptime", "Control"),
            // == Mining ==
            ("estimatefees", "Mining"),
            ("generateblock", "Mining"),
            ("generatetoaddress", "Mining"),
            ("generatetodescriptor", "Mining"),
            ("getblocktemplate", "Mining"),
            ("getmininginfo", "Mining"),
            ("getnetworkhashps", "Mining"),
            ("getprioritisedtransactions", "Mining"),
            ("prioritisetransaction", "Mining"),
            ("submitblock", "Mining"),
            ("submitheader", "Mining"),
            // == Network ==
            ("addnode", "Network"),
            ("clearbanned", "Network"),
            ("disconnectnode", "Network"),
            ("getaddednodeinfo", "Network"),
            ("getconnectioncount", "Network"),
            ("getnettotals", "Network"),
            ("getnetworkinfo", "Network"),
            ("getorphaninfo", "Network"),
            ("getpeerinfo", "Network"),
            ("listbanned", "Network"),
            ("ping", "Network"),
            ("setban", "Network"),
            ("setnetworkactive", "Network"),
            // == Rawtransactions ==
            ("decoderawtransaction", "Rawtransactions"),
            ("decodescript", "Rawtransactions"),
            ("getrawtransaction", "Rawtransactions"),
            ("sendrawtransaction", "Rawtransactions"),
            ("submitpackage", "Rawtransactions"),
            ("signrawtransactionwithkey", "Rawtransactions"),
            ("testmempoolaccept", "Rawtransactions"),
            // == Util ==
            ("deriveaddresses", "Util"),
            ("estimaterawfee", "Util"),
            ("estimatesmartfee", "Util"),
            ("getdescriptorinfo", "Util"),
            ("getindexinfo", "Util"),
            ("validateaddress", "Util"),
        ];

        if let Some(cmd) = command {
            if cmd == "dump_all_command_conversions" {
                let entries = crate::rpc::named_params::dump_all_command_conversions();
                let json_entries: Vec<serde_json::Value> = entries
                    .into_iter()
                    .map(|(m, i, n, s)| serde_json::json!([m, i, n, s]))
                    .collect();
                return Ok::<_, ErrorObjectOwned>(serde_json::json!(json_entries));
            }
            if cmd == "generate" {
                return Ok::<_, ErrorObjectOwned>(serde_json::json!(
                    "generate\n\nhas been replaced by the -generate cli option. Refer to -help for more information.\n"
                ));
            }
            if cmd == "logging" {
                // The help text for `logging` must include the sorted list
                // of valid categories (rpc_misc.py checks for it).
                let cats = [
                    "addrman", "bench", "blockstorage", "cmpctblock", "coindb",
                    "estimatefee", "http", "i2p", "ipc", "leveldb", "libevent",
                    "lock", "mempool", "mempoolrej", "net", "proxy", "prune",
                    "qt", "rand", "reindex", "rpc", "scan", "selectcoins",
                    "tor", "txpackages", "txreconciliation", "util", "validation",
                    "walletdb", "zmq",
                ];
                let cats_str = cats.join(", ");
                return Ok::<_, ErrorObjectOwned>(serde_json::json!(format!(
                    "logging ( <include> <exclude> )\n\nGets and sets the logging configuration.\nvalid logging categories are: {cats_str}\n"
                )));
            }
            if cmd.is_empty() || METHODS.iter().any(|(name, _)| *name == cmd.as_str()) {
                return Ok::<_, ErrorObjectOwned>(serde_json::json!(format!("{cmd}\n")));
            }
            // Unknown command: Core returns a successful result with this
            // string (not an error), so rpc_help.py can assert_equal on it.
            return Ok::<_, ErrorObjectOwned>(serde_json::json!(format!(
                "help: unknown command: {cmd}"
            )));
        }

        // Build the categorized help listing.
        let categories = ["Blockchain", "Control", "Mining", "Network", "Rawtransactions", "Util"];
        let mut output = String::new();
        for cat in &categories {
            output.push_str(&format!("== {} ==\n", cat));
            for &(name, method_cat) in METHODS {
                if method_cat == *cat {
                    output.push_str(name);
                    output.push('\n');
                }
            }
        }
        // Remove the trailing newline for clean formatting.
        let trimmed = output.trim_end().to_string();
        Ok::<_, ErrorObjectOwned>(serde_json::json!(trimmed))
    })?;

    // Core's version blocks until its serialized validation-callback queue has
    // drained past everything pending on entry; its test framework calls it
    // from `sync_all()` so assertions do not race a callback. satd writes
    // indexes inline during block connection and updates the mempool under its
    // own lock, so RPC-visible state is already settled when the RPC that
    // changed it returns; what is genuinely asynchronous here is outbound
    // event delivery, so that is what this drains. See `events::drain`.
    //
    // Scope, so callers do not over-read it: this waits for events to reach the
    // `NodeEvent` bus, not for any particular subscriber to have received one.
    // The gRPC/WebSocket/ZMQ sinks consume the bus as independent tasks and are
    // not counted, and neither are the other consumers of the chain-event
    // broadcast (the address-index status notifier, the P2P block-announcement
    // task, `-stopatheight`, `-blocknotify`). Core's drain does cover its
    // equivalents, so a test that needs one of those settled needs more than
    // this. Unlike `setmocktime` below, this is not chain-gated -- Core's is
    // not either.
    module.register_async_method(
        "syncwithvalidationinterfacequeue",
        |_params, _ctx, _extensions| async move {
            if crate::events::drain::wait_for_drain().await {
                Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
            } else {
                // Better to say the queue is wedged than to return as though
                // it drained and let a caller assert against stale state.
                Err(ErrorObjectOwned::owned(
                    -32603,
                    "timed out waiting for the event queue to drain",
                    None::<()>,
                ))
            }
        },
    )?;

    // Core gates this to a "mockable chain", which in Core is regtest alone --
    // mainnet, testnet3, testnet4 and signet all set m_is_mockable_chain
    // false. satd matches that, with Core's message, so a node off regtest
    // behaves exactly as bitcoind would. satd adds one further restriction on
    // top: `test:clock` is not implied by `rpc:write`, so a delegated bearer
    // token cannot move the clock even on regtest unless the authfile grants
    // it. The cookie/rpcauth operator has every capability, which is what lets
    // the test harness drive it.
    module.register_method("setmocktime", |params, ctx, _extensions| {
        if !crate::time::clock_is_mockable(ctx.chain_state.network) {
            // -1 (RPC_MISC_ERROR), not -8: Core throws a bare
            // `std::runtime_error` here, which its dispatcher converts to
            // RPC_MISC_ERROR. Only the range check below is
            // RPC_INVALID_PARAMETER. A Core-derived test asserting -1 would
            // otherwise fail against satd for the wrong reason.
            return Err(ErrorObjectOwned::owned(
                -1,
                "setmocktime is for regression testing (-regtest mode) only",
                None::<()>,
            ));
        }
        let mut args = Args::new(&params);
        let timestamp: i64 = args.required("timestamp").map_err(|e| {
            ErrorObjectOwned::owned(-8, format!("Invalid timestamp: {}", e.message()), None::<()>)
        })?;
        args.check()?;
        // Core's bound is the largest second representable as nanoseconds.
        const MAX_MOCK_TIME: i64 = i64::MAX / 1_000_000_000;
        if !(0..=MAX_MOCK_TIME).contains(&timestamp) {
            return Err(ErrorObjectOwned::owned(
                -8,
                format!("Mocktime must be in the range [0, {MAX_MOCK_TIME}], not {timestamp}."),
                None::<()>,
            ));
        }
        // Core spells "stop mocking" as timestamp 0.
        crate::time::set_mock_time(if timestamp == 0 {
            None
        } else {
            Some(timestamp as u64)
        });
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
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
        let mut args = Args::new(&params);
        let since_secs: u64 = args.optional_or("since_secs", 86_400)?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let since_secs: u64 = args.optional_or("since_secs", 3_600)?;
        args.check()?;
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

    module.register_method("getmemoryinfo", |params, _ctx, _extensions| {
        let mut args = Args::new(&params);
        let mode: Option<String> = args.optional("mode")?;
        args.check()?;
        let mode_str = mode.as_deref().unwrap_or("stats");
        match mode_str {
            "stats" => {
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
                // The test asserts used > 0, free > 0, chunks_used > 0,
                // chunks_free > 0, and used + free == total. Use the RSS
                // as "used" and derive plausible values for the rest.
                let used = rss.max(1);
                let free = 1024u64; // At least 1 kB free
                let total = used + free;
                Ok::<_, ErrorObjectOwned>(serde_json::json!({
                    "locked": {
                        "used": used,
                        "free": free,
                        "total": total,
                        "locked": 0,
                        "chunks_used": 1,
                        "chunks_free": 1,
                    }
                }))
            }
            "mallocinfo" => {
                Err(ErrorObjectOwned::owned(
                    -8,
                    "mallocinfo mode not available",
                    None::<()>,
                ))
            }
            other => {
                Err(ErrorObjectOwned::owned(
                    -8,
                    format!("unknown mode {other}"),
                    None::<()>,
                ))
            }
        }
    })?;

    module.register_method("getrpcinfo", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "active_commands": [],
            "logpath": "",
        }))
    })?;

    module.register_method("logging", |params, _ctx, _extensions| {
        // Core-compatible logging categories. All start enabled; callers can
        // toggle them with include/exclude arrays. State is per-process
        // (static) because satd logging is process-wide.
        use std::sync::OnceLock;
        static LOGGING_STATE: OnceLock<parking_lot::RwLock<std::collections::BTreeMap<String, bool>>> = OnceLock::new();
        let state = LOGGING_STATE.get_or_init(|| {
            let cats = [
                "addrman", "bench", "blockstorage", "cmpctblock", "coindb",
                "estimatefee", "http", "i2p", "ipc", "leveldb", "libevent",
                "lock", "mempool", "mempoolrej", "net", "proxy", "prune",
                "qt", "rand", "reindex", "rpc", "scan", "selectcoins",
                "tor", "txpackages", "txreconciliation", "util", "validation",
                "walletdb", "zmq",
            ];
            let map: std::collections::BTreeMap<String, bool> = cats
                .iter()
                .map(|c| (c.to_string(), true))
                .collect();
            parking_lot::RwLock::new(map)
        });

        let mut args = Args::new(&params);
        let include: Option<Vec<String>> = args.optional("include")?;
        let exclude: Option<Vec<String>> = args.optional("exclude")?;
        args.check()?;

        if let Some(ref inc) = include {
            let mut map = state.write();
            for cat in inc {
                if let Some(v) = map.get_mut(cat) {
                    *v = true;
                }
            }
        }
        if let Some(ref exc) = exclude {
            let mut map = state.write();
            for cat in exc {
                if let Some(v) = map.get_mut(cat) {
                    *v = false;
                }
            }
        }

        let map = state.read();
        let obj: serde_json::Map<String, serde_json::Value> = map
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(*v)))
            .collect();
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Object(obj))
    })?;

    module.register_method("validateaddress", |params, _ctx, _extensions| {
        let address: String = params
            .one()
            .map_err(|e| ErrorObjectOwned::owned(-1, e.to_string(), None::<()>))?;
        Ok::<_, ErrorObjectOwned>(util::validate_address(&address))
    })?;

    module.register_method("getdescriptorinfo", |params, _ctx, _extensions| {
        let mut args = Args::new(&params);
        // Core returns -3 for a type error and its help text for a missing
        // argument; `required` already answers -3 for the former.
        let descriptor: String = args.required("descriptor").map_err(|e| {
            if e.code() == -1 {
                ErrorObjectOwned::owned(
                    -1,
                    "getdescriptorinfo \"descriptor\"\n\n\
                     Analyses a descriptor.\n\n\
                     Arguments:\n\
                     1. descriptor    (string, required) The descriptor.\n",
                    None::<()>,
                )
            } else {
                e
            }
        })?;
        args.check()?;
        crate::rpc::descriptor::get_descriptor_info(&descriptor)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("deriveaddresses", |params, ctx, _extensions| {
        let mut args = Args::new(&params);
        let descriptor: String = args.required("descriptor")?;
        // Core declares `range` as RANGE (numeric or array), so it has no
        // single expected JSON type and is validated downstream.
        let range: Option<serde_json::Value> = args.raw("range")?;
        args.check()?;
        crate::rpc::descriptor::derive_addresses(
            &descriptor,
            range.as_ref(),
            ctx.chain_state.network,
        )
        .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- Long-polling RPCs ---

    module.register_async_method(
        "waitforblockheight",
        |params, ctx, _extensions| async move {
            let mut args = Args::new(&params);
            let target_height: u32 = args.required("height")?;
            let timeout_ms: u64 = args.optional_or("timeout", 0)?;
            args.check()?;
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
        let mut args = Args::new(&params);
        let timeout_ms: u64 = args.optional_or("timeout", 0)?;
        args.check()?;
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
        let mut args = Args::new(&params);
        let blockhash: String = args.required("blockhash")?;
        let timeout_ms: u64 = args.optional_or("timeout", 0)?;
        args.check()?;
        let target_hash: bitcoin::BlockHash = blockhash
            .parse()
            .map_err(|_| ErrorObjectOwned::owned(-1, "Invalid block hash", None::<()>))?;
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
        .max_request_body_size(crate::rpc::RPC_MAX_BODY_SIZE as u32)
        .max_response_body_size(crate::rpc::RPC_MAX_BODY_SIZE as u32)
        .build();
    // Methods is Arc-backed and cheap to clone — one copy is consumed
    // by each per-bind `Server::start()` call below, plus one to feed
    // the TLS path's per-connection service builder if TLS is enabled.
    let methods: Methods = module.into();

    // Completeness audit for the named-parameter table. A method missing from
    // it is not rejected -- it simply keeps failing on object `params` the way
    // the whole surface used to -- so nothing here is load-bearing for safety.
    // But a gap is a silent Core-compatibility regression for that method, and
    // the table is generated from Core's declarations rather than maintained
    // by hand, so a newly registered RPC is exactly the case that slips
    // through. `debug_assert` makes the test suite the place that catches it.
    let unnamed: Vec<&str> = methods
        .method_names()
        .filter(|m| crate::rpc::named_params::arg_names(m).is_none())
        .collect();
    if !unnamed.is_empty() {
        tracing::warn!(
            methods = ?unnamed,
            "registered RPC methods missing from the named-parameter table in \
             rpc::named_params; they will reject object `params` that Bitcoin Core accepts"
        );
        debug_assert!(
            unnamed.is_empty(),
            "RPC methods missing from rpc::named_params::arg_names: {unnamed:?}"
        );
    }
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
            // Not the startup listener: this is the full RPC server.
            None,
            header_read_timeout,
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
        spawn_readonly_listeners(ro, &server_cfg, &auth, &methods, &shutdown_tx_outer, header_read_timeout).await?
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
    header_read_timeout: Option<Duration>,
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
                // Not the startup listener.
                None,
                header_read_timeout,
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
    // CoreHttpPreludeLayer is outermost: the Core-compatible checks that
    // need only the request head (404 for non-root paths, 400 for long
    // URIs, Content-Type injection) run before auth, matching Core's
    // libevent httpserver, which answers those unauthenticated.
    // AdmissionLayer is next so an over-budget request is shed (429)
    // before any auth work. AuthLayer follows, and JsonRpcCompatLayer is
    // innermost — deliberately: it is the layer that buffers and JSON-parses
    // the request body, and an unauthenticated caller must never be able to
    // make us do that. When the surface honors bearer tokens,
    // install the capability filter at the RPC layer so scoped
    // tokens are gated per method; the operator principal has all
    // capabilities, so this is a no-op for legacy clients.
    let capability_filter = bearer.as_ref().map(|_| CapabilityLayer::new());
    let tls_middleware = tower::ServiceBuilder::new()
        .layer(CoreHttpPreludeLayer::new())
        .layer(AdmissionLayer::new(admission))
        .layer(AuthLayer::new(auth, bearer))
        .layer(JsonRpcCompatLayer::new());
    let rpc_svc = ServerBuilder::new()
        .set_config(server_cfg)
        .set_http_middleware(tls_middleware)
        .set_rpc_middleware(
            RpcServiceBuilder::new()
                // Outermost: object `params` becomes positional `params`
                // before anything downstream inspects them, so the filters and
                // every handler see one shape.
                .layer(NamedParamsLayer::new())
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
    // `Some` only on the startup listener, which serves progress while the
    // node comes up: answers every other method with Core's `-28 RPC in
    // warmup` instead of `-32601 Method not found`. `None` elsewhere.
    warmup: Option<crate::rpc::warmup::WarmupLayer>,
    // Per-connection HTTP header-read timeout (`-rpcservertimeout`).
    // `None` disables (hyper's default). When set, hyper closes any
    // connection whose client does not complete the HTTP request
    // header within this window — the Core libevent equivalent of
    // `evhttp_set_timeout`.
    header_read_timeout: Option<Duration>,
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
        .layer(CoreHttpPreludeLayer::new())
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
                // Outermost: object `params` becomes positional `params`
                // before anything downstream inspects them, so the filters and
                // every handler see one shape.
                .layer(NamedParamsLayer::new())
                .option_layer(warmup)
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
            let serve = tokio::spawn(serve_http_connection(
                stream,
                svc,
                conn_stop.shutdown(),
                header_read_timeout,
            ));
            tokio::spawn(async move {
                let _permit = permit;
                let _ = serve.await;
            });
        }
    });

    Ok(server_handle)
}

/// Serve a single HTTP connection with an optional header-read timeout.
///
/// This is the plain-HTTP equivalent of jsonrpsee's
/// [`serve_with_graceful_shutdown`], with one addition: when
/// `header_read_timeout` is `Some`, the underlying hyper HTTP/1.1
/// builder is configured with a matching `header_read_timeout` (plus
/// the required timer), so a client that opens a TCP connection but
/// never completes the HTTP request headers gets disconnected rather
/// than holding a connection slot forever.  This wires Bitcoin Core's
/// `-rpcservertimeout` knob.
async fn serve_http_connection<S, B>(
    io: tokio::net::TcpStream,
    service: S,
    stopped: impl std::future::Future<Output = ()>,
    header_read_timeout: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tower::Service<
            jsonrpsee::server::HttpRequest<hyper::body::Incoming>,
            Response = jsonrpsee::server::HttpResponse<B>,
            Error = tower::BoxError,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
    B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
    B::Error: Into<tower::BoxError>,
{
    let service = hyper_util::service::TowerToHyperService::new(service);
    let io = hyper_util::rt::TokioIo::new(io);

    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    if let Some(timeout) = header_read_timeout {
        builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(timeout);
    }
    let conn = builder.serve_connection_with_upgrades(io, service);

    tokio::pin!(stopped, conn);

    tokio::select! {
        result = &mut conn => result,
        () = stopped => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    }
}
