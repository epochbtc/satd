mod config;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Tune jemalloc: return freed pages to the OS faster to reduce RSS bloat.
// Default decay is 10s; under heavy alloc/free churn (LRU eviction, HashMap
// resize) dirty pages accumulate faster than they decay, inflating RSS by 2-3x.
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: &[u8] = b"dirty_decay_ms:1000,muzzy_decay_ms:2000\0";

use config::Config;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::{Mempool, MempoolConfig};
use node::rpc::auth::RpcAuth;
use node::storage::Store;
use node::storage::rocksdb_store::RocksDbStore;
use node::storage::flatfile::FlatFileManager;
use config::ConsensusEngine;
use node::validation::script::{ConsensusVerifier, RustVerifier, ShadowVerifier, ScriptVerifier};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Config must be parsed before tracing init so --log-format can select
    // the formatter. Config parse errors go to stderr as plain text.
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match config.log_format {
        config::LogFormat::Json => {
            // Stable JSON shape: `timestamp`, `level`, `target`,
            // `fields.message`, plus any per-event structured fields.
            tracing_subscriber::fmt()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_env_filter(env_filter)
                .init();
        }
        config::LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    tracing::info!(
        network = %config.network,
        datadir = %config.datadir.display(),
        rpcport = config.rpcport,
        "satd v0.1.0 starting"
    );

    // Configure server-wide structured-error switch before any RPC handlers run.
    node::rpc::error::set_extended_enabled(config.rpc_extended_errors);
    if config.rpc_extended_errors {
        tracing::info!(
            "RPC extended errors enabled — responses include data.category/suggestion/debug (non-Core-compat wire format)"
        );
    }

    // Configure server-wide default RPC amount unit before any RPC starts.
    node::rpc::amounts::set_default(config.rpc_default_units);
    if config.rpc_default_units != node::rpc::amounts::AmountUnit::Btc {
        tracing::info!(
            units = config.rpc_default_units.as_str(),
            "RPC default units: integer satoshis (non-Core-compat; clients expecting BTC will see numeric differences)"
        );
    }

    if config.max_ahead < 1000 && config.max_ahead != u32::MAX {
        tracing::warn!(
            max_ahead = config.max_ahead,
            "Low --maxahead value may cause slow IBD block assignment. Consider >= 1000."
        );
    }

    // Create network-specific data directory
    let net_datadir = config.network_datadir();
    if let Err(e) = std::fs::create_dir_all(&net_datadir) {
        eprintln!(
            "Error creating data directory {}: {}",
            net_datadir.display(),
            e
        );
        std::process::exit(1);
    }

    // Consume the clean-shutdown marker from the previous run (if any), BEFORE
    // opening the chain database. Unlinking happens first so a crash during
    // startup always results in "dirty" on the next run.
    let prior_shutdown = node::shutdown::consume_marker(&net_datadir);
    let last_shutdown_clean = prior_shutdown.is_some();
    match &prior_shutdown {
        Some(rec) => tracing::info!(
            tip_height = rec.tip_height,
            tip_hash = %rec.tip_hash,
            "Clean shutdown marker observed — previous exit flushed cleanly"
        ),
        None => tracing::warn!(
            "No clean-shutdown marker — previous exit was dirty or this is a fresh datadir. \
             Block-index replay will run lazily as needed via DataStored→Valid path."
        ),
    }

    // Set up authentication
    let auth = if let (Some(user), Some(pass)) = (&config.rpcuser, &config.rpcpassword) {
        RpcAuth::from_user_pass(user.clone(), pass.clone())
    } else {
        match RpcAuth::generate_cookie(&net_datadir) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Error generating cookie file: {}", e);
                std::process::exit(1);
            }
        }
    };
    let auth = Arc::new(auth);

    // Start a lightweight startup-status RPC server immediately.
    // This lets the TUI show "Loading database..." instead of "Connecting...".
    // It will be stopped once the full RPC server is ready.
    let rpc_bind: SocketAddr = format!("{}:{}", config.rpcbind, config.rpcport)
        .parse()
        .expect("Invalid RPC bind address");
    let startup_status = Arc::new(std::sync::RwLock::new("Opening database...".to_string()));
    let startup_handle = {
        let status = startup_status.clone();
        let auth_clone = auth.clone();
        start_startup_rpc(rpc_bind, auth_clone, status).await
    };

    // Open block storage
    let blocks_dir = net_datadir.join("blocks");

    // Detect legacy redb database and fail fast
    let legacy_redb = net_datadir.join("chainstate.redb");
    if legacy_redb.exists() {
        eprintln!(
            "Error: found legacy redb database at {}.\n\
             The storage engine has changed to RocksDB. To continue:\n\
             1. Delete the old chainstate: rm {}\n\
             2. Restart with --reindex to rebuild from block files, or\n\
             3. Start fresh with a new datadir.",
            legacy_redb.display(),
            legacy_redb.display(),
        );
        auth.cleanup();
        std::process::exit(1);
    }

    // Partition dbcache budget: 1/3 to RocksDB block cache, 2/3 to CoinCache overlays
    let rocksdb_cache_mb = config.dbcache / 3;
    let coincache_mb = config.dbcache - rocksdb_cache_mb;

    let reindex = config.reindex || config.reindex_chainstate;
    let store = match RocksDbStore::open(&net_datadir, config.txindex, rocksdb_cache_mb, reindex) {
        Ok(s) => Box::new(s),
        Err(e) => {
            eprintln!("Error opening chain database: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // Handle -reindex: clear everything, will rebuild from flat files
    if config.reindex {
        tracing::info!("Reindexing: clearing database, will rebuild from block files");
        if let Err(e) = store.clear_all() {
            eprintln!("Error clearing database for reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    } else if config.reindex_chainstate {
        // Handle -reindex-chainstate: clear UTXO/undo, keep block index
        tracing::info!("Reindexing chainstate: clearing UTXO set, will rebuild from block files");
        if let Err(e) = store.clear_chainstate() {
            eprintln!("Error clearing chainstate for reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    }

    let flat_files = match FlatFileManager::new(&blocks_dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error initializing block storage: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // For -reindex: scan flat files before FlatFileManager is moved into ChainState
    let reindex_blocks = if config.reindex {
        let scanned = flat_files.scan_all_blocks();
        tracing::info!(blocks = scanned.len(), "Scanned flat files for reindex");
        Some(scanned)
    } else {
        None
    };

    // Parse assumevalid: Core-compatible semantics + "all" extension
    //   (none)       → per-network default hash
    //   <hash>       → skip scripts at or below that hash
    //   0            → disable (verify all scripts)
    //   all          → skip scripts for ALL blocks (trust network)
    let assumevalid = match config.assumevalid.as_deref() {
        None | Some("") => {
            let av = node::chain::state::default_assumevalid(config.network);
            match &av {
                node::chain::state::AssumeValid::Hash(h) => {
                    tracing::info!(%h, "Using default assumevalid hash");
                }
                node::chain::state::AssumeValid::Disabled => {
                    tracing::info!("No default assumevalid for this network");
                }
                _ => {}
            }
            av
        }
        Some("0") => {
            tracing::info!("assumevalid disabled — verifying all scripts");
            node::chain::state::AssumeValid::Disabled
        }
        Some("all") => {
            tracing::info!(
                max_age_secs = config.assumevalidage,
                "assumevalid=all — skipping script verification for blocks older than {}s",
                config.assumevalidage,
            );
            node::chain::state::AssumeValid::All { max_age_secs: config.assumevalidage }
        }
        Some(hash_str) => {
            match hash_str.parse::<bitcoin::BlockHash>() {
                Ok(h) => {
                    tracing::info!(%h, "Assuming blocks valid up to hash");
                    node::chain::state::AssumeValid::Hash(h)
                }
                Err(e) => {
                    eprintln!("Error: invalid assumevalid hash '{}': {}", hash_str, e);
                    std::process::exit(1);
                }
            }
        }
    };

    // Initialize chain state with script verification
    *startup_status.write().unwrap() = "Initializing chain state...".to_string();
    let verifier: Box<dyn ScriptVerifier> = match config.consensus {
        ConsensusEngine::Cpp => {
            Box::new(ConsensusVerifier)
        }
        ConsensusEngine::Rust => {
            tracing::warn!("Using Rust consensus engine — NOT YET VALIDATED FOR PRODUCTION");
            Box::new(RustVerifier)
        }
        ConsensusEngine::RustShadow => {
            tracing::info!("Consensus: rust-shadow (cpp authoritative, rust shadow)");
            Box::new(ShadowVerifier::new(
                Box::new(ConsensusVerifier),
                Box::new(RustVerifier),
                "cpp",
                "rust",
                config.shadow_queue_size,
                config.shadow_workers,
            ))
        }
        ConsensusEngine::CppShadow => {
            tracing::info!("Consensus: cpp-shadow (rust authoritative, cpp shadow)");
            Box::new(ShadowVerifier::new(
                Box::new(RustVerifier),
                Box::new(ConsensusVerifier),
                "rust",
                "cpp",
                config.shadow_queue_size,
                config.shadow_workers,
            ))
        }
    };
    let chain_state = match ChainState::new(
        store,
        flat_files,
        config.network,
        verifier,
        assumevalid,
        coincache_mb as u64,
        config.prefetch_workers,
        node::index::address::AddressIndexConfig {
            enabled: config.addressindex,
            max_subscriptions: config.addrindexsubscriptions,
            ..Default::default()
        },
    ) {
        Ok(cs) => Arc::new(cs),
        Err(e) => {
            eprintln!("Error initializing chain state: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    tracing::info!(
        height = chain_state.tip_height(),
        tip = %chain_state.tip_hash(),
        "Chain state initialized"
    );

    // Open reorg log + optional webhook dispatcher. Failure is non-fatal
    // — the node still runs, just without persistent reorg history.
    match node::chain::reorg_log::ReorgLog::open(
        &net_datadir,
        node::chain::reorg_log::DEFAULT_RING_CAPACITY,
    ) {
        Ok(log) => {
            let reorg_log = Arc::new(log);
            if let Some(url) = config.reorg_webhook.clone() {
                let (tx, rx) = tokio::sync::mpsc::channel::<node::chain::reorg_log::ReorgRecord>(64);
                reorg_log.set_webhook_sender(tx);
                let secret = config.reorg_webhook_secret.clone();
                tokio::spawn(reorg_webhook_dispatcher(url, secret, rx));
            }
            chain_state.attach_reorg_log(reorg_log);
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to open reorg log; running without persistent reorg history");
        }
    }

    // Run reindex replay if requested
    if config.reindex {
        if let Err(e) = chain_state.reindex_from_blocks(reindex_blocks.unwrap()) {
            eprintln!("Error during reindex: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    } else if config.reindex_chainstate
        && let Err(e) = chain_state.reindex_chainstate()
    {
        eprintln!("Error during chainstate reindex: {}", e);
        auth.cleanup();
        std::process::exit(1);
    }

    // Shutdown channel — created before the mempool so the snapshotter
    // task can subscribe to it.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Initialize mempool with policy from config
    let mempool = Arc::new(Mempool::with_config(MempoolConfig {
        max_size_bytes: config.maxmempool * 1_000_000,
        min_fee_rate: config.minrelaytxfee,
        full_rbf: config.mempoolfullrbf,
        dust_relay_fee: config.dustrelayfee,
        data_carrier: config.datacarrier,
        data_carrier_size: config.datacarriersize,
        max_ancestor_count: config.limitancestorcount,
        max_descendant_count: config.limitdescendantcount,
        expiry_secs: config.mempoolexpiry * 3600,
        permit_bare_multisig: config.permitbaremultisig,
    }));
    let fee_estimator = Arc::new(FeeEstimator::new());

    // Wire the mempool event broadcaster used by `subscribemempool`
    // AND by the address-index mempool variant (M4). The address index
    // task subscribes before any tx admission so it observes every
    // Enter/Leave event from startup onward.
    //
    // Only the index task subscribes to mempool events — the M5
    // notifier piggybacks on the index task (mutate-then-notify in the
    // same tokio arm) so chain/mempool ordering is deterministic.
    let (mempool_event_tx, _) = tokio::sync::broadcast::channel::<
        node::mempool::events::MempoolEvent,
    >(node::mempool::pool::EVENT_BROADCAST_CAPACITY);
    let addr_index_mempool_event_rx = mempool_event_tx.subscribe();
    mempool.set_event_sender(mempool_event_tx);

    // Wire the chain-event broadcaster used by the address-index
    // notifier (M5) and any future observability subscribers.
    let (chain_event_tx, _) = tokio::sync::broadcast::channel::<
        node::chain::events::ChainEvent,
    >(node::chain::events::CHAIN_EVENT_BROADCAST_CAPACITY);
    let addr_notifier_chain_event_rx = chain_event_tx.subscribe();
    chain_state.set_chain_event_sender(chain_event_tx);

    // Hook the mempool back into ChainState so `perform_reorg` can
    // re-add disconnected non-coinbase txs after a reorg (Bitcoin Core
    // semantics). Without this, every reorg would silently drop
    // unconfirmed-but-still-valid user txs.
    chain_state.set_mempool(mempool.clone());

    // Shared MempoolAddrIndex handle. Both the read-side
    // RocksAddressIndex (for RPC queries) and the background
    // event-loop task hold the same Arc<RwLock<...>>.
    let mempool_addr_index = std::sync::Arc::new(std::sync::RwLock::new(
        node::index::address::MempoolAddrIndex::new(),
    ));

    // Construct the read-side RocksAddressIndex up front so its
    // `subscription_registry()` handle is available to the mempool
    // index task (which fires status-update notifications inline with
    // each event mutation — see `NotifyBundle`).
    let address_index_store: std::sync::Arc<dyn node::storage::Store> =
        chain_state.store_ref().clone();
    let address_index_concrete = std::sync::Arc::new(
        node::index::address::RocksAddressIndex::with_mempool_index(
            address_index_store,
            node::index::address::AddressIndexConfig {
                enabled: config.addressindex,
                max_subscriptions: config.addrindexsubscriptions,
                ..Default::default()
            },
            mempool_addr_index.clone(),
        ),
    );
    let address_index: std::sync::Arc<dyn node::index::address::AddressIndex> =
        address_index_concrete.clone();

    {
        let task_index = mempool_addr_index.clone();
        let task_mempool = mempool.clone();
        let task_chain = chain_state.clone();
        let task_shutdown = shutdown_rx.clone();
        let notify = node::index::address::NotifyBundle {
            index: address_index_concrete.clone(),
            registry: address_index_concrete.subscription_registry(),
        };
        tokio::spawn(async move {
            node::index::address::mempool_index_task(
                task_index,
                task_mempool,
                task_chain,
                addr_index_mempool_event_rx,
                task_shutdown,
                Some(notify),
            )
            .await;
        });
    }

    // Open the mempool history ring + spawn the snapshotter task.
    // Failure is non-fatal — the node still runs, but the
    // `getmempoolhistory` RPC reports `available: false` so operators
    // know the feature is off, not just quiet. 10 s cadence × 256-entry
    // ring ≈ 40 min of coverage.
    let mempool_history: Option<Arc<node::mempool::history::MempoolHistory>> =
        match node::mempool::history::MempoolHistory::open(
            &net_datadir,
            node::mempool::history::DEFAULT_RING_CAPACITY,
        ) {
            Ok(h) => {
                let arc = Arc::new(h);
                let snap_arc = arc.clone();
                let snap_mempool = mempool.clone();
                let mut snap_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            _ = snap_shutdown.changed() => break,
                            _ = interval.tick() => {
                                let snap = node::mempool::history::snapshot_from_mempool(&snap_mempool);
                                snap_arc.record_if_changed(snap);
                            }
                        }
                    }
                });
                Some(arc)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to open mempool history; getmempoolhistory will report available=false"
                );
                None
            }
        };

    // Initialize P2P peer manager
    let peer_manager = node::net::manager::PeerManager::with_config(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        config.network,
        shutdown_rx.clone(),
        config.prune,
        config.maxconnections,
        config.bantime,
        config.proxy.clone(),
        config.onion.clone(),
        config.prefetch_workers,
        config.max_ahead,
    );

    if config.prune > 0 {
        tracing::info!(target_mb = config.prune, "Block pruning enabled");
    }

    if config.proxy.is_some() {
        tracing::info!(proxy = config.proxy.as_deref().unwrap(), "SOCKS5 proxy enabled for outbound connections");
    }

    // Start Tor hidden service if -torcontrol is set
    let mut _onion_addr: Option<String> = None;
    if let Some(ref torcontrol) = config.torcontrol {
        match node::net::tor::TorController::connect(torcontrol).await {
            Ok(mut controller) => {
                let password = config.torpassword.as_deref().unwrap_or("");
                match controller.authenticate(password).await {
                    Ok(()) => {
                        let target = format!("127.0.0.1:{}", config.port);
                        match controller.create_hidden_service(config.port, &target).await {
                            Ok(onion) => {
                                tracing::info!(onion_addr = %onion, "Tor hidden service created");
                                _onion_addr = Some(onion);
                            }
                            Err(e) => {
                                tracing::error!("Failed to create Tor hidden service: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Tor control authentication failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to connect to Tor control port: {}", e);
            }
        }
    }

    // Stop the startup RPC server and start the real one on the same port
    startup_handle.stop().expect("Failed to stop startup RPC");
    // Give the port a moment to be released
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let bind_addr = rpc_bind;

    let effective_config_view = config.effective_view();

    // Spawn the chain-driven status-update notifier (M5). The mempool-
    // driven path is folded into `mempool_index_task` above so the
    // index mutation and notification fire as a single unit; this
    // task only handles `BlockConnected` / `BlockDisconnected` events
    // that affect every subscribed scripthash with confirmed history.
    {
        let task_index = address_index_concrete.clone();
        let task_registry = address_index_concrete.subscription_registry();
        let task_chain = chain_state.clone();
        let task_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            node::index::address::notifier_task(
                task_index,
                task_registry,
                task_chain,
                addr_notifier_chain_event_rx,
                task_shutdown,
            )
            .await;
        });
    }

    // Backfill handle (M7). Always created so `getindexinfo` /
    // pause/resume/cancel report a stable shape — for non-AssumeUTXO
    // datadirs the cursor stays Idle and the RPCs are no-ops.
    let backfill_handle = std::sync::Arc::new(
        node::index::address::BackfillHandle::new(
            node::index::address::BackfillCursor::idle(),
        ),
    );

    let server_handle = match node::rpc::server::start(
        bind_addr,
        auth.clone(),
        chain_state.clone(),
        mempool.clone(),
        peer_manager.clone(),
        fee_estimator.clone(),
        shutdown_tx,
        last_shutdown_clean,
        effective_config_view,
        mempool_history.clone(),
        address_index,
        config.addressindex,
        Some(backfill_handle.clone()),
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error starting RPC server: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    tracing::info!(%bind_addr, "RPC server listening");

    // Start MCP server if enabled
    if config.mcp {
        let mcp_ctx = std::sync::Arc::new(satd_mcp::McpContext {
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            peer_manager: peer_manager.clone(),
            fee_estimator: fee_estimator.clone(),
            start_time: std::time::Instant::now(),
            network: config.network,
            effective_config: config.effective_view(),
            mempool_history: mempool_history.clone(),
        });

        if config.mcp_stdio {
            let ctx = mcp_ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = satd_mcp::serve_stdio(ctx).await {
                    tracing::error!("MCP stdio server error: {}", e);
                }
            });
            tracing::info!("MCP stdio server started");
        }

        if let Some(mcp_port) = config.mcp_port {
            let mcp_bind: SocketAddr = format!("{}:{}", config.mcp_bind, mcp_port)
                .parse()
                .expect("Invalid MCP bind address");
            let ctx = mcp_ctx.clone();
            let rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = satd_mcp::serve_http(ctx, mcp_bind, rx).await {
                    tracing::error!("MCP HTTP server error: {}", e);
                }
            });
        }
    }

    // Start metrics/health HTTP server if enabled (unauthenticated — bind to
    // loopback by default, or firewall externally).
    if let Some(metricsport) = config.metricsport {
        let metrics_bind: SocketAddr = format!("{}:{}", config.metricsbind, metricsport)
            .parse()
            .expect("Invalid metrics bind address");
        let metrics_ctx = node::metrics::MetricsContext {
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            peer_manager: peer_manager.clone(),
            network: config.network,
            start_time: std::time::Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            addr_subs: Some(address_index_concrete.subscription_registry()),
            addr_enabled: config.addressindex,
        };
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = node::metrics::serve_metrics_http(metrics_ctx, metrics_bind, rx).await {
                tracing::error!("Metrics HTTP server error: {}", e);
            }
        });
    }

    // Write PID file if requested
    if let Some(ref pid_path) = config.pid
        && let Err(e) = std::fs::write(pid_path, std::process::id().to_string())
    {
        eprintln!("Warning: failed to write PID file {}: {}", pid_path, e);
    }

    // Start P2P networking
    if config.listen {
        let p2p_addr: SocketAddr = format!("{}:{}", config.bind, config.port)
            .parse()
            .expect("Invalid P2P bind address");
        let pm = peer_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = pm.listen(p2p_addr).await {
                tracing::error!("P2P listener error: {}", e);
            }
        });
        tracing::info!(port = config.port, "P2P listening");
    }

    // Connect to configured peers (and register for auto-reconnect)
    for addr_str in &config.connect {
        match node::net::peer::PeerAddr::parse(addr_str) {
            Ok(addr) => {
                peer_manager.add_peer_addr(addr.clone());
                let pm = peer_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::warn!(%addr, "Failed to connect to peer: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = addr_str, "Invalid connect address: {}", e);
            }
        }
    }

    // Connect to -addnode peers (does NOT disable DNS seeding)
    for addr_str in &config.addnode {
        match node::net::peer::PeerAddr::parse(addr_str) {
            Ok(addr) => {
                peer_manager.add_peer_addr(addr.clone());
                let pm = peer_manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = pm.connect_peer_addr(&addr).await {
                        tracing::warn!(%addr, "Failed to connect to addnode peer: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!(addr = addr_str, "Invalid addnode address: {}", e);
            }
        }
    }

    // DNS seeding: only if no explicit --connect peers and --dns is enabled
    if config.connect.is_empty() && config.dns {
        let seed_addrs = node::net::dns::resolve_seeds(
            config.network,
            config.proxy.as_deref(),
        )
        .await;
        let max_dns_outbound = 64;
        for addr in seed_addrs.into_iter().take(max_dns_outbound) {
            peer_manager.add_peer_addr(addr.clone());
            let pm = peer_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = pm.connect_peer_addr(&addr).await {
                    tracing::warn!(%addr, "Seed peer connection failed: {}", e);
                }
            });
        }
    }

    // Spawn P2P event loop
    {
        let pm = peer_manager.clone();
        tokio::spawn(async move { pm.run().await });
    }

    // Spawn adaptive-dbcache controller if --dbcache=auto was requested.
    // It resizes the RocksDB block cache and the CoinCache clean LRU every
    // 30 seconds based on /proc/meminfo MemAvailable.
    if config.dbcache_mode.is_auto() {
        let max_bytes = config.dbcache as u64 * 1_000_000;
        let cs = chain_state.clone();
        let rx = shutdown_rx.clone();
        node::adaptive_cache::spawn_adaptive_cache(cs, max_bytes, rx);
        tracing::info!(
            max_mb = config.dbcache,
            "Adaptive dbcache enabled — cap set to max budget, adjusted from /proc/meminfo"
        );
    }

    // Wait for shutdown signal (stop RPC, Ctrl+C, or SIGTERM)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to register SIGTERM handler");
    tokio::select! {
        _ = shutdown_rx.wait_for(|v| *v) => {
            tracing::info!("Shutdown signal received from RPC");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down");
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down");
        }
    }

    // Graceful shutdown — flush UTXO cache before stopping, bounded by
    // --max-shutdown-secs so we actually exit within the deadline no matter
    // how long the blocking flush takes.
    //
    // Implementation note: tokio::task::spawn_blocking cannot be aborted, and
    // tokio's runtime shutdown will wait for blocking tasks to complete. If
    // we only wrapped it in tokio::time::timeout, the outer await would
    // return but the process would still hang until the flush finishes (or
    // forever, on a stuck flush). To genuinely enforce the deadline we run
    // the flush on a dedicated std::thread, signal completion over a oneshot,
    // and std::process::exit on timeout — that's the only way to end the
    // process when the flush is stuck inside the rocksdb FFI.
    //
    // Safety on timeout-forced exit: no data is lost. The next startup will
    // replay any DataStored-but-not-Valid blocks from flat files. We just
    // lose the clean-shutdown marker (which advertises "we flushed cleanly").
    let shutdown_deadline = std::time::Duration::from_secs(config.max_shutdown_secs);
    let tip_hash = chain_state.tip_hash().to_string();
    let tip_height = chain_state.tip_height();
    let flush_cs = chain_state.clone();
    let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        // Drain dirty cache to RocksDB memtable, THEN fsync the memtable to
        // SST. With BulkLoad mode (WAL disabled) a bare `flush_coin_cache`
        // leaves every post-last-atomic-flush mutation volatile — recovery
        // on restart replays from DataStored blocks, but only if those
        // blocks' chainstate effects were truly durable. Relying on the
        // RocksDB Drop-time flush is not safe: force-exit, SIGKILL or
        // panic skip destructors and memtable contents are lost. An
        // explicit `flush_durable` after `flush_coin_cache` guarantees the
        // tip pointer and its coin mutations are on disk together before
        // we signal shutdown-complete.
        let result = flush_cs.flush_coin_cache().and_then(|()| flush_cs.flush_durable());
        let _ = flush_tx.send(result);
    });
    let flushed_ok = match node::shutdown::await_bounded_flush(flush_rx, shutdown_deadline).await {
        node::shutdown::BoundedFlushOutcome::Clean => {
            tracing::info!(
                "UTXO cache flushed cleanly within {}s deadline",
                config.max_shutdown_secs
            );
            true
        }
        node::shutdown::BoundedFlushOutcome::FlushError(e) => {
            tracing::error!("UTXO cache flush reported error on shutdown: {}", e);
            false
        }
        node::shutdown::BoundedFlushOutcome::ChannelDropped => {
            tracing::error!("UTXO cache flush sender dropped before completing");
            false
        }
        node::shutdown::BoundedFlushOutcome::TimedOut => {
            // Flush exceeded the deadline. The std::thread is still inside
            // the rocksdb FFI and we can't reach in to cancel it. Force exit
            // at the OS level so the deadline is actually honored — this is
            // the point of --max-shutdown-secs. Emit the same cleanup we
            // would have done below first (PID file, cookie) so operators
            // don't see leftover state.
            tracing::error!(
                deadline_secs = config.max_shutdown_secs,
                "UTXO cache flush exceeded --max-shutdown-secs; force-exiting. \
                 Next startup will replay DataStored blocks from flat files."
            );
            auth.cleanup();
            if let Some(ref pid_path) = config.pid {
                let _ = std::fs::remove_file(pid_path);
            }
            std::process::exit(1);
        }
    };

    // Write the clean-shutdown marker only if the flush actually succeeded.
    // If we timed out or errored, leaving the marker absent is correct — it
    // tells the next startup (and the operator) that this exit was dirty.
    if flushed_ok {
        if let Err(e) = node::shutdown::write_marker(&net_datadir, &tip_hash, tip_height) {
            tracing::warn!(error = %e, "Failed to write clean-shutdown marker");
        } else {
            tracing::info!(tip_height, "Wrote clean-shutdown marker");
        }
    }

    server_handle.stop().expect("Failed to stop server");
    auth.cleanup();
    if let Some(ref pid_path) = config.pid {
        let _ = std::fs::remove_file(pid_path);
    }

    // Drop local references to help cleanup, but spawned tasks may still hold Arcs
    drop(peer_manager);
    drop(mempool);
    drop(fee_estimator);
    drop(chain_state);
    tracing::info!("Shutdown complete — local references released");

    tracing::info!("satd stopped");
}

/// Start a minimal RPC server that only serves `getstartupinfo`.
/// This runs on the RPC port before the full node is initialized,
/// so the TUI can show startup progress instead of "Connecting...".
async fn start_startup_rpc(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    status: Arc<std::sync::RwLock<String>>,
) -> jsonrpsee::server::ServerHandle {
    use jsonrpsee::server::{RpcModule, ServerBuilder};
    use jsonrpsee::types::ErrorObjectOwned;
    use node::rpc::auth::AuthLayer;

    let mut module = RpcModule::new(status);

    module
        .register_method("getstartupinfo", |_params, ctx, _extensions| {
            let status = ctx.read().unwrap().clone();
            Ok::<_, ErrorObjectOwned>(serde_json::json!({
                "started": false,
                "status": status,
            }))
        })
        .unwrap();

    let middleware = tower::ServiceBuilder::new().layer(AuthLayer::new(auth));
    let server = ServerBuilder::new()
        .set_http_middleware(middleware)
        .build(bind_addr)
        .await
        .expect("Failed to start startup RPC server");

    server.start(module)
}

/// Forwards reorg records to the configured HTTP webhook. Best effort —
/// failures are logged and dropped. Never blocks the consensus path:
/// the only backpressure is the channel itself, which `ReorgLog::record`
/// `try_send`s into (full queue = silent drop, counted).
async fn reorg_webhook_dispatcher(
    url: String,
    secret: Option<String>,
    mut rx: tokio::sync::mpsc::Receiver<node::chain::reorg_log::ReorgRecord>,
) {
    use reqwest::header::{HeaderMap, HeaderValue};
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to build reorg webhook HTTP client");
            return;
        }
    };
    tracing::info!(url = %url, signed = secret.is_some(), "Reorg webhook dispatcher started");
    while let Some(record) = rx.recv().await {
        let body = match serde_json::to_vec(&record) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize reorg record for webhook");
                continue;
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(ref key) = secret {
            let sig = hmac_sha256_hex(key.as_bytes(), &body);
            if let Ok(h) = HeaderValue::from_str(&format!("sha256={}", sig)) {
                headers.insert("X-Satd-Signature", h);
            }
        }

        // Simple retry loop: 3 attempts with jittered backoff. A failing
        // webhook must not back up consensus, so we stop after 3 and move
        // on to the next record.
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match client
                .post(&url)
                .headers(headers.clone())
                .body(body.clone())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => break,
                Ok(r) => {
                    tracing::warn!(status = %r.status(), attempt, "Reorg webhook returned non-2xx");
                }
                Err(e) => {
                    tracing::warn!(error = %e, attempt, "Reorg webhook request failed");
                }
            }
            if attempt >= 3 {
                break;
            }
            let backoff_ms = 200u64 * (1 << (attempt - 1));
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
        }
    }
    tracing::info!("Reorg webhook dispatcher stopped");
}

/// HMAC-SHA256 over `msg` keyed by `key`, hex-encoded. Pure Rust so we
/// don't pull in yet another dep; reorg rate is low so the tiny-fast-
/// crypto path is unnecessary.
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine, sha256};
    let mut hmac: HmacEngine<sha256::Hash> = HmacEngine::new(key);
    hmac.input(msg);
    let out = Hmac::<sha256::Hash>::from_engine(hmac);
    hex::encode(out.to_byte_array())
}
