mod config;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!(
        network = %config.network,
        datadir = %config.datadir.display(),
        rpcport = config.rpcport,
        "satd v0.1.0 starting"
    );

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
            ))
        }
        ConsensusEngine::CppShadow => {
            tracing::info!("Consensus: cpp-shadow (rust authoritative, cpp shadow)");
            Box::new(ShadowVerifier::new(
                Box::new(RustVerifier),
                Box::new(ConsensusVerifier),
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

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

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

    let server_handle = match node::rpc::server::start(
        bind_addr,
        auth.clone(),
        chain_state.clone(),
        mempool.clone(),
        peer_manager.clone(),
        fee_estimator.clone(),
        shutdown_tx,
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

    // Graceful shutdown — flush UTXO cache before stopping
    if let Err(e) = chain_state.flush_coin_cache() {
        tracing::error!("Failed to flush UTXO cache on shutdown: {}", e);
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
