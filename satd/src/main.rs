mod config;

use config::Config;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::policy::{DEFAULT_MAX_MEMPOOL_SIZE, DEFAULT_MIN_RELAY_FEE_RATE};
use node::mempool::pool::Mempool;
use node::rpc::auth::RpcAuth;
use node::storage::db::RocksDbStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::ConsensusVerifier;
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

    // Open block storage
    let blocks_dir = net_datadir.join("blocks");
    let chainstate_dir = net_datadir.join("chainstate");

    let store = match RocksDbStore::open(&chainstate_dir) {
        Ok(s) => Box::new(s),
        Err(e) => {
            eprintln!("Error opening chain database: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    let flat_files = match FlatFileManager::new(&blocks_dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error initializing block storage: {}", e);
            auth.cleanup();
            std::process::exit(1);
        }
    };

    // Parse assumevalid hash
    let assumevalid: Option<bitcoin::BlockHash> = config.assumevalid.as_ref().and_then(|s| {
        if s.is_empty() { None } else { s.parse().ok() }
    });

    if let Some(ref av) = assumevalid {
        tracing::info!(%av, "Assuming blocks valid up to hash");
    }

    // Initialize chain state with script verification
    let chain_state = match ChainState::new(
        store,
        flat_files,
        config.network,
        Box::new(ConsensusVerifier),
        assumevalid,
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

    // Initialize mempool and fee estimator
    let mempool = Arc::new(Mempool::new(
        DEFAULT_MAX_MEMPOOL_SIZE,
        DEFAULT_MIN_RELAY_FEE_RATE,
    ));
    let fee_estimator = Arc::new(FeeEstimator::new());

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Initialize P2P peer manager
    let peer_manager = node::net::manager::PeerManager::new(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        config.network,
        shutdown_rx.clone(),
    );

    // Start RPC server
    let bind_addr: SocketAddr = format!("{}:{}", config.rpcbind, config.rpcport)
        .parse()
        .expect("Invalid RPC bind address");

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

    // Start P2P networking
    if config.listen {
        let p2p_addr: SocketAddr = format!("0.0.0.0:{}", config.port)
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
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            peer_manager.add_connect_addr(addr);
            let pm = peer_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = pm.connect_outbound(addr).await {
                    tracing::warn!(%addr, "Failed to connect to peer: {}", e);
                }
            });
        }
    }

    // DNS seeding: only if no explicit --connect peers are configured
    // (matches Bitcoin Core behavior where --connect disables DNS seeding)
    if config.connect.is_empty() {
        let dns_addrs =
            node::net::dns::resolve_dns_seeds(config.network).await;
        let max_dns_outbound = 8;
        for addr in dns_addrs.into_iter().take(max_dns_outbound) {
            peer_manager.add_connect_addr(addr);
            let pm = peer_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = pm.connect_outbound(addr).await {
                    tracing::warn!(%addr, "DNS seed peer connection failed: {}", e);
                }
            });
        }
    }

    // Spawn P2P event loop
    {
        let pm = peer_manager.clone();
        tokio::spawn(async move { pm.run().await });
    }

    // Wait for shutdown signal (stop RPC or Ctrl+C)
    tokio::select! {
        _ = shutdown_rx.wait_for(|v| *v) => {
            tracing::info!("Shutdown signal received from RPC");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down");
        }
    }

    // Graceful shutdown
    server_handle.stop().expect("Failed to stop server");
    auth.cleanup();
    tracing::info!("satd stopped");
}
