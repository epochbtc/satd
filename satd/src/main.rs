mod config;

use config::Config;
use node::chain::state::ChainState;
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::{Mempool, MempoolConfig};
use node::rpc::auth::RpcAuth;
use node::storage::Store;
use node::storage::redb_store::RedbStore;
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
    let _chainstate_dir = net_datadir.join("chainstate");

    let store = match RedbStore::open(&net_datadir, config.txindex) {
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
    let peer_manager = node::net::manager::PeerManager::with_prune(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        config.network,
        shutdown_rx.clone(),
        config.prune,
    );

    if config.prune > 0 {
        tracing::info!(target_mb = config.prune, "Block pruning enabled");
    }

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
        let max_dns_outbound = 64;
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
