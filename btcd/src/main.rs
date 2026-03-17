mod config;

use config::Config;
use node::chain::state::ChainState;
use node::rpc::auth::RpcAuth;
use node::storage::db::RocksDbStore;
use node::storage::flatfile::FlatFileManager;
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
        "btcd v0.1.0 starting"
    );

    // Create network-specific data directory
    let net_datadir = config.network_datadir();
    if let Err(e) = std::fs::create_dir_all(&net_datadir) {
        eprintln!("Error creating data directory {}: {}", net_datadir.display(), e);
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

    // Initialize chain state (loads tip or writes genesis)
    let chain_state = match ChainState::new(store, flat_files, config.network) {
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

    // Shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Start RPC server
    let bind_addr: SocketAddr = format!("{}:{}", config.rpcbind, config.rpcport)
        .parse()
        .expect("Invalid RPC bind address");

    let server_handle = match node::rpc::server::start(
        bind_addr,
        auth.clone(),
        chain_state.clone(),
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
    tracing::info!("btcd stopped");
}
