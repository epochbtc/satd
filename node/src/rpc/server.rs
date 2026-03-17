use crate::rpc::auth::{AuthLayer, RpcAuth};
use crate::rpc::{blockchain, network};
use bitcoin::{Block, Network};
use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Shared state for RPC handlers.
pub struct RpcContext {
    pub network: Network,
    pub genesis_hash: String,
    pub shutdown_tx: watch::Sender<bool>,
}

/// Start the JSON-RPC HTTP server with authentication.
pub async fn start(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    network: Network,
    genesis_block: &Block,
    shutdown_tx: watch::Sender<bool>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = Arc::new(RpcContext {
        network,
        genesis_hash: genesis_block.block_hash().to_string(),
        shutdown_tx,
    });

    let mut module = RpcModule::new(ctx);

    // Register getblockchaininfo
    module.register_method("getblockchaininfo", |_params, ctx, _extensions| {
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(blockchain::get_blockchain_info(
            ctx.network,
            &ctx.genesis_hash,
        ))
    })?;

    // Register getnetworkinfo
    module.register_method("getnetworkinfo", |_params, _ctx, _extensions| {
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(network::get_network_info())
    })?;

    // Register stop
    module.register_async_method("stop", |_params, ctx, _extensions| async move {
        tracing::info!("Received stop RPC, shutting down");
        let _ = ctx.shutdown_tx.send(true);
        Ok::<_, jsonrpsee::types::ErrorObjectOwned>(
            serde_json::Value::String("btcd stopping".to_string()),
        )
    })?;

    // Build server with auth middleware
    let middleware = tower::ServiceBuilder::new().layer(AuthLayer::new(auth));

    let server = ServerBuilder::new()
        .set_http_middleware(middleware)
        .build(bind_addr)
        .await?;

    let handle = server.start(module);
    Ok(handle)
}
