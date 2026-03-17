use crate::chain::state::ChainState;
use crate::rpc::auth::{AuthLayer, RpcAuth};
use crate::rpc::{blockchain, mining, network};
use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Shared state for RPC handlers.
pub struct RpcContext {
    pub chain_state: Arc<ChainState>,
    pub shutdown_tx: watch::Sender<bool>,
}

/// Start the JSON-RPC HTTP server with authentication.
pub async fn start(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    chain_state: Arc<ChainState>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = Arc::new(RpcContext {
        chain_state,
        shutdown_tx,
    });

    let mut module = RpcModule::new(ctx);

    // Register getblockchaininfo
    module.register_method("getblockchaininfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_blockchain_info(&ctx.chain_state))
    })?;

    // Register getnetworkinfo
    module.register_method("getnetworkinfo", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(network::get_network_info())
    })?;

    // Register getbestblockhash
    module.register_method("getbestblockhash", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_best_block_hash(&ctx.chain_state))
    })?;

    // Register getblockcount
    module.register_method("getblockcount", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_block_count(&ctx.chain_state))
    })?;

    // Register getblockhash
    module.register_method("getblockhash", |params, ctx, _extensions| {
        let height: u32 = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::get_block_hash(&ctx.chain_state, height).map_err(|e| {
            ErrorObjectOwned::owned(-1, e, None::<()>)
        })
    })?;

    // Register getblock
    module.register_method("getblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hash: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let verbosity: u32 = seq.optional_next().unwrap_or(Some(1)).unwrap_or(1);
        blockchain::get_block(&ctx.chain_state, &hash, verbosity).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    // Register getblockheader
    module.register_method("getblockheader", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hash: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(true)).unwrap_or(true);
        blockchain::get_block_header(&ctx.chain_state, &hash, verbose).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    // Register submitblock
    module.register_method("submitblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_block: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        Ok::<_, ErrorObjectOwned>(mining::submit_block(&ctx.chain_state, &hex_block))
    })?;

    // Register stop
    module.register_async_method("stop", |_params, ctx, _extensions| async move {
        tracing::info!("Received stop RPC, shutting down");
        let _ = ctx.shutdown_tx.send(true);
        Ok::<_, ErrorObjectOwned>(
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
