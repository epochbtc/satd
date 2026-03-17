use crate::chain::state::ChainState;
use crate::mempool::fee::FeeEstimator;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::rpc::auth::{AuthLayer, RpcAuth};
use crate::rpc::{blockchain, mining, network, rawtx};
use jsonrpsee::server::{RpcModule, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Shared state for RPC handlers.
pub struct RpcContext {
    pub chain_state: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub fee_estimator: Arc<FeeEstimator>,
    pub shutdown_tx: watch::Sender<bool>,
}

/// Start the JSON-RPC HTTP server with authentication.
pub async fn start(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
    peer_manager: Arc<PeerManager>,
    fee_estimator: Arc<FeeEstimator>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = Arc::new(RpcContext {
        chain_state,
        mempool,
        peer_manager,
        fee_estimator,
        shutdown_tx,
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
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::get_block_hash(&ctx.chain_state, height).map_err(|e| {
            ErrorObjectOwned::owned(-1, e, None::<()>)
        })
    })?;

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

    // --- Mining RPCs ---

    module.register_method("submitblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_block: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        Ok::<_, ErrorObjectOwned>(mining::submit_block(
            &ctx.chain_state,
            &ctx.mempool,
            &hex_block,
        ))
    })?;

    module.register_method("generatetoaddress", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let nblocks: u32 = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let address: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        mining::generate_to_address(&ctx.chain_state, &ctx.mempool, nblocks, &address)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("generateblock", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let address: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        mining::generate_block(&ctx.chain_state, &ctx.mempool, &address)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("getblocktemplate", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(mining::get_block_template(&ctx.chain_state, &ctx.mempool))
    })?;

    // --- Transaction / Mempool RPCs ---

    module.register_method("sendrawtransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_tx: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        rawtx::send_raw_transaction(&ctx.chain_state, &ctx.mempool, &hex_tx).map_err(
            |(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>),
        )
    })?;

    module.register_method("getmempoolinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(rawtx::get_mempool_info(&ctx.mempool))
    })?;

    module.register_method("getrawmempool", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        Ok::<_, ErrorObjectOwned>(rawtx::get_raw_mempool(&ctx.mempool, verbose))
    })?;

    module.register_method("getrawtransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
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
        let hex_tx: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        rawtx::decode_raw_transaction(&hex_tx)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    // --- UTXO / Chain RPCs ---

    module.register_method("gettxout", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let vout: u32 = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::get_tx_out(&ctx.chain_state, &txid, vout).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    module.register_method("gettxoutsetinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_tx_out_set_info(&ctx.chain_state))
    })?;

    module.register_method("estimatesmartfee", |params, ctx, _extensions| {
        let conf_target: u32 = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let fee_rate = ctx.fee_estimator.estimate_fee(conf_target)
            .map(|r| r as f64 / 100_000_000.0) // sat/kvB to BTC/kvB
            .unwrap_or(0.00001000_f64); // fallback: 1 sat/vB
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "feerate": fee_rate,
            "blocks": conf_target,
            "errors": [],
        }))
    })?;

    // --- P2P RPCs ---

    module.register_method("getpeerinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.get_peer_info()))
    })?;

    module.register_method("getconnectioncount", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.connection_count()))
    })?;

    module.register_async_method("addnode", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let addr_str: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let command: String = seq.optional_next().unwrap_or(Some("onetry".to_string())).unwrap_or("onetry".to_string());

        if command == "onetry" || command == "add" {
            let addr: std::net::SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
                ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
            })?;
            ctx.peer_manager.connect_outbound(addr).await.map_err(|e| {
                ErrorObjectOwned::owned(-1, e, None::<()>)
            })?;
        }
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    module.register_method("disconnectnode", |params, ctx, _extensions| {
        let addr_str: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let addr: std::net::SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        ctx.peer_manager.disconnect(&addr);
        Ok::<_, ErrorObjectOwned>(serde_json::Value::Null)
    })?;

    // --- Control RPCs ---

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
