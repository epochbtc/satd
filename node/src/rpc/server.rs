use crate::chain::state::ChainState;
use crate::mempool::fee::FeeEstimator;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::rpc::amounts::{annotate_units, default_unit, format_amount, format_feerate_sat_per_kvb};
use crate::rpc::auth::{AuthLayer, RpcAuth};
use crate::rpc::{blockchain, mining, network, psbt, rawtx, util};
use crate::storage::Store;
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
    pub start_time: std::time::Instant,
    /// Observed at startup from the clean-shutdown marker. `true` if the
    /// previous process wrote the marker during a successful flush; `false`
    /// on first boot or after a crash / timed-out shutdown.
    pub last_shutdown_clean: bool,
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
            let est = crate::mempool::estimate::estimate_from_mempool(snapshot_fn(), target as usize);
            let (rate, _) = crate::mempool::estimate::target_estimate(&est, target, floor_sat_per_kvb);
            rate
        }
        EstimateMode::Blend => {
            let est = crate::mempool::estimate::estimate_from_mempool(snapshot_fn(), target as usize);
            let (mp_rate, mp_conf) = crate::mempool::estimate::target_estimate(&est, target, floor_sat_per_kvb);
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
#[allow(clippy::too_many_arguments)]
pub async fn start(
    bind_addr: SocketAddr,
    auth: Arc<RpcAuth>,
    chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
    peer_manager: Arc<PeerManager>,
    fee_estimator: Arc<FeeEstimator>,
    shutdown_tx: watch::Sender<bool>,
    last_shutdown_clean: bool,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = Arc::new(RpcContext {
        chain_state,
        mempool,
        peer_manager,
        fee_estimator,
        shutdown_tx,
        start_time: std::time::Instant::now(),
        last_shutdown_clean,
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

    module.register_method("getdifficulty", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_difficulty(&ctx.chain_state))
    })?;

    module.register_method("getblockstats", |params, ctx, _extensions| {
        let hash_or_height: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::get_block_stats(&ctx.chain_state, &hash_or_height).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    module.register_method("getchaintips", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::get_chain_tips(&ctx.chain_state))
    })?;

    module.register_method("getchaintxstats", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let nblocks: Option<u32> = seq.optional_next().unwrap_or(None);
        blockchain::get_chain_tx_stats(&ctx.chain_state, nblocks).map_err(|e| {
            ErrorObjectOwned::owned(-1, e, None::<()>)
        })
    })?;

    module.register_method("getmempoolancestors", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        blockchain::get_mempool_ancestors(&ctx.mempool, &txid, verbose).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    module.register_method("getmempooldescendants", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let verbose: bool = seq.optional_next().unwrap_or(Some(false)).unwrap_or(false);
        blockchain::get_mempool_descendants(&ctx.mempool, &txid, verbose).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    module.register_method("getmempoolentry", |params, ctx, _extensions| {
        let txid: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::get_mempool_entry(&ctx.mempool, &txid).map_err(|e| {
            ErrorObjectOwned::owned(-5, e, None::<()>)
        })
    })?;

    module.register_method("preciousblock", |params, _ctx, _extensions| {
        let hash: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        blockchain::precious_block(&hash).map_err(|e| {
            ErrorObjectOwned::owned(-1, e, None::<()>)
        })
    })?;

    module.register_method("verifychain", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let check_level: u32 = seq.optional_next().unwrap_or(Some(3)).unwrap_or(3);
        let nblocks: u32 = seq.optional_next().unwrap_or(Some(6)).unwrap_or(6);
        Ok::<_, ErrorObjectOwned>(blockchain::verify_chain(&ctx.chain_state, check_level, nblocks))
    })?;

    module.register_method("savemempool", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(blockchain::save_mempool())
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
        let hex_header: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        mining::submit_header(&ctx.chain_state, &hex_header).map_err(|e| {
            ErrorObjectOwned::owned(-1, e, None::<()>)
        })
    })?;

    // --- Transaction / Mempool RPCs ---

    module.register_method("sendrawtransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_tx: String = seq.next().map_err(|e| {
            crate::rpc::error::RpcError::new(-1, "rpc.input.parse", e.to_string())
                .with_suggestion("Pass the raw transaction as a hex string in the first argument.")
                .into_error_object()
        })?;
        rawtx::send_raw_transaction(&ctx.chain_state, &ctx.mempool, &hex_tx).map_err(
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

    module.register_method("createrawtransaction", |params, _ctx, _extensions| {
        let mut seq = params.sequence();
        let inputs: Vec<serde_json::Value> = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let outputs: serde_json::Value = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let locktime: Option<u32> = seq.optional_next().unwrap_or(None);
        rawtx::create_raw_transaction(&inputs, &outputs, locktime)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("combinerawtransaction", |params, _ctx, _extensions| {
        let hex_txs: Vec<String> = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        rawtx::combine_raw_transaction(&hex_txs)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decodescript", |params, _ctx, _extensions| {
        let hex_script: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        rawtx::decode_script(&hex_script)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("signrawtransactionwithkey", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let hex_tx: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let privkeys: Vec<String> = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
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
        let rawtxs: Vec<String> = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let mut results = Vec::new();
        for hex_tx in &rawtxs {
            let tx_bytes = hex::decode(hex_tx).map_err(|_| {
                ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>)
            })?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes).map_err(|_| {
                ErrorObjectOwned::owned(-22, "TX decode failed", None::<()>)
            })?;
            match ctx.mempool.test_accept(&tx, &ctx.chain_state, ctx.chain_state.script_verifier()) {
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
        let inputs: Vec<serde_json::Value> = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let outputs: serde_json::Value = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let locktime: Option<u32> = seq.optional_next().unwrap_or(None);
        psbt::create_psbt(&inputs, &outputs, locktime)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("decodepsbt", |params, _ctx, _extensions| {
        let psbt_b64: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::decode_psbt(&psbt_b64)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("analyzepsbt", |params, _ctx, _extensions| {
        let psbt_b64: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::analyze_psbt(&psbt_b64)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("combinepsbt", |params, _ctx, _extensions| {
        let psbt_b64s: Vec<String> = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::combine_psbt(&psbt_b64s)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("finalizepsbt", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let psbt_b64: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let extract: bool = seq.optional_next().unwrap_or(Some(true)).unwrap_or(true);
        let _ = &ctx; // suppress unused
        psbt::finalize_psbt(&psbt_b64, extract)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("converttopsbt", |params, _ctx, _extensions| {
        let hex_tx: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::convert_to_psbt(&hex_tx)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("joinpsbts", |params, _ctx, _extensions| {
        let psbt_b64s: Vec<String> = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::join_psbts(&psbt_b64s)
            .map_err(|(code, msg)| ErrorObjectOwned::owned(code, msg, None::<()>))
    })?;

    module.register_method("utxoupdatepsbt", |params, ctx, _extensions| {
        let psbt_b64: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        psbt::utxo_update_psbt(&ctx.chain_state, &psbt_b64)
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
        let mut seq = params.sequence();
        let conf_target: u32 = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        // Optional trailing `mode` string. Core-compat vocabulary
        // (ECONOMICAL/CONSERVATIVE/UNSET) is accepted and treated as
        // Historical; our own vocabulary is historical/mempool/blend.
        let mode_str: Option<String> = seq.optional_next().unwrap_or(None);
        let mode = EstimateMode::parse(mode_str.as_deref()).unwrap_or(EstimateMode::Historical);

        let unit = default_unit();
        let floor_sat_per_kvb = ctx.mempool.info().min_fee_rate.max(1_000);
        let historical = ctx.fee_estimator.estimate_fee(conf_target);
        let sat_per_kvb = resolve_feerate_sat_per_kvb(
            mode,
            conf_target,
            historical,
            floor_sat_per_kvb,
            || ctx.mempool.get_all_entries(),
        );
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

        let mut response = serde_json::json!({
            "targets": targets_obj,
            "histogram": histogram,
            "mode": mode.as_str(),
            "fallback": any_fallback,
            "mempool_weight": mempool_est.mempool_weight,
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

    module.register_method("getaddednodeinfo", |_params, ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!(ctx.peer_manager.get_added_node_info()))
    })?;

    module.register_method("getnettotals", |_params, _ctx, _extensions| {
        Ok::<_, ErrorObjectOwned>(serde_json::json!({
            "totalbytesrecv": 0,
            "totalbytessent": 0,
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
        let addr_str: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let command: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let addr: std::net::SocketAddr = addr_str.parse().map_err(|e: std::net::AddrParseError| {
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

    module.register_method("setnetworkactive", |params, _ctx, _extensions| {
        let _active: bool = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        // Stub: network is always active
        Ok::<_, ErrorObjectOwned>(serde_json::json!(true))
    })?;

    module.register_method("prioritisetransaction", |params, ctx, _extensions| {
        let mut seq = params.sequence();
        let txid_str: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let _dummy: Option<f64> = seq.optional_next().unwrap_or(None); // ignored (Core compat)
        let fee_delta: i64 = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let txid: bitcoin::Txid = txid_str.parse().map_err(|_| {
            ErrorObjectOwned::owned(-8, "Invalid txid", None::<()>)
        })?;
        let found = ctx.mempool.prioritise_transaction(&txid, fee_delta);
        Ok::<_, ErrorObjectOwned>(serde_json::json!(found))
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

    module.register_method("help", |_params, _ctx, _extensions| {
        let methods = vec![
            "addnode", "clearbanned", "decoderawtransaction", "decodescript",
            "disconnectnode", "estimatesmartfee", "generateblock", "generatetoaddress",
            "getaddednodeinfo", "getbestblockhash", "getblock", "getblockchaininfo",
            "getblockcount", "getblockhash", "getblockheader", "getblockstats",
            "getblocktemplate", "getchaintips", "getchaintxstats", "getconnectioncount",
            "getdifficulty", "getibdprogress", "getmempoolancestors", "getmempooldescendants",
            "getmempoolentry", "getmempoolinfo", "getmemoryinfo", "getmininginfo",
            "getnettotals", "getnetworkhashps", "getnetworkinfo", "getpeerinfo",
            "getrawmempool", "getrawtransaction", "getrpcinfo", "getsysteminfo", "gettxout",
            "gettxoutsetinfo", "help", "listbanned", "logging", "ping",
            "preciousblock", "prioritisetransaction",
            "savemempool", "sendrawtransaction", "setban",
            "signrawtransactionwithkey",
            "setnetworkactive", "stop", "submitblock", "submitheader",
            "testmempoolaccept", "uptime", "verifychain",
        ];
        Ok::<_, ErrorObjectOwned>(serde_json::json!(methods.join("\n")))
    })?;

    module.register_method("uptime", |_params, ctx, _extensions| {
        let uptime = ctx.start_time.elapsed().as_secs();
        Ok::<_, ErrorObjectOwned>(serde_json::json!(uptime))
    })?;

    module.register_method("getsysteminfo", |_params, ctx, _extensions| {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let rss_bytes = status.lines()
            .find(|l| l.starts_with("VmRSS:"))
            .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
            .unwrap_or(0) * 1024;
        let threads = status.lines()
            .find(|l| l.starts_with("Threads:"))
            .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok()))
            .unwrap_or(0);
        let uptime = ctx.start_time.elapsed().as_secs();
        let cache_dirty = ctx.chain_state.cache_dirty_count();
        let cache_clean = ctx.chain_state.cache_size().saturating_sub(cache_dirty as usize);
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
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| {
                        l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok())
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
        let address: String = params.one().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        Ok::<_, ErrorObjectOwned>(util::validate_address(&address))
    })?;

    // --- Long-polling RPCs ---

    module.register_async_method("waitforblockheight", |params, ctx, _extensions| async move {
        let mut seq = params.sequence();
        let target_height: u32 = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
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
    })?;

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
        let blockhash: String = seq.next().map_err(|e| {
            ErrorObjectOwned::owned(-1, e.to_string(), None::<()>)
        })?;
        let target_hash: bitcoin::BlockHash = blockhash.parse().map_err(|_| {
            ErrorObjectOwned::owned(-1, "Invalid block hash", None::<()>)
        })?;
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
        Ok::<_, ErrorObjectOwned>(
            serde_json::Value::String("satd stopping".to_string()),
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
