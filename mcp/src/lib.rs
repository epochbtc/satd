pub mod context;
pub mod tools;

pub use context::McpContext;

use context::McpContext as Ctx;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use rmcp::schemars;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

/// The MCP server for satd. Holds shared node state and a tool router.
pub struct SatdMcpServer {
    ctx: Arc<Ctx>,
    tool_router: ToolRouter<Self>,
}

// --- Parameter structs for tools that take arguments ---

#[derive(Deserialize, schemars::JsonSchema)]
struct GetBlockParams {
    #[schemars(description = "Block hash (hex) or height (number)")]
    identifier: String,
    #[schemars(description = "Output verbosity: 'summary' (header+txids, default), 'full' (decoded txs), 'raw' (hex)")]
    verbosity: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetBlockHeaderParams {
    #[schemars(description = "Block hash (hex) or height (number)")]
    identifier: String,
    #[schemars(description = "Return raw hex instead of JSON (default: false)")]
    raw: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetBlockStatsParams {
    #[schemars(description = "Block hash (hex) or height (number)")]
    identifier: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetChainInfoParams {
    #[schemars(description = "Number of blocks for tx rate calculation window (default: 30)")]
    window: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SearchBlockRangeParams {
    #[schemars(description = "Starting block height")]
    start_height: u32,
    #[schemars(description = "Ending block height (max 100 block range)")]
    end_height: u32,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetTransactionParams {
    #[schemars(description = "Transaction ID (hex)")]
    txid: String,
    #[schemars(description = "Block hash hint for faster lookup (optional)")]
    blockhash: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DecodeRawTransactionParams {
    #[schemars(description = "Hex-encoded raw transaction")]
    hex_tx: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DecodeScriptParams {
    #[schemars(description = "Hex-encoded script")]
    hex_script: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ListMempoolTxParams {
    #[schemars(description = "Sort by: 'fee_rate' (default), 'time', or 'size'")]
    sort_by: Option<String>,
    #[schemars(description = "Maximum entries to return (default: 25, max: 100)")]
    limit: Option<u32>,
    #[schemars(description = "Minimum fee rate filter in sat/vB")]
    min_fee_rate: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetMempoolEntryParams {
    #[schemars(description = "Transaction ID (hex)")]
    txid: String,
    #[schemars(description = "Include ancestor and descendant chains (default: false)")]
    include_relatives: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EstimateFeeParams {
    #[schemars(description = "Confirmation targets in blocks (default: [1, 3, 6, 12, 25])")]
    targets: Option<Vec<u32>>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetPeerInfoParams {
    #[schemars(description = "Compact summary mode (default: true)")]
    summary: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ManagePeerParams {
    #[schemars(description = "Action: 'add', 'disconnect', 'ban', or 'unban'")]
    action: String,
    #[schemars(description = "Peer address (host:port)")]
    address: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateTransactionParams {
    #[schemars(description = "Transaction inputs: [{\"txid\": \"...\", \"vout\": N}]")]
    inputs: Value,
    #[schemars(description = "Transaction outputs: {\"address\": amount_btc, ...}")]
    outputs: Value,
    #[schemars(description = "Transaction locktime (default: 0)")]
    locktime: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SignTransactionParams {
    #[schemars(description = "Hex-encoded raw transaction to sign")]
    hex_tx: String,
    #[schemars(description = "Array of private keys in WIF format")]
    private_keys: Vec<String>,
    #[schemars(description = "Previous transaction outputs for signing context")]
    prevtxs: Option<Value>,
    #[schemars(description = "Signature hash type (default: ALL)")]
    sighash: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SendTransactionParams {
    #[schemars(description = "Hex-encoded signed raw transaction")]
    hex_tx: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct PsbtWorkflowParams {
    #[schemars(description = "PSBT action: 'create', 'decode', 'analyze', 'combine', 'finalize', 'update', 'convert', 'join'")]
    action: String,
    #[schemars(description = "Action-specific parameters (psbt, inputs, outputs, psbts, extract, hex_tx, descriptors)")]
    params: Option<Value>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GenerateBlocksParams {
    #[schemars(description = "Number of blocks to generate")]
    count: u32,
    #[schemars(description = "Bitcoin address to receive mining rewards")]
    address: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetUtxoParams {
    #[schemars(description = "Transaction ID (hex)")]
    txid: String,
    #[schemars(description = "Output index")]
    vout: u32,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ValidateAddressParams {
    #[schemars(description = "Bitcoin address to validate")]
    address: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetMempoolEntriesBulkParams {
    #[schemars(description = "Array of transaction IDs (hex). Missing entries return as `null`.")]
    txids: Vec<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetMempoolHistoryParams {
    #[schemars(description = "Return snapshots from the last N seconds (default: 3600)")]
    since_secs: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct SubscribeMempoolSnapshotParams {
    #[schemars(description = "Maximum events to return (default: 50, max: 50)")]
    limit: Option<u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct GetReorgHistoryParams {
    #[schemars(description = "Return records from the last N seconds (default: 86400)")]
    since_secs: Option<u64>,
}

// --- Tool router: register all 27 tools ---

#[tool_router]
impl SatdMcpServer {
    // === Node Status ===

    #[tool(description = "Get comprehensive node status including chain height, sync progress, mempool summary, peer count, difficulty, and uptime. This is the first tool to call when assessing node health.")]
    fn get_node_status(&self) -> String {
        tools::node_status::get_node_status(&self.ctx)
    }

    #[tool(description = "Get system resource usage: memory (RSS), UTXO cache statistics, and database info.")]
    fn get_system_info(&self) -> String {
        tools::node_status::get_system_info(&self.ctx)
    }

    // === Blockchain Queries ===

    #[tool(description = "Retrieve a block by hash or height. Verbosity: 'summary' (header + txid list, default), 'full' (decoded transactions), 'raw' (hex-encoded block).")]
    fn get_block(&self, Parameters(p): Parameters<GetBlockParams>) -> String {
        tools::blockchain::get_block(&self.ctx, &p.identifier, p.verbosity.as_deref().unwrap_or("summary"))
    }

    #[tool(description = "Retrieve a block header by hash or height.")]
    fn get_block_header(&self, Parameters(p): Parameters<GetBlockHeaderParams>) -> String {
        tools::blockchain::get_block_header(&self.ctx, &p.identifier, p.raw.unwrap_or(false))
    }

    #[tool(description = "Get detailed statistics for a block: fee rates, sizes, transaction counts, UTXO changes, SegWit usage.")]
    fn get_block_stats(&self, Parameters(p): Parameters<GetBlockStatsParams>) -> String {
        tools::blockchain::get_block_stats(&self.ctx, &p.identifier)
    }

    #[tool(description = "Get chain analysis: active/fork tips, transaction rate over a block window, and current difficulty.")]
    fn get_chain_info(&self, Parameters(p): Parameters<GetChainInfoParams>) -> String {
        tools::blockchain::get_chain_info(&self.ctx, p.window.unwrap_or(30))
    }

    #[tool(description = "Retrieve headers for a contiguous range of blocks. Maximum 100 blocks per call. Useful for analyzing chain segments.")]
    fn search_block_range(&self, Parameters(p): Parameters<SearchBlockRangeParams>) -> String {
        tools::blockchain::search_block_range(&self.ctx, p.start_height, p.end_height)
    }

    // === Transaction Queries ===

    #[tool(description = "Look up a transaction by txid. Searches both the blockchain and mempool. Optionally provide a block hash hint for faster lookup.")]
    fn get_transaction(&self, Parameters(p): Parameters<GetTransactionParams>) -> String {
        tools::transactions::get_transaction(&self.ctx, &p.txid, p.blockhash.as_deref())
    }

    #[tool(description = "Decode a hex-encoded raw transaction into JSON with all inputs, outputs, and witness data.")]
    fn decode_raw_transaction(&self, Parameters(p): Parameters<DecodeRawTransactionParams>) -> String {
        tools::transactions::decode_raw_transaction(&p.hex_tx)
    }

    #[tool(description = "Decode a hex-encoded script into human-readable opcodes, type classification, and addresses.")]
    fn decode_script(&self, Parameters(p): Parameters<DecodeScriptParams>) -> String {
        tools::transactions::decode_script(&p.hex_script)
    }

    // === Mempool ===

    #[tool(description = "Get mempool overview: size, byte usage, fee rate distribution histogram (buckets: 0-1, 1-2, 2-5, 5-10, 10-20, 20-50, 50+ sat/vB), and policy settings.")]
    fn get_mempool_overview(&self) -> String {
        tools::mempool::get_mempool_overview(&self.ctx)
    }

    #[tool(description = "List mempool transactions with sorting and filtering. Returns txid, fee, fee rate, size, and time for each entry.")]
    fn list_mempool_transactions(&self, Parameters(p): Parameters<ListMempoolTxParams>) -> String {
        tools::mempool::list_mempool_transactions(
            &self.ctx,
            p.sort_by.as_deref().unwrap_or("fee_rate"),
            p.limit.unwrap_or(25),
            p.min_fee_rate,
        )
    }

    #[tool(description = "Get detailed info about a mempool transaction, optionally including its ancestor and descendant dependency chains.")]
    fn get_mempool_entry(&self, Parameters(p): Parameters<GetMempoolEntryParams>) -> String {
        tools::mempool::get_mempool_entry(&self.ctx, &p.txid, p.include_relatives.unwrap_or(false))
    }

    // === Fee Estimation ===

    #[tool(description = "Estimate fee rates for multiple confirmation targets at once. Returns rates in both BTC/kvB and sat/vB. Default targets: 1, 3, 6, 12, 25 blocks.")]
    fn estimate_fee(&self, Parameters(p): Parameters<EstimateFeeParams>) -> String {
        let targets = p.targets.unwrap_or_else(|| vec![1, 3, 6, 12, 25]);
        tools::fees::estimate_fee(&self.ctx, &targets)
    }

    // === Network/Peers ===

    #[tool(description = "Get information about connected peers. Summary mode (default) gives a compact overview; full mode includes all protocol details.")]
    fn get_peer_info(&self, Parameters(p): Parameters<GetPeerInfoParams>) -> String {
        tools::network::get_peer_info(&self.ctx, p.summary.unwrap_or(true))
    }

    #[tool(description = "Manage peer connections: disconnect, ban, or unban a peer by address (host:port).")]
    fn manage_peer(&self, Parameters(p): Parameters<ManagePeerParams>) -> String {
        tools::network::manage_peer(&self.ctx, &p.action, &p.address)
    }

    #[tool(description = "List all currently banned peers with ban timestamps and reasons.")]
    fn get_ban_list(&self) -> String {
        tools::network::get_ban_list(&self.ctx)
    }

    // === Transaction Construction ===

    #[tool(description = "Create an unsigned raw transaction from specified inputs and outputs. Amounts in BTC.")]
    fn create_transaction(&self, Parameters(p): Parameters<CreateTransactionParams>) -> String {
        tools::construction::create_transaction(&p.inputs, &p.outputs, p.locktime)
    }

    #[tool(description = "Sign a raw transaction with provided private keys (WIF format). Returns the signed hex and completion status.")]
    fn sign_transaction(&self, Parameters(p): Parameters<SignTransactionParams>) -> String {
        tools::construction::sign_transaction(
            &self.ctx,
            &p.hex_tx,
            &p.private_keys,
            p.prevtxs.as_ref(),
            p.sighash.as_deref(),
        )
    }

    #[tool(description = "Broadcast a signed raw transaction to the network. Returns the transaction ID on success.")]
    fn send_transaction(&self, Parameters(p): Parameters<SendTransactionParams>) -> String {
        tools::construction::send_transaction(&self.ctx, &p.hex_tx)
    }

    #[tool(description = "Perform PSBT (Partially Signed Bitcoin Transaction) operations. Actions: 'create' (new PSBT from inputs/outputs), 'decode' (show PSBT contents), 'analyze' (check what signatures are needed), 'combine' (merge partial signatures), 'finalize' (complete for broadcast), 'update' (add UTXO info), 'convert' (raw tx to PSBT), 'join' (merge independent PSBTs).")]
    fn psbt_workflow(&self, Parameters(p): Parameters<PsbtWorkflowParams>) -> String {
        tools::construction::psbt_workflow(
            &self.ctx,
            &p.action,
            p.params.as_ref().unwrap_or(&Value::Object(Default::default())),
        )
    }

    // === Mining ===

    #[tool(description = "Get current mining information: difficulty, network hashrate, chain height.")]
    fn get_mining_info(&self) -> String {
        tools::mining::get_mining_info(&self.ctx)
    }

    #[tool(description = "Mine blocks to an address (regtest only). Returns array of new block hashes.")]
    fn generate_blocks(&self, Parameters(p): Parameters<GenerateBlocksParams>) -> String {
        tools::mining::generate_blocks(&self.ctx, p.count, &p.address)
    }

    #[tool(description = "Get a block template for mining. Returns template with transactions, previous block hash, target, and coinbase details.")]
    fn get_block_template(&self) -> String {
        tools::mining::get_block_template(&self.ctx)
    }

    // === UTXO ===

    #[tool(description = "Look up a single unspent transaction output by txid and output index. Returns value, script, confirmations, and coinbase status. Returns null if spent.")]
    fn get_utxo(&self, Parameters(p): Parameters<GetUtxoParams>) -> String {
        tools::utxo::get_utxo(&self.ctx, &p.txid, p.vout)
    }

    #[tool(description = "Get UTXO set statistics: total unspent outputs, total value, and best block.")]
    fn get_utxo_set_stats(&self) -> String {
        tools::utxo::get_utxo_set_stats(&self.ctx)
    }

    // === Address ===

    #[tool(description = "Validate a Bitcoin address and return its type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR), script hex, and witness info.")]
    fn validate_address(&self, Parameters(p): Parameters<ValidateAddressParams>) -> String {
        tools::address::validate_address(&p.address)
    }

    // === Operator Ergonomics (PRs #59-#67) ===

    #[tool(description = "Return detailed info for multiple mempool transactions at once. Missing entries are returned as null in the response map.")]
    fn get_mempool_entries_bulk(
        &self,
        Parameters(p): Parameters<GetMempoolEntriesBulkParams>,
    ) -> String {
        tools::mempool::get_mempool_entries_bulk(&self.ctx, &p.txids)
    }

    #[tool(description = "Return time-windowed mempool snapshots (size, bytes, fee-rate histogram). Useful for tracking mempool state over ~40 minutes of history.")]
    fn get_mempool_history(&self, Parameters(p): Parameters<GetMempoolHistoryParams>) -> String {
        tools::mempool::get_mempool_history(&self.ctx, p.since_secs.unwrap_or(3_600))
    }

    #[tool(description = "Return the most recent mempool events (enter, leave_confirmed, leave_evicted, leave_replaced). Snapshot-style; for live streaming use the subscribemempool JSON-RPC subscription.")]
    fn subscribe_mempool_snapshot(
        &self,
        Parameters(p): Parameters<SubscribeMempoolSnapshotParams>,
    ) -> String {
        tools::mempool::subscribe_mempool_snapshot(
            &self.ctx,
            p.limit.unwrap_or(50) as usize,
        )
    }

    #[tool(description = "Return the effective node configuration post-merge of CLI flags, profile, and config file. Passwords and cookies are redacted.")]
    fn get_config(&self) -> String {
        tools::ergonomics::get_config(&self.ctx)
    }

    #[tool(description = "Return persisted reorg events — depth, fork height, disconnected/reconnected block hashes. Default window: 24 hours.")]
    fn get_reorg_history(&self, Parameters(p): Parameters<GetReorgHistoryParams>) -> String {
        tools::ergonomics::get_reorg_history(&self.ctx, p.since_secs.unwrap_or(86_400))
    }

    #[tool(description = "Render the current Prometheus metrics snapshot as text — useful for ad-hoc inspection without scraping the /metrics HTTP endpoint.")]
    fn get_metrics_snapshot(&self) -> String {
        tools::ergonomics::get_metrics_snapshot(&self.ctx)
    }

    #[tool(description = "Liveness check: returns 'ok' plus uptime if the process is running. Mirrors the /healthz HTTP endpoint.")]
    fn get_health(&self) -> String {
        tools::ergonomics::get_health(&self.ctx)
    }

    #[tool(description = "Readiness check: returns true once the node is within a few blocks of the header tip. Mirrors the /readyz HTTP endpoint.")]
    fn get_readiness(&self) -> String {
        tools::ergonomics::get_readiness(&self.ctx)
    }
}

// --- ServerHandler implementation ---

#[tool_handler]
impl ServerHandler for SatdMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("satd-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "MCP server for satd, a Bitcoin Core-compatible node. \
                 Provides tools for querying blockchain state, mempool, peers, fees, \
                 constructing transactions (including PSBTs), and managing the node.",
            )
    }
}

impl SatdMcpServer {
    /// Create a new MCP server with the given context.
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self {
            ctx,
            tool_router: Self::tool_router(),
        }
    }

    /// List all registered tools (for testing / introspection).
    pub fn list_tools_from_router(&self) -> Vec<rmcp::model::Tool> {
        self.tool_router.list_all()
    }
}

// --- Public API ---

/// Start the MCP server over stdio (stdin/stdout).
pub async fn serve_stdio(
    ctx: Arc<McpContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = SatdMcpServer::new(ctx);

    tracing::info!("MCP stdio server starting");
    let service = server.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    tracing::info!("MCP stdio server stopped");
    Ok(())
}

/// Start the MCP server over Streamable HTTP (also serves legacy SSE clients).
pub async fn serve_http(
    ctx: Arc<McpContext>,
    bind_addr: std::net::SocketAddr,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };
    use tokio_util::sync::CancellationToken;

    let cancel = CancellationToken::new();
    let mut config = StreamableHttpServerConfig::default();
    config.stateful_mode = true;
    config.cancellation_token = cancel.clone();

    let session_manager = std::sync::Arc::new(LocalSessionManager::default());

    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(SatdMcpServer::new(ctx.clone()))
        },
        session_manager,
        config,
    );

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "MCP HTTP server listening");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let svc = mcp_service.clone();
                        tokio::spawn(async move {
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let svc = hyper::service::service_fn(move |req| {
                                let svc = svc.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(svc.handle(req).await)
                                }
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .with_upgrades()
                                .await
                            {
                                tracing::debug!("MCP HTTP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("MCP HTTP accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.wait_for(|v| *v) => {
                tracing::info!("MCP HTTP server shutting down");
                cancel.cancel();
                break;
            }
        }
    }

    Ok(())
}
