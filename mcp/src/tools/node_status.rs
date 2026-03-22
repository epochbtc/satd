use crate::context::McpContext;
use node::rpc::{blockchain, network, rawtx};
use serde_json::json;

/// Get comprehensive node status: chain state, sync progress, mempool summary, peers, and uptime.
pub fn get_node_status(ctx: &McpContext) -> String {
    let chain_info = blockchain::get_blockchain_info(&ctx.chain_state);
    let mempool_info = rawtx::get_mempool_info(&ctx.mempool);
    let net_info = network::get_network_info(&ctx.peer_manager);
    let uptime = ctx.start_time.elapsed().as_secs();

    let ibd_progress = ctx.peer_manager.get_ibd_progress();

    let result = json!({
        "chain": chain_info["chain"],
        "height": chain_info["blocks"],
        "headers": chain_info["headers"],
        "best_block_hash": chain_info["bestblockhash"],
        "difficulty": chain_info["difficulty"],
        "time": chain_info["time"],
        "verification_progress": chain_info["verificationprogress"],
        "initial_block_download": chain_info["initialblockdownload"],
        "chainwork": chain_info["chainwork"],
        "mempool": {
            "size": mempool_info["size"],
            "bytes": mempool_info["bytes"],
            "min_fee_rate": mempool_info["mempoolminfee"],
        },
        "peers": {
            "connections": net_info["connections"],
            "subversion": net_info["subversion"],
        },
        "ibd_progress": ibd_progress,
        "uptime_seconds": uptime,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Get system resource usage: memory, UTXO cache stats, and database info.
pub fn get_system_info(ctx: &McpContext) -> String {
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
        })
        .unwrap_or(0)
        * 1024;

    let uptime = ctx.start_time.elapsed().as_secs();

    let result = json!({
        "memory_rss_bytes": rss,
        "uptime_seconds": uptime,
        "utxo_set": {
            "coin_count": ctx.chain_state.coin_count(),
        },
        "chain": {
            "height": ctx.chain_state.tip_height(),
            "tip": ctx.chain_state.tip_hash().to_string(),
        },
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
