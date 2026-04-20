//! MCP wrappers for the ergonomics surface landed in PRs #59–#67.
//!
//! Each function calls into the same in-process functions the JSON-RPC
//! and HTTP handlers use so MCP clients see identical data without a
//! second network hop. No business logic lives here — these are thin
//! adapters that JSON-stringify for the rmcp transport.

use crate::context::McpContext;
use node::metrics::MetricsContext;
use serde_json::json;

/// Return the effective post-merge configuration (secrets redacted).
pub fn get_config(ctx: &McpContext) -> String {
    serde_json::to_string_pretty(&ctx.effective_config).unwrap_or_else(|_| "{}".to_string())
}

/// Return recent reorg records, optionally filtered by `since_secs`.
/// Default window: 24 h.
pub fn get_reorg_history(ctx: &McpContext, since_secs: u64) -> String {
    let records = match ctx.chain_state.reorg_log() {
        Some(log) => log.history(since_secs),
        None => Vec::new(),
    };
    let result = json!({
        "since_secs": since_secs,
        "records": records,
    });
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Return the current Prometheus-text `/metrics` payload.
///
/// MCP can't stream scrapes the way Prometheus does — this is a
/// one-shot render for ad-hoc operator inspection ("what does the
/// current metrics snapshot look like?"). Wraps it in JSON so rmcp's
/// text transport handles it cleanly.
pub fn get_metrics_snapshot(ctx: &McpContext) -> String {
    let metrics_ctx = MetricsContext {
        chain_state: ctx.chain_state.clone(),
        mempool: ctx.mempool.clone(),
        peer_manager: ctx.peer_manager.clone(),
        network: ctx.network,
        start_time: ctx.start_time,
        version: env!("CARGO_PKG_VERSION"),
    };
    let body = metrics_ctx.render_prometheus();
    let result = json!({
        "format": "prometheus-text",
        "body": body,
    });
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Liveness signal. Always healthy if the MCP server itself is
/// running — matches the `/healthz` HTTP endpoint semantics.
pub fn get_health(ctx: &McpContext) -> String {
    let uptime = ctx.start_time.elapsed().as_secs();
    let result = json!({
        "status": "ok",
        "uptime_seconds": uptime,
    });
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Readiness signal. Green when the node is close enough to the
/// header tip to serve queries — matches the `/readyz` HTTP endpoint.
pub fn get_readiness(ctx: &McpContext) -> String {
    let metrics_ctx = MetricsContext {
        chain_state: ctx.chain_state.clone(),
        mempool: ctx.mempool.clone(),
        peer_manager: ctx.peer_manager.clone(),
        network: ctx.network,
        start_time: ctx.start_time,
        version: env!("CARGO_PKG_VERSION"),
    };
    let (ready, reason) = match metrics_ctx.is_ready() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };
    let result = json!({
        "ready": ready,
        "reason": reason,
        "tip_height": ctx.chain_state.tip_height(),
        "headers_tip_height": ctx.chain_state.headers_tip_height(),
    });
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
