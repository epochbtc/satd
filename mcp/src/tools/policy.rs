//! MCP tools for the transaction-filtering **policy observability** surface
//! (design §10, PR 7c) — thin wrappers over the node RPC handlers in
//! [`node::rpc::policy`]. These are the *only* MCP tools that expose the
//! quarantine class; the standard mempool tools stay acting-only (PR 7a).

use crate::context::McpContext;
use node::rpc::policy;

/// `getpolicyinfo` — ruleset metadata, per-rule match counters, quarantine totals.
pub fn get_policy_info(ctx: &McpContext) -> String {
    pretty(policy::get_policy_info(&ctx.mempool))
}

/// `getquarantineinfo` — per-rule rollup, confirmed-anyway, foregone fees.
pub fn get_quarantine_info(ctx: &McpContext) -> String {
    pretty(policy::get_quarantine_info(&ctx.mempool))
}

/// `listquarantine` — paged list of the quarantine class, optionally by rule.
pub fn list_quarantine(ctx: &McpContext, rule: Option<&str>, count: usize, skip: usize) -> String {
    pretty(policy::list_quarantine(&ctx.mempool, rule, count, skip))
}

/// `getquarantineentry` — detail for a single quarantined transaction.
pub fn get_quarantine_entry(ctx: &McpContext, txid: &str) -> String {
    match policy::get_quarantine_entry(&ctx.mempool, txid) {
        Ok(v) => pretty(v),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn pretty(v: serde_json::Value) -> String {
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_string())
}
