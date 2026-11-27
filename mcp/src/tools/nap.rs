//! The NAP aggregator's view: what coin holders have attested, and the
//! report that weighs it. Both answer an error unless the node runs with
//! `-napaggregator=1`.

use crate::context::McpContext;
use serde_json::{Value, json};

/// The most attestations one `list_nap_aggregate` page returns.
pub const MAX_PAGE: usize = 1000;
/// The page size when the caller gives none.
pub const DEFAULT_PAGE: usize = 100;

/// An RPC error's message as the MCP tools' `{"error": ...}` shape.
fn error(message: &str) -> String {
    json!({ "error": message }).to_string()
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string())
}

/// `getnapreport`: per key, each value's weight in coin, its share of the
/// supply, its concentration and age, at the tip. Computed off the async
/// threads, since the first report on a new tip judges the whole set.
pub async fn get_nap_report(ctx: &McpContext) -> String {
    if let Err(e) = node::rpc::nap::aggregator_enabled(ctx.nap_aggregator.as_deref()) {
        return error(e.message());
    }
    let puller = ctx.nap_aggregator.clone().expect("checked above");
    let chain = std::sync::Arc::clone(&ctx.chain_state);
    match tokio::task::spawn_blocking(move || node::rpc::nap::report(&puller, &chain)).await {
        Ok(Ok(report)) => pretty(&report),
        Ok(Err(e)) => error(e.message()),
        Err(e) => json!({ "error": format!("report task failed: {e}") }).to_string(),
    }
}

/// One page of the attestations that count, without the peer each came
/// from. `after` is the `next` of the previous page.
pub fn list_nap_aggregate(
    ctx: &McpContext,
    after_outpoint: Option<&str>,
    after_key: Option<&str>,
    limit: Option<u32>,
) -> String {
    let puller = match node::rpc::nap::aggregator_enabled(ctx.nap_aggregator.as_deref()) {
        Ok(p) => p,
        Err(e) => return error(e.message()),
    };
    let after = match (after_outpoint, after_key) {
        (None, None) => None,
        (Some(outpoint), Some(key)) => match node::rpc::nap::parse_outpoint(outpoint) {
            Ok(op) => Some((op, key.to_owned())),
            Err(e) => return error(e.message()),
        },
        _ => {
            return json!({
                "error": "after_outpoint and after_key go together: pass both, from the previous page's next, or neither"
            })
            .to_string();
        }
    };
    let limit = limit.map_or(DEFAULT_PAGE, |n| (n as usize).clamp(1, MAX_PAGE));
    pretty(&node::rpc::nap::aggregate_page(
        puller,
        ctx.chain_state.tip_height(),
        after.as_ref(),
        limit,
    ))
}
