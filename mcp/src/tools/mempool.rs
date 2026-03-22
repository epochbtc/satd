use crate::context::McpContext;
use node::rpc::{blockchain as rpc_bc, rawtx};
use serde_json::json;

/// Get mempool overview: size, bytes, fee rate histogram, and policy.
pub fn get_mempool_overview(ctx: &McpContext) -> String {
    let info = rawtx::get_mempool_info(&ctx.mempool);

    // Build fee histogram from verbose mempool entries
    let entries = ctx.mempool.get_all_entries();
    let mut buckets = [0u64; 7]; // 0-1, 1-2, 2-5, 5-10, 10-20, 20-50, 50+ sat/vB
    for (_txid, entry) in &entries {
        let fee_rate_sat_vb = if entry.weight > 0 {
            (entry.fee as f64 / (entry.weight as f64 / 4.0)) as u64
        } else {
            0
        };
        match fee_rate_sat_vb {
            0..=1 => buckets[0] += 1,
            2 => buckets[1] += 1,
            3..=5 => buckets[2] += 1,
            6..=10 => buckets[3] += 1,
            11..=20 => buckets[4] += 1,
            21..=50 => buckets[5] += 1,
            _ => buckets[6] += 1,
        }
    }

    let result = json!({
        "size": info["size"],
        "bytes": info["bytes"],
        "max_size": info["maxmempool"],
        "min_fee_rate": info["mempoolminfee"],
        "full_rbf": info["fullrbf"],
        "fee_histogram": {
            "0-1_sat_vb": buckets[0],
            "1-2_sat_vb": buckets[1],
            "2-5_sat_vb": buckets[2],
            "5-10_sat_vb": buckets[3],
            "10-20_sat_vb": buckets[4],
            "20-50_sat_vb": buckets[5],
            "50+_sat_vb": buckets[6],
        },
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// List mempool transactions with sorting and filtering.
pub fn list_mempool_transactions(
    ctx: &McpContext,
    sort_by: &str,
    limit: u32,
    min_fee_rate: Option<u64>,
) -> String {
    let mut entries: Vec<_> = ctx.mempool.get_all_entries();

    // Filter by min fee rate (sat/vB)
    if let Some(min_rate) = min_fee_rate {
        entries.retain(|(_txid, entry)| {
            let rate = if entry.weight > 0 {
                (entry.fee as f64 / (entry.weight as f64 / 4.0)) as u64
            } else {
                0
            };
            rate >= min_rate
        });
    }

    // Sort
    match sort_by {
        "time" => entries.sort_by(|a, b| b.1.time.cmp(&a.1.time)),
        "size" => entries.sort_by(|a, b| b.1.weight.cmp(&a.1.weight)),
        _ => {
            // fee_rate (default) — highest first
            entries.sort_by(|a, b| {
                let rate_a =
                    if a.1.weight > 0 { a.1.fee as f64 / (a.1.weight as f64 / 4.0) } else { 0.0 };
                let rate_b =
                    if b.1.weight > 0 { b.1.fee as f64 / (b.1.weight as f64 / 4.0) } else { 0.0 };
                rate_b.partial_cmp(&rate_a).unwrap_or(std::cmp::Ordering::Equal)
            });
        }
    }

    let limit = limit.min(100) as usize;
    let txs: Vec<_> = entries
        .iter()
        .take(limit)
        .map(|(txid, entry)| {
            let fee_rate = if entry.weight > 0 {
                entry.fee as f64 / (entry.weight as f64 / 4.0)
            } else {
                0.0
            };
            json!({
                "txid": txid.to_string(),
                "fee": entry.fee,
                "weight": entry.weight,
                "fee_rate_sat_vb": format!("{:.2}", fee_rate),
                "time": entry.time,
            })
        })
        .collect();

    let result = json!({
        "count": txs.len(),
        "total_mempool_size": entries.len(),
        "transactions": txs,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

/// Get detailed info about a single mempool transaction.
pub fn get_mempool_entry(ctx: &McpContext, txid: &str, include_relatives: bool) -> String {
    let entry = match rpc_bc::get_mempool_entry(&ctx.mempool, txid) {
        Ok(v) => v,
        Err(msg) => return json!({"error": msg}).to_string(),
    };

    if !include_relatives {
        return serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".to_string());
    }

    let ancestors = rpc_bc::get_mempool_ancestors(&ctx.mempool, txid, false)
        .unwrap_or(json!([]));
    let descendants = rpc_bc::get_mempool_descendants(&ctx.mempool, txid, false)
        .unwrap_or(json!([]));

    let result = json!({
        "entry": entry,
        "ancestors": ancestors,
        "descendants": descendants,
    });

    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}
