//! `mempool.*` method handlers.

use serde_json::Value;

use crate::error::JsonRpcError;
use crate::handlers::blockchain::fee_histogram_buckets;
use crate::state::ElectrumState;

/// `mempool.get_fee_histogram()` — returns an array of
/// `[fee_per_vbyte, total_vbytes]` pairs in descending fee-rate
/// order. Each row aggregates ~50_000 vbytes of mempool entries by
/// fee rate.
pub fn get_fee_histogram(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let entries = state.mempool.get_all_entries();

    // `MempoolEntry::fee_rate` is sat-per-1000-weight-units. vbyte =
    // weight / 4. So sat/vbyte = fee_rate / 250 (integer divide is
    // fine; clients use the histogram as a fee-rate hint, not for
    // exact accounting).
    let pairs: Vec<(u64, u64)> = entries
        .iter()
        .map(|(_txid, entry)| {
            let sats_per_vb = entry.fee_rate / 250;
            let vbytes = (entry.weight as u64) / 4;
            (sats_per_vb, vbytes)
        })
        .collect();

    let buckets = fee_histogram_buckets(&pairs);
    Ok(serde_json::to_value(&buckets).unwrap())
}
