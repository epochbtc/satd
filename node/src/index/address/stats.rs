//! Process-wide counters for address-index metrics.
//!
//! Counters are bumped at the commit boundary in
//! `RocksDbStore::write_batch_mode` after the underlying RocksDB
//! `write_opt` succeeds, and snapshotted by the Prometheus `/metrics`
//! endpoint (M6). Counting at commit (rather than at emission inside
//! `connect_block`) means a block whose batch fails validation or
//! whose commit fails does not move the counters — the values
//! correspond to rows actually persisted.
//!
//! Held as atomics in a `static` so the storage path doesn't need to
//! thread a stats handle through.

use std::sync::atomic::{AtomicU64, Ordering};

static FUNDING_ROWS_TOTAL: AtomicU64 = AtomicU64::new(0);
static SPENDING_ROWS_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUNDING_REMOVES_TOTAL: AtomicU64 = AtomicU64::new(0);
static SPENDING_REMOVES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increment the committed funding-rows counter by `n`.
pub fn add_funding_rows(n: u64) {
    FUNDING_ROWS_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the committed spending-rows counter by `n`.
pub fn add_spending_rows(n: u64) {
    SPENDING_ROWS_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the committed funding-removes counter by `n`.
pub fn add_funding_removes(n: u64) {
    FUNDING_REMOVES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the committed spending-removes counter by `n`.
pub fn add_spending_removes(n: u64) {
    SPENDING_REMOVES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Snapshot all counters for `/metrics` rendering.
pub fn snapshot() -> Snapshot {
    Snapshot {
        funding_rows: FUNDING_ROWS_TOTAL.load(Ordering::Relaxed),
        spending_rows: SPENDING_ROWS_TOTAL.load(Ordering::Relaxed),
        funding_removes: FUNDING_REMOVES_TOTAL.load(Ordering::Relaxed),
        spending_removes: SPENDING_REMOVES_TOTAL.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub funding_rows: u64,
    pub spending_rows: u64,
    pub funding_removes: u64,
    pub spending_removes: u64,
}
