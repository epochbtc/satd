//! Process-wide counters for address-index metrics.
//!
//! Counters are bumped during emission (M2) and snapshotted by the
//! Prometheus `/metrics` endpoint (M6). Held as atomics in a `static`
//! so emission paths don't need to thread a stats handle through
//! `connect_block` / `disconnect_block` / `StoreBatch`.

use std::sync::atomic::{AtomicU64, Ordering};

static FUNDING_ROWS_TOTAL: AtomicU64 = AtomicU64::new(0);
static SPENDING_ROWS_TOTAL: AtomicU64 = AtomicU64::new(0);
static FUNDING_REMOVES_TOTAL: AtomicU64 = AtomicU64::new(0);
static SPENDING_REMOVES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increment the funding-rows counter by `n`. Called from emission
/// in `connect_block` (one per output that produced a funding row).
pub fn add_funding_rows(n: u64) {
    FUNDING_ROWS_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the spending-rows counter by `n`. Called from emission
/// in `connect_block` (one per non-coinbase input).
pub fn add_spending_rows(n: u64) {
    SPENDING_ROWS_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the funding-removes counter by `n`. Called during
/// `disconnect_block` (rows removed for a rolled-back block).
pub fn add_funding_removes(n: u64) {
    FUNDING_REMOVES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the spending-removes counter by `n`. Called during
/// `disconnect_block`.
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
