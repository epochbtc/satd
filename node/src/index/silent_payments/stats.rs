//! Process-wide counters for silent-payment-index metrics.
//!
//! Bumped at the commit boundary in `RocksDbStore::write_batch_mode`
//! after the RocksDB write succeeds — counting at commit (not at
//! emission in `connect_block`) means a batch that fails validation or
//! commit does not move the counters; the values correspond to rows
//! actually persisted. Held as atomics in a `static` so the storage
//! path needn't thread a stats handle through. Mirrors
//! `crate::index::address::stats`.

use std::sync::atomic::{AtomicU64, Ordering};

static ROWS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROW_REMOVES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Increment the committed tweak-rows counter by `n` (one per block).
pub fn add_rows(n: u64) {
    ROWS_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Increment the committed tweak-row-removes counter by `n`.
pub fn add_row_removes(n: u64) {
    ROW_REMOVES_TOTAL.fetch_add(n, Ordering::Relaxed);
}

/// Snapshot the counters for `/metrics` rendering.
pub fn snapshot() -> Snapshot {
    Snapshot {
        rows: ROWS_TOTAL.load(Ordering::Relaxed),
        row_removes: ROW_REMOVES_TOTAL.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub rows: u64,
    pub row_removes: u64,
}
