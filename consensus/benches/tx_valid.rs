//! Whole-transaction verification from Bitcoin Core's tx_valid.json.
//!
//! Each entry becomes one WorkloadCase per input (multi-input txs expand
//! into N cases). This is the closest in-tree approximation of real IBD
//! workload: full transactions with arbitrary input/output structures.
//!
//! Run: `cargo bench --bench tx_valid`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{load_tx_valid_cases, make_criterion, run_suite};

fn tx_valid_suite(c: &mut Criterion) {
    let workload = load_tx_valid_cases();
    run_suite(c, "tx_valid_suite", &workload);
}

criterion_group! {
    name = benches;
    config = make_criterion();
    targets = tx_valid_suite
}
criterion_main!(benches);
