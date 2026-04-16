//! Legacy (pre-SegWit, no P2SH) script verification: Rust vs C++.
//!
//! Workload: script_tests.json entries with no P2SH/WITNESS/TAPROOT flags.
//! Isolates the bare script interpreter + legacy sighash.
//!
//! Run: `cargo bench --bench legacy`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{filter_category, load_script_tests, make_criterion, run_suite, Category};

fn legacy_suite(c: &mut Criterion) {
    let workload = filter_category(load_script_tests(), Category::Legacy);
    run_suite(c, "legacy_suite", &workload);
}

criterion_group! {
    name = benches;
    config = make_criterion();
    targets = legacy_suite
}
criterion_main!(benches);
