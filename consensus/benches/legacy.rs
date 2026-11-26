//! Legacy (pre-SegWit, no P2SH) script verification: Rust vs C++.
//!
//! Workload: script_tests.json entries with no P2SH/WITNESS/TAPROOT flags.
//! Isolates the bare script interpreter + legacy sighash.
//!
//! Run: `cargo bench --bench legacy`

use criterion::{Criterion, criterion_group, criterion_main};

mod common;
use common::{Category, filter_category, load_script_tests, make_criterion, run_suite};

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
