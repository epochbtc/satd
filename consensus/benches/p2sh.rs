//! P2SH-wrapped script verification: Rust vs C++.
//!
//! Workload: script_tests.json entries with P2SH set, no WITNESS/TAPROOT.
//! Isolates the P2SH redeem-script unwrap path on top of the legacy interpreter.
//!
//! Run: `cargo bench --bench p2sh`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{filter_category, load_script_tests, make_criterion, run_suite, Category};

fn p2sh_suite(c: &mut Criterion) {
    let workload = filter_category(load_script_tests(), Category::P2sh);
    run_suite(c, "p2sh_suite", &workload);
}

criterion_group! {
    name = benches;
    config = make_criterion();
    targets = p2sh_suite
}
criterion_main!(benches);
