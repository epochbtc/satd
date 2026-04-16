//! SegWit v0 script verification: Rust vs C++.
//!
//! Workload: script_tests.json entries with VERIFY_WITNESS but not TAPROOT.
//! Exercises P2WPKH / P2WSH / P2SH-P2WPKH, which means BIP143 sighash is on
//! the hot path — the piece that most likely dominates Rust's per-verify cost.
//!
//! Run: `cargo bench --bench segwit_v0`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{filter_category, load_script_tests, run_suite, Category};

fn segwit_v0_suite(c: &mut Criterion) {
    let workload = filter_category(load_script_tests(), Category::SegwitV0);
    run_suite(c, "segwit_v0_suite", &workload);
}

criterion_group!(benches, segwit_v0_suite);
criterion_main!(benches);
