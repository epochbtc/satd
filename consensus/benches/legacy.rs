//! Legacy (pre-SegWit) script verification: Rust consensus vs bitcoinconsensus.
//!
//! Workload: script_tests.json entries that do not set VERIFY_WITNESS or
//! VERIFY_TAPROOT, and that both engines accept. This is P2PK / P2PKH /
//! OP_CHECKMULTISIG / P2SH territory — the script interpreter loop and
//! legacy sighash, no BIP143 or BIP341 machinery.
//!
//! Run with: `cargo bench --bench legacy`

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

mod common;
use common::{load_script_tests, verify_cpp, verify_rust, Category, WorkloadCase};

fn load_legacy_workload() -> Vec<WorkloadCase> {
    load_script_tests()
        .into_iter()
        .filter(|c| matches!(common::categorize(c.flags), Category::Legacy))
        .collect()
}

fn legacy_suite(c: &mut Criterion) {
    let workload = load_legacy_workload();
    eprintln!("legacy workload: {} cases", workload.len());

    let mut group = c.benchmark_group("legacy_suite");
    group.throughput(Throughput::Elements(workload.len() as u64));

    group.bench_function("rust", |b| {
        b.iter(|| {
            for case in &workload {
                let _ = std::hint::black_box(verify_rust(case));
            }
        })
    });

    group.bench_function("cpp", |b| {
        b.iter(|| {
            for case in &workload {
                let _ = std::hint::black_box(verify_cpp(case));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, legacy_suite);
criterion_main!(benches);
