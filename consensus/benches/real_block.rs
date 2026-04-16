//! Real mainnet block verification: Rust vs C++.
//!
//! Workload: every non-coinbase input in the block at height 300000 (2014,
//! pre-SegWit legacy era). Extracted from the synced satd node via
//! `consensus/bench-data/extract_block.py`. Real tx graphs, real scripts,
//! real sizes — the most honest approximation we have of IBD hot-path
//! workload using mainnet data.
//!
//! Run: `cargo bench --bench real_block`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{load_real_block, make_criterion, run_suite};

fn real_block_suite(c: &mut Criterion) {
    const FIXTURE: &str = include_str!("../bench-data/block_300000.json");
    let (height, workload) = load_real_block(FIXTURE);
    let name = format!("real_block_h{height}");
    run_suite(c, &name, &workload);
}

criterion_group! {
    name = benches;
    config = make_criterion();
    targets = real_block_suite
}
criterion_main!(benches);
