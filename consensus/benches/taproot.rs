//! Taproot key-path script verification: Rust vs C++.
//!
//! Workload: BIP341 wallet-vector key-path spending — 9 taproot inputs from
//! the single fully-signed test transaction. Exercises BIP341 sighash +
//! BIP340 Schnorr verify (key-path). Small sample but the only taproot
//! workload in-tree.
//!
//! Run: `cargo bench --bench taproot`

use criterion::{criterion_group, criterion_main, Criterion};

mod common;
use common::{load_bip341_keypath_cases, run_suite};

fn taproot_suite(c: &mut Criterion) {
    let workload = load_bip341_keypath_cases();
    run_suite(c, "taproot_suite", &workload);
}

criterion_group!(benches, taproot_suite);
criterion_main!(benches);
