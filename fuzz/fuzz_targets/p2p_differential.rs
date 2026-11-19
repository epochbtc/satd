//! P2P message decoding differential against a live Bitcoin Core (#1135).
//!
//! libFuzzer mutates a message (transport, type, payload; see
//! `Case::from_bytes`). satd decodes it in-process with the readers its
//! connection loops use, so coverage follows satd's decoders, and a resident
//! regtest `bitcoind` is sent the same message over a v1 or v2 connection.
//! A divergence is a different verdict (accept, reject, ignore), or a
//! different decoded field where Core exposes one. The comparison and its
//! limits are described in `fuzz/src/p2p_diff.rs`.
//!
//! The oracle is `$BITCOIND` if set (it must be the Core version pinned by
//! CORE_IMAGE in scripts/canary/PINS), else the `bitcoind` copied out of that
//! image with Docker. Run it as the nightly job does:
//!
//! ```text
//! BITCOIND=/path/to/bitcoind-32.1 SECONDS_PER_TARGET=120 \
//!     scripts/fuzz/run-standalone-targets.sh p2p_differential
//! ```
//!
//! On a divergence the target writes `divergence-<hash>.txt` next to
//! libFuzzer's reproducer and panics. The nightly job files those under the
//! `p2p-decode-divergence` label.

#![no_main]

use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use satd_fuzz::p2p_diff::{compare, satd_decode, Case, CoreOracle, Outcome, TypeName};

static ORACLE: OnceLock<Mutex<CoreOracle>> = OnceLock::new();

fn harness_failure(what: &str) -> ! {
    eprintln!("=== P2P-DIFFERENTIAL FUZZ HARNESS FAILURE ===");
    eprintln!("{what}");
    eprintln!("This is a harness/infrastructure failure, NOT a decoding divergence.");
    std::process::exit(2);
}

/// Where libFuzzer writes reproducers (`-artifact_prefix=`, which cargo-fuzz
/// passes), so the divergence report lands beside its input.
fn artifact_dir() -> std::path::PathBuf {
    std::env::args()
        .find_map(|a| a.strip_prefix("-artifact_prefix=").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn report(data: &[u8], case: &Case, what: &str) {
    use bitcoin::hashes::{sha256, Hash};
    let id = sha256::Hash::hash(data).to_string();
    let path = artifact_dir().join(format!("divergence-{}.txt", &id[..16]));
    let body = format!(
        "P2P decoding divergence between satd and Bitcoin Core {}\n\n{what}\n\ncase: {case}\ninput (hex): {}\n",
        satd_fuzz::p2p_diff::core_version(),
        hex::encode(data)
    );
    if let Err(e) = std::fs::write(&path, &body) {
        eprintln!("could not write {}: {e}", path.display());
    }
    eprintln!("{body}");
}

fuzz_target!(
    init: {
        match CoreOracle::start() {
            Ok(o) => {
                let _ = ORACLE.set(Mutex::new(o));
            }
            Err(e) => harness_failure(&format!("could not start the Bitcoin Core oracle: {e}")),
        }
    },
    |data: &[u8]| {
        let Some(case) = Case::from_bytes(data) else { return };
        if case.type_name() == TypeName::OtherKnown {
            return;
        }
        let satd = satd_decode(&case);
        let mut oracle = ORACLE.get().expect("oracle started in init").lock().unwrap_or_else(|e| e.into_inner());
        let core = match oracle.verdict(&case) {
            Ok(v) => v,
            // One retry on fresh connections before calling the harness
            // broken: a connection Core closed is not a verdict.
            Err(first) => match oracle.verdict(&case) {
                Ok(v) => v,
                Err(e) => harness_failure(&format!("Core oracle failed twice: {first}; then {e}")),
            },
        };
        let outcome = compare(&case, &satd, &core);
        oracle.note(&outcome);
        let n = oracle.stats.compared;
        if n > 0 && n.is_multiple_of(5_000) && !matches!(outcome, Outcome::Skipped(_)) {
            eprintln!("p2p-differential: {n} verdicts compared against Bitcoin Core; {:?}", oracle.stats);
        }
        if let Outcome::Diverge(what) = outcome {
            report(data, &case, &format!("{what}\nsatd: {satd:?}\nCore: {core:?}"));
            panic!("P2P DECODE DIVERGENCE: {what}");
        }
    }
);
