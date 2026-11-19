//! P2P message decoding differential against a live Bitcoin Core (#1135):
//! the seed replay.
//!
//! Replays the seed cases of the `p2p_differential` fuzz target against a
//! regtest `bitcoind` and asserts satd and Core agree on every one. The
//! harness is `fuzz/src/p2p_diff.rs`, shared with the fuzz target, which
//! runs nightly; this test runs on pull requests that change the decoders
//! (`node/src/net/{payload,addrv2,v2transport}.rs`).
//!
//! The oracle is `$BITCOIND` if set (it must be the Core version pinned by
//! CORE_IMAGE in scripts/canary/PINS), else the `bitcoind` copied out of that
//! image with Docker:
//!
//! ```text
//! cargo test -p satd --test core_p2p_differential --features core-p2p-differential
//! ```
//!
//! `P2P_DIFF_WRITE_SEEDS=1` rewrites `fuzz/seeds/p2p_differential/` from the
//! generator.

#[path = "../../fuzz/src/p2p_diff.rs"]
mod p2p_diff;

use std::collections::BTreeMap;
use std::path::PathBuf;

use p2p_diff::{compare, satd_decode, seed_cases, CoreOracle, CoreVerdict, Outcome};

fn seed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds/p2p_differential")
}

/// Every seed is observable, and satd and Core agree on it. The run must
/// also have seen Core reject, ignore and accept, and report each kind of
/// decoded content: a harness that read every message as accepted, or never
/// saw a field, would pass the agreement check without testing anything.
#[test]
fn seed_cases_agree_with_core() {
    let mut core = CoreOracle::start().unwrap_or_else(|e| panic!("could not start the Bitcoin Core oracle: {e}"));
    let mut failures = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, case) in seed_cases() {
        let satd = satd_decode(&case);
        let verdict = core.verdict(&case).unwrap_or_else(|e| panic!("{name}: the Core oracle failed: {e}"));
        let outcome = compare(&case, &satd, &verdict);
        eprintln!("{name}: {outcome:?}");
        match &verdict {
            CoreVerdict::Accept(o) => {
                *seen.entry("accept").or_default() += 1;
                for (field, present) in [
                    ("version fields", o.version.is_some()),
                    ("entry count", o.count.is_some()),
                    ("tx ids", o.tx.is_some()),
                    ("block hash", o.block.is_some()),
                ] {
                    if present {
                        *seen.entry(field).or_default() += 1;
                    }
                }
            }
            CoreVerdict::Reject(_) => *seen.entry("reject").or_default() += 1,
            CoreVerdict::Ignore(_) => *seen.entry("ignore").or_default() += 1,
            CoreVerdict::Unobservable(_) => {}
        }
        match outcome {
            Outcome::Agree | Outcome::Allowed(_) => {}
            Outcome::Skipped(why) => failures.push(format!("{name}: Core gave no verdict ({why}); a seed must be observable")),
            Outcome::Diverge(d) => failures.push(format!("{name}: DIVERGENCE: {d}\n    case: {case}")),
        }
    }
    eprintln!("seen: {seen:?}");
    for kind in ["accept", "reject", "ignore", "version fields", "entry count", "tx ids", "block hash"] {
        if !seen.contains_key(kind) {
            failures.push(format!("no seed produced a Core '{kind}': the oracle is not observing what it claims to"));
        }
    }
    assert!(failures.is_empty(), "{} problem(s):\n{}", failures.len(), failures.join("\n"));
}

/// The committed seed corpus is the generator's output, so the nightly
/// fuzzer starts from the cases this test replays.
#[test]
fn committed_seeds_match_the_generator() {
    let dir = seed_dir();
    let want: BTreeMap<String, Vec<u8>> =
        seed_cases().into_iter().map(|(name, case)| (format!("{name}.bin"), case.to_bytes())).collect();
    for (name, case) in seed_cases() {
        assert_eq!(
            p2p_diff::Case::from_bytes(&case.to_bytes()).as_ref(),
            Some(&case),
            "{name}: to_bytes does not read back"
        );
    }
    if std::env::var_os("P2P_DIFF_WRITE_SEEDS").is_some() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove the old seeds");
        }
        std::fs::create_dir_all(&dir).expect("create the seed dir");
        for (name, bytes) in &want {
            std::fs::write(dir.join(name), bytes).expect("write a seed");
        }
        return;
    }
    let have: BTreeMap<String, Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| {
            let e = e.expect("dir entry");
            (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).expect("read a seed"))
        })
        .collect();
    assert!(
        have == want,
        "fuzz/seeds/p2p_differential/ is out of date; regenerate it with P2P_DIFF_WRITE_SEEDS=1 \
         cargo test -p satd --test core_p2p_differential --features core-p2p-differential \
         committed_seeds_match_the_generator"
    );
}
