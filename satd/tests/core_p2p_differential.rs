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
use std::process::Command;
use std::time::{Duration, Instant};

use p2p_diff::{CoreOracle, CoreVerdict, Outcome, compare, satd_decode, seed_cases};

fn seed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds/p2p_differential")
}

/// Every seed is observable, and satd and Core agree on it. The run must
/// also have seen Core reject, ignore and accept, and report each kind of
/// decoded content: a harness that read every message as accepted, or never
/// saw a field, would pass the agreement check without testing anything.
#[test]
fn seed_cases_agree_with_core() {
    let mut core = CoreOracle::start()
        .unwrap_or_else(|e| panic!("could not start the Bitcoin Core oracle: {e}"));
    let mut failures = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, case) in seed_cases() {
        let satd = satd_decode(&case);
        let verdict = core
            .verdict(&case)
            .unwrap_or_else(|e| panic!("{name}: the Core oracle failed: {e}"));
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
            Outcome::Skipped(why) => failures.push(format!(
                "{name}: Core gave no verdict ({why}); a seed must be observable"
            )),
            Outcome::Diverge(d) => {
                failures.push(format!("{name}: DIVERGENCE: {d}\n    case: {case}"))
            }
        }
    }
    eprintln!("seen: {seen:?}");
    for kind in [
        "accept",
        "reject",
        "ignore",
        "version fields",
        "entry count",
        "tx ids",
        "block hash",
    ] {
        if !seen.contains_key(kind) {
            failures.push(format!(
                "no seed produced a Core '{kind}': the oracle is not observing what it claims to"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} problem(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The committed seed corpus is the generator's output, so the nightly
/// fuzzer starts from the cases this test replays.
#[test]
fn committed_seeds_match_the_generator() {
    let dir = seed_dir();
    let want: BTreeMap<String, Vec<u8>> = seed_cases()
        .into_iter()
        .map(|(name, case)| (format!("{name}.bin"), case.to_bytes()))
        .collect();
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
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).expect("read a seed"),
            )
        })
        .collect();
    assert!(
        have == want,
        "fuzz/seeds/p2p_differential/ is out of date; regenerate it with P2P_DIFF_WRITE_SEEDS=1 \
         cargo test -p satd --test core_p2p_differential --features core-p2p-differential \
         committed_seeds_match_the_generator"
    );
}

/// Set in a child run of this test binary to pick what the child does.
const CHILD: &str = "P2P_DIFF_TEST_CHILD";

/// Run one test of this binary in a child process, with `CHILD` set.
fn run_child(test: &str, mode: &str, envs: &[(&str, &std::ffi::OsStr)]) -> std::process::Output {
    let mut cmd = Command::new(std::env::current_exe().expect("test binary"));
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, mode);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run the child test")
}

/// The fuzz target keeps the oracle in a static and libFuzzer leaves by
/// `exit`, so the oracle is never dropped. `bitcoind` must stop, and its
/// work dir go, when the process ends anyway.
#[test]
fn bitcoind_does_not_outlive_its_process() {
    if std::env::var_os(CHILD).is_some_and(|m| m == "leak") {
        let core = CoreOracle::start()
            .unwrap_or_else(|e| panic!("could not start the Bitcoin Core oracle: {e}"));
        println!("WORK={}", core.work_dir().display());
        std::mem::forget(core);
        std::process::exit(0);
    }
    let out = run_child("bitcoind_does_not_outlive_its_process", "leak", &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let work = stdout
        .lines()
        .find_map(|l| l.split_once("WORK=").map(|(_, w)| w.trim()))
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("the child printed no work dir: {stdout}"));
    // The shim removes the work dir only after bitcoind has exited.
    let deadline = Instant::now() + Duration::from_secs(60);
    while work.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !work.exists(),
        "{} outlived the process that started it: bitcoind is still running",
        work.display()
    );
}

/// A start that fails before bitcoind runs leaves no work dir behind.
#[test]
fn a_failed_start_leaves_no_work_dir() {
    if std::env::var_os(CHILD).is_some_and(|m| m == "bad-bitcoind") {
        match CoreOracle::start() {
            Ok(_) => panic!("started an oracle on a binary that is not bitcoind"),
            Err(e) => println!("refused: {e}"),
        }
        std::process::exit(0);
    }
    let scratch = tempfile::tempdir().expect("tempdir");
    let out = run_child(
        "a_failed_start_leaves_no_work_dir",
        "bad-bitcoind",
        &[
            ("BITCOIND", "/bin/true".as_ref()),
            ("P2P_DIFF_TMPDIR", scratch.path().as_os_str()),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("refused: "),
        "child: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let left: Vec<_> = std::fs::read_dir(scratch.path())
        .expect("read scratch")
        .map(|e| e.expect("entry").path())
        .collect();
    assert!(left.is_empty(), "a failed start left {left:?}");
}
