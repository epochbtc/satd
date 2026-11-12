//! The `--interop-node` wrapper's own failure paths, with a stand-in for
//! satd. The live runs against Bitcoin Core are the nightly interop job.

use std::process::Command;

use serde_json::Value;

fn interop_node(satd: &str, options: &str) -> (i32, Vec<Value>, String) {
    let datadir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_satd-conformance-harness"))
        .args(["--interop-node", "--satd", satd, "--network", "regtest", "--datadir"])
        .arg(datadir.path())
        .args(["--peer", "127.0.0.1:1", "--stall-timeout", "5", "--options", options])
        .args(["--stop-at", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"])
        .output()
        .unwrap();
    let lines = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every stdout line is a protocol line"))
        .collect();
    (out.status.code().unwrap(), lines, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_node_that_exits_at_start_is_started_again_then_reported() {
    let (status, lines, stderr) = interop_node("/bin/false", "{}");
    assert_eq!(status, 1);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["event"], "error");
    assert!(lines[0]["message"].as_str().unwrap().contains("before its RPC answered"), "{lines:?}");
    assert_eq!(stderr.matches("starting satd again").count(), 2, "{stderr}");
}

#[test]
fn an_option_satd_lacks_ends_the_run_before_satd_starts() {
    let (status, lines, _) = interop_node("/nonexistent/satd", r#"{"test":["addrman"]}"#);
    assert_eq!(status, 1);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["message"], "satd has no -test=addrman option");
}
