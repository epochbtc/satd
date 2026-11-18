//! The startup file-descriptor budget (#1294), against a satd started under
//! a low `RLIMIT_NOFILE`: Core's `AppInitParameterInteraction` lowers
//! `-maxconnections` to fit, or refuses to start when even its own needs do
//! not fit.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// satd's needs with `--esplora=0 --maxopenfiles=100` on regtest: the base
/// (151), RocksDB's table files (100, set, so fixed), eight addnode peers,
/// one P2P listener and the two default RPC loopback listeners of 1 + 100
/// each.
const REQUIRED: u64 = 151 + 100 + 8 + 1 + 2 * 101;

/// The arguments the tests above `REQUIRED` describe.
const FIXED: &[&str] = &["--esplora=0", "--maxopenfiles=100"];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Start satd with the soft and hard `RLIMIT_NOFILE` set to `soft` / `hard`
/// and return its output once it logs the connection budget or exits.
fn start_under(soft: u64, hard: u64, extra: &[&str]) -> (Option<i32>, String) {
    let mut args = FIXED.to_vec();
    args.extend_from_slice(extra);
    start_with(soft, hard, &args)
}

/// [`start_under`] with only `args` after the datadir and ports.
fn start_with(soft: u64, hard: u64, args: &[&str]) -> (Option<i32>, String) {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let datadir = std::env::temp_dir().join(format!("satd-fd-budget-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).unwrap();
    let log = datadir.join("out.log");
    let out = std::fs::File::create(&log).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_satd"));
    cmd.arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", free_port()))
        .arg(format!("--port={}", free_port()))
        .arg("--loglevel=info")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out));
    // SAFETY: setrlimit is async-signal-safe and touches only the child.
    unsafe {
        cmd.pre_exec(move || {
            let lim = libc::rlimit { rlim_cur: soft as libc::rlim_t, rlim_max: hard as libc::rlim_t };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn satd");
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut text = String::new();
    let status = loop {
        text.clear();
        std::fs::File::open(&log).unwrap().read_to_string(&mut text).unwrap();
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if text.contains("Using at most") || Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    text.clear();
    std::fs::File::open(&log).unwrap().read_to_string(&mut text).unwrap();
    let _ = std::fs::remove_dir_all(&datadir);
    (status, text)
}

/// The soft limit is raised to the hard limit (Core's
/// `RaiseFileDescriptorLimit`), and the 200 default connections are lowered
/// to what is left of it, with Core's warning.
#[test]
fn a_low_limit_lowers_maxconnections() {
    let hard = REQUIRED + 50;
    let (status, out) = start_under(256, hard, &[]);
    assert_eq!(status, None, "satd exited early:\n{out}");
    assert!(
        out.contains("Reducing -maxconnections from 200 to 50, because of system limitations."),
        "no reduction warning:\n{out}"
    );
    assert!(
        out.contains(&format!("Using at most 50 automatic connections ({hard} file descriptors available)")),
        "no budget line:\n{out}"
    );
}

/// With enough descriptors, `-maxconnections` is taken as given, and the
/// soft limit is raised only as far as satd asks: its needs plus the 200
/// peers, not the hard limit.
#[test]
fn enough_descriptors_keep_maxconnections() {
    let (status, out) = start_under(256, REQUIRED + 500, &[]);
    assert_eq!(status, None, "satd exited early:\n{out}");
    assert!(!out.contains("Reducing -maxconnections"), "unexpected reduction:\n{out}");
    let asked = REQUIRED + 200;
    assert!(
        out.contains(&format!("Using at most 200 automatic connections ({asked} file descriptors available)")),
        "no budget line:\n{out}"
    );
}

/// Below satd's own needs, startup fails with Core's error.
#[test]
fn below_the_minimum_refuses_to_start() {
    let hard = REQUIRED - 1;
    let (status, out) = start_under(hard, hard, &[]);
    assert_eq!(status, Some(1), "satd did not refuse:\n{out}");
    assert!(
        out.contains(&format!("Error: Not enough file descriptors available. {hard} available, {REQUIRED} required.")),
        "no refusal message:\n{out}"
    );
}

/// A default config under the common shell limit of 1,024 starts: the caps
/// left at their defaults, RocksDB's 2048 table files and Esplora's 1024
/// sockets, shrink to share what is left once the hard minimum (491) and
/// the 200 peers are met, one line each, and `-maxconnections` keeps 200.
#[test]
fn a_default_node_starts_under_1024_with_its_default_caps_shrunk() {
    let esplora = format!("--esplorabind=127.0.0.1:{}", free_port());
    let (status, out) = start_with(1024, 1024, &[esplora.as_str()]);
    assert_eq!(status, None, "satd exited early:\n{out}");
    for line in [
        "Reducing -maxopenfiles from 2048 to 288, because of system limitations.",
        "Reducing -esploramaxsockets from 1024 to 172, because of system limitations.",
        "Using at most 200 automatic connections (1024 file descriptors available)",
    ] {
        assert!(out.contains(line), "no {line:?}:\n{out}");
    }
    assert!(!out.contains("Reducing -maxconnections"), "{out}");
}

/// The same limit with Esplora's socket cap set to its default value: a
/// cap the operator set stays in the hard minimum, so the node refuses.
#[test]
fn an_explicit_cap_still_refuses_under_1024() {
    let esplora = format!("--esplorabind=127.0.0.1:{}", free_port());
    let (status, out) = start_with(1024, 1024, &[esplora.as_str(), "--esploramaxsockets=1024"]);
    assert_eq!(status, Some(1), "satd did not refuse:\n{out}");
    let required = 151 + 8 + 1 + 2 * 101 + 1 + 64 + 1024;
    assert!(
        out.contains(&format!("Error: Not enough file descriptors available. 1024 available, {required} required.")),
        "no refusal message:\n{out}"
    );
}
