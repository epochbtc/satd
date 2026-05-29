// Shared regtest harness for integration-test binaries.
//
// This module is `mod common;`-imported by `tests/regtest.rs` and
// `tests/e2e.rs`. Each integration-test binary compiles its own copy, so
// symbols unused by a given binary trigger dead-code warnings — silenced
// at the module level.

#![allow(dead_code)]

use base64::Engine;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Multiply a test timeout by `SATD_TEST_TIMEOUT_MULT` (default 1.0). CI
/// runs on a hosted runner whose wall-clock under load can push satd's
/// startup from <2s locally to >120s. Local dev keeps tight timeouts (so
/// real regressions surface quickly); CI sets the mult to ≥2.0 in
/// `.github/workflows/ci.yml` to absorb the runner's worst-case load.
///
/// Read once on first call and cached. The mult is clamped to (0, 100) so
/// a typo (`SATD_TEST_TIMEOUT_MULT=foo`) silently falls back to 1.0 rather
/// than disabling all timeouts.
pub fn test_timeout_mult() -> f64 {
    static MULT: OnceLock<f64> = OnceLock::new();
    *MULT.get_or_init(|| {
        std::env::var("SATD_TEST_TIMEOUT_MULT")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|m| *m > 0.0 && *m < 100.0)
            .unwrap_or(1.0)
    })
}

/// Construct a [`Duration`] for a test deadline, scaled by
/// [`test_timeout_mult`]. Use this for long startup / sync waits that have
/// flaked under CI load; do *not* use it for per-HTTP-request `reqwest`
/// timeouts, where a long timeout actually masks bugs.
pub fn test_timeout(secs: u64) -> Duration {
    Duration::from_secs_f64(secs as f64 * test_timeout_mult())
}

/// Like [`test_timeout`], but additionally scaled by `SATD_E2E_TIMEOUT_MULT`
/// when set. The unit-test suite uses [`test_timeout`] directly; the E2E
/// suite chains poll loops on top of the harness's own startup wait, so it
/// wants an independent knob. CI sets the unit-test mult to 2 and the E2E
/// mult to 3.
pub fn e2e_test_timeout(secs: u64) -> Duration {
    static MULT: OnceLock<f64> = OnceLock::new();
    let e2e = *MULT.get_or_init(|| {
        std::env::var("SATD_E2E_TIMEOUT_MULT")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|m| *m > 0.0 && *m < 100.0)
            .unwrap_or_else(test_timeout_mult)
    });
    Duration::from_secs_f64(secs as f64 * e2e)
}

pub struct TestNode {
    pub process: Child,
    pub datadir: PathBuf,
    pub rpcport: u16,
    /// P2P listen port — tracked so tests can connect raw P2P clients
    /// without re-parsing the command line. `None` when the caller passes
    /// an unusual --port format we can't extract.
    pub p2p_port: Option<u16>,
    pub cookie: String,
    /// Path where the spawned satd's stderr is captured. Tests can read
    /// this on failure to surface satd's internal logs in CI output.
    pub stderr_log: PathBuf,
}

impl TestNode {
    pub fn start(extra_args: &[&str]) -> Self {
        Self::start_inner(extra_args, &[], false)
    }

    /// Like `start` but also captures the spawned satd's stderr into a file
    /// in its datadir. The captured path is exposed as `stderr_log` so the
    /// caller can dump it on failure. Opt-in because heavy logging adds
    /// enough I/O on loaded CI runners to slow other tests.
    pub fn start_capturing_stderr(extra_args: &[&str]) -> Self {
        Self::start_inner(extra_args, &[], true)
    }

    /// Like `start` but also sets environment variables on the spawned
    /// satd process. Used by backfill tests to inject the per-block debug
    /// delay knob (`SATD_BACKFILL_DEBUG_DELAY_MS`) without polluting the
    /// parent process's environment, which would race across parallel
    /// tests.
    pub fn start_with_env(extra_args: &[&str], env: &[(&str, &str)]) -> Self {
        Self::start_inner(extra_args, env, false)
    }

    fn start_inner(extra_args: &[&str], env: &[(&str, &str)], capture_stderr: bool) -> Self {
        let rpcport = find_available_port();
        let datadir = std::env::temp_dir().join(format!("satd-test-{}", rpcport));
        let _ = std::fs::create_dir_all(&datadir);

        let satd_bin = env!("CARGO_BIN_EXE_satd");

        // Allocate a unique P2P port unless the caller already specified --port.
        let caller_port: Option<u16> = extra_args
            .iter()
            .find_map(|a| a.strip_prefix("--port="))
            .and_then(|s| s.parse().ok());
        let has_port = caller_port.is_some();
        let p2p_port = if has_port { 0 } else { find_available_port() };
        let tracked_p2p_port = caller_port.or(if has_port { None } else { Some(p2p_port) });

        let mut cmd = Command::new(satd_bin);
        cmd.arg("--regtest")
            .arg(format!("--datadir={}", datadir.display()))
            .arg(format!("--rpcport={}", rpcport));
        if !has_port {
            cmd.arg(format!("--port={}", p2p_port));
        }
        apply_listener_arg_defaults(&mut cmd, extra_args);
        for arg in extra_args {
            cmd.arg(arg);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }

        // Stderr capture is opt-in via the `capture_stderr` flag from
        // `start_capturing_stderr`. Default null matches the prior behavior
        // — always-on capture adds enough I/O on loaded CI runners to slow
        // other tests into their poll-until budgets.
        let stderr_log = datadir.join("satd.stderr");
        let stderr_target = if capture_stderr {
            let f = std::fs::File::create(&stderr_log)
                .expect("create satd stderr capture file");
            std::process::Stdio::from(f)
        } else {
            std::process::Stdio::null()
        };
        let process = cmd
            .stdout(std::process::Stdio::null())
            .stderr(stderr_target)
            .spawn()
            .expect("Failed to start satd");

        // Check if using user/pass auth (no cookie file expected)
        let uses_userpass = extra_args.iter().any(|a| a.starts_with("--rpcuser"));

        let (userpass_user, userpass_pass) = if uses_userpass {
            let user = extra_args
                .iter()
                .find_map(|a| a.strip_prefix("--rpcuser="))
                .unwrap_or("");
            let pass = extra_args
                .iter()
                .find_map(|a| a.strip_prefix("--rpcpassword="))
                .unwrap_or("");
            (user.to_string(), pass.to_string())
        } else {
            (String::new(), String::new())
        };
        // 120s deadline: locally satd is ready in <2s but the hosted CI
        // runner has needed >60s when many parallel workers contend for
        // the runner. Scaled by SATD_TEST_TIMEOUT_MULT.
        let deadline = Instant::now() + test_timeout(120);
        let cookie_path = datadir.join("regtest").join(".cookie");
        loop {
            let rpc_ready = if uses_userpass {
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap();
                client
                    .post(format!("http://127.0.0.1:{}/", rpcport))
                    .basic_auth(&userpass_user, Some(&userpass_pass))
                    .header("Content-Type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
                    .send()
                    .ok()
                    .and_then(|r| r.json::<serde_json::Value>().ok())
                    .is_some_and(|j| !j["result"]["chain"].is_null())
            } else if let Ok(cookie) = std::fs::read_to_string(&cookie_path) {
                let auth = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap();
                client
                    .post(format!("http://127.0.0.1:{}/", rpcport))
                    .header("Authorization", format!("Basic {}", auth))
                    .header("Content-Type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
                    .send()
                    .ok()
                    .and_then(|r| r.json::<serde_json::Value>().ok())
                    .is_some_and(|j| !j["result"]["chain"].is_null())
            } else {
                false
            };
            if rpc_ready {
                break;
            }
            if Instant::now() >= deadline {
                panic!("Timed out waiting for satd to start on port {}", rpcport);
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let cookie = if uses_userpass {
            String::new()
        } else {
            std::fs::read_to_string(&cookie_path).expect("Failed to read cookie file")
        };

        TestNode {
            process,
            datadir,
            rpcport,
            p2p_port: tracked_p2p_port,
            cookie,
            stderr_log,
        }
    }

    /// Start a node reusing an existing datadir (for restart/reindex tests).
    pub fn start_with_datadir(
        datadir: &std::path::Path,
        rpcport: u16,
        extra_args: &[&str],
    ) -> Self {
        Self::start_with_datadir_env(datadir, rpcport, extra_args, &[])
    }

    pub fn start_with_datadir_env(
        datadir: &std::path::Path,
        rpcport: u16,
        extra_args: &[&str],
        env: &[(&str, &str)],
    ) -> Self {
        let satd_bin = env!("CARGO_BIN_EXE_satd");

        let has_port = extra_args.iter().any(|a| a.starts_with("--port"));
        let p2p_port = if has_port { 0 } else { find_available_port() };

        let mut cmd = Command::new(satd_bin);
        cmd.arg("--regtest")
            .arg(format!("--datadir={}", datadir.display()))
            .arg(format!("--rpcport={}", rpcport));
        if !has_port {
            cmd.arg(format!("--port={}", p2p_port));
        }
        apply_listener_arg_defaults(&mut cmd, extra_args);
        for arg in extra_args {
            cmd.arg(arg);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }

        // Opt-in stderr capture: `SATD_TEST_STDERR_DIR` directs logs to a
        // stable path for debugging. Default null matches prior behavior;
        // see `start` for the I/O-cost rationale on CI.
        let env_dir = std::env::var("SATD_TEST_STDERR_DIR").ok();
        let (stderr_target, stderr_log) = match env_dir {
            Some(dir) => {
                let _ = std::fs::create_dir_all(&dir);
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0);
                let path = std::path::PathBuf::from(&dir)
                    .join(format!("satd-{}-{}.stderr.log", rpcport, stamp));
                let f = std::fs::File::create(&path).expect("create stderr log");
                (std::process::Stdio::from(f), path)
            }
            None => (std::process::Stdio::null(), PathBuf::new()),
        };
        let process = cmd
            .stdout(std::process::Stdio::null())
            .stderr(stderr_target)
            .spawn()
            .expect("Failed to start satd");

        let cookie_path = datadir.join("regtest").join(".cookie");
        let deadline = Instant::now() + test_timeout(120);
        loop {
            if let Ok(cookie) = std::fs::read_to_string(&cookie_path) {
                let auth = base64::engine::general_purpose::STANDARD.encode(cookie.trim());
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap();
                let rpc_ready = client
                    .post(format!("http://127.0.0.1:{}/", rpcport))
                    .header("Authorization", format!("Basic {}", auth))
                    .header("Content-Type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
                    .send()
                    .ok()
                    .and_then(|r| r.json::<serde_json::Value>().ok())
                    .is_some_and(|j| !j["result"]["chain"].is_null());
                if rpc_ready {
                    break;
                }
            }
            if Instant::now() >= deadline {
                panic!("Timed out waiting for satd to start on port {}", rpcport);
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let cookie = std::fs::read_to_string(&cookie_path).expect("Failed to read cookie file");

        TestNode {
            process,
            datadir: datadir.to_path_buf(),
            rpcport,
            p2p_port: None,
            cookie,
            stderr_log,
        }
    }

    pub fn rpc_call(&self, method: &str) -> Result<serde_json::Value, String> {
        self.rpc_call_with_params(method, vec![])
    }

    pub fn rpc_call_with_params(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let url = format!("http://127.0.0.1:{}/", self.rpcport);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": method,
            "params": params,
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let (user, pass) = self
            .cookie
            .split_once(':')
            .unwrap_or(("__cookie__", "none"));

        let response = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value = response.json().map_err(|e| e.to_string())?;
        Ok(json)
    }

    /// POST an exact request body string (verbatim, no shaping) and
    /// return the parsed JSON response. Used to exercise Bitcoin Core
    /// JSON-RPC compatibility: requests carrying `jsonrpc` 1.0 / 1.1 /
    /// no version member at all, which Core accepts and the canonical
    /// client libraries (NBitcoin, python-bitcoinrpc) emit.
    pub fn rpc_call_raw_body(&self, body: &str) -> Result<serde_json::Value, String> {
        let url = format!("http://127.0.0.1:{}/", self.rpcport);
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let (user, pass) = self
            .cookie
            .split_once(':')
            .unwrap_or(("__cookie__", "none"));
        let response = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| e.to_string())?;
        let json: serde_json::Value = response.json().map_err(|e| e.to_string())?;
        Ok(json)
    }

    pub fn rpc_call_raw_status(&self, method: &str, user: &str, pass: &str) -> u16 {
        let url = format!("http://127.0.0.1:{}/", self.rpcport);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": method,
            "params": [],
        });

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .expect("Failed to send request");

        response.status().as_u16()
    }

    pub fn stop(&mut self) {
        if !self.cookie.is_empty() {
            let _ = self.rpc_call("stop");
        }
        // Wait for process to exit, kill if it doesn't.
        let mut attempts = 0;
        loop {
            match self.process.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    attempts += 1;
                    if attempts > 30 {
                        let _ = self.process.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// Apply the listener-coupling defaults that both startup paths
/// share. Centralised so the restart-path (`start_with_datadir_env`)
/// stays consistent with the cold-start path (`start_with_env`) as
/// new listener flags are added — the kind of drift the L2 review
/// finding called out.
///
/// Rules:
/// - `--esplora=0` unless the caller passed any `--esplora*` flag.
///   The Esplora server binds a fixed port (default :3000) and would
///   conflict across parallel `TestNode` instances.
/// - `--txindex` when Esplora or Electrum is explicitly enabled and
///   the caller didn't otherwise set txindex. satd refuses to start
///   `--esplora=1 --txindex=0` (the tx + outspend / get_merkle
///   endpoints all require txindex), and an unhelpful refuse-to-start
///   is the most common footgun for new tests.
fn apply_listener_arg_defaults(cmd: &mut Command, extra_args: &[&str]) {
    let caller_sets_esplora = extra_args.iter().any(|a| a.starts_with("--esplora"));
    let esplora_explicitly_on = extra_args
        .iter()
        .any(|a| *a == "--esplora=1" || *a == "--esplora=true");
    if !caller_sets_esplora {
        cmd.arg("--esplora=0");
    }
    let caller_sets_txindex = extra_args.iter().any(|a| a.starts_with("--txindex"));
    let electrum_explicitly_on = extra_args
        .iter()
        .any(|a| *a == "--electrum=1" || *a == "--electrum=true");
    if (esplora_explicitly_on || electrum_explicitly_on) && !caller_sets_txindex {
        cmd.arg("--txindex");
    }
}

pub fn find_available_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    // Process-unique atomic counter from a high port range. Avoids the
    // TOCTOU race where bind(0) finds a port, releases it, and another
    // test grabs the same port before satd can bind.
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);
    let offset = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Base port derived from PID to avoid collisions across concurrent
    // test processes.
    let base = 30000 + (std::process::id() as u16 % 10000);
    let port = base + offset * 2; // *2 because each node may use rpc + p2p
    if TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok() {
        port
    } else {
        // Fallback: let OS pick. Rare.
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
        listener.local_addr().unwrap().port()
    }
}

/// Poll a condition until it returns true, or panic after timeout.
pub fn poll_until(check: impl Fn() -> bool, timeout: Duration, msg: &str) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("poll_until timed out after {:?}: {}", timeout, msg);
}

/// Poll a JSON-returning probe until `predicate` accepts the value, then
/// return that value. Panics with the last-seen value on timeout.
///
/// Used by E2E tests for "tx-in-mempool", "tx-confirmed", "notification
/// arrived" predicates — anything where the assertion depends on
/// background state convergence. Deadline derived from
/// [`e2e_test_timeout`].
pub fn poll_until_json<F, P>(probe: F, predicate: P, deadline_secs: u64) -> serde_json::Value
where
    F: Fn() -> serde_json::Value,
    P: Fn(&serde_json::Value) -> bool,
{
    let deadline = Instant::now() + e2e_test_timeout(deadline_secs);
    loop {
        let value = probe();
        if predicate(&value) {
            return value;
        }
        if Instant::now() >= deadline {
            panic!(
                "poll_until_json timed out after {}s (last value: {})",
                deadline_secs, value
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn get_rpc_u64(node: &TestNode, method: &str) -> Option<u64> {
    node.rpc_call(method)
        .ok()
        .and_then(|r| r["result"].as_u64())
}

pub fn get_rpc_str(node: &TestNode, method: &str) -> Option<String> {
    node.rpc_call(method)
        .ok()
        .and_then(|r| r["result"].as_str().map(|s| s.to_string()))
}
