// Shared regtest harness for integration-test binaries.
//
// This module is `mod common;`-imported by `tests/regtest.rs` and
// `tests/e2e.rs`. Each integration-test binary compiles its own copy, so
// symbols unused by a given binary trigger dead-code warnings — silenced
// at the module level.

#![allow(dead_code)]

/// A real Bitcoin Core node (Docker) for the Phase C live differential
/// harness. Each integration-test binary compiles its own copy of `common`;
/// binaries that don't use it just carry the (allow-dead-code) module.
pub mod core_node;

/// Real gRPC + WS/SSE clients for the streaming Consumption-API E2E suite
/// (`tests/streaming.rs`). Compiled into every integration binary that
/// `mod common`-imports this; the `regtest`/`e2e` binaries don't use them,
/// hence the module-level `#![allow(dead_code)]` inside each.
pub mod grpc_client;
pub mod ws_client;

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
        // A satd that never answers RPC has almost always *crashed* on startup
        // (a port race, a datadir lock, a panic) rather than merely being slow:
        // the 120s×MULT deadline is far longer than even a heavily contended CI
        // start. The old code polled such a dead process until the full deadline
        // and then panicked with an opaque "timed out". Instead, watch for early
        // process exit and retry the whole spawn on a fresh port/datadir — which
        // auto-recovers the transient startup races that previously required a
        // manual CI re-run. A genuinely broken binary still fails, after
        // exhausting the attempts, with the real exit status.
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_failure = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_start_once(extra_args, env, capture_stderr) {
                Ok(node) => return node,
                Err(reason) => {
                    last_failure = format!("attempt {attempt}/{MAX_ATTEMPTS}: {reason}");
                    if attempt < MAX_ATTEMPTS {
                        eprintln!(
                            "satd startup failed ({last_failure}); retrying on a fresh port"
                        );
                    }
                }
            }
        }
        panic!("satd failed to start after {MAX_ATTEMPTS} attempts; last failure: {last_failure}");
    }

    /// One spawn-and-wait attempt. Returns `Err` (after reaping the process) if
    /// satd exits before its RPC comes up or doesn't answer within the deadline,
    /// so the caller can retry on a fresh port. Each attempt allocates its own
    /// port/datadir, so a retry never reuses a contended port or a locked dir.
    fn try_start_once(
        extra_args: &[&str],
        env: &[(&str, &str)],
        capture_stderr: bool,
    ) -> Result<Self, String> {
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
        let mut process = cmd
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
        // Captured from the readiness probe below so we never re-read the
        // cookie file after the loop — that second read used to race the file
        // momentarily vanishing under parallel-startup contention and panic.
        let mut captured_cookie = String::new();
        loop {
            // Fail fast if satd already exited — no point polling a corpse until
            // the deadline. `try_wait` reaps the child when it reports `Some`.
            if let Ok(Some(status)) = process.try_wait() {
                return Err(format!(
                    "satd (port {rpcport}) exited with {status} before its RPC came up"
                ));
            }
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
                let ready = client
                    .post(format!("http://127.0.0.1:{}/", rpcport))
                    .header("Authorization", format!("Basic {}", auth))
                    .header("Content-Type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
                    .send()
                    .ok()
                    .and_then(|r| r.json::<serde_json::Value>().ok())
                    .is_some_and(|j| !j["result"]["chain"].is_null());
                // Keep the exact cookie we just authenticated with rather than
                // re-reading the file after the loop (which can race).
                if ready {
                    captured_cookie = cookie;
                }
                ready
            } else {
                false
            };
            if rpc_ready {
                break;
            }
            if Instant::now() >= deadline {
                // Kill and reap the hung process so it can't leak across a retry.
                let _ = process.kill();
                let _ = process.wait();
                return Err(format!(
                    "satd (port {rpcport}) did not answer RPC within the startup deadline"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // `captured_cookie` is the value the readiness probe authenticated
        // with (empty for the userpass path, which doesn't use a cookie).
        let cookie = captured_cookie;

        Ok(TestNode {
            process,
            datadir,
            rpcport,
            p2p_port: tracked_p2p_port,
            cookie,
            stderr_log,
        })
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

    /// POST an exact body string and report the transport outcome:
    /// `Some(status)` if the server returned an HTTP response, or `None`
    /// if the connection was dropped mid-send. Both are valid ways for
    /// the server to reject an oversized body early (when it rejects on
    /// `Content-Length` without draining the upload, the client's
    /// in-flight write breaks before it can read the response) — what
    /// must never happen is a hang or OOM. Used to assert the
    /// request-size cap in the JSON-RPC compat shim.
    pub fn rpc_post_raw_outcome(&self, body: &str) -> Option<u16> {
        let url = format!("http://127.0.0.1:{}/", self.rpcport);
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let (user, pass) = self
            .cookie
            .split_once(':')
            .unwrap_or(("__cookie__", "none"));
        match client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
        {
            Ok(resp) => Some(resp.status().as_u16()),
            // Connection dropped mid-send (e.g. broken pipe) — the server
            // rejected without draining. Treated as a rejection, not a
            // hang. The caller proves liveness with a follow-up request.
            Err(_) => None,
        }
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

// ---------------------------------------------------------------------------
// Streaming Consumption-API E2E harness
// ---------------------------------------------------------------------------

/// A `TestNode` plus the runtime-bound ports of its streaming listeners,
/// discovered from `getserverstatus` after startup. `None` means the listener
/// was not requested (or didn't bind). Reach through `.node` for RPC / mining.
pub struct StreamingNode {
    pub node: TestNode,
    pub grpc_port: Option<u16>,
    pub ws_port: Option<u16>,
}

impl StreamingNode {
    /// Boot a regtest `satd` with the gRPC + streamws listeners enabled on
    /// OS-assigned ports, then poll `getserverstatus` until each requested
    /// listener reports a concrete bound address. Binding `:0` and reading the
    /// port back avoids the fixed-port TOCTOU that a `find_available_port` +
    /// explicit-bind would carry.
    ///
    /// Both listeners are enabled by default; pass an explicit
    /// `--events-grpc-bind` / `--streamws` in `extra_args` to override (e.g. to
    /// enable only one, or to bind with auth). The caller's flags win.
    pub fn start(extra_args: &[&str]) -> Self {
        Self::start_with_env(extra_args, &[])
    }

    /// Like [`Self::start`] but also sets environment variables on the spawned
    /// `satd` — used by the Lagged / replay-ring tests to shrink the broadcast
    /// buffer via `SATD_EVENT_BROADCAST_CAPACITY`.
    pub fn start_with_env(extra_args: &[&str], env: &[(&str, &str)]) -> Self {
        // Detect ONLY the explicit bind flags (`--events-grpc-bind` /
        // `--streamws`), not their siblings like `--streamws-auth` or
        // `--streamws-max-conns` — otherwise a caller that tunes a streamws
        // knob would suppress the auto-added bind and the listener would never
        // come up.
        let is_bind = |a: &&str, flag: &str| **a == *flag || a.starts_with(&format!("{flag}="));
        let want_grpc = !extra_args.iter().any(|a| is_bind(a, "--events-grpc-bind"));
        let want_ws = !extra_args.iter().any(|a| is_bind(a, "--streamws"));
        let mut args: Vec<String> = Vec::new();
        if want_grpc {
            args.push("--events-grpc-bind=127.0.0.1:0".to_string());
        }
        if want_ws {
            args.push("--streamws=127.0.0.1:0".to_string());
        }
        for a in extra_args {
            args.push((*a).to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let node = TestNode::start_with_env(&arg_refs, env);

        // The caller may have supplied explicit binds; in that case still poll
        // for them (they're requested) — only a fully-absent listener flag with
        // a `=0`/disabled value is skipped, which we approximate by requesting
        // whatever the merged args ask for.
        let req_grpc = args
            .iter()
            .any(|a| a == "--events-grpc-bind" || a.starts_with("--events-grpc-bind="));
        let req_ws = args
            .iter()
            .any(|a| a == "--streamws" || a.starts_with("--streamws="));
        let (grpc_port, ws_port) = poll_streaming_ports(&node, req_grpc, req_ws);
        StreamingNode {
            node,
            grpc_port,
            ws_port,
        }
    }

    pub fn grpc_port(&self) -> u16 {
        self.grpc_port.expect("gRPC listener not bound")
    }

    pub fn ws_port(&self) -> u16 {
        self.ws_port.expect("streamws listener not bound")
    }

    /// Stop and re-spawn `satd` on the same datadir + RPC port (preserving the
    /// durable chain), re-enabling the streaming listeners on fresh
    /// OS-assigned ports and re-discovering them. Used by the `instance_id`
    /// epoch test: the per-process publisher nonce changes across a restart
    /// while the durable confirmed chain (and its cursor replay) survives.
    /// Blocking — call via `spawn_blocking` from an async test.
    pub fn restart(&mut self) {
        self.node.stop();
        let args = ["--events-grpc-bind=127.0.0.1:0", "--streamws=127.0.0.1:0"];
        let mut fresh =
            TestNode::start_with_datadir(&self.node.datadir, self.node.rpcport, &args);
        std::mem::swap(&mut self.node.process, &mut fresh.process);
        self.node.cookie = std::mem::take(&mut fresh.cookie);
        self.node.p2p_port = fresh.p2p_port;
        self.node.stderr_log = std::mem::take(&mut fresh.stderr_log);
        // Blank the husk's datadir so its Drop can't delete the shared dir.
        fresh.datadir = PathBuf::new();
        let (g, w) = poll_streaming_ports(&self.node, true, true);
        self.grpc_port = g;
        self.ws_port = w;
    }
}

/// Poll `getserverstatus` until the requested streaming listeners report a
/// concrete `{"bind": "host:port"}`, returning the parsed ports. satd starts
/// the JSON-RPC server before the optional listeners bind, so a fresh
/// `getblockchaininfo`-readiness does not imply the streaming ports are up.
fn poll_streaming_ports(
    node: &TestNode,
    want_grpc: bool,
    want_ws: bool,
) -> (Option<u16>, Option<u16>) {
    let parse_port = |v: &serde_json::Value| -> Option<u16> {
        v.get("bind")
            .and_then(|b| b.as_str())
            .and_then(|s| s.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok())
    };
    let deadline = Instant::now() + test_timeout(60);
    loop {
        if let Ok(status) = node.rpc_call("getserverstatus") {
            let res = &status["result"];
            let grpc = parse_port(&res["events_grpc"]);
            let ws = parse_port(&res["streamws"]);
            let grpc_ready = !want_grpc || grpc.is_some();
            let ws_ready = !want_ws || ws.is_some();
            if grpc_ready && ws_ready {
                return (grpc, ws);
            }
        }
        if Instant::now() >= deadline {
            panic!(
                "streaming listeners not up within deadline (want_grpc={want_grpc}, want_ws={want_ws})"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A blocking JSON-RPC caller. Implemented by both [`TestNode`] (sync tests,
/// borrows the node) and [`RpcHandle`] (async tests, moves into
/// `spawn_blocking`), so the funding helpers below work from either context
/// without changing the existing `e2e.rs` call sites.
pub trait BlockingRpc {
    fn rpc(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String>;
}

impl BlockingRpc for TestNode {
    fn rpc(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        self.rpc_call_with_params(method, params)
    }
}

impl BlockingRpc for RpcHandle {
    fn rpc(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        self.call(method, params)
    }
}

/// A `Send + 'static` RPC caller cloned from a [`TestNode`]. The streaming
/// suite drives mining / tx submission from `tokio::task::spawn_blocking`
/// while holding an async event stream — and `reqwest::blocking` panics if
/// called directly on a tokio worker thread ("Cannot start a runtime from
/// within a runtime"). `RpcHandle` carries only the port + cookie, so it
/// moves cleanly into a blocking task.
#[derive(Clone)]
pub struct RpcHandle {
    rpcport: u16,
    cookie: String,
}

impl RpcHandle {
    pub fn call(
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
        let (user, pass) = self.cookie.split_once(':').unwrap_or(("__cookie__", "none"));
        let response = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        response.json().map_err(|e| e.to_string())
    }

    /// Mine `n` blocks to `addr`, returning the list of block hashes.
    pub fn mine(&self, n: u32, addr: &str) -> Vec<String> {
        let res = self
            .call(
                "generatetoaddress",
                vec![serde_json::json!(n), serde_json::json!(addr)],
            )
            .expect("generatetoaddress");
        res["result"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Current best-block height.
    pub fn block_count(&self) -> u64 {
        self.call("getblockcount", vec![])
            .expect("getblockcount")["result"]
            .as_u64()
            .expect("height")
    }

    /// Broadcast a raw transaction hex, returning the txid.
    pub fn send_raw_tx(&self, raw_hex: &str) -> String {
        let res = self
            .call("sendrawtransaction", vec![serde_json::json!(raw_hex)])
            .expect("sendrawtransaction");
        res["result"]
            .as_str()
            .unwrap_or_else(|| panic!("sendrawtransaction error: {res}"))
            .to_string()
    }
}

impl TestNode {
    /// A `Send + 'static` RPC handle for use from `spawn_blocking` /
    /// `std::thread` (see [`RpcHandle`]).
    pub fn rpc_handle(&self) -> RpcHandle {
        RpcHandle {
            rpcport: self.rpcport,
            cookie: self.cookie.clone(),
        }
    }

    /// Stop this node and re-spawn `satd` on the *same* datadir and RPC port,
    /// preserving the durable chain state. Used by the cursor `instance_id`
    /// epoch test, which needs a same-datadir restart to prove the per-process
    /// nonce changes (mempool replay resets) while confirmed replay survives.
    ///
    /// Implemented in place because `Drop for TestNode` deletes the datadir —
    /// the freshly-spawned husk's datadir field is neutralised so its own Drop
    /// doesn't nuke the still-live shared directory.
    pub fn restart_preserving_datadir(&mut self, extra_args: &[&str]) {
        self.stop();
        let mut fresh = TestNode::start_with_datadir(&self.datadir, self.rpcport, extra_args);
        std::mem::swap(&mut self.process, &mut fresh.process);
        self.cookie = std::mem::take(&mut fresh.cookie);
        self.p2p_port = fresh.p2p_port;
        self.stderr_log = std::mem::take(&mut fresh.stderr_log);
        // `fresh` now owns the already-exited old process and a shared datadir;
        // blank the datadir so its Drop's `remove_dir_all` is a harmless no-op.
        fresh.datadir = PathBuf::new();
    }
}

/// Derived from a deterministic 32-byte secret: a P2WPKH source address plus
/// the matching `SecretKey` / `PublicKey` for signing spends. Lifted from the
/// E2E suite so both `tests/e2e.rs` and `tests/streaming.rs` share one funding
/// primitive.
#[derive(Clone)]
pub struct DeterministicWallet {
    pub sk: bitcoin::secp256k1::SecretKey,
    pub pk: bitcoin::PublicKey,
    pub address: bitcoin::Address,
}

impl DeterministicWallet {
    pub fn from_secret(secret: [u8; 32]) -> Self {
        use bitcoin::key::CompressedPublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::{Network, PublicKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).expect("valid secret");
        let pk = PublicKey::new(sk.public_key(&secp));
        let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).expect("compressed");
        let address = bitcoin::Address::p2wpkh(&cpk, Network::Regtest);
        DeterministicWallet { sk, pk, address }
    }
}

/// The display-hex txid of block 1's coinbase (the input most streaming tests
/// spend). The caller must have mined ≥1 block.
pub fn block1_coinbase_txid<R: BlockingRpc>(node: &R) -> String {
    let block1_hash = node
        .rpc("getblockhash", vec![serde_json::json!(1)])
        .expect("getblockhash 1")["result"]
        .as_str()
        .expect("hash string")
        .to_string();
    node.rpc(
        "getblock",
        vec![serde_json::json!(block1_hash), serde_json::json!(1)],
    )
    .expect("getblock")["result"]["tx"][0]
        .as_str()
        .expect("coinbase txid")
        .to_string()
}

/// `sha256(scriptPubKey)` as natural-order hex — the watch-set scripthash form
/// (`AddScripts` input and `ScriptMatched.scripthash` output both use this).
pub fn scripthash_hex(spk: &bitcoin::Script) -> String {
    use bitcoin::hashes::{sha256, Hash as _};
    hex::encode(sha256::Hash::hash(spk.as_bytes()).to_byte_array())
}

/// The top `bits/8` bytes of `sha256(scriptPubKey)` as hex — a byte-aligned
/// script-prefix bucket for `AddScriptPrefixes`. `bits` must be a multiple of 8
/// in `1..=32` (the tests use byte-aligned prefixes to avoid sub-byte masking).
pub fn script_prefix_hex(spk: &bitcoin::Script, bits: u32) -> String {
    assert!(bits.is_multiple_of(8) && (8..=32).contains(&bits), "byte-aligned bits");
    use bitcoin::hashes::{sha256, Hash as _};
    let sh = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
    hex::encode(&sh[..(bits / 8) as usize])
}

/// Convert a display-order (RPC) txid/blockhash hex into internal (raw)
/// byte-order hex. Watch matches encode txids as `as_raw_hash().to_byte_array()`
/// (internal order), whereas RPC returns display (reversed) hex — so an
/// assertion comparing a match field against an RPC txid must convert one.
pub fn display_to_internal_hex(display_hex: &str) -> String {
    let mut b = hex::decode(display_hex).expect("hex");
    b.reverse();
    hex::encode(b)
}

/// Build + sign a P2WPKH spend from block-1's coinbase to `dest_script`.
/// Returns `(raw_tx_hex, txid_hex)`. The caller must have mined ≥101 blocks to
/// `wallet.address` so the coinbase is mature. `Sequence::MAX` (no RBF
/// signalling). Lifted from `tests/e2e.rs`.
pub fn build_signed_p2wpkh_spend_from_block1_coinbase<R: BlockingRpc>(
    node: &R,
    wallet: &DeterministicWallet,
    dest_script: bitcoin::ScriptBuf,
    fee_sat: u64,
) -> (String, String) {
    build_signed_p2wpkh_spend_seq(node, wallet, dest_script, fee_sat, 0xffff_ffff)
}

/// Like [`build_signed_p2wpkh_spend_from_block1_coinbase`] but with an explicit
/// input `sequence` — pass a BIP125-signalling value (e.g. `0xffff_fffd`) to
/// make the tx replaceable for the RBF (`TxidReplaced`) tests, and vary
/// `fee_sat` to build the higher-fee replacement.
pub fn build_signed_p2wpkh_spend_seq<R: BlockingRpc>(
    node: &R,
    wallet: &DeterministicWallet,
    dest_script: bitcoin::ScriptBuf,
    fee_sat: u64,
    sequence: u32,
) -> (String, String) {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use std::str::FromStr;

    let cb_txid_str = block1_coinbase_txid(node);
    let cb_txid = bitcoin::Txid::from_str(&cb_txid_str).expect("txid parse");
    // Regtest block-1 coinbase subsidy: 50 BTC (no halvings before 150).
    let cb_value_sat: u64 = 50 * 100_000_000;

    let mut spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_value_sat - fee_sat),
            script_pubkey: dest_script,
        }],
    };

    let secp = Secp256k1::new();
    let src_script = wallet.address.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value_sat),
            EcdsaSighashType::All,
        )
        .expect("sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &wallet.sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(wallet.pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let txid_hex = spend.compute_txid().to_string();
    (raw_hex, txid_hex)
}

/// One `[[token]]` entry for [`write_authfile`].
pub struct TokenSpec {
    pub id: &'static str,
    /// Plaintext bearer token presented by the client; its sha256 is stored.
    pub token: &'static str,
    pub capabilities: &'static [&'static str],
    /// e.g. `Some("1/s")`.
    pub rate_limit: Option<&'static str>,
    /// Per-principal watch-unit ceiling (`stream:watch` quota).
    pub watch_quota: Option<u64>,
}

/// A written authfile fixture; kept alive to retain the temp dir. The
/// `authfile` path is passed to `satd --authfile=...`.
pub struct AuthFixture {
    _dir: tempfile::TempDir,
    pub authfile: PathBuf,
}

/// Write a 0600 `auth.toml` with the given tokens (sha256-hashed) and return
/// the fixture. Mirrors the bearer-auth test setup in `regtest.rs`.
pub fn write_authfile(tokens: &[TokenSpec]) -> AuthFixture {
    use bitcoin::hashes::{sha256, Hash as _};
    use std::io::Write as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let authfile = dir.path().join("auth.toml");
    let mut toml = String::from("version = 1\n");
    for t in tokens {
        let hash = sha256::Hash::hash(t.token.as_bytes());
        let caps = t
            .capabilities
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml.push_str(&format!(
            "[[token]]\nid = \"{}\"\nhash = \"sha256:{}\"\ncapabilities = [{}]\n",
            t.id, hash, caps
        ));
        if let Some(rl) = t.rate_limit {
            toml.push_str(&format!("rate_limit = \"{rl}\"\n"));
        }
        if let Some(wq) = t.watch_quota {
            toml.push_str(&format!("watch_quota = {wq}\n"));
        }
    }
    {
        let mut f = std::fs::File::create(&authfile).expect("create authfile");
        f.write_all(toml.as_bytes()).expect("write authfile");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&authfile, std::fs::Permissions::from_mode(0o600))
                .expect("chmod authfile");
        }
    }
    AuthFixture {
        _dir: dir,
        authfile,
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
