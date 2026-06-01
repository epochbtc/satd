// A real Bitcoin Core (`bitcoind`) regtest node, spawned in Docker, for the
// Phase C live differential harness (`tests/phase_c_differential.rs`).
//
// Phase B (`node/tests/feature_block_consensus.rs`) pins satd's block-
// acceptance verdicts against Core reasons *hand-transcribed* from
// `feature_block.py`. Phase C runs the same adversarial blocks/txs against a
// *live* Core and asserts satd reaches the identical verdict — Core is the
// oracle, observed at runtime rather than baked in. This module is the Core
// half of that harness.
//
// Provisioning mirrors the existing Bitcoin Core interop canary
// (`scripts/canary/core-interop-smoke.sh`): the same pinned image
// (`lncm/bitcoind:v27.0`) run on the host network namespace so the test's
// `bitcoincore-rpc` client reaches it at 127.0.0.1. Unlike the canary we do
// NOT peer Core with satd over P2P — the harness submits identical bytes to
// each node independently and compares verdicts, so any P2P relay between
// them would destroy that isolation.
//
// The container is torn down on `Drop` (and best-effort by name on the next
// run), so a panicking test never leaks a `bitcoind`.

#![allow(dead_code)]

use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{find_available_port, test_timeout};

/// Pinned Core image — kept identical to the interop canary's pin so the two
/// jobs provision the same reference node. Bumping it is a deliberate
/// maintenance step (a Core major moves consensus/relay behaviour).
pub const CORE_IMAGE: &str = "lncm/bitcoind:v27.0";

/// satd / Core accept-or-reject verdict for one submission. `Reject` carries
/// the reject-reason string each node emits (the `bad-*` labels both keep
/// deliberately aligned with Core's `BlockValidationState`/`TxValidationState`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    Reject(String),
}

impl Outcome {
    pub fn reason(&self) -> Option<&str> {
        match self {
            Outcome::Accept => None,
            Outcome::Reject(r) => Some(r.as_str()),
        }
    }
}

pub struct CoreNode {
    container: String,
    pub rpc: Client,
    pub rpc_port: u16,
}

impl CoreNode {
    /// Spawn a fresh regtest `bitcoind` in Docker and block until its RPC is
    /// answering. Panics (failing the test) if Docker is unavailable or Core
    /// never comes up — Phase C is gated only where Docker is provisioned, so
    /// a missing daemon is a setup error, not a skip.
    pub fn start() -> Self {
        let rpc_port = find_available_port();
        // Core still wants a P2P port even with listening disabled; give it a
        // unique one so parallel harnesses never collide on the default 18444.
        let p2p_port = find_available_port();
        let user = "phasec";
        // Loopback-only regtest container — the password just has to match
        // between `docker run` and the client; uniqueness avoids confusion in
        // logs when several runs overlap.
        let pass = format!("pw-{}", rpc_port);
        let container = format!("satd-phasec-core-{}-{}", std::process::id(), rpc_port);

        // Best-effort cleanup of any stale container with this exact name
        // (only possible after a hard crash that skipped Drop).
        let _ = Command::new("docker")
            .args(["rm", "-f", &container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &container,
                "--network=host",
                CORE_IMAGE,
                "-regtest",
                "-server",
                "-listen=0",
                &format!("-rpcport={rpc_port}"),
                &format!("-port={p2p_port}"),
                &format!("-rpcuser={user}"),
                &format!("-rpcpassword={pass}"),
                "-rpcallowip=127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn `docker run` (is Docker installed and on PATH?)");
        assert!(
            run.status.success(),
            "docker run for Bitcoin Core failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );

        let url = format!("http://127.0.0.1:{rpc_port}");
        let rpc = Client::new(&url, Auth::UserPass(user.to_string(), pass.to_string()))
            .expect("construct Bitcoin Core RPC client");

        let node = CoreNode { container, rpc, rpc_port };

        // Wait for the RPC to answer. Scaled by SATD_TEST_TIMEOUT_MULT for CI.
        let deadline = Instant::now() + test_timeout(90);
        loop {
            if node.rpc.get_blockchain_info().is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "Bitcoin Core RPC never came up on port {rpc_port}\n--- docker logs ---\n{}",
                    node.docker_logs()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        node
    }

    /// Submit a serialized block (hex). `Outcome::Accept` when Core returns
    /// `null`, `Outcome::Reject(reason)` for the reject-reason string Core
    /// returns (e.g. `"bad-cb-amount"`), matching `submitblock`'s contract.
    ///
    /// An RPC-level error (e.g. malformed-hex `-22`) is surfaced as a
    /// `Reject("rpc-error: …")` so a harness mistake shows up as a divergence
    /// rather than being silently swallowed.
    pub fn submit_block(&self, block_hex: &str) -> Outcome {
        match self
            .rpc
            .call::<serde_json::Value>("submitblock", &[block_hex.into()])
        {
            Ok(serde_json::Value::Null) => Outcome::Accept,
            Ok(serde_json::Value::String(s)) => Outcome::Reject(s),
            Ok(other) => Outcome::Reject(format!("unexpected-submitblock-result: {other}")),
            Err(e) => Outcome::Reject(format!("rpc-error: {e}")),
        }
    }

    /// Submit a single transaction (hex) via `testmempoolaccept` — the
    /// standalone-tx oracle for context-free `CheckTransaction` rules.
    /// `Accept` when Core reports `allowed: true`, else `Reject(reject-reason)`.
    pub fn test_mempool_accept(&self, tx_hex: &str) -> Outcome {
        let arg = serde_json::json!([tx_hex]);
        match self.rpc.call::<Vec<serde_json::Value>>("testmempoolaccept", &[arg]) {
            Ok(results) => {
                let r = results.first().cloned().unwrap_or(serde_json::Value::Null);
                if r.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false) {
                    Outcome::Accept
                } else {
                    Outcome::Reject(
                        r.get("reject-reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("missing-reject-reason")
                            .to_string(),
                    )
                }
            }
            Err(e) => Outcome::Reject(format!("rpc-error: {e}")),
        }
    }

    pub fn best_block_hash(&self) -> String {
        self.rpc
            .call::<String>("getbestblockhash", &[])
            .expect("Core getbestblockhash")
    }

    pub fn block_count(&self) -> u64 {
        self.rpc.call::<u64>("getblockcount", &[]).expect("Core getblockcount")
    }

    /// Mark a block invalid (used to roll the chain back to a shared tip
    /// between accept-cases / fuzz iterations).
    pub fn invalidate_block(&self, block_hash: &str) {
        let _ = self
            .rpc
            .call::<serde_json::Value>("invalidateblock", &[block_hash.into()]);
    }

    fn docker_logs(&self) -> String {
        Command::new("docker")
            .args(["logs", "--tail", "40", &self.container])
            .output()
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_else(|e| format!("(docker logs failed: {e})"))
    }
}

impl Drop for CoreNode {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Pre-pull the Core image so the first `CoreNode::start()` doesn't fold a
/// multi-second registry fetch into its RPC-readiness deadline. Best-effort:
/// a failure here just means `docker run` pulls lazily. Mirrors the canary's
/// retry-pull.
pub fn pull_core_image() {
    for attempt in 1..=3 {
        let ok = Command::new("docker")
            .args(["pull", CORE_IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        std::thread::sleep(Duration::from_secs(attempt * 2));
    }
}
