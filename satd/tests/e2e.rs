// End-to-end integration tests driving real `satd` over real sockets.
//
// Each surface (JSON-RPC, Esplora REST, Electrum) has its own test group;
// the cross-surface group asserts the shared-chainstate guarantee that a
// tx broadcast on one surface is observable on the others.
//
// Run with: `cargo test --test e2e --locked -- --test-threads=1`
//
// CI sets `SATD_E2E_TIMEOUT_MULT=3` to absorb hosted-runner load. See
// `docs/E2E_TESTING.md`.

mod common;

use common::{TestNode, e2e_test_timeout};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

/// Wrapper around `TestNode` that also tracks the OS-assigned Esplora and
/// Electrum ports read back from `getserverstatus`. Reach through to the
/// inner `TestNode` for everything else.
pub struct E2eNode {
    pub node: TestNode,
    pub esplora_port: Option<u16>,
    pub electrum_port: Option<u16>,
}

impl E2eNode {
    /// Boot a `satd` regtest node with the given extra args, then poll
    /// `getserverstatus` until every requested optional listener
    /// (Esplora / Electrum) reports a non-null bind with a non-zero
    /// port. `TestNode::start` only waits for the JSON-RPC server, but
    /// satd starts the RPC server *before* the optional listeners
    /// bind — so observing `chain == regtest` doesn't imply the
    /// Esplora/Electrum ports are ready to read back.
    pub fn boot_with(extra_args: &[&str]) -> Self {
        let node = TestNode::start(extra_args);
        let want_esplora = args_request_listener(extra_args, "--esplora");
        let want_electrum = args_request_listener(extra_args, "--electrum");
        let (esplora_port, electrum_port) = poll_listener_ports(&node, want_esplora, want_electrum);
        E2eNode {
            node,
            esplora_port,
            electrum_port,
        }
    }
}

/// Detect whether `extra_args` requests the given listener (e.g.
/// `--esplora=1` / `--electrum=1` / `--esplora=true`). Returns false
/// for `=0` / `=false` / absent.
fn args_request_listener(extra_args: &[&str], flag_prefix: &str) -> bool {
    let on = format!("{}=1", flag_prefix);
    let on_true = format!("{}=true", flag_prefix);
    extra_args.iter().any(|a| *a == on || *a == on_true)
}

/// Poll `getserverstatus` until every requested optional listener
/// reports a non-null bind with a non-zero port. Returns the parsed
/// ports — `None` for any listener not requested by the caller.
/// Panics on timeout with the last-seen `getserverstatus` body so
/// the failure points at the actual startup state, not a generic
/// "no listener" message.
fn poll_listener_ports(
    node: &TestNode,
    want_esplora: bool,
    want_electrum: bool,
) -> (Option<u16>, Option<u16>) {
    let deadline = std::time::Instant::now() + e2e_test_timeout(30);
    loop {
        let last_body = node
            .rpc_call("getserverstatus")
            .unwrap_or(serde_json::Value::Null);
        let result = &last_body["result"];
        let esplora = result["esplora"]["bind"]
            .as_str()
            .and_then(parse_port_from_bind);
        let electrum = result["electrum"]["bind"]
            .as_str()
            .and_then(parse_port_from_bind);
        let esplora_ready = !want_esplora || esplora.is_some();
        let electrum_ready = !want_electrum || electrum.is_some();
        if esplora_ready && electrum_ready {
            // Only surface ports for listeners the caller requested:
            // an enabled-by-default future listener that the caller
            // didn't opt into shouldn't leak through `E2eNode`.
            return (
                if want_esplora { esplora } else { None },
                if want_electrum { electrum } else { None },
            );
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for listeners (esplora wanted={} got={:?}, electrum wanted={} got={:?}); last getserverstatus: {}",
                want_esplora, esplora, want_electrum, electrum, last_body
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Parse the trailing port from a `host:port` bind string. Returns
/// `None` if the port is 0 — port-0 is the request the operator
/// sends to ask for an OS-assigned port, so observing it on the
/// reply path means `local_addr()` lookup hasn't completed yet and
/// callers should keep polling.
fn parse_port_from_bind(bind: &str) -> Option<u16> {
    bind.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .filter(|&p| p != 0)
}

#[test]
fn test_e2e_smoke_boot_and_query() {
    let mut e2e = E2eNode::boot_with(&[]);
    let resp = e2e
        .node
        .rpc_call("getblockchaininfo")
        .expect("getblockchaininfo");
    let result = &resp["result"];
    assert_eq!(result["chain"], "regtest");
    assert_eq!(result["blocks"], 0);
    e2e.node.stop();
}

#[test]
fn test_e2e_smoke_poll_until_json() {
    let mut e2e = E2eNode::boot_with(&[]);
    let rpcport = e2e.node.rpcport;
    let cookie = e2e.node.cookie.clone();
    let value = common::poll_until_json(
        || {
            // Probe getblockchaininfo independently so the helper sees a
            // realistic call path, not just a cached value.
            let url = format!("http://127.0.0.1:{}/", rpcport);
            let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .unwrap();
            client
                .post(&url)
                .basic_auth(user, Some(pass))
                .header("Content-Type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
                .send()
                .ok()
                .and_then(|r| r.json::<serde_json::Value>().ok())
                .unwrap_or(serde_json::Value::Null)
        },
        |v| v["result"]["chain"] == "regtest",
        10,
    );
    assert_eq!(value["result"]["blocks"], 0);
    // Demonstrate the SATD_E2E_TIMEOUT_MULT pathway is wired by exercising
    // e2e_test_timeout (zero-cost — just confirms the symbol resolves).
    let _ = e2e_test_timeout(1);
    e2e.node.stop();
}

// ─────────────────────────────────────────────────────────────────────
// JSON-RPC lifecycle suite (driven by `sat-cli`)
// ─────────────────────────────────────────────────────────────────────

/// Resolve the `sat-cli` binary path relative to `CARGO_BIN_EXE_satd`.
/// Both binaries live in the same workspace target directory.
fn sat_cli_path() -> PathBuf {
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    PathBuf::from(satd_bin)
        .parent()
        .expect("satd binary parent")
        .join("sat-cli")
}

/// Build a `Command` for `sat-cli` pre-wired with this node's regtest
/// datadir + rpcport. Caller appends the subcommand and any flags.
fn sat_cli_for(node: &TestNode) -> Command {
    let mut cmd = Command::new(sat_cli_path());
    cmd.arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport));
    cmd
}

#[test]
fn test_e2e_jsonrpc_chain_info_via_sat_cli() {
    let mut e2e = E2eNode::boot_with(&[]);
    let output = sat_cli_for(&e2e.node)
        .arg("--output=json")
        .args(["chain", "info"])
        .output()
        .expect("run sat-cli chain info");
    assert!(
        output.status.success(),
        "sat-cli chain info exit failure. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("sat-cli --output=json should emit valid JSON");
    assert_eq!(v["chain"], "regtest");
    assert_eq!(v["blocks"], 0);
    e2e.node.stop();
}

/// Derived from a deterministic 32-byte secret: P2WPKH source address +
/// the matching `SecretKey` / `PublicKey` for signing spends. Reused
/// across PR-2 / PR-3 / PR-4 tests so funding flows share a seed.
struct DeterministicWallet {
    sk: bitcoin::secp256k1::SecretKey,
    pk: bitcoin::PublicKey,
    address: bitcoin::Address,
}

impl DeterministicWallet {
    fn from_secret(secret: [u8; 32]) -> Self {
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

#[test]
fn test_e2e_jsonrpc_fund_and_mine_lifecycle() {
    let mut e2e = E2eNode::boot_with(&[]);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let addr = wallet.address.to_string();

    // Mine 101 blocks to the deterministic P2WPKH via sat-cli's
    // legacy-passthrough invocation. (`sat-cli generatetoaddress` is
    // not a structured subcommand; satd preserves Core's RPC name.)
    let output = sat_cli_for(&e2e.node)
        .args(["generatetoaddress", "101", &addr])
        .output()
        .expect("run sat-cli generatetoaddress");
    assert!(
        output.status.success(),
        "sat-cli generatetoaddress exit failure. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify height through sat-cli's structured `chain height`.
    let h = sat_cli_for(&e2e.node)
        .args(["chain", "height"])
        .output()
        .expect("run sat-cli chain height");
    assert!(h.status.success());
    let height_str = String::from_utf8_lossy(&h.stdout).trim().to_string();
    assert_eq!(height_str, "101", "height after 101 mined blocks");

    // Cross-check via direct RPC: the best block hash should be the
    // tip of the 101-block chain. We don't pin the exact hash (it
    // depends on the coinbase scriptPubKey, which is address-dependent
    // and outside the deterministic-secret contract), but the hash
    // must be a 64-char hex string and not the regtest genesis.
    let best = e2e
        .node
        .rpc_call("getbestblockhash")
        .expect("getbestblockhash");
    let h = best["result"].as_str().expect("hash string");
    assert_eq!(h.len(), 64);
    assert_ne!(
        h, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        "best block must not still be regtest genesis"
    );
    e2e.node.stop();
}

/// Build + sign a P2WPKH spend from block-1's coinbase to a destination
/// script. Returns (raw_tx_hex, txid_hex). Mirrors the existing pattern
/// at `regtest.rs:test_address_index_backfill_spending_row_with_real_spend`.
/// Caller must have already mined ≥101 blocks to `wallet.address`.
fn build_signed_p2wpkh_spend_from_block1_coinbase(
    node: &TestNode,
    wallet: &DeterministicWallet,
    dest_script: bitcoin::ScriptBuf,
    fee_sat: u64,
) -> (String, String) {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
    };
    use std::str::FromStr;

    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .expect("getblockhash 1")["result"]
        .as_str()
        .expect("hash string")
        .to_string();
    let cb_txid_str = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .expect("getblock")["result"]["tx"][0]
        .as_str()
        .expect("coinbase txid")
        .to_string();
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
            sequence: Sequence::MAX,
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

#[test]
fn test_e2e_jsonrpc_tx_broadcast_and_mempool() {
    let mut e2e = E2eNode::boot_with(&[]);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    // Mature block-1 coinbase: mine 101 blocks to the deterministic
    // P2WPKH source so subsidy is spendable.
    let mine = sat_cli_for(&e2e.node)
        .args(["generatetoaddress", "101", &wallet.address.to_string()])
        .output()
        .expect("sat-cli generatetoaddress");
    assert!(mine.status.success(), "mine 101 blocks");

    // Build a spend cb1 → bcrt1qqqqqq...dku202 with a 1000-sat fee.
    // The destination is the canonical all-zero-hash P2WPKH burn
    // address; we just need a valid script, never to spend it back.
    let dest_addr_str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let dest_script = bitcoin::Address::from_str(dest_addr_str)
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &wallet, dest_script, 1000);

    // Broadcast via sat-cli (legacy-passthrough form). Capture the
    // emitted txid and assert it matches the locally-computed one.
    let bcast = sat_cli_for(&e2e.node)
        .args(["sendrawtransaction", &raw_hex])
        .output()
        .expect("sat-cli sendrawtransaction");
    assert!(
        bcast.status.success(),
        "sat-cli sendrawtransaction exit failure. stderr: {}",
        String::from_utf8_lossy(&bcast.stderr)
    );
    let bcast_out = String::from_utf8_lossy(&bcast.stdout).trim().to_string();
    let bcast_txid = bcast_out.trim_matches('"');
    assert_eq!(bcast_txid, txid_hex, "broadcast txid round-trip");

    // Poll for the tx in the mempool. 10s with the e2e mult is enough
    // even under the worst-case CI runner load; the mempool admit
    // happens synchronously in `sendrawtransaction`'s handler so this
    // typically converges in the first probe.
    let rpcport = e2e.node.rpcport;
    let cookie = e2e.node.cookie.clone();
    let want_txid = txid_hex.clone();
    common::poll_until_json(
        || rpc_post(rpcport, &cookie, "getrawmempool", &[]),
        |v| {
            v["result"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(want_txid.as_str())))
        },
        10,
    );

    // Mine 1 block to confirm; poll for empty mempool.
    let confirm = sat_cli_for(&e2e.node)
        .args(["generatetoaddress", "1", &wallet.address.to_string()])
        .output()
        .expect("sat-cli generatetoaddress confirm");
    assert!(confirm.status.success());
    common::poll_until_json(
        || rpc_post(rpcport, &cookie, "getrawmempool", &[]),
        |v| v["result"].as_array().is_some_and(|a| a.is_empty()),
        10,
    );

    // Confirm via `getrawtransaction` verbose=true — wallet-free
    // observation. After mining 1 block on top, the spend has exactly
    // 1 confirmation. This same call also returns `blockheight: 102`
    // (the spend lands in block 102, mined just above); both fields
    // are part of the Core-compatible verbose response.
    let raw = rpc_post(
        rpcport,
        &cookie,
        "getrawtransaction",
        &[serde_json::json!(txid_hex), serde_json::json!(true)],
    );
    assert_eq!(
        raw["result"]["confirmations"], 1,
        "tx should show 1 confirmation; got {}",
        raw
    );
    assert_eq!(raw["result"]["blockheight"], 102);

    e2e.node.stop();
}

/// Thin helper used by tests that need to drive a JSON-RPC method
/// from inside a `poll_until_json` probe. Mirrors
/// `TestNode::rpc_call_with_params` but is fail-fast on real errors:
/// transport failures, non-2xx HTTP, malformed JSON, and JSON-RPC
/// errors all panic immediately with structured context. Predicates
/// in `poll_until_json` callers only see *valid* JSON-RPC successes
/// — the loop is for state-convergence, not error masking.
///
/// This is the right policy because the harness's `TestNode::start`
/// already waits for the RPC server to answer `getblockchaininfo`
/// before the test body runs. Any post-start RPC error is a real bug
/// (auth regression, 500, malformed shape) that timing-based polling
/// would hide behind a generic `poll_until_json timed out` panic.
fn rpc_post(
    rpcport: u16,
    cookie: &str,
    method: &str,
    params: &[serde_json::Value],
) -> serde_json::Value {
    let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "e2e",
        "method": method,
        "params": params,
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let resp = client
        .post(format!("http://127.0.0.1:{}/", rpcport))
        .basic_auth(user, Some(pass))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .unwrap_or_else(|e| panic!("rpc_post {method}: transport error: {e}"));
    let status = resp.status();
    let text = resp
        .text()
        .unwrap_or_else(|e| panic!("rpc_post {method}: body read failed: {e}"));
    if !status.is_success() {
        panic!("rpc_post {method}: HTTP {} — body: {}", status, text);
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("rpc_post {method}: JSON parse failed: {e} — body: {text}"));
    if !v["error"].is_null() {
        panic!("rpc_post {method}: JSON-RPC error: {}", v["error"]);
    }
    v
}

/// Companion helper for tests that probe an Esplora endpoint inside a
/// `poll_until_json` predicate. Same fail-fast policy as `rpc_post`:
/// transport failures and non-2xx HTTP panic with structured context;
/// only the parsed-JSON-but-not-converged path returns to the
/// predicate.
fn esplora_get_json(esplora: &EsploraClient, path: &str) -> serde_json::Value {
    let resp = esplora.get(path);
    let status = resp.status();
    let text = resp
        .text()
        .unwrap_or_else(|e| panic!("esplora GET {path}: body read failed: {e}"));
    if !status.is_success() {
        panic!("esplora GET {path}: HTTP {} — body: {}", status, text);
    }
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("esplora GET {path}: JSON parse failed: {e} — body: {text}"))
}

// ─────────────────────────────────────────────────────────────────────
// Esplora REST suite
// ─────────────────────────────────────────────────────────────────────

/// Build an `EsploraClient` for a booted node. Panics if Esplora isn't
/// enabled — `boot_with(&["--esplora=1", "--esplorabind=127.0.0.1:0", ...])`
/// is required.
fn esplora_for(e2e: &E2eNode) -> EsploraClient {
    let port = e2e
        .esplora_port
        .expect("E2eNode booted with --esplora=1 and --esplorabind=127.0.0.1:0");
    EsploraClient { port }
}

/// Thin wrapper around `reqwest::blocking::Client` for the Esplora
/// endpoint set. All helpers return the raw `Response` so tests can
/// assert on status + body shape.
struct EsploraClient {
    port: u16,
}

impl EsploraClient {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    fn get(&self, path: &str) -> reqwest::blocking::Response {
        Self::client()
            .get(self.url(path))
            .send()
            .expect("esplora GET")
    }

    /// Plain-text POST /tx (the canonical Esplora wire shape: raw-hex
    /// body, `Content-Type: text/plain`). Matches mempool.space and
    /// blockstream.info.
    fn post_tx(&self, raw_hex: &str) -> reqwest::blocking::Response {
        Self::client()
            .post(self.url("/tx"))
            .header("Content-Type", "text/plain")
            .body(raw_hex.to_string())
            .send()
            .expect("esplora POST /tx")
    }

    /// POST /tx with a caller-chosen Content-Type (or no header).
    /// Used by the content-type-compatibility test to assert that
    /// satd accepts any Content-Type the way blockstream.io does.
    fn post_tx_with_content_type(
        &self,
        raw_hex: &str,
        content_type: Option<&str>,
    ) -> reqwest::blocking::Response {
        let mut req = Self::client().post(self.url("/tx"));
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        req.body(raw_hex.to_string())
            .send()
            .expect("esplora POST /tx (custom CT)")
    }

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("build reqwest client")
    }
}

fn esplora_e2e_args() -> Vec<&'static str> {
    // `--esplora=1` triggers the harness's txindex auto-coupling
    // (`common/mod.rs::start_with_env`); addressindex is on by default
    // in satd so no explicit flag is needed.
    vec!["--esplora=1", "--esplorabind=127.0.0.1:0"]
}

#[test]
fn test_e2e_esplora_tip_height_after_mining() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);

    // Fresh regtest tip should be 0 (genesis).
    let r = esplora.get("/blocks/tip/height");
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.text().expect("body utf8").trim(),
        "0",
        "fresh regtest tip should be 0"
    );

    // Mine 5 blocks to a deterministic P2WPKH; tip should flip to 5.
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(5),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress");

    let r = esplora.get("/blocks/tip/height");
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().expect("body utf8").trim(), "5");

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_post_tx_round_trip() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    // Mature block-1 coinbase.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_script = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &wallet, dest_script, 1000);

    let r = esplora.post_tx(&raw_hex);
    assert_eq!(r.status(), 200, "POST /tx should return 200");
    let body = r.text().expect("body utf8");
    assert_eq!(body.trim(), txid_hex, "POST /tx body should be the txid");

    // GET /tx/:txid — assert unconfirmed (in mempool, not yet mined).
    let tx_r = esplora.get(&format!("/tx/{}", txid_hex));
    assert_eq!(tx_r.status(), 200);
    let tx_json: serde_json::Value = tx_r.json().expect("tx body json");
    assert_eq!(tx_json["txid"], txid_hex);
    assert_eq!(tx_json["status"]["confirmed"], false);

    // GET /mempool — the txid should appear in the verbose mempool
    // snapshot. We poll briefly since admit is synchronous but the
    // mempool snapshot is rebuilt lazily.
    let port = esplora.port;
    let want_txid = txid_hex.clone();
    let _ = port;
    common::poll_until_json(
        || esplora_get_json(&esplora, "/mempool/txids"),
        |v| {
            v.as_array()
                .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(want_txid.as_str())))
        },
        10,
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_address_history_after_spend() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let src_wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    // Mine 101 to src so cb-1 is matured.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(src_wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    // Build + broadcast the spend cb-1 → canonical-burn dest.
    let dest_addr_str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let dest_script = bitcoin::Address::from_str(dest_addr_str)
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &src_wallet, dest_script, 1000);

    let r = esplora.post_tx(&raw_hex);
    assert_eq!(r.status(), 200);
    let body = r.text().expect("body utf8");
    assert_eq!(
        body.trim(),
        txid_hex,
        "POST /tx body must echo the broadcast txid"
    );

    // Mine 1 block to confirm.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(src_wallet.address.to_string()),
            ],
        )
        .expect("confirm block");

    // GET /address/:src/txs should now include the spend.
    let src_str = src_wallet.address.to_string();
    let want_txid = txid_hex.clone();
    let src_path = format!("/address/{}/txs", src_str);
    common::poll_until_json(
        || esplora_get_json(&esplora, &src_path),
        |v| {
            v.as_array().is_some_and(|a| {
                a.iter()
                    .any(|t| t["txid"].as_str() == Some(want_txid.as_str()))
            })
        },
        10,
    );

    // GET /address/:dest/utxo should list the new output (post-mine).
    let dest_utxos = esplora.get(&format!("/address/{}/utxo", dest_addr_str));
    assert_eq!(dest_utxos.status(), 200);
    let utxos: serde_json::Value = dest_utxos.json().expect("utxos json");
    let arr = utxos.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|u| u["txid"].as_str() == Some(txid_hex.as_str())),
        "dest /utxo should include the spend output; got {}",
        utxos
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_content_type_compatibility() {
    // blockstream.info / mempool.space accept POST /tx regardless of
    // the Content-Type sent by the client. Many Esplora clients send
    // `application/json` (wrong) or omit the header entirely; satd
    // must hex-parse the body regardless to stay compatible.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_script = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &wallet, dest_script, 1000);

    // Wrong Content-Type: application/json. Must still succeed.
    let r = esplora.post_tx_with_content_type(&raw_hex, Some("application/json"));
    assert_eq!(
        r.status(),
        200,
        "POST /tx with application/json Content-Type must succeed (blockstream-compat)"
    );
    assert_eq!(r.text().expect("body utf8").trim(), txid_hex);

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_content_type_missing_compatibility() {
    // No Content-Type header at all (some HTTP libraries omit it for
    // POSTs with a String body). Must succeed for the same reason
    // application/json must succeed.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_script = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &wallet, dest_script, 1000);

    let r = esplora.post_tx_with_content_type(&raw_hex, None);
    assert_eq!(
        r.status(),
        200,
        "POST /tx with no Content-Type must succeed (blockstream-compat)"
    );
    assert_eq!(r.text().expect("body utf8").trim(), txid_hex);

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_cookie_auth_required_when_configured() {
    let mut e2e = E2eNode::boot_with(&[
        "--esplora=1",
        "--esplorabind=127.0.0.1:0",
        "--esploraauth=cookie",
    ]);
    let esplora = esplora_for(&e2e);

    // Unauthenticated request must get 401.
    let r = esplora.get("/blocks/tip/height");
    assert_eq!(
        r.status(),
        401,
        "unauthed Esplora request must be rejected with 401 under --esploraauth=cookie"
    );

    // Authenticated request with the cookie must succeed. The
    // cookie value in `node.cookie` is the on-disk `user:pass`
    // string; satd reuses the same cookie file for both JSON-RPC
    // and Esplora cookie auth.
    let (user, pass) = e2e
        .node
        .cookie
        .split_once(':')
        .expect("cookie has user:pass");
    let r = EsploraClient::client()
        .get(format!(
            "http://127.0.0.1:{}/blocks/tip/height",
            esplora.port
        ))
        .basic_auth(user, Some(pass))
        .send()
        .expect("authed GET");
    assert_eq!(r.status(), 200, "authed Esplora request must succeed");
    assert_eq!(r.text().expect("body utf8").trim(), "0");

    e2e.node.stop();
}

/// Esplora-flavored scripthash of a `scriptPubKey`: raw SHA-256, hex
/// in natural byte order. Mirrors `node_index::scripthash_of` so tests
/// can derive the same key the handler does without depending on
/// `node-index` types here.
fn esplora_scripthash_of_spk(spk: &bitcoin::Script) -> String {
    use bitcoin::hashes::{Hash as _, sha256};
    let h = sha256::Hash::hash(spk.as_bytes());
    hex::encode(h.to_byte_array())
}

#[test]
fn test_e2e_esplora_block_family_suite() {
    // Boot once, mine 5 blocks, assert every block-family endpoint
    // returns a shape consistent with the same data fetched via JSON-RPC.
    // This catches regressions in serialization, height→hash mapping,
    // and pagination in one fixture.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(5),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 5");

    // Resolve height-3 hash via RPC so subsequent assertions have a
    // known-good reference; pick a mid-chain block so height/prev/next
    // logic is all in scope.
    let h3_hash = e2e
        .node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(3)])
        .expect("getblockhash 3")["result"]
        .as_str()
        .expect("hash string")
        .to_string();
    let tip_hash = e2e
        .node
        .rpc_call("getbestblockhash")
        .expect("getbestblockhash")["result"]
        .as_str()
        .expect("hash string")
        .to_string();

    // /block/:hash — summary shape with size, weight, mediantime,
    // version, merkle_root, prev/next.
    let v = esplora_get_json(&esplora, &format!("/block/{}", h3_hash));
    assert_eq!(v["id"], h3_hash, "id field round-trips block hash");
    assert_eq!(v["height"], 3);
    assert_eq!(v["tx_count"], 1, "regtest coinbase-only block");
    assert!(v["size"].as_u64().unwrap_or(0) > 0, "size > 0");
    assert!(v["weight"].as_u64().unwrap_or(0) > 0, "weight > 0");
    assert!(
        v["merkle_root"].as_str().is_some_and(|s| s.len() == 64),
        "merkle_root is 64-char hex"
    );
    assert!(
        v["previousblockhash"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "previousblockhash present for non-genesis"
    );

    // /block/:hash/header — 80-byte serialized header as 160-char hex.
    let r = esplora.get(&format!("/block/{}/header", h3_hash));
    assert_eq!(r.status(), 200);
    let header_hex = r.text().expect("body utf8").trim().to_string();
    assert_eq!(header_hex.len(), 160, "80-byte header → 160 hex chars");

    // /block/:hash/raw — bytes must deserialize back to a Block whose
    // hash matches the original.
    let r = esplora.get(&format!("/block/{}/raw", h3_hash));
    assert_eq!(r.status(), 200);
    let raw = r.bytes().expect("body bytes");
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&raw).expect("block deserializes");
    assert_eq!(
        block.block_hash().to_string(),
        h3_hash,
        "raw bytes round-trip to same block hash"
    );

    // /block/:hash/status — in_best_chain true, height matches, next_best
    // points at height 4.
    let v = esplora_get_json(&esplora, &format!("/block/{}/status", h3_hash));
    assert_eq!(v["in_best_chain"], true);
    assert_eq!(v["height"], 3);
    assert!(
        v["next_best"].as_str().is_some_and(|s| s.len() == 64),
        "non-tip block has next_best"
    );

    // /block/:hash/txids + /block/:hash/txid/:i agree.
    let txids = esplora_get_json(&esplora, &format!("/block/{}/txids", h3_hash));
    let arr = txids.as_array().expect("txids array");
    assert_eq!(arr.len(), 1, "coinbase-only");
    let cb_txid_from_array = arr[0].as_str().expect("txid string").to_string();
    let r = esplora.get(&format!("/block/{}/txid/0", h3_hash));
    assert_eq!(r.status(), 200);
    let cb_txid_indexed = r.text().expect("body utf8").trim().to_string();
    assert_eq!(
        cb_txid_from_array, cb_txid_indexed,
        "/txids[0] and /txid/0 must agree"
    );

    // /block-height/3 → same hash as `getblockhash 3` via RPC.
    let r = esplora.get("/block-height/3");
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().expect("body utf8").trim(), h3_hash);

    // /blocks → up to 10 descending; first entry must be tip.
    let v = esplora_get_json(&esplora, "/blocks");
    let arr = v.as_array().expect("blocks array");
    assert_eq!(arr.len(), 6, "5 mined + genesis = 6 entries");
    assert_eq!(arr[0]["id"], tip_hash, "tip block first in /blocks");
    assert_eq!(arr[0]["height"], 5);
    assert_eq!(arr[5]["height"], 0, "genesis last");

    // /blocks/2 → up to 10 descending ending at height 2 inclusive.
    let v = esplora_get_json(&esplora, "/blocks/2");
    let arr = v.as_array().expect("blocks/2 array");
    assert_eq!(arr.len(), 3, "heights 2, 1, 0");
    assert_eq!(arr[0]["height"], 2);

    // /blocks/9999 past tip → 404.
    let r = esplora.get("/blocks/9999");
    assert_eq!(r.status(), 404, "past-tip start_height should 404");

    // Bogus block hash → 4xx (either 400 BadRequest or 404 NotFound).
    let r = esplora.get("/block/0000000000000000000000000000000000000000000000000000000000000000");
    assert!(
        (400..500).contains(&r.status().as_u16()),
        "unknown block hash should be 4xx, got {}",
        r.status()
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_tx_family_suite() {
    // Boot once, mature cb1, broadcast a spend, mine 1, then assert
    // every tx-family endpoint against the confirmed spend.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_addr = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest");
    let dest_script = dest_addr.script_pubkey();
    let (raw_hex, txid_hex) = build_signed_p2wpkh_spend_from_block1_coinbase(
        &e2e.node,
        &wallet,
        dest_script.clone(),
        1000,
    );

    let r = esplora.post_tx(&raw_hex);
    assert_eq!(r.status(), 200, "POST /tx accept");
    assert_eq!(r.text().expect("body utf8").trim(), txid_hex);

    // Mine 1 to confirm. The spend lands at height 102.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 1");

    // Wait for the spend to show as confirmed on /tx/:txid/status. Use
    // a bounded poll because the address-index + tx-index updates
    // happen in connect_block, which is synchronous with the miner
    // RPC's reply — typically converges on the first probe.
    let status_path = format!("/tx/{}/status", txid_hex);
    let v = common::poll_until_json(
        || esplora_get_json(&esplora, &status_path),
        |v| v["confirmed"] == true,
        10,
    );
    assert_eq!(v["block_height"], 102);
    assert!(
        v["block_hash"].as_str().is_some_and(|s| s.len() == 64),
        "block_hash hex"
    );

    // /tx/:txid/hex returns the same hex we broadcast.
    let r = esplora.get(&format!("/tx/{}/hex", txid_hex));
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.text().expect("body utf8").trim(),
        raw_hex,
        "/tx/:txid/hex round-trips"
    );

    // /tx/:txid/raw returns bytes that decode back to the same tx.
    let r = esplora.get(&format!("/tx/{}/raw", txid_hex));
    assert_eq!(r.status(), 200);
    let raw = r.bytes().expect("body bytes");
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).expect("tx deserialize");
    assert_eq!(
        tx.compute_txid().to_string(),
        txid_hex,
        "/tx/:txid/raw bytes match txid"
    );

    // /tx/:txid/outspends — the burn destination is unspent; the array
    // has one entry matching the single vout.
    let v = esplora_get_json(&esplora, &format!("/tx/{}/outspends", txid_hex));
    let arr = v.as_array().expect("outspends array");
    assert_eq!(arr.len(), 1, "spend has 1 output");
    assert_eq!(arr[0]["spent"], false, "burn output is unspent");

    // /tx/:txid/outspend/0 — same single-shot lookup, same answer.
    let v = esplora_get_json(&esplora, &format!("/tx/{}/outspend/0", txid_hex));
    assert_eq!(v["spent"], false);

    // Out-of-range vout → 404 (review-hardened path).
    let r = esplora.get(&format!("/tx/{}/outspend/9", txid_hex));
    assert_eq!(r.status(), 404, "out-of-range vout must 404");

    // /tx/:txid/merkle-proof — recompute root from branch+pos and
    // assert it matches the block's merkle_root field.
    let v = esplora_get_json(&esplora, &format!("/tx/{}/merkle-proof", txid_hex));
    assert_eq!(v["block_height"], 102);
    let pos = v["pos"].as_u64().expect("pos number") as usize;
    assert_eq!(pos, 1, "coinbase at 0, spend at 1");
    let branch_bytes: Vec<[u8; 32]> = v["merkle"]
        .as_array()
        .expect("merkle branch array")
        .iter()
        .map(|n| {
            let mut buf = [0u8; 32];
            let bytes = hex::decode(n.as_str().expect("hex node")).expect("hex decode");
            buf.copy_from_slice(&bytes);
            buf
        })
        .collect();
    let txid = bitcoin::Txid::from_str(&txid_hex).expect("txid parse");
    let recomputed = recompute_merkle_root(&txid, &branch_bytes, pos);
    let block_hash = e2e
        .node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(102)])
        .expect("getblockhash 102")["result"]
        .as_str()
        .expect("hash")
        .to_string();
    let header = e2e
        .node
        .rpc_call_with_params("getblockheader", vec![serde_json::json!(block_hash)])
        .expect("getblockheader")["result"]
        .clone();
    let expected_root = header["merkleroot"]
        .as_str()
        .expect("merkleroot")
        .to_string();
    assert_eq!(
        recomputed.to_string(),
        expected_root,
        "reconstructed merkle root must equal block's merkleroot"
    );

    // Unknown txid on any tx-family endpoint → 404.
    let bogus = "0000000000000000000000000000000000000000000000000000000000000001";
    let r = esplora.get(&format!("/tx/{}/status", bogus));
    assert_eq!(r.status(), 404, "unknown txid status should 404");
    let r = esplora.get(&format!("/tx/{}/hex", bogus));
    assert_eq!(r.status(), 404, "unknown txid hex should 404");

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_scripthash_parity_with_address() {
    // The scripthash endpoint family must return identical stats to
    // the address endpoint family for the same scriptPubKey. Wallets
    // like Sparrow query via scripthash; explorers query via address.
    // Drift here is a wire-level compat break.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let addr_str = wallet.address.to_string();
    let sh = esplora_scripthash_of_spk(&wallet.address.script_pubkey());

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr_str.clone())],
        )
        .expect("generatetoaddress 5");

    // /address/:addr vs /scripthash/:hash — stats must agree.
    let a = esplora_get_json(&esplora, &format!("/address/{}", addr_str));
    let s = esplora_get_json(&esplora, &format!("/scripthash/{}", sh));
    assert_eq!(
        a["chain_stats"], s["chain_stats"],
        "chain_stats must match between /address and /scripthash"
    );
    assert_eq!(
        a["mempool_stats"], s["mempool_stats"],
        "mempool_stats must match"
    );

    // /address/:addr/utxo vs /scripthash/:hash/utxo — same UTXO set.
    let a_utxo = esplora_get_json(&esplora, &format!("/address/{}/utxo", addr_str));
    let s_utxo = esplora_get_json(&esplora, &format!("/scripthash/{}/utxo", sh));
    let a_arr = a_utxo.as_array().expect("address utxo array");
    let s_arr = s_utxo.as_array().expect("scripthash utxo array");
    assert_eq!(a_arr.len(), s_arr.len(), "same UTXO count");
    let collect_keys = |arr: &[serde_json::Value]| -> std::collections::BTreeSet<(String, u64)> {
        arr.iter()
            .map(|u| {
                (
                    u["txid"].as_str().unwrap_or("").to_string(),
                    u["vout"].as_u64().unwrap_or(0),
                )
            })
            .collect()
    };
    assert_eq!(
        collect_keys(a_arr),
        collect_keys(s_arr),
        "same (txid, vout) set across the two endpoints"
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_mempool_detail_tracks_broadcast() {
    // Boot fresh, mine to maturity, broadcast a spend, assert that
    // /mempool, /mempool/txids, /mempool/recent all reflect the
    // broadcast tx. Wire shapes for mempool.space / blockstream.info
    // consumers — drift here breaks downstream tooling.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);

    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_addr = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest");
    let (raw_hex, txid_hex) = build_signed_p2wpkh_spend_from_block1_coinbase(
        &e2e.node,
        &wallet,
        dest_addr.script_pubkey(),
        1000,
    );
    let r = esplora.post_tx(&raw_hex);
    assert_eq!(r.status(), 200);

    // /mempool/txids includes the txid.
    let want_txid = txid_hex.clone();
    common::poll_until_json(
        || esplora_get_json(&esplora, "/mempool/txids"),
        |v| {
            v.as_array()
                .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(want_txid.as_str())))
        },
        10,
    );

    // /mempool summary: count == 1, vsize > 0, total_fee == 1000.
    let v = esplora_get_json(&esplora, "/mempool");
    assert_eq!(v["count"], 1);
    assert!(v["vsize"].as_u64().unwrap_or(0) > 0, "vsize > 0");
    assert_eq!(v["total_fee"], 1000, "fee_sat we paid");
    assert!(v["fee_histogram"].is_array(), "fee_histogram must be array");

    // /mempool/recent includes the tx with shape {txid, fee, vsize, value}.
    let v = esplora_get_json(&esplora, "/mempool/recent");
    let arr = v.as_array().expect("recent array");
    let entry = arr
        .iter()
        .find(|e| e["txid"].as_str() == Some(txid_hex.as_str()))
        .unwrap_or_else(|| panic!("broadcast tx not in /mempool/recent; got {:?}", arr));
    assert_eq!(entry["fee"], 1000);
    assert!(entry["vsize"].as_u64().unwrap_or(0) > 0);
    assert!(
        entry["value"].as_u64().unwrap_or(0) > 0,
        "value field is sum of output values"
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_fee_estimates_keys() {
    // /fee-estimates must always return the full target set so
    // BDK / mempool-sdk consumers can index into it without
    // missing-key handling. Confirmation targets are pinned in
    // `mempool::FEE_TARGETS`.
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let v = esplora_get_json(&esplora, "/fee-estimates");
    let obj = v.as_object().expect("fee-estimates object");
    // Sentinel keys from the FEE_TARGETS array in mempool.rs — must
    // always be present even on a fresh chain (the handler falls back
    // to 1.0 sat/vB when the estimator has no data).
    for target in ["1", "2", "6", "10", "20", "144", "504", "1008"] {
        let v = obj.get(target).unwrap_or_else(|| {
            panic!(
                "fee-estimates missing target '{}'; got keys {:?}",
                target,
                obj.keys().collect::<Vec<_>>()
            )
        });
        assert!(
            v.as_f64().is_some_and(|f| f > 0.0),
            "fee-estimates['{}'] must be positive float, got {}",
            target,
            v
        );
    }
    e2e.node.stop();
}

// ─────────────────────────────────────────────────────────────────────
// Electrum suite (driven by third-party `electrum-client` crate)
// ─────────────────────────────────────────────────────────────────────

fn electrum_e2e_args() -> Vec<&'static str> {
    // `--electrum=1` triggers the harness's txindex auto-coupling
    // (`common/mod.rs::start_with_env`); addressindex is on by default.
    vec!["--electrum=1", "--electrumbind=127.0.0.1:0"]
}

fn electrum_url_for(e2e: &E2eNode) -> String {
    let port = e2e
        .electrum_port
        .expect("E2eNode booted with --electrum=1 and --electrumbind=127.0.0.1:0");
    format!("tcp://127.0.0.1:{}", port)
}

#[test]
fn test_e2e_electrum_server_features_from_third_party_client() {
    // The whole point of using a third-party client: if our framer or
    // serde shapes are wrong, this single call fails before any of the
    // surface-specific tests do.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let client =
        electrum_client::Client::new(&electrum_url_for(&e2e)).expect("electrum client connect");
    let features = client.server_features().expect("server_features");

    // The regtest genesis hash, big-endian display order:
    //   0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
    // Compare against the bitcoin crate's authoritative value rather
    // than a hand-typed constant so a future regtest-params change
    // doesn't silently invalidate the test.
    let expected = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let expected_hex = expected.to_string();
    let got_hex = hex::encode(features.genesis_hash);
    assert_eq!(
        got_hex.to_lowercase(),
        expected_hex.to_lowercase(),
        "genesis_hash mismatch"
    );
    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_headers_subscribe_notification() {
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum client connect");

    // Subscribe to header notifications. The initial reply already
    // carries the current tip (height 0, regtest genesis header).
    let initial = client.block_headers_subscribe().expect("subscribe");
    assert_eq!(initial.height, 0, "fresh regtest tip should be 0");

    // Mine 1 block via the inner JSON-RPC. The server should send a
    // header notification; poll `block_headers_pop` until it returns
    // Some(header) at the new height.
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress");

    // `electrum-client` only reads from the socket when an RPC method
    // is called; it has no background reader thread. So a bare
    // `block_headers_pop` against an idle client always returns None,
    // even when notifications are waiting on the wire. `ping()` is
    // the cheapest call we can issue to drain the read buffer into
    // the notification queue. Same pattern in the scripthash
    // subscribe test below.
    let deadline = std::time::Instant::now() + e2e_test_timeout(10);
    loop {
        client.ping().expect("ping");
        if let Some(notif) = client.block_headers_pop().expect("headers pop") {
            assert_eq!(notif.height, 1, "expected height 1, got {}", notif.height);
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no header notification received within deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_scripthash_get_history_for_funded_address() {
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    // Mine 3 blocks to a known P2WPKH; the address has 3 coinbase
    // outputs (one per block). Electrum's history returns one entry
    // per tx that touches the scripthash.
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(3),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 3");

    let script = wallet.address.script_pubkey();
    let history = client
        .script_get_history(&script)
        .expect("script_get_history");
    assert_eq!(
        history.len(),
        3,
        "expected 3 history entries, got {:?}",
        history
    );
    let heights: Vec<i32> = history.iter().map(|h| h.height).collect();
    let mut sorted = heights.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![1, 2, 3],
        "expected heights 1, 2, 3; got {:?}",
        heights
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_transaction_broadcast() {
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_script = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest")
        .script_pubkey();
    let (raw_hex, expected_txid_str) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &wallet, dest_script, 1000);
    let raw_bytes = hex::decode(&raw_hex).expect("hex");

    // Broadcast via the third-party Electrum client.
    let txid = client
        .transaction_broadcast_raw(&raw_bytes)
        .expect("transaction_broadcast_raw");
    assert_eq!(
        txid.to_string(),
        expected_txid_str,
        "broadcast txid round-trip"
    );

    // Round-trip via `transaction.get`: fetch the raw bytes back. The
    // server reads from mempool here (tx not yet mined).
    let fetched = client
        .transaction_get_raw(&txid)
        .expect("transaction_get_raw");
    assert_eq!(
        hex::encode(&fetched),
        raw_hex,
        "transaction_get_raw should return the broadcast bytes verbatim"
    );

    // Mine and verify the merkle proof.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("confirm block");

    // Allow a beat for indexes / tx-location to flip. The merkle
    // fetch needs the height (`102`) and the server reads from the
    // confirmed block.
    let deadline = std::time::Instant::now() + e2e_test_timeout(10);
    let merkle = loop {
        match client.transaction_get_merkle(&txid, 102) {
            Ok(m) if m.block_height == 102 => break m,
            Ok(_) | Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            panic!("transaction_get_merkle didn't reach block 102 within deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };

    // Block at height 102 has exactly two transactions: the coinbase
    // (pos 0) plus our spend (pos 1). The merkle proof for pos 1
    // contains a single sibling — the coinbase txid.
    assert_eq!(
        merkle.pos, 1,
        "spend should be at pos 1 (right of the coinbase); got pos {}",
        merkle.pos
    );
    assert_eq!(
        merkle.merkle.len(),
        1,
        "2-tx block must yield a 1-element merkle branch; got {} elements",
        merkle.merkle.len()
    );

    // Independent verification: recompute the merkle root from the
    // proof and compare against the on-chain header. This is the
    // *security surface* the Electrum protocol exposes — without
    // this check the server could return a syntactically valid but
    // semantically broken proof and the test would still pass.
    let block102_hash_str = e2e
        .node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(102)])
        .expect("getblockhash 102")["result"]
        .as_str()
        .expect("block hash")
        .to_string();
    let raw_block_hex = e2e
        .node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block102_hash_str), serde_json::json!(0)],
        )
        .expect("getblock verbosity 0")["result"]
        .as_str()
        .expect("raw block hex")
        .to_string();
    let raw_block = hex::decode(&raw_block_hex).expect("decode block hex");
    let block: bitcoin::Block =
        bitcoin::consensus::deserialize(&raw_block).expect("deserialize block");
    let expected_root = block.header.merkle_root;
    let computed_root = recompute_merkle_root(&txid, &merkle.merkle, merkle.pos);
    assert_eq!(
        computed_root, expected_root,
        "merkle proof failed to recompute the block's merkle root; \
         computed {}, expected {}",
        computed_root, expected_root
    );

    e2e.node.stop();
}

/// Recompute a Bitcoin merkle root from a leaf txid + proof + index.
/// Electrum's `blockchain.transaction.get_merkle` returns siblings as
/// hex strings in display (big-endian) byte order; `electrum-client`'s
/// `from_hex` for `[u8; 32]` produces the bytes in that same display
/// order. Bitcoin's internal SHA256d operates on the natural
/// (little-endian) byte order, so each sibling is reversed before
/// hashing. The starting leaf (`txid.to_byte_array()`) is already in
/// natural order.
fn recompute_merkle_root(
    txid: &bitcoin::Txid,
    branch: &[[u8; 32]],
    pos: usize,
) -> bitcoin::TxMerkleNode {
    use bitcoin::hashes::Hash;
    let mut current: [u8; 32] = txid.to_byte_array();
    let mut p = pos;
    for sibling_display in branch {
        let mut sibling_internal = *sibling_display;
        sibling_internal.reverse();
        let mut combined = [0u8; 64];
        if p & 1 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(&sibling_internal);
        } else {
            combined[..32].copy_from_slice(&sibling_internal);
            combined[32..].copy_from_slice(&current);
        }
        current = bitcoin::hashes::sha256d::Hash::hash(&combined).to_byte_array();
        p >>= 1;
    }
    let hash = bitcoin::hashes::sha256d::Hash::from_byte_array(current);
    bitcoin::TxMerkleNode::from_raw_hash(hash)
}

#[test]
fn test_e2e_electrum_scripthash_subscribe_fires_on_mempool() {
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let src_wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(src_wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest_addr = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest");
    let dest_script = dest_addr.script_pubkey();

    // Subscribe to dest BEFORE broadcasting. Initial status is None
    // (no history) — that's expected.
    let initial = client
        .script_subscribe(&dest_script)
        .expect("script_subscribe");
    assert!(
        initial.is_none(),
        "dest should start with empty status, got {:?}",
        initial
    );

    // Broadcast the funding tx via JSON-RPC (we already tested the
    // Electrum broadcast path above; here the publisher is JSON-RPC,
    // so a successful notification proves the mempool→index→
    // subscription pipeline works regardless of which surface
    // broadcasts).
    let (raw_hex, _txid_str) = build_signed_p2wpkh_spend_from_block1_coinbase(
        &e2e.node,
        &src_wallet,
        dest_script.clone(),
        1000,
    );
    let _ = e2e
        .node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .expect("sendrawtransaction");

    // Poll for a status update on the dest scripthash. Bound at 20s
    // (more generous than other tests because the mempool→notify
    // hop is the highest-latency path in the suite). If this flakes
    // even once in 10 runs, the bug is in the publisher/forwarder,
    // not the test.
    // See note on `electrum-client`'s lack of a background reader in
    // the headers test above; `ping()` each iteration drains the
    // socket into the notification queue.
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    loop {
        client.ping().expect("ping");
        if client
            .script_pop(&dest_script)
            .expect("script_pop")
            .is_some()
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no scripthash notification received within deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_block_header_and_headers_suite() {
    // Boot once, mine 5, then assert block.header / block.headers
    // round-trip cleanly. Wallets like Sparrow / BlueWallet rely on
    // these for header-chain verification — wire-shape drift here
    // breaks SPV proofs.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(5),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 5");

    // block_header(0) returns regtest genesis. The genesis hash is
    // pinned in `bitcoin::blockdata::constants` — a deserialize-then-
    // compute-hash round trip ties the wire format to a known value.
    let h0 = client.block_header(0).expect("block_header 0");
    let regtest_genesis =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    assert_eq!(
        h0.block_hash(),
        regtest_genesis,
        "block_header(0) must be regtest genesis"
    );

    // block_header(3) returns a header whose hash matches the same
    // hash JSON-RPC returns for getblockhash(3).
    let h3_via_rpc = e2e
        .node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(3)])
        .expect("getblockhash 3")["result"]
        .as_str()
        .expect("hash string")
        .to_string();
    let h3 = client.block_header(3).expect("block_header 3");
    assert_eq!(
        h3.block_hash().to_string(),
        h3_via_rpc,
        "Electrum block_header(3) must match JSON-RPC getblockhash(3)"
    );

    // block_headers(0, 6) returns 6 contiguous headers starting at
    // genesis. The first header's hash must equal regtest genesis;
    // each consecutive header's prev_blockhash must equal the
    // previous header's hash (chain linkage invariant).
    let res = client.block_headers(0, 6).expect("block_headers 0..6");
    assert_eq!(res.count, 6, "asked for 6, got count={}", res.count);
    assert_eq!(res.headers.len(), 6, "headers array length");
    assert_eq!(
        res.headers[0].block_hash(),
        regtest_genesis,
        "first header is regtest genesis"
    );
    for (i, w) in res.headers.windows(2).enumerate() {
        assert_eq!(
            w[1].prev_blockhash,
            w[0].block_hash(),
            "headers[{}].prev_blockhash must equal headers[{}].block_hash()",
            i + 1,
            i
        );
    }

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_scripthash_balance_and_listunspent() {
    // Wallets call get_balance + listunspent every time they refresh
    // a watched address. The shape must stay stable across regressions.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let spk = wallet.address.script_pubkey();

    // Mine 5 immediately-spendable coinbases. (101 isn't needed here:
    // we don't spend, we just observe balance / listunspent.) Each
    // coinbase yields 50 BTC subsidy on regtest pre-halving.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(5),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 5");

    // The electrum-client wraps the wire-level reversed-hex scripthash
    // derivation; pass it the raw scriptPubKey.
    let bal = client.script_get_balance(&spk).expect("script_get_balance");
    // 5 coinbases * 50 BTC * 1e8 sat/BTC. Coinbase isn't matured for
    // spend (101 confs needed), but Electrum's balance just sums
    // confirmed outputs — so all 5 count here.
    assert_eq!(
        bal.confirmed,
        5 * 50 * 100_000_000,
        "confirmed balance = 5 × 50 BTC subsidy"
    );

    let utxos = client
        .script_list_unspent(&spk)
        .expect("script_list_unspent");
    assert_eq!(utxos.len(), 5, "5 mined coinbases → 5 UTXOs");
    for u in &utxos {
        assert_eq!(u.value, 50 * 100_000_000, "each coinbase = 50 BTC");
        assert_eq!(u.tx_pos, 0, "coinbase output is at vout=0");
        assert!(
            (1..=5).contains(&u.height),
            "coinbase height in [1, 5], got {}",
            u.height
        );
    }

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_merkle_and_id_from_pos_round_trip() {
    // Wallets verify confirmations by:
    //   1. calling `transaction_get_merkle(txid, height)` to get the
    //      branch + pos
    //   2. independently asking for `txid_from_pos(height, pos)` and
    //      confirming it matches their txid
    // Both must agree, and the merkle path must reconstruct the
    // block's merkleroot. Wire-shape drift here breaks every SPV
    // wallet that talks to satd.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest");
    let (raw_hex, txid_hex) = build_signed_p2wpkh_spend_from_block1_coinbase(
        &e2e.node,
        &wallet,
        dest.script_pubkey(),
        1000,
    );
    let txid = bitcoin::Txid::from_str(&txid_hex).expect("txid parse");

    // Broadcast + confirm at height 102.
    let _ = client
        .transaction_broadcast_raw(&hex::decode(&raw_hex).expect("hex"))
        .expect("transaction_broadcast_raw");
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 1");

    // txid_from_pos(102, 1) returns our spend (coinbase at pos=0).
    let from_pos = client.txid_from_pos(102, 1).expect("txid_from_pos(102, 1)");
    assert_eq!(
        from_pos, txid,
        "txid_from_pos(102, 1) must equal the spend's txid"
    );

    // transaction_get_merkle returns (block_height=102, pos=1, branch).
    let merkle = client
        .transaction_get_merkle(&txid, 102)
        .expect("transaction_get_merkle");
    assert_eq!(merkle.block_height, 102);
    assert_eq!(merkle.pos, 1, "spend at index 1 in block 102");

    // Reconstruct merkle root from branch and compare against the
    // block's merkleroot via JSON-RPC. Catches any drift in branch
    // ordering, byte direction, or pair-hash composition.
    let recomputed = recompute_merkle_root(&txid, &merkle.merkle, merkle.pos);
    let block_hash = e2e
        .node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(102)])
        .expect("getblockhash 102")["result"]
        .as_str()
        .expect("hash")
        .to_string();
    let expected_root = e2e
        .node
        .rpc_call_with_params("getblockheader", vec![serde_json::json!(block_hash)])
        .expect("getblockheader")["result"]["merkleroot"]
        .as_str()
        .expect("merkleroot")
        .to_string();
    assert_eq!(
        recomputed.to_string(),
        expected_root,
        "reconstructed root from Electrum merkle proof must match block merkleroot"
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_estimatefee_and_relayfee() {
    // estimatefee / relayfee are the two fee endpoints every wallet
    // calls before composing a tx. Both return BTC/kB on the wire;
    // satd's internal unit is sat per 1000 weight units, so a
    // conversion regression has historically been a 4x error
    // (see electrum-proto blockchain.rs sat_per_1000_wu_to_btc_per_kb).
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    // relay_fee always has a value because it reflects the mempool
    // admission floor (a static operator config, not estimator data).
    let relay = client.relay_fee().expect("relay_fee");
    assert!(
        relay > 0.0 && relay < 1.0,
        "relay_fee should be a small positive BTC/kB, got {}",
        relay
    );

    // estimate_fee on a fresh chain has no real estimator data;
    // satd returns -1.0 as a sentinel. Either a positive estimate
    // OR -1.0 is acceptable wire behavior — both are valid Electrum
    // responses (-1.0 mirrors what Electrum servers return when they
    // can't form an estimate).
    let est = client.estimate_fee(6, None).expect("estimate_fee");
    assert!(
        est == -1.0 || est > 0.0,
        "estimate_fee should be -1.0 (no data) or a positive BTC/kB, got {}",
        est
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_ping_and_server_features_genesis() {
    // ping() is the heartbeat every long-lived wallet uses to keep
    // the connection alive. server_features.genesis_hash pins the
    // network — wallets compare it to a hardcoded constant before
    // syncing. A wire-format regression on either is severe.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    client.ping().expect("ping must succeed");

    let features = client.server_features().expect("server_features");
    // server_features.genesis_hash is reported in display-byte order
    // as a [u8; 32] array. Compare against the regtest genesis
    // constant computed from rust-bitcoin's tables.
    let regtest_genesis =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    // genesis_hash field on the server_features response is the raw
    // 32-byte hash in **display** order (Electrum sends reversed-hex).
    // Compare via string representation to sidestep byte-order
    // questions: convert both to natural-hex then compare.
    let from_features = hex::encode(features.genesis_hash);
    let expected = regtest_genesis.to_string();
    assert_eq!(
        from_features, expected,
        "server_features.genesis_hash must match regtest genesis"
    );

    e2e.node.stop();
}

#[test]
fn test_e2e_electrum_scripthash_unsubscribe_returns_true() {
    // satd's scripthash.unsubscribe always returns true (the per-
    // connection subscription state is implicit on disconnect; the
    // explicit unsubscribe RPC is a wire-shape compatibility shim).
    // This test pins that behavior so a future refactor that
    // accidentally returns false / 0 / null gets caught.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let spk = wallet.address.script_pubkey();

    // Subscribe, then unsubscribe. Both should succeed on the wire.
    // electrum-client tracks subscription state on the client side and
    // refuses to send a second unsubscribe — that path is exercised
    // by the client's own unit tests; what we're testing here is the
    // server's wire response, which is what wallets read.
    let _ = client.script_subscribe(&spk).expect("script_subscribe");
    let ok = client.script_unsubscribe(&spk).expect("script_unsubscribe");
    assert!(ok, "scripthash_unsubscribe must return true");

    e2e.node.stop();
}

#[test]
fn test_e2e_jsonrpc_sat_cli_auth_failure_shape() {
    // Boot a node so sat-cli has something to connect to, but ignore
    // the real cookie path and pass a deliberately-wrong rpcuser /
    // rpcpassword via the CLI. This exercises sat-cli's HTTP auth
    // path (the same path `reqwest`-driven tests do not cover) and
    // the JSON-RPC server's 401 response.
    let mut e2e = E2eNode::boot_with(&[]);
    let output = sat_cli_for(&e2e.node)
        .arg("--rpcuser=wrong")
        .arg("--rpcpassword=wrong")
        .arg("getblockchaininfo")
        .output()
        .expect("run sat-cli with wrong auth");
    assert!(
        !output.status.success(),
        "sat-cli with wrong auth must exit non-zero; got status={:?}, stdout={}",
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("unauthorized") || stderr.contains("401") || stderr.contains("auth"),
        "stderr should signal an auth failure; got: {}",
        stderr
    );
    e2e.node.stop();
}

// ─────────────────────────────────────────────────────────────────────
// Cross-surface test (the merge gate)
// ─────────────────────────────────────────────────────────────────────
//
// The single test below is the whole reason this work exists: it
// asserts the shared-chainstate / one-process / one-RocksDB guarantee
// that justifies satd's architecture. A tx broadcast through Esplora's
// `POST /tx` must:
//
//   * appear in JSON-RPC `getrawmempool` (proves the broadcast wrote to
//     the same `Mempool` instance the RPC reads from);
//   * fire an Electrum `scripthash.subscribe` notification on the dest
//     scripthash (proves the mempool→index→subscription pipeline
//     remains correct, with scripthash derivation matching across
//     Esplora and Electrum);
//   * then, after mining, flip `status.confirmed` to `true` on Esplora's
//     `GET /tx/:txid` (proves the confirm path is wired symmetrically).
//
// Failure modes this single test catches that nothing else does:
//   * Esplora's `/tx` handler accepts the body but writes to a
//     different `Mempool` instance than the index reads from.
//   * Mempool→index update fires but `maybe_notify` is called with the
//     wrong scripthash (Esplora/Electrum derivation mismatch).
//   * Notification fires but the per-conn `scripthash_forwarder` task
//     is wedged.
//   * RPC `getrawmempool` reads a stale snapshot.

#[test]
fn test_e2e_cross_surface_esplora_broadcast_visible_in_rpc_and_electrum() {
    use electrum_client::ElectrumApi;
    // Boot with all three surfaces. `--esplora=1` triggers the
    // harness's txindex auto-coupling; addressindex is on by default;
    // `--electrum=1` brings up the TCP listener.
    let mut e2e = E2eNode::boot_with(&[
        "--esplora=1",
        "--esplorabind=127.0.0.1:0",
        "--electrum=1",
        "--electrumbind=127.0.0.1:0",
    ]);
    let esplora = esplora_for(&e2e);
    let electrum = electrum_client::Client::new(&electrum_url_for(&e2e)).expect("electrum connect");

    // Source wallet + dest burn address.
    let src_wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let dest_addr_str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let dest_addr = bitcoin::Address::from_str(dest_addr_str)
        .expect("valid bech32")
        .require_network(bitcoin::Network::Regtest)
        .expect("regtest");
    let dest_script = dest_addr.script_pubkey();

    // Mature block-1 coinbase so the spend can use it.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(src_wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    // Subscribe via Electrum BEFORE broadcasting so the notification
    // is queued the moment the mempool admit fires.
    let initial = electrum
        .script_subscribe(&dest_script)
        .expect("script_subscribe");
    assert!(
        initial.is_none(),
        "dest should start with empty status, got {:?}",
        initial
    );

    // Build the spend (block-1 coinbase → dest, 1000-sat fee).
    let (raw_hex, txid_hex) = build_signed_p2wpkh_spend_from_block1_coinbase(
        &e2e.node,
        &src_wallet,
        dest_script.clone(),
        1000,
    );

    // *** Broadcast via Esplora. *** This is the cross-surface
    // critical path: a write on Esplora must propagate to both
    // JSON-RPC (read) and Electrum (subscription).
    let resp = esplora.post_tx(&raw_hex);
    assert_eq!(
        resp.status(),
        200,
        "Esplora POST /tx must succeed; got {}",
        resp.status()
    );
    let body = resp.text().expect("body utf8");
    assert_eq!(
        body.trim(),
        txid_hex,
        "Esplora POST /tx body must match txid"
    );

    // (a) JSON-RPC `getrawmempool` must show the txid within 10s.
    let rpcport = e2e.node.rpcport;
    let cookie = e2e.node.cookie.clone();
    let want_txid = txid_hex.clone();
    common::poll_until_json(
        || rpc_post(rpcport, &cookie, "getrawmempool", &[]),
        |v| {
            v["result"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(want_txid.as_str())))
        },
        10,
    );

    // (b) Electrum `scripthash.subscribe` must fire on the dest
    // scripthash. Same `ping()` interleave as the PR-4 subscribe
    // test — `electrum-client` has no background reader thread.
    let deadline = std::time::Instant::now() + e2e_test_timeout(10);
    loop {
        electrum.ping().expect("ping");
        if electrum
            .script_pop(&dest_script)
            .expect("script_pop")
            .is_some()
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("no Electrum scripthash notification within deadline after Esplora broadcast");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Mine 1 block to confirm. After this, all three surfaces should
    // see the spend as confirmed.
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(1),
                serde_json::json!(src_wallet.address.to_string()),
            ],
        )
        .expect("confirm block");

    // RPC mempool drains.
    common::poll_until_json(
        || rpc_post(rpcport, &cookie, "getrawmempool", &[]),
        |v| v["result"].as_array().is_some_and(|a| a.is_empty()),
        10,
    );

    // Esplora `GET /tx/:txid` flips to confirmed.
    let tx_path = format!("/tx/{}", txid_hex);
    common::poll_until_json(
        || esplora_get_json(&esplora, &tx_path),
        |v| v["status"]["confirmed"] == true,
        10,
    );

    e2e.node.stop();
}
