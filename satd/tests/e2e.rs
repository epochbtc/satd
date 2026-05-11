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
    /// Boot a `satd` regtest node with the given extra args, then read
    /// back the bound Esplora / Electrum ports (`None` when the listener
    /// isn't requested or didn't come up). Use `--esplorabind=127.0.0.1:0`
    /// / `--electrumbind=127.0.0.1:0` to get OS-assigned ports.
    pub fn boot_with(extra_args: &[&str]) -> Self {
        let node = TestNode::start(extra_args);
        let (esplora_port, electrum_port) = read_listener_ports(&node);
        E2eNode {
            node,
            esplora_port,
            electrum_port,
        }
    }
}

/// Probe `getserverstatus` and return `(esplora_port, electrum_port)`.
/// Each is `None` when the listener field is null or absent. Used by
/// `boot_with` after startup; the per-listener bind status flips from
/// null to a `{"bind": "host:port"}` object once that listener
/// successfully binds, so this read happens after `TestNode::start`'s
/// own startup poll completes.
fn read_listener_ports(node: &TestNode) -> (Option<u16>, Option<u16>) {
    let resp = match node.rpc_call("getserverstatus") {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let result = &resp["result"];
    let esplora = result["esplora"]["bind"]
        .as_str()
        .and_then(parse_port_from_bind);
    let electrum = result["electrum"]["bind"]
        .as_str()
        .and_then(parse_port_from_bind);
    (esplora, electrum)
}

fn parse_port_from_bind(bind: &str) -> Option<u16> {
    bind.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
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
        |v| {
            v["result"]
                .as_array()
                .is_some_and(|a| a.is_empty())
        },
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

/// Thin helper used by tests that need to drive a JSON-RPC method from
/// inside a `poll_until_json` probe. Mirrors `TestNode::rpc_call_with_params`
/// but returns `Value::Null` on transport failure (lets the predicate
/// loop instead of panicking inside the closure).
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
        .expect("build client");
    client
        .post(format!("http://127.0.0.1:{}/", rpcport))
        .basic_auth(user, Some(pass))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .ok()
        .and_then(|r| r.json::<serde_json::Value>().ok())
        .unwrap_or(serde_json::Value::Null)
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
    assert_eq!(
        body.trim(),
        txid_hex,
        "POST /tx body should be the txid"
    );

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
    common::poll_until_json(
        || {
            let r = EsploraClient::client()
                .get(format!("http://127.0.0.1:{}/mempool/txids", port))
                .send()
                .expect("GET /mempool/txids");
            r.json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null)
        },
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
    common::poll_until_json(
        || {
            let r = esplora.get(&format!("/address/{}/txs", src_str));
            r.json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null)
        },
        |v| {
            v.as_array()
                .is_some_and(|a| a.iter().any(|t| t["txid"].as_str() == Some(want_txid.as_str())))
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
        .get(format!("http://127.0.0.1:{}/blocks/tip/height", esplora.port))
        .basic_auth(user, Some(pass))
        .send()
        .expect("authed GET");
    assert_eq!(r.status(), 200, "authed Esplora request must succeed");
    assert_eq!(r.text().expect("body utf8").trim(), "0");

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
    let port = e2e.electrum_port.expect(
        "E2eNode booted with --electrum=1 and --electrumbind=127.0.0.1:0",
    );
    format!("tcp://127.0.0.1:{}", port)
}

#[test]
fn test_e2e_electrum_server_features_from_third_party_client() {
    // The whole point of using a third-party client: if our framer or
    // serde shapes are wrong, this single call fails before any of the
    // surface-specific tests do.
    use electrum_client::ElectrumApi;
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let client = electrum_client::Client::new(&electrum_url_for(&e2e))
        .expect("electrum client connect");
    let features = client.server_features().expect("server_features");

    // The regtest genesis hash, big-endian display order:
    //   0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
    // Compare against the bitcoin crate's authoritative value rather
    // than a hand-typed constant so a future regtest-params change
    // doesn't silently invalidate the test.
    let expected =
        bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
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
    assert_eq!(history.len(), 3, "expected 3 history entries, got {:?}", history);
    let heights: Vec<i32> = history.iter().map(|h| h.height).collect();
    let mut sorted = heights.clone();
    sorted.sort();
    assert_eq!(sorted, vec![1, 2, 3], "expected heights 1, 2, 3; got {:?}", heights);

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
    let merkle = common::poll_until_json(
        || match client.transaction_get_merkle(&txid, 102) {
            Ok(m) => serde_json::json!({
                "block_height": m.block_height,
                "pos": m.pos,
                "merkle_len": m.merkle.len(),
            }),
            Err(_) => serde_json::Value::Null,
        },
        |v| v["block_height"] == 102,
        10,
    );
    assert!(merkle["pos"].as_u64().unwrap_or(0) >= 1, "spend should not be at pos 0 (coinbase)");

    e2e.node.stop();
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
    assert!(initial.is_none(), "dest should start with empty status, got {:?}", initial);

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
        stderr.contains("unauthorized")
            || stderr.contains("401")
            || stderr.contains("auth"),
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
    let electrum =
        electrum_client::Client::new(&electrum_url_for(&e2e)).expect("electrum connect");

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
    let (raw_hex, txid_hex) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&e2e.node, &src_wallet, dest_script.clone(), 1000);

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
    assert_eq!(body.trim(), txid_hex, "Esplora POST /tx body must match txid");

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
            panic!(
                "no Electrum scripthash notification within deadline after Esplora broadcast"
            );
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
    let want_txid_for_esplora = txid_hex.clone();
    common::poll_until_json(
        || {
            let r = esplora.get(&format!("/tx/{}", want_txid_for_esplora));
            r.json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null)
        },
        |v| v["status"]["confirmed"] == true,
        10,
    );

    e2e.node.stop();
}
