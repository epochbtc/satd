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
    // observation that the tx is now in block 102 (the block we just
    // mined after the broadcast). satd's verbose response currently
    // emits `blockheight` but not `confirmations`; that omission is a
    // Core-compat gap to fix in a follow-up. For this test the
    // `blockheight` match is sufficient: it proves the spend is mined
    // at the expected position.
    let raw = rpc_post(
        rpcport,
        &cookie,
        "getrawtransaction",
        &[serde_json::json!(txid_hex), serde_json::json!(true)],
    );
    assert_eq!(
        raw["result"]["blockheight"], 102,
        "tx should be mined in block 102; got {}",
        raw
    );

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
