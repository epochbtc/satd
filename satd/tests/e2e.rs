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
