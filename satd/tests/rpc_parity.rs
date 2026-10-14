//! Replies a live regtest node sends, checked against Bitcoin Core: number
//! text (`UniValue::setFloat` and `ValueFromAmount`), `submitblock`'s decode
//! error (src/rpc/mining.cpp), `getblockfilter`'s refusals
//! (src/rpc/blockchain.cpp), and the failed-password log line and pause
//! (src/httprpc.cpp).

mod common;

use std::time::{Duration, Instant};

use common::{poll_until, test_timeout, TestNode};
use serde_json::{json, Value};

/// The `error` of a call the node must refuse, as `(code, message)`.
fn refused(node: &TestNode, method: &str, params: Vec<Value>) -> (i64, String) {
    let resp = node.rpc_call_with_params(method, params.clone()).expect("node reachable");
    let err = &resp["error"];
    assert!(!err.is_null(), "{method}{params:?} must be refused; got {resp}");
    (
        err["code"].as_i64().expect("error code"),
        err["message"].as_str().expect("error message").to_string(),
    )
}

#[test]
fn numbers_on_the_wire_are_printed_as_core_prints_them() {
    let mut node = TestNode::start(&[]);

    // A double with 16 significant digits, not the shortest round trip.
    assert_eq!(node.rpc_ok("getdifficulty", vec![]).to_string(), "4.656542373906925e-10");
    // `GetNetworkHashPS` returns a bare 0 for a chain with nothing to measure.
    assert_eq!(node.rpc_ok("getnetworkhashps", vec![]).to_string(), "0");
    // Fee floors are amounts: eight decimal places.
    let net = node.rpc_ok("getnetworkinfo", vec![]);
    assert_eq!(net["relayfee"].to_string(), "0.00000100", "{net}");
    assert_eq!(net["incrementalfee"].to_string(), "0.00000100", "{net}");

    node.stop();
}

#[test]
fn submitblock_and_getblockfilter_refuse_with_cores_codes() {
    let mut node = TestNode::start(&[]);

    // Core: RPC_DESERIALIZATION_ERROR, not a BIP 22 result string.
    assert_eq!(
        refused(&node, "submitblock", vec![json!("00")]),
        (-22, "Block decode failed".to_string())
    );

    let genesis = node.rpc_ok("getblockhash", vec![json!(0)]);
    // The node runs without -blockfilterindex.
    assert_eq!(
        refused(&node, "getblockfilter", vec![genesis.clone()]),
        (-1, "Index is not enabled for filtertype basic".to_string())
    );
    assert_eq!(
        refused(&node, "getblockfilter", vec![genesis, json!("unknown")]),
        (-5, "Unknown filtertype".to_string())
    );

    node.stop();
}

#[test]
fn a_wrong_password_is_logged_with_the_peer_address_and_answered_late() {
    let mut node = TestNode::start(&["--loglevel=warn"]);

    let start = Instant::now();
    assert_eq!(node.rpc_call_raw_status("getblockchaininfo", "wrong", "credentials"), 401);
    assert!(
        start.elapsed() >= Duration::from_millis(250),
        "answered after {:?}",
        start.elapsed()
    );
    // The peer address comes from the listener's accept loop.
    let log = || std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    poll_until(
        || log().contains("ThreadRPCServer incorrect password attempt from 127.0.0.1:"),
        test_timeout(10),
        "no incorrect-password line in the log",
    );
    // The right credentials still work.
    assert!(node.rpc_ok("getblockcount", vec![]).is_u64());

    node.stop();
}
