//! Replies a live regtest node sends, checked against Bitcoin Core: number
//! text (`UniValue::setFloat` and `ValueFromAmount`), `submitblock`'s decode
//! error (src/rpc/mining.cpp), `getblockfilter`'s refusals
//! (src/rpc/blockchain.cpp), the failed-password log line and pause
//! (src/httprpc.cpp), and how integer and verbosity arguments are parsed
//! (`UniValue::getInt`, `ParseVerbosity`).

mod common;

use std::time::{Duration, Instant};

use common::{TestNode, poll_until, test_timeout};
use serde_json::{Value, json};

/// The `error` of a call the node must refuse, as `(code, message)`.
fn refused(node: &TestNode, method: &str, params: Vec<Value>) -> (i64, String) {
    let resp = node
        .rpc_call_with_params(method, params.clone())
        .expect("node reachable");
    let err = &resp["error"];
    assert!(
        !err.is_null(),
        "{method}{params:?} must be refused; got {resp}"
    );
    (
        err["code"].as_i64().expect("error code"),
        err["message"].as_str().expect("error message").to_string(),
    )
}

#[test]
fn numbers_on_the_wire_are_printed_as_core_prints_them() {
    let mut node = TestNode::start(&[]);

    // A double with 16 significant digits, not the shortest round trip.
    assert_eq!(
        node.rpc_ok("getdifficulty", vec![]).to_string(),
        "4.656542373906925e-10"
    );
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
    assert_eq!(
        node.rpc_call_raw_status("getblockchaininfo", "wrong", "credentials"),
        401
    );
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

/// A JSON number exactly as written, so `1.0`, `1e0` and `-0` reach the node
/// as those characters (the workspace's `serde_json` keeps number text).
fn num(text: &str) -> Value {
    serde_json::from_str(text).expect("a JSON number")
}

/// Integer and verbosity arguments are read as Core v32.1 reads them:
/// `UniValue::getInt<T>` for the integer (a fraction, an exponent, or a value
/// outside the C++ type is -1 "JSON integer out of range"), then each
/// method's own range check. Every expectation here was captured from a
/// v32.1 `bitcoind -regtest` sent the same JSON (#1267).
#[test]
fn integer_and_verbosity_arguments_are_parsed_as_core_parses_them() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_ok("generatetoaddress", vec![json!(10), json!(addr)]);
    let b = node.rpc_ok("getblockhash", vec![json!(1)]);
    let t = node.rpc_ok("getblock", vec![b.clone(), json!(1)])["tx"][0].clone();
    let range = || (-1, "JSON integer out of range".to_string());
    let p = |code: i64, msg: &str| (code, msg.to_string());

    let cases: Vec<(&str, Vec<Value>, (i64, String))> = vec![
        (
            "getblockhash",
            vec![num("-1")],
            p(-8, "Block height out of range"),
        ),
        (
            "getblockhash",
            vec![num("11")],
            p(-8, "Block height out of range"),
        ),
        ("getblockhash", vec![num("2147483648")], range()),
        ("getblockhash", vec![num("-2147483649")], range()),
        ("getblockhash", vec![num("1.5")], range()),
        ("getblockhash", vec![num("1.0")], range()),
        ("getblockhash", vec![num("1e0")], range()),
        ("getblockhash", vec![num("99999999999999999999")], range()),
        ("getblock", vec![b.clone(), num("-2147483649")], range()),
        ("getblock", vec![b.clone(), num("2147483648")], range()),
        ("getblock", vec![b.clone(), num("1.5")], range()),
        (
            "getrawtransaction",
            vec![t.clone(), num("2147483648"), b.clone()],
            range(),
        ),
        (
            "getrawtransaction",
            vec![t.clone(), num("1.5"), b.clone()],
            range(),
        ),
        ("gettxout", vec![t.clone(), num("-1")], range()),
        ("gettxout", vec![t.clone(), num("4294967296")], range()),
        ("gettxout", vec![t.clone(), num("0.5")], range()),
        ("waitforblockheight", vec![num("2147483648")], range()),
        (
            "waitforblockheight",
            vec![num("5"), num("-1")],
            p(-1, "Negative timeout"),
        ),
        (
            "waitforblockheight",
            vec![num("5"), num("2147483648")],
            range(),
        ),
        ("waitforblockheight", vec![num("-1"), num("1.5")], range()),
        (
            "waitfornewblock",
            vec![num("-1")],
            p(-1, "Negative timeout"),
        ),
        (
            "waitforblock",
            vec![b.clone(), num("-1")],
            p(-1, "Negative timeout"),
        ),
        (
            "getblockstats",
            vec![num("-1")],
            p(-8, "Target block height -1 is negative"),
        ),
        (
            "getblockstats",
            vec![num("11")],
            p(-8, "Target block height 11 after current tip 10"),
        ),
        ("getblockstats", vec![num("2147483648")], range()),
        ("getblockstats", vec![num("1.5")], range()),
        (
            "getchaintxstats",
            vec![num("-1")],
            p(
                -8,
                "Invalid block count: should be between 0 and the block's height - 1",
            ),
        ),
        (
            "getchaintxstats",
            vec![num("10")],
            p(
                -8,
                "Invalid block count: should be between 0 and the block's height - 1",
            ),
        ),
        ("getchaintxstats", vec![num("2147483648")], range()),
        ("getchaintxstats", vec![num("1.5")], range()),
        // Not a pruning node: Core's prune-mode check precedes `getInt`.
        (
            "pruneblockchain",
            vec![num("1.5")],
            p(-1, "Cannot prune blocks because node is not in prune mode."),
        ),
        ("getnetworkhashps", vec![num("2147483648")], range()),
        (
            "getnetworkhashps",
            vec![num("120"), num("2147483648")],
            range(),
        ),
        ("getnetworkhashps", vec![num("1.5")], range()),
        (
            "estimatesmartfee",
            vec![num("-1")],
            p(-8, "Invalid conf_target, must be between 1 and 1008"),
        ),
        ("estimatesmartfee", vec![num("2147483648")], range()),
        ("estimatesmartfee", vec![num("1.5")], range()),
        // The target is parsed before the mode.
        (
            "estimatesmartfee",
            vec![num("-1"), json!("bogus")],
            p(-8, "Invalid conf_target, must be between 1 and 1008"),
        ),
        (
            "estimaterawfee",
            vec![num("-1")],
            p(-8, "Invalid conf_target, must be between 1 and 1008"),
        ),
        ("estimaterawfee", vec![num("2147483648")], range()),
        ("estimaterawfee", vec![num("1.5")], range()),
        ("verifychain", vec![num("2147483648")], range()),
        ("verifychain", vec![num("3"), num("2147483648")], range()),
        (
            "generatetoaddress",
            vec![num("2147483648"), json!(addr)],
            range(),
        ),
        (
            "generatetoaddress",
            vec![num("0"), json!(addr), num("2147483648")],
            range(),
        ),
        (
            "generatetodescriptor",
            vec![num("2147483648"), json!("raw(51)")],
            range(),
        ),
        (
            "generatetodescriptor",
            vec![num("0"), json!("raw(51)"), num("-1")],
            range(),
        ),
        ("getorphantxs", vec![num("2147483648")], range()),
        (
            "getorphantxs",
            vec![num("-1")],
            p(-8, "Invalid verbosity value -1"),
        ),
        (
            "createrawtransaction",
            vec![json!([]), json!({}), num("1.5")],
            range(),
        ),
        (
            "createrawtransaction",
            vec![json!([]), json!({}), num("-1")],
            p(-8, "Invalid parameter, locktime out of range"),
        ),
        (
            "createpsbt",
            vec![json!([]), json!({}), num("-1")],
            p(-8, "Invalid parameter, locktime out of range"),
        ),
        (
            "createpsbt",
            vec![json!([]), json!({}), num("0"), json!(true), num("-1")],
            range(),
        ),
        (
            "createpsbt",
            vec![
                json!([]),
                json!({}),
                num("0"),
                json!(true),
                num("4294967296"),
            ],
            range(),
        ),
        (
            "setban",
            vec![json!("10.0.0.2"), json!("add"), num("9223372036854775808")],
            range(),
        ),
        (
            "disconnectnode",
            vec![json!(""), num("-1")],
            p(-29, "Node not found in connected nodes"),
        ),
        (
            "disconnectnode",
            vec![json!(""), num("9223372036854775808")],
            range(),
        ),
        ("getnodeaddresses", vec![num("2147483648")], range()),
        (
            "getblockfrompeer",
            vec![b.clone(), num("9223372036854775808")],
            range(),
        ),
        (
            "sendmsgtopeer",
            vec![num("-1"), json!("ping"), json!("")],
            p(-1, "Error: Could not send message to peer"),
        ),
        (
            "prioritisetransaction",
            vec![t.clone(), num("0"), num("9223372036854775808")],
            range(),
        ),
        ("setmocktime", vec![num("9223372036854775808")], range()),
        (
            "setmocktime",
            vec![num("-1")],
            p(-8, "Mocktime must be in the range [0, 4294967295], not -1."),
        ),
        (
            "setmocktime",
            vec![num("4294967296")],
            p(
                -8,
                "Mocktime must be in the range [0, 4294967295], not 4294967296.",
            ),
        ),
    ];
    let mut wrong = Vec::new();
    for (method, params, want) in cases {
        let resp = node
            .rpc_call_with_params(method, params.clone())
            .expect("node reachable");
        let err = &resp["error"];
        let got = (
            err["code"].as_i64().unwrap_or(0),
            err["message"].as_str().unwrap_or_default().to_string(),
        );
        if got != want {
            wrong.push(format!(
                "{method} {params:?}: got {resp}, Core answers {want:?}"
            ));
        }
    }
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));

    // What Core accepts, it answers.
    let tip = node.rpc_ok("getbestblockhash", vec![]);
    let genesis = node.rpc_ok("getblockhash", vec![json!(0)]);
    assert_eq!(node.rpc_ok("getblockhash", vec![num("-0")]), genesis);
    // Verbosity at or below 0 is the hex string; past the top level is the top level.
    for v in ["-1", "-2147483648", "0"] {
        assert!(
            node.rpc_ok("getblock", vec![b.clone(), num(v)]).is_string(),
            "getblock {v}"
        );
        assert!(
            node.rpc_ok("getrawtransaction", vec![t.clone(), num(v), b.clone()])
                .is_string(),
            "getrawtransaction {v}"
        );
    }
    let top = node.rpc_ok("getblock", vec![b.clone(), json!(3)]);
    for v in ["4", "2147483647"] {
        assert_eq!(
            node.rpc_ok("getblock", vec![b.clone(), num(v)]),
            top,
            "getblock {v}"
        );
    }
    let top = node.rpc_ok("getrawtransaction", vec![t.clone(), json!(2), b.clone()]);
    for v in ["3", "99", "2147483647"] {
        assert_eq!(
            node.rpc_ok("getrawtransaction", vec![t.clone(), num(v), b.clone()]),
            top,
            "getrawtransaction {v}"
        );
    }
    // A height at or below the tip, negative included, answers at once.
    for h in ["-1", "0"] {
        let r = node.rpc_ok("waitforblockheight", vec![num(h)]);
        assert_eq!(
            (r["hash"].clone(), r["height"].clone()),
            (tip.clone(), json!(10)),
            "{h}"
        );
    }
    assert!(
        node.rpc_ok("gettxout", vec![t.clone(), num("4294967295")])
            .is_null()
    );
    assert_eq!(
        node.rpc_ok("getblockstats", vec![num("-0")])["height"],
        json!(0)
    );
    // `VerifyDB` clamps the level and depth rather than refusing them.
    assert_eq!(
        node.rpc_ok("verifychain", vec![num("-1"), num("-1")]),
        json!(true)
    );
    // A count at or below 0 mines nothing; a negative `maxtries` is a huge budget.
    assert_eq!(
        node.rpc_ok("generatetoaddress", vec![num("-1"), json!(addr)]),
        json!([])
    );
    assert_eq!(
        node.rpc_ok("generatetoaddress", vec![num("0"), json!(addr), num("-1")]),
        json!([])
    );
    assert_eq!(
        node.rpc_ok("generatetodescriptor", vec![num("-1"), json!("raw(51)")]),
        json!([])
    );
    assert_eq!(node.rpc_ok("getblockcount", vec![]), json!(10));
    // A bantime at or below 0 is the default ban.
    assert!(
        node.rpc_ok("setban", vec![json!("10.0.0.1"), json!("add"), num("-1")])
            .is_null()
    );
    let banned = node.rpc_ok("listbanned", vec![]);
    assert_eq!(banned[0]["ban_duration"], json!(86400), "{banned}");

    node.stop();
}
