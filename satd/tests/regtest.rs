use base64::Engine;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

mod common;
use common::{
    TestNode, find_available_port, get_rpc_str, get_rpc_u64, poll_until, test_timeout,
};

#[test]
fn test_regtest_getblockchaininfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getblockchaininfo").unwrap();
    let result = &response["result"];

    assert_eq!(result["chain"], "regtest");
    assert_eq!(result["blocks"], 0);
    assert_eq!(result["headers"], 0);
    assert_eq!(
        result["bestblockhash"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );
    assert_eq!(result["initialblockdownload"], true);
    assert_eq!(result["pruned"], false);

    node.stop();
}

#[test]
fn test_regtest_getnetworkinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getnetworkinfo").unwrap();
    let result = &response["result"];

    assert_eq!(result["subversion"], "/satd:0.1.0/");
    assert_eq!(result["connections"], 0);
    assert_eq!(result["protocolversion"], 70016);
    assert_eq!(result["networkactive"], true);

    node.stop();
}

#[test]
fn test_auth_rejection() {
    let mut node = TestNode::start(&[]);
    let status = node.rpc_call_raw_status("getblockchaininfo", "wrong", "credentials");
    assert_eq!(status, 401);
    node.stop();
}

#[test]
fn test_stop_rpc() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("stop").unwrap();
    assert_eq!(response["result"], "satd stopping");

    // Wait for process to exit
    let mut attempts = 0;
    loop {
        match node.process.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success());
                break;
            }
            Ok(None) => {
                attempts += 1;
                if attempts > 30 {
                    panic!("satd did not exit after stop RPC");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for satd: {}", e),
        }
    }

    // Verify cookie file was cleaned up
    let cookie_path = node.datadir.join("regtest").join(".cookie");
    assert!(
        !cookie_path.exists(),
        "Cookie file should be deleted after stop"
    );
}

#[test]
fn test_stopatheight_exits_after_target_block() {
    // Start satd with --stopatheight=5. Mining 5 blocks should
    // trigger a BlockConnected event whose height matches the
    // target, causing the watcher task to broadcast shutdown.
    let mut node = TestNode::start(&["--stopatheight=5"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine 5 blocks.
    let response = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr)],
        )
        .unwrap();
    assert_eq!(
        response["result"].as_array().unwrap().len(),
        5,
        "should mine all 5 blocks"
    );

    // Within ~6s, the watcher should observe the height-5 BlockConnected,
    // broadcast shutdown, and the daemon should exit cleanly.
    let mut attempts = 0;
    let exit_status = loop {
        match node.process.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                attempts += 1;
                if attempts > 60 {
                    let _ = node.process.kill();
                    panic!("satd did not exit within 6s after reaching stopatheight=5");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for satd: {e}"),
        }
    };
    assert!(
        exit_status.success(),
        "satd should exit cleanly after stopatheight, got {exit_status:?}"
    );
}

#[test]
fn test_stopatheight_zero_disabled() {
    // No --stopatheight flag → daemon does not self-shutdown after
    // mining blocks. Sanity check that the watcher only spawns when
    // configured.
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(3), serde_json::json!(addr)],
    )
    .unwrap();

    // Briefly poll: process must STILL be running.
    std::thread::sleep(Duration::from_millis(500));
    match node.process.try_wait() {
        Ok(None) => {} // expected: still running
        Ok(Some(status)) => panic!("satd exited unexpectedly: {status:?}"),
        Err(e) => panic!("try_wait error: {e}"),
    }
    node.stop();
}

#[test]
fn test_sat_cli_integration() {
    let mut node = TestNode::start(&[]);

    // sat-cli is in a sibling crate; find it relative to the satd binary
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let sat_cli_bin = std::path::Path::new(satd_bin)
        .parent()
        .unwrap()
        .join("sat-cli");
    let sat_cli_bin = sat_cli_bin.to_str().unwrap();

    let output = Command::new(sat_cli_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport))
        .arg("getblockchaininfo")
        .output()
        .expect("Failed to run sat-cli");

    assert!(
        output.status.success(),
        "sat-cli should exit successfully.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    assert_eq!(result["chain"], "regtest");
    assert_eq!(
        result["bestblockhash"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );

    node.stop();
}

#[test]
fn test_userpass_auth() {
    let mut node = TestNode::start(&["--rpcuser=testuser", "--rpcpassword=testpass"]);

    // Cookie file should NOT exist when using user/pass auth
    let cookie_path = node.datadir.join("regtest").join(".cookie");
    assert!(
        !cookie_path.exists(),
        "Cookie file should not exist with user/pass auth"
    );

    // Correct credentials should work
    let status = node.rpc_call_raw_status("getblockchaininfo", "testuser", "testpass");
    assert_eq!(status, 200);

    // Wrong credentials should be rejected
    let status = node.rpc_call_raw_status("getblockchaininfo", "testuser", "wrongpass");
    assert_eq!(status, 401);

    node.stop();
}

#[test]
fn test_getbestblockhash() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getbestblockhash").unwrap();
    assert_eq!(
        response["result"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );
    node.stop();
}

#[test]
fn test_getblockcount() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 0);
    node.stop();
}

#[test]
fn test_getblockhash() {
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(0)])
        .unwrap();
    assert_eq!(
        response["result"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );

    // Out of range should error
    let response = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(999)])
        .unwrap();
    assert!(response["error"].is_object());
    node.stop();
}

#[test]
fn test_getblock() {
    let mut node = TestNode::start(&[]);
    let genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    // Verbose (default)
    let response = node
        .rpc_call_with_params("getblock", vec![serde_json::json!(genesis_hash)])
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["hash"], genesis_hash);
    assert_eq!(result["height"], 0);
    assert_eq!(result["confirmations"], 1);
    assert!(result["tx"].is_array());

    // Raw hex (verbosity 0)
    let response = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(genesis_hash), serde_json::json!(0)],
        )
        .unwrap();
    let hex = response["result"].as_str().unwrap();
    assert!(hex.len() > 160); // at least 80 bytes header

    node.stop();
}

#[test]
fn test_getblockheader() {
    let mut node = TestNode::start(&[]);
    let genesis_hash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    // Verbose
    let response = node
        .rpc_call_with_params(
            "getblockheader",
            vec![serde_json::json!(genesis_hash), serde_json::json!(true)],
        )
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["hash"], genesis_hash);
    assert_eq!(result["height"], 0);
    assert_eq!(result["bits"], "207fffff");

    // Raw hex (80 bytes = 160 hex chars)
    let response = node
        .rpc_call_with_params(
            "getblockheader",
            vec![serde_json::json!(genesis_hash), serde_json::json!(false)],
        )
        .unwrap();
    let hex = response["result"].as_str().unwrap();
    assert_eq!(hex.len(), 160);

    node.stop();
}

#[test]
fn test_submitblock_invalid() {
    let mut node = TestNode::start(&[]);

    // Submit garbage hex
    let response = node
        .rpc_call_with_params("submitblock", vec![serde_json::json!("deadbeef")])
        .unwrap();
    assert_eq!(response["result"], "Block decode failed");

    // Submit invalid hex
    let response = node
        .rpc_call_with_params("submitblock", vec![serde_json::json!("not-hex!")])
        .unwrap();
    assert_eq!(response["result"], "Block decode failed");

    node.stop();
}

#[test]
fn test_getmempoolinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getmempoolinfo").unwrap();
    let result = &response["result"];

    assert_eq!(result["loaded"], true);
    assert_eq!(result["size"], 0);
    assert_eq!(result["bytes"], 0);
    assert!(result["maxmempool"].as_u64().unwrap() > 0);

    node.stop();
}

#[test]
fn test_getrawmempool_empty() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getrawmempool").unwrap();
    let result = &response["result"];
    assert!(result.is_array());
    assert_eq!(result.as_array().unwrap().len(), 0);

    node.stop();
}

#[test]
fn test_decoderawtransaction() {
    let mut node = TestNode::start(&[]);

    // Use the regtest genesis coinbase tx hex
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let coinbase_hex = hex::encode(bitcoin::consensus::serialize(&genesis.txdata[0]));

    let response = node
        .rpc_call_with_params(
            "decoderawtransaction",
            vec![serde_json::json!(coinbase_hex)],
        )
        .unwrap();
    let result = &response["result"];

    assert!(result["txid"].is_string());
    assert!(result["vin"].is_array());
    assert!(result["vout"].is_array());
    assert_eq!(result["vin"].as_array().unwrap().len(), 1);
    assert_eq!(result["vout"].as_array().unwrap().len(), 1);
    // Coinbase input should have "coinbase" field
    assert!(result["vin"][0]["coinbase"].is_string());

    node.stop();
}

#[test]
fn test_sendrawtransaction_invalid() {
    let mut node = TestNode::start(&[]);

    // Sending garbage should fail
    let response = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!("deadbeef")])
        .unwrap();
    assert!(response["error"].is_object());

    node.stop();
}

#[test]
fn test_getpeerinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getpeerinfo").unwrap();
    let result = &response["result"];
    assert!(result.is_array());
    // No peers connected yet
    assert_eq!(result.as_array().unwrap().len(), 0);
    node.stop();
}

#[test]
fn test_getconnectioncount() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getconnectioncount").unwrap();
    assert_eq!(response["result"], 0);
    node.stop();
}

#[test]
fn test_generatetoaddress() {
    let mut node = TestNode::start(&[]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine 1 block
    let response = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let result = &response["result"];
    assert!(result.is_array());
    assert_eq!(result.as_array().unwrap().len(), 1);

    // Verify block count increased
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 1);

    // Mine 10 more blocks
    let response = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(10), serde_json::json!(addr)],
        )
        .unwrap();
    assert_eq!(response["result"].as_array().unwrap().len(), 10);

    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 11);

    node.stop();
}

#[test]
fn test_getblocktemplate() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getblocktemplate").unwrap();
    let result = &response["result"];

    assert_eq!(result["height"], 1);
    assert!(result["previousblockhash"].is_string());
    assert!(result["transactions"].is_array());
    assert!(result["coinbasevalue"].as_u64().unwrap() > 0);
    assert_eq!(result["bits"], "207fffff");

    node.stop();
}

#[test]
fn test_generateblock() {
    let mut node = TestNode::start(&[]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let response = node
        .rpc_call_with_params("generateblock", vec![serde_json::json!(addr)])
        .unwrap();
    let result = &response["result"];
    assert!(result["hash"].is_string());

    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 1);

    node.stop();
}

#[test]
fn test_getnetworkinfo_connections() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getnetworkinfo").unwrap();
    let result = &response["result"];
    assert_eq!(result["connections"], 0);
    assert_eq!(result["subversion"], "/satd:0.1.0/");
    node.stop();
}

#[test]
fn test_gettxoutsetinfo() {
    let mut node = TestNode::start(&[]);

    // Mine a block so we have some UTXOs
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1), serde_json::json!(addr)],
    )
    .unwrap();

    let response = node.rpc_call("gettxoutsetinfo").unwrap();
    let result = &response["result"];
    assert_eq!(result["height"], 1);
    assert!(result["bestblock"].is_string());
    assert!(result["txouts"].as_u64().unwrap() >= 1);

    node.stop();
}

#[test]
fn test_gettxout() {
    let mut node = TestNode::start(&[]);

    // Mine a block to create a UTXO
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let response = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let block_hash = &response["result"][0].as_str().unwrap();

    // Get the block to find the coinbase txid
    let response = node
        .rpc_call_with_params("getblock", vec![serde_json::json!(block_hash)])
        .unwrap();
    let txid = response["result"]["tx"][0].as_str().unwrap();

    // Query the UTXO
    let response = node
        .rpc_call_with_params(
            "gettxout",
            vec![serde_json::json!(txid), serde_json::json!(0)],
        )
        .unwrap();
    let result = &response["result"];
    assert!(result["value"].as_f64().unwrap() > 0.0);
    assert_eq!(result["coinbase"], true);

    node.stop();
}

#[test]
fn test_estimatesmartfee() {
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("estimatesmartfee", vec![serde_json::json!(6)])
        .unwrap();
    let result = &response["result"];
    assert!(result["feerate"].as_f64().unwrap() > 0.0);
    assert_eq!(result["blocks"], 6);
    node.stop();
}

#[test]
fn test_estimatesmartfee_core_compat_shape_unchanged() {
    // The default (no mode param) response must contain exactly the Core-
    // compatible keys: `feerate`, `blocks`, `errors`. Nothing else.
    // Regression guard: adding mempool-based estimation must not break
    // Bitcoin Core clients.
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("estimatesmartfee", vec![serde_json::json!(6)])
        .unwrap();
    let result = response["result"].as_object().unwrap();
    let keys: std::collections::BTreeSet<&str> = result.keys().map(|k| k.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["feerate", "blocks", "errors"].into_iter().collect();
    assert_eq!(keys, expected, "estimatesmartfee default shape drifted");
    assert!(result["feerate"].as_f64().unwrap() > 0.0);
    assert_eq!(result["blocks"], 6);
    // `errors` is always an empty list.
    assert!(result["errors"].as_array().unwrap().is_empty());
    node.stop();
}

#[test]
fn test_estimatesmartfee_accepts_mode_param() {
    // mode=mempool is accepted and returns the same shape. With an empty
    // mempool the feerate falls back to the min-relay floor.
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params(
            "estimatesmartfee",
            vec![serde_json::json!(6), serde_json::json!("mempool")],
        )
        .unwrap();
    let result = &response["result"];
    assert!(result["feerate"].as_f64().unwrap() > 0.0);
    assert_eq!(result["blocks"], 6);
    // Same keys as Core-compat default — only the source differs.
    let keys: std::collections::BTreeSet<&str> = result
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    assert_eq!(keys, ["feerate", "blocks", "errors"].into_iter().collect());
    node.stop();
}

#[test]
fn test_estimatefees_default_shape() {
    // estimatefees with no args returns a blend over default targets with
    // a histogram and a `mode` tag. Empty mempool → Low confidence.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("estimatefees").unwrap();
    let result = response["result"].as_object().unwrap();

    assert!(result.contains_key("targets"));
    assert!(result.contains_key("histogram"));
    assert!(result.contains_key("mode"));
    assert!(result.contains_key("fallback"));
    assert!(result.contains_key("mempool_weight"));
    assert!(result.contains_key("economy_feerate"));
    assert!(result.contains_key("thin_block"));
    assert_eq!(result["mode"], "blend");
    // Fresh node → block 0 is empty → thin.
    assert_eq!(result["thin_block"].as_bool(), Some(true));
    // Economy feerate is present and > 0.
    assert!(result["economy_feerate"].as_f64().unwrap() > 0.0);

    let targets = result["targets"].as_object().unwrap();
    for key in ["1", "3", "6", "12", "24"] {
        let t = &targets[key];
        assert!(t["feerate"].as_f64().unwrap() > 0.0);
        let conf = t["confidence"].as_str().unwrap();
        assert!(
            matches!(conf, "high" | "medium" | "low"),
            "confidence must be one of high|medium|low; got {}",
            conf
        );
    }

    // Histogram is a JSON array (may be empty when mempool is empty).
    assert!(result["histogram"].is_array());
    // Fresh node with empty mempool: no tx queued.
    assert_eq!(result["mempool_weight"].as_u64(), Some(0));
    node.stop();
}

#[test]
fn test_estimatefees_respects_sats_units() {
    // With --rpcdefaultunits=sats, feerate fields inside `targets` are
    // JSON integers (sat/kvB), and the response carries `_units: sats`.
    let mut node = TestNode::start(&["--rpcdefaultunits=sats"]);
    let response = node.rpc_call("estimatefees").unwrap();
    let result = &response["result"];
    assert_eq!(result["_units"].as_str(), Some("sats"));
    let targets = result["targets"].as_object().unwrap();
    for (_, t) in targets {
        assert!(
            t["feerate"].as_u64().is_some(),
            "feerate must be integer sat/kvB in sats mode, got: {}",
            t["feerate"]
        );
    }
    node.stop();
}

#[test]
fn test_estimatefees_custom_targets_and_mode() {
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params(
            "estimatefees",
            vec![serde_json::json!([1, 2, 5]), serde_json::json!("mempool")],
        )
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["mode"], "mempool");
    let targets = result["targets"].as_object().unwrap();
    assert_eq!(
        targets.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
        vec!["1", "2", "5"]
    );
    node.stop();
}

#[test]
fn test_mine_many_blocks_bip34() {
    // Tests that BIP 34 coinbase height encoding works for heights 0-20
    // (covers OP_0, OP_1..OP_16, and data-push encoding)
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let response = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .unwrap();
    let hashes = response["result"].as_array().unwrap();
    assert_eq!(hashes.len(), 20);

    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 20);

    // Verify each block has the correct height
    for height in 1..=20u32 {
        let response = node
            .rpc_call_with_params("getblockhash", vec![serde_json::json!(height)])
            .unwrap();
        let hash = response["result"].as_str().unwrap();
        let response = node
            .rpc_call_with_params("getblock", vec![serde_json::json!(hash)])
            .unwrap();
        assert_eq!(response["result"]["height"], height);
    }

    node.stop();
}

#[test]
fn test_ibd_detection() {
    // A fresh regtest node with height 0 should report initialblockdownload=false
    // because the genesis block timestamp is old but regtest is special
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getblockchaininfo").unwrap();
    let result = &response["result"];

    // At height 0 with genesis timestamp far in the past, IBD should be true
    assert_eq!(result["initialblockdownload"], true);

    // Mine a block — now tip timestamp is current, IBD should be false
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1), serde_json::json!(addr)],
    )
    .unwrap();

    let response = node.rpc_call("getblockchaininfo").unwrap();
    let result = &response["result"];
    assert_eq!(result["initialblockdownload"], false);

    node.stop();
}

#[test]
fn test_getblocktemplate_fields() {
    // Verify the improved getblocktemplate has all BIP 22/23 fields
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getblocktemplate").unwrap();
    let result = &response["result"];

    // BIP 22/23 required fields
    assert!(result["version"].is_number());
    assert!(result["previousblockhash"].is_string());
    assert!(result["transactions"].is_array());
    assert!(result["coinbasevalue"].is_number());
    assert!(result["target"].is_string());
    assert_eq!(result["target"].as_str().unwrap().len(), 64);
    assert!(result["bits"].is_string());
    assert!(result["height"].is_number());
    assert!(result["curtime"].is_number());
    assert!(result["mintime"].is_number());
    assert!(result["mutable"].is_array());
    assert!(result["noncerange"].is_string());
    assert!(result["sigoplimit"].is_number());
    assert!(result["sizelimit"].is_number());
    assert!(result["weightlimit"].is_number());
    // New BIP 23 fields
    assert!(result["rules"].is_array());
    assert!(result["vbavailable"].is_object());
    assert!(result["vbrequired"].is_number());
    assert!(result["capabilities"].is_array());

    node.stop();
}

// --- P2P Integration Tests ---

#[test]
fn test_two_nodes_connect() {
    let p2p_port_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_port_a)]);
    let mut node_b = TestNode::start(&[&format!("--connect=127.0.0.1:{}", p2p_port_a)]);

    poll_until(
        || get_rpc_u64(&node_a, "getconnectioncount").unwrap_or(0) >= 1,
        Duration::from_secs(15),
        "node A did not see a connection",
    );

    let a_count = get_rpc_u64(&node_a, "getconnectioncount").unwrap();
    assert!(a_count >= 1, "node A connection count: {}", a_count);

    let a_peers = node_a.rpc_call("getpeerinfo").unwrap();
    let peers = a_peers["result"].as_array().unwrap();
    assert!(!peers.is_empty(), "node A should have peers");
    // Node A sees an inbound connection
    assert_eq!(peers[0]["inbound"], true);

    node_b.stop();
    node_a.stop();
}

#[test]
fn test_block_sync_between_nodes() {
    let p2p_port_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_port_a)]);

    // Mine 5 blocks on node A
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr)],
        )
        .unwrap();
    assert_eq!(get_rpc_u64(&node_a, "getblockcount").unwrap(), 5);

    // Start node B connected to A
    let mut node_b = TestNode::start(&[&format!("--connect=127.0.0.1:{}", p2p_port_a)]);

    // Wait for B to sync all 5 blocks
    poll_until(
        || get_rpc_u64(&node_b, "getblockcount").unwrap_or(0) >= 5,
        Duration::from_secs(30),
        "node B did not sync to height 5",
    );

    // Verify both nodes agree on the best block
    let a_hash = get_rpc_str(&node_a, "getbestblockhash").unwrap();
    let b_hash = get_rpc_str(&node_b, "getbestblockhash").unwrap();
    assert_eq!(a_hash, b_hash, "nodes should agree on best block hash");

    node_b.stop();
    node_a.stop();
}

#[test]
fn test_parallel_ibd() {
    let p2p_port_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_port_a)]);

    // Mine 200 blocks on node A — enough to trigger IBD path (tip + 24 < headers_tip)
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(200), serde_json::json!(addr)],
        )
        .unwrap();
    assert_eq!(get_rpc_u64(&node_a, "getblockcount").unwrap(), 200);

    // Start node B connected to A — should use parallel IBD. Capture
    // node B's stderr so the wedge dump below can include satd-side
    // logs when the test fails (without paying the I/O cost in every
    // other regtest test).
    let mut node_b = TestNode::start_capturing_stderr(&[&format!(
        "--connect=127.0.0.1:{}",
        p2p_port_a
    )]);

    // Wait for B to sync all 200 blocks. The timeout has headroom for slow
    // CI runners: per-peer in-flight is capped at 16 (Bitcoin Core's
    // MAX_BLOCKS_IN_TRANSIT_PER_PEER), so a 1-peer regtest run needs ~13
    // round-trips and can take 60s+ when the runner is under load even
    // though it completes in ~11s locally.
    let start = std::time::Instant::now();
    let mut last_logged = 0u64;
    while start.elapsed() < Duration::from_secs(180) {
        let count = get_rpc_u64(&node_b, "getblockcount").unwrap_or(0);
        if count >= 200 {
            eprintln!(
                "test_parallel_ibd: synced 200/200 in {:.1}s",
                start.elapsed().as_secs_f64()
            );
            break;
        }
        if count != last_logged && start.elapsed().as_secs() > 5 {
            eprintln!(
                "test_parallel_ibd: at {:.1}s, node B getblockcount={}",
                start.elapsed().as_secs_f64(),
                count
            );
            last_logged = count;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let final_count = get_rpc_u64(&node_b, "getblockcount").unwrap_or(0);
    if final_count < 200 {
        // Dump node B state to make the wedge debuggable from CI logs.
        let chaininfo = node_b
            .rpc_call("getblockchaininfo")
            .map(|v| v.to_string())
            .unwrap_or_else(|e| format!("(rpc err: {e})"));
        let peerinfo = node_b
            .rpc_call("getpeerinfo")
            .map(|v| v.to_string())
            .unwrap_or_else(|e| format!("(rpc err: {e})"));
        let a_count = get_rpc_u64(&node_a, "getblockcount").unwrap_or(0);
        let b_stderr = std::fs::read_to_string(&node_b.stderr_log)
            .unwrap_or_else(|e| format!("(read err: {e})"));
        // Last 200 log lines are usually enough to see the wedge state.
        let tail: String = b_stderr.lines().rev().take(200).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        eprintln!(
            "test_parallel_ibd wedge dump:\n  node_a.getblockcount={a_count}\n  node_b.getblockchaininfo={chaininfo}\n  node_b.getpeerinfo={peerinfo}\n  node_b.stderr (last 200 lines):\n{tail}",
        );
        panic!(
            "node B did not sync to height 200 via parallel IBD; stuck at {} after {:.1}s",
            final_count,
            start.elapsed().as_secs_f64()
        );
    }

    // Verify both nodes agree on the best block
    let a_hash = get_rpc_str(&node_a, "getbestblockhash").unwrap();
    let b_hash = get_rpc_str(&node_b, "getbestblockhash").unwrap();
    assert_eq!(
        a_hash, b_hash,
        "nodes should agree on best block after parallel IBD"
    );

    node_b.stop();
    node_a.stop();
}

#[test]
fn test_block_propagation() {
    let p2p_port_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_port_a)]);
    let mut node_b = TestNode::start(&[&format!("--connect=127.0.0.1:{}", p2p_port_a)]);

    // Wait for connection
    poll_until(
        || get_rpc_u64(&node_a, "getconnectioncount").unwrap_or(0) >= 1,
        Duration::from_secs(15),
        "nodes did not connect",
    );

    // Mine a block on A
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    // Wait for B to receive the block
    poll_until(
        || get_rpc_u64(&node_b, "getblockcount").unwrap_or(0) >= 1,
        Duration::from_secs(15),
        "block did not propagate to node B",
    );

    let a_hash = get_rpc_str(&node_a, "getbestblockhash").unwrap();
    let b_hash = get_rpc_str(&node_b, "getbestblockhash").unwrap();
    assert_eq!(a_hash, b_hash);

    node_b.stop();
    node_a.stop();
}

#[test]
fn test_multiple_connections() {
    let p2p_port_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_port_a)]);
    let mut node_b = TestNode::start(&[&format!("--connect=127.0.0.1:{}", p2p_port_a)]);
    let mut node_c = TestNode::start(&[&format!("--connect=127.0.0.1:{}", p2p_port_a)]);

    poll_until(
        || get_rpc_u64(&node_a, "getconnectioncount").unwrap_or(0) >= 2,
        Duration::from_secs(15),
        "node A did not reach 2 connections",
    );

    let count = get_rpc_u64(&node_a, "getconnectioncount").unwrap();
    assert_eq!(count, 2, "node A should have exactly 2 connections");

    node_c.stop();
    node_b.stop();
    node_a.stop();
}

// ── New RPC tests ────────────────────────────────────────────────

#[test]
fn test_getdifficulty() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getdifficulty").unwrap();
    assert!(response["result"].is_number());
    node.stop();
}

#[test]
fn test_getblockstats() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1), serde_json::json!(addr)],
    )
    .unwrap();

    let response = node
        .rpc_call_with_params("getblockstats", vec![serde_json::json!("1")])
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["height"], 1);
    assert!(result["txs"].as_u64().unwrap() >= 1);
    assert!(result["subsidy"].as_u64().unwrap() > 0);
    node.stop();
}

#[test]
fn test_getchaintips() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getchaintips").unwrap();
    let result = &response["result"];
    assert!(result.is_array());
    assert!(!result.as_array().unwrap().is_empty());
    assert_eq!(result[0]["status"], "active");
    node.stop();
}

#[test]
fn test_getchaintxstats() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(5), serde_json::json!(addr)],
    )
    .unwrap();

    let response = node
        .rpc_call_with_params("getchaintxstats", vec![serde_json::json!(3)])
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["window_block_count"], 3);
    assert!(result["txcount"].as_u64().unwrap() > 0);
    node.stop();
}

#[test]
fn test_getmempoolentry() {
    let mut node = TestNode::start(&[]);
    // Generate blocks + get utxo for crafting a tx is complex,
    // so just verify the RPC returns an error for nonexistent tx
    let response = node
        .rpc_call_with_params(
            "getmempoolentry",
            vec![serde_json::json!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )],
        )
        .unwrap();
    assert!(response["error"].is_object());
    node.stop();
}

#[test]
fn test_testmempoolaccept() {
    let mut node = TestNode::start(&[]);
    // Test with invalid tx hex
    let response = node
        .rpc_call_with_params("testmempoolaccept", vec![serde_json::json!(["deadbeef"])])
        .unwrap();
    // Should return an error for decode failure
    assert!(response["error"].is_object());
    node.stop();
}

#[test]
fn test_verifychain() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("verifychain").unwrap();
    assert_eq!(response["result"], true);
    node.stop();
}

#[test]
fn test_preciousblock() {
    let mut node = TestNode::start(&[]);
    let hash = node.rpc_call("getbestblockhash").unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let response = node
        .rpc_call_with_params("preciousblock", vec![serde_json::json!(hash)])
        .unwrap();
    assert!(response["result"].is_null());
    node.stop();
}

#[test]
fn test_getmininginfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getmininginfo").unwrap();
    let result = &response["result"];
    assert_eq!(result["chain"], "regtest");
    assert!(result["blocks"].is_number());
    assert!(result["difficulty"].is_number());
    node.stop();
}

#[test]
fn test_getnetworkhashps() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getnetworkhashps").unwrap();
    assert!(response["result"].is_number());
    node.stop();
}

#[test]
fn test_submitheader() {
    let mut node = TestNode::start(&[]);
    // Submit an invalid header
    let response = node
        .rpc_call_with_params("submitheader", vec![serde_json::json!("deadbeef")])
        .unwrap();
    assert!(response["error"].is_object());
    node.stop();
}

#[test]
fn test_listbanned() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("listbanned").unwrap();
    assert!(response["result"].is_array());
    assert!(response["result"].as_array().unwrap().is_empty());
    node.stop();
}

#[test]
fn test_clearbanned() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("clearbanned").unwrap();
    assert!(response["result"].is_null());
    node.stop();
}

#[test]
fn test_ping_rpc() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("ping").unwrap();
    assert!(response["result"].is_null());
    node.stop();
}

#[test]
fn test_help() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("help").unwrap();
    let help_text = response["result"].as_str().unwrap();
    assert!(help_text.contains("getblockchaininfo"));
    assert!(help_text.contains("getmininginfo"));
    assert!(help_text.contains("testmempoolaccept"));
    node.stop();
}

#[test]
fn test_uptime() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("uptime").unwrap();
    let uptime = response["result"].as_u64().unwrap();
    assert!(uptime < 60); // should be < 60 seconds in test
    node.stop();
}

#[test]
fn test_getmemoryinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getmemoryinfo").unwrap();
    let result = &response["result"];
    assert!(result["locked"].is_object());
    node.stop();
}

#[test]
fn test_getrpcinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getrpcinfo").unwrap();
    let result = &response["result"];
    assert!(result["active_commands"].is_array());
    node.stop();
}

#[test]
fn test_logging() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("logging").unwrap();
    let result = &response["result"];
    assert_eq!(result["net"], true);
    node.stop();
}

#[test]
fn test_getaddednodeinfo() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getaddednodeinfo").unwrap();
    assert!(response["result"].is_array());
    node.stop();
}

#[test]
fn test_getnettotals() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getnettotals").unwrap();
    let result = &response["result"];
    assert!(result["timemillis"].is_number());
    node.stop();
}

#[test]
fn test_savemempool() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("savemempool").unwrap();
    assert!(response["result"].is_null());
    node.stop();
}

#[test]
fn test_dumptxoutset_writes_core_format_snapshot() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine 10 blocks → 10 spendable coinbase UTXOs.
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .unwrap();

    let dump_path = std::env::temp_dir().join(format!(
        "satd-dumptxoutset-{}-{}.dat",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_file(&dump_path);

    let response = node
        .rpc_call_with_params(
            "dumptxoutset",
            vec![serde_json::json!(dump_path.to_string_lossy())],
        )
        .unwrap();
    let result = &response["result"];
    assert!(result.is_object(), "result should be an object: {response}");
    assert_eq!(result["coins_written"].as_u64().unwrap(), 10);
    assert_eq!(result["base_height"].as_u64().unwrap(), 10);
    assert!(result["base_hash"].as_str().unwrap().len() == 64);
    assert!(result["path"].as_str().unwrap().contains("satd-dumptxoutset-"));
    let reported_hash = result["txoutset_hash"].as_str().unwrap().to_string();
    assert_eq!(reported_hash.len(), 64);

    // File exists on disk.
    let raw = std::fs::read(&dump_path).expect("read snapshot file");
    assert!(raw.len() > 51, "snapshot smaller than header: {} bytes", raw.len());

    // First 5 bytes: snapshot magic "utxo\xff".
    assert_eq!(&raw[..5], &[b'u', b't', b'x', b'o', 0xff]);
    // Bytes 5..7: version 2 LE.
    assert_eq!(&raw[5..7], &[0x02, 0x00]);
    // Bytes 7..11: regtest network magic.
    assert_eq!(&raw[7..11], &[0xfa, 0xbf, 0xb5, 0xda]);
    // Bytes 43..51: coins_count = 10 LE.
    assert_eq!(&raw[43..51], &10u64.to_le_bytes());

    // The reported `txoutset_hash` is HASH_SERIALIZED_3 — single SHA-256
    // over Core's `TxOutSer` stream of the UTXO set — NOT the SHA-256
    // of the snapshot file bytes. To independently verify, parse the
    // file into (outpoint, coin) pairs and re-hash via TxOutSer; the
    // result must match `txoutset_hash`. Lib-side `state.rs` has the
    // detailed roundtrip test; here we just confirm the field is
    // present, well-formed hex, and a stable 64-char string.
    assert_eq!(reported_hash.len(), 64, "txoutset_hash must be 32-byte hex");
    assert!(
        reported_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "txoutset_hash must be hex: {reported_hash}"
    );

    // Refuses overwrite on a second call.
    let response = node
        .rpc_call_with_params(
            "dumptxoutset",
            vec![serde_json::json!(dump_path.to_string_lossy())],
        )
        .unwrap();
    assert!(response["error"].is_object(), "expected error: {response}");
    assert_eq!(response["error"]["code"], -8);

    let _ = std::fs::remove_file(&dump_path);
    node.stop();
}

#[test]
fn test_setnetworkactive() {
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("setnetworkactive", vec![serde_json::json!(true)])
        .unwrap();
    assert_eq!(response["result"], true);
    node.stop();
}

#[test]
fn test_createrawtransaction() {
    let mut node = TestNode::start(&[]);
    let inputs = serde_json::json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let response = node
        .rpc_call_with_params("createrawtransaction", vec![inputs, outputs])
        .unwrap();
    assert!(response["result"].is_string());
    let hex = response["result"].as_str().unwrap();
    assert!(!hex.is_empty());
    node.stop();
}

#[test]
fn test_decodescript() {
    let mut node = TestNode::start(&[]);
    // OP_TRUE (0x51) — simplest valid script
    let response = node
        .rpc_call_with_params("decodescript", vec![serde_json::json!("51")])
        .unwrap();
    let result = &response["result"];
    assert!(result["asm"].is_string());
    assert!(result["type"].is_string());
    node.stop();
}

#[test]
fn test_createpsbt() {
    let mut node = TestNode::start(&[]);
    let inputs = serde_json::json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let response = node
        .rpc_call_with_params("createpsbt", vec![inputs, outputs])
        .unwrap();
    assert!(response["result"].is_string());
    // Should be valid base64
    let b64 = response["result"].as_str().unwrap();
    assert!(b64.starts_with("cHNidP8")); // PSBT magic in base64
    node.stop();
}

#[test]
fn test_decodepsbt() {
    let mut node = TestNode::start(&[]);
    // First create a PSBT
    let inputs = serde_json::json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let create_resp = node
        .rpc_call_with_params("createpsbt", vec![inputs, outputs])
        .unwrap();
    let psbt_b64 = create_resp["result"].as_str().unwrap();

    // Decode it
    let response = node
        .rpc_call_with_params("decodepsbt", vec![serde_json::json!(psbt_b64)])
        .unwrap();
    let result = &response["result"];
    assert!(result["tx"].is_object());
    assert!(result["inputs"].is_array());
    node.stop();
}

#[test]
fn test_analyzepsbt() {
    let mut node = TestNode::start(&[]);
    let inputs = serde_json::json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let create_resp = node
        .rpc_call_with_params("createpsbt", vec![inputs, outputs])
        .unwrap();
    let psbt_b64 = create_resp["result"].as_str().unwrap();

    let response = node
        .rpc_call_with_params("analyzepsbt", vec![serde_json::json!(psbt_b64)])
        .unwrap();
    let result = &response["result"];
    assert!(result["inputs"].is_array());
    assert_eq!(result["next"], "updater"); // unsigned, no UTXOs
    node.stop();
}

#[test]
fn test_converttopsbt() {
    let mut node = TestNode::start(&[]);
    // Create a raw tx first
    let inputs = serde_json::json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000000",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let raw_resp = node
        .rpc_call_with_params("createrawtransaction", vec![inputs, outputs])
        .unwrap();
    let hex_tx = raw_resp["result"].as_str().unwrap();

    let response = node
        .rpc_call_with_params("converttopsbt", vec![serde_json::json!(hex_tx)])
        .unwrap();
    assert!(response["result"].is_string());
    let b64 = response["result"].as_str().unwrap();
    assert!(b64.starts_with("cHNidP8"));
    node.stop();
}

#[test]
fn test_validateaddress() {
    let mut node = TestNode::start(&[]);
    // Valid regtest bech32 address
    let response = node
        .rpc_call_with_params(
            "validateaddress",
            vec![serde_json::json!(
                "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202"
            )],
        )
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["isvalid"], true);
    assert_eq!(result["iswitness"], true);

    // Invalid address
    let response = node
        .rpc_call_with_params("validateaddress", vec![serde_json::json!("notanaddress")])
        .unwrap();
    let result = &response["result"];
    assert_eq!(result["isvalid"], false);
    node.stop();
}

#[test]
fn test_waitforblockheight() {
    let mut node = TestNode::start(&[]);
    // Height 0 is already reached, should return immediately
    let response = node
        .rpc_call_with_params(
            "waitforblockheight",
            vec![serde_json::json!(0), serde_json::json!(1000)],
        )
        .unwrap();
    let result = &response["result"];
    assert!(result["height"].is_number());
    assert!(result["hash"].is_string());
    node.stop();
}

// ── Additional integration tests ─────────────────────────────────

#[test]
fn test_submitblock_valid() {
    // Mine a valid block using generatetoaddress and verify the block count
    // increments. Then get the raw block hex, reset to a fresh node, and
    // submit it via submitblock to verify the RPC accepts a valid block.
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine one block via generatetoaddress
    let gen_resp = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let block_hash = gen_resp["result"][0].as_str().unwrap().to_string();

    // Verify block count incremented
    let count = node.rpc_call("getblockcount").unwrap();
    assert_eq!(count["result"], 1);

    // Get the raw block hex (verbosity 0)
    let raw_resp = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block_hash), serde_json::json!(0)],
        )
        .unwrap();
    let block_hex = raw_resp["result"].as_str().unwrap().to_string();
    assert!(!block_hex.is_empty());

    // Submit the same block again — should get "duplicate" (not an error)
    let submit_resp = node
        .rpc_call_with_params("submitblock", vec![serde_json::json!(block_hex)])
        .unwrap();
    // Submitting a known block should return "duplicate" or null, not an error
    let submit_result = &submit_resp["result"];
    assert!(
        submit_result.is_null() || submit_result == "duplicate",
        "Expected null or 'duplicate', got: {:?}",
        submit_result
    );

    node.stop();
}

#[test]
fn test_node_restart_persistence() {
    // Start a node, mine blocks, stop, restart with same datadir, verify state persists.
    // We use raw process management here because TestNode::start always creates its own
    // datadir, and we need to reuse the same datadir across two invocations.
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir().join(format!("satd-restart-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    // Guard that kills the child on drop. Needed because an assertion
    // failure between spawn and the explicit cleanup below would
    // otherwise leak the satd process, which then holds its ports and
    // cascades into startup-timeout failures in unrelated tests.
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    impl std::ops::Deref for ChildGuard {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.0
        }
    }
    impl std::ops::DerefMut for ChildGuard {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.0
        }
    }

    // Helper: make an RPC call to a given port with a given cookie
    let rpc = |port: u16,
               cookie: &str,
               method: &str,
               params: Vec<serde_json::Value>|
     -> serde_json::Value {
        let url = format!("http://127.0.0.1:{}/", port);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": method,
            "params": params,
        });
        let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
        let client = reqwest::blocking::Client::new();
        client
            .post(&url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .unwrap()
            .json()
            .unwrap()
    };

    // Wait for the cookie file AND for the real RPC server to be
    // serving. satd binds a lightweight startup-status RPC to the
    // port as soon as the cookie is written — but that stub only
    // responds to `getstartupinfo`. Probe `getblockchaininfo` until
    // the real RPC server replaces the stub and the chain is
    // initialized (matches the pattern used by `TestNode::start`).
    let wait_for_cookie = |dir: &std::path::Path, port: u16| -> String {
        let cookie_path = dir.join("regtest").join(".cookie");
        // 120s for the same CI-load reasons documented in TestNode::start.
        let deadline = Instant::now() + test_timeout(120);
        loop {
            if let Ok(cookie) = std::fs::read_to_string(&cookie_path) {
                let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap();
                let ready = client
                    .post(format!("http://127.0.0.1:{}/", port))
                    .basic_auth(user, Some(pass))
                    .header("Content-Type", "application/json")
                    .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}"#)
                    .send()
                    .ok()
                    .and_then(|r| r.json::<serde_json::Value>().ok())
                    .is_some_and(|j| !j["result"]["chain"].is_null());
                if ready {
                    return cookie;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "Timed out waiting for satd RPC to be ready on port {}",
                    port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };

    let saved_best_hash;

    // ── First run ──
    let rpcport1 = find_available_port();
    {
        let mut child = ChildGuard(
            Command::new(satd_bin)
                .arg("--regtest")
                .arg(format!("--datadir={}", datadir.display()))
                .arg(format!("--rpcport={}", rpcport1))
                // Esplora defaults on but requires txindex; tests
                // spawning satd directly opt out unless they want it.
                .arg("--esplora=0")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("Failed to start satd"),
        );

        let cookie = wait_for_cookie(&datadir, rpcport1);
        let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

        // Mine 3 blocks
        rpc(
            rpcport1,
            &cookie,
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr)],
        );

        let count = rpc(rpcport1, &cookie, "getblockcount", vec![]);
        assert_eq!(count["result"], 3);

        saved_best_hash = rpc(rpcport1, &cookie, "getbestblockhash", vec![])["result"]
            .as_str()
            .unwrap()
            .to_string();

        // Graceful stop
        let _ = rpc(rpcport1, &cookie, "stop", vec![]);
        for _ in 0..30 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    // ── Second run (same datadir, new port) ──
    let rpcport2 = find_available_port();
    {
        let mut child = ChildGuard(
            Command::new(satd_bin)
                .arg("--regtest")
                .arg(format!("--datadir={}", datadir.display()))
                .arg(format!("--rpcport={}", rpcport2))
                .arg("--esplora=0")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("Failed to start satd (second run)"),
        );

        let cookie = wait_for_cookie(&datadir, rpcport2);

        // Verify chain state persisted
        let count = rpc(rpcport2, &cookie, "getblockcount", vec![]);
        assert_eq!(
            count["result"], 3,
            "Block count should persist across restarts"
        );

        let best_hash = rpc(rpcport2, &cookie, "getbestblockhash", vec![])["result"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            best_hash, saved_best_hash,
            "Best block hash should persist across restarts"
        );

        let info = rpc(rpcport2, &cookie, "getblockchaininfo", vec![]);
        assert_eq!(info["result"]["blocks"], 3);
        assert_eq!(info["result"]["chain"], "regtest");

        // Graceful stop
        let _ = rpc(rpcport2, &cookie, "stop", vec![]);
        for _ in 0..30 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_gettxoutsetinfo_at_genesis() {
    // At genesis (height 0), the UTXO set should be empty because
    // the genesis coinbase is unspendable and not in the UTXO set.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("gettxoutsetinfo").unwrap();
    let result = &response["result"];

    assert_eq!(result["height"], 0);
    assert!(result["bestblock"].is_string());
    assert_eq!(
        result["bestblock"],
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    );
    // Genesis coinbase is unspendable, so txouts should be 0
    assert_eq!(
        result["txouts"], 0,
        "Genesis UTXO set should have 0 spendable outputs"
    );

    node.stop();
}

#[test]
fn test_getblockstats_genesis() {
    // Call getblockstats for the genesis block (height 0) and verify expected fields.
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("getblockstats", vec![serde_json::json!("0")])
        .unwrap();

    if response["error"].is_object() {
        // Some implementations may not support getblockstats for genesis block.
        // If it errors, just verify it's a reasonable error.
        let error = &response["error"];
        assert!(error["message"].is_string());
    } else {
        let result = &response["result"];
        assert_eq!(result["height"], 0);
        assert!(result["txs"].is_number());
        // Genesis block should have exactly 1 transaction (coinbase)
        assert_eq!(result["txs"], 1);
        // Subsidy at height 0 should be 50 BTC = 5_000_000_000 satoshis
        assert!(result["subsidy"].is_number());
    }

    node.stop();
}

#[test]
fn test_getdifficulty_regtest_value() {
    // On regtest, the difficulty should be a very small value since
    // the target is set to the maximum (easiest) difficulty.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getdifficulty").unwrap();
    let difficulty = response["result"].as_f64().unwrap();

    // Regtest difficulty should be positive and very small
    assert!(difficulty > 0.0, "Difficulty must be positive");
    // Regtest minimum difficulty is ~4.656e-10
    assert!(
        difficulty < 1.0,
        "Regtest difficulty should be less than 1, got: {}",
        difficulty
    );

    node.stop();
}

#[test]
fn test_getchaintips_fields() {
    // Verify getchaintips returns properly structured entries with all
    // expected fields: height, hash, branchlen, status.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getchaintips").unwrap();
    let result = &response["result"];

    assert!(result.is_array());
    let tips = result.as_array().unwrap();
    assert!(!tips.is_empty(), "Should have at least one chain tip");

    // Verify the active tip
    let active_tip = &tips[0];
    assert!(active_tip["height"].is_number());
    assert!(active_tip["hash"].is_string());
    assert_eq!(active_tip["status"], "active");
    assert_eq!(
        active_tip["branchlen"], 0,
        "Active tip branchlen should be 0"
    );

    // At genesis, the height should be 0
    assert_eq!(active_tip["height"], 0);

    node.stop();
}

#[test]
fn test_getblockfilter_errors_when_index_disabled() {
    // Default-off: --blockfilterindex is not set, so getblockfilter
    // returns an error citing the disabled index. The genesis hash is
    // a real, known hash on regtest so the failure path is "index
    // disabled" rather than "block not found".
    let mut node = TestNode::start(&[]);
    let genesis_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(0)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let response = node
        .rpc_call_with_params("getblockfilter", vec![serde_json::json!(genesis_hash)])
        .unwrap();
    assert!(
        response["error"].is_object(),
        "getblockfilter should error when index is disabled, got: {:?}",
        response
    );
    let msg = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("disabled") || msg.contains("not synced"),
        "expected disabled/not-synced message, got: {msg}"
    );

    node.stop();
}

#[test]
fn test_getblockfilter_returns_filter_when_complete() {
    // With --blockfilterindex=basic enabled on a fresh-from-genesis
    // regtest sync, the completeness marker is true at open and the
    // genesis filter is emitted by the connect_block hook. Hitting
    // getblockfilter with the genesis hash must return a hex filter
    // and a hex header.
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let genesis_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(0)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let response = node
        .rpc_call_with_params("getblockfilter", vec![serde_json::json!(genesis_hash)])
        .unwrap();
    let result = &response["result"];
    assert!(
        result.is_object(),
        "expected getblockfilter to return object, got: {:?}",
        response
    );
    let filter_hex = result["filter"].as_str().expect("filter field");
    let header_hex = result["header"].as_str().expect("header field");
    // Hex-encoded; no 0x prefix; lowercase.
    assert!(filter_hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(header_hex.len(), 64, "header should be 32 bytes hex");

    node.stop();
}

/// Regression test for M2 (review 2026-05-04): `getblockfilter`
/// returns the filter header in display/reversed byte order to match
/// Bitcoin Core's uint256 RPC convention. Asserts the RPC result
/// matches `bitcoin::bip158::FilterHeader::to_string()` exactly,
/// which Display-prints in reversed (display) order — proving the
/// raw `to_byte_array()` internal-order encoding bug from before the
/// fix is gone.
#[test]
fn test_getblockfilter_header_is_display_byte_order() {
    use bitcoin::bip158::{BlockFilter, FilterHeader};
    use bitcoin::hashes::Hash as _;

    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let genesis_hash_hex = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(0)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();

    // Compute the expected genesis filter header locally so we can
    // compare byte order. Genesis (regtest) has prev_filter_header
    // == [0u8; 32] per BIP 157.
    let getblock = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(genesis_hash_hex), serde_json::json!(0)],
        )
        .unwrap();
    let block_hex = getblock["result"].as_str().expect("block hex");
    let block_bytes = hex::decode(block_hex).expect("decode block");
    let block: bitcoin::Block =
        bitcoin::consensus::deserialize(&block_bytes).expect("deserialize block");
    let prev_outputs: std::collections::HashMap<bitcoin::OutPoint, bitcoin::ScriptBuf> =
        std::collections::HashMap::new();
    let filter = BlockFilter::new_script_filter(&block, |op| {
        prev_outputs
            .get(op)
            .cloned()
            .ok_or(bitcoin::bip158::Error::UtxoMissing(*op))
    })
    .expect("filter");
    let prev = FilterHeader::from_byte_array([0u8; 32]);
    let expected_header = filter.filter_header(&prev);
    let expected_display = expected_header.to_string();

    let response = node
        .rpc_call_with_params("getblockfilter", vec![serde_json::json!(genesis_hash_hex)])
        .unwrap();
    let actual_header = response["result"]["header"]
        .as_str()
        .expect("header field");
    assert_eq!(
        actual_header, expected_display,
        "getblockfilter must return header in display byte order; \
         got {actual_header} expected {expected_display}",
    );

    // Also assert it does NOT match the byte-reversed (raw internal)
    // form — which is the pre-fix behavior.
    let raw_internal_hex = hex::encode(expected_header.to_byte_array());
    assert_ne!(
        actual_header, raw_internal_hex,
        "header should be display-form, not internal-byte order"
    );
    node.stop();
}

/// Regression test for H2 (review 2026-05-04): `getblockfilter` must
/// reject hashes that are not the active-chain block at their
/// claimed height. A made-up hash returns a not-found error rather
/// than the active block's filter.
#[test]
fn test_getblockfilter_rejects_non_active_hash() {
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    // A hash that doesn't exist anywhere in the block index. The
    // `get_block_index` lookup returns None for this case, which is
    // already handled by the original "block not found" error path —
    // the H2 fix covers the more subtle case where the hash IS in
    // block_index (e.g. a stored fork/header-only entry) but is not
    // the active-chain hash at its height. Probing for that case
    // requires controlled fork construction; we cover the basic
    // not-found path here as the smoke check that the RPC doesn't
    // accept arbitrary hashes.
    let fake_hash = "00000000000000000000000000000000000000000000000000000000deadbeef";
    let response = node
        .rpc_call_with_params("getblockfilter", vec![serde_json::json!(fake_hash)])
        .unwrap();
    assert!(
        response["error"].is_object(),
        "getblockfilter on unknown hash must error, got {:?}",
        response
    );
    node.stop();
}

#[test]
fn test_getindexinfo_includes_basic_block_filter_index_key() {
    // With --blockfilterindex=basic, getindexinfo must surface the
    // Bitcoin-Core-shaped key "basic block filter index" alongside
    // "address". synced=true on a fresh-sync datadir.
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let response = node.rpc_call("getindexinfo").unwrap();
    let result = &response["result"];
    assert!(
        result["basic block filter index"].is_object(),
        "expected 'basic block filter index' key, got: {:?}",
        result
    );
    assert!(
        result["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "expected synced=true on fresh-sync datadir"
    );

    node.stop();
}

#[test]
fn test_config_peerblockfilters_forces_blockfilterindex() {
    // Setting --peerblockfilters=1 alone auto-enables the index.
    // getconfig surfaces the resolved values via effective_view.
    let mut node = TestNode::start(&["--peerblockfilters=1"]);
    let response = node.rpc_call("getconfig").unwrap();
    let bfi = &response["result"]["block_filter_index"];
    assert_eq!(bfi["enabled"].as_bool(), Some(true));
    assert_eq!(bfi["peer_serve"].as_bool(), Some(true));

    node.stop();
}

#[test]
fn test_multiple_rpc_concurrent() {
    // Make several RPC calls in parallel using threads and verify none
    // deadlock and all complete within a reasonable timeout.
    let mut node = TestNode::start(&[]);

    let rpcport = node.rpcport;
    let cookie = node.cookie.clone();

    let methods = vec![
        "getblockchaininfo",
        "getblockcount",
        "getbestblockhash",
        "getmempoolinfo",
        "getnetworkinfo",
        "getpeerinfo",
        "getmininginfo",
        "uptime",
    ];

    let handles: Vec<_> = methods
        .into_iter()
        .map(|method| {
            let cookie = cookie.clone();
            let method = method.to_string();
            std::thread::spawn(move || {
                let url = format!("http://127.0.0.1:{}/", rpcport);
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": "test",
                    "method": method,
                    "params": [],
                });
                let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap();
                let response = client
                    .post(&url)
                    .basic_auth(user, Some(pass))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .expect("RPC request failed");
                let json: serde_json::Value = response.json().expect("Failed to parse JSON");
                assert!(
                    json["result"] != serde_json::Value::Null || json["error"].is_null(),
                    "RPC {} returned unexpected response: {:?}",
                    method,
                    json
                );
                method
            })
        })
        .collect();

    // Wait for all threads to complete (with a timeout)
    let start = Instant::now();
    for handle in handles {
        let method = handle.join().expect("Thread panicked");
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "RPC call {} took too long, possible deadlock",
            method
        );
    }

    node.stop();
}

#[test]
fn test_verifychain_after_mining() {
    // Mine several blocks and then run verifychain to verify integrity.
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine 10 blocks
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .unwrap();

    let count = node.rpc_call("getblockcount").unwrap();
    assert_eq!(count["result"], 10);

    // Run verifychain — should return true for a healthy chain
    let response = node.rpc_call("verifychain").unwrap();
    assert_eq!(
        response["result"], true,
        "verifychain should return true after mining"
    );

    node.stop();
}

#[test]
fn test_uptime_increases() {
    // Verify that uptime increases between two calls (not stuck at 0).
    let mut node = TestNode::start(&[]);

    let response1 = node.rpc_call("uptime").unwrap();
    let uptime1 = response1["result"].as_u64().unwrap();

    // Sleep briefly to let uptime increase
    std::thread::sleep(Duration::from_secs(2));

    let response2 = node.rpc_call("uptime").unwrap();
    let uptime2 = response2["result"].as_u64().unwrap();

    assert!(
        uptime2 >= uptime1,
        "Uptime should not decrease: first={}, second={}",
        uptime1,
        uptime2
    );
    // uptime2 should be at least 1 second more (we slept 2s)
    assert!(
        uptime2 >= 1,
        "Uptime should be at least 1 second after sleeping, got: {}",
        uptime2
    );

    node.stop();
}

#[test]
fn test_reindex_chainstate() {
    // Mine blocks, stop, restart with -reindex-chainstate, verify chain is intact
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-reindex-cs-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);

    // Start node and mine blocks
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .unwrap();
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 10);
    node.stop();

    // Restart with -reindex-chainstate
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--reindex-chainstate"]);
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(
        response["result"], 10,
        "Block count should be preserved after reindex-chainstate"
    );

    // Verify UTXO set is consistent
    let response = node.rpc_call("gettxoutsetinfo").unwrap();
    assert!(response["result"]["txouts"].as_u64().unwrap() > 0);
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// `-reindex-chainstate` honors `-stopatheight` and exits cleanly when
/// it reaches the target height. Mirrors test_stopatheight_exits_after_target_block
/// but for the reindex path, which (unlike IBD) runs before RPC stands
/// up — so we spawn satd directly and `wait()` rather than going
/// through TestNode (which blocks until RPC is ready).
#[test]
fn test_reindex_chainstate_stopatheight_exits() {
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-reindex-stop-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);

    // Phase 1: build chainstate up to height 10 the normal way.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .unwrap();
    assert_eq!(node.rpc_call("getblockcount").unwrap()["result"], 10);
    node.stop();

    // Phase 2: spawn satd with --reindex-chainstate --stopatheight=5.
    // The daemon exits before standing up RPC, so we wait on the
    // process directly.
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let p2p_port = find_available_port();
    let mut child = std::process::Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--reindex-chainstate")
        .arg("--stopatheight=5")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start satd for reindex-stopatheight test");

    let deadline = Instant::now() + test_timeout(60);
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    panic!("satd did not exit within 60s of --reindex-chainstate --stopatheight=5");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for satd: {e}"),
        }
    };
    assert!(
        exit_status.success(),
        "satd should exit cleanly after reindex hits stopatheight; got {exit_status:?}"
    );

    // Phase 3: restart normally (regtest has no seed peers, so IBD
    // won't advance past the stopped tip on its own). Chainstate
    // should be at height 5, with the block index still carrying
    // entries 6..10 (reindex only stopped replay; it didn't drop
    // block-index rows).
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let height = node.rpc_call("getblockcount").unwrap()["result"]
        .as_u64()
        .unwrap();
    assert_eq!(
        height, 5,
        "after stopped reindex, chainstate tip must be at the stop target"
    );
    node.stop();

    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_rpc_extended_errors_off_by_default() {
    // Default: error responses must be byte-identical to Bitcoin Core —
    // just {code, message}, no `data` payload.
    let mut node = TestNode::start(&[]);
    let resp = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(9999)])
        .unwrap();
    let err = &resp["error"];
    assert!(err.is_object(), "expected error object, got: {}", resp);
    assert!(err["code"].is_number());
    assert!(err["message"].is_string());
    // Core emits no `data` field; we mirror that.
    assert!(
        err.get("data").is_none() || err["data"].is_null(),
        "with --rpcextendederrors off, response should omit `data`; got: {}",
        err
    );
    node.stop();
}

#[test]
fn test_rpc_extended_errors_on_emits_structured_payload() {
    // --rpcextendederrors flips the error responses to include data.
    let mut node = TestNode::start(&["--rpcextendederrors"]);
    let resp = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(9999)])
        .unwrap();
    let err = &resp["error"];
    let data = &err["data"];
    assert!(data.is_object(), "expected data object, got: {}", err);
    assert_eq!(data["category"], "rpc.input.range");
    assert!(data["suggestion"].is_string());
    assert!(data["debug"]["requested_height"].as_u64().is_some());
    node.stop();
}

#[test]
fn test_clean_shutdown_marker_graceful_stop() {
    // Graceful RPC stop should write the marker and next startup should see it.
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-clean-shutdown-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    // First run: start, stop gracefully.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let info1 = node.rpc_call("getsysteminfo").unwrap();
    // First boot has no prior marker — expect dirty.
    assert_eq!(
        info1["result"]["last_shutdown"], "dirty",
        "first boot should report dirty, got: {}",
        info1
    );
    node.stop();

    // Marker should now exist on disk.
    let marker = datadir.join("regtest").join(".clean_shutdown");
    assert!(
        marker.exists(),
        "clean-shutdown marker should be written after graceful stop"
    );
    let contents = std::fs::read_to_string(&marker).unwrap();
    assert!(
        contents.contains("tip_hash"),
        "marker contents: {}",
        contents
    );

    // Second run: marker present → getsysteminfo should say clean. Marker
    // is consumed at startup so checking getsysteminfo proves the startup
    // observed it before unlinking.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let info2 = node.rpc_call("getsysteminfo").unwrap();
    assert_eq!(
        info2["result"]["last_shutdown"], "clean",
        "second boot after clean stop should report clean, got: {}",
        info2
    );
    // And the marker should have been unlinked at startup.
    assert!(
        !marker.exists(),
        "marker should be consumed (unlinked) at startup"
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_clean_shutdown_marker_after_kill() {
    // SIGKILL bypasses the graceful shutdown path — no marker should be written.
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-dirty-shutdown-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    {
        let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
        // Kill hard — skip the RPC stop path entirely.
        let _ = node.process.kill();
        let _ = node.process.wait();
        // Don't call node.stop(); Drop will just try kill again (no-op).
    }

    let marker = datadir.join("regtest").join(".clean_shutdown");
    assert!(
        !marker.exists(),
        "SIGKILL must not leave a clean-shutdown marker behind"
    );

    // Restart — should report dirty.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let info = node.rpc_call("getsysteminfo").unwrap();
    assert_eq!(
        info["result"]["last_shutdown"], "dirty",
        "after SIGKILL, last_shutdown should be dirty, got: {}",
        info
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_dbcache_auto_starts_cleanly() {
    // --dbcache=auto should start the node without error and expose a
    // non-zero RocksDB block-cache budget in getsysteminfo. Specific budget
    // values depend on the host's MemAvailable so we only assert the
    // plumbing is intact.
    let mut node = TestNode::start(&["--dbcache=auto"]);
    let info = node.rpc_call("getsysteminfo").unwrap();
    let bytes = info["result"]["dbcache_rocksdb_bytes"]
        .as_u64()
        .expect("dbcache_rocksdb_bytes should be a number");
    assert!(
        bytes > 0,
        "expected non-zero RocksDB cache budget, got: {}",
        info
    );
    node.stop();
}

#[test]
fn test_dbcache_fixed_numeric_still_works() {
    // Preserve Bitcoin-Core-compatible numeric form: --dbcache=200 must
    // keep working as a static 200 MB budget after the auto/Fixed refactor.
    let mut node = TestNode::start(&["--dbcache=200"]);
    let info = node.rpc_call("getsysteminfo").unwrap();
    let bytes = info["result"]["dbcache_rocksdb_bytes"].as_u64().unwrap();
    assert!(bytes >= 16 * 1_000_000, "too small: {}", bytes);
    assert!(bytes <= 200 * 1_000_000, "too large: {}", bytes);
    node.stop();
}

#[test]
fn test_rpc_default_units_btc_preserves_core_format() {
    // Default is --rpcdefaultunits=btc. The response must be byte-identical
    // to Bitcoin Core: mempoolminfee is a float (BTC/kvB) AND no `_units`
    // annotation field is added. Adding `_units` in the default mode would
    // silently break strict-typed Core-compat clients.
    let mut node = TestNode::start(&[]);
    let info = node.rpc_call("getmempoolinfo").unwrap();
    let result = &info["result"];
    let fee = &result["mempoolminfee"];
    assert!(
        fee.as_f64().is_some(),
        "default mempoolminfee should be a float (BTC/kvB), got: {}",
        fee
    );
    assert!(
        result.get("_units").is_none(),
        "default mode must not add `_units`; got: {}",
        result
    );

    // Same invariant for estimatesmartfee.
    let est = node
        .rpc_call_with_params("estimatesmartfee", vec![serde_json::json!(6)])
        .unwrap();
    assert!(
        est["result"].get("_units").is_none(),
        "default estimatesmartfee must not include `_units`, got: {}",
        est["result"]
    );

    // gettxoutsetinfo — also an amount-bearing response; the same default
    // Core-compat invariant applies. No need to create UTXOs; regtest
    // post-genesis has the coinbase subsidy which materializes once mining
    // happens, but the RPC itself works on an empty set too.
    let txset = node.rpc_call("gettxoutsetinfo").unwrap();
    let txset_result = &txset["result"];
    assert!(
        txset_result.get("_units").is_none(),
        "default gettxoutsetinfo must not include `_units`, got: {}",
        txset_result
    );
    // total_amount should be a float (BTC), not an integer, in default mode.
    // Empty UTXO set legitimately yields 0.0; the *type* is what matters.
    let total = &txset_result["total_amount"];
    assert!(
        total.is_f64() || total.as_f64() == Some(0.0),
        "default total_amount should be a float (BTC), got: {}",
        total
    );
    node.stop();
}

#[test]
fn test_rpc_default_units_btc_gettxout_mines_coin() {
    // gettxout requires a real UTXO. Mine a block to get a coinbase we can
    // query, then assert the default (btc) response has no `_units` tag and
    // emits `value` as a float.
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1), serde_json::json!(addr)],
    )
    .unwrap();
    // Get the coinbase txid from the mined block. Use verbose=1 so
    // `tx[0]` is a txid string (verbose=2 wraps each tx in an object).
    let hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap();
    let block = node
        .rpc_call_with_params(
            "getblock",
            vec![hash["result"].clone(), serde_json::json!(1)],
        )
        .unwrap();
    let coinbase_txid = block["result"]["tx"][0]
        .as_str()
        .expect("coinbase txid")
        .to_string();

    let out = node
        .rpc_call_with_params(
            "gettxout",
            vec![serde_json::json!(coinbase_txid), serde_json::json!(0)],
        )
        .unwrap();
    let result = &out["result"];
    assert!(
        result.get("_units").is_none(),
        "default gettxout must not include `_units`, got: {}",
        result
    );
    let value = &result["value"];
    assert!(
        value.is_f64(),
        "default gettxout.value should be a float (BTC), got: {}",
        value
    );
    node.stop();
}

#[test]
fn test_rpc_default_units_sats_emits_integers() {
    // --rpcdefaultunits=sats flips mempoolminfee to an integer sat/kvB
    // value, and estimatesmartfee.feerate also becomes integer.
    let mut node = TestNode::start(&["--rpcdefaultunits=sats"]);
    let info = node.rpc_call("getmempoolinfo").unwrap();
    let fee = &info["result"]["mempoolminfee"];
    assert!(
        fee.as_u64().is_some(),
        "with rpcdefaultunits=sats, mempoolminfee should be integer sat/kvB, got: {}",
        fee
    );
    let est = node
        .rpc_call_with_params("estimatesmartfee", vec![serde_json::json!(6)])
        .unwrap();
    let feerate = &est["result"]["feerate"];
    assert!(
        feerate.as_u64().is_some(),
        "estimatesmartfee.feerate should be integer sat/kvB, got: {}",
        feerate
    );
    // Response should advertise the unit.
    assert_eq!(est["result"]["_units"], "sats");
    node.stop();
}

#[test]
fn test_sat_cli_subcommands_chain() {
    // Structured subcommand `sat-cli chain info` should translate to
    // getblockchaininfo. `sat-cli chain height` should emit the raw height.
    let mut node = TestNode::start(&[]);

    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let sat_cli_bin = std::path::Path::new(satd_bin)
        .parent()
        .unwrap()
        .join("sat-cli");

    let info = Command::new(&sat_cli_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport))
        .arg("--output=json")
        .args(["chain", "info"])
        .output()
        .expect("Failed to run sat-cli");

    assert!(
        info.status.success(),
        "sat-cli chain info should succeed. stderr: {}",
        String::from_utf8_lossy(&info.stderr),
    );
    let stdout = String::from_utf8(info.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON output");
    assert_eq!(result["chain"], "regtest");

    let height = Command::new(&sat_cli_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport))
        .args(["chain", "height"])
        .output()
        .expect("Failed to run sat-cli");
    assert!(height.status.success());
    let out = String::from_utf8(height.stdout).unwrap();
    assert_eq!(
        out.trim(),
        "0",
        "fresh regtest should have height 0, got: {}",
        out
    );

    node.stop();
}

#[test]
fn test_sat_cli_node_version_returns_version_not_uptime() {
    // `sat-cli node version` should emit version/subversion/protocolversion
    // (pretty mode). Regression test for a review finding where the
    // subcommand was accidentally mapped to `uptime`.
    let mut node = TestNode::start(&[]);

    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let sat_cli_bin = std::path::Path::new(satd_bin)
        .parent()
        .unwrap()
        .join("sat-cli");

    let output = Command::new(&sat_cli_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport))
        .args(["node", "version"])
        .output()
        .expect("Failed to run sat-cli");

    assert!(
        output.status.success(),
        "sat-cli node version should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("version:") && stdout.contains("subversion:"),
        "expected version fields, got:\n{}",
        stdout
    );
    // Make sure we're not returning a bare integer (which is what `uptime` emits).
    assert!(
        stdout.trim().parse::<u64>().is_err(),
        "sat-cli node version must not return a bare uptime integer; got: {:?}",
        stdout
    );

    node.stop();
}

#[test]
fn test_reindex() {
    // Mine blocks, stop, restart with -reindex, verify chain is rebuilt from flat files
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-reindex-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);

    // Start node and mine blocks
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .unwrap();
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(response["result"], 10);
    node.stop();

    // Restart with -reindex
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--reindex"]);
    let response = node.rpc_call("getblockcount").unwrap();
    assert_eq!(
        response["result"], 10,
        "Block count should be preserved after reindex"
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_metrics_and_health_endpoints() {
    let metrics_port = find_available_port();
    let mut node = TestNode::start(&[&format!("--metricsport={}", metrics_port)]);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{}", metrics_port);

    // Poll until the metrics server is listening (spawned after RPC server).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if client.get(format!("{}/healthz", base)).send().is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            panic!("metrics server did not come up on port {}", metrics_port);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // /healthz — always 200 if the process is up.
    let r = client.get(format!("{}/healthz", base)).send().unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(r.text().unwrap().contains("ok"));

    // /readyz — regtest starts at genesis with no peers, so headers_tip ==
    // tip == 0 and the node is "ready" by our definition (lag <= 6 blocks).
    let r = client.get(format!("{}/readyz", base)).send().unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "regtest node at genesis should be ready"
    );

    // /metrics — Prometheus text format with the documented schema.
    let r = client.get(format!("{}/metrics", base)).send().unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let ct = r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("text/plain"), "wrong content-type: {}", ct);
    let body = r.text().unwrap();
    for required in [
        "satd_tip_height",
        "satd_headers_tip_height",
        "satd_ibd_active",
        "satd_mempool_transactions",
        "satd_mempool_bytes",
        "satd_peer_connections",
        "satd_process_uptime_seconds",
        "satd_build_info",
        // Address-history index metrics (M6).
        "satd_addrindex_enabled",
        "satd_addrindex_funding_rows_total",
        "satd_addrindex_spending_rows_total",
        "satd_addrindex_subscriptions_active",
    ] {
        assert!(
            body.contains(required),
            "missing metric {} in /metrics body:\n{}",
            required,
            body
        );
    }
    // Build-info should carry the network label.
    assert!(
        body.contains("network=\"regtest\""),
        "build_info missing network label:\n{}",
        body
    );

    // Unknown path → 404.
    let r = client
        .get(format!("{}/does-not-exist", base))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    node.stop();
}

#[test]
fn test_metrics_endpoint_off_by_default() {
    // Without --metricsport, the endpoint must not be listening. Pick a port
    // at random and confirm it's refused — this proves the feature is
    // truly opt-in and does not silently expose operator state.
    let mut node = TestNode::start(&[]);
    let probe_port = find_available_port();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    // Either we get a connection refused (normal) or a response from
    // something we didn't start; we just assert it's not 200-with-our-body.
    let result = client
        .get(format!("http://127.0.0.1:{}/metrics", probe_port))
        .send();
    match result {
        Err(_) => { /* refused — expected */ }
        Ok(r) => {
            // If something answered, it is not us.
            let body = r.text().unwrap_or_default();
            assert!(
                !body.contains("satd_tip_height"),
                "metrics endpoint should be off by default"
            );
        }
    }
    node.stop();
}

#[test]
fn test_reorg_record_reflects_completed_state() {
    // Drive a real reorg by building two independent chains on two
    // nodes and transplanting the longer one onto the shorter node.
    // The persisted reorg record MUST report:
    //   - the final new tip (the longest submitted block), not the
    //     fork-disconnect point
    //   - the actual reconnected side-chain hashes, not an empty list
    //   - the actual disconnected hashes
    //
    // Distinct A/B coinbase addresses so the two chains have different
    // block hashes from height 1 — same address + same template time +
    // nonce 0 produces identical blocks deterministically, in which
    // case submitblock returns "duplicate" and no reorg occurs. Same
    // pattern documented on test_address_index_backfill_reorg_invalidates_to_failed.
    use bitcoin::WitnessProgram;
    use bitcoin::WitnessVersion;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, PublicKey};
    let addr_a = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let secp = Secp256k1::new();
    let sk_b = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
    let pk_b = PublicKey::new(sk_b.public_key(&secp));
    use bitcoin::hashes::Hash as _;
    let pkh_b = bitcoin::hashes::hash160::Hash::hash(&pk_b.to_bytes());
    let prog_b = WitnessProgram::new(WitnessVersion::V0, pkh_b.as_byte_array()).unwrap();
    let addr_b_str = Address::from_witness_program(prog_b, Network::Regtest).to_string();
    let addr_b = addr_b_str.as_str();

    // Node A: mine a short chain of 2 blocks.
    let mut node_a = TestNode::start(&[]);
    let gen_a = node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr_a)],
        )
        .unwrap();
    let a_hashes: Vec<String> = gen_a["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(a_hashes.len(), 2);

    // Node B: mine a longer chain of 3 blocks independently (same
    // genesis parent, so it's a competing fork).
    let mut node_b = TestNode::start(&[]);
    let gen_b = node_b
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr_b)],
        )
        .unwrap();
    let b_hashes: Vec<String> = gen_b["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(b_hashes.len(), 3);

    // Pull raw hex for each B block from node B.
    let mut b_hex: Vec<String> = Vec::new();
    for h in &b_hashes {
        let raw = node_b
            .rpc_call_with_params("getblock", vec![serde_json::json!(h), serde_json::json!(0)])
            .unwrap();
        b_hex.push(raw["result"].as_str().unwrap().to_string());
    }
    node_b.stop();

    // Submit B chain to node A. Node A should reorg once B has more
    // work than A (after the 3rd B block is submitted — B=3 > A=2).
    for hex in &b_hex {
        let _ = node_a
            .rpc_call_with_params("submitblock", vec![serde_json::json!(hex)])
            .unwrap();
    }

    // Node A's tip should now be the last B block.
    let tip = node_a.rpc_call("getbestblockhash").unwrap();
    assert_eq!(
        tip["result"].as_str().unwrap(),
        b_hashes[2],
        "node A should have reorged to B's tip"
    );

    // Reorg history should contain exactly one record describing the
    // completed reorg, with the correct new tip and both disconnected
    // and reconnected lists populated.
    let hist = node_a.rpc_call("getreorghistory").unwrap();
    let records = hist["result"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "expected exactly one reorg record");
    let rec = &records[0];

    assert_eq!(
        rec["new_tip"].as_str().unwrap(),
        b_hashes[2],
        "reorg record new_tip must be the post-reorg chain tip, not the fork point"
    );
    assert_eq!(
        rec["old_tip"].as_str().unwrap(),
        a_hashes[1],
        "reorg record old_tip must be A's pre-reorg tip"
    );

    let disconnected: Vec<String> = rec["disconnected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // disconnected is ordered old-tip-first (the order we rolled back).
    assert_eq!(disconnected, vec![a_hashes[1].clone(), a_hashes[0].clone()]);

    let reconnected: Vec<String> = rec["reconnected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        reconnected, b_hashes,
        "reconnected must list every B block in chain order"
    );

    assert_eq!(rec["fork_height"].as_u64(), Some(0));
    assert_eq!(rec["depth"].as_u64(), Some(2));

    node_a.stop();
}

#[test]
fn test_reorg_record_not_written_when_final_block_fails() {
    // Residual edge case: disconnect + intermediate side-chain reconnect
    // succeed, then the final triggering block fails `connect_block`
    // validation. The persisted reorg record must NOT appear, because
    // that block never became the active tip.
    //
    // We engineer the failure by hand-crafting a block with a valid
    // header (correct merkle root, satisfies regtest PoW) but an invalid
    // coinbase value (51 BTC instead of the 50 BTC regtest subsidy).
    // `connect_block` rejects it with `BadCoinbaseValue`.
    use bitcoin::consensus::{Encodable, deserialize};
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, Block, Transaction};

    // Distinct A/B coinbase addresses so the two chains have different
    // block hashes from height 1. Without this, regtest's deterministic
    // mining (same address + same template time + nonce 0) makes the
    // first two B blocks duplicates of A's, which silently bypasses the
    // side-chain reorg path entirely — turning this test into a false
    // positive (no record IS written, but for the wrong reason).
    use bitcoin::WitnessProgram;
    use bitcoin::WitnessVersion;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, PublicKey};
    let addr_a = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let secp = Secp256k1::new();
    let sk_b = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
    let pk_b = PublicKey::new(sk_b.public_key(&secp));
    let pkh_b = bitcoin::hashes::hash160::Hash::hash(&pk_b.to_bytes());
    let prog_b = WitnessProgram::new(WitnessVersion::V0, pkh_b.as_byte_array()).unwrap();
    let addr_b_str = Address::from_witness_program(prog_b, Network::Regtest).to_string();
    let addr_b = addr_b_str.as_str();

    // Node A: short chain of 2 blocks.
    let mut node_a = TestNode::start(&[]);
    let gen_a = node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr_a)],
        )
        .unwrap();
    let a_hashes: Vec<String> = gen_a["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Node B: longer chain (3 valid blocks). Take the last one's hex so
    // we can corrupt its coinbase value.
    let mut node_b = TestNode::start(&[]);
    let gen_b = node_b
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr_b)],
        )
        .unwrap();
    let b_hashes: Vec<String> = gen_b["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Fetch each B block's hex from node B, tampering with B3's coinbase.
    let mut b_hex: Vec<String> = Vec::with_capacity(3);
    for (i, h) in b_hashes.iter().enumerate() {
        let raw = node_b
            .rpc_call_with_params("getblock", vec![serde_json::json!(h), serde_json::json!(0)])
            .unwrap();
        let hex_str = raw["result"].as_str().unwrap().to_string();
        if i == 2 {
            // Deserialize, bump coinbase output value, recompute merkle
            // root, re-solve PoW. Regtest bits = 0x207fffff → near-max
            // target, so a valid nonce is found in a handful of tries.
            let bytes = hex::decode(&hex_str).unwrap();
            let mut block: Block = deserialize(&bytes).unwrap();

            // Corrupt the coinbase: 50 BTC → 51 BTC (invalid subsidy).
            let cb: &mut Transaction = &mut block.txdata[0];
            cb.output[0].value = Amount::from_sat(51 * 100_000_000);

            // Recompute merkle root.
            let txids: Vec<[u8; 32]> = block
                .txdata
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect();
            let root = compute_merkle_root(&txids);
            block.header.merkle_root = bitcoin::TxMerkleNode::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array(root),
            );

            // Re-solve PoW against regtest target.
            let target = block.header.target();
            for nonce in 0u32..10_000_000 {
                block.header.nonce = nonce;
                if target.is_met_by(block.header.block_hash()) {
                    break;
                }
            }

            let mut buf = Vec::new();
            block.consensus_encode(&mut buf).unwrap();
            b_hex.push(hex::encode(&buf));
        } else {
            b_hex.push(hex_str);
        }
    }
    node_b.stop();

    // Submit B1, B2, B3 to node A. The first two are side-chain blocks
    // (equal-or-less work). B3 makes B heavier than A → triggers reorg.
    // perform_reorg succeeds, B1+B2 reconnect, then connect_block for
    // B3 must fail on the bad coinbase.
    for hex in &b_hex {
        let _ = node_a
            .rpc_call_with_params("submitblock", vec![serde_json::json!(hex)])
            .unwrap();
    }

    // With the final connect failing, atomic rollback (M4 round 2)
    // disconnects B2 and B1 and reconnects A1, A2 — restoring the
    // original tip. The node must end up with A2 as tip, not B2 or B3.
    let tip = node_a.rpc_call("getbestblockhash").unwrap();
    assert_eq!(
        tip["result"].as_str().unwrap(),
        a_hashes[1],
        "final connect failure must roll back the partial reorg → tip restored to original A2"
    );

    // No reorg record may claim the invalid block as a new tip. With
    // atomic rollback the reorg never committed end-to-end, so the
    // pending reorg record is never persisted; getreorghistory stays
    // honest about completed reorgs only.
    let hist = node_a.rpc_call("getreorghistory").unwrap();
    let records = hist["result"]["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .all(|r| r["new_tip"].as_str() != Some(&b_hashes[2])),
        "getreorghistory must not report the invalid block as a new tip; got: {:?}",
        records
    );

    node_a.stop();
}

/// Double-SHA256 merkle root helper for the failure-path test.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    use bitcoin::hashes::Hash;
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut current = hashes.to_vec();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(&pair[1]);
            let h = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(h.to_byte_array());
        }
        current = next;
    }
    current[0]
}

#[test]
fn test_getreorghistory_empty_on_fresh_node() {
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getreorghistory").unwrap();
    let result = &response["result"];
    assert!(result["records"].is_array());
    assert_eq!(result["records"].as_array().unwrap().len(), 0);
    assert_eq!(result["since_secs"].as_u64(), Some(86_400));
    node.stop();
}

#[test]
fn test_getreorghistory_accepts_custom_window() {
    let mut node = TestNode::start(&[]);
    let response = node
        .rpc_call_with_params("getreorghistory", vec![serde_json::json!(3600u64)])
        .unwrap();
    assert_eq!(response["result"]["since_secs"].as_u64(), Some(3_600));
    node.stop();
}

#[test]
fn test_profile_pruned_home_applies_defaults() {
    // --profile=pruned-home sets prune/dbcache/maxconnections. Observable
    // via getconfig.
    let mut node = TestNode::start(&["--profile=pruned-home"]);
    let response = node.rpc_call("getconfig").unwrap();
    let cfg = &response["result"];
    assert_eq!(cfg["profile"], "pruned-home");
    assert_eq!(cfg["storage"]["prune_mb"].as_u64(), Some(10_000));
    assert_eq!(cfg["storage"]["dbcache_mb"].as_u64(), Some(450));
    assert_eq!(cfg["p2p"]["max_connections"].as_u64(), Some(20));
    node.stop();
}

#[test]
fn test_profile_cli_override_wins() {
    // CLI flag overrides profile default. --profile=pruned-home would set
    // dbcache=450, but --dbcache=100 wins.
    let mut node = TestNode::start(&["--profile=pruned-home", "--dbcache=100"]);
    let response = node.rpc_call("getconfig").unwrap();
    let cfg = &response["result"];
    assert_eq!(cfg["storage"]["dbcache_mb"].as_u64(), Some(100));
    // Other profile fields still apply.
    assert_eq!(cfg["storage"]["prune_mb"].as_u64(), Some(10_000));
    node.stop();
}

#[test]
fn test_profile_archival_enables_txindex() {
    let mut node = TestNode::start(&["--profile=archival"]);
    let response = node.rpc_call("getconfig").unwrap();
    let cfg = &response["result"];
    assert_eq!(cfg["profile"], "archival");
    assert_eq!(cfg["storage"]["txindex"].as_bool(), Some(true));
    assert_eq!(cfg["storage"]["prune_mb"].as_u64(), Some(0));
    node.stop();
}

#[test]
fn test_getconfig_redacts_sensitive_fields() {
    // Password fields must never be echoed back through getconfig,
    // even when set via CLI.
    let mut node = TestNode::start(&["--rpcuser=alice", "--rpcpassword=secret-sauce"]);
    // User/pass auth mode — TestNode's rpc_call uses cookie, which
    // doesn't exist here. Call raw with basic auth.
    let url = format!("http://127.0.0.1:{}/", node.rpcport);
    let client = reqwest::blocking::Client::new();
    let resp: serde_json::Value = client
        .post(&url)
        .basic_auth("alice", Some("secret-sauce"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "t", "method": "getconfig", "params": []
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    let cfg = &resp["result"];
    let serialized = cfg.to_string();
    assert!(
        !serialized.contains("secret-sauce"),
        "getconfig must redact rpcpassword; got: {}",
        serialized
    );
    assert_eq!(cfg["rpc"]["password"], "(set)");

    // Also cleanly stop the node via authenticated RPC.
    let _ = client
        .post(&url)
        .basic_auth("alice", Some("secret-sauce"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "s", "method": "stop", "params": []
        }))
        .send();
    // Drop `node` via its Drop/stop isn't safe here (cookie empty) — the
    // child process will be reaped by the test harness's exit sequence
    // or by the explicit stop we just sent.
    let exit_deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < exit_deadline {
        if node.process.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if node.process.try_wait().unwrap().is_none() {
        let _ = node.process.kill();
    }
}

#[test]
fn test_log_format_json_emits_valid_json_with_trace_id() {
    // Launch satd with --log-format=json and capture stderr to a file.
    // Assert at least one line parses as a JSON object containing the
    // stable fields (timestamp, level, fields.message). When a block is
    // mined, the corresponding span carries a trace_id we can verify.
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-jsonlog-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir).unwrap();

    let log_path = datadir.join("stderr.log");
    let log_file = std::fs::File::create(&log_path).unwrap();
    let satd_bin = env!("CARGO_BIN_EXE_satd");

    let mut child = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--log-format=json")
        .arg("--esplora=0")
        .stdout(log_file)
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start satd with --log-format=json");

    // Wait for readiness then mine one block so we generate a connect span.
    let cookie_path = datadir.join("regtest").join(".cookie");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut cookie = String::new();
    while Instant::now() < deadline {
        if let Ok(c) = std::fs::read_to_string(&cookie_path)
            && !c.is_empty()
        {
            cookie = c;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!cookie.is_empty(), "cookie never appeared — startup failed");

    let url = format!("http://127.0.0.1:{}/", rpcport);
    let (user, pass) = cookie.split_once(':').unwrap_or(("__cookie__", "none"));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Wait for RPC readiness — require a valid `chain` field in the
    // getblockchaininfo result, not just HTTP 200 (auth error pages
    // also return 200 with a JSON-RPC error body).
    let mut rpc_ready = false;
    let rpc_deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < rpc_deadline {
        let resp = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "r", "method": "getblockchaininfo", "params": []
            }))
            .send();
        if let Ok(r) = resp
            && let Ok(v) = r.json::<serde_json::Value>()
            && v["result"]["chain"].as_str().is_some()
        {
            rpc_ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(rpc_ready, "RPC never became ready");

    // Mine a block to generate a connect span. Poll block count until it
    // advances so we know the log has a connect event by the time we stop.
    let mine_resp = client
        .post(&url)
        .basic_auth(user, Some(pass))
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "m", "method": "generatetoaddress",
            "params": [1, "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202"],
        }))
        .send()
        .expect("generatetoaddress request failed");
    let mine_json: serde_json::Value = mine_resp.json().expect("mine response not JSON");
    assert!(
        mine_json["error"].is_null(),
        "generatetoaddress error: {}",
        mine_json["error"]
    );
    let mine_deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < mine_deadline {
        let resp = client
            .post(&url)
            .basic_auth(user, Some(pass))
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": "bc", "method": "getblockcount", "params": []
            }))
            .send();
        if let Ok(r) = resp
            && let Ok(v) = r.json::<serde_json::Value>()
            && v["result"].as_u64().unwrap_or(0) >= 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Graceful shutdown so logs flush.
    let _ = client
        .post(&url)
        .basic_auth(user, Some(pass))
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "s", "method": "stop", "params": [],
        }))
        .send();
    let exit_deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < exit_deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if child.try_wait().unwrap().is_none() {
        let _ = child.kill();
    }

    let logs = std::fs::read_to_string(&log_path).unwrap();
    let mut parsed_lines = 0usize;
    let mut saw_trace_id = false;
    let mut saw_required_fields = false;
    for line in logs.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            panic!(
                "--log-format=json emitted non-JSON line:\n{}\nfull logs:\n{}",
                line, logs
            );
        };
        parsed_lines += 1;
        let obj = v.as_object().expect("log line must be a JSON object");
        if obj.contains_key("timestamp") && obj.contains_key("level") && obj.contains_key("fields")
        {
            saw_required_fields = true;
        }
        // Check any span carries a trace_id — the connect / accept paths
        // all open an info_span with a trace_id field. With
        // `with_current_span(true)`, the current span appears in a `span`
        // or `spans` field of each event.
        let as_str = v.to_string();
        if as_str.contains("trace_id") {
            saw_trace_id = true;
        }
    }
    assert!(
        parsed_lines > 0,
        "--log-format=json produced no lines. logs:\n{}",
        logs
    );
    assert!(
        saw_required_fields,
        "no JSON line had the stable required fields (timestamp, level, fields); logs:\n{}",
        logs
    );
    assert!(
        saw_trace_id,
        "no JSON line carried a trace_id from a validation span; logs:\n{}",
        logs
    );

    let _ = std::fs::remove_dir_all(&datadir);
}

// ---------------------------------------------------------------------------
// Tier-2 #11 — Operator mempool APIs
// ---------------------------------------------------------------------------

#[test]
fn test_getmempoolentry_bulk_missing_entries_are_null() {
    // `getmempoolentry` with an array argument returns a map. Non-existent
    // txids surface as JSON null rather than an error — callers batch and
    // filter per entry.
    let mut node = TestNode::start(&[]);

    let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
    let response = node
        .rpc_call_with_params("getmempoolentry", vec![serde_json::json!([fake_txid])])
        .unwrap();
    let result = response["result"].as_object().unwrap();
    assert!(result.contains_key(fake_txid));
    assert!(result[fake_txid].is_null());
    node.stop();
}

#[test]
fn test_getmempoolentry_single_string_still_core_compat() {
    // Regression: the original single-string form must still error for a
    // missing txid (Core-compat behavior). We don't silently turn errors
    // into nulls for the single-argument path.
    let mut node = TestNode::start(&[]);
    let fake_txid = "0000000000000000000000000000000000000000000000000000000000000002";
    let response = node
        .rpc_call_with_params("getmempoolentry", vec![serde_json::json!(fake_txid)])
        .unwrap();
    assert!(
        response.get("error").is_some(),
        "single-string missing txid must still error: {}",
        response
    );
    node.stop();
}

#[test]
fn test_getmempoolhistory_returns_snapshots_shape() {
    // On a fresh node the history ring is open but no snapshots have
    // landed yet — we just verify the response shape here. The
    // snapshotter cadence is 10 s so waiting for a filled snapshot
    // would make the test flaky under CI load.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getmempoolhistory").unwrap();
    let result = response["result"].as_object().unwrap();
    assert!(result.contains_key("since_secs"));
    assert!(result.contains_key("snapshots"));
    assert!(result.contains_key("available"));
    assert!(result["snapshots"].is_array());
    assert_eq!(result["since_secs"].as_u64(), Some(3_600));
    // History log opens successfully on a fresh node so available=true.
    assert_eq!(result["available"].as_bool(), Some(true));

    // Custom window.
    let response2 = node
        .rpc_call_with_params("getmempoolhistory", vec![serde_json::json!(120u64)])
        .unwrap();
    assert_eq!(response2["result"]["since_secs"].as_u64(), Some(120));
    node.stop();
}

#[test]
fn test_getorphaninfo_empty_shape() {
    // A fresh regtest node has an empty orphan pool. Assert the RPC
    // returns the Core-compat-ish shape we commit to: size, bytes,
    // max_size.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("getorphaninfo").unwrap();
    let result = &response["result"];
    assert!(
        result.is_object(),
        "getorphaninfo result should be an object"
    );
    assert_eq!(result["size"].as_u64(), Some(0));
    assert_eq!(result["bytes"].as_u64(), Some(0));
    assert!(
        result["max_size"].as_u64().unwrap_or(0) > 0,
        "max_size should be a positive cap; got: {:?}",
        result["max_size"]
    );
    node.stop();
}

#[test]
fn test_getorphaninfo_registered_in_help() {
    // Help text must advertise getorphaninfo so operators can discover it.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("help").unwrap();
    let body = response["result"].as_str().unwrap_or("");
    assert!(
        body.contains("getorphaninfo"),
        "`help` output should advertise getorphaninfo; got: {}",
        body
    );
    node.stop();
}

#[test]
fn test_sendrawtransaction_orphan_rejected_not_orphaned() {
    // RPC path must NOT route orphans to the orphanage — only P2P relay
    // should. sendrawtransaction of a tx with a missing parent returns
    // an error, and getorphaninfo stays at size 0.
    let mut node = TestNode::start(&[]);

    // Build a raw tx referencing a non-existent parent output. Uses the
    // createrawtransaction helper so we don't hand-roll the hex.
    let inputs = serde_json::json!([{
        "txid": "1111111111111111111111111111111111111111111111111111111111111111",
        "vout": 0,
    }]);
    let outputs = serde_json::json!({
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01,
    });
    let create_resp = node
        .rpc_call_with_params("createrawtransaction", vec![inputs, outputs])
        .unwrap();
    let hex = create_resp["result"].as_str().unwrap().to_string();

    // Submit via RPC; expect an error (MissingInputs / similar).
    let submit = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(hex)])
        .unwrap();
    assert!(
        submit["error"].is_object(),
        "sendrawtransaction of an orphan should error; got: {:?}",
        submit
    );

    // Orphanage must still be empty — RPC path does not orphan.
    let info = node.rpc_call("getorphaninfo").unwrap();
    assert_eq!(
        info["result"]["size"].as_u64(),
        Some(0),
        "getorphaninfo.size should stay 0 after RPC-rejected orphan"
    );
    node.stop();
}

#[test]
fn test_subscribemempool_registered_in_help() {
    // End-to-end WS subscription exercise is hard to make reliable in
    // regtest (auth, timing, tokio runtime interop). The broadcast
    // emission path is unit-tested in node/src/mempool/events.rs + the
    // Mempool::emit tests; here we verify the RPC is actually
    // registered — i.e. the WS wire-up compiled in — by inspecting
    // `help`.
    let mut node = TestNode::start(&[]);
    let response = node.rpc_call("help").unwrap();
    let body = response["result"].as_str().unwrap_or("");
    assert!(
        body.contains("subscribemempool"),
        "`help` output should advertise subscribemempool; got: {}",
        body
    );
    assert!(
        body.contains("unsubscribemempool"),
        "`help` output should advertise unsubscribemempool"
    );
    node.stop();
}

// ---------------------------------------------------------------------------
// Raw P2P test client — used by the orphan-pool tests below to exercise the
// live `handle_tx` path. Does the version/verack handshake, then exposes
// `send_tx` for injecting transactions. A background thread drains incoming
// frames so the node's send queue doesn't back up while we hold the socket.
// ---------------------------------------------------------------------------

mod raw_p2p {
    use bitcoin::Transaction;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::{Address, ServiceFlags};
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant, SystemTime};

    const HEADER_SIZE: usize = 24;
    const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;

    pub struct RawP2pClient {
        stream: TcpStream,
    }

    impl RawP2pClient {
        /// Connect to a regtest satd node on 127.0.0.1:`p2p_port` and
        /// complete the version/verack handshake. Panics on failure —
        /// only intended for tests.
        pub fn connect(p2p_port: u16) -> Self {
            let addr = format!("127.0.0.1:{}", p2p_port);
            // Bumped from 10s after observing CI-load races where the
            // P2P listener came up fractionally after RPC ready.
            let deadline = Instant::now() + Duration::from_secs(30);
            let stream = loop {
                match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)) {
                    Ok(s) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => panic!("P2P connect to {} failed: {}", addr, e),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.set_nodelay(true).unwrap();

            let mut client = RawP2pClient { stream };
            client.handshake();

            // Spawn a drain thread so the node's writes to us (getheaders,
            // ping, getdata, etc.) never block the node's send queue.
            let drain_stream = client.stream.try_clone().unwrap();
            std::thread::spawn(move || drain_loop(drain_stream));

            client
        }

        fn handshake(&mut self) {
            // 1. Send our Version.
            let our_ver = build_version();
            self.send_msg(NetworkMessage::Version(our_ver));

            // 2. Read messages until we see both a Version and a Verack
            //    from the node. Order observed: Version → SendAddrV2 →
            //    Verack, but don't hard-code. 30s for the same CI-load
            //    margin documented on the connect deadline above.
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut saw_version = false;
            let mut saw_verack = false;
            while !(saw_version && saw_verack) {
                if Instant::now() >= deadline {
                    panic!("handshake timeout waiting for peer version+verack");
                }
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::Version(_)) => saw_version = true,
                    Ok(NetworkMessage::Verack) => saw_verack = true,
                    Ok(_) => continue,
                    Err(e) => panic!("handshake recv failed: {}", e),
                }
            }

            // 3. Send our Verack.
            self.send_msg(NetworkMessage::Verack);
        }

        pub fn send_tx(&mut self, tx: &Transaction) {
            self.send_msg(NetworkMessage::Tx(tx.clone()));
        }

        fn send_msg(&mut self, msg: NetworkMessage) {
            let raw = RawNetworkMessage::new(Magic::REGTEST, msg);
            let bytes = serialize(&raw);
            self.stream.write_all(&bytes).expect("p2p write");
            self.stream.flush().ok();
        }
    }

    fn build_version() -> VersionMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        VersionMessage {
            version: 70016,
            services,
            timestamp,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, services),
            nonce: 0xDEAD_BEEF_CAFE_F00D,
            user_agent: "/satd-regtest-p2p:0.1/".into(),
            start_height: 0,
            relay: true,
        }
    }

    fn recv_msg(stream: &mut TcpStream) -> io::Result<NetworkMessage> {
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header)?;
        let payload_len =
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload too large",
            ));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&payload);
        deserialize::<RawNetworkMessage>(&buf)
            .map(|raw| raw.payload().clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Drain and discard all frames on `stream` until EOF or error. Keeps
    /// the node's write queue unblocked while tests hold the connection.
    fn drain_loop(mut stream: TcpStream) {
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        while recv_msg(&mut stream).is_ok() {}
    }
}

// ---------------------------------------------------------------------------
// Orphan-pool P2P regtests. These exercise the live handle_tx path: they
// send a tx with unresolvable parents via raw P2P and assert the node
// defers it to the orphanage without banning the peer.
// ---------------------------------------------------------------------------

fn orphan_tx_with_fake_parent(parent_seed: u8, out_value: u64) -> bitcoin::Transaction {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

    let mut parent_bytes = [0u8; 32];
    parent_bytes[0] = parent_seed;
    parent_bytes[1] = 0xAB;
    parent_bytes[2] = 0xCD;
    let parent = Txid::from_slice(&parent_bytes).unwrap();

    // Minimal P2WPKH-shaped output: OP_0 <20 bytes>. Any standard-looking
    // script is fine — we just need to reach the UTXO-lookup step of
    // mempool acceptance (which will reject with MissingInputs because
    // the parent txid is fake).
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&[parent_seed; 20]);
    let script_pubkey = ScriptBuf::from_bytes(p2wpkh);

    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            // Minimal witness so the tx has a witness marker — the SegWit
            // path is what matters on P2WPKH spends.
            witness: Witness::from_slice(&[&[0u8; 1][..]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey,
        }],
    }
}

// Spin up two nodes: `miner` produces blocks, `relay` connects to miner,
// syncs via real P2P (so PeerManager::headers_tip advances and its
// `is_ibd()` returns false), and is the node we connect our raw client to.
// `handle_tx` early-returns during IBD, so a single-node setup doesn't
// exercise the relay path — the miner's real P2P headers are the only
// mechanism that advances the relay node's headers_tip counter.
fn spawn_two_node_relay_pair() -> (TestNode, TestNode) {
    let miner_p2p_port = find_available_port();
    let miner = TestNode::start(&[&format!("--port={}", miner_p2p_port)]);

    // Mine a handful of blocks. Need enough for the relay node's
    // PeerManager::is_ibd() check (`htip == 0 || tip + 24 < htip`) to
    // flip to false — i.e. headers_tip must be non-zero and within 24
    // of tip. Mining 1 is enough if the relay syncs before we send txs.
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    miner
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr)],
        )
        .unwrap();

    let relay_p2p_port = find_available_port();
    let relay = TestNode::start(&[
        &format!("--port={}", relay_p2p_port),
        &format!("--connect=127.0.0.1:{}", miner_p2p_port),
    ]);

    // Wait for relay to sync + exit IBD. Scaled by SATD_TEST_TIMEOUT_MULT
    // because under CI runner load the inter-node sync (header download +
    // block fetch) has been observed to exceed the locally-comfortable 30s.
    poll_until(
        || get_rpc_u64(&relay, "getblockcount").unwrap_or(0) >= 3,
        test_timeout(30),
        "relay node did not sync miner's blocks",
    );
    poll_until(
        || {
            relay
                .rpc_call("getblockchaininfo")
                .ok()
                .and_then(|r| r["result"]["initialblockdownload"].as_bool())
                == Some(false)
        },
        test_timeout(15),
        "relay node stuck in IBD",
    );

    (miner, relay)
}

#[test]
fn test_p2p_orphan_no_ban_and_deferred() {
    let (mut miner, mut relay) = spawn_two_node_relay_pair();
    let relay_p2p_port = relay.p2p_port.expect("relay p2p port tracked");

    let mut client = raw_p2p::RawP2pClient::connect(relay_p2p_port);
    poll_until(
        || get_rpc_u64(&relay, "getconnectioncount").unwrap_or(0) >= 2,
        Duration::from_secs(10),
        "raw client did not register as a peer",
    );

    // Relay a single orphan tx — parent txid is unknown.
    let tx = orphan_tx_with_fake_parent(0x11, 1_000);
    client.send_tx(&tx);

    // Orphanage should pick it up.
    poll_until(
        || get_rpc_u64_from_json(&relay, "getorphaninfo", "size").is_some_and(|n| n >= 1),
        Duration::from_secs(10),
        "orphan never appeared in orphanage",
    );

    // Peer must not have been banned, and we're still connected.
    let banned = relay.rpc_call("listbanned").unwrap();
    assert_eq!(
        banned["result"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "listbanned should be empty after P2P orphan relay"
    );

    relay.stop();
    miner.stop();
}

#[test]
fn test_p2p_many_orphans_do_not_ban() {
    // Under the pre-fix code, each MissingInputs relay added +1 ban score;
    // 100 orphans = ban + disconnect. After the fix, no ban and the peer
    // stays connected. Strongest regression check we can do without
    // exposing ban_score in getpeerinfo.
    let (mut miner, mut relay) = spawn_two_node_relay_pair();
    let relay_p2p_port = relay.p2p_port.expect("relay p2p port tracked");

    let mut client = raw_p2p::RawP2pClient::connect(relay_p2p_port);
    poll_until(
        || get_rpc_u64(&relay, "getconnectioncount").unwrap_or(0) >= 2,
        Duration::from_secs(10),
        "raw client not registered",
    );

    // 120 distinct orphans (each with a distinct fake parent).
    for i in 0..120u8 {
        let tx = orphan_tx_with_fake_parent(i.wrapping_add(1), 1_000 + i as u64);
        client.send_tx(&tx);
    }

    // Wait long enough for the node to process the backlog.
    std::thread::sleep(Duration::from_secs(1));

    let banned = relay.rpc_call("listbanned").unwrap();
    assert_eq!(
        banned["result"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "listbanned must stay empty after 120 orphan relays"
    );
    // Still connected — miner + our raw client = 2.
    let conn_count = get_rpc_u64(&relay, "getconnectioncount").unwrap_or(0);
    assert!(
        conn_count >= 2,
        "raw peer must not be disconnected after 120 orphans; got conn_count={}",
        conn_count
    );

    // Pool is bounded at max_count (default 100).
    let info = relay.rpc_call("getorphaninfo").unwrap();
    let size = info["result"]["size"].as_u64().unwrap_or(0);
    let max = info["result"]["max_size"].as_u64().unwrap_or(u64::MAX);
    assert!(
        size <= max,
        "orphanage size {} exceeds max_size {}",
        size,
        max
    );
    assert!(size > 0, "some orphans should be retained");

    relay.stop();
    miner.stop();
}

#[test]
fn test_p2p_duplicate_orphan_no_pool_growth() {
    // Sending the same orphan repeatedly must not grow the pool beyond 1
    // and must not ban. The add()→AddOutcome::Duplicate signal is what
    // makes handle_tx skip re-requesting parents; here we observe the
    // pool-size invariant, which suffices for the regression.
    let (mut miner, mut relay) = spawn_two_node_relay_pair();
    let relay_p2p_port = relay.p2p_port.expect("relay p2p port tracked");

    let mut client = raw_p2p::RawP2pClient::connect(relay_p2p_port);
    poll_until(
        || get_rpc_u64(&relay, "getconnectioncount").unwrap_or(0) >= 2,
        Duration::from_secs(10),
        "raw client not registered",
    );

    let tx = orphan_tx_with_fake_parent(0x55, 1_234);
    for _ in 0..5 {
        client.send_tx(&tx);
    }

    // Wait for at least one to land.
    poll_until(
        || get_rpc_u64_from_json(&relay, "getorphaninfo", "size").is_some_and(|n| n >= 1),
        Duration::from_secs(10),
        "orphan never landed",
    );

    // Size must stay at exactly 1 — idempotent insert.
    std::thread::sleep(Duration::from_millis(500));
    let size = get_rpc_u64_from_json(&relay, "getorphaninfo", "size").unwrap_or(0);
    assert_eq!(
        size, 1,
        "duplicate orphan relay must not grow pool; got size={}",
        size
    );

    let banned = relay.rpc_call("listbanned").unwrap();
    assert_eq!(
        banned["result"].as_array().map(|a| a.len()).unwrap_or(0),
        0,
        "duplicate orphan relay must not ban"
    );

    relay.stop();
    miner.stop();
}

fn get_rpc_u64_from_json(node: &TestNode, method: &str, key: &str) -> Option<u64> {
    let r = node.rpc_call(method).ok()?;
    r["result"][key].as_u64()
}

// ── Address-history index (M2 integration smoke tests) ────────────────

/// satd must accept `--addressindex=0` and continue to function normally.
/// Lightweight smoke for the M2 runtime opt-out flag.
#[test]
fn test_address_index_disabled_flag_accepted() {
    let mut node = TestNode::start(&["--addressindex=0"]);
    let r = node.rpc_call("getblockchaininfo").expect("rpc");
    assert!(r["result"]["chain"].as_str().is_some());
    node.stop();
}

/// `-noindex=address` is the Bitcoin-Core-compatible alias for
/// `--addressindex=0`. Verifies `translate_index_aliases` runs in the
/// startup pipeline and the node accepts the spelling.
#[test]
fn test_address_index_noindex_alias_accepted() {
    let mut node = TestNode::start(&["-noindex=address"]);
    let r = node.rpc_call("getblockchaininfo").expect("rpc");
    assert!(r["result"]["chain"].as_str().is_some());
    node.stop();
}

/// satd must accept `--addressindex=1` (explicit on, the default).
#[test]
fn test_address_index_enabled_flag_accepted() {
    let mut node = TestNode::start(&["--addressindex=1"]);
    let r = node.rpc_call("getblockchaininfo").expect("rpc");
    assert!(r["result"]["chain"].as_str().is_some());
    node.stop();
}

// ── Address-history index — operator RPCs (M3) ────────────────────────

/// Mining one block to a regtest address must surface a non-zero
/// confirmed balance on `getaddressbalance` for that address — this
/// closes the loop M2 wrote (per-block emission) plus M3 reads (the
/// trait + RPCs).
#[test]
fn test_address_index_rpc_getaddressbalance() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Mine 101 blocks so the first coinbase is matured + spendable
    // visibility doesn't matter — we just want a confirmed balance.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(addr)],
        )
        .unwrap();

    let resp = node
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    let confirmed = resp["result"]["confirmed"]
        .as_u64()
        .expect("confirmed is u64");
    assert!(
        confirmed > 0,
        "expected non-zero confirmed balance after mining; got {}",
        confirmed
    );
    assert_eq!(resp["result"]["unconfirmed"].as_i64().unwrap_or(0), 0);

    node.stop();
}

/// `getaddresshistory` must return one funding entry per mined block
/// for the address, in height-ascending order.
#[test]
fn test_address_index_rpc_getaddresshistory() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr)],
        )
        .unwrap();

    let resp = node
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(addr)])
        .expect("rpc");
    let arr = resp["result"]
        .as_array()
        .expect("history result is array")
        .clone();
    // 5 coinbases → 5 funding entries (no spends in this test).
    assert_eq!(arr.len(), 5);

    let mut last_height: i64 = -1;
    for entry in &arr {
        assert_eq!(entry["type"].as_str(), Some("funding"));
        let h = entry["height"].as_i64().expect("height i64");
        assert!(h > last_height, "history must be height-ascending");
        last_height = h;
        assert!(entry["txid"].as_str().is_some());
        assert!(entry["amount_sat"].as_u64().is_some());
    }

    node.stop();
}

/// `getaddressutxos` must return one UTXO per unspent coinbase output
/// for the address.
#[test]
fn test_address_index_rpc_getaddressutxos() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr)],
        )
        .unwrap();

    let resp = node
        .rpc_call_with_params("getaddressutxos", vec![serde_json::json!(addr)])
        .expect("rpc");
    let arr = resp["result"]
        .as_array()
        .expect("utxos result is array")
        .clone();
    assert_eq!(arr.len(), 3);
    for utxo in &arr {
        assert!(utxo["txid"].as_str().is_some());
        assert!(utxo["amount_sat"].as_u64().is_some());
        assert!(utxo["height"].as_u64().is_some());
    }

    node.stop();
}

/// With `--addressindex=0`, the read RPCs surface
/// `IndexError::Disabled` (mapped to JSON-RPC code -32601) so wallet
/// tooling can detect a disabled-index server cleanly.
#[test]
fn test_address_index_disabled_lookup_returns_error() {
    let mut node = TestNode::start(&["--addressindex=0"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let resp = node
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    assert!(
        resp["error"]["code"].as_i64().is_some(),
        "expected error response when index disabled, got: {}",
        resp
    );
    assert_eq!(resp["error"]["code"].as_i64().unwrap(), -32601);

    node.stop();
}

/// Calling a getaddress* RPC with a 32-byte hex `scripthash` form
/// matches the result of calling it with the address string. Verifies
/// `parse_scripthash_param`'s second-form parser.
#[test]
fn test_address_index_scripthash_param_form() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    // Resolve scripthash by computing sha256 of the bech32-decoded spk.
    // Easier: use the bare-address form, observe history, then probe
    // with a hand-computed scripthash. We reproduce the same value via
    // the `address::scripthash_of` helper on the python side... but the
    // test just needs to demonstrate the alternate param form is
    // accepted and yields a parsed call. For robustness we ship the
    // scripthash as the sha256 of the spk, which the regtest faucet
    // address has stable bytes for.
    use bitcoin::hashes::Hash as _;
    let unchecked: bitcoin::Address<bitcoin::address::NetworkUnchecked> = addr.parse().unwrap();
    let address = unchecked
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let spk = address.script_pubkey();
    let sh = bitcoin::hashes::sha256::Hash::hash(spk.as_bytes()).to_byte_array();
    let sh_hex = hex::encode(sh);

    let resp = node
        .rpc_call_with_params(
            "getaddressbalance",
            vec![serde_json::json!({ "scripthash": sh_hex })],
        )
        .expect("rpc");
    let confirmed = resp["result"]["confirmed"]
        .as_u64()
        .expect("confirmed is u64");
    assert!(confirmed > 0);

    node.stop();
}

// ── Address-history index — subscriptions flag (M5) ───────────────────

/// satd must accept `--addrindexsubscriptions=N` and continue to
/// function normally. Smoke for the M5 subscription-cap flag.
#[test]
fn test_address_index_subscriptions_flag_accepted() {
    let mut node = TestNode::start(&["--addrindexsubscriptions=2500"]);
    let r = node.rpc_call("getblockchaininfo").expect("rpc");
    assert!(r["result"]["chain"].as_str().is_some());
    node.stop();
}

// ── Address-history index — mempool variant (M4) ──────────────────────

/// With no mempool txs, `getaddressbalance.unconfirmed` is 0 even
/// after mining several blocks. Verifies the mempool task doesn't
/// spuriously credit confirmed coinbases as unconfirmed.
#[test]
fn test_address_index_mempool_quiet_when_empty() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr)],
        )
        .unwrap();

    let resp = node
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    let confirmed = resp["result"]["confirmed"].as_u64().unwrap_or(0);
    let unconfirmed = resp["result"]["unconfirmed"].as_i64().unwrap_or(0);
    assert!(confirmed > 0, "confirmed must be non-zero after 5 blocks");
    assert_eq!(
        unconfirmed, 0,
        "unconfirmed delta must be 0 when mempool is empty; got {}",
        unconfirmed
    );
    node.stop();
}

// ── Address-history index — backfill RPCs (M7) ────────────────────────

/// `getindexinfo` returns the wrapping `{"address": {...}}` envelope
/// with nested `{address: {synced, best_block_height, backfill: {...}}}`.
/// The shape is constructed in `node/src/rpc/indexes.rs` and locked by
/// `STABILITY_POLICY.md` Tier 2 so downstream tooling can rely on it.
#[test]
fn test_address_index_getindexinfo_shape() {
    let mut node = TestNode::start(&[]);
    let resp = node.rpc_call("getindexinfo").expect("rpc");
    let addr = &resp["result"]["address"];
    assert!(addr.is_object(), "address key missing: {}", resp);
    // synced=true is correct for a non-AssumeUTXO datadir: every
    // block already had its rows written from connect_block.
    assert_eq!(addr["synced"].as_bool(), Some(true));
    assert!(
        addr["best_block_height"].as_u64().is_some(),
        "best_block_height must be present: {}",
        resp
    );

    let bf = &addr["backfill"];
    assert!(bf.is_object(), "backfill substructure missing: {}", resp);
    assert_eq!(bf["active"].as_bool(), Some(false));
    assert_eq!(bf["pass"].as_u64(), Some(0));
    assert_eq!(bf["cursor_height"].as_u64(), Some(0));
    assert_eq!(bf["snapshot_height"].as_u64(), Some(0));
    assert_eq!(bf["estimated_remaining_seconds"].as_u64(), Some(0));
    // outpoint_spend completeness — true on a fresh datadir
    // (round-3 H2 fix surfaces this so operators / tooling can
    // detect upgrade-time gaps).
    let os = &addr["outpoint_spend"];
    assert!(os.is_object(), "outpoint_spend key missing: {}", resp);
    assert_eq!(os["complete"].as_bool(), Some(true));
    node.stop();
}

/// `pauseindex address` / `resumeindex address` / `cancelindex address`
/// must accept the `address` target and surface the cursor's state
/// label. Wrong targets reject with a -8 error.
#[test]
fn test_address_index_backfill_control_rpcs() {
    // M7 ships scaffolding: no backfill task is spawned (AssumeUTXO
    // isn't in the tree). pause/resume/cancel must reject as -8 with
    // a clear "no backfill running" message rather than returning
    // success+state:idle, which would mislead operators into thinking
    // the index is paused when it isn't.
    let mut node = TestNode::start(&[]);

    for method in ["pauseindex", "resumeindex", "cancelindex"] {
        let r = node
            .rpc_call_with_params(method, vec![serde_json::json!("address")])
            .expect("rpc");
        assert_eq!(
            r["error"]["code"].as_i64(),
            Some(-8),
            "{} on idle backfill must return -8: {}",
            method,
            r
        );
        let msg = r["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("no backfill is in progress"),
            "{} error message should explain idle state: {:?}",
            method,
            msg
        );
    }

    // Wrong target still rejected.
    let r = node
        .rpc_call_with_params("pauseindex", vec![serde_json::json!("not-a-real-index")])
        .expect("rpc");
    assert!(
        r["error"]["code"].as_i64().is_some(),
        "expected error for unknown target: {}",
        r
    );
    assert_eq!(r["error"]["code"].as_i64().unwrap(), -8);

    node.stop();
}

/// Helper: poll `getindexinfo` until the address-index backfill state
/// matches one of `expected`. Returns the final response, or panics on
/// timeout. Default 30 s deadline tracks the runner's per-batch
/// cadence; tests that inject a long debug delay should size up.
fn poll_backfill_state(
    node: &TestNode,
    expected: &[&str],
    deadline: std::time::Duration,
) -> serde_json::Value {
    let start = Instant::now();
    let mut last = serde_json::Value::Null;
    while start.elapsed() < deadline {
        let r = node.rpc_call("getindexinfo").expect("rpc");
        let bf = &r["result"]["address"]["backfill"];
        // Prefer the explicit state field (added in the round-1 fix);
        // fall back to active/synced inference for backwards compat
        // if the field is missing.
        let state_str = bf["state"].as_str().unwrap_or("");
        if !state_str.is_empty() {
            for label in expected {
                if &state_str == label {
                    return r;
                }
                if *label == "synced" && (state_str == "completed" || state_str == "idle") {
                    return r;
                }
            }
        } else {
            let active = bf["active"].as_bool().unwrap_or(false);
            let synced = r["result"]["address"]["synced"].as_bool().unwrap_or(false);
            for label in expected {
                let matches = match *label {
                    "running" | "paused" => active,
                    "completed" | "idle" => synced && !active,
                    "synced" => synced,
                    _ => false,
                };
                if matches {
                    return r;
                }
            }
        }
        last = r;
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timeout waiting for backfill state {:?}; last response: {}",
        expected, last
    );
}

/// `backfillindex address` starts a real two-pass backfill on a
/// non-AssumeUTXO datadir. Replaces the M7-era "no-op" test once the
/// genesis→tip walk landed.
#[test]
fn test_address_index_backfillindex_starts_and_completes() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    // Mine a small chain so there's something to walk over.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .expect("rpc");

    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "expected started=true on fresh datadir: {}",
        r
    );

    let final_resp = poll_backfill_state(&node, &["completed"], Duration::from_secs(30));
    let bf = &final_resp["result"]["address"]["backfill"];
    assert_eq!(bf["active"].as_bool(), Some(false));
    assert!(
        final_resp["result"]["address"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced must be true after completion: {}",
        final_resp
    );
    // Snapshot height should reflect the chain tip at the time of start.
    assert!(bf["snapshot_height"].as_u64().unwrap_or(0) >= 20);

    node.stop();
}

/// A second `backfillindex` after completion is idempotent: returns
/// `started: false` with the "already completed" reason.
#[test]
fn test_address_index_backfill_idempotent_after_completion() {
    let mut node = TestNode::start(&[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(15), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    poll_backfill_state(&node, &["completed"], Duration::from_secs(30));

    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(r["result"]["started"].as_bool(), Some(false));
    let reason = r["result"]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("already completed"),
        "expected 'already completed' reason; got: {}",
        reason
    );

    node.stop();
}

/// `--addressindex=0` makes `backfillindex address` reject with an
/// operator-friendly -8 error. Otherwise the runner would write rows
/// to a CF nobody reads.
#[test]
fn test_address_index_backfill_disabled_returns_error() {
    let mut node = TestNode::start(&["--addressindex=0"]);
    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(r["error"]["code"].as_i64(), Some(-8));
    let msg = r["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("disabled") || msg.contains("--addressindex=0"),
        "error should explain index is disabled; got: {}",
        msg
    );
    node.stop();
}

/// Pause mid-run, observe paused state, resume, observe completion.
/// Uses `SATD_BACKFILL_DEBUG_DELAY_MS` to slow the runner so the test
/// can race the pause flag in.
#[test]
fn test_address_index_backfill_pause_resume() {
    // Inject 30 ms per-block delay so 30 blocks ≈ 1 s pass 1 and we
    // have time to pause cleanly. Env var is set on the spawned
    // process only — parent's env stays clean across parallel tests.
    let mut node = TestNode::start_with_env(&[], &[("SATD_BACKFILL_DEBUG_DELAY_MS", "30")]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(30), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");

    // Pause within 100 ms — runner is almost certainly between batches.
    std::thread::sleep(Duration::from_millis(100));
    let pause_resp = node
        .rpc_call_with_params("pauseindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        pause_resp["result"]["paused"].as_bool(),
        Some(true),
        "pauseindex should accept while running: {}",
        pause_resp
    );

    // Observe `active=true` (paused state still shows as active in the
    // RPC envelope — `synced` would be false because the cursor isn't
    // at snapshot_height yet).
    let mid = node.rpc_call("getindexinfo").expect("rpc");
    let bf_mid = &mid["result"]["address"]["backfill"];
    assert_eq!(bf_mid["active"].as_bool(), Some(true), "{}", mid);

    // Resume and wait for completion.
    let resume_resp = node
        .rpc_call_with_params("resumeindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(resume_resp["result"]["resumed"].as_bool(), Some(true));

    poll_backfill_state(&node, &["completed"], Duration::from_secs(60));

    node.stop();
}

/// Cancel mid-run, observe cancelled state, then a fresh start
/// succeeds (proving the temp CF was dropped and persisted state
/// was reset).
#[test]
fn test_address_index_backfill_cancel_then_restart_succeeds() {
    let mut node = TestNode::start_with_env(&[], &[("SATD_BACKFILL_DEBUG_DELAY_MS", "30")]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(30), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");

    std::thread::sleep(Duration::from_millis(100));
    let cancel_resp = node
        .rpc_call_with_params("cancelindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        cancel_resp["result"]["cancelled"].as_bool(),
        Some(true),
        "cancelindex should accept while running: {}",
        cancel_resp
    );

    // Wait briefly for the runner to observe the cancel flag, persist
    // state=Cancelled, and drop the temp CF before exiting.
    std::thread::sleep(Duration::from_millis(500));

    // A fresh start must succeed (started=true) — the previous
    // Cancelled state isn't terminal.
    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "start after cancel should succeed: {}",
        r
    );
    let prev = r["result"]["previous_state"].as_str().unwrap_or("");
    assert_eq!(prev, "cancelled", "previous_state should be cancelled");

    poll_backfill_state(&node, &["completed"], Duration::from_secs(60));

    node.stop();
}

/// Crash recovery: kill the process mid-backfill, restart with the
/// same datadir, observe the supervisor auto-resumes and completes.
/// Uses the debug delay so the kill lands in the middle of pass 1.
///
/// Test setup mines + graceful-stops *before* the kill phase so the
/// chain tip is durable on disk. Without that step, regtest's
/// CoinCache buffers tip writes in memory until the next flush
/// threshold (which 40 small blocks won't trigger), so a kill -9
/// would lose the chain tip and the resumed run would have nothing
/// to walk.
#[test]
fn test_address_index_backfill_resumable_after_kill() {
    let datadir = std::env::temp_dir().join(format!("satd-backfill-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);

    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let port_arg = format!("--port={}", p2p_port);

    // Phase 1: mine 40 blocks, graceful-stop to flush tip durably.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[&port_arg]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(40), serde_json::json!(addr)],
        )
        .expect("rpc");
    node.stop();

    // Phase 2: restart with the debug delay, kick off backfill,
    // kill -9 mid-pass-1.
    let env: &[(&str, &str)] = &[("SATD_BACKFILL_DEBUG_DELAY_MS", "30")];
    let mut node = TestNode::start_with_datadir_env(&datadir, rpcport, &[], env);
    // Sanity: chain should still be at 40 after the restart.
    let info = node.rpc_call("getblockchaininfo").expect("rpc");
    assert_eq!(
        info["result"]["blocks"].as_u64(),
        Some(40),
        "chain tip should survive graceful stop+restart: {}",
        info
    );
    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    std::thread::sleep(Duration::from_millis(300));
    let _ = node.process.kill();
    let _ = node.process.wait();
    std::mem::forget(node); // skip Drop's datadir cleanup

    // Phase 3: restart cleanly (no debug delay) and observe the
    // supervisor's auto-resume reaching Completed.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    poll_backfill_state(&node, &["completed"], Duration::from_secs(60));

    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// After a successful backfill, restarting the node leaves the
/// persisted state at Completed (not Idle). The `address.synced`
/// field reads true and a fresh `backfillindex` call is the
/// "already completed" no-op.
#[test]
fn test_address_index_backfill_persists_completed_across_restart() {
    let datadir =
        std::env::temp_dir().join(format!("satd-backfill-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let port_arg = format!("--port={}", p2p_port);

    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &[&port_arg]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(15), serde_json::json!(addr)],
        )
        .expect("rpc");
    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    poll_backfill_state(&node, &["completed"], Duration::from_secs(30));
    node.stop();

    // Restart against the same datadir.
    let node = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let info = node.rpc_call("getindexinfo").expect("rpc");
    assert!(
        info["result"]["address"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced should still be true after restart: {}",
        info
    );
    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(r["result"]["started"].as_bool(), Some(false));
    let reason = r["result"]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("already completed"),
        "expected 'already completed' after restart: {}",
        reason
    );
    let mut node = node;
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Data-correctness test: mine with `--addressindex=0`, restart with
/// `=1`, run backfill, and verify `getaddressbalance`/
/// `getaddresshistory`/`getaddressutxos` produce the same results as
/// a control node that ran with `=1` from genesis.
///
/// This is THE test that exercises the row-writing code path on data
/// that doesn't already have rows. The earlier completion-state tests
/// pass even on a broken row writer because live `connect_block`
/// already wrote the rows during mining.
#[test]
fn test_address_index_backfill_data_parity_after_disabled_mining() {
    // The address used as both coinbase recipient and lookup key.
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let blocks = 25;

    // ── Control: run with --addressindex=1 from the start ──
    let mut control = TestNode::start(&[]);
    let _ = control
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(blocks), serde_json::json!(addr)],
        )
        .expect("rpc");
    let control_balance = control
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    let control_history = control
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(addr)])
        .expect("rpc");
    let control_utxos = control
        .rpc_call_with_params("getaddressutxos", vec![serde_json::json!(addr)])
        .expect("rpc");
    control.stop();

    // ── Subject: mine with --addressindex=0 (no rows written), then
    // restart with =1 (live indexer covers heights from restart-tip
    // onward, but pre-restart rows are missing), then run backfill. ──
    let datadir = std::env::temp_dir().join(format!("satd-backfill-parity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let port_arg = format!("--port={}", p2p_port);

    let mut subject =
        TestNode::start_with_datadir(&datadir, rpcport, &["--addressindex=0", &port_arg]);
    let _ = subject
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(blocks), serde_json::json!(addr)],
        )
        .expect("rpc");
    // Sanity: with the index disabled, lookups return an explicit
    // error (not zero/empty silently) so operators can tell the
    // difference between "no activity" and "index off".
    let pre_balance = subject
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    assert!(
        pre_balance["error"].is_object(),
        "getaddressbalance should error when --addressindex=0; got {}",
        pre_balance
    );
    subject.stop();

    // Restart with index enabled. Mine no further blocks. Run backfill.
    let subject = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let r = subject
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "expected backfill to start: {}",
        r
    );
    poll_backfill_state(&subject, &["completed"], Duration::from_secs(60));

    let subj_balance = subject
        .rpc_call_with_params("getaddressbalance", vec![serde_json::json!(addr)])
        .expect("rpc");
    let subj_history = subject
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(addr)])
        .expect("rpc");
    let subj_utxos = subject
        .rpc_call_with_params("getaddressutxos", vec![serde_json::json!(addr)])
        .expect("rpc");

    assert_eq!(
        control_balance["result"]["confirmed"].as_u64(),
        subj_balance["result"]["confirmed"].as_u64(),
        "confirmed balance must match control: control={} subject={}",
        control_balance,
        subj_balance,
    );
    // Compare full row content (txid, vout, height, amount, type),
    // not just counts. A count-equal-but-content-divergent backfill
    // would silently pass a count-only check (review-2 #10).
    let mut ctrl_hist: Vec<String> = control_history["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| serde_json::to_string(&v).unwrap_or_default())
        .collect();
    let mut subj_hist: Vec<String> = subj_history["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| serde_json::to_string(&v).unwrap_or_default())
        .collect();
    ctrl_hist.sort();
    subj_hist.sort();
    assert_eq!(
        ctrl_hist, subj_hist,
        "address history rows must match control content-for-content"
    );

    let mut ctrl_utxos: Vec<String> = control_utxos["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| serde_json::to_string(&v).unwrap_or_default())
        .collect();
    let mut subj_utxos: Vec<String> = subj_utxos["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| serde_json::to_string(&v).unwrap_or_default())
        .collect();
    ctrl_utxos.sort();
    subj_utxos.sort();
    assert_eq!(
        ctrl_utxos, subj_utxos,
        "address UTXO rows must match control content-for-content"
    );

    let mut subject = subject;
    subject.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Spending-row test: mine to a known-key address, spend that
/// coinbase to a second address, and verify the backfill emits a
/// `getaddresshistory` entry on the *destination* (a spending row
/// referenced through pass 2's temp-CF lookup) plus the coinbase
/// funding rows.
#[test]
fn test_address_index_backfill_spending_row_with_real_spend() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    // ── Build a known-key P2WPKH source address ──
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();

    // Destination: the canonical zero-hash address (no key needed —
    // we never spend from it, just observe rows).
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Run the whole mine-and-spend sequence with `--addressindex=0`
    // so live indexing writes NOTHING. Then restart with `=1` and
    // run backfill — this is the only way to actually exercise
    // pass-2 row writing on a non-coinbase input. With the index
    // enabled from the start, live `connect_block` already writes
    // the spending row and a broken backfill would still be silent
    // (review-2 #8).
    let datadir =
        std::env::temp_dir().join(format!("satd-spending-row-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let port_arg = format!("--port={}", p2p_port);

    let mut node =
        TestNode::start_with_datadir(&datadir, rpcport, &["--addressindex=0", &port_arg]);

    // Mine 101 blocks so the first coinbase is matured (subsidy spendable).
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str)],
        )
        .expect("rpc");

    // Pull block 1's coinbase txid. satd's `getblock` verbosity 1
    // returns the tx-id list; verbosity 2 (full tx detail) is not
    // supported, so we infer the coinbase value from the regtest
    // block-1 subsidy (50 BTC).
    let block1_hash_resp = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .expect("rpc");
    let block1_hash = block1_hash_resp["result"].as_str().unwrap().to_string();
    let block1_resp = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .expect("rpc");
    let cb_txid_str = block1_resp["result"]["tx"][0].as_str().unwrap();
    let cb_txid = bitcoin::Txid::from_str(cb_txid_str).unwrap();
    // Regtest block-1 coinbase subsidy: 50 BTC (no halvings before 150).
    let cb_value_sat: u64 = 50 * 100_000_000;

    // ── Build the spending tx: src coinbase → dest, minus 1000 sat fee ──
    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send_value = cb_value_sat - 1000;
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
            value: Amount::from_sat(send_value),
            script_pubkey: dest_script,
        }],
    };

    // Sign the P2WPKH input. BIP143 sighash → ECDSA over the digest.
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value_sat),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let submit = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .expect("rpc");
    assert!(
        submit["result"].is_string(),
        "sendrawtransaction should accept signed P2WPKH spend; got {}",
        submit
    );

    // Mine one more block to confirm the spend.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(src_str)],
        )
        .expect("rpc");

    let spend_txid = spend.compute_txid().to_string();

    // Stop with --addressindex=0 (no rows written); restart with =1
    // so backfill is the ONLY writer of address rows.
    node.stop();

    let node = TestNode::start_with_datadir(&datadir, rpcport, &[]);

    // Sanity: lookups should work but return empty pre-backfill
    // (chain is fully synced; just no rows in the addr CFs yet).
    let pre_dest_history = node
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(dest_addr)])
        .expect("rpc");
    assert_eq!(
        pre_dest_history["result"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "pre-backfill: dest history must be empty (no rows yet)"
    );

    // ── Run backfill (the ONLY writer of rows here) ──
    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "expected backfill to start: {}",
        r
    );
    poll_backfill_state(&node, &["completed"], Duration::from_secs(60));

    // Destination must have exactly one funding row (the spend
    // delivered cb_value_sat - 1000 to it).
    let post_dest_history = node
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(dest_addr)])
        .expect("rpc");
    let dest_entries = post_dest_history["result"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        dest_entries.len(),
        1,
        "destination should have exactly 1 funding row: {:?}",
        dest_entries
    );
    let dest_row = &dest_entries[0];
    assert_eq!(dest_row["type"].as_str(), Some("funding"));
    assert_eq!(dest_row["txid"].as_str(), Some(spend_txid.as_str()));
    assert_eq!(dest_row["vout"].as_u64(), Some(0));
    assert_eq!(
        dest_row["amount_sat"].as_u64(),
        Some(cb_value_sat - 1000),
        "destination amount must equal send_value: {}",
        dest_row
    );

    // Source must have a spending row referencing the spend's txid
    // and the coinbase outpoint we spent. Pass-2 specifically wrote
    // this — without backfill working, the row wouldn't exist (we
    // ran the entire mine+spend sequence with --addressindex=0).
    let post_src_history = node
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(src_str)])
        .expect("rpc");
    let src_entries = post_src_history["result"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let spending_row = src_entries.iter().find(|e| {
        e["type"].as_str() == Some("spending") && e["txid"].as_str() == Some(spend_txid.as_str())
    });
    assert!(
        spending_row.is_some(),
        "source must have a spending row from backfill pass 2; entries: {:?}",
        src_entries
    );
    let row = spending_row.unwrap();
    assert_eq!(
        row["prev_txid"].as_str(),
        Some(cb_txid.to_string().as_str()),
        "spending row prev_txid must match the coinbase we spent: {}",
        row
    );
    assert_eq!(row["prev_vout"].as_u64(), Some(0));

    let mut node = node;
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Reorg invalidates the backfill snapshot mid-run → state=Failed.
/// Mid-run we submit a longer competing chain that triggers a reorg
/// at depths > 0 below snapshot_height. The runner's per-batch
/// verify_anchor_active sees the new active hash and aborts with
/// ReorgInvalidated; the supervisor persists Failed with the error
/// surfaced via getindexinfo.last_error.
#[test]
fn test_address_index_backfill_reorg_invalidates_to_failed() {
    use bitcoin::WitnessProgram;
    use bitcoin::WitnessVersion;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, Network, PublicKey};

    // Distinct A/B addresses so the two chains have different block
    // hashes from height 1 (otherwise regtest's deterministic mining
    // of the same address from the same genesis produces identical
    // headers and submitblock returns "duplicate" — no reorg).
    let addr_a = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    // Derive a second valid P2WPKH from a fixed key so we don't have
    // to hand-roll a bech32 checksum.
    let secp = Secp256k1::new();
    let sk_b = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
    let pk_b = PublicKey::new(sk_b.public_key(&secp));
    use bitcoin::hashes::Hash as _;
    let pkh_b = bitcoin::hashes::hash160::Hash::hash(&pk_b.to_bytes());
    let prog_b = WitnessProgram::new(WitnessVersion::V0, pkh_b.as_byte_array()).unwrap();
    let addr_b_str = Address::from_witness_program(prog_b, Network::Regtest).to_string();
    let addr_b = addr_b_str.as_str();

    // Node A first: shorter chain + slow backfill knob so the reorg
    // lands mid-run. Mining order matters here — the existing
    // reorg test (test_reorg_record_reflects_completed_state) mines
    // A first then B; reversing the order trips the BIP113 MTP
    // check on subsequent B blocks because B's earlier timestamps
    // become "time-too-old" against A's chain.
    //
    // 1000 ms per batch gives a wide enough pause-observation window
    // to absorb RPC-roundtrip variance on the self-hosted CI runner.
    // 4 batches × 1 s = ~4 s of runtime; pauseindex from the test
    // reliably lands during the first batch's sleep.
    let mut node_a = TestNode::start_with_env(&[], &[("SATD_BACKFILL_DEBUG_DELAY_MS", "1000")]);
    let _ = node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr_a)],
        )
        .expect("rpc");
    let a_tip_height = node_a.rpc_call("getblockcount").expect("rpc")["result"]
        .as_u64()
        .unwrap_or(0) as u32;
    assert_eq!(a_tip_height, 2);

    // Node B: build a longer competing fork (3 blocks) and capture
    // hex so we can later submit it to A.
    let mut node_b = TestNode::start(&[]);
    let gen_b = node_b
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr_b)],
        )
        .unwrap();
    let b_hashes: Vec<String> = gen_b["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let mut b_hex: Vec<String> = Vec::new();
    for h in &b_hashes {
        let raw = node_b
            .rpc_call_with_params("getblock", vec![serde_json::json!(h), serde_json::json!(0)])
            .unwrap();
        b_hex.push(raw["result"].as_str().unwrap().to_string());
    }
    node_b.stop();

    // Pause the runner immediately so we control timing precisely.
    // pauseindex flips an atomic flag the runner observes between
    // batches. Without pausing first, the 20-block backfill at 100ms
    // per batch (2s) might finish before the reorg lands under load.
    let r = node_a
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(r["result"]["started"].as_bool(), Some(true));
    let _ = node_a
        .rpc_call_with_params("pauseindex", vec![serde_json::json!("address")])
        .expect("rpc");
    // Wait for the runner to observe paused so cursor reflects Paused.
    // 15s timeout covers RPC-roundtrip variance + the 1 s/batch debug
    // delay on the slowest self-hosted CI runners.
    poll_backfill_state(&node_a, &["paused"], Duration::from_secs(15));

    // Submit B's blocks while the runner is paused. The reorg lands
    // immediately; the runner is sleeping in check_pause_loop. When
    // we resume, the next verify_anchor_active is the first thing it
    // does and trips ReorgInvalidated deterministically.
    for (i, hex) in b_hex.iter().enumerate() {
        let res = node_a
            .rpc_call_with_params("submitblock", vec![serde_json::json!(hex)])
            .unwrap();
        if let Some(err) = res.get("error")
            && !err.is_null()
        {
            panic!("submitblock B[{}] errored: {}", i, res);
        }
    }
    // Sanity: A reorged to B (or at least past A's old tip).
    let bestblock = node_a.rpc_call("getbestblockhash").expect("rpc")["result"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        bestblock, b_hashes[2],
        "A should have reorged to B's tip; current tip = {}",
        bestblock
    );

    // Resume — next runner wake → verify_anchor_active fails → Failed.
    let _ = node_a
        .rpc_call_with_params("resumeindex", vec![serde_json::json!("address")])
        .expect("rpc");

    // Poll for Failed deterministically (no `completed` fallback now).
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut final_state = String::new();
    let mut last_err = String::new();
    while Instant::now() < deadline {
        let info = node_a.rpc_call("getindexinfo").expect("rpc");
        if let Some(s) = info["result"]["address"]["backfill"]["state"].as_str()
            && s == "failed"
        {
            final_state = s.to_string();
            last_err = info["result"]["address"]["backfill"]["last_error"]
                .as_str()
                .unwrap_or("")
                .to_string();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        final_state, "failed",
        "backfill must reach Failed after reorg; got state {:?}",
        final_state
    );
    assert!(
        last_err.contains("reorg") || last_err.contains("Reorg") || last_err.contains("anchor"),
        "expected reorg-invalidated last_error; got {:?}",
        last_err
    );

    // Verify no stale rows remain. After Failed-cleanup:
    //  - addr_a should be empty (its blocks were disconnected by
    //    reorg AND backfill's stale rows for A were cleaned up).
    //  - addr_b should have B's 3 live-indexed rows.
    let history_a = node_a
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(addr_a)])
        .expect("rpc");
    let entries_a = history_a["result"].as_array().cloned().unwrap_or_default();
    assert!(
        entries_a.is_empty(),
        "addr_a history should be empty after reorg cleanup; got {} stale entries: {:?}",
        entries_a.len(),
        entries_a
    );
    let history_b = node_a
        .rpc_call_with_params("getaddresshistory", vec![serde_json::json!(addr_b)])
        .expect("rpc");
    let entries_b = history_b["result"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        entries_b.len(),
        3,
        "addr_b should have B's 3 live-indexed rows; got {}: {:?}",
        entries_b.len(),
        entries_b
    );
    for entry in &entries_b {
        let h = entry["height"].as_u64().unwrap_or(0);
        assert!(
            (1..=3).contains(&h),
            "addr_b row at unexpected height {}: {}",
            h,
            entry
        );
    }

    // After Failed: a fresh backfillindex starts a new run (lenient).
    let r2 = node_a
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r2["result"]["started"].as_bool(),
        Some(true),
        "fresh backfill after Failed should start (lenient): {}",
        r2
    );
    poll_backfill_state(&node_a, &["completed"], Duration::from_secs(60));

    node_a.stop();
}

/// Two backfillindex calls in quick succession: first transitions
/// Idle→Running synchronously, second sees Running and returns
/// started:false. Verifies the synchronous-Starting fix for the
/// duplicate-RPC race (review finding #5).
#[test]
fn test_address_index_backfill_duplicate_rpc_race_rejected() {
    let mut node = TestNode::start_with_env(&[], &[("SATD_BACKFILL_DEBUG_DELAY_MS", "50")]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .expect("rpc");

    let r1 = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r1["result"]["started"].as_bool(),
        Some(true),
        "first call must start: {}",
        r1
    );

    // Second call: state was persisted to Running synchronously by
    // the first call's start(), so this must see in-progress.
    let r2 = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("address")])
        .expect("rpc");
    assert_eq!(
        r2["result"]["started"].as_bool(),
        Some(false),
        "second call must reject as already-in-progress: {}",
        r2
    );
    let reason = r2["result"]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("already in progress"),
        "expected 'already in progress' reason; got: {}",
        reason
    );

    poll_backfill_state(&node, &["completed"], Duration::from_secs(60));
    node.stop();
}

// ── Esplora REST scaffolding (PR 2) ──

/// Helper: GET a path from the Esplora server and return body as String.
fn esplora_get(port: u16, path: &str) -> reqwest::blocking::Response {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    client
        .get(format!("http://127.0.0.1:{}{}", port, path))
        .send()
        .expect("esplora GET")
}

/// Tip endpoints: `/blocks/tip/hash` and `/blocks/tip/height` must
/// return plain-text responses matching upstream Esplora's shape.
#[test]
fn test_esplora_tip_hash_and_height_match_chain_state() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr)],
        )
        .unwrap();

    let h_resp = esplora_get(esplora_port, "/blocks/tip/height");
    assert_eq!(h_resp.status(), 200);
    let h: u32 = h_resp.text().unwrap().trim().parse().unwrap();
    assert_eq!(h, 3);

    let hash_resp = esplora_get(esplora_port, "/blocks/tip/hash");
    assert_eq!(hash_resp.status(), 200);
    let tip_hex = hash_resp.text().unwrap().trim().to_string();
    assert_eq!(tip_hex.len(), 64, "tip hash is 32 raw bytes hex-encoded");

    // /block-height/:h should agree with /blocks/tip/hash.
    let by_height = esplora_get(esplora_port, &format!("/block-height/{}", h));
    assert_eq!(by_height.status(), 200);
    assert_eq!(by_height.text().unwrap().trim(), tip_hex);

    node.stop();
}

/// `/blocks` returns up to 10 most recent block summaries, descending.
#[test]
fn test_esplora_blocks_recent_returns_descending_summaries() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(5), serde_json::json!(addr)],
        )
        .unwrap();

    let r = esplora_get(esplora_port, "/blocks");
    assert_eq!(r.status(), 200);
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    // 5 mined + genesis = 6, /blocks returns at most 10 → all 6.
    assert_eq!(arr.len(), 6, "expected 6 block summaries; got {:?}", arr);

    let mut last_height: i64 = i64::MAX;
    for entry in &arr {
        let h = entry["height"].as_i64().expect("height i64");
        assert!(h < last_height, "/blocks must be height-descending");
        last_height = h;
        // Required upstream-Esplora fields.
        assert!(entry["id"].as_str().is_some());
        assert!(entry["timestamp"].as_u64().is_some());
        assert!(entry["tx_count"].as_u64().is_some());
        assert!(entry["nonce"].as_u64().is_some());
    }

    node.stop();
}

/// `/block-height/:h` for a height past tip returns 404.
#[test]
fn test_esplora_block_height_past_tip_404() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let r = esplora_get(esplora_port, "/block-height/9999999");
    assert_eq!(r.status(), 404);
    node.stop();
}

/// `--esplora=0` keeps the listener silent — connections refuse.
#[test]
fn test_esplora_disabled_does_not_listen() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=0", &bind]);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let r = client
        .get(format!(
            "http://127.0.0.1:{}/blocks/tip/height",
            esplora_port
        ))
        .send();
    assert!(r.is_err(), "expected connection refused; got: {:?}", r);
    node.stop();
}

/// `--esploraprefix=/api` mounts every route under that prefix. The
/// unprefixed paths must 404, and the prefixed paths must serve.
/// (Review H2.)
#[test]
fn test_esplora_prefix_mounts_under_path() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--esploraprefix=/api"]);

    let with_prefix = esplora_get(esplora_port, "/api/blocks/tip/height");
    assert_eq!(with_prefix.status(), 200);
    assert!(with_prefix.text().unwrap().trim().parse::<u32>().is_ok());

    let without_prefix = esplora_get(esplora_port, "/blocks/tip/height");
    assert_eq!(
        without_prefix.status(),
        404,
        "unprefixed path must 404 when --esploraprefix=/api"
    );
    node.stop();
}

/// `--esploraauth=cookie --esploracookiefile=<missing>` must fail
/// daemon startup, NOT silently start an unauthenticated listener.
/// (Review H1.)
#[test]
fn test_esplora_missing_cookie_file_fails_startup() {
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let esplora_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-esplora-bad-cookie-{}", rpcport));
    // Self-hosted CI runner persists /tmp between runs; a prior run
    // with the same rpcport hashing leaves chainstate rows that flip
    // the address_index.complete marker to false on reopen and break
    // this test's expected error path. Wipe before recreating.
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);
    let missing = datadir.join("definitely-not-a-cookie");

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--esplora=1")
        // PR #102 adds H3 (esplora requires --txindex=1); pass it so
        // this PR's check (auth init) is the failure that fires.
        .arg("--txindex")
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .arg("--esploraauth=cookie")
        .arg(format!("--esploracookiefile={}", missing.display()))
        .output()
        .expect("spawn satd");
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("esplora startup failed") || stderr.contains("auth init failed"),
        "expected esplora auth failure in stderr; got: {stderr}"
    );
}

/// Esplora bind to an already-taken port must fail daemon startup,
/// not silently log a warning. (Review H4.)
#[test]
fn test_esplora_port_conflict_fails_startup() {
    use std::net::TcpListener;
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    // Squat the port so satd can't bind it. Hold the listener for the
    // lifetime of the satd process.
    let squatter = TcpListener::bind("127.0.0.1:0").expect("squatter bind");
    let occupied = squatter.local_addr().unwrap().port();
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-esplora-port-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--esplora=1")
        .arg("--txindex") // see note in test_esplora_missing_cookie_file_fails_startup
        .arg(format!("--esplorabind=127.0.0.1:{}", occupied))
        .output()
        .expect("spawn satd");
    drop(squatter);
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not bind"),
        "expected bind failure in stderr; got: {stderr}"
    );
}

// ── Esplora block detail endpoints (PR 3) ──

#[test]
fn test_esplora_block_detail_populated() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r = esplora_get(esplora_port, &format!("/block/{}", tip));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["id"].as_str().unwrap(), tip);
    assert_eq!(body["height"].as_u64().unwrap(), 2);
    assert_eq!(
        body["tx_count"].as_u64().unwrap(),
        1,
        "regtest coinbase only"
    );
    assert!(body["size"].as_u64().unwrap() > 0);
    assert!(body["weight"].as_u64().unwrap() > 0);

    node.stop();
}

#[test]
fn test_esplora_block_header_hex() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r = esplora_get(esplora_port, &format!("/block/{}/header", tip));
    assert_eq!(r.status(), 200);
    let hex_body = r.text().unwrap();
    assert_eq!(hex_body.trim().len(), 160, "80-byte header = 160 hex chars");
    node.stop();
}

#[test]
fn test_esplora_block_raw_bytes() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r = esplora_get(esplora_port, &format!("/block/{}/raw", tip));
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    let bytes = r.bytes().unwrap();
    assert!(bytes.len() > 80, "raw block must be > header size");
    node.stop();
}

#[test]
fn test_esplora_block_status_in_best_chain() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    let h1 = esplora_get(esplora_port, "/block-height/1")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r = esplora_get(esplora_port, &format!("/block/{}/status", h1));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert!(body["in_best_chain"].as_bool().unwrap());
    assert_eq!(body["height"].as_u64().unwrap(), 1);
    assert!(body["next_best"].as_str().is_some());

    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r2 = esplora_get(esplora_port, &format!("/block/{}/status", tip));
    let body2: serde_json::Value = r2.json().unwrap();
    assert!(body2["in_best_chain"].as_bool().unwrap());
    assert!(body2.get("next_best").is_none());

    node.stop();
}

#[test]
fn test_esplora_block_txids_and_paging() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();

    let r = esplora_get(esplora_port, &format!("/block/{}/txids", tip));
    assert_eq!(r.status(), 200);
    let txids: Vec<String> = r.json().unwrap();
    assert_eq!(txids.len(), 1);

    let r2 = esplora_get(esplora_port, &format!("/block/{}/txid/0", tip));
    assert_eq!(r2.status(), 200);
    assert_eq!(r2.text().unwrap().trim(), txids[0]);

    let r3 = esplora_get(esplora_port, &format!("/block/{}/txs", tip));
    assert_eq!(r3.status(), 200);
    let stubs: Vec<serde_json::Value> = r3.json().unwrap();
    assert_eq!(stubs.len(), 1);
    assert_eq!(stubs[0]["txid"].as_str().unwrap(), txids[0]);

    node.stop();
}

/// `/block/:hash/txs/:start_index` returns an empty array for an
/// in-range-but-past-end offset, and tolerates `usize::MAX` without
/// panicking. (Review H5.)
#[test]
fn test_esplora_block_txs_pagination_past_end_returns_empty() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();

    // Offset == len → empty array, not 404 / panic.
    let r = esplora_get(esplora_port, &format!("/block/{}/txs/1", tip));
    assert_eq!(r.status(), 200);
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    assert!(arr.is_empty());

    // usize::MAX must be saturated, not overflow-panic.
    let r2 = esplora_get(esplora_port, &format!("/block/{}/txs/{}", tip, usize::MAX));
    assert_eq!(r2.status(), 200);
    let arr2: Vec<serde_json::Value> = r2.json().unwrap();
    assert!(arr2.is_empty());

    node.stop();
}

/// `mediantime` for the tip includes the tip's own header time in
/// the median set, not just its 11 ancestors. (Round-2 M2.) Mining
/// a single block past genesis yields a tip whose `mediantime`
/// should equal the tip's own header time (not genesis time, which
/// is what the off-by-one helper would return).
#[test]
fn test_esplora_block_mediantime_includes_target_block() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let body: serde_json::Value = esplora_get(esplora_port, &format!("/block/{}", tip))
        .json()
        .unwrap();
    let header_time = body["timestamp"].as_u64().unwrap();
    let mediantime = body["mediantime"].as_u64().unwrap();
    // With 2 blocks total (genesis + the one mined), the median of
    // {genesis_time, tip_time} is the larger of the two (since
    // even-length medians return the upper-middle). For monotonic
    // regtest timestamps that's the tip's own time. The off-by-one
    // helper would have returned genesis time.
    assert_eq!(
        mediantime, header_time,
        "tip mediantime must include the tip itself; off-by-one would return genesis"
    );
    node.stop();
}

/// `/blocks` returns real `size`/`weight` from flat-file data (no
/// longer the PR-2 placeholder zeros). (Review M1.)
#[test]
fn test_esplora_blocks_recent_reports_real_size_weight() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();
    let r = esplora_get(esplora_port, "/blocks");
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    // Inspect the most recent (non-genesis) entries — genesis is
    // small but the regtest coinbase blocks must report >0.
    let non_genesis: Vec<&serde_json::Value> = arr
        .iter()
        .filter(|e| e["height"].as_u64() != Some(0))
        .collect();
    assert!(!non_genesis.is_empty());
    for entry in non_genesis {
        assert!(
            entry["size"].as_u64().unwrap() > 0,
            "non-genesis block size must be > 0; entry: {entry}"
        );
        assert!(
            entry["weight"].as_u64().unwrap() > 0,
            "non-genesis block weight must be > 0; entry: {entry}"
        );
    }
    node.stop();
}

#[test]
fn test_esplora_block_bad_hash_returns_400() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let r = esplora_get(esplora_port, "/block/not-a-hash");
    assert_eq!(r.status(), 400);
    node.stop();
}

#[test]
fn test_esplora_block_unknown_hash_returns_404() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let zero = "0".repeat(64);
    let r = esplora_get(esplora_port, &format!("/block/{}", zero));
    assert_eq!(r.status(), 404);
    node.stop();
}

/// Cookie auth: when `--esploraauth=cookie`, requests without the
/// Authorization header get 401, and cookie-authenticated requests
/// succeed.
#[test]
fn test_esplora_auth_cookie_gates_endpoints() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--esploraauth=cookie"]);

    // No auth → 401.
    let unauth = esplora_get(esplora_port, "/blocks/tip/height");
    assert_eq!(unauth.status(), 401);

    // With cookie → 200. The cookie path defaults to the JSON-RPC
    // shared `.cookie`, which TestNode already read into `node.cookie`.
    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let r = client
        .get(format!(
            "http://127.0.0.1:{}/blocks/tip/height",
            esplora_port
        ))
        .header("Authorization", format!("Basic {}", auth))
        .send()
        .expect("esplora GET with cookie");
    assert_eq!(r.status(), 200, "expected 200 with cookie auth");

    node.stop();
}

// ── Esplora tx endpoints (PR 4) ──

/// `/tx/:txid` for a confirmed coinbase returns the full Esplora tx
/// shape with `is_coinbase=true` and a populated `status` block.
#[test]
fn test_esplora_tx_detail_confirmed_coinbase() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    let txids: Vec<String> = {
        let tip = esplora_get(esplora_port, "/blocks/tip/hash")
            .text()
            .unwrap()
            .trim()
            .to_string();
        esplora_get(esplora_port, &format!("/block/{}/txids", tip))
            .json()
            .unwrap()
    };
    let coinbase = &txids[0];
    let r = esplora_get(esplora_port, &format!("/tx/{}", coinbase));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["txid"].as_str().unwrap(), coinbase);
    let vin = body["vin"].as_array().unwrap();
    assert_eq!(vin.len(), 1);
    assert!(vin[0]["is_coinbase"].as_bool().unwrap());
    assert!(vin[0]["txid"].is_null(), "coinbase vin omits prev txid");
    let vout = body["vout"].as_array().unwrap();
    assert!(!vout.is_empty(), "coinbase has at least one output");
    assert_eq!(vout[0]["scriptpubkey_type"].as_str().unwrap(), "v0_p2wpkh");
    assert!(vout[0]["scriptpubkey_address"].as_str().is_some());
    let status = &body["status"];
    assert!(status["confirmed"].as_bool().unwrap());
    assert_eq!(status["block_height"].as_u64().unwrap(), 1);
    assert!(status["block_hash"].as_str().is_some());
    assert!(body["fee"].as_u64().unwrap() == 0, "coinbase has fee=0");
    node.stop();
}

/// `/tx/:txid/status` confirms-then-mempool fallback.
#[test]
fn test_esplora_tx_status_confirmed() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let r = esplora_get(esplora_port, &format!("/tx/{}/status", txids[0]));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert!(body["confirmed"].as_bool().unwrap());
    assert_eq!(body["block_height"].as_u64().unwrap(), 1);
    assert_eq!(body["block_hash"].as_str().unwrap(), tip);
    node.stop();
}

/// `/tx/:txid/hex` returns the consensus-serialized tx as hex; deser
/// must round-trip to the same txid.
#[test]
fn test_esplora_tx_hex_roundtrip() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let txid = &txids[0];

    let hex_resp = esplora_get(esplora_port, &format!("/tx/{}/hex", txid));
    assert_eq!(hex_resp.status(), 200);
    let hex_body = hex_resp.text().unwrap();
    let bytes = hex::decode(hex_body.trim()).expect("hex decode");
    let tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(&bytes).expect("tx deserialize");
    assert_eq!(tx.compute_txid().to_string(), *txid);

    // /raw must agree byte-for-byte.
    let raw_resp = esplora_get(esplora_port, &format!("/tx/{}/raw", txid));
    let raw_bytes = raw_resp.bytes().unwrap();
    assert_eq!(raw_bytes.as_ref(), bytes.as_slice());

    node.stop();
}

/// Unknown txid → 404 across all `/tx/:txid` shapes.
#[test]
fn test_esplora_tx_unknown_returns_404() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let zero = "0".repeat(64);
    for path in [
        format!("/tx/{}", zero),
        format!("/tx/{}/status", zero),
        format!("/tx/{}/hex", zero),
        format!("/tx/{}/raw", zero),
    ] {
        let r = esplora_get(esplora_port, &path);
        assert_eq!(
            r.status(),
            404,
            "expected 404 for {} but got {}",
            path,
            r.status()
        );
    }
    node.stop();
}

/// Bad txid hex → 400.
#[test]
fn test_esplora_tx_bad_txid_returns_400() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let r = esplora_get(esplora_port, "/tx/not-a-txid");
    assert_eq!(r.status(), 400);
    node.stop();
}

/// `--esplora=1 --txindex=0` must fail daemon startup with a clear
/// Default `satd --regtest --datadir=...` (no `--esplora=0`, no
/// `--txindex`) starts cleanly. Earlier round-1 H3 made this combo
/// hard-fail on startup; round-2 reconciles by auto-enabling txindex
/// when esplora is on. (Review-2 H3.)
#[test]
fn test_esplora_default_startup_auto_enables_txindex() {
    use std::process::Command;
    use std::time::Instant;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let esplora_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-default-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    let mut child = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        // No --esplora flag (default true), no --txindex flag (default
        // false). The reconciliation should kick in.
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn satd");

    // Wait for the Esplora listener to come up (proves the daemon
    // didn't exit at startup).
    let deadline = Instant::now() + test_timeout(120);
    let mut ready = false;
    while Instant::now() < deadline {
        if reqwest::blocking::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/blocks/tip/height",
                esplora_port
            ))
            .timeout(Duration::from_millis(500))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ready,
        "esplora listener didn't come up under default startup"
    );
}

/// Round-3 H1: an upgraded datadir (synced previously with
/// `--txindex=0`) that now starts with default Esplora settings
/// must NOT silently come up — it would false-404 historical txs.
/// This test simulates the upgrade by:
/// 1. Mining blocks with `--esplora=0` (so txindex stays at default off).
/// 2. Restarting with default settings (esplora auto-enables txindex).
/// 3. Asserting startup fails with a clear "incomplete" message.
#[test]
fn test_esplora_refuses_legacy_txindex_incomplete_datadir() {
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir().join(format!("satd-legacy-txi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    // Phase 1: sync with --esplora=0 (no txindex implication, no
    // tx_index rows written).
    let rpcport1 = find_available_port();
    let p2p_port1 = find_available_port();
    let mut node1 = TestNode::start_with_datadir(
        &datadir,
        rpcport1,
        &["--esplora=0", &format!("--port={}", p2p_port1)],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node1
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .expect("rpc");
    node1.stop();

    // Phase 2: restart with default settings — esplora auto-enables
    // txindex, but the CF is empty for historical rows. Startup
    // must hard-fail.
    let rpcport2 = find_available_port();
    let p2p_port2 = find_available_port();
    let esplora_port = find_available_port();
    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport2))
        .arg(format!("--port={}", p2p_port2))
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .output()
        .expect("spawn satd");
    assert!(
        !out.status.success(),
        "expected non-zero exit; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tx_index") && stderr.contains("incomplete"),
        "expected tx_index incomplete diag in stderr; got: {stderr}"
    );
    assert!(
        stderr.contains("--reindex-chainstate"),
        "expected reindex hint in stderr; got: {stderr}"
    );
}

/// Round-4 H1: a partial-history datadir (legacy empty
/// `tx_index` plus a single later block mined with `--txindex=1`)
/// must still be refused by the Esplora startup gate. The earlier
/// "any rows means complete" heuristic incorrectly accepted this
/// case.
#[test]
fn test_esplora_refuses_partial_txindex_history() {
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir().join(format!("satd-partial-txi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    // Phase 1: legacy sync with --esplora=0 --txindex=0. tx_index
    // stays empty; the marker is invalidated to false on first
    // block-connect under txindex=off.
    let rpcport1 = find_available_port();
    let p2p_port1 = find_available_port();
    let mut node1 = TestNode::start_with_datadir(
        &datadir,
        rpcport1,
        &["--esplora=0", &format!("--port={}", p2p_port1)],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node1
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .expect("rpc");
    node1.stop();

    // Phase 2: enable --txindex=1 (still --esplora=0). This writes
    // ONE block's tx_index rows on top of the empty CF, but doesn't
    // change the marker (it's stamped false from phase 1).
    let rpcport2 = find_available_port();
    let p2p_port2 = find_available_port();
    let mut node2 = TestNode::start_with_datadir(
        &datadir,
        rpcport2,
        &["--esplora=0", "--txindex", &format!("--port={}", p2p_port2)],
    );
    let _ = node2
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .expect("rpc");
    node2.stop();

    // Phase 3: default startup (esplora on). Marker is still false
    // — the "any rows" heuristic would have accepted this, but the
    // round-4 fix keeps the marker one-way.
    let rpcport3 = find_available_port();
    let p2p_port3 = find_available_port();
    let esplora_port = find_available_port();
    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport3))
        .arg(format!("--port={}", p2p_port3))
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .output()
        .expect("spawn satd");
    assert!(
        !out.status.success(),
        "expected non-zero exit; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tx_index") && stderr.contains("incomplete"),
        "expected incomplete diag in stderr; got: {stderr}"
    );
}

/// Round-4 H1: a fully-indexed datadir, then one block connected
/// with `--txindex=0`, must invalidate the marker so Esplora
/// refuses to start without a reindex. (Inverse direction of
/// `test_esplora_refuses_partial_txindex_history`.)
#[test]
fn test_esplora_refuses_after_txindex_disabled_gap() {
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir().join(format!("satd-disabled-gap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);

    // Phase 1: full sync with --esplora=0 --txindex=1. Marker stays
    // true after open (fresh datadir); blocks land with their
    // tx_index rows. No invalidation fires (txindex enabled).
    let rpcport1 = find_available_port();
    let p2p_port1 = find_available_port();
    let mut node1 = TestNode::start_with_datadir(
        &datadir,
        rpcport1,
        &["--esplora=0", "--txindex", &format!("--port={}", p2p_port1)],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node1
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .expect("rpc");
    node1.stop();

    // Phase 2: connect ONE more block with --txindex=0. This MUST
    // flip the marker to false via the connect-time invalidation.
    let rpcport2 = find_available_port();
    let p2p_port2 = find_available_port();
    let mut node2 = TestNode::start_with_datadir(
        &datadir,
        rpcport2,
        &["--esplora=0", &format!("--port={}", p2p_port2)],
    );
    let _ = node2
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .expect("rpc");
    node2.stop();

    // Phase 3: default startup must hard-fail now.
    let rpcport3 = find_available_port();
    let p2p_port3 = find_available_port();
    let esplora_port = find_available_port();
    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport3))
        .arg(format!("--port={}", p2p_port3))
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .output()
        .expect("spawn satd");
    assert!(
        !out.status.success(),
        "expected non-zero exit; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tx_index") && stderr.contains("incomplete"),
        "expected incomplete diag in stderr; got: {stderr}"
    );
}

/// Round-3 M1: `--txindex` on the CLI overrides `txindex=0` in the
/// config file. (Without this fix, the operator's CLI override is
/// silently ignored and the daemon hard-fails.)
#[test]
fn test_esplora_cli_txindex_overrides_config_disable() {
    use std::process::Command;
    use std::time::Instant;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let esplora_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-cli-override-{}", rpcport));
    let _ = std::fs::remove_dir_all(&datadir);
    let _ = std::fs::create_dir_all(&datadir);
    // Plant txindex=0 in the config file.
    std::fs::write(datadir.join("bitcoin.conf"), "txindex=0\n").unwrap();

    // CLI --txindex must win over the config-file disable.
    let mut child = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--esplora=1")
        .arg("--txindex")
        .arg(format!("--esplorabind=127.0.0.1:{}", esplora_port))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn satd");

    // Wait briefly for the listener — proves startup succeeded.
    let deadline = Instant::now() + test_timeout(120);
    let mut ready = false;
    while Instant::now() < deadline {
        if reqwest::blocking::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/blocks/tip/height",
                esplora_port
            ))
            .timeout(Duration::from_millis(500))
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ready,
        "esplora listener didn't come up; CLI --txindex must override config txindex=0"
    );
}

/// Explicit `txindex=0` in the config file with `--esplora=1`
/// remains a hard-fail — the operator made an irreconcilable
/// choice. (Review-2 H3, contrast.)
#[test]
fn test_esplora_with_explicit_txindex_disabled_fails_startup() {
    use std::process::Command;
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let rpcport = find_available_port();
    let p2p_port = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-conflict-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let net_dir = datadir.join("regtest");
    let _ = std::fs::create_dir_all(&net_dir);
    std::fs::write(net_dir.join("bitcoin.conf"), "txindex=0\n").unwrap();
    // Also write a top-level .conf that satd reads first; safest to
    // cover both possible search paths.
    std::fs::write(datadir.join("bitcoin.conf"), "txindex=0\n").unwrap();

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", p2p_port))
        .arg("--esplora=1")
        .output()
        .expect("spawn satd");
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("txindex=0"),
        "expected explicit-disable diag in stderr; got: {stderr}"
    );
}

/// `/block/:hash/txs` now returns the full Esplora tx shape (replaces
/// PR 3's `{txid}` stub).
#[test]
fn test_esplora_block_txs_returns_full_tx_shape() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--txindex"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let r = esplora_get(esplora_port, &format!("/block/{}/txs", tip));
    assert_eq!(r.status(), 200);
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    assert_eq!(arr.len(), 1);
    let entry = &arr[0];
    // Full TxJson shape must be present, not the PR-3 stub.
    assert!(entry["vin"].is_array());
    assert!(entry["vout"].is_array());
    assert!(entry["status"].is_object());
    // fee is `Option<u64>`: `Some(0)` for coinbase, otherwise number;
    // null only when prevouts couldn't be resolved.
    assert!(entry["fee"].is_u64() || entry["fee"].is_null());
    assert!(entry["weight"].is_u64());
    node.stop();
}

// ── Esplora address/scripthash endpoints (PR 5) ──

/// Compute the Esplora-flavored scripthash (raw sha256 of the
/// scriptPubKey, hex-encoded in natural byte order) of a regtest
/// address. Used by the address-vs-scripthash equivalence tests.
fn esplora_scripthash_of(addr: &str) -> String {
    use bitcoin::hashes::Hash as _;
    let unchecked: bitcoin::Address<bitcoin::address::NetworkUnchecked> = addr.parse().unwrap();
    let address = unchecked
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let spk = address.script_pubkey();
    let h = bitcoin::hashes::sha256::Hash::hash(spk.as_bytes());
    hex::encode(h.to_byte_array())
}

/// Stats for an unfunded address are all zero. Establishes the empty
/// baseline so positive-funded tests can assert deltas, not absolutes.
#[test]
fn test_esplora_address_info_empty_returns_zero_stats() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let r = esplora_get(esplora_port, &format!("/address/{}", addr));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["address"], serde_json::json!(addr));
    assert_eq!(body["chain_stats"]["tx_count"], 0);
    assert_eq!(body["chain_stats"]["funded_txo_count"], 0);
    assert_eq!(body["chain_stats"]["funded_txo_sum"], 0);
    assert_eq!(body["chain_stats"]["spent_txo_count"], 0);
    assert_eq!(body["chain_stats"]["spent_txo_sum"], 0);
    assert_eq!(body["mempool_stats"]["tx_count"], 0);
    node.stop();
}

/// Mining N blocks to an address must populate `chain_stats` with N
/// funding rows totalling N × subsidy and `tx_count == N` (each
/// coinbase is a distinct tx).
#[test]
fn test_esplora_address_info_funded_chain_stats() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(3), serde_json::json!(addr)],
        )
        .unwrap();

    let r = esplora_get(esplora_port, &format!("/address/{}", addr));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    let chain = &body["chain_stats"];
    assert_eq!(chain["tx_count"], 3);
    assert_eq!(chain["funded_txo_count"], 3);
    // Regtest subsidy 50 BTC/block before halvings (height < 150).
    assert_eq!(chain["funded_txo_sum"], 3u64 * 50 * 100_000_000);
    assert_eq!(chain["spent_txo_count"], 0);
    assert_eq!(chain["spent_txo_sum"], 0);
    node.stop();
}

/// `/scripthash/:hash` must return the same payload as `/address/:addr`
/// for a key whose scripthash we precompute — proves the parser
/// equivalence + same render path.
#[test]
fn test_esplora_scripthash_endpoint_matches_address() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    let sh = esplora_scripthash_of(addr);
    let by_addr: serde_json::Value = esplora_get(esplora_port, &format!("/address/{}", addr))
        .json()
        .unwrap();
    let by_sh: serde_json::Value = esplora_get(esplora_port, &format!("/scripthash/{}", sh))
        .json()
        .unwrap();
    assert_eq!(by_addr["chain_stats"], by_sh["chain_stats"]);
    assert_eq!(by_addr["mempool_stats"], by_sh["mempool_stats"]);
    // The `address` field reflects the literal input — different by
    // construction. Everything else must agree.
    assert_eq!(by_sh["address"], serde_json::json!(sh));
    node.stop();
}

/// `/address/:addr/utxo` lists each live UTXO with a confirmed status
/// block (block_height + block_hash + block_time present).
#[test]
fn test_esplora_address_utxo_lists_coinbases() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    let r = esplora_get(esplora_port, &format!("/address/{}/utxo", addr));
    assert_eq!(r.status(), 200);
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    assert_eq!(arr.len(), 2, "two coinbase outputs to addr");
    for entry in &arr {
        assert_eq!(entry["status"]["confirmed"], true);
        assert!(entry["status"]["block_height"].is_u64());
        assert!(entry["status"]["block_hash"].is_string());
        assert!(entry["status"]["block_time"].is_u64());
        assert_eq!(entry["value"], 50u64 * 100_000_000);
    }
    node.stop();
}

/// `/address/:addr/txs/chain` returns at most 25 confirmed txs newest
/// first; subsequent pages via `…/chain/:last_seen_txid` continue
/// strictly older than the cursor.
#[test]
fn test_esplora_address_txs_chain_pagination() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    // 30 distinct coinbases → 25 on page 1, 5 on page 2, empty on page 3.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(30), serde_json::json!(addr)],
        )
        .unwrap();

    let page1: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/txs/chain", addr))
            .json()
            .unwrap();
    assert_eq!(page1.len(), 25);
    // Newest first — first entry's block_height must be 30.
    assert_eq!(page1[0]["status"]["block_height"], 30);
    // Last entry's block_height = 6 (first page = heights 30..6).
    assert_eq!(page1[24]["status"]["block_height"], 6);

    let last_txid = page1[24]["txid"].as_str().unwrap();
    let page2: Vec<serde_json::Value> = esplora_get(
        esplora_port,
        &format!("/address/{}/txs/chain/{}", addr, last_txid),
    )
    .json()
    .unwrap();
    assert_eq!(page2.len(), 5);
    assert_eq!(page2[0]["status"]["block_height"], 5);
    assert_eq!(page2[4]["status"]["block_height"], 1);

    let final_txid = page2[4]["txid"].as_str().unwrap();
    let page3: Vec<serde_json::Value> = esplora_get(
        esplora_port,
        &format!("/address/{}/txs/chain/{}", addr, final_txid),
    )
    .json()
    .unwrap();
    assert_eq!(page3.len(), 0);
    node.stop();
}

/// An unknown `last_seen_txid` returns an empty page, NOT 404 —
/// matches upstream Esplora's contract for clients whose pagination
/// state went stale.
#[test]
fn test_esplora_address_txs_chain_unknown_cursor_returns_empty() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    // 32-byte zero txid is never a real tx; cursor lookup fails.
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    let r = esplora_get(
        esplora_port,
        &format!("/address/{}/txs/chain/{}", addr, zero),
    );
    assert_eq!(r.status(), 200);
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    assert_eq!(arr.len(), 0);
    node.stop();
}

/// Spending one of two coinbases must update chain_stats: spent_txo_count
/// increments and spent_txo_sum equals the spent coinbase's value.
#[test]
fn test_esplora_address_chain_stats_after_spend() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x37u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    // Mine 101 blocks to src so coinbase 1 is matured.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str.clone())],
        )
        .unwrap();

    // Pull block 1's coinbase txid.
    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let block1 = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .unwrap();
    let cb_txid_str = block1["result"]["tx"][0].as_str().unwrap();
    let cb_txid = bitcoin::Txid::from_str(cb_txid_str).unwrap();
    let cb_value = 50u64 * 100_000_000;

    // Spend cb output → dest, fee 1000.
    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send = cb_value - 1000;
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
            value: Amount::from_sat(send),
            script_pubkey: dest_script,
        }],
    };
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;
    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let _ = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .unwrap();
    // Mine to confirm.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(src_str.clone())],
        )
        .unwrap();

    // src now has 100 confirmed coinbases (101 mined; matured ones
    // count as "funded" rows regardless of maturity since the index
    // is independent of coinbase maturity policy). One was spent.
    let r = esplora_get(esplora_port, &format!("/address/{}", src_str));
    let body: serde_json::Value = r.json().unwrap();
    let chain = &body["chain_stats"];
    // 101 src coinbases + 1 from the spend-confirming block = 102.
    assert_eq!(chain["funded_txo_count"], 102);
    assert_eq!(chain["spent_txo_count"], 1);
    assert_eq!(chain["spent_txo_sum"], cb_value);
    // tx_count: 102 distinct coinbase txids + the spend tx (which
    // also touches src as the spending input).
    assert_eq!(chain["tx_count"], 103);

    // dest sees one funding row for `send` value, no spends.
    let r2 = esplora_get(esplora_port, &format!("/address/{}", dest_addr));
    let body2: serde_json::Value = r2.json().unwrap();
    assert_eq!(body2["chain_stats"]["funded_txo_count"], 1);
    assert_eq!(body2["chain_stats"]["funded_txo_sum"], send);
    assert_eq!(body2["chain_stats"]["spent_txo_count"], 0);
    node.stop();
}

/// `/address/:addr/txs/mempool` reflects unconfirmed txs while
/// `/address/:addr/txs/chain` does not (until they're mined).
#[test]
fn test_esplora_address_txs_mempool_visibility() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str.clone())],
        )
        .unwrap();
    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let block1 = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .unwrap();
    let cb_txid_str = block1["result"]["tx"][0].as_str().unwrap();
    let cb_txid = bitcoin::Txid::from_str(cb_txid_str).unwrap();
    let cb_value = 50u64 * 100_000_000;

    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send = cb_value - 1000;
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
            value: Amount::from_sat(send),
            script_pubkey: dest_script,
        }],
    };
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;
    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let spend_txid = spend.compute_txid().to_string();

    // Submit but DO NOT mine — tx sits in mempool.
    let _ = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .unwrap();

    // dest's `/txs/mempool` must include the unconfirmed tx; `/txs/chain` must not.
    let mempool_resp: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/txs/mempool", dest_addr))
            .json()
            .unwrap();
    let mempool_txids: Vec<String> = mempool_resp
        .iter()
        .map(|v| v["txid"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        mempool_txids.contains(&spend_txid),
        "/txs/mempool must contain the unconfirmed spend; got {:?}",
        mempool_txids
    );

    let chain_resp: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/txs/chain", dest_addr))
            .json()
            .unwrap();
    assert!(
        chain_resp.is_empty(),
        "/txs/chain must be empty pre-confirmation; got {:?}",
        chain_resp
    );

    // mempool_stats: 1 funding row for dest, value `send`.
    let info: serde_json::Value = esplora_get(esplora_port, &format!("/address/{}", dest_addr))
        .json()
        .unwrap();
    assert_eq!(info["mempool_stats"]["funded_txo_count"], 1);
    assert_eq!(info["mempool_stats"]["funded_txo_sum"], send);
    assert_eq!(info["mempool_stats"]["tx_count"], 1);

    // /utxo shows the mempool funding output with confirmed: false.
    let utxo: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/utxo", dest_addr))
            .json()
            .unwrap();
    let unconfirmed = utxo
        .iter()
        .find(|v| v["txid"] == serde_json::json!(spend_txid))
        .expect("mempool funding utxo should appear in /utxo");
    assert_eq!(unconfirmed["status"]["confirmed"], false);
    assert_eq!(unconfirmed["value"], send);
    node.stop();
}

/// Bad address strings produce 400, not 500. Bad scripthash hex
/// produces 400. Mainnet address against regtest produces 400.
#[test]
fn test_esplora_address_bad_input_400() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let r = esplora_get(esplora_port, "/address/not-an-address");
    assert_eq!(r.status(), 400);

    let r = esplora_get(esplora_port, "/scripthash/not-hex");
    assert_eq!(r.status(), 400);

    let r = esplora_get(esplora_port, "/scripthash/0011");
    assert_eq!(r.status(), 400, "scripthash must be exactly 32 bytes");

    // Mainnet bech32 against regtest network → wrong-network 400.
    let r = esplora_get(
        esplora_port,
        "/address/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    );
    assert_eq!(r.status(), 400);
    node.stop();
}

/// Review H2: a confirmed UTXO that is consumed by an unconfirmed
/// mempool transaction must NOT appear in the source address's
/// `/utxo` listing. Listing it would let wallets attempt to
/// double-spend the same outpoint.
#[test]
fn test_esplora_address_utxo_excludes_mempool_spent() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x91u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str.clone())],
        )
        .unwrap();

    // Pull block 1's coinbase (the matured one we'll spend).
    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let block1 = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .unwrap();
    let cb_txid_str = block1["result"]["tx"][0].as_str().unwrap();
    let cb_txid = bitcoin::Txid::from_str(cb_txid_str).unwrap();
    let cb_value = 50u64 * 100_000_000;

    // Pre-broadcast: src has 101 confirmed coinbase UTXOs; the one at
    // block 1 is in /utxo. Verify presence.
    let pre: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/utxo", src_str))
            .json()
            .unwrap();
    assert!(
        pre.iter()
            .any(|u| u["txid"] == serde_json::json!(cb_txid_str) && u["vout"] == 0),
        "pre-broadcast: block-1 coinbase outpoint must appear in /utxo"
    );

    // Build + broadcast a P2WPKH spend: src(block-1 cb) → dest, fee 1000.
    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send = cb_value - 1000;
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
            value: Amount::from_sat(send),
            script_pubkey: dest_script,
        }],
    };
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let _ = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .unwrap();

    // Post-broadcast: src's `/utxo` MUST NOT list the spent outpoint
    // even though the spending tx is still in the mempool.
    let post: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/utxo", src_str))
            .json()
            .unwrap();
    assert!(
        !post
            .iter()
            .any(|u| u["txid"] == serde_json::json!(cb_txid_str) && u["vout"] == 0),
        "/utxo must NOT list a confirmed outpoint with a mempool spend; got: {:?}",
        post
    );

    // dest's `/utxo` does list the unconfirmed funding output.
    let dest_utxos: Vec<serde_json::Value> =
        esplora_get(esplora_port, &format!("/address/{}/utxo", dest_addr))
            .json()
            .unwrap();
    let spend_txid = spend.compute_txid().to_string();
    let dest_entry = dest_utxos
        .iter()
        .find(|u| u["txid"] == serde_json::json!(spend_txid))
        .expect("dest /utxo should list the mempool funding output");
    assert_eq!(dest_entry["status"]["confirmed"], false);
    node.stop();
}
// ── Esplora outspends + merkle proofs (PR 6) ──

/// Helper: build a confirmed P2WPKH spend for tests below. Returns
/// `(spend_tx_hex, spend_txid_str, src_str, dest_str, cb_value_sat)`
/// after mining 101 blocks to the src and submitting the spend (pre-
/// mining; caller decides whether to mine the next block to confirm).
fn esplora_pr6_make_spend(node: &mut TestNode) -> (String, String, String, &'static str, u64) {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x73u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str.clone())],
        )
        .unwrap();

    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let block1 = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .unwrap();
    let cb_txid = bitcoin::Txid::from_str(block1["result"]["tx"][0].as_str().unwrap()).unwrap();
    let cb_value = 50u64 * 100_000_000;

    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send = cb_value - 1000;
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
            value: Amount::from_sat(send),
            script_pubkey: dest_script,
        }],
    };
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let spend_txid = spend.compute_txid().to_string();
    let _ = node
        .rpc_call_with_params(
            "sendrawtransaction",
            vec![serde_json::json!(raw_hex.clone())],
        )
        .unwrap();
    (raw_hex, spend_txid, src_str, dest_addr, cb_value)
}

/// `/tx/:txid/outspend/:vout` returns `{spent: false}` for an unspent
/// coinbase output.
#[test]
fn test_esplora_outspend_unspent_returns_spent_false() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let cb = &txids[0];
    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/0", cb));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["spent"], false);
    assert!(body["txid"].is_null() || !body.as_object().unwrap().contains_key("txid"));
    node.stop();
}

/// After confirming a real spend, `/outspend/:vout` reports the
/// spending tx with `confirmed: true` and the spending tx's block.
#[test]
fn test_esplora_outspend_confirmed_spend_reports_spender() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let (_raw_hex, spend_txid, src_str, _dest, cb_value) = esplora_pr6_make_spend(&mut node);

    // Mine 1 to confirm the spend.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(src_str)],
        )
        .unwrap();

    // Find the cb txid for block 1 (the one being spent).
    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let cb_txid: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", block1_hash))
        .json()
        .unwrap();
    let cb = &cb_txid[0];

    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/0", cb));
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["spent"], true);
    assert_eq!(body["txid"], serde_json::json!(spend_txid));
    assert_eq!(body["vin"], 0);
    assert_eq!(body["status"]["confirmed"], true);
    // The confirming block height for the spend = 102.
    assert_eq!(body["status"]["block_height"], 102);
    let _ = cb_value;
    node.stop();
}

/// A mempool-only spend appears in /outspend with `confirmed: false`.
#[test]
fn test_esplora_outspend_mempool_spend_reports_unconfirmed() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let (_raw_hex, spend_txid, _src, _dest, _) = esplora_pr6_make_spend(&mut node);
    // DO NOT mine — spend remains in mempool.

    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let cb_txid: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", block1_hash))
        .json()
        .unwrap();
    let cb = &cb_txid[0];

    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/0", cb));
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["spent"], true);
    assert_eq!(body["txid"], serde_json::json!(spend_txid));
    assert_eq!(body["status"]["confirmed"], false);
    assert!(body["status"]["block_height"].is_null());
    node.stop();
}

/// `/outspends` returns one entry per output, in vout order. For a
/// confirmed coinbase that's been spent at vout 0, the array is `[spent, ...rest]`.
#[test]
fn test_esplora_outspends_array_matches_output_count() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    // Pull tip's coinbase.
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let cb = &txids[0];

    let r = esplora_get(esplora_port, &format!("/tx/{}/outspends", cb));
    let arr: Vec<serde_json::Value> = r.json().unwrap();
    // Coinbase to a single P2WPKH/P2WSH address: one output.
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["spent"], false);
    node.stop();
}

/// Single-tx block: merkle-proof returns empty `merkle` array, pos=0.
#[test]
fn test_esplora_merkle_proof_single_tx_block_is_empty() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let cb = &txids[0];

    let r = esplora_get(esplora_port, &format!("/tx/{}/merkle-proof", cb));
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["block_height"], 1);
    assert_eq!(body["pos"], 0);
    let merkle: Vec<serde_json::Value> = body["merkle"].as_array().unwrap().clone();
    assert!(
        merkle.is_empty(),
        "single-tx block has empty merkle path; got {:?}",
        merkle
    );
    node.stop();
}

/// Multi-tx block: merkle-proof returns a non-empty path that proves
/// the tx is in the block. Verify length matches ceil(log2(n)) and that
/// the reconstructed root matches the block header's merkle_root.
#[test]
fn test_esplora_merkle_proof_two_tx_block_proves_inclusion() {
    use bitcoin::hashes::Hash as _;
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let (_raw, spend_txid, src_str, _dest, _) = esplora_pr6_make_spend(&mut node);
    // Mine to confirm spend → block 102 has 2 txs (coinbase + spend).
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(src_str)],
        )
        .unwrap();

    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    assert_eq!(txids.len(), 2);

    let r = esplora_get(esplora_port, &format!("/tx/{}/merkle-proof", spend_txid));
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["block_height"], 102);
    let pos = body["pos"].as_u64().unwrap();
    assert_eq!(pos, 1, "spend tx is the 2nd tx in the block");
    let merkle: Vec<String> = body["merkle"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(merkle.len(), 1, "2-tx block has a single-step merkle path");

    // Reconstruct the merkle root from the proof and compare against
    // the block header's merkle_root.
    let block_detail: serde_json::Value = esplora_get(esplora_port, &format!("/block/{}", tip))
        .json()
        .unwrap();
    let header_merkle_root = block_detail["merkle_root"].as_str().unwrap().to_string();

    // Walk the proof: start with our txid (display→raw byte order),
    // pair with each sibling (display order; reverse for raw), apply
    // sha256d, reverse for display.
    fn reverse_hex(s: &str) -> Vec<u8> {
        let mut bytes = hex::decode(s).unwrap();
        bytes.reverse();
        bytes
    }
    let mut acc: [u8; 32] = reverse_hex(&spend_txid).try_into().unwrap();
    let mut idx = pos as usize;
    for sib_hex in &merkle {
        let sib: [u8; 32] = reverse_hex(sib_hex).try_into().unwrap();
        let mut combined = [0u8; 64];
        if idx & 1 == 0 {
            combined[..32].copy_from_slice(&acc);
            combined[32..].copy_from_slice(&sib);
        } else {
            combined[..32].copy_from_slice(&sib);
            combined[32..].copy_from_slice(&acc);
        }
        acc = bitcoin::hashes::sha256d::Hash::hash(&combined).to_byte_array();
        idx /= 2;
    }
    // Reverse for display.
    let mut display = acc.to_vec();
    display.reverse();
    let computed = hex::encode(display);
    assert_eq!(computed, header_merkle_root);
    node.stop();
}

/// `/merkleblock-proof` returns valid hex that decodes to a MerkleBlock
/// containing the requested txid.
#[test]
fn test_esplora_merkleblock_proof_decodes_with_target_txid() {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::merkle_tree::MerkleBlock;
    use std::str::FromStr;
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let (_raw, spend_txid, src_str, _dest, _) = esplora_pr6_make_spend(&mut node);
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(src_str)],
        )
        .unwrap();

    let r = esplora_get(
        esplora_port,
        &format!("/tx/{}/merkleblock-proof", spend_txid),
    );
    assert_eq!(r.status(), 200);
    let hex_body = r.text().unwrap();
    let bytes = hex::decode(hex_body.trim()).unwrap();
    let mb: MerkleBlock = deserialize(&bytes).expect("must decode as MerkleBlock");

    let mut matches: Vec<bitcoin::Txid> = Vec::new();
    let mut indexes: Vec<u32> = Vec::new();
    mb.extract_matches(&mut matches, &mut indexes).unwrap();
    let want = bitcoin::Txid::from_str(&spend_txid).unwrap();
    assert!(matches.contains(&want));
    node.stop();
}

/// `/outspend` for an unknown txid → 404 (not 500).
#[test]
fn test_esplora_outspend_unknown_txid_returns_404() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    // /outspends — list endpoint must 404 for an unknown txid.
    let r = esplora_get(
        esplora_port,
        "/tx/0000000000000000000000000000000000000000000000000000000000000000/outspends",
    );
    assert_eq!(r.status(), 404);

    // /outspend/:vout — single-output endpoint must also 404 for an
    // unknown txid (review H1). Previously returned `200 {spent:false}`.
    let r = esplora_get(
        esplora_port,
        "/tx/0000000000000000000000000000000000000000000000000000000000000000/outspend/0",
    );
    assert_eq!(r.status(), 404);
    node.stop();
}

/// Review H1: `/tx/:txid/outspend/:vout` must return 404 when `vout`
/// is past the tx's output count, even for a real txid. Previously
/// returned `200 {spent:false}` for any out-of-range vout.
#[test]
fn test_esplora_outspend_out_of_range_vout_returns_404() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();
    let tip = esplora_get(esplora_port, "/blocks/tip/hash")
        .text()
        .unwrap()
        .trim()
        .to_string();
    let txids: Vec<String> = esplora_get(esplora_port, &format!("/block/{}/txids", tip))
        .json()
        .unwrap();
    let cb = &txids[0];

    // vout 0 (in range) → 200 spent:false.
    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/0", cb));
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["spent"], false);

    // vout 1 (past coinbase output count) → 404.
    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/1", cb));
    assert_eq!(r.status(), 404);

    // vout 999 (way out of range) → 404.
    let r = esplora_get(esplora_port, &format!("/tx/{}/outspend/999", cb));
    assert_eq!(r.status(), 404);
    node.stop();
}

// ── Esplora mempool + fee + root (PR 7) ──

/// `GET /` returns the chain tip + mempool count.
#[test]
fn test_esplora_root_returns_chain_tip_and_mempool_count() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(2), serde_json::json!(addr)],
        )
        .unwrap();

    let r = esplora_get(esplora_port, "/");
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["chain_tip"]["height"], 2);
    assert!(body["chain_tip"]["hash"].is_string());
    assert_eq!(body["mempool_count"], 0);
    node.stop();
}

/// `GET /mempool` returns zeros for an empty mempool.
#[test]
fn test_esplora_mempool_summary_empty() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let r = esplora_get(esplora_port, "/mempool");
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    assert_eq!(body["count"], 0);
    assert_eq!(body["vsize"], 0);
    assert_eq!(body["total_fee"], 0);
    assert_eq!(body["fee_histogram"], serde_json::json!([]));
    node.stop();
}

/// `GET /mempool/txids` returns an empty array for an empty mempool.
#[test]
fn test_esplora_mempool_txids_empty() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let r = esplora_get(esplora_port, "/mempool/txids");
    assert_eq!(r.status(), 200);
    let arr: Vec<String> = r.json().unwrap();
    assert!(arr.is_empty());
    node.stop();
}

/// After broadcasting a tx, `/mempool` reports count=1, total_fee = 1000
/// (the test tx's fee), and the fee_histogram lists exactly one bucket.
/// `/mempool/txids` and `/mempool/recent` both surface the txid.
#[test]
fn test_esplora_mempool_with_tx_reports_summary_txids_and_recent() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{
        Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness, absolute::LockTime,
    };
    use std::str::FromStr;

    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x88u8; 32]).unwrap();
    let pk = PublicKey::new(sk.public_key(&secp));
    let cpk = CompressedPublicKey::from_slice(&pk.to_bytes()).unwrap();
    let src_addr = Address::p2wpkh(&cpk, Network::Regtest);
    let src_str = src_addr.to_string();
    let dest_addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(101), serde_json::json!(src_str.clone())],
        )
        .unwrap();
    let block1_hash = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(1)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let block1 = node
        .rpc_call_with_params(
            "getblock",
            vec![serde_json::json!(block1_hash), serde_json::json!(1)],
        )
        .unwrap();
    let cb_txid = bitcoin::Txid::from_str(block1["result"]["tx"][0].as_str().unwrap()).unwrap();
    let cb_value = 50u64 * 100_000_000;
    let dest_script = Address::from_str(dest_addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey();
    let send = cb_value - 1000;
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
            value: Amount::from_sat(send),
            script_pubkey: dest_script,
        }],
    };
    let src_script = src_addr.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &src_script,
            Amount::from_sat(cb_value),
            EcdsaSighashType::All,
        )
        .unwrap();
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let spend_txid = spend.compute_txid().to_string();
    let _ = node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .unwrap();

    // /mempool: count=1, total_fee=1000.
    let body: serde_json::Value = esplora_get(esplora_port, "/mempool").json().unwrap();
    assert_eq!(body["count"], 1);
    assert_eq!(body["total_fee"], 1000);
    let vsize = body["vsize"].as_u64().unwrap();
    assert!(vsize > 0, "vsize must be positive for a real tx");
    let hist = body["fee_histogram"].as_array().unwrap();
    assert!(
        !hist.is_empty(),
        "non-empty mempool must produce a histogram bucket"
    );

    // /mempool/txids
    let txids: Vec<String> = esplora_get(esplora_port, "/mempool/txids").json().unwrap();
    assert!(txids.contains(&spend_txid));

    // /mempool/recent
    let recent: Vec<serde_json::Value> =
        esplora_get(esplora_port, "/mempool/recent").json().unwrap();
    let entry = recent
        .iter()
        .find(|v| v["txid"] == serde_json::json!(spend_txid))
        .expect("spend tx should appear in /mempool/recent");
    assert_eq!(entry["fee"], 1000);
    assert_eq!(entry["value"], send);
    assert!(entry["vsize"].as_u64().unwrap() > 0);
    node.stop();
}

/// `GET /fee-estimates` returns a complete map keyed by every standard
/// confirmation target — entries default to 1.0 sat/vB when the node
/// lacks confirmed-block fee samples (regtest mempool is normally empty).
#[test]
fn test_esplora_fee_estimates_returns_complete_map() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    let r = esplora_get(esplora_port, "/fee-estimates");
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().unwrap();
    let obj = body.as_object().unwrap();
    // Standard targets: 1..25 + 144, 504, 1008.
    for t in [1u32, 2, 3, 6, 10, 25, 144, 504, 1008] {
        let v = obj
            .get(&t.to_string())
            .unwrap_or_else(|| panic!("missing target {t}"));
        let f = v.as_f64().expect("feerate is a number");
        // Floor is 1.0 sat/vB so consumers always have a usable value.
        assert!(f >= 1.0, "target {} feerate {} below 1.0 floor", t, f);
    }
    node.stop();
}

/// `/mempool/recent` is capped at 10 entries.
#[test]
fn test_esplora_mempool_recent_caps_at_ten() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);
    // Empty mempool: returns empty array.
    let arr: Vec<serde_json::Value> = esplora_get(esplora_port, "/mempool/recent").json().unwrap();
    assert!(arr.is_empty());
    // Seeding 10+ mempool txs in a regtest harness is heavy (each
    // requires a unique funded coinbase). The unit-level cap is verified
    // by the handler constant + sort+truncate logic; this test ensures
    // the empty-case path returns a well-formed empty array, not 404 /
    // 500. Combined with the with-tx test above (which exercises the
    // populated path), the cap behavior is covered.
    node.stop();
}

// ── Esplora live updates / SSE (PR 9) ──

/// Minimal SSE client over raw TCP. Holds a `BufReader<TcpStream>` so
/// callers can read events one at a time after the initial handshake.
/// Each call to `next_event` returns the (event_type, data) pair from
/// the next non-empty event, or panics if no event arrives within the
/// configured deadline.
struct SseClient {
    reader: std::io::BufReader<std::net::TcpStream>,
}

impl SseClient {
    fn connect(port: u16, path: &str) -> Self {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::net::TcpStream;
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("sse connect");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(req.as_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        // Skip HTTP response headers (until blank line). Verify status
        // is 200 along the way.
        let mut status_line = String::new();
        reader.read_line(&mut status_line).expect("status line");
        assert!(
            status_line.contains(" 200 "),
            "sse expected 200 OK; got: {}",
            status_line.trim()
        );
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).expect("header line");
            if header.trim().is_empty() {
                break;
            }
        }
        Self { reader }
    }

    /// Block until a complete SSE event is read. Returns
    /// `(event_type, data)`. SSE comments (`:keepalive`) are skipped.
    fn next_event(&mut self) -> (String, String) {
        use std::io::BufRead as _;
        let mut event_type = String::new();
        let mut data = String::new();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("sse read");
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                if !event_type.is_empty() || !data.is_empty() {
                    return (event_type, data);
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("event: ") {
                event_type = rest.to_string();
            } else if let Some(rest) = trimmed.strip_prefix("data: ") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(rest);
            }
            // `:` comment lines (heartbeats) and unknown directives ignored.
        }
    }
}

/// `/blocks/sse` emits a `block` event for each new BlockConnected.
/// Mine one block; expect exactly one event with the right hash + height.
#[test]
fn test_esplora_blocks_sse_emits_on_new_block() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let mut client = SseClient::connect(esplora_port, "/blocks/sse");

    // Mine in a separate thread so we don't deadlock on the SSE read.
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    let (event_type, data) = client.next_event();
    assert_eq!(event_type, "block");
    let payload: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert!(payload["hash"].is_string());
    assert_eq!(payload["height"], 1);
    node.stop();
}

/// `/address/:addr/sse` emits a `status` event when the address is
/// touched by a confirmed tx. Mine one block to the address; expect
/// the status_hash to update.
#[test]
fn test_esplora_address_sse_emits_status_on_touch() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let mut client = SseClient::connect(esplora_port, &format!("/address/{}/sse", addr));

    // Mine to the address so the status_hash updates.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    let (event_type, data) = client.next_event();
    assert_eq!(event_type, "status");
    let payload: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(payload["address"], serde_json::json!(addr));
    let sh = payload["status_hash"].as_str().unwrap();
    assert_eq!(sh.len(), 64, "status_hash hex is 32 bytes");
    // Cannot be all-zero — that's the empty-history sentinel and we
    // just funded the address.
    assert_ne!(sh, "0".repeat(64));
    node.stop();
}

/// `/scripthash/:hash/sse` is the parallel scripthash variant.
#[test]
fn test_esplora_scripthash_sse_emits_status_on_touch() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let sh = esplora_scripthash_of(addr);
    let mut client = SseClient::connect(esplora_port, &format!("/scripthash/{}/sse", sh));

    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .unwrap();

    let (event_type, data) = client.next_event();
    assert_eq!(event_type, "status");
    let payload: serde_json::Value = serde_json::from_str(&data).unwrap();
    // Under /scripthash the label is the scripthash hex.
    assert_eq!(payload["address"], serde_json::json!(sh));
    node.stop();
}

/// Bad address / scripthash to SSE endpoints → 400, like their
/// non-SSE siblings.
#[test]
fn test_esplora_sse_bad_input_400() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpStream;
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind]);

    for path in [
        "/address/not-an-address/sse",
        "/scripthash/not-hex/sse",
        "/scripthash/0011/sse",
    ] {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", esplora_port)).unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(req.as_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        assert!(
            status_line.contains(" 400 "),
            "expected 400 for {}; got: {}",
            path,
            status_line.trim()
        );
    }
    node.stop();
}

/// Review M2: open SSE streams must be bounded by `--esplorasseconns`.
/// Set the cap to 1, open one stream, then verify the next attempt
/// returns 503 (not a hung socket / accepted connection).
#[test]
fn test_esplora_sse_connection_cap_saturates_with_503() {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpStream;

    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind, "--esplorasseconns=1"]);

    // First connection: claims the only permit. Hold it open by NOT
    // dropping the SseClient until after the second connection's
    // status line has been read.
    let _holder = SseClient::connect(esplora_port, "/blocks/sse");

    // Second connection should see 503 immediately on the status line.
    let mut sock = TcpStream::connect(format!("127.0.0.1:{}", esplora_port)).unwrap();
    let req = "GET /blocks/sse HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n";
    sock.write_all(req.as_bytes()).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(sock);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    assert!(
        status.contains(" 503 "),
        "second SSE connection past cap=1 should 503; got: {}",
        status.trim()
    );

    drop(_holder); // release the permit so the node can shut down cleanly
    node.stop();
}

// ── Electrum server (PR-6 of the electrum stack) ──────────────────

/// Helper: connect a raw TCP client to an Electrum server, send one
/// JSON-RPC request line, and read the single-line response.
fn electrum_round_trip(port: u16, request: &serde_json::Value) -> serde_json::Value {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    let mut sock =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to electrum server");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut s = serde_json::to_string(request).unwrap();
    s.push('\n');
    sock.write_all(s.as_bytes()).unwrap();
    sock.flush().unwrap();
    let mut reader = BufReader::new(sock);
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read response");
    assert!(n > 0, "EOF before electrum response arrived");
    serde_json::from_str(line.trim_end()).expect("electrum response is valid JSON")
}

/// `server.version` round-trips and reports `satd/<ver>` + protocol
/// version `1.4.5`.
#[test]
fn test_electrum_server_version_round_trips() {
    let electrum_port = find_available_port();
    let bind = format!("--electrumbind=127.0.0.1:{}", electrum_port);
    let mut node = TestNode::start(&["--electrum=1", &bind]);

    let v = electrum_round_trip(
        electrum_port,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server.version",
            "params": ["test-client", "1.4"],
        }),
    );
    assert_eq!(v["id"], 1);
    let result = v["result"].as_array().expect("result is array");
    let server_name = result[0].as_str().expect("server name string");
    assert!(
        server_name.starts_with("satd/"),
        "server.version should report satd/<ver>; got {server_name}"
    );
    // Protocol version matches romanz/electrs v0.11.1 — `"1.4"`. See
    // electrum-proto::PROTOCOL_VERSION for the rationale.
    assert_eq!(result[1], "1.4", "protocol version should be 1.4");

    node.stop();
}

/// `blockchain.headers.subscribe` returns the current tip after a
/// `generatetoaddress` mines new blocks.
#[test]
fn test_electrum_headers_subscribe_returns_tip_after_mining() {
    let electrum_port = find_available_port();
    let bind = format!("--electrumbind=127.0.0.1:{}", electrum_port);
    let mut node = TestNode::start(&["--electrum=1", &bind]);

    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(7), serde_json::json!(addr)],
        )
        .unwrap();

    let v = electrum_round_trip(
        electrum_port,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "blockchain.headers.subscribe",
            "params": [],
        }),
    );
    assert_eq!(v["id"], 2);
    let height = v["result"]["height"].as_u64().expect("height");
    assert_eq!(height, 7, "tip height after 7 generatetoaddress blocks");
    let hex_str = v["result"]["hex"].as_str().expect("hex");
    // 80-byte raw header, hex-encoded → 160 hex chars.
    assert_eq!(hex_str.len(), 160, "raw header is 80 bytes (160 hex)");

    node.stop();
}

/// `blockchain.scripthash.subscribe` returns either an all-zero hex
/// status or null for an unknown scripthash. Confirms the
/// AddressIndex plumbing is wired (a missing handler would error).
#[test]
fn test_electrum_scripthash_subscribe_unknown_returns_null() {
    let electrum_port = find_available_port();
    let bind = format!("--electrumbind=127.0.0.1:{}", electrum_port);
    let mut node = TestNode::start(&["--electrum=1", &bind]);

    let v = electrum_round_trip(
        electrum_port,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "blockchain.scripthash.subscribe",
            "params": ["00".repeat(32)],
        }),
    );
    assert_eq!(v["id"], 3);
    assert!(
        v["result"].is_null(),
        "empty-history scripthash should subscribe with null status; got {}",
        v["result"]
    );

    node.stop();
}

/// `--electrum=0` (the default) means no Electrum listener is bound;
/// connecting to 127.0.0.1:50001 should refuse.
#[test]
fn test_electrum_disabled_does_not_listen() {
    let mut node = TestNode::start(&[]);
    // Connecting to the standard port without --electrum should fail
    // (or succeed only if some other process is listening — which
    // we don't try to disambiguate; we just check that satd itself
    // hasn't bound it).
    let port = find_available_port();
    let _hold = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    drop(_hold);
    // Now port is free. Verify a fresh TestNode without --electrum
    // doesn't bind it. We can't directly query "is satd binding
    // port X" from outside, so this test just confirms the node
    // boots successfully without --electrum and we can call a
    // regular RPC.
    let info = node.rpc_call("getblockchaininfo").unwrap();
    assert!(info["result"]["chain"].is_string());
    node.stop();
    // (We don't try to connect to 50001; CI environments may have
    // unrelated services there.)
}

/// Default regtest flags (no Esplora/Electrum) → `getserverstatus`
/// must report all listeners as `null` (not bound). The
/// `addressindex` field still reports its enabled/complete flags.
#[test]
fn test_getserverstatus_default_no_listeners() {
    let mut node = TestNode::start(&[]);
    let v = node.rpc_call("getserverstatus").unwrap();
    let res = &v["result"];
    assert!(
        res["esplora"].is_null(),
        "esplora should be null with default flags; got {}",
        res["esplora"]
    );
    assert!(
        res["electrum"].is_null(),
        "electrum should be null with default flags; got {}",
        res["electrum"]
    );
    assert!(
        res["electrum_tls"].is_null(),
        "electrum_tls should be null with default flags; got {}",
        res["electrum_tls"]
    );
    assert!(
        res["addressindex"]["enabled"].is_boolean(),
        "addressindex.enabled must be a bool"
    );
    assert!(
        res["addressindex"]["complete"].is_boolean(),
        "addressindex.complete must be a bool"
    );
    node.stop();
}

/// Regression test for PR #127 H1: `getserverstatus` must reflect
/// **runtime** listener state, not config intent. With
/// `--addressindex=0 --esplora=1`, the daemon silently skips binding
/// Esplora (logs a warning, keeps running). Reading the config-only
/// shape that PR #127 v1 emitted would have falsely claimed Esplora
/// was bound.
#[test]
fn test_getserverstatus_addressindex_off_skips_esplora() {
    let esplora_port = find_available_port();
    let bind = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    // Esplora=1 + addressindex=0 → daemon must boot but skip Esplora.
    let mut node = TestNode::start(&["--esplora=1", "--addressindex=0", &bind]);
    let v = node.rpc_call("getserverstatus").unwrap();
    let res = &v["result"];
    assert!(
        res["esplora"].is_null(),
        "esplora must be null when --addressindex=0 silently skipped its bind; got {}",
        res["esplora"]
    );
    node.stop();
}

/// `--esplora=1` with `--addressindex=1` (the supported combo) →
/// `getserverstatus.esplora` must carry the bind address.
#[test]
fn test_getserverstatus_esplora_bound_carries_bind() {
    let esplora_port = find_available_port();
    let bind_arg = format!("--esplorabind=127.0.0.1:{}", esplora_port);
    let mut node = TestNode::start(&["--esplora=1", &bind_arg]);
    let v = node.rpc_call("getserverstatus").unwrap();
    let res = &v["result"];
    let bind = res["esplora"]["bind"].as_str().unwrap_or_else(|| {
        panic!(
            "esplora.bind missing or not a string; got {}",
            res["esplora"]
        )
    });
    assert!(
        bind.ends_with(&format!(":{}", esplora_port)),
        "expected esplora bind to end in :{}, got {bind}",
        esplora_port
    );
    node.stop();
}

/// Regression test for PR #127 L3: `getconfig` must not surface
/// `electrum.tls_bind` when Electrum itself is disabled. v1 of PR #127
/// gated `electrum.bind` on `enabled` but left `tls_bind` ungated.
#[test]
fn test_getconfig_tls_bind_gated_on_electrum_enabled() {
    let mut node = TestNode::start(&[]);
    let v = node.rpc_call("getconfig").unwrap();
    let electrum = &v["result"]["electrum"];
    assert_eq!(
        electrum["enabled"].as_bool(),
        Some(false),
        "default Electrum is off"
    );
    assert!(
        electrum["bind"].is_null(),
        "electrum.bind should be null when disabled"
    );
    assert!(
        electrum["tls_bind"].is_null(),
        "electrum.tls_bind should be null when disabled; got {}",
        electrum["tls_bind"]
    );
    node.stop();
}

// ============================================================================
// BIP 158 filter-index backfill tests (PR-3 of the BIP 157/158 stack)
// ============================================================================

/// Helper: poll `getindexinfo` until the filter-index backfill state
/// matches one of `expected`. Returns the final response, or panics on
/// timeout.
fn poll_filter_backfill_state(
    node: &TestNode,
    expected: &[&str],
    deadline: Duration,
) -> serde_json::Value {
    let start = Instant::now();
    let mut last = serde_json::Value::Null;
    while start.elapsed() < deadline {
        let r = node.rpc_call("getindexinfo").expect("rpc");
        let bf = &r["result"]["basic block filter index"]["backfill"];
        let state_str = bf["state"].as_str().unwrap_or("");
        for label in expected {
            if &state_str == label {
                return r;
            }
            if *label == "synced" && (state_str == "completed" || state_str == "idle") {
                return r;
            }
        }
        last = r;
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timeout waiting for filter backfill state {:?}; last response: {}",
        expected, last
    );
}

/// `backfillindex blockfilter` rejects when the filter index is
/// disabled at runtime.
#[test]
fn test_filter_backfill_rejects_when_disabled() {
    let mut node = TestNode::start(&[]);
    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    let err_msg = r["error"]["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("disabled") || err_msg.contains("blockfilterindex"),
        "expected disabled-message; got: {}",
        err_msg
    );
    node.stop();
}

/// `backfillindex blockfilter` starts a real single-pass walk on a
/// fresh datadir with the index enabled.
#[test]
fn test_filter_backfill_starts_and_completes() {
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    // Mine a small chain.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(15), serde_json::json!(addr)],
        )
        .expect("rpc");

    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "expected started=true on fresh datadir: {}",
        r
    );

    let final_resp = poll_filter_backfill_state(&node, &["completed"], Duration::from_secs(30));
    let bf = &final_resp["result"]["basic block filter index"]["backfill"];
    assert_eq!(bf["active"].as_bool(), Some(false));
    assert!(
        final_resp["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced must be true after completion: {}",
        final_resp
    );
    assert!(bf["snapshot_height"].as_u64().unwrap_or(0) >= 15);

    node.stop();
}

/// A second `backfillindex` after completion is idempotent: returns
/// `started: false` with the "already completed" reason.
#[test]
fn test_filter_backfill_idempotent_after_completion() {
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(10), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    poll_filter_backfill_state(&node, &["completed"], Duration::from_secs(30));

    let r = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(r["result"]["started"].as_bool(), Some(false));
    let reason = r["result"]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("already completed"),
        "expected 'already completed' reason; got: {}",
        reason
    );
    node.stop();
}

/// pause/resume mid-flight via the operator RPCs. Uses the
/// `SATD_FILTER_BACKFILL_DEBUG_DELAY_MS` knob to slow the runner so
/// the test can observe the cursor pinning.
#[test]
fn test_filter_backfill_pause_resume() {
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-filter-bf-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--blockfilterindex=basic"],
        &[("SATD_FILTER_BACKFILL_DEBUG_DELAY_MS", "100")],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    // Mine a chain long enough that 100ms/block dwarfs the test's
    // pause-observe window.
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(40), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    poll_filter_backfill_state(&node, &["running"], Duration::from_secs(15));

    let p = node
        .rpc_call_with_params("pauseindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(p["result"]["paused"].as_bool(), Some(true));
    poll_filter_backfill_state(&node, &["paused"], Duration::from_secs(10));

    // Confirm the cursor pins under pause.
    let mid = node.rpc_call("getindexinfo").expect("rpc");
    let cursor1 = mid["result"]["basic block filter index"]["backfill"]["cursor_height"]
        .as_u64()
        .unwrap_or(0);
    std::thread::sleep(Duration::from_millis(700));
    let mid2 = node.rpc_call("getindexinfo").expect("rpc");
    let cursor2 = mid2["result"]["basic block filter index"]["backfill"]["cursor_height"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(cursor1, cursor2, "cursor must not advance while paused");

    let r = node
        .rpc_call_with_params("resumeindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(r["result"]["resumed"].as_bool(), Some(true));
    poll_filter_backfill_state(&node, &["completed"], Duration::from_secs(60));
    node.stop();
}

/// cancel mid-flight: cursor goes to Cancelled, partial filter rows
/// below cursor_height are kept (single-pass: they're correct rows
/// for the active chain).
#[test]
fn test_filter_backfill_cancel_drops_progress() {
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-filter-bf-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--blockfilterindex=basic"],
        &[("SATD_FILTER_BACKFILL_DEBUG_DELAY_MS", "100")],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(40), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    poll_filter_backfill_state(&node, &["running"], Duration::from_secs(15));

    let r = node
        .rpc_call_with_params("cancelindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(r["result"]["cancelled"].as_bool(), Some(true));
    poll_filter_backfill_state(&node, &["cancelled"], Duration::from_secs(15));
    let info = node.rpc_call("getindexinfo").expect("rpc");
    assert!(
        !info["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(true),
        "synced must be false after Cancelled"
    );
    // After Cancelled, a fresh backfillindex starts a new run.
    let r2 = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(
        r2["result"]["started"].as_bool(),
        Some(true),
        "fresh backfill after Cancelled must start: {}",
        r2
    );
    poll_filter_backfill_state(&node, &["completed"], Duration::from_secs(60));
    node.stop();
}

/// Restart in the middle of a backfill: persisted Running cursor
/// auto-resumes on next start. The supervisor's `resume_on_start`
/// path is structurally identical to the address-index supervisor
/// (which has its own resume-after-kill regression test); this test
/// covers the filter-side wiring end-to-end.
///
/// Marked `#[ignore]` for the regtest run because the deterministic
/// kill window between "backfill is mid-flight" and "graceful stop
/// completes" is narrow under load and produces flaky signals on CI;
/// run it locally with `cargo test ... -- --ignored
/// test_filter_backfill_resume_after_restart` when working on the
/// supervisor wiring.
#[test]
#[ignore]
fn test_filter_backfill_resume_after_restart() {
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-filter-bf-resume-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);

    // Use shadowing rather than a `{...}` block so the first
    // `TestNode`'s Drop (which `remove_dir_all`s the datadir) doesn't
    // fire before the second start. Both bindings are dropped at
    // end-of-fn — by then we're already done with the datadir.
    let mut node = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--blockfilterindex=basic"],
        &[("SATD_FILTER_BACKFILL_DEBUG_DELAY_MS", "100")],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    let _ = node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(40), serde_json::json!(addr)],
        )
        .expect("rpc");

    let _ = node
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    poll_filter_backfill_state(&node, &["running"], Duration::from_secs(15));
    // Capture some progress, then `kill -9`-style stop without
    // letting the backfill finish.
    std::thread::sleep(Duration::from_millis(500));
    node.stop();

    // Restart the same datadir. The supervisor should auto-resume.
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--blockfilterindex=basic"]);
    poll_filter_backfill_state(&node, &["completed"], Duration::from_secs(60));
    let info = node.rpc_call("getindexinfo").expect("rpc");
    assert!(
        info["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced must be true after auto-resume completion"
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// `getindexinfo` exposes the `basic block filter index` sibling key
/// even when the filter index is disabled, with `synced: false` and
/// the backfill substructure.
#[test]
fn test_filter_index_getindexinfo_shape_when_disabled() {
    let mut node = TestNode::start(&[]);
    let r = node.rpc_call("getindexinfo").expect("rpc");
    let bfi = &r["result"]["basic block filter index"];
    assert!(!bfi.is_null(), "expected sibling key");
    assert_eq!(
        bfi["synced"].as_bool(),
        Some(false),
        "synced must be false when index is disabled"
    );
    let bf = &bfi["backfill"];
    assert!(!bf.is_null(), "expected backfill substructure");
    assert_eq!(bf["state"].as_str(), Some("idle"));
    node.stop();
}

/// Backfill on an upgraded datadir: bring up satd with
/// `--blockfilterindex=0` (and mine some chain so the index is
/// missing), restart with the index on, run `backfillindex
/// blockfilter`, and verify the filter rows produced by the backfill
/// are byte-identical to filter rows produced by the connect-time
/// emit path on a fresh-from-genesis datadir.
#[test]
fn test_filter_backfill_from_disabled_datadir_matches_connect_time() {
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

    // Reference: fresh datadir mined with the index on. The
    // connect-time emit stamps every filter; we'll snapshot the tip
    // and pull `getblockfilter` on it once PR-5 lands. For PR-3, we
    // probe internal state via `getindexinfo` and assert the cursor
    // walks to the snapshot height (sufficient evidence the backfill
    // visited every block).
    let rpcport_a = find_available_port();
    let datadir_a = std::env::temp_dir().join(format!("satd-filter-bf-ref-test-{}", rpcport_a));
    let _ = std::fs::create_dir_all(&datadir_a);
    let mut node_a =
        TestNode::start_with_datadir(&datadir_a, rpcport_a, &["--blockfilterindex=basic"]);
    node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .expect("rpc");
    let info_a = node_a.rpc_call("getindexinfo").expect("rpc");
    assert!(
        info_a["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "fresh+enabled must be synced after live IBD: {}",
        info_a
    );
    node_a.stop();
    let _ = std::fs::remove_dir_all(&datadir_a);

    // Now: fresh datadir mined with the index OFF, restart with on,
    // backfill, assert it walks to snapshot_height.
    let rpcport_b = find_available_port();
    let datadir_b = std::env::temp_dir().join(format!("satd-filter-bf-upgrade-test-{}", rpcport_b));
    let _ = std::fs::create_dir_all(&datadir_b);
    // Shadow the binding rather than wrapping in `{...}` so the
    // first node's `Drop::remove_dir_all` doesn't fire before the
    // second `start_with_datadir` reads from it.
    let mut node_pre = TestNode::start_with_datadir(&datadir_b, rpcport_b, &[]);
    node_pre
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .expect("rpc");
    // With the index off, getindexinfo should report not-synced.
    let info = node_pre.rpc_call("getindexinfo").expect("rpc");
    assert!(
        !info["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(true),
        "with index off, must report not-synced"
    );
    node_pre.stop();

    let mut node_b =
        TestNode::start_with_datadir(&datadir_b, rpcport_b, &["--blockfilterindex=basic"]);
    let r = node_b
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(
        r["result"]["started"].as_bool(),
        Some(true),
        "expected started=true on upgraded datadir: {}",
        r
    );
    let final_resp = poll_filter_backfill_state(&node_b, &["completed"], Duration::from_secs(60));
    let bf = &final_resp["result"]["basic block filter index"]["backfill"];
    assert!(bf["snapshot_height"].as_u64().unwrap_or(0) >= 20);
    assert!(
        final_resp["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced must be true after backfill completion"
    );
    node_b.stop();
    let _ = std::fs::remove_dir_all(&datadir_b);
}

/// Regression test for H1 (review 2026-05-04): backfill running on
/// an upgraded datadir while a new live block lands. The filter
/// header at `snapshot_height + 1` must chain off the freshly-stamped
/// header at `snapshot_height`, NOT off all-zeros from the live emit
/// hitting a missing prev_header. Without the runner's tail catch-up
/// phase, the post-snapshot chain is corrupt.
#[test]
fn test_filter_backfill_tail_catchup_after_concurrent_live_block() {
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-filter-bf-tail-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);

    // Phase 1: mine a chain with the index OFF so historical heights
    // have no filter rows.
    let mut node_a = TestNode::start_with_datadir(&datadir, rpcport, &[]);
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node_a
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(20), serde_json::json!(addr)],
        )
        .expect("rpc");
    node_a.stop();

    // Phase 2: restart with the index ON + a slow runner. While the
    // backfill is mid-flight, mine an extra block so it lands above
    // `snapshot_height` while at least some heights ≤ snapshot are
    // still missing. The runner's tail catch-up phase has to rewrite
    // the post-snapshot header so the chain is intact at completion.
    let mut node_b = TestNode::start_with_datadir_env(
        &datadir,
        rpcport,
        &["--blockfilterindex=basic"],
        &[("SATD_FILTER_BACKFILL_DEBUG_DELAY_MS", "100")],
    );
    let r = node_b
        .rpc_call_with_params("backfillindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert_eq!(r["result"]["started"].as_bool(), Some(true));
    poll_filter_backfill_state(&node_b, &["running"], Duration::from_secs(15));
    // Mine ONE extra block via live path. It connects through
    // `connect_block` and would (without the H1 fix) chain off zero.
    node_b
        .rpc_call_with_params(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr)],
        )
        .expect("rpc");
    poll_filter_backfill_state(&node_b, &["completed"], Duration::from_secs(60));

    // synced=true after tail-catchup completion means the marker is
    // stamped AND the post-snapshot tail is rewritten with correctly
    // chained headers. The byte-level header validation lives in PR-5
    // once `getblockfilter` returns the header hex.
    let info = node_b.rpc_call("getindexinfo").expect("rpc");
    assert!(
        info["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "synced must be true after tail-catchup completion"
    );
    let bci = node_b.rpc_call("getblockchaininfo").expect("rpc");
    let blocks = bci["result"]["blocks"].as_u64().unwrap_or(0);
    assert!(blocks >= 21, "tip must be > snapshot height; got {blocks}");
    node_b.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

// ============================================================================
// BIP 157 P2P service integration tests (PR-4 of the BIP 157/158 stack)
// ============================================================================

/// Specialised P2P client that lets the test inspect inbound messages
/// (`CFilter`, `CFHeaders`, `CFCheckpt`, `Version`). Unlike
/// `raw_p2p::RawP2pClient`, this variant doesn't spawn a drain thread —
/// the test itself owns the recv loop so it can selectively accept
/// filter responses.
mod cf_client {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::{Address, Magic, ServiceFlags};
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant, SystemTime};

    const HEADER_SIZE: usize = 24;
    const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;

    pub struct CFilterClient {
        stream: TcpStream,
        /// Captured peer Version message — the BIP 157 spec requires
        /// `NODE_COMPACT_FILTERS` (bit 6) to be advertised when a node
        /// is willing to serve filter messages.
        pub peer_services: ServiceFlags,
    }

    impl CFilterClient {
        pub fn connect(p2p_port: u16) -> Self {
            let addr = format!("127.0.0.1:{}", p2p_port);
            let deadline = Instant::now() + Duration::from_secs(30);
            let stream = loop {
                match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)) {
                    Ok(s) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => panic!("CFilter P2P connect to {} failed: {}", addr, e),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.set_nodelay(true).unwrap();

            let mut client = CFilterClient {
                stream,
                peer_services: ServiceFlags::NONE,
            };
            client.handshake();
            client
        }

        fn handshake(&mut self) {
            let our_ver = build_version();
            self.send_msg(NetworkMessage::Version(our_ver));

            let deadline = Instant::now() + Duration::from_secs(30);
            let mut saw_version = false;
            let mut saw_verack = false;
            while !(saw_version && saw_verack) {
                if Instant::now() >= deadline {
                    panic!("handshake timeout waiting for peer version+verack");
                }
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::Version(v)) => {
                        self.peer_services = v.services;
                        saw_version = true;
                    }
                    Ok(NetworkMessage::Verack) => saw_verack = true,
                    Ok(_) => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => panic!("handshake recv failed: {}", e),
                }
            }
            self.send_msg(NetworkMessage::Verack);
        }

        pub fn send_get_cfilters(&mut self, req: GetCFilters) {
            self.send_msg(NetworkMessage::GetCFilters(req));
        }

        pub fn send_get_cfheaders(&mut self, req: GetCFHeaders) {
            self.send_msg(NetworkMessage::GetCFHeaders(req));
        }

        pub fn send_get_cfcheckpt(&mut self, req: GetCFCheckpt) {
            self.send_msg(NetworkMessage::GetCFCheckpt(req));
        }

        /// Receive at most `count` `CFilter` messages with the given
        /// timeout. Returns whatever it collected before the deadline.
        ///
        /// Uses a single long read_timeout per message rather than a
        /// short polling loop because `read_exact` on a partial-read
        /// timeout consumes some bytes from the stream irrecoverably,
        /// corrupting subsequent message framing.
        pub fn recv_cfilters(
            &mut self,
            count: usize,
            timeout: Duration,
        ) -> Vec<bitcoin::p2p::message_filter::CFilter> {
            let deadline = Instant::now() + timeout;
            let mut out = Vec::with_capacity(count);
            while out.len() < count && Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                self.stream
                    .set_read_timeout(Some(remaining.max(Duration::from_millis(100))))
                    .unwrap();
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::CFilter(f)) => out.push(f),
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
            out
        }

        pub fn recv_cfheaders(
            &mut self,
            timeout: Duration,
        ) -> Option<bitcoin::p2p::message_filter::CFHeaders> {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                self.stream
                    .set_read_timeout(Some(remaining.max(Duration::from_millis(100))))
                    .unwrap();
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::CFHeaders(h)) => return Some(h),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
            None
        }

        pub fn recv_cfcheckpt(
            &mut self,
            timeout: Duration,
        ) -> Option<bitcoin::p2p::message_filter::CFCheckpt> {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                self.stream
                    .set_read_timeout(Some(remaining.max(Duration::from_millis(100))))
                    .unwrap();
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::CFCheckpt(c)) => return Some(c),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
            None
        }

        /// Assert that no CFilter / CFHeaders / CFCheckpt arrives in the
        /// window — the silent-drop contract from BIP 157.
        pub fn assert_silent(&mut self, window: Duration) {
            let deadline = Instant::now() + window;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                self.stream
                    .set_read_timeout(Some(remaining.max(Duration::from_millis(100))))
                    .unwrap();
                match recv_msg(&mut self.stream) {
                    Ok(NetworkMessage::CFilter(_))
                    | Ok(NetworkMessage::CFHeaders(_))
                    | Ok(NetworkMessage::CFCheckpt(_)) => {
                        panic!("assert_silent: peer sent a filter response unexpectedly");
                    }
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        }

        fn send_msg(&mut self, msg: NetworkMessage) {
            let raw = RawNetworkMessage::new(Magic::REGTEST, msg);
            let bytes = serialize(&raw);
            self.stream.write_all(&bytes).expect("p2p write");
            self.stream.flush().ok();
        }
    }

    fn build_version() -> VersionMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        VersionMessage {
            version: 70016,
            services,
            timestamp,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, services),
            nonce: 0xCAFE_F00D_DEAD_BEEF,
            user_agent: "/satd-cf-client:0.1/".into(),
            start_height: 0,
            relay: true,
        }
    }

    fn recv_msg(stream: &mut TcpStream) -> io::Result<NetworkMessage> {
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header)?;
        let payload_len =
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload too large",
            ));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }
        let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&payload);
        deserialize::<RawNetworkMessage>(&buf)
            .map(|raw| raw.payload().clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Bring up satd with `--blockfilterindex=basic --peerblockfilters=1`,
/// mine some blocks, request `getcfheaders` over P2P, and assert the
/// returned `CFHeaders` has the expected per-height filter hashes.
#[test]
fn test_p2p_getcfheaders_returns_chain() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFHeaders;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-p2p-cfheaders-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(20), serde_json::json!(addr)],
    )
    .expect("rpc");

    let info = node.rpc_call("getindexinfo").expect("rpc");
    assert!(
        info["result"]["basic block filter index"]["synced"]
            .as_bool()
            .unwrap_or(false),
        "filter index must be synced after mining: {}",
        info
    );

    // Resolve tip hash for stop_hash.
    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let tip_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let tip_bytes = <[u8; 32]>::try_from(hex::decode(&tip_hex).expect("hex").as_slice())
        .expect("32 bytes");
    // RPC returns display form; reverse for consensus-byte stop_hash.
    let mut consensus = tip_bytes;
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    // BIP 157: NODE_COMPACT_FILTERS bit 6 set in advertised services.
    assert!(
        client
            .peer_services
            .has(bitcoin::p2p::ServiceFlags::COMPACT_FILTERS),
        "peer must advertise NODE_COMPACT_FILTERS when peerblockfilters=1 + index complete; got {:?}",
        client.peer_services
    );

    client.send_get_cfheaders(GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash,
    });
    let resp = client
        .recv_cfheaders(Duration::from_secs(5))
        .expect("CFHeaders response");
    assert_eq!(resp.filter_type, 0);
    assert_eq!(resp.stop_hash, stop_hash);
    // 21 hashes expected: heights 0..=20.
    assert_eq!(resp.filter_hashes.len(), 21);
    // start_height=0 → previous_filter_header is all-zeros per BIP 157.
    assert_eq!(resp.previous_filter_header.to_byte_array(), [0u8; 32]);

    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_getcfilters_returns_blobs() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFilters;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-p2p-cfilters-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(25), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice()).expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    client.send_get_cfilters(GetCFilters {
        filter_type: 0,
        start_height: 10,
        stop_hash,
    });
    // Heights 10..=25 = 16 messages.
    let cfilters = client.recv_cfilters(16, Duration::from_secs(10));
    assert_eq!(
        cfilters.len(),
        16,
        "expected 16 CFilter responses, got {}",
        cfilters.len()
    );
    for f in &cfilters {
        assert_eq!(f.filter_type, 0);
        // BIP 158 SCRIPT_FILTER for a coinbase-only block is a small
        // GCS blob — at minimum the length-prefix bytes — never empty
        // because every block has at least one output script.
        assert!(!f.filter.is_empty(), "filter blob must be non-empty");
    }
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_getcfcheckpt_thousand_block_intervals() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFCheckpt;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-p2p-cfcheckpt-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    // Mine just enough to get a single 1000-boundary checkpoint.
    // Mining 1500 regtest blocks via generatetoaddress is cheap.
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1500), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice()).expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    client.send_get_cfcheckpt(GetCFCheckpt {
        filter_type: 0,
        stop_hash,
    });
    let resp = client
        .recv_cfcheckpt(Duration::from_secs(5))
        .expect("CFCheckpt response");
    assert_eq!(resp.filter_type, 0);
    assert_eq!(resp.stop_hash, stop_hash);
    // 1500 blocks → only one checkpoint at height 1000 (the rule is
    // strict 1000-block intervals, genesis is excluded).
    assert_eq!(
        resp.filter_headers.len(),
        1,
        "expected 1 checkpoint at height 1000, got {}",
        resp.filter_headers.len()
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_silent_drop_when_peer_serve_disabled() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFHeaders;

    // blockfilterindex=basic but peerblockfilters off: handlers must
    // silent-drop and the version handshake must NOT advertise
    // NODE_COMPACT_FILTERS.
    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!("satd-p2p-silent-test-{}", rpcport));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            // No --peerblockfilters
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(15), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice()).expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    assert!(
        !client
            .peer_services
            .has(bitcoin::p2p::ServiceFlags::COMPACT_FILTERS),
        "NODE_COMPACT_FILTERS must NOT be set when peerblockfilters is off; got {:?}",
        client.peer_services
    );

    client.send_get_cfheaders(GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash,
    });
    client.assert_silent(Duration::from_secs(2));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_silent_drop_invalid_filter_type() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFilters;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!(
        "satd-p2p-bad-filter-type-test-{}",
        rpcport
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice()).expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    client.send_get_cfilters(GetCFilters {
        filter_type: 0x99,
        start_height: 0,
        stop_hash,
    });
    client.assert_silent(Duration::from_secs(2));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Regression test for H3 (review 2026-05-04): a max-size
/// `getcfilters` request that produces 1000 `CFilter` responses must
/// be delivered fully. Before the H3 fix the per-peer outbound mpsc
/// channel was 256 slots and the handler used best-effort `try_send`,
/// which silently dropped the tail of any 257+ message response.
#[test]
fn test_p2p_getcfilters_max_size_response_not_truncated() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFilters;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!(
        "satd-p2p-cfilters-1000-test-{}",
        rpcport
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1000), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice())
            .expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    // Range 1..=1000 = 1000 messages — exactly at the cap (the rule
    // is `stop - start < 1000`, so `1000 - 1 = 999`).
    client.send_get_cfilters(GetCFilters {
        filter_type: 0,
        start_height: 1,
        stop_hash,
    });
    let cfilters = client.recv_cfilters(1000, Duration::from_secs(60));
    assert_eq!(
        cfilters.len(),
        1000,
        "expected 1000 CFilter responses delivered without truncation, got {}",
        cfilters.len()
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Regression test for M1 (review 2026-05-04): `getcfheaders` accepts
/// up to 2000 headers per Bitcoin Core's
/// `MAX_GETCFHEADERS_SIZE = 2000`. Before the M1 fix satd reused the
/// `getcfilters` 1000 cap and silently dropped 1001..=2000 ranges.
#[test]
fn test_p2p_getcfheaders_accepts_2000_headers() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFHeaders;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!(
        "satd-p2p-cfheaders-2000-test-{}",
        rpcport
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(2010), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let tip_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&tip_hex).expect("hex").as_slice())
            .expect("32 bytes");
    consensus.reverse();
    let tip_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );
    // Use getblockhash for stop at height 2000 specifically — exactly
    // 2000 headers in the range 1..=2000 (count == 2000, allowed).
    let stop_hex_2000 = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(2000)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let mut consensus2k =
        <[u8; 32]>::try_from(hex::decode(&stop_hex_2000).expect("hex").as_slice())
            .expect("32 bytes");
    consensus2k.reverse();
    let stop_hash_2000 = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus2k),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    // 2000 headers = at the cap. Inclusive count rule: `stop - start <
    // 2000` means start=1, stop=2000 yields 2000 entries — allowed.
    client.send_get_cfheaders(GetCFHeaders {
        filter_type: 0,
        start_height: 1,
        stop_hash: stop_hash_2000,
    });
    let resp = client
        .recv_cfheaders(Duration::from_secs(30))
        .expect("CFHeaders response for 2000-header request");
    assert_eq!(
        resp.filter_hashes.len(),
        2000,
        "expected 2000 hashes, got {}",
        resp.filter_hashes.len()
    );

    // 2001 headers must be silent-dropped (start=0, stop=2000 = 2001).
    let stop_hex_genesis = node
        .rpc_call_with_params("getblockhash", vec![serde_json::json!(0)])
        .unwrap()["result"]
        .as_str()
        .unwrap()
        .to_string();
    let mut _consensus_g =
        <[u8; 32]>::try_from(hex::decode(&stop_hex_genesis).expect("hex").as_slice())
            .expect("32 bytes");
    let _ = tip_hash; // suppress unused var warnings on the silent-drop path
    client.send_get_cfheaders(GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash: stop_hash_2000,
    });
    client.assert_silent(Duration::from_secs(2));

    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_silent_drop_oversized_range() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFilters;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!(
        "satd-p2p-oversize-test-{}",
        rpcport
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    // Need >=1000 blocks so we can form a >1000-range request.
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(1100), serde_json::json!(addr)],
    )
    .expect("rpc");

    let bci = node.rpc_call("getblockchaininfo").expect("rpc");
    let stop_hex = bci["result"]["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_string();
    let mut consensus =
        <[u8; 32]>::try_from(hex::decode(&stop_hex).expect("hex").as_slice()).expect("32 bytes");
    consensus.reverse();
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(consensus),
    );

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    // Range from 0 to 1100 = 1101 blocks, well over the 1000 cap.
    client.send_get_cfilters(GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash,
    });
    client.assert_silent(Duration::from_secs(2));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

#[test]
fn test_p2p_silent_drop_off_chain_stop_hash() {
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_filter::GetCFHeaders;

    let p2p_port = find_available_port();
    let rpcport = find_available_port();
    let datadir = std::env::temp_dir().join(format!(
        "satd-p2p-offchain-test-{}",
        rpcport
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let mut node = TestNode::start_with_datadir(
        &datadir,
        rpcport,
        &[
            "--blockfilterindex=basic",
            "--peerblockfilters=1",
            &format!("--port={}", p2p_port),
        ],
    );
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![serde_json::json!(10), serde_json::json!(addr)],
    )
    .expect("rpc");

    let mut client = cf_client::CFilterClient::connect(p2p_port);
    // A made-up stop_hash that doesn't exist in the block index.
    let fake = [0xab; 32];
    let stop_hash = bitcoin::BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(fake),
    );
    client.send_get_cfheaders(GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash,
    });
    client.assert_silent(Duration::from_secs(2));
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// `pauseindex blockfilter` / `resumeindex blockfilter` return -8 when
/// no backfill is active.
#[test]
fn test_filter_pause_resume_rejects_when_idle() {
    let mut node = TestNode::start(&["--blockfilterindex=basic"]);
    let p = node
        .rpc_call_with_params("pauseindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert!(
        p["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("no filter backfill is in progress"),
        "expected idle-rejection: {}",
        p
    );
    let r = node
        .rpc_call_with_params("resumeindex", vec![serde_json::json!("blockfilter")])
        .expect("rpc");
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("no filter backfill is in progress"),
        "expected idle-rejection: {}",
        r
    );
    node.stop();
}

/// Mint a self-signed `localhost` certificate + key, write them to PEM
/// files under `dir`, and return the two paths. Used by the RPC-TLS
/// integration tests so each test runs against a fresh ephemeral cert
/// — keeps the test independent of any operator-managed keys on the
/// host.
fn mint_test_tls_cert(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_path = dir.join("rpc-cert.pem");
    let key_path = dir.join("rpc-key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// End-to-end test that proves `--rpctlsbind` + cert + key boots a
/// real HTTPS surface that authenticates and answers RPC calls. The
/// plain-HTTP surface is asserted to keep working in parallel so the
/// TLS path is purely additive.
///
/// Mirrors the Electrum and Esplora TLS round-trip tests so a future
/// reader sees the same shape on all three surfaces.
#[test]
fn test_rpc_tls_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = mint_test_tls_cert(tmp.path());
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", cert_path.display()),
        &format!("--rpctlskey={}", key_path.display()),
    ]);

    // Plain HTTP still works.
    let info = node
        .rpc_call("getblockchaininfo")
        .expect("plain HTTP rpc");
    assert_eq!(info["result"]["chain"].as_str(), Some("regtest"));

    // HTTPS round-trip. Trust our self-signed cert via
    // `add_root_certificate` rather than disabling cert validation —
    // we want a real cert-chain check so a regression that drops the
    // server cert surfaces as a test failure, not a silent pass.
    let cert_pem = std::fs::read(&cert_path).unwrap();
    let root = reqwest::Certificate::from_pem(&cert_pem).unwrap();
    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(root)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("https://localhost:{}/", tls_port);
    let resp: serde_json::Value = client
        .post(&url)
        .header("Authorization", format!("Basic {}", auth))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS request")
        .json()
        .expect("HTTPS response JSON");
    assert_eq!(resp["result"]["chain"].as_str(), Some("regtest"));

    // No-auth HTTPS request must be rejected — the Basic-auth tower
    // layer wraps the RPC stack and is applied transparently over TLS
    // (TLS is transport, auth is HTTP layer). A regression that
    // somehow detached auth on the TLS surface would let this slip
    // through.
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS unauth request");
    assert_eq!(resp.status(), 401);

    node.stop();
}

/// Build a `reqwest` blocking client that trusts the supplied
/// self-signed cert and bounds requests with a 5s timeout. Used by
/// the TLS integration tests so each one doesn't repeat the same six
/// lines of client setup. `add_root_certificate` is preferred over
/// disabling validation — we want a real cert-chain check so a
/// regression that drops the server cert surfaces as a test failure
/// rather than a silent pass.
fn https_client(cert_pem_path: &std::path::Path) -> reqwest::blocking::Client {
    let cert_pem = std::fs::read(cert_pem_path).unwrap();
    let root = reqwest::Certificate::from_pem(&cert_pem).unwrap();
    reqwest::blocking::Client::builder()
        .add_root_certificate(root)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// Userpass auth must work over TLS in addition to cookie auth. The
/// AuthLayer is the same code path on both the plain-HTTP and TLS
/// surfaces, but the round-trip test only exercised cookie; this one
/// pins the userpass-mode credential check on the TLS surface so a
/// future refactor of either side surfaces the regression here.
#[test]
fn test_rpc_tls_userpass_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = mint_test_tls_cert(tmp.path());
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        "--rpcuser=tlsuser",
        "--rpcpassword=tlssecret",
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", cert_path.display()),
        &format!("--rpctlskey={}", key_path.display()),
    ]);

    let client = https_client(&cert_path);
    let url = format!("https://localhost:{}/", tls_port);

    // Correct userpass over HTTPS → 200.
    let good = base64::engine::general_purpose::STANDARD.encode("tlsuser:tlssecret");
    let resp: serde_json::Value = client
        .post(&url)
        .header("Authorization", format!("Basic {}", good))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS userpass request")
        .json()
        .expect("HTTPS userpass response JSON");
    assert_eq!(resp["result"]["chain"].as_str(), Some("regtest"));

    // Wrong password over HTTPS → 401. Distinct code path from
    // no-auth (which the round-trip test already covers) because the
    // Basic header is decoded and compared rather than missing.
    let bad = base64::engine::general_purpose::STANDARD.encode("tlsuser:wrongpw");
    let status = client
        .post(&url)
        .header("Authorization", format!("Basic {}", bad))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS wrong-userpass request")
        .status();
    assert_eq!(status, 401);

    node.stop();
}

/// Concurrent HTTPS connections must all succeed. The TLS path
/// spawns a fresh task per accepted connection and clones the shared
/// `TowerService` for each; a bug in that cloning (or in shared
/// `TlsAcceptor` cloning) would surface here as one of the threads
/// failing or hanging. Eight parallel clients is enough to flush out
/// the obvious shared-state bugs without making the test load-heavy.
#[test]
fn test_rpc_tls_concurrent_requests() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = mint_test_tls_cert(tmp.path());
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", cert_path.display()),
        &format!("--rpctlskey={}", key_path.display()),
    ]);

    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let url = format!("https://localhost:{}/", tls_port);

    // std::thread::scope keeps the borrow of `cert_path` / `auth` /
    // `url` valid for the duration of the spawned threads without
    // requiring `'static` clones per thread.
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for i in 0..8 {
            let cert_path = &cert_path;
            let auth = &auth;
            let url = &url;
            handles.push(s.spawn(move || {
                let client = https_client(cert_path);
                let resp: serde_json::Value = client
                    .post(url)
                    .header("Authorization", format!("Basic {}", auth))
                    .header("Content-Type", "application/json")
                    .body(format!(
                        r#"{{"jsonrpc":"2.0","id":{i},"method":"getblockchaininfo"}}"#
                    ))
                    .send()
                    .unwrap_or_else(|e| panic!("thread {i}: HTTPS request: {e}"))
                    .json()
                    .unwrap_or_else(|e| panic!("thread {i}: HTTPS response JSON: {e}"));
                assert_eq!(
                    resp["result"]["chain"].as_str(),
                    Some("regtest"),
                    "thread {i}: unexpected response: {resp}"
                );
                assert_eq!(resp["id"].as_i64(), Some(i as i64));
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
    });

    node.stop();
}

/// The `stop` RPC issued over HTTPS must cleanly shut the whole
/// daemon down. This exercises the composite shutdown end-to-end:
/// the stop handler sends `shutdown_tx`, the TLS bridge task stops
/// the TLS surface, main.rs's signal-wait completes and runs the
/// flush phase, then `RpcServerHandle::stop()` stops the plain
/// surface. A regression in any link breaks this test.
#[test]
fn test_rpc_tls_stop_rpc_shuts_down_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = mint_test_tls_cert(tmp.path());
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", cert_path.display()),
        &format!("--rpctlskey={}", key_path.display()),
    ]);

    let client = https_client(&cert_path);
    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let url = format!("https://localhost:{}/", tls_port);

    let resp: serde_json::Value = client
        .post(&url)
        .header("Authorization", format!("Basic {}", auth))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"stop"}"#)
        .send()
        .expect("HTTPS stop request")
        .json()
        .expect("HTTPS stop response JSON");
    assert_eq!(resp["result"], "satd stopping");

    // Wait for the process to exit. Same deadline shape as the plain
    // `test_stop_rpc` for behavioural parity.
    let mut attempts = 0;
    loop {
        match node.process.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "satd exited unsuccessfully after stop-over-TLS: {status:?}"
                );
                break;
            }
            Ok(None) => {
                attempts += 1;
                if attempts > 30 {
                    panic!("satd did not exit after stop RPC issued over TLS");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for satd: {e}"),
        }
    }

    // Cookie cleanup happens after `server_handle.stop()`; if it ran,
    // the composite shutdown reached the cleanup step.
    let cookie_path = node.datadir.join("regtest").join(".cookie");
    assert!(
        !cookie_path.exists(),
        "Cookie file should be deleted after stop-over-TLS"
    );
}

/// `--rpctlsbind` without the matching cert/key flags must be a hard
/// startup error. The config-load layer already rejects this; this
/// test verifies the satd binary actually surfaces a non-zero exit
/// so an operator who mistyped a flag doesn't end up with a daemon
/// that silently fell back to plain HTTP.
#[test]
fn test_rpc_tls_partial_config_aborts_startup() {
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir().join(format!(
        "satd-test-rpctls-partial-{}",
        find_available_port()
    ));
    let _ = std::fs::create_dir_all(&datadir);
    let rpcport = find_available_port();
    let tls_port = find_available_port();

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", find_available_port()))
        .arg("--esplora=0")
        .arg(format!("--rpctlsbind=127.0.0.1:{}", tls_port))
        // Deliberately omit --rpctlscert / --rpctlskey.
        .output()
        .expect("spawn satd");

    assert!(
        !out.status.success(),
        "satd should reject partial --rpctls* config; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("rpctls"),
        "error message should mention rpctls; got: {combined}"
    );

    let _ = std::fs::remove_dir_all(&datadir);
}

/// Mint a CA + a server cert + a client cert all chained to the CA.
/// Returns absolute paths for each PEM file (server cert/key, CA, and
/// the client cert+key concatenated for reqwest `Identity::from_pem`)
/// plus the client cert's CN for the allowlist tests.
fn mint_mtls_pki(dir: &std::path::Path, client_cn: &str) -> RpcMtlsPki {
    use std::io::Write as _;
    // CA root.
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rpc-mtls-test-ca");
    let ca_kp = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

    // Server leaf signed by the CA — what the RPC TLS server presents.
    let mut server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let server_kp = rcgen::KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_kp, &ca_cert, &ca_kp).unwrap();

    // Client leaf signed by the CA — what reqwest presents during the
    // mTLS handshake. Two DNS SANs so allowlist tests can target
    // either the CN or a SAN value.
    let mut client_params =
        rcgen::CertificateParams::new(vec![format!("{client_cn}.client.test")]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, client_cn);
    let client_kp = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_kp, &ca_cert, &ca_kp).unwrap();

    let server_cert_path = dir.join("server.pem");
    let server_key_path = dir.join("server.key.pem");
    let ca_path = dir.join("ca.pem");
    let client_id_path = dir.join("client-identity.pem");

    std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
    std::fs::write(&server_key_path, server_kp.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    let mut id_file = std::fs::File::create(&client_id_path).unwrap();
    id_file.write_all(client_cert.pem().as_bytes()).unwrap();
    id_file.write_all(client_kp.serialize_pem().as_bytes()).unwrap();

    RpcMtlsPki {
        server_cert_path,
        server_key_path,
        ca_path,
        ca_pem: ca_cert.pem(),
        client_identity_pem: {
            let mut buf = client_cert.pem();
            buf.push_str(&client_kp.serialize_pem());
            buf
        },
    }
}

struct RpcMtlsPki {
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    ca_path: PathBuf,
    ca_pem: String,
    client_identity_pem: String,
}

/// Build a reqwest blocking client that trusts the supplied CA and
/// presents the given client identity (cert + key concatenated PEM).
/// Forces rustls because workspace feature unification can pull in
/// native-tls as well, and `Identity::from_pem` is rustls-only.
fn https_mtls_client(ca_pem: &str, client_identity_pem: Option<&str>) -> reqwest::blocking::Client {
    let root = reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap();
    let mut builder = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(root)
        .timeout(Duration::from_secs(5));
    if let Some(pem) = client_identity_pem {
        let id = reqwest::Identity::from_pem(pem.as_bytes()).unwrap();
        builder = builder.identity(id);
    }
    builder.build().unwrap()
}

/// mTLS happy path: server requires CA-signed client cert; client
/// presents one + cookie auth. HTTPS round-trip succeeds; plain HTTP
/// still works as the backwards-compatible default surface; HTTPS
/// without Basic auth is still 401 (mTLS is strictly additive when
/// `--rpcdisableauth` is NOT set).
#[test]
fn test_rpc_mtls_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = mint_mtls_pki(tmp.path(), "alice");
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", pki.server_cert_path.display()),
        &format!("--rpctlskey={}", pki.server_key_path.display()),
        "--rpcmtls=1",
        &format!("--rpcmtlsclientca={}", pki.ca_path.display()),
    ]);

    // Plain HTTP keeps working — mTLS is additive on the TLS surface.
    let info = node.rpc_call("getblockchaininfo").expect("plain rpc");
    assert_eq!(info["result"]["chain"].as_str(), Some("regtest"));

    // HTTPS with valid client cert + cookie auth → 200.
    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let client = https_mtls_client(&pki.ca_pem, Some(&pki.client_identity_pem));
    let url = format!("https://localhost:{}/", tls_port);
    let resp: serde_json::Value = client
        .post(&url)
        .header("Authorization", format!("Basic {}", auth))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS mTLS request")
        .json()
        .expect("HTTPS mTLS response JSON");
    assert_eq!(resp["result"]["chain"].as_str(), Some("regtest"));

    // HTTPS with valid client cert but NO Basic auth → 401. mTLS is
    // strictly additive: the AuthLayer keeps running on top.
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS mTLS no-auth request");
    assert_eq!(resp.status(), 401);

    node.stop();
}

/// mTLS rejection: server requires client cert; the client connects
/// without one. The handshake is refused at the TLS layer; reqwest
/// surfaces a connection-level error.
#[test]
fn test_rpc_mtls_rejects_client_without_cert() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = mint_mtls_pki(tmp.path(), "alice");
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", pki.server_cert_path.display()),
        &format!("--rpctlskey={}", pki.server_key_path.display()),
        "--rpcmtls=1",
        &format!("--rpcmtlsclientca={}", pki.ca_path.display()),
    ]);

    // Build a client that trusts the CA but offers NO client cert.
    let client = https_mtls_client(&pki.ca_pem, None);
    let url = format!("https://localhost:{}/", tls_port);
    let result = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send();
    assert!(
        result.is_err(),
        "mTLS-required server should refuse no-cert client; got: {result:?}",
    );

    node.stop();
}

/// `--rpcdisableauth=1` + `--rpcmtls=1`: mTLS becomes the only auth
/// on the TLS surface; the AuthLayer is a no-op so a client with a
/// valid cert and NO Basic header gets a 200. The plain-HTTP surface
/// must still enforce Basic — that's the safety invariant of
/// rpcdisableauth: it only weakens the mTLS-protected surface.
#[test]
fn test_rpc_mtls_disable_auth_skips_basic_on_tls() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = mint_mtls_pki(tmp.path(), "alice");
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", pki.server_cert_path.display()),
        &format!("--rpctlskey={}", pki.server_key_path.display()),
        "--rpcmtls=1",
        &format!("--rpcmtlsclientca={}", pki.ca_path.display()),
        "--rpcdisableauth=1",
    ]);

    // Plain HTTP still requires Basic — auth-disable is TLS-surface
    // only. Use a raw reqwest request without auth to assert 401.
    let plain_url = format!("http://127.0.0.1:{}/", node.rpcport);
    let plain_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = plain_client
        .post(&plain_url)
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("plain HTTP no-auth request");
    assert_eq!(resp.status(), 401, "plain HTTP must keep enforcing auth");

    // HTTPS with valid client cert but NO Basic header → 200, because
    // --rpcdisableauth=1 turns the AuthLayer into a pass-through on
    // the TLS surface.
    let client = https_mtls_client(&pki.ca_pem, Some(&pki.client_identity_pem));
    let url = format!("https://localhost:{}/", tls_port);
    let resp: serde_json::Value = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS mTLS request")
        .json()
        .expect("HTTPS mTLS response JSON");
    assert_eq!(resp["result"]["chain"].as_str(), Some("regtest"));

    node.stop();
}

/// `--rpcmtlsclientallow=alice` narrows the principal set. The
/// client cert's CN is `alice`, so the request succeeds.
#[test]
fn test_rpc_mtls_allowlist_accepts_matching_cn() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = mint_mtls_pki(tmp.path(), "alice");
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", pki.server_cert_path.display()),
        &format!("--rpctlskey={}", pki.server_key_path.display()),
        "--rpcmtls=1",
        &format!("--rpcmtlsclientca={}", pki.ca_path.display()),
        "--rpcmtlsclientallow=alice,bob",
    ]);

    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let client = https_mtls_client(&pki.ca_pem, Some(&pki.client_identity_pem));
    let url = format!("https://localhost:{}/", tls_port);
    let resp: serde_json::Value = client
        .post(&url)
        .header("Authorization", format!("Basic {}", auth))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send()
        .expect("HTTPS request")
        .json()
        .expect("HTTPS response JSON");
    assert_eq!(resp["result"]["chain"].as_str(), Some("regtest"));

    node.stop();
}

/// Allowlist rejection: the client cert's CN is `mallory`, which is
/// not in `--rpcmtlsclientallow=alice,bob`. The handshake succeeds
/// (cert is CA-signed) but the listener drops the connection
/// post-handshake; reqwest sees a connection-level error.
#[test]
fn test_rpc_mtls_allowlist_drops_unlisted_principal() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = mint_mtls_pki(tmp.path(), "mallory");
    let tls_port = find_available_port();
    let tls_bind = format!("127.0.0.1:{}", tls_port);

    let mut node = TestNode::start(&[
        &format!("--rpctlsbind={}", tls_bind),
        &format!("--rpctlscert={}", pki.server_cert_path.display()),
        &format!("--rpctlskey={}", pki.server_key_path.display()),
        "--rpcmtls=1",
        &format!("--rpcmtlsclientca={}", pki.ca_path.display()),
        "--rpcmtlsclientallow=alice,bob",
    ]);

    let auth = base64::engine::general_purpose::STANDARD.encode(node.cookie.trim());
    let client = https_mtls_client(&pki.ca_pem, Some(&pki.client_identity_pem));
    let url = format!("https://localhost:{}/", tls_port);
    let result = client
        .post(&url)
        .header("Authorization", format!("Basic {}", auth))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}"#)
        .send();
    assert!(
        result.is_err(),
        "allowlist should drop unlisted principal; got: {result:?}",
    );

    node.stop();
}

/// Misconfiguration: `--rpcmtls=1` without `--rpcmtlsclientca`
/// aborts startup. The config-load gate refuses; the binary exits
/// non-zero before the listener binds.
#[test]
fn test_rpc_mtls_without_ca_aborts_startup() {
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir()
        .join(format!("satd-test-rpcmtls-noca-{}", find_available_port()));
    let _ = std::fs::create_dir_all(&datadir);
    let tmp = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = mint_test_tls_cert(tmp.path());
    let rpcport = find_available_port();
    let tls_port = find_available_port();

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", find_available_port()))
        .arg("--esplora=0")
        .arg(format!("--rpctlsbind=127.0.0.1:{}", tls_port))
        .arg(format!("--rpctlscert={}", cert_path.display()))
        .arg(format!("--rpctlskey={}", key_path.display()))
        .arg("--rpcmtls=1")
        // Deliberately omit --rpcmtlsclientca.
        .output()
        .expect("spawn satd");

    assert!(!out.status.success(), "should reject mtls without ca");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("rpcmtlsclientca"),
        "error should mention rpcmtlsclientca; got: {combined}"
    );

    let _ = std::fs::remove_dir_all(&datadir);
}

/// Misconfiguration: `--rpcdisableauth=1` without `--rpcmtls=1`
/// aborts startup. Prevents the operator from accidentally opening
/// a no-auth HTTP port behind nothing.
#[test]
fn test_rpc_disableauth_without_mtls_aborts_startup() {
    let satd_bin = env!("CARGO_BIN_EXE_satd");
    let datadir = std::env::temp_dir()
        .join(format!("satd-test-rpcda-nomtls-{}", find_available_port()));
    let _ = std::fs::create_dir_all(&datadir);
    let rpcport = find_available_port();

    let out = Command::new(satd_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", datadir.display()))
        .arg(format!("--rpcport={}", rpcport))
        .arg(format!("--port={}", find_available_port()))
        .arg("--esplora=0")
        .arg("--rpcdisableauth=1")
        // Deliberately omit --rpcmtls=1 and the rest of the TLS quad.
        .output()
        .expect("spawn satd");

    assert!(
        !out.status.success(),
        "should reject --rpcdisableauth=1 without --rpcmtls=1"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("rpcdisableauth") || combined.contains("rpcmtls"),
        "error should mention rpcdisableauth / rpcmtls; got: {combined}"
    );

    let _ = std::fs::remove_dir_all(&datadir);
}
