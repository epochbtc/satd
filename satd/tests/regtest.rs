use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct TestNode {
    process: Child,
    datadir: PathBuf,
    rpcport: u16,
    cookie: String,
}

impl TestNode {
    fn start(extra_args: &[&str]) -> Self {
        let rpcport = find_available_port();
        let datadir = std::env::temp_dir().join(format!("satd-test-{}", rpcport));
        let _ = std::fs::create_dir_all(&datadir);

        let satd_bin = env!("CARGO_BIN_EXE_satd");

        let mut cmd = Command::new(satd_bin);
        cmd.arg("--regtest")
            .arg(format!("--datadir={}", datadir.display()))
            .arg(format!("--rpcport={}", rpcport));
        for arg in extra_args {
            cmd.arg(arg);
        }

        let process = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start satd");

        // Check if using user/pass auth (no cookie file expected)
        let uses_userpass = extra_args.iter().any(|a| a.starts_with("--rpcuser"));

        let cookie = if uses_userpass {
            // Wait for server to be ready by polling the port
            let mut attempts = 0;
            loop {
                if std::net::TcpStream::connect(format!("127.0.0.1:{}", rpcport)).is_ok() {
                    break;
                }
                attempts += 1;
                if attempts > 50 {
                    panic!("Timed out waiting for satd to start on port {}", rpcport);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            String::new()
        } else {
            // Wait for cookie file to appear
            let cookie_path = datadir.join("regtest").join(".cookie");
            let mut attempts = 0;
            loop {
                if cookie_path.exists() {
                    break;
                }
                attempts += 1;
                if attempts > 50 {
                    panic!(
                        "Timed out waiting for cookie file at {}",
                        cookie_path.display()
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            std::fs::read_to_string(&cookie_path).expect("Failed to read cookie file")
        };

        TestNode {
            process,
            datadir,
            rpcport,
            cookie,
        }
    }

    fn rpc_call(&self, method: &str) -> Result<serde_json::Value, String> {
        self.rpc_call_with_params(method, vec![])
    }

    fn rpc_call_with_params(
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

        let client = reqwest::blocking::Client::new();
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

    fn rpc_call_raw_status(&self, method: &str, user: &str, pass: &str) -> u16 {
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

    fn stop(&mut self) {
        if !self.cookie.is_empty() {
            let _ = self.rpc_call("stop");
        }
        // Wait for process to exit, kill if it doesn't
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

fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

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
    assert!(!cookie_path.exists(), "Cookie file should be deleted after stop");
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
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("Output should be valid JSON");

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
    assert!(!cookie_path.exists(), "Cookie file should not exist with user/pass auth");

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

/// Poll a condition until it returns true, or panic after timeout.
fn poll_until(check: impl Fn() -> bool, timeout: Duration, msg: &str) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("poll_until timed out after {:?}: {}", timeout, msg);
}

fn get_rpc_u64(node: &TestNode, method: &str) -> Option<u64> {
    node.rpc_call(method)
        .ok()
        .and_then(|r| r["result"].as_u64())
}

fn get_rpc_str(node: &TestNode, method: &str) -> Option<String> {
    node.rpc_call(method)
        .ok()
        .and_then(|r| r["result"].as_str().map(|s| s.to_string()))
}

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
        .rpc_call_with_params(
            "testmempoolaccept",
            vec![serde_json::json!(["deadbeef"])],
        )
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
        .rpc_call_with_params(
            "decodescript",
            vec![serde_json::json!("51")],
        )
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
            vec![serde_json::json!("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")],
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
