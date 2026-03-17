use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

struct TestNode {
    process: Child,
    datadir: PathBuf,
    rpcport: u16,
    cookie: String,
}

impl TestNode {
    fn start(extra_args: &[&str]) -> Self {
        let rpcport = find_available_port();
        let datadir = std::env::temp_dir().join(format!("btcd-test-{}", rpcport));
        let _ = std::fs::create_dir_all(&datadir);

        let btcd_bin = env!("CARGO_BIN_EXE_btcd");

        let mut cmd = Command::new(btcd_bin);
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
            .expect("Failed to start btcd");

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
                    panic!("Timed out waiting for btcd to start on port {}", rpcport);
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

    assert_eq!(result["subversion"], "/btcd:0.1.0/");
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
    assert_eq!(response["result"], "btcd stopping");

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
                    panic!("btcd did not exit after stop RPC");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("Error waiting for btcd: {}", e),
        }
    }

    // Verify cookie file was cleaned up
    let cookie_path = node.datadir.join("regtest").join(".cookie");
    assert!(!cookie_path.exists(), "Cookie file should be deleted after stop");
}

#[test]
fn test_btc_cli_integration() {
    let mut node = TestNode::start(&[]);

    // btc-cli is in a sibling crate; find it relative to the btcd binary
    let btcd_bin = env!("CARGO_BIN_EXE_btcd");
    let btc_cli_bin = std::path::Path::new(btcd_bin)
        .parent()
        .unwrap()
        .join("btc-cli");
    let btc_cli_bin = btc_cli_bin.to_str().unwrap();

    let output = Command::new(btc_cli_bin)
        .arg("--regtest")
        .arg(format!("--datadir={}", node.datadir.display()))
        .arg(format!("--rpcport={}", node.rpcport))
        .arg("getblockchaininfo")
        .output()
        .expect("Failed to run btc-cli");

    assert!(output.status.success(), "btc-cli should exit successfully");

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
