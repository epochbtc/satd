//! The read-only MCP profile over the real HTTP transport.
//!
//! Each test starts `serve_http` with `-mcpauth` semantics (a token table)
//! and talks to it as an MCP client would: `initialize`, then `tools/list`
//! and `tools/call` over streamable HTTP. Three tokens: `mcp:*`, `mcp:read`,
//! and `rpc:read` (no MCP at all).

use std::net::SocketAddr;
use std::sync::Arc;

use bitcoin::Network;
use node::chain::state::{AssumeValid, ChainState};
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::net::manager::PeerManager;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::NoopVerifier;
use satd_mcp::McpContext;
use satd_mcp::profile::{FULL_ONLY_TOOLS, READ_TOOLS};
use serde_json::{Value, json};

const FULL_TOKEN: &str = "full-token-0123456789";
const READ_TOKEN: &str = "read-token-0123456789";
const RPC_TOKEN: &str = "rpc-token-0123456789";
const PROTOCOL: &str = "2025-06-18";

fn make_ctx(dir: &std::path::Path) -> McpContext {
    let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let peer_manager = PeerManager::new(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        Network::Regtest,
        shutdown_rx,
    );
    McpContext {
        chain_state,
        mempool,
        peer_manager,
        fee_estimator,
        start_time: std::time::Instant::now(),
        network: Network::Regtest,
        effective_config: json!({"network": "regtest"}),
        mempool_history: None,
        addr_enabled: false,
        sp_enabled: false,
        filter_enabled: false,
        addr_subs: None,
        health: None,
        webhooks: None,
        shutdown: None,
    }
}

fn token_entry(id: &str, token: &str, caps: &str) -> String {
    let hash: String = satd_auth::token_digest(token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("[[token]]\nid = \"{id}\"\nhash = \"sha256:{hash}\"\ncapabilities = [{caps}]\n")
}

/// A running MCP server with the three tokens, and what keeps it alive.
struct Server {
    url: String,
    _dir: tempfile::TempDir,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

async fn start() -> Server {
    let dir = tempfile::TempDir::new().unwrap();
    let authfile = dir.path().join("auth.toml");
    std::fs::write(
        &authfile,
        format!(
            "version = 1\n{}{}{}",
            token_entry("full", FULL_TOKEN, "\"mcp:*\""),
            token_entry("read", READ_TOKEN, "\"mcp:read\""),
            token_entry("rpc", RPC_TOKEN, "\"rpc:read\""),
        ),
    )
    .unwrap();
    // The store refuses a token file others can read.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&authfile, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Arc::new(satd_auth::TokenStore::load(&authfile).unwrap());
    let ctx = Arc::new(make_ctx(dir.path()));
    let addr: SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        satd_mcp::serve_http(ctx, addr, Some(store), None, &[], rx)
            .await
            .unwrap();
    });
    let url = format!("http://{addr}/mcp");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Server {
        url,
        _dir: dir,
        _shutdown: tx,
    }
}

/// The JSON-RPC message answering `id`, from a JSON or an SSE body.
fn answer(body: &str, id: u64) -> Option<Value> {
    let candidates: Vec<&str> = if body.trim_start().starts_with('{') {
        vec![body]
    } else {
        body.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .collect()
    };
    candidates
        .into_iter()
        .filter_map(|c| serde_json::from_str::<Value>(c).ok())
        .find(|v| v["id"] == json!(id))
}

/// An MCP client session under one bearer token.
struct Client {
    http: reqwest::Client,
    url: String,
    token: String,
    session: Option<String>,
    next_id: u64,
}

impl Client {
    async fn post(&self, body: Value) -> reqwest::Response {
        let mut req = self
            .http
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body);
        if let Some(s) = &self.session {
            req = req
                .header("Mcp-Session-Id", s)
                .header("MCP-Protocol-Version", PROTOCOL);
        }
        req.send().await.unwrap()
    }

    /// Open a session. Returns the HTTP status of `initialize`.
    async fn connect(server: &Server, token: &str) -> (Self, u16) {
        let mut c = Client {
            http: reqwest::Client::new(),
            url: server.url.clone(),
            token: token.to_owned(),
            session: None,
            next_id: 1,
        };
        let r = c
            .post(
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": PROTOCOL, "capabilities": {},
                "clientInfo": {"name": "profile-test", "version": "1"}}}),
            )
            .await;
        let status = r.status().as_u16();
        c.session = r
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = r.text().await;
        if status == 200 {
            let r = c
                .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .await;
            assert!(r.status().is_success(), "initialized: {}", r.status());
        }
        (c, status)
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let r = self
            .post(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let status = r.status();
        let body = r.text().await.unwrap();
        answer(&body, id).unwrap_or_else(|| panic!("{method}: no answer ({status}): {body}"))
    }

    async fn tool_names(&mut self) -> Vec<String> {
        let v = self.request("tools/list", json!({})).await;
        v["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list: {v}"))
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn call(&mut self, tool: &str, args: Value) -> Value {
        self.request("tools/call", json!({"name": tool, "arguments": args}))
            .await
    }
}

fn is_not_found(answer: &Value) -> bool {
    answer["error"]["message"] == "tool not found"
}

#[tokio::test]
async fn a_read_token_lists_exactly_the_read_tools() {
    let server = start().await;
    let (mut read, status) = Client::connect(&server, READ_TOKEN).await;
    assert_eq!(status, 200);
    let mut listed = read.tool_names().await;
    listed.sort();
    let mut want: Vec<String> = READ_TOOLS.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(listed, want);

    // The wildcard token sees every tool, the withheld ones included.
    let (mut full, _) = Client::connect(&server, FULL_TOKEN).await;
    let all = full.tool_names().await;
    assert_eq!(all.len(), READ_TOOLS.len() + FULL_ONLY_TOOLS.len());
    for t in FULL_ONLY_TOOLS {
        assert!(all.iter().any(|a| a == t), "{t} missing for mcp:*");
    }
}

#[tokio::test]
async fn a_read_token_calls_a_read_tool() {
    let server = start().await;
    let (mut read, _) = Client::connect(&server, READ_TOKEN).await;
    let v = read.call("get_health", json!({})).await;
    assert!(v["error"].is_null(), "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("ok"), "{v}");
    let v = read
        .call("get_block_header", json!({"identifier": "0"}))
        .await;
    assert!(
        v["error"].is_null() && v["result"]["isError"] != json!(true),
        "{v}"
    );
}

#[tokio::test]
async fn a_token_without_mcp_is_refused_at_the_door() {
    let server = start().await;
    let (_, status) = Client::connect(&server, RPC_TOKEN).await;
    assert_eq!(status, 401);
    let (_, status) = Client::connect(&server, "not-a-token").await;
    assert_eq!(status, 401);
}

/// One withheld tool: the read token is told it does not exist, the same
/// answer as for a name no tool has; the wildcard token, sending the same
/// call, reaches the tool (empty arguments, so it stops at its argument
/// check and does nothing).
async fn withheld(tool: &str) {
    assert!(FULL_ONLY_TOOLS.contains(&tool), "{tool} is not withheld");
    let server = start().await;
    let (mut read, _) = Client::connect(&server, READ_TOKEN).await;
    let refused = read.call(tool, json!({})).await;
    assert!(is_not_found(&refused), "mcp:read reached {tool}: {refused}");
    let unknown = read.call("no_such_tool", json!({})).await;
    assert_eq!(
        refused["error"], unknown["error"],
        "a withheld tool must look absent"
    );

    let (mut full, _) = Client::connect(&server, FULL_TOKEN).await;
    let reached = full.call(tool, json!({})).await;
    assert!(
        !is_not_found(&reached),
        "mcp:* could not reach {tool}: {reached}"
    );
}

macro_rules! withheld_tests {
    ($($name:ident => $tool:literal,)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                withheld($tool).await;
            }
        )*

        #[test]
        fn every_withheld_tool_has_a_named_test() {
            let tested = [$($tool),*];
            for t in FULL_ONLY_TOOLS {
                assert!(tested.contains(t), "{t} has no read_token_cannot_call_* test");
            }
        }
    };
}

withheld_tests! {
    read_token_cannot_call_sign_transaction => "sign_transaction",
    read_token_cannot_call_send_transaction => "send_transaction",
    read_token_cannot_call_generate_blocks => "generate_blocks",
    read_token_cannot_call_manage_peer => "manage_peer",
    read_token_cannot_call_get_peer_info => "get_peer_info",
    read_token_cannot_call_get_ban_list => "get_ban_list",
    read_token_cannot_call_get_config => "get_config",
    read_token_cannot_call_get_policy_info => "get_policy_info",
    read_token_cannot_call_get_system_info => "get_system_info",
    read_token_cannot_call_get_metrics_snapshot => "get_metrics_snapshot",
    read_token_cannot_call_get_utxo_set_stats => "get_utxo_set_stats",
    read_token_cannot_call_get_block_template => "get_block_template",
}
