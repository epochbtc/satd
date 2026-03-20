use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::path::{Path, PathBuf};

/// RPC client for communicating with satd.
pub struct RpcClient {
    url: String,
    auth_header: String,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(host: &str, port: u16, user: &str, pass: &str) -> Self {
        let auth_header = format!("Basic {}", BASE64.encode(format!("{}:{}", user, pass)));
        Self {
            url: format!("http://{}:{}/", host, port),
            auth_header,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    pub async fn call(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, RpcError> {
        self.call_with(&self.client, method, params).await
    }

    async fn call_with(&self, client: &reqwest::Client, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "sat-tui",
            "method": method,
            "params": params,
        });

        let response = client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", &self.auth_header)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() || e.is_request() {
                    RpcError::ConnectionFailed
                } else if e.is_timeout() {
                    RpcError::Timeout
                } else {
                    RpcError::Request(e.to_string())
                }
            })?;

        if response.status().as_u16() == 401 {
            return Err(RpcError::AuthFailed);
        }

        let resp: serde_json::Value = response.json().await
            .map_err(|e| RpcError::Request(e.to_string()))?;

        if let Some(error) = resp.get("error").filter(|e| !e.is_null()) {
            let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            return Err(RpcError::Rpc(msg.to_string()));
        }

        Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    // Convenience methods for each RPC we need

    pub async fn get_blockchain_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getblockchaininfo", &[]).await
    }

    pub async fn get_peer_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getpeerinfo", &[]).await
    }

    pub async fn get_mempool_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getmempoolinfo", &[]).await
    }

    pub async fn get_connection_count(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getconnectioncount", &[]).await
    }

    pub async fn get_ibd_progress(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getibdprogress", &[]).await
    }

    pub async fn get_mining_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getmininginfo", &[]).await
    }

    pub async fn get_chain_tx_stats(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getchaintxstats", &[]).await
    }

    pub async fn get_uptime(&self) -> Result<serde_json::Value, RpcError> {
        self.call("uptime", &[]).await
    }

    pub async fn estimate_smart_fee(&self, target: u32) -> Result<serde_json::Value, RpcError> {
        self.call("estimatesmartfee", &[serde_json::json!(target)]).await
    }

    pub async fn get_block_stats(&self, height: u32) -> Result<serde_json::Value, RpcError> {
        self.call("getblockstats", &[serde_json::json!(height.to_string())]).await
    }

    pub async fn get_raw_mempool_verbose(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getrawmempool", &[serde_json::json!(true)]).await
    }

    pub async fn get_tx_out_set_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("gettxoutsetinfo", &[]).await
    }
}

#[derive(Debug)]
pub enum RpcError {
    ConnectionFailed,
    AuthFailed,
    Timeout,
    Request(String),
    Rpc(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ConnectionFailed => write!(f, "Connection failed"),
            RpcError::AuthFailed => write!(f, "Authentication failed"),
            RpcError::Timeout => write!(f, "Request timed out"),
            RpcError::Request(e) => write!(f, "Request error: {}", e),
            RpcError::Rpc(e) => write!(f, "RPC error: {}", e),
        }
    }
}

/// Read cookie file and return (user, pass).
pub fn read_cookie_file(path: &Path) -> Result<(String, String), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read cookie file: {}", e))?;
    let (user, pass) = content
        .trim()
        .split_once(':')
        .ok_or_else(|| "Invalid cookie file format".to_string())?;
    Ok((user.to_string(), pass.to_string()))
}

/// Default datadir (~/.bitcoin).
pub fn default_datadir() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".bitcoin"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/.bitcoin"))
}
