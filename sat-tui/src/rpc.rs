use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::path::{Path, PathBuf};

/// RPC client for communicating with satd.
/// Automatically re-reads the cookie file on auth failure (handles satd restarts).
pub struct RpcClient {
    url: String,
    auth_header: parking_lot::RwLock<String>,
    cookie_path: Option<PathBuf>,
    /// The most recent cookie-file *read* failure, if the cookie is
    /// currently unreadable (permission denied, missing, malformed).
    /// `None` when authenticating with `--rpcuser`/`--rpcpassword`, or
    /// when the cookie last read successfully. A cookie that can't be read
    /// is the root cause of every downstream 401, so we keep the specific
    /// error here and surface it instead of the generic "auth failed" — see
    /// `RpcClient::cookie_error`.
    cookie_error: parking_lot::RwLock<Option<String>>,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(host: &str, port: u16, user: &str, pass: &str) -> Self {
        let auth_header = format!("Basic {}", BASE64.encode(format!("{}:{}", user, pass)));
        Self {
            url: format!("http://{}:{}/", host, port),
            auth_header: parking_lot::RwLock::new(auth_header),
            cookie_path: None,
            cookie_error: parking_lot::RwLock::new(None),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Create with cookie file path for automatic re-auth on satd restart.
    ///
    /// A cookie that can't be read at construction is recorded (not
    /// silently swallowed into an empty auth header): the resulting requests
    /// would only ever 401, and the operator needs the real reason —
    /// e.g. "Permission denied" while satd holds the cookie `0600` until it
    /// reaches READY. `refresh_auth` retries the read on each auth failure,
    /// so the client recovers automatically once the cookie becomes readable.
    pub fn with_cookie(host: &str, port: u16, cookie_path: PathBuf) -> Self {
        let (auth_header, cookie_error) = match read_cookie_file(&cookie_path) {
            Ok((u, p)) => (
                format!("Basic {}", BASE64.encode(format!("{}:{}", u, p))),
                None,
            ),
            Err(e) => (String::new(), Some(e)),
        };
        Self {
            url: format!("http://{}:{}/", host, port),
            auth_header: parking_lot::RwLock::new(auth_header),
            cookie_path: Some(cookie_path),
            cookie_error: parking_lot::RwLock::new(cookie_error),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// The current cookie-file read error, if the cookie is unreadable.
    /// The poller surfaces this over a generic 401 because it's the
    /// actionable root cause; it clears the moment the cookie reads.
    pub fn cookie_error(&self) -> Option<String> {
        self.cookie_error.read().clone()
    }

    /// Re-read the cookie file and update the auth header. Records the
    /// read error (or clears it on success) so a cookie that becomes
    /// readable — e.g. satd relaxing it to `0640` at READY — flips the
    /// client back to a good state and dismisses the failure modal.
    fn refresh_auth(&self) -> bool {
        let Some(path) = &self.cookie_path else {
            return false;
        };
        match read_cookie_file(path) {
            Ok((u, p)) => {
                let new_auth = format!("Basic {}", BASE64.encode(format!("{}:{}", u, p)));
                *self.auth_header.write() = new_auth;
                *self.cookie_error.write() = None;
                true
            }
            Err(e) => {
                *self.cookie_error.write() = Some(e);
                false
            }
        }
    }

    pub async fn call(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, RpcError> {
        let result = self.call_inner(method, params).await;
        // On auth failure, try refreshing the cookie and retrying once
        if matches!(result, Err(RpcError::AuthFailed)) && self.refresh_auth() {
            return self.call_inner(method, params).await;
        }
        result
    }

    async fn call_inner(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "sat-tui",
            "method": method,
            "params": params,
        });

        let auth = self.auth_header.read().clone();
        let response = self.client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", &auth)
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
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            return Err(RpcError::Rpc { code, message: msg.to_string() });
        }

        Ok(resp.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    // Convenience methods for each RPC we need

    pub async fn get_startup_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getstartupinfo", &[]).await
    }

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

    pub async fn estimate_fees(&self) -> Result<serde_json::Value, RpcError> {
        // Positional: [targets_array, mode]. Targets map mempool.space tiers:
        // 1=High, 3=Medium, 6=Low. `none` tier is the economy_feerate that
        // estimatefees always returns alongside targets.
        self.call("estimatefees", &[serde_json::json!([1, 3, 6])]).await
    }

    pub async fn get_reorg_history(&self) -> Result<serde_json::Value, RpcError> {
        // 7-day window is plenty for the TUI display.
        self.call("getreorghistory", &[serde_json::json!(7 * 86_400)]).await
    }

    pub async fn get_warnings(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getwarnings", &[]).await
    }

    pub async fn get_mempool_history(&self) -> Result<serde_json::Value, RpcError> {
        // 40-minute window: at 10s snapshot cadence + 256-cap default ring
        // that's the full depth. Larger values just waste bytes on the wire.
        self.call("getmempoolhistory", &[serde_json::json!(2400)]).await
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

    pub async fn get_system_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getsysteminfo", &[]).await
    }

    pub async fn get_block_hash(&self, height: u32) -> Result<serde_json::Value, RpcError> {
        self.call("getblockhash", &[serde_json::json!(height)]).await
    }

    /// Verbose=true: returns the JSON header (with `time`, `chainwork`, etc.).
    pub async fn get_block_header(&self, hash: &str) -> Result<serde_json::Value, RpcError> {
        self.call("getblockheader", &[serde_json::json!(hash), serde_json::json!(true)]).await
    }

    pub async fn get_index_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getindexinfo", &[]).await
    }

    pub async fn get_server_status(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getserverstatus", &[]).await
    }

    pub async fn get_network_info(&self) -> Result<serde_json::Value, RpcError> {
        self.call("getnetworkinfo", &[]).await
    }
}

/// JSON-RPC 2.0 reserved code for an unregistered method. satd returns this
/// for steady-state methods while it is still pre-READY (e.g. mid-reindex):
/// the daemon is reachable and answering, the method just isn't wired up yet,
/// so it must never be treated as a connectivity failure.
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

#[derive(Debug)]
pub enum RpcError {
    ConnectionFailed,
    AuthFailed,
    Timeout,
    Request(String),
    Rpc { code: i64, message: String },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::ConnectionFailed => write!(f, "Connection failed"),
            RpcError::AuthFailed => write!(f, "Authentication failed"),
            RpcError::Timeout => write!(f, "Request timed out"),
            RpcError::Request(e) => write!(f, "Request error: {}", e),
            RpcError::Rpc { message, .. } => write!(f, "RPC error: {}", message),
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

#[cfg(test)]
mod tests {
    use super::*;

    // A unique, definitely-missing path. Uses the process id rather than a
    // clock/RNG so the test stays deterministic.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sat-tui-cookie-{}-{}", std::process::id(), name))
    }

    #[test]
    fn with_cookie_surfaces_read_error_for_missing_file() {
        let path = scratch("missing.cookie");
        let _ = std::fs::remove_file(&path);
        let c = RpcClient::with_cookie("127.0.0.1", 8332, path);
        // The real read error is kept, not laundered into an empty auth
        // header that would only ever produce a confusing downstream 401.
        let err = c.cookie_error().expect("a missing cookie must surface a read error");
        assert!(err.contains("Cannot read cookie file"), "got: {err}");
        assert!(
            c.auth_header.read().is_empty(),
            "no credentials when the cookie can't be read"
        );
    }

    #[test]
    fn refresh_auth_recovers_once_cookie_becomes_readable() {
        let path = scratch("recover.cookie");
        let _ = std::fs::remove_file(&path);
        let c = RpcClient::with_cookie("127.0.0.1", 8332, path.clone());
        assert!(c.cookie_error().is_some(), "missing cookie -> error recorded");

        // satd relaxes the cookie to 0640 at READY; the next auth-failure
        // retry re-reads it and the client flips back to a good state.
        std::fs::write(&path, "__cookie__:s3cr3t").unwrap();
        assert!(c.refresh_auth(), "refresh must succeed once the cookie is readable");
        assert!(c.cookie_error().is_none(), "the read error must clear on success");
        assert!(
            c.auth_header.read().starts_with("Basic "),
            "auth header must be rebuilt from the cookie"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn user_pass_client_has_no_cookie_error() {
        let c = RpcClient::new("127.0.0.1", 8332, "u", "p");
        assert!(c.cookie_error().is_none());
    }
}
