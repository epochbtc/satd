//! Resolved Esplora handler configuration. Mirrors the `-esplora*`
//! CLI flags from `satd::config`. Populated by the daemon at startup
//! and frozen for the server's lifetime.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct EsploraConfig {
    /// Whether the Esplora HTTP server should run at all. When false
    /// the daemon never spawns the listener.
    pub enabled: bool,
    /// `host:port` to bind. Defaults to `127.0.0.1:3000`.
    pub bind: String,
    /// URL prefix to mount the API under. Defaults to `/`. Set to
    /// `/api` for `blockstream.info`-style deployments.
    pub prefix: String,
    /// Allowed CORS origins. Empty = no CORS (browser cross-origin
    /// requests will fail). Use `["*"]` to allow any origin.
    pub cors_origins: Vec<String>,
    /// Per-request handler-side timeout. Includes time to assemble
    /// the response body but excludes long-running streaming blocks
    /// (which apply their own bounded read).
    pub request_timeout: Duration,
    /// Hard cap on concurrent in-flight requests. Excess are queued
    /// briefly then 503'd. 0 disables the limit (not recommended in
    /// production).
    pub max_concurrency: usize,
    /// Hard cap on simultaneously-open SSE streams. Each open stream
    /// holds a permit for the lifetime of the socket; the next
    /// connection past the cap is rejected with 503. `0` disables.
    /// Separate from `max_concurrency` because tower's
    /// `ConcurrencyLimitLayer` only bounds request handling until the
    /// `Sse` response is constructed — long-lived streaming bodies
    /// outlive that permit (review M2).
    pub max_sse_conns: usize,
    /// Authentication scheme. Default `None` matches public-Esplora
    /// deployments; operators on a flat LAN flip to `Cookie`.
    pub auth: EsploraAuth,
}

impl Default for EsploraConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:3000".to_string(),
            prefix: "/".to_string(),
            cors_origins: Vec::new(),
            request_timeout: Duration::from_secs(30),
            max_concurrency: 256,
            // SSE streams are inherently long-lived. The default cap
            // (256) matches `max_concurrency` so a default-config
            // operator can't accidentally accumulate more open SSE
            // sockets than they sized their non-streaming endpoints
            // for. Bump explicitly via --esplorasseconns.
            max_sse_conns: 256,
            auth: EsploraAuth::None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EsploraAuth {
    /// Wide-open. Default for public-Esplora deployments.
    #[default]
    None,
    /// Shared `__cookie__:<hex-token>` file. Same shape as the
    /// JSON-RPC cookie; `path` defaults to the same `.cookie` file the
    /// JSON-RPC server writes so a single credential covers both.
    Cookie { path: PathBuf },
    /// Static user/pass Basic Auth.
    UserPass { username: String, password: String },
}

impl EsploraAuth {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, EsploraAuth::None)
    }
}
