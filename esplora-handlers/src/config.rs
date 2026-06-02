//! Resolved Esplora handler configuration. Mirrors the `-esplora*`
//! CLI flags from `satd::config`. Populated by the daemon at startup
//! and frozen for the server's lifetime.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct EsploraConfig {
    /// Whether the Esplora HTTP server should run at all. When false
    /// the daemon never spawns the listener.
    pub enabled: bool,
    /// `host:port` to bind. Defaults to `127.0.0.1:3000`.
    pub bind: String,
    /// Optional TLS bind. When `Some`, both `tls_cert_path` and
    /// `tls_key_path` MUST also be `Some`; the server validates this
    /// at construction time. Mirrors the Electrum-server shape so a
    /// single operator mental model covers both surfaces.
    pub tls_bind: Option<String>,
    /// Path to the TLS server certificate (PEM). Read once at server
    /// start and held in memory.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS server private key (PEM). Read once at
    /// server start and held in memory.
    pub tls_key_path: Option<PathBuf>,
    /// Require mutual TLS on the Esplora TLS listener. Off by default
    /// (backwards-compatible with public-Esplora deployments). When
    /// `true`, both `tls_bind` and `mtls_client_ca` MUST be set; the
    /// server refuses any client without a cert validly signed by the
    /// configured CA. Strictly additive — the existing `auth` layer
    /// (None / Cookie / UserPass) keeps running on top of the mTLS
    /// handshake. Operators who want "mTLS is the only auth" set
    /// `auth = EsploraAuth::None`.
    pub mtls_enabled: bool,
    /// PEM CA bundle used to verify client certificates when
    /// `mtls_enabled` is `true`.
    pub mtls_client_ca: Option<PathBuf>,
    /// Optional allowlist of accepted client-cert subject identities
    /// (CN / DNS-SAN, case-insensitive). Empty means "any CA-signed
    /// cert is accepted"; non-empty narrows further.
    pub mtls_client_allow: Vec<String>,
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
    /// Unified-auth bearer-token store, `Some` only when `-esploraauthbearer`
    /// is set (which requires `authfile`). When present, the Esplora surface
    /// additionally accepts `Authorization: Bearer <token>` for tokens holding
    /// the `esplora:read` capability, on top of (or instead of) the legacy
    /// `auth` credential. `None` is today's behavior.
    pub auth_bearer: Option<Arc<satd_auth::TokenStore>>,
}

impl Default for EsploraConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:3000".to_string(),
            tls_bind: None,
            tls_cert_path: None,
            tls_key_path: None,
            mtls_enabled: false,
            mtls_client_ca: None,
            mtls_client_allow: Vec::new(),
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
            auth_bearer: None,
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
