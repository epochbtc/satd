//! Resolved Electrum-server configuration. Mirrors the `--electrum*`
//! CLI flags from `satd::config`. Populated by the daemon at startup
//! and frozen for the server's lifetime.
//!
//! Transport-related fields (`bind`, `tls_*`, `max_conns`,
//! `request_timeout`) land in PR-3 / PR-5 along with the actual
//! listener. Static-data fields used by handlers (banner,
//! per-method limits) are defined here so PR-2 can wire them through.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Defaults align with `romanz/electrs` where possible:
/// - `MAX_HISTORY_ENTRIES`: cap on confirmed-history rows returned by
///   `blockchain.scripthash.get_history` so a pathological scripthash
///   doesn't OOM the server. electrs uses 200,000.
/// - `MAX_HEADERS_PER_REQUEST`: max headers `blockchain.block.headers`
///   will return in a single call. electrs uses 2016 (one retarget
///   period).
pub const MAX_HISTORY_ENTRIES: usize = 200_000;
pub const MAX_HEADERS_PER_REQUEST: u32 = 2016;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_CONNS: usize = 64;
pub const DEFAULT_MAX_SUBS_PER_CONN: usize = 100;
/// Max requests in a single JSON-RPC batch. electrs uses 16; matches
/// the wallet client mix where Sparrow batches 2–8 reads at startup.
pub const DEFAULT_MAX_BATCH_REQUESTS: usize = 16;
/// Max txs in a single `blockchain.transaction.broadcast_package`
/// call. electrs accepts up to ~25 (matching Bitcoin Core's
/// `MAX_PACKAGE_COUNT`).
pub const DEFAULT_MAX_BROADCAST_PACKAGE_TXS: usize = 25;
/// Default TTL for the `mempool.get_fee_histogram` cache. electrs
/// uses 10 seconds. Wallets that poll this every 10s naturally
/// see one rebuild per poll cycle.
pub const DEFAULT_FEE_HISTOGRAM_TTL_SECS: u64 = 10;

/// Configuration available to method handlers + transport.
///
/// PR-5 adds the TLS fields. This struct is intentionally
/// `Clone`-cheap so per-connection state can hold a snapshot without
/// reaching back through an `Arc`.
#[derive(Debug, Clone)]
pub struct ElectrumConfig {
    /// `host:port` to bind. Defaults to loopback on the standard
    /// Electrum plain-TCP port (50001).
    pub bind: SocketAddr,
    /// Optional TLS bind. When `Some`, both `tls_cert_path` and
    /// `tls_key_path` MUST also be `Some`; the server validates this
    /// at construction time.
    pub tls_bind: Option<SocketAddr>,
    /// Path to the TLS server certificate (PEM). Read once at server
    /// start and held in memory.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to the TLS server private key (PEM). Read once at
    /// server start and held in memory.
    pub tls_key_path: Option<PathBuf>,
    /// Banner string returned by `server.banner`. `None` falls back to
    /// a default constructed at server start (`format!("powered by
    /// satd {}", version)`).
    pub banner: Option<String>,
    /// Donation address returned by `server.donation_address`. Empty
    /// string is the documented "no donations" sentinel.
    pub donation_address: String,
    /// Max confirmed-history entries any single `get_history` call
    /// will return before erroring with `history_too_large`.
    pub max_history_entries: usize,
    /// Max headers per `blockchain.block.headers` response.
    pub max_headers_per_request: u32,
    /// Hard cap on simultaneously-open connections. Excess
    /// connections are accepted then immediately closed with a
    /// `subscription_cap`-style JSON-RPC error so the client knows
    /// to retry — same shape `romanz/electrs` uses.
    pub max_conns: usize,
    /// Per-connection scripthash subscription cap (PR-4 enforces).
    pub max_subs_per_conn: usize,
    /// Wall-clock timeout per inbound request. Enforced around the
    /// dispatch path so a slow handler can't pin a connection slot
    /// indefinitely (review-round-1 M2).
    pub request_timeout: Duration,
    /// Max requests in a single JSON-RPC batch. Excess batches are
    /// rejected with `bad_request` (review-round-1 M5).
    pub max_batch_requests: usize,
    /// Max txs in a single `blockchain.transaction.broadcast_package`
    /// call. Excess packages are rejected (review-round-1 M5).
    pub max_broadcast_package_txs: usize,
    /// TTL for the `mempool.get_fee_histogram` cache (review-round-1
    /// M5). The first call after expiry rebuilds; subsequent calls
    /// within the window return the cached JSON.
    pub fee_histogram_ttl: Duration,
}

impl Default for ElectrumConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:50001".parse().unwrap(),
            tls_bind: None,
            tls_cert_path: None,
            tls_key_path: None,
            banner: None,
            donation_address: String::new(),
            max_history_entries: MAX_HISTORY_ENTRIES,
            max_headers_per_request: MAX_HEADERS_PER_REQUEST,
            max_conns: DEFAULT_MAX_CONNS,
            max_subs_per_conn: DEFAULT_MAX_SUBS_PER_CONN,
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_batch_requests: DEFAULT_MAX_BATCH_REQUESTS,
            max_broadcast_package_txs: DEFAULT_MAX_BROADCAST_PACKAGE_TXS,
            fee_histogram_ttl: Duration::from_secs(DEFAULT_FEE_HISTOGRAM_TTL_SECS),
        }
    }
}
