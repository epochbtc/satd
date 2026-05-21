use bitcoin::Network;
use clap::Parser;
use node::rpc::allowip::IpAllowEntry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// DB cache sizing mode. `Fixed(n)` is the Core-compatible static N-MB budget;
/// `Auto { max_mb }` lets the adaptive controller grow/shrink the cache based
/// on system memory pressure, capped at max_mb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbCacheSize {
    Fixed(usize),
    Auto { max_mb: usize },
}

impl DbCacheSize {
    /// Effective budget to start with, in MB. For Auto, this is the max cap —
    /// the controller will shrink from here based on runtime MemAvailable.
    pub fn initial_mb(&self) -> usize {
        match self {
            Self::Fixed(n) => *n,
            Self::Auto { max_mb } => *max_mb,
        }
    }

    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto { .. })
    }

    /// Parse Bitcoin-Core-compatible string: either a number (MB) or "auto".
    /// When "auto" is given without an explicit max, the cap is chosen based
    /// on total system memory: 50% of MemTotal, min 450 MB, max 8192 MB.
    fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("auto") {
            let default_max_mb = default_auto_max_mb();
            Some(Self::Auto {
                max_mb: default_max_mb,
            })
        } else {
            trimmed.parse::<usize>().ok().map(Self::Fixed)
        }
    }
}

fn default_auto_max_mb() -> usize {
    // Read MemTotal once at config-load time. When unavailable (non-Linux:
    // /proc/meminfo doesn't exist), fall back to Core's default static
    // budget — NOT a larger value. The adaptive controller will separately
    // detect the missing meminfo and stay inactive. Together this keeps
    // `--dbcache=auto` on non-Linux equivalent to the default `--dbcache=450`,
    // matching the documented "no-op on platforms without /proc/meminfo".
    if let Some(info) = node::memstat::meminfo() {
        let half_gb = (info.total_bytes / 2 / 1_000_000) as usize;
        half_gb.clamp(450, 8192)
    } else {
        450
    }
}

/// Consensus engine selection.
///
/// Controls which script verification engine is used:
/// - `cpp`: C++ libbitcoinconsensus FFI only (current default)
/// - `rust`: Pure Rust consensus engine only (not yet production-ready)
/// - `rust-shadow`: Both engines, cpp authoritative, log mismatches
/// - `cpp-shadow`: Both engines, rust authoritative, log mismatches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusEngine {
    /// C++ libbitcoinconsensus FFI (default, eventually deprecated).
    Cpp,
    /// Pure Rust consensus engine (not yet validated for production).
    Rust,
    /// Both engines: cpp is authoritative, rust runs in shadow, mismatches logged.
    RustShadow,
    /// Both engines: rust is authoritative, cpp runs in shadow, mismatches logged.
    CppShadow,
}

impl ConsensusEngine {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cpp" => Some(Self::Cpp),
            "rust" => Some(Self::Rust),
            "rust-shadow" => Some(Self::RustShadow),
            "cpp-shadow" => Some(Self::CppShadow),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConsensusEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cpp => write!(f, "cpp"),
            Self::Rust => write!(f, "rust"),
            Self::RustShadow => write!(f, "rust-shadow"),
            Self::CppShadow => write!(f, "cpp-shadow"),
        }
    }
}

/// Log output format selected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable text (default) — matches pre-flag behavior.
    #[default]
    Text,
    /// One JSON object per event. Fields: `timestamp`, `level`,
    /// `target`, `fields.message`, plus any structured fields attached
    /// by the emitting span/event. Stable field names; safe for
    /// log-shipping pipelines.
    Json,
}

impl LogFormat {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" | "human" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown log format: {}", other)),
        }
    }
}

/// Named preset that populates several knobs at once. Applied between
/// config-file merging and CLI overrides, so a user-supplied CLI flag
/// always wins over a profile value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Full archival node: `txindex=true`, no pruning, large dbcache.
    Archival,
    /// Home-node pruned build: modest prune target, small dbcache,
    /// lower peer count. Target: Pi / Umbrel / entry-level VPS.
    PrunedHome,
    /// Mining-pool-oriented: higher peer limits, nudged relay policy.
    Mining,
    /// Local regtest development: permissive relay, tight peer limits.
    RegtestDev,
    /// Signet watchtower: low resource, relay-friendly, signet network.
    SignetWatchtower,
}

impl Profile {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "archival" | "archive" => Ok(Self::Archival),
            "pruned-home" | "pruned_home" | "home" => Ok(Self::PrunedHome),
            "mining" | "miner" => Ok(Self::Mining),
            "regtest-dev" | "regtest_dev" | "dev" => Ok(Self::RegtestDev),
            "signet-watchtower" | "signet_watchtower" | "watchtower" => Ok(Self::SignetWatchtower),
            other => Err(format!("unknown profile: {}", other)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Archival => "archival",
            Self::PrunedHome => "pruned-home",
            Self::Mining => "mining",
            Self::RegtestDev => "regtest-dev",
            Self::SignetWatchtower => "signet-watchtower",
        }
    }

    /// Default field values this profile suggests. Each returned value
    /// has `None` for fields the profile does not care about, so the
    /// normal precedence chain (`cli → file → profile → hardcoded`)
    /// falls through to the next source.
    pub fn defaults(&self) -> ProfileDefaults {
        match self {
            Self::Archival => ProfileDefaults {
                txindex: Some(true),
                prune: Some(0),
                dbcache: Some(8192),
                maxconnections: None,
                minrelaytxfee: None,
                network_regtest: false,
                network_signet: false,
            },
            Self::PrunedHome => ProfileDefaults {
                txindex: Some(false),
                prune: Some(10_000),
                dbcache: Some(450),
                maxconnections: Some(20),
                minrelaytxfee: None,
                network_regtest: false,
                network_signet: false,
            },
            Self::Mining => ProfileDefaults {
                txindex: None,
                prune: Some(0),
                dbcache: Some(2048),
                maxconnections: Some(125),
                minrelaytxfee: None,
                network_regtest: false,
                network_signet: false,
            },
            Self::RegtestDev => ProfileDefaults {
                txindex: None,
                prune: Some(0),
                dbcache: Some(450),
                maxconnections: Some(8),
                minrelaytxfee: Some(0),
                network_regtest: true,
                network_signet: false,
            },
            Self::SignetWatchtower => ProfileDefaults {
                txindex: None,
                prune: Some(2_000),
                dbcache: Some(450),
                maxconnections: Some(50),
                minrelaytxfee: None,
                network_regtest: false,
                network_signet: true,
            },
        }
    }
}

/// Esplora authentication scheme. Mirrors `esplora_handlers::EsploraAuth`'s
/// shape but lives here so resolution from CLI/config doesn't require a
/// build-time dependency on the handlers crate (the daemon constructs
/// the runtime `EsploraAuth` from this enum at startup).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EsploraAuthMode {
    #[default]
    None,
    Cookie,
    UserPass,
}

impl std::str::FromStr for EsploraAuthMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "cookie" => Ok(Self::Cookie),
            "userpass" => Ok(Self::UserPass),
            other => Err(format!(
                "esplora_auth: expected one of none/cookie/userpass, got {other:?}"
            )),
        }
    }
}

/// A single Bitcoin-Core-format rpcauth credential: the line
/// `user:salt$hash` where `hash = hex(HMAC-SHA256(key=salt, msg=password))`.
/// Parsing splits on the first `:` and the first `$`; we deliberately
/// don't allow `:` in the username because Core's rpcauth.py forbids it
/// too (Basic-auth header is `user:pass`, so a `:` in the user breaks
/// the decode).
#[derive(Debug, Clone)]
pub struct RpcAuthEntry {
    pub username: String,
    /// The salt EXACTLY as written in the config line. Core's
    /// `share/rpcauth/rpcauth.py` emits a printable hex string and then
    /// uses `salt.encode('utf-8')` as the HMAC key — i.e. the ASCII bytes
    /// of the string, NOT the hex-decoded bytes. We must store and key on
    /// the string verbatim or real Core-generated lines won't verify.
    pub salt: String,
    /// The expected HMAC-SHA256 tag, hex-decoded to 32 raw bytes.
    pub hash: Vec<u8>,
}

impl RpcAuthEntry {
    pub fn parse(s: &str) -> Result<Self, String> {
        let raw = s.trim();
        let (user, rest) = raw.split_once(':').ok_or_else(|| {
            format!("invalid --rpcauth entry: expected `user:salt$hash`, got {raw:?}")
        })?;
        if user.is_empty() {
            return Err("invalid --rpcauth entry: empty username".to_string());
        }
        let (salt, hash_hex) = rest.split_once('$').ok_or_else(|| {
            format!(
                "invalid --rpcauth entry for user {user:?}: expected `user:salt$hash`, no `$` separator found"
            )
        })?;
        let salt = salt.trim();
        if salt.is_empty() {
            return Err(format!(
                "invalid --rpcauth entry for user {user:?}: empty salt"
            ));
        }
        let hash = hex::decode(hash_hex.trim()).map_err(|e| {
            format!("invalid --rpcauth entry for user {user:?}: hash is not hex: {e}")
        })?;
        // Sanity: Core's rpcauth.py always produces 32-byte HMAC-SHA256
        // tags. A short tag is almost certainly a typo and would let
        // through trivial collisions.
        if hash.len() != 32 {
            return Err(format!(
                "invalid --rpcauth entry for user {user:?}: hash is {} bytes (hex {} chars); expected 32 bytes (hex 64 chars) for HMAC-SHA256",
                hash.len(),
                hash_hex.trim().len(),
            ));
        }
        Ok(Self {
            username: user.to_string(),
            salt: salt.to_string(),
            hash,
        })
    }
}

/// Filesystem permissions applied to the auto-generated cookie file.
/// Mirrors Bitcoin Core's `-rpccookieperms=<owner|group|all>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CookiePerms {
    /// 0600 — readable by the satd UID only. Core's default.
    #[default]
    Owner,
    /// 0640 — readable by the `satd` group. Lets group members
    /// (operators in the systemd `satd` group) authenticate without
    /// sudo. Matches the `ExecStartPost=chmod 0640` shim that
    /// `satd.service` currently runs after every startup, with the
    /// difference that this mode writes the file with the right perms
    /// in the first place (no brief 0600 window).
    Group,
    /// 0644 — readable by every local user. Only ever sensible on
    /// dedicated boxes where local-process separation isn't a concern.
    All,
}

impl CookiePerms {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "owner" => Ok(Self::Owner),
            "group" => Ok(Self::Group),
            "all" => Ok(Self::All),
            other => Err(format!(
                "invalid --rpccookieperms value {other:?}: expected one of owner/group/all"
            )),
        }
    }

    pub fn as_mode(self) -> u32 {
        match self {
            Self::Owner => 0o600,
            Self::Group => 0o640,
            Self::All => 0o644,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Group => "group",
            Self::All => "all",
        }
    }
}

/// Per-field defaults contributed by a named `Profile`. None means the
/// profile does not opine on this field.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProfileDefaults {
    pub txindex: Option<bool>,
    pub prune: Option<u64>,
    pub dbcache: Option<usize>,
    pub maxconnections: Option<usize>,
    pub minrelaytxfee: Option<u64>,
    pub network_regtest: bool,
    pub network_signet: bool,
}

/// Resolved node configuration after merging CLI args, config file, and defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    pub datadir: PathBuf,
    /// Alternative location for `blocks/`. `None` means use the
    /// default `<datadir>/blocks` (or network-suffixed equivalent
    /// like `<datadir>/regtest/blocks`). Mirrors Bitcoin Core's
    /// `-blocksdir=<dir>`.
    pub blocksdir: Option<PathBuf>,
    /// Additional signet seed nodes. Empty = built-in seeds only.
    /// Only consulted on signet.
    pub signet_seed_nodes: Vec<String>,
    pub rpcport: u16,
    /// Concrete socket addresses the JSON-RPC HTTP listener binds to.
    /// Mirrors Bitcoin Core's `-rpcbind=<addr>[:port]` — repeatable, so
    /// one node can listen on multiple interfaces (e.g. both `127.0.0.1`
    /// and `[::1]`, which is Core's no-flag default). When no operator
    /// value is supplied, defaults to `127.0.0.1:rpcport` only — same
    /// posture as Core when no `-rpcallowip` is configured.
    pub rpcbind: Vec<SocketAddr>,
    /// Per-request source-IP allowlist for the JSON-RPC HTTP listener.
    /// Mirrors Bitcoin Core's `-rpcallowip=<ip|cidr>` — repeatable.
    /// Empty list means loopback only (Core's default). If any
    /// `rpcbind` entry is non-loopback while this list is empty,
    /// `Config::load` refuses to start: that's the misconfiguration
    /// Core specifically guards against.
    pub rpcallowip: Vec<IpAllowEntry>,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
    /// Bitcoin-Core-compatible HMAC-SHA256 RPC credentials. Each entry
    /// is `user:salt$hash` where `hash = hex(HMAC-SHA256(salt, password))`.
    /// Generated by Core's `share/rpcauth/rpcauth.py` — satd consumes
    /// the same format verbatim so a Core operator's existing rpcauth
    /// lines work unchanged. Repeatable so multiple users can be
    /// configured. Coexists with `--rpcuser`/`--rpcpassword` and cookie
    /// auth; any valid credential opens the door.
    pub rpcauth: Vec<RpcAuthEntry>,
    /// Operator-overridable path for the auto-generated cookie file
    /// (Core's `-rpccookiefile`). `None` (default) keeps Core's
    /// `$DATADIR/.cookie` behaviour. Absolute paths only — relative
    /// paths would be ambiguous against the network-suffixed datadir.
    pub rpc_cookie_file: Option<PathBuf>,
    /// Filesystem permissions applied to the cookie file when it's
    /// written, matching Core's `-rpccookieperms=<owner|group|all>`.
    /// `Owner` (0600, default) restricts to the satd UID; `Group`
    /// (0640) lets the `satd` group read it (this is what
    /// `satd.service`'s `ExecStartPost=chmod 0640` already does post-
    /// write); `All` (0644) lets every local user read — only ever
    /// sensible on dedicated boxes where local separation isn't a
    /// concern.
    pub rpc_cookie_perms: CookiePerms,
    /// Optional TLS bind. When set, `rpc_tls_cert` and `rpc_tls_key`
    /// MUST also be set. Bitcoin Core's RPC is HTTP-only; this is a
    /// satd-specific addition for operators who want native TLS
    /// without a reverse proxy. Mirrors the Electrum / Esplora TLS
    /// surfaces.
    pub rpc_tls_bind: Option<String>,
    pub rpc_tls_cert: Option<std::path::PathBuf>,
    pub rpc_tls_key: Option<std::path::PathBuf>,
    /// Require mutual TLS on the JSON-RPC TLS listener. Off by
    /// default. When `true`, the listener refuses any client without
    /// a cert validly signed by `rpc_mtls_client_ca`. Strictly
    /// additive — cookie / userpass auth keeps running on top unless
    /// the operator also passes `--rpcdisableauth=1`.
    pub rpc_mtls: bool,
    /// PEM CA bundle used to verify client certificates on the
    /// JSON-RPC TLS surface. Required when `rpc_mtls = true`.
    pub rpc_mtls_client_ca: Option<std::path::PathBuf>,
    /// Optional allowlist of accepted client-cert subject identities
    /// (CN / DNS-SAN, case-insensitive). Empty = any CA-signed cert.
    pub rpc_mtls_client_allow: Vec<String>,
    /// Disable HTTP Basic auth on the JSON-RPC TLS surface. Only
    /// accepted when `rpc_mtls = true` (the mTLS handshake becomes
    /// the only gate on that surface). The plain-HTTP surface is
    /// UNAFFECTED — it always keeps cookie / userpass enforcement so
    /// loopback access stays gated against other local processes.
    pub rpc_disable_auth: bool,
    /// Per-handshake wall-clock timeout on the JSON-RPC TLS surface
    /// (review H2). Defaults to 10 seconds — shorter than the
    /// Electrum / Esplora handshake timeouts (30s) because JSON-RPC
    /// clients are typically local or short-haul; a slow TLS
    /// handshake is more likely a probe than a real client.
    /// Operators behind high-latency links can raise this via
    /// `--rpctlshandshaketimeout`.
    pub rpc_tls_handshake_timeout: u64,
    pub listen: bool,
    pub port: u16,
    pub connect: Vec<String>,
    pub assumevalid: Option<String>,
    pub assumevalidage: u64,
    /// Stop running once the active-chain tip reaches this height
    /// (matches Bitcoin Core's `-stopatheight`). The node accepts the
    /// block at the target height, then broadcasts graceful shutdown
    /// so RocksDB flushes cleanly. Primary use case is deterministic
    /// testing — e.g. dumping a UTXO snapshot at exactly an AssumeUTXO
    /// anchor height for cross-validation against Core's published
    /// `hash_serialized_3` values. `None` (default) = run indefinitely.
    pub stopatheight: Option<u32>,
    // Mempool policy
    pub mempoolfullrbf: bool,
    pub maxmempool: usize,
    pub minrelaytxfee: u64,
    pub dustrelayfee: u64,
    pub datacarriersize: usize,
    pub datacarrier: bool,
    pub limitancestorcount: usize,
    pub limitdescendantcount: usize,
    pub mempoolexpiry: u64,
    pub permitbaremultisig: bool,
    pub txindex: bool,
    /// Address-history index. On by default; disable via
    /// `--addressindex=0` or `-noindex=address`. Backs the native
    /// Electrum and Esplora subsystems.
    pub addressindex: bool,
    /// Maximum concurrent per-scripthash status subscriptions. Caps
    /// memory growth from the per-scripthash broadcast registry.
    /// Default 10000 — generous for typical xpub-derivation patterns.
    pub addrindexsubscriptions: usize,
    /// Native Esplora REST server (per `ECOSYSTEM.md` §4). On by
    /// default; `--esplora=0` disables. Requires `--addressindex=1`.
    pub esplora: bool,
    /// `host:port` for the Esplora HTTP listener.
    pub esplora_bind: String,
    /// Optional TLS bind. When set, `esplora_tls_cert` and
    /// `esplora_tls_key` MUST also be set. Mirrors the Electrum-server
    /// shape so operators learn one TLS configuration pattern. No
    /// standard Esplora TLS port; `:3001` is a common convention
    /// (one above the plain `:3000`).
    pub esplora_tls_bind: Option<String>,
    /// Path to PEM-encoded TLS certificate for the Esplora server
    /// (operator-supplied; self-signed-on-first-start is deferred,
    /// same stance as Electrum).
    pub esplora_tls_cert: Option<std::path::PathBuf>,
    /// Path to PEM-encoded TLS private key for the Esplora server.
    pub esplora_tls_key: Option<std::path::PathBuf>,
    /// Require mutual TLS on the Esplora TLS listener. Off by default
    /// (backwards-compatible with public-Esplora deployments). When
    /// `true`, both `esplora_tls_bind` and `esplora_mtls_client_ca`
    /// MUST be set; the server refuses any client without a cert
    /// validly signed by the configured CA. Strictly additive — the
    /// existing `esplora_auth` layer still runs on top.
    pub esplora_mtls: bool,
    /// PEM CA bundle used to verify client certificates on the Esplora
    /// TLS surface. Required when `esplora_mtls = true`.
    pub esplora_mtls_client_ca: Option<std::path::PathBuf>,
    /// Optional allowlist of accepted client-cert subject identities
    /// (CN / DNS-SAN, case-insensitive). Empty means "any CA-signed
    /// cert is accepted"; non-empty narrows further.
    pub esplora_mtls_client_allow: Vec<String>,
    /// URL prefix to mount the API under (default `/`; `/api` for
    /// `blockstream.info`-style deployments).
    pub esplora_prefix: String,
    /// Allowed CORS origins. Empty = no CORS.
    pub esplora_cors: Vec<String>,
    /// Per-request handler timeout (seconds).
    pub esplora_request_timeout: u64,
    /// Hard cap on concurrent in-flight Esplora requests.
    pub esplora_max_conns: usize,
    /// Hard cap on simultaneously-open SSE streams. Separate from
    /// `esplora_max_conns` because the request concurrency layer
    /// does not bound long-lived streaming bodies (review M2). `0`
    /// disables the cap.
    pub esplora_sse_max_conns: usize,
    /// Authentication scheme: `none` (default), `cookie`, or
    /// `userpass`. `none` matches public-Esplora deployments.
    pub esplora_auth: EsploraAuthMode,
    /// Path to the cookie file used when `esplora_auth = cookie`.
    /// Defaults to the same `.cookie` file as JSON-RPC so a single
    /// credential covers both surfaces.
    pub esplora_cookie_file: Option<std::path::PathBuf>,
    /// `user:pass` for `esplora_auth = userpass`.
    pub esplora_userpass: Option<(String, String)>,
    /// Native Electrum protocol server (per `ECOSYSTEM.md` §4 / §4a).
    /// Off by default; `--electrum=1` enables. Requires
    /// `--addressindex=1` AND a complete `--txindex` for the
    /// confirmed-tx and merkle-proof endpoints. Both invariants
    /// are enforced at startup.
    pub electrum: bool,
    /// `host:port` for the plain-TCP Electrum listener. Defaults to
    /// loopback on port 50001 (Electrum's standard plain-TCP port);
    /// expose via Tor / .onion rather than directly on the LAN per
    /// the operator advice in `OPERATOR_ERGONOMICS.md`.
    pub electrum_bind: String,
    /// Optional TLS bind. When set, `electrum_tls_cert` and
    /// `electrum_tls_key` MUST also be set. Standard Electrum TLS
    /// port is 50002.
    pub electrum_tls_bind: Option<String>,
    /// Path to PEM-encoded TLS certificate (operator-supplied;
    /// self-signed-on-first-start is deferred).
    pub electrum_tls_cert: Option<std::path::PathBuf>,
    /// Path to PEM-encoded TLS private key.
    pub electrum_tls_key: Option<std::path::PathBuf>,
    /// Require mutual TLS on the Electrum TLS listener. Off by default
    /// (backwards-compatible with electrs). When `true`, both
    /// `electrum_tls_bind` and `electrum_mtls_client_ca` MUST be set;
    /// the server refuses any client without a cert validly signed by
    /// the configured CA. Electrum has no application auth today, so
    /// the mTLS handshake is the only gate.
    pub electrum_mtls: bool,
    /// PEM CA bundle used to verify client certificates on the
    /// Electrum TLS surface. Required when `electrum_mtls = true`.
    pub electrum_mtls_client_ca: Option<std::path::PathBuf>,
    /// Optional allowlist of accepted client-cert subject identities
    /// (CN / DNS-SAN, case-insensitive). Empty means "any CA-signed
    /// cert is accepted"; non-empty narrows further. Repeatable
    /// `--electrummtlsclientallow` or comma-separated.
    pub electrum_mtls_client_allow: Vec<String>,
    /// Hard cap on simultaneously-open connections.
    pub electrum_max_conns: usize,
    /// Per-connection scripthash subscription cap.
    pub electrum_max_subs_per_conn: usize,
    /// Per-request timeout (seconds). Wraps the dispatch path
    /// (read → handler → write) and the TLS handshake via
    /// `tokio::time::timeout`; an idle or slow client cannot pin a
    /// connection slot indefinitely. A timed-out dispatch returns
    /// `bad_request("request timed out after Ns")` on the wire.
    pub electrum_request_timeout: u64,
    /// Max requests in a single JSON-RPC batch line. Excess batches
    /// are rejected with `bad_request`.
    pub electrum_max_batch_requests: usize,
    /// Max txs in a single `blockchain.transaction.broadcast_package`
    /// call. Excess packages are rejected with `bad_request`.
    pub electrum_max_broadcast_package_txs: usize,
    /// TTL (seconds) for the `mempool.get_fee_histogram` cache.
    /// Default 10s — matches `romanz/electrs`. Lower = fresher data
    /// but more CPU per wallet poll cycle.
    pub electrum_fee_histogram_ttl: u64,
    /// Override for `server.banner`. `None` falls back to a default
    /// composed at request time (`format!("powered by satd {}",
    /// version)`).
    pub electrum_banner: Option<String>,
    /// BIP 158 compact-block-filter index (per `ECOSYSTEM.md` §3,
    /// `bip157-158-compact-filters.md`). Off by default; enable via
    /// `--blockfilterindex=basic` (Bitcoin-Core-compatible spelling)
    /// or `--blockfilterindex=1`. Required for the BIP 157 P2P
    /// service and the `getblockfilter` RPC. Implies an additional
    /// per-block disk write of ~30 KB filter blob + 32-byte header.
    pub blockfilterindex: bool,
    /// Whether to advertise `NODE_COMPACT_FILTERS` and answer
    /// `getcfilters` / `getcfheaders` / `getcfcheckpt` over the BIP
    /// 157 P2P service. Off by default. Enabling requires
    /// `--blockfilterindex=basic`; the `Config::load` reconciliation
    /// hard-fails on the conflict.
    pub peerblockfilters: bool,
    pub prune: u64,
    pub reindex: bool,
    pub reindex_chainstate: bool,
    // P2P
    pub maxconnections: usize,
    /// Maximum simultaneous inbound peers from the same source IP
    /// (Core-style flood guard; default 3).
    pub maxinboundperip: usize,
    pub bind: String,
    #[allow(dead_code)]
    pub timeout: u64,
    pub addnode: Vec<String>,
    pub dns: bool,
    pub bantime: u64,
    // Proxy / Tor
    pub proxy: Option<String>,
    pub onion: Option<String>,
    pub torcontrol: Option<String>,
    pub torpassword: Option<String>,
    #[allow(dead_code)]
    pub onlynet: Vec<String>,
    // Mining
    #[allow(dead_code)]
    pub blockmaxweight: usize,
    #[allow(dead_code)]
    pub blockmintxfee: u64,
    // Misc
    pub pid: Option<String>,
    // Cache — raw budget for the static partition; see `dbcache_mode` for
    // whether the adaptive controller should further adjust it at runtime.
    pub dbcache: usize,
    pub dbcache_mode: DbCacheSize,
    /// Number of IBD prefetch worker threads (default: CPU core count)
    pub prefetch_workers: usize,
    /// Maximum blocks downloaded ahead of the connect cursor during IBD.
    /// "all" = unlimited (u32::MAX), "N%" = percentage of remaining (encoded as 1_000_000_000 + pct),
    /// N = fixed count.
    pub max_ahead: u32,
    /// RocksDB `max_open_files` cap. Bounds the table-reader cache so a
    /// large compaction backlog doesn't pin tens of thousands of SST file
    /// descriptors and their per-SST metadata in memory. `-1` = unlimited
    /// (legacy behavior). Default: 2048.
    pub max_open_files: i32,
    /// Underlying storage class for the chainstate. Selects a set of
    /// RocksDB tunables sized for the media: `Ssd` (default) maxes
    /// background parallelism and uses a large WAL trigger; `Hdd`
    /// reduces concurrency to avoid seek thrash and shortens the WAL
    /// to bound crash-recovery time on slow writes.
    pub storage_profile: node::storage::profile::StorageProfile,
    /// Optional override for `Options::set_max_background_jobs`. When
    /// `None`, the value from `storage_profile` applies. Advanced
    /// users only — the three rocksdb-* overrides interact, and
    /// setting one in isolation can make compaction worse.
    pub rocksdb_background_jobs: Option<i32>,
    /// Optional override for `Options::set_max_subcompactions`. See
    /// `rocksdb_background_jobs` for the cross-knob caveat.
    pub rocksdb_subcompactions: Option<u32>,
    /// Optional override for `Options::set_max_total_wal_size`,
    /// expressed in megabytes for CLI ergonomics. Must be comfortably
    /// larger than the sum of per-CF write buffers (~680 MB on the
    /// stock schema), otherwise flushes are driven by WAL pressure
    /// rather than memtable pressure (the failure mode that caused
    /// the 2026-05-13 disk-fill incident).
    pub rocksdb_wal_mb: Option<u64>,
    /// Interval at which the per-CF pending-compaction diagnostic
    /// logger emits a snapshot. Default: 60s. `0` disables.
    pub compaction_diag_interval_secs: u64,
    /// IBD connector backpressure: pause each loop iteration when the
    /// chainstate's L0 SST count is at or above this value, so RocksDB
    /// compaction has a chance to drain. `0` disables. Default: 64.
    pub ibd_l0_pause_at: u32,
    /// Periodic forced-compaction interval, in seconds. The dedicated
    /// compactor thread wakes this often, checks the chainstate's L0 file
    /// count, and forces a synchronous compaction if it's at or above
    /// `compaction_l0_at`. `0` disables the thread. Default: 1800 (30 min).
    pub compaction_interval_secs: u64,
    /// L0 SST count at or above which the periodic compactor forces a
    /// chainstate compaction. Distinct from `ibd_l0_pause_at` because the
    /// connector reacts every block (so a high threshold avoids constant
    /// micro-pauses) while the compactor runs on a long interval (so a
    /// lower threshold cleans up moderate backlogs that the connector is
    /// tolerating). Default: 16.
    pub compaction_l0_at: u64,
    /// Seconds without chain-tip advancement before the stall watchdog
    /// dumps thread states from `/proc/self/task/*` for post-mortem.
    /// `0` disables the watchdog entirely. Default: 300 (5 min).
    pub stall_watchdog_secs: u64,
    /// Additional seconds after a forensics dump before the watchdog
    /// calls `std::process::abort()` so systemd restarts the unit.
    /// Default: 300 (so total = `stall_watchdog_secs + stall_abort_secs`
    /// = 10 min by default).
    pub stall_abort_secs: u64,
    /// Consensus engine selection.
    pub consensus: ConsensusEngine,
    /// Shadow verification queue capacity (default: 4_194_304).
    pub shadow_queue_size: usize,
    /// Shadow verification worker threads (default: 4).
    pub shadow_workers: usize,
    // MCP server
    pub mcp: bool,
    pub mcp_stdio: bool,
    pub mcp_port: Option<u16>,
    pub mcp_bind: String,
    // Metrics / health HTTP server (unauthenticated — bind to loopback or firewall)
    pub metricsport: Option<u16>,
    pub metricsbind: String,
    /// Emit structured `data` payloads (category, suggestion, debug) on
    /// RPC errors. Default off to preserve Bitcoin-Core wire format.
    pub rpc_extended_errors: bool,
    /// Maximum seconds the graceful shutdown flush may take before we
    /// exit anyway. Bounds worst-case hangs on large dbcache flushes.
    pub max_shutdown_secs: u64,
    /// Server-wide default unit for amount serialization in RPC responses.
    /// `Btc` (default) matches Bitcoin Core byte-for-byte; `Sats` emits
    /// integer satoshis (no floating-point precision loss).
    pub rpc_default_units: node::rpc::amounts::AmountUnit,
    /// Log output format. `Text` is human-readable (default); `Json`
    /// emits one JSON object per event for log-shipping pipelines.
    pub log_format: LogFormat,
    /// Named profile the operator selected (if any). Informational —
    /// the profile's effects are already baked into the other fields.
    pub profile: Option<Profile>,
    /// Optional HTTP endpoint receiving reorg-event POSTs. None = the
    /// dispatcher is not started.
    pub reorg_webhook: Option<String>,
    /// Optional HMAC-SHA256 secret for `X-Satd-Signature`. If set, the
    /// dispatcher signs each webhook body. Absent = unsigned POSTs.
    pub reorg_webhook_secret: Option<String>,
    /// Operator-pinned per-node identifier for the events bus. 32-char
    /// lowercase hex (UUIDv4). `None` = auto-generate and persist to
    /// `<datadir>/node_id` on first start.
    pub events_node_id: Option<String>,
    /// Optional region tag stamped on every events envelope (≤ 8
    /// printable ASCII bytes). Used for geo-correlation across
    /// multi-watcher deployments.
    pub events_region: Option<String>,
    /// `host:port` to bind the events gRPC streaming server. `None`
    /// (default) leaves the gRPC sink disabled. The server speaks the
    /// `satd.events.v1.NodeEventStream` schema; clients open a single
    /// `Subscribe` RPC and consume the stream. The server is
    /// **unauthenticated and unencrypted**; non-loopback bindings are
    /// rejected unless `events_grpc_allow_remote` is also set.
    pub events_grpc_bind: Option<String>,
    /// Permit `events_grpc_bind` to point at a non-loopback address.
    /// Default `false`. Operators must enable this explicitly *and*
    /// place the server behind a firewall, mTLS terminator, or auth
    /// proxy — the gRPC sink itself has no auth or rate limits.
    pub events_grpc_allow_remote: bool,
    /// ZMQ endpoint string (e.g. `tcp://0.0.0.0:28332`) for the events
    /// PUB-socket sink. `None` = disabled. Topics emitted: `hashtx`,
    /// `hashblock` (Bitcoin Core wire-format compatible), plus
    /// `mpevict`, `mpreplace`, `mpconfirm`, `nodeevent` (JSON
    /// payloads). Per-topic enable/disable lives in the matching
    /// `events_zmq_*` fields.
    pub events_zmq_bind: Option<String>,
    /// Per-topic ZMQ enable flags. `None` = topic enabled by default
    /// (matching Core's behavior — if you bind ZMQ, you get every
    /// topic). Set explicitly to disable.
    pub events_zmq_hashtx: Option<bool>,
    pub events_zmq_hashblock: Option<bool>,
    pub events_zmq_mpevict: Option<bool>,
    pub events_zmq_mpreplace: Option<bool>,
    pub events_zmq_mpconfirm: Option<bool>,
    pub events_zmq_nodeevent: Option<bool>,
    // No-op compatibility flags (accepted but ignored)
    #[allow(dead_code)]
    pub server: bool,
    #[allow(dead_code)]
    pub daemon: bool,
    /// Operator-facing notes produced during config reconciliation.
    /// Emitted by `main.rs` AFTER the tracing subscriber is
    /// initialized — `Config::from_cli` runs before `tracing` is set
    /// up, so logging from inside the resolver would silently disappear
    /// (round-3 M2). Consumed once by `take_pending_notes`.
    pub pending_notes: Vec<ConfigNote>,
}

/// A deferred operator-facing note emitted during config load. Its
/// `level` selects the tracing macro in `main.rs`.
#[derive(Debug, Clone)]
pub struct ConfigNote {
    pub level: NoteLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
pub enum NoteLevel {
    Info,
    Warn,
}

impl Config {
    /// Load configuration by merging CLI args → config file → defaults.
    pub fn load() -> Result<Self, String> {
        let raw_args: Vec<String> = std::env::args().collect();
        let normalized = normalize_args(raw_args);
        let cli = match CliArgs::try_parse_from(normalized) {
            Ok(c) => c,
            Err(e) => {
                // `--version` and `--help` come back as `Err` from
                // `try_parse_from`; clap's `print()` writes the
                // requested output to the right stream and we exit
                // 0. Without this, satd treats `--version` /
                // `--help` as a parse error and exits 1.
                use clap::error::ErrorKind;
                if matches!(
                    e.kind(),
                    ErrorKind::DisplayVersion | ErrorKind::DisplayHelp
                ) {
                    e.print().ok();
                    std::process::exit(0);
                }
                return Err(e.to_string());
            }
        };
        Self::from_cli(cli)
    }

    pub fn from_cli(cli: CliArgs) -> Result<Self, String> {
        // Resolve named profile (if any). Fields from the profile flow
        // through as a lower-priority default: CLI flags always override,
        // config-file entries override profile, and profile wins only over
        // the hardcoded defaults.
        let profile = cli
            .profile
            .as_ref()
            .map(|p| Profile::parse(p))
            .transpose()?;
        let profile_defaults: ProfileDefaults = profile.map(|p| p.defaults()).unwrap_or_default();

        // Determine datadir (datadir lookup intentionally precedes
        // network resolution because the config file location depends
        // on datadir, and the config file may carry `chain=`).
        let base_datadir = cli.datadir.clone().unwrap_or_else(default_datadir);

        // Determine config file path and parse it.
        let conf_path = cli
            .conf
            .clone()
            .unwrap_or_else(|| base_datadir.join("bitcoin.conf"));
        let config_file = if conf_path.exists() {
            Some(ConfigFile::parse_file(&conf_path)?)
        } else {
            None
        };

        // Network resolution. Precedence:
        //   1. --chain=<name>   (Bitcoin Core's unified selector)
        //   2. --regtest / --testnet / --signet   (older form, still
        //      accepted)
        //   3. config-file `chain=<name>` line
        //   4. profile defaults
        //   5. mainnet
        //
        // Refuse to start if --chain conflicts with the older single-
        // network flags: the operator's intent is ambiguous and
        // silently picking one would be the wrong kind of helpful.
        if cli.chain.is_some() && (cli.regtest || cli.testnet || cli.signet) {
            return Err(
                "--chain conflicts with --regtest/--testnet/--signet — pass only one of them"
                    .to_string(),
            );
        }
        let chain_from_cli = cli.chain.as_deref();
        // `chain_from_cli` first, then look for `chain=` in the config
        // file global. The section-keyed lookup is intentionally
        // skipped here because sections are themselves chain-keyed
        // — a `chain=` line inside `[main]` would be circular.
        let chain_from_file: Option<String> = config_file
            .as_ref()
            .and_then(|cf| cf.global.get("chain"))
            .and_then(|v: &Vec<String>| v.last().cloned());
        let network = if let Some(name) = chain_from_cli.or(chain_from_file.as_deref()) {
            parse_chain_name(name)?
        } else if cli.regtest || profile_defaults.network_regtest {
            Network::Regtest
        } else if cli.testnet {
            Network::Testnet
        } else if cli.signet || profile_defaults.network_signet {
            Network::Signet
        } else {
            Network::Bitcoin
        };

        // Section name for the active network. Matches Bitcoin Core's
        // section naming convention so a Core `bitcoin.conf` with
        // `[regtest]` / `[test]` / `[signet]` / `[main]` blocks is
        // picked up correctly. Before this PR, Signet fell through
        // to `[main]` — that silently merged mainnet operator
        // settings into a signet node, a real misconfiguration risk.
        let section = match network {
            Network::Regtest => "regtest",
            Network::Testnet => "test",
            Network::Signet => "signet",
            Network::Bitcoin => "main",
            _ => "main",
        };

        // Helper: look up a key from config file (section first, then global)
        let file_get = |key: &str| -> Option<String> {
            config_file.as_ref().and_then(|cf| {
                cf.sections
                    .get(section)
                    .and_then(|s| s.get(key))
                    .and_then(|v| v.last().cloned())
                    .or_else(|| cf.global.get(key).and_then(|v| v.last().cloned()))
            })
        };

        let file_get_all = |key: &str| -> Vec<String> {
            config_file
                .as_ref()
                .map(|cf| {
                    let mut vals = cf.global.get(key).cloned().unwrap_or_default();
                    if let Some(s) = cf.sections.get(section)
                        && let Some(sv) = s.get(key)
                    {
                        vals.extend(sv.iter().cloned());
                    }
                    vals
                })
                .unwrap_or_default()
        };

        // Merge: CLI > config file > defaults
        let rpcport = cli
            .rpcport
            .or_else(|| file_get("rpcport").and_then(|v| v.parse().ok()))
            .unwrap_or_else(|| default_rpc_port(network));

        // --rpcbind resolution: CLI list wins (multi-flag); else config
        // file (multi-value); else single default loopback. Each entry
        // is `addr[:port]` per Bitcoin Core; bare addresses inherit
        // `rpcport`. Resolved to concrete `SocketAddr`s here so the
        // server-side binding code doesn't have to re-parse.
        let rpcbind_raw: Vec<String> = if !cli.rpcbind.is_empty() {
            cli.rpcbind.clone()
        } else {
            file_get_all("rpcbind")
        };
        let mut rpcbind: Vec<SocketAddr> = Vec::new();
        if rpcbind_raw.is_empty() {
            // Core's posture when no -rpcbind is set: 127.0.0.1 (and
            // ::1 when IPv6 is available). We default to 127.0.0.1
            // only — adding ::1 by default risks an unexpected open
            // listener on dual-stack boxes where IPv6 firewall rules
            // haven't been written. Operators who want ::1 can pass
            // `--rpcbind=[::1]` explicitly.
            rpcbind.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpcport));
        } else {
            for entry in &rpcbind_raw {
                let parsed = parse_rpcbind_entry(entry, rpcport).map_err(|e| {
                    format!("invalid --rpcbind value {entry:?}: {e}")
                })?;
                rpcbind.push(parsed);
            }
        }

        // --rpcallowip resolution: CLI list wins; else config (multi).
        // Defer the "non-loopback bind requires non-empty allowlist"
        // check until both are parsed so the operator gets one clear
        // error message instead of two.
        let rpcallowip_raw: Vec<String> = if !cli.rpcallowip.is_empty() {
            cli.rpcallowip.clone()
        } else {
            file_get_all("rpcallowip")
        };
        let mut rpcallowip: Vec<IpAllowEntry> = Vec::new();
        for entry in &rpcallowip_raw {
            rpcallowip.push(IpAllowEntry::parse(entry)?);
        }

        // Core's gate against accidental exposure: if any rpcbind is
        // non-loopback AND no rpcallowip is set, refuse to start. This
        // is the configuration where a Core operator would also see
        // `Cannot obtain a lock on data directory` style errors —
        // satd is more explicit about the why.
        let any_non_loopback = rpcbind.iter().any(|a| !a.ip().is_loopback());
        if any_non_loopback && rpcallowip.is_empty() {
            let exposed: Vec<String> =
                rpcbind.iter().filter(|a| !a.ip().is_loopback()).map(|a| a.to_string()).collect();
            return Err(format!(
                "--rpcbind on non-loopback address(es) {exposed:?} requires at least one \
                --rpcallowip entry. Add `--rpcallowip=<ip-or-cidr>` (or the matching \
                `rpcallowip=` line in bitcoin.conf) so the JSON-RPC server isn't open \
                to every IP that can reach the bind interface. This matches Bitcoin \
                Core's behavior."
            ));
        }

        // --rpcauth resolution: CLI list wins; else config (multi).
        let rpcauth_raw: Vec<String> = if !cli.rpcauth.is_empty() {
            cli.rpcauth.clone()
        } else {
            file_get_all("rpcauth")
        };
        let mut rpcauth: Vec<RpcAuthEntry> = Vec::new();
        for entry in &rpcauth_raw {
            rpcauth.push(RpcAuthEntry::parse(entry)?);
        }

        let rpc_cookie_file = cli
            .rpccookiefile
            .or_else(|| file_get("rpccookiefile").map(PathBuf::from));
        if let Some(p) = &rpc_cookie_file
            && p.is_relative()
        {
            return Err(format!(
                "--rpccookiefile must be an absolute path, got {p:?}. Relative paths would \
                be ambiguous against satd's network-suffixed datadir (regtest/, signet/, \
                testnet3/)."
            ));
        }

        let rpc_cookie_perms = match cli.rpccookieperms.or_else(|| file_get("rpccookieperms")) {
            Some(s) => CookiePerms::parse(&s)?,
            None => CookiePerms::default(),
        };

        let rpcuser = cli.rpcuser.or_else(|| file_get("rpcuser"));
        let rpcpassword = cli.rpcpassword.or_else(|| file_get("rpcpassword"));

        // --blocksdir resolution: CLI > config file > None (= use
        // default `<datadir>/<net>/blocks`). The path is kept as-is —
        // the storage layer is what consults it; this layer just
        // surfaces it to operator-visible config echo and asserts it
        // is absolute when present (relative paths would be
        // ambiguous against the network-suffixed datadir).
        let blocksdir = cli
            .blocksdir
            .or_else(|| file_get("blocksdir").map(PathBuf::from));
        if let Some(p) = &blocksdir
            && p.is_relative()
        {
            return Err(format!(
                "--blocksdir must be an absolute path, got {p:?}. Relative paths would \
                be ambiguous against satd's network-suffixed datadir (regtest/, signet/, \
                testnet3/)."
            ));
        }

        // --signetseednode resolution: CLI list wins; else config
        // (multi). Only meaningful on Signet; on other networks the
        // value is parsed and stored but unused. Logging a warning
        // when set off-signet would be noisy for operators with a
        // single config used across networks via `[signet]` sections.
        let signet_seed_nodes: Vec<String> = if !cli.signetseednode.is_empty() {
            cli.signetseednode.clone()
        } else {
            file_get_all("signetseednode")
        };

        let rpc_tls_bind = cli.rpctlsbind.or_else(|| file_get("rpctlsbind"));
        let rpc_tls_cert = cli
            .rpctlscert
            .or_else(|| file_get("rpctlscert").map(std::path::PathBuf::from));
        let rpc_tls_key = cli
            .rpctlskey
            .or_else(|| file_get("rpctlskey").map(std::path::PathBuf::from));
        // Partial-config validation: same shape as Electrum/Esplora
        // TLS. Catching here surfaces a friendlier CLI message than
        // the server-side check; both layers stay so a programmatic
        // caller that bypasses `Config::load` still hits the hard
        // error.
        if rpc_tls_bind.is_some() && (rpc_tls_cert.is_none() || rpc_tls_key.is_none()) {
            return Err("--rpctlsbind requires --rpctlscert AND --rpctlskey".to_string());
        }

        let rpc_mtls = cli
            .rpcmtls
            .or_else(|| file_get("rpcmtls").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let rpc_mtls_client_ca = cli
            .rpcmtlsclientca
            .or_else(|| file_get("rpcmtlsclientca").map(std::path::PathBuf::from));
        let rpc_mtls_client_allow: Vec<String> = {
            let mut values: Vec<String> = cli.rpcmtlsclientallow.clone();
            if values.is_empty() {
                values = file_get_all("rpcmtlsclientallow");
            }
            values
                .into_iter()
                .flat_map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let rpc_disable_auth = cli
            .rpcdisableauth
            .or_else(|| file_get("rpcdisableauth").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let rpc_tls_handshake_timeout = cli
            .rpctlshandshaketimeout
            .or_else(|| {
                file_get("rpctlshandshaketimeout").and_then(|v| v.parse().ok())
            })
            .unwrap_or(10);

        // mTLS validation, mirroring the other surfaces.
        if rpc_mtls && rpc_tls_bind.is_none() {
            return Err("--rpcmtls=1 requires --rpctlsbind".to_string());
        }
        if rpc_mtls && rpc_mtls_client_ca.is_none() {
            return Err("--rpcmtls=1 requires --rpcmtlsclientca".to_string());
        }
        // Refuse `--rpcmtlsclientallow` without `--rpcmtls=1` (review
        // C3). Mirrors the electrum/esplora gates: a non-empty
        // allowlist without an mTLS handshake has no peer cert to
        // match and would reject every TLS connection.
        if !rpc_mtls && !rpc_mtls_client_allow.is_empty() {
            return Err("--rpcmtlsclientallow requires --rpcmtls=1".to_string());
        }
        // --rpcdisableauth only makes sense behind mTLS. The plain-
        // HTTP surface ALWAYS retains its cookie / userpass auth, so
        // this flag never opens an unauthenticated HTTP port; the
        // gate here is "you must have an mTLS surface for this to
        // affect anything," which avoids configuration confusion.
        if rpc_disable_auth && !rpc_mtls {
            return Err("--rpcdisableauth=1 requires --rpcmtls=1".to_string());
        }

        let listen = cli
            .listen
            .or_else(|| file_get("listen").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        let port = cli
            .port
            .or_else(|| file_get("port").and_then(|v| v.parse().ok()))
            .unwrap_or_else(|| default_p2p_port(network));

        let mut connect = cli.connect;
        if connect.is_empty() {
            connect = file_get_all("connect");
        }

        let assumevalid = cli.assumevalid.or_else(|| file_get("assumevalid"));

        let assumevalidage = cli
            .assumevalidage
            .or_else(|| file_get("assumevalidage").and_then(|v| v.parse().ok()))
            .unwrap_or(86400); // default: 24 hours

        let stopatheight = cli
            .stopatheight
            .or_else(|| file_get("stopatheight").and_then(|v| v.parse().ok()));

        // Mempool policy: CLI > config file > defaults
        let mempoolfullrbf = cli
            .mempoolfullrbf
            .or_else(|| file_get("mempoolfullrbf").and_then(|v| parse_bool(&v)))
            .unwrap_or(true); // full RBF on by default (matches Bitcoin Core v28+)

        let maxmempool = cli
            .maxmempool
            .or_else(|| file_get("maxmempool").and_then(|v| v.parse().ok()))
            .unwrap_or(300); // MB

        let minrelaytxfee = cli
            .minrelaytxfee
            .or_else(|| file_get("minrelaytxfee").and_then(|v| v.parse().ok()))
            .or(profile_defaults.minrelaytxfee)
            .unwrap_or(1_000); // sat/kvB

        let dustrelayfee = cli
            .dustrelayfee
            .or_else(|| file_get("dustrelayfee").and_then(|v| v.parse().ok()))
            .unwrap_or(3_000); // sat/kvB

        let datacarriersize = cli
            .datacarriersize
            .or_else(|| file_get("datacarriersize").and_then(|v| v.parse().ok()))
            .unwrap_or(83);

        let datacarrier = cli
            .datacarrier
            .or_else(|| file_get("datacarrier").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        let limitancestorcount = cli
            .limitancestorcount
            .or_else(|| file_get("limitancestorcount").and_then(|v| v.parse().ok()))
            .unwrap_or(25);

        let limitdescendantcount = cli
            .limitdescendantcount
            .or_else(|| file_get("limitdescendantcount").and_then(|v| v.parse().ok()))
            .unwrap_or(25);

        let mempoolexpiry = cli
            .mempoolexpiry
            .or_else(|| file_get("mempoolexpiry").and_then(|v| v.parse().ok()))
            .unwrap_or(336); // hours

        let permitbaremultisig = cli
            .permitbaremultisig
            .or_else(|| file_get("permitbaremultisig").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        // Track whether txindex was explicitly disabled via the
        // config file (CLI can't express that; it's a `bool` flag).
        // The Esplora auto-implication below honors an explicit
        // disable and refuses to silently override the operator.
        //
        // CLI > config-file precedence (round-3 M1): if the operator
        // passes `--txindex` on the command line, that wins even when
        // an old `txindex=0` line is sitting in the config file.
        // Without this, the Esplora hard-fail below would refuse to
        // start despite the operator's clear intent.
        let txindex_file = file_get("txindex").and_then(|v| parse_bool(&v));
        let txindex_explicitly_disabled = !cli.txindex && matches!(txindex_file, Some(false));
        let mut txindex = cli.txindex
            || matches!(txindex_file, Some(true))
            || profile_defaults.txindex.unwrap_or(false);

        // Address-history index: on by default. CLI `--addressindex=0`,
        // config `addressindex=0`, or the Bitcoin-Core-compatible
        // `-noindex=address` alias (translated to `--addressindex=0`
        // pre-clap; see normalize_args) all disable it.
        let addressindex = cli
            .addressindex
            .or_else(|| file_get("addressindex").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);

        // Per-scripthash subscription cap. Default 10000 covers
        // typical xpub-derivation patterns; operators serving public
        // Electrum/Esplora endpoints may want to raise this.
        let addrindexsubscriptions = cli
            .addrindexsubscriptions
            .or_else(|| file_get("addrindexsubscriptions").and_then(|v| v.parse().ok()))
            .unwrap_or(10_000);

        // BIP 158 compact-block-filter index + peerblockfilters: see
        // the resolution block below near line 833 (it includes the
        // `-noindex=blockfilter` alias handling and `peerblockfilters`
        // reconciliation that PR-5 layers on top of PR-3's CLI knob).

        // Esplora REST server: on by default. Disabling requires
        // turning off --addressindex too (Esplora reads through it),
        // but we don't enforce that here — the daemon refuses to
        // start the listener when addressindex=0 and logs the reason.
        let esplora = cli
            .esplora
            .or_else(|| file_get("esplora").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);
        let esplora_bind = cli
            .esplorabind
            .or_else(|| file_get("esplorabind"))
            .unwrap_or_else(|| "127.0.0.1:3000".to_string());
        let esplora_prefix = cli
            .esploraprefix
            .or_else(|| file_get("esploraprefix"))
            .unwrap_or_else(|| "/".to_string());
        let esplora_cors = {
            let mut origins = cli.esploracors.clone();
            if origins.is_empty() {
                origins = file_get_all("esploracors");
            }
            origins
        };
        let esplora_request_timeout = cli
            .esplorarequesttimeout
            .or_else(|| file_get("esplorarequesttimeout").and_then(|v| v.parse().ok()))
            .unwrap_or(30);
        let esplora_max_conns = cli
            .esploramaxconns
            .or_else(|| file_get("esploramaxconns").and_then(|v| v.parse().ok()))
            .unwrap_or(256);
        let esplora_sse_max_conns = cli
            .esplorasseconns
            .or_else(|| file_get("esplorasseconns").and_then(|v| v.parse().ok()))
            .unwrap_or(esplora_max_conns);
        let esplora_auth = cli
            .esploraauth
            .or_else(|| file_get("esploraauth"))
            .map(|s| s.parse::<EsploraAuthMode>())
            .transpose()?
            .unwrap_or_default();
        let esplora_cookie_file = cli
            .esploracookiefile
            .or_else(|| file_get("esploracookiefile").map(std::path::PathBuf::from));
        let esplora_userpass = cli
            .esplorauserpass
            .or_else(|| file_get("esplorauserpass"))
            .map(|s| {
                s.split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .ok_or_else(|| "esplorauserpass: expected user:pass form".to_string())
            })
            .transpose()?;
        if matches!(esplora_auth, EsploraAuthMode::UserPass) && esplora_userpass.is_none() {
            return Err("--esploraauth=userpass requires --esplorauserpass=user:pass".to_string());
        }
        let esplora_tls_bind = cli.esploratlsbind.or_else(|| file_get("esploratlsbind"));
        let esplora_tls_cert = cli
            .esploratlscert
            .or_else(|| file_get("esploratlscert").map(std::path::PathBuf::from));
        let esplora_tls_key = cli
            .esploratlskey
            .or_else(|| file_get("esploratlskey").map(std::path::PathBuf::from));
        let esplora_mtls = cli
            .esploramtls
            .or_else(|| file_get("esploramtls").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let esplora_mtls_client_ca = cli
            .esploramtlsclientca
            .or_else(|| file_get("esploramtlsclientca").map(std::path::PathBuf::from));
        let esplora_mtls_client_allow: Vec<String> = {
            let mut values: Vec<String> = cli.esploramtlsclientallow.clone();
            if values.is_empty() {
                values = file_get_all("esploramtlsclientallow");
            }
            values
                .into_iter()
                .flat_map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        // TLS partial-config validation: same shape as Electrum below.
        // Catching here surfaces a friendlier CLI message than the
        // server-side check; both layers stay so a programmatic caller
        // that bypasses `Config::load` still hits the hard error.
        // Esplora mTLS validation, mirroring the Electrum / RPC shape.
        if esplora_mtls && esplora_tls_bind.is_none() {
            return Err("--esploramtls=1 requires --esploratlsbind".to_string());
        }
        if esplora_mtls && esplora_mtls_client_ca.is_none() {
            return Err("--esploramtls=1 requires --esploramtlsclientca".to_string());
        }
        // Refuse `--esploramtlsclientallow` without `--esploramtls=1`
        // (review C3). See the electrum equivalent: a non-empty
        // allowlist without an mTLS handshake has no peer cert to
        // match and would reject every connection.
        if !esplora_mtls && !esplora_mtls_client_allow.is_empty() {
            return Err("--esploramtlsclientallow requires --esploramtls=1".to_string());
        }
        if esplora_tls_bind.is_some()
            && (esplora_tls_cert.is_none() || esplora_tls_key.is_none())
        {
            return Err(
                "--esploratlsbind requires --esploratlscert AND --esploratlskey".to_string(),
            );
        }

        // ── Electrum ─────────────────────────────────────────────
        let electrum = cli
            .electrum
            .or_else(|| file_get("electrum").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let electrum_bind = cli
            .electrumbind
            .or_else(|| file_get("electrumbind"))
            .unwrap_or_else(|| "127.0.0.1:50001".to_string());
        let electrum_tls_bind = cli.electrumtlsbind.or_else(|| file_get("electrumtlsbind"));
        let electrum_tls_cert = cli
            .electrumtlscert
            .or_else(|| file_get("electrumtlscert").map(std::path::PathBuf::from));
        let electrum_tls_key = cli
            .electrumtlskey
            .or_else(|| file_get("electrumtlskey").map(std::path::PathBuf::from));
        let electrum_mtls = cli
            .electrummtls
            .or_else(|| file_get("electrummtls").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let electrum_mtls_client_ca = cli
            .electrummtlsclientca
            .or_else(|| file_get("electrummtlsclientca").map(std::path::PathBuf::from));
        let electrum_mtls_client_allow: Vec<String> = {
            // Match the `esploracors` pattern: CLI takes precedence; if
            // no CLI values were given, fall back to all matching keys
            // in bitcoin.conf (so `electrummtlsclientallow=alice` lines
            // accumulate). Comma-separated values inside a single flag
            // are split here so operators can pick whichever style.
            let mut values: Vec<String> = cli.electrummtlsclientallow.clone();
            if values.is_empty() {
                values = file_get_all("electrummtlsclientallow");
            }
            values
                .into_iter()
                .flat_map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let electrum_max_conns = cli
            .electrummaxconns
            .or_else(|| file_get("electrummaxconns").and_then(|v| v.parse().ok()))
            .unwrap_or(64);
        let electrum_max_subs_per_conn = cli
            .electrummaxsubsperconn
            .or_else(|| file_get("electrummaxsubsperconn").and_then(|v| v.parse().ok()))
            .unwrap_or(100);
        let electrum_request_timeout = cli
            .electrumrequesttimeout
            .or_else(|| file_get("electrumrequesttimeout").and_then(|v| v.parse().ok()))
            .unwrap_or(30);
        let electrum_max_batch_requests = cli
            .electrummaxbatchrequests
            .or_else(|| file_get("electrummaxbatchrequests").and_then(|v| v.parse().ok()))
            .unwrap_or(16);
        let electrum_max_broadcast_package_txs = cli
            .electrummaxbroadcastpackagetxs
            .or_else(|| file_get("electrummaxbroadcastpackagetxs").and_then(|v| v.parse().ok()))
            .unwrap_or(25);
        let electrum_fee_histogram_ttl = cli
            .electrumfeehistogramttl
            .or_else(|| file_get("electrumfeehistogramttl").and_then(|v| v.parse().ok()))
            .unwrap_or(10);
        let electrum_banner = cli.electrumbanner.or_else(|| file_get("electrumbanner"));

        // BIP 158 filter index. CLI `--blockfilterindex=<0|1|basic>`,
        // config `blockfilterindex=<0|1|basic>`, or
        // `-noindex=blockfilter` (translated to `--blockfilterindex=0`
        // by the alias normalizer, mirroring `-noindex=address`).
        // Off by default per Bitcoin Core's documented stance: the
        // operator pays the disk overhead only when wallets need it.
        let blockfilterindex = cli
            .blockfilterindex
            .or_else(|| file_get("blockfilterindex").and_then(parse_blockfilterindex_value))
            .unwrap_or(false);

        // BIP 157 P2P advertisement and serving.
        let peerblockfilters = cli
            .peerblockfilters
            .or_else(|| file_get("peerblockfilters").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        // TLS partial-config validation. The server-side `bind` also
        // catches this, but checking here lets us surface a friendlier
        // CLI message and refuse to start up.
        if electrum_tls_bind.is_some()
            && (electrum_tls_cert.is_none() || electrum_tls_key.is_none())
        {
            return Err(
                "--electrumtlsbind requires --electrumtlscert AND --electrumtlskey".to_string(),
            );
        }
        // mTLS validation. Strictly additive: enabling mTLS requires
        // an existing TLS surface (cert + key + bind) plus the
        // operator-supplied CA bundle. We catch all three here so the
        // CLI surfaces a single friendly message; the server-side
        // `bind` also checks the CA-without-mTLS combination.
        if electrum_mtls && electrum_tls_bind.is_none() {
            return Err("--electrummtls=1 requires --electrumtlsbind".to_string());
        }
        if electrum_mtls && electrum_mtls_client_ca.is_none() {
            return Err("--electrummtls=1 requires --electrummtlsclientca".to_string());
        }
        // Refuse `--electrummtlsclientallow` without `--electrummtls=1`
        // (review C3): the allowlist runs after a successful handshake
        // and matches the leaf cert's CN/SAN; without mTLS there is no
        // peer cert, and a non-empty allowlist would reject every
        // connection. Surface the misconfiguration at startup rather
        // than as silent connection drops at runtime.
        if !electrum_mtls && !electrum_mtls_client_allow.is_empty() {
            return Err("--electrummtlsclientallow requires --electrummtls=1".to_string());
        }

        let prune = cli
            .prune
            .or_else(|| file_get("prune").and_then(|v| v.parse().ok()))
            .or(profile_defaults.prune)
            .unwrap_or(0); // 0 = no pruning

        // Esplora ↔ txindex coupling (review-2 H3, round-3 M2).
        //
        // Esplora's tx + outspend endpoints depend on txindex. Rather
        // than failing default startup (which the round-1 H3 hard-fail
        // did), reconcile the two flags here:
        //
        //   - prune > 0 + esplora: txindex can't run alongside prune,
        //     so auto-disable Esplora with a warning.
        //   - esplora && !txindex && config didn't explicitly disable
        //     txindex: auto-enable txindex.
        //   - esplora && txindex_explicitly_disabled: hard-fail; the
        //     two flags conflict and the operator made the call.
        //
        // Notes collected here are emitted by `main.rs` after the
        // tracing subscriber is initialized — Config::from_cli runs
        // before `tracing_subscriber::fmt()...init()` (because
        // --log-format selects the formatter), so direct
        // `tracing::warn!` calls would silently drop on the floor.
        let mut pending_notes: Vec<ConfigNote> = Vec::new();
        let mut esplora_resolved = esplora;
        if esplora_resolved && prune > 0 {
            pending_notes.push(ConfigNote {
                level: NoteLevel::Warn,
                message: format!(
                    "esplora requires --txindex, which is incompatible with --prune={prune}; \
                     disabling esplora. Set --esplora=0 explicitly to silence this warning."
                ),
            });
            esplora_resolved = false;
        } else if esplora_resolved && !txindex && !txindex_explicitly_disabled {
            pending_notes.push(ConfigNote {
                level: NoteLevel::Info,
                message: "esplora is enabled; auto-enabling --txindex (required for tx endpoints)"
                    .to_string(),
            });
            txindex = true;
        } else if esplora_resolved && txindex_explicitly_disabled {
            return Err("esplora=1 with txindex=0 in config: refusing to start. \
                 Either remove the txindex=0 line or set esplora=0, \
                 or pass --txindex on the CLI to override the config."
                .into());
        }
        let esplora = esplora_resolved;

        // Electrum ↔ txindex / addressindex coupling. Same shape as
        // the esplora block above. Electrum's transaction.* and
        // get_merkle endpoints need txindex; scripthash.* needs
        // addressindex.
        let mut electrum_resolved = electrum;
        if electrum_resolved && prune > 0 {
            pending_notes.push(ConfigNote {
                level: NoteLevel::Warn,
                message: format!(
                    "electrum requires --txindex, which is incompatible with --prune={prune}; \
                     disabling electrum. Set --electrum=0 explicitly to silence this warning."
                ),
            });
            electrum_resolved = false;
        } else if electrum_resolved && !txindex && !txindex_explicitly_disabled {
            pending_notes.push(ConfigNote {
                level: NoteLevel::Info,
                message:
                    "electrum is enabled; auto-enabling --txindex (required for tx + merkle endpoints)"
                        .to_string(),
            });
            txindex = true;
        } else if electrum_resolved && txindex_explicitly_disabled {
            return Err("electrum=1 with txindex=0 in config: refusing to start. \
                 Either remove the txindex=0 line or set electrum=0, \
                 or pass --txindex on the CLI to override the config."
                .into());
        }
        if electrum_resolved && !addressindex {
            return Err(
                "electrum=1 with addressindex=0 in config: refusing to start. \
                 Electrum reads through the address index — enable it with \
                 --addressindex=1, or set --electrum=0."
                    .into(),
            );
        }
        let electrum = electrum_resolved;

        // BIP 157/158 reconciliation. `--peerblockfilters=1` requires
        // `--blockfilterindex=basic` because the P2P arms read through
        // the index. Mirror the Esplora ↔ addressindex coupling: if
        // the operator only sets `peerblockfilters`, auto-enable the
        // index with a config-load note. If they explicitly disabled
        // the index, refuse to start.
        let mut blockfilterindex_resolved = blockfilterindex;
        let blockfilterindex_explicitly_disabled = cli.blockfilterindex == Some(false)
            || file_get("blockfilterindex")
                .and_then(parse_blockfilterindex_value)
                .map(|v| !v)
                .unwrap_or(false);
        if peerblockfilters && !blockfilterindex_resolved && !blockfilterindex_explicitly_disabled
        {
            pending_notes.push(ConfigNote {
                level: NoteLevel::Info,
                message: "peerblockfilters is enabled; auto-enabling --blockfilterindex=basic \
                          (required for the BIP 157 P2P service to read filter rows)"
                    .to_string(),
            });
            blockfilterindex_resolved = true;
        } else if peerblockfilters && blockfilterindex_explicitly_disabled {
            return Err(
                "peerblockfilters=1 with blockfilterindex=0 in config: refusing to start. \
                 The BIP 157 P2P service reads through the filter index — enable it with \
                 --blockfilterindex=basic, or set --peerblockfilters=0."
                    .into(),
            );
        }
        let blockfilterindex = blockfilterindex_resolved;

        // Validate prune + txindex conflict (now redundant with the
        // esplora reconciliation above for the esplora=1 path, but
        // still catches the operator who explicitly enables both).
        if prune > 0 && txindex {
            return Err("prune mode is incompatible with -txindex".to_string());
        }

        // Validate auth consistency
        if rpcuser.is_some() != rpcpassword.is_some() {
            return Err("rpcuser and rpcpassword must both be set or both be unset".to_string());
        }

        Ok(Config {
            network,
            datadir: base_datadir,
            blocksdir,
            signet_seed_nodes,
            rpcport,
            rpcbind,
            rpcallowip,
            rpcuser,
            rpcpassword,
            rpcauth,
            rpc_cookie_file,
            rpc_cookie_perms,
            rpc_tls_bind,
            rpc_mtls,
            rpc_mtls_client_ca,
            rpc_mtls_client_allow,
            rpc_disable_auth,
            rpc_tls_handshake_timeout,
            rpc_tls_cert,
            rpc_tls_key,
            listen,
            port,
            connect,
            assumevalid,
            assumevalidage,
            stopatheight,
            mempoolfullrbf,
            maxmempool,
            minrelaytxfee,
            dustrelayfee,
            datacarriersize,
            datacarrier,
            limitancestorcount,
            limitdescendantcount,
            mempoolexpiry,
            permitbaremultisig,
            txindex,
            addressindex,
            addrindexsubscriptions,
            esplora,
            esplora_bind,
            esplora_tls_bind,
            esplora_tls_cert,
            esplora_tls_key,
            esplora_mtls,
            esplora_mtls_client_ca,
            esplora_mtls_client_allow,
            esplora_prefix,
            esplora_cors,
            esplora_request_timeout,
            esplora_max_conns,
            esplora_sse_max_conns,
            esplora_auth,
            esplora_cookie_file,
            esplora_userpass,
            electrum,
            electrum_bind,
            electrum_tls_bind,
            electrum_tls_cert,
            electrum_tls_key,
            electrum_mtls,
            electrum_mtls_client_ca,
            electrum_mtls_client_allow,
            electrum_max_conns,
            electrum_max_subs_per_conn,
            electrum_request_timeout,
            electrum_max_batch_requests,
            electrum_max_broadcast_package_txs,
            electrum_fee_histogram_ttl,
            electrum_banner,
            blockfilterindex,
            peerblockfilters,
            prune,
            reindex: cli.reindex,
            reindex_chainstate: cli.reindex_chainstate,
            maxconnections: cli
                .maxconnections
                .or_else(|| file_get("maxconnections").and_then(|v| v.parse().ok()))
                .or(profile_defaults.maxconnections)
                .unwrap_or(125),
            maxinboundperip: cli
                .maxinboundperip
                .or_else(|| file_get("maxinboundperip").and_then(|v| v.parse().ok()))
                .unwrap_or(3),
            bind: cli
                .bind
                .or_else(|| file_get("bind"))
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            timeout: cli
                .timeout
                .or_else(|| file_get("timeout").and_then(|v| v.parse().ok()))
                .unwrap_or(10),
            addnode: {
                let mut nodes = cli.addnode;
                if nodes.is_empty() {
                    nodes = file_get_all("addnode");
                }
                nodes
            },
            dns: cli
                .dns
                .or_else(|| file_get("dns").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
            bantime: cli
                .bantime
                .or_else(|| file_get("bantime").and_then(|v| v.parse().ok()))
                .unwrap_or(86400),
            proxy: cli.proxy.or_else(|| file_get("proxy")),
            onion: cli.onion.or_else(|| file_get("onion")),
            torcontrol: cli.torcontrol.or_else(|| file_get("torcontrol")),
            torpassword: cli.torpassword.or_else(|| file_get("torpassword")),
            onlynet: {
                let mut nets = cli.onlynet;
                if nets.is_empty() {
                    nets = file_get_all("onlynet");
                }
                nets
            },
            blockmaxweight: cli
                .blockmaxweight
                .or_else(|| file_get("blockmaxweight").and_then(|v| v.parse().ok()))
                .unwrap_or(4_000_000),
            blockmintxfee: cli
                .blockmintxfee
                .or_else(|| file_get("blockmintxfee").and_then(|v| v.parse().ok()))
                .unwrap_or(1_000),
            pid: cli.pid.or_else(|| file_get("pid")),
            mcp: cli.mcp
                || file_get("mcp")
                    .and_then(|v| parse_bool(&v))
                    .unwrap_or(false),
            mcp_stdio: cli
                .mcpstdio
                .or_else(|| file_get("mcpstdio").and_then(|v| parse_bool(&v)))
                .unwrap_or(true), // default: enabled when --mcp is set
            mcp_port: cli
                .mcpport
                .or_else(|| file_get("mcpport").and_then(|v| v.parse().ok())),
            mcp_bind: cli
                .mcpbind
                .or_else(|| file_get("mcpbind"))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            dbcache: {
                // Pre-compute static-partition size: the initial budget that
                // the coin/rocksdb partition is built from. For Auto we use
                // the max cap, and the adaptive controller shrinks from there.
                let raw = cli
                    .dbcache
                    .clone()
                    .or_else(|| file_get("dbcache"))
                    .or_else(|| profile_defaults.dbcache.map(|v| v.to_string()))
                    .unwrap_or_else(|| "450".to_string());
                DbCacheSize::parse(&raw)
                    .unwrap_or(DbCacheSize::Fixed(450))
                    .initial_mb()
            },
            dbcache_mode: {
                let raw = cli
                    .dbcache
                    .or_else(|| file_get("dbcache"))
                    .or_else(|| profile_defaults.dbcache.map(|v| v.to_string()))
                    .unwrap_or_else(|| "450".to_string());
                DbCacheSize::parse(&raw).unwrap_or(DbCacheSize::Fixed(450))
            },
            prefetch_workers: cli
                .prefetchworkers
                .or_else(|| file_get("prefetchworkers").and_then(|v| v.parse().ok()))
                .unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(4)
                }),
            max_ahead: {
                let raw = cli
                    .maxahead
                    .or_else(|| file_get("maxahead"))
                    .unwrap_or_else(|| "50000".to_string());
                if raw == "all" {
                    u32::MAX
                } else if raw.ends_with('%') {
                    // Store as a sentinel — will be computed at scheduler creation time
                    // Values > 1_000_000_000 are percentages encoded as 1_000_000_000 + pct
                    let pct: u32 = raw.trim_end_matches('%').parse().unwrap_or(100);
                    1_000_000_000 + pct.min(100)
                } else {
                    raw.parse().unwrap_or(50_000)
                }
            },
            max_open_files: cli
                .maxopenfiles
                .or_else(|| file_get("maxopenfiles").and_then(|v| v.parse().ok()))
                .unwrap_or(2048),
            storage_profile: {
                let raw = cli
                    .storageprofile
                    .clone()
                    .or_else(|| file_get("storageprofile"))
                    .unwrap_or_else(|| "ssd".to_string());
                raw.parse().unwrap_or_else(|e| {
                    eprintln!("warning: {}, falling back to 'ssd'", e);
                    node::storage::profile::StorageProfile::default()
                })
            },
            rocksdb_background_jobs: cli
                .rocksdbbackgroundjobs
                .or_else(|| file_get("rocksdbbackgroundjobs").and_then(|v| v.parse().ok())),
            rocksdb_subcompactions: cli
                .rocksdbsubcompactions
                .or_else(|| file_get("rocksdbsubcompactions").and_then(|v| v.parse().ok())),
            rocksdb_wal_mb: cli
                .rocksdbwalmb
                .or_else(|| file_get("rocksdbwalmb").and_then(|v| v.parse().ok())),
            compaction_diag_interval_secs: cli
                .compactiondiagintervalsecs
                .or_else(|| file_get("compactiondiagintervalsecs").and_then(|v| v.parse().ok()))
                .unwrap_or(60),
            ibd_l0_pause_at: cli
                .ibdl0pauseat
                .or_else(|| file_get("ibdl0pauseat").and_then(|v| v.parse().ok()))
                .unwrap_or(64),
            compaction_interval_secs: cli
                .compactionintervalsecs
                .or_else(|| file_get("compactionintervalsecs").and_then(|v| v.parse().ok()))
                .unwrap_or(1800),
            compaction_l0_at: cli
                .compactionl0at
                .or_else(|| file_get("compactionl0at").and_then(|v| v.parse().ok()))
                .unwrap_or(16),
            stall_watchdog_secs: cli
                .stallwatchdogsecs
                .or_else(|| file_get("stallwatchdogsecs").and_then(|v| v.parse().ok()))
                .unwrap_or(300),
            stall_abort_secs: cli
                .stallabortsecs
                .or_else(|| file_get("stallabortsecs").and_then(|v| v.parse().ok()))
                .unwrap_or(300),
            consensus: {
                let raw = cli
                    .consensus
                    .or_else(|| file_get("consensus"))
                    .unwrap_or_else(|| "rust-shadow".to_string());
                ConsensusEngine::from_str(&raw).unwrap_or_else(|| {
                    eprintln!("Warning: unknown consensus engine '{}', using 'cpp'", raw);
                    ConsensusEngine::Cpp
                })
            },
            shadow_queue_size: cli
                .shadowqueuesize
                .or_else(|| file_get("shadowqueuesize").and_then(|v| v.parse().ok()))
                .unwrap_or(4_194_304),
            shadow_workers: cli
                .shadowworkers
                .or_else(|| file_get("shadowworkers").and_then(|v| v.parse().ok()))
                // --par as fallback for shadow workers (was previously a no-op)
                .or_else(|| {
                    cli.par
                        .or_else(|| file_get("par").and_then(|v| v.parse().ok()))
                        .filter(|&n| n > 0)
                })
                .unwrap_or(4),
            server: cli.server
                || file_get("server")
                    .and_then(|v| parse_bool(&v))
                    .unwrap_or(false),
            daemon: cli.daemon
                || file_get("daemon")
                    .and_then(|v| parse_bool(&v))
                    .unwrap_or(false),
            metricsport: cli
                .metricsport
                .or_else(|| file_get("metricsport").and_then(|v| v.parse().ok())),
            metricsbind: cli
                .metricsbind
                .or_else(|| file_get("metricsbind"))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            rpc_extended_errors: cli.rpcextendederrors
                || file_get("rpcextendederrors")
                    .and_then(|v| parse_bool(&v))
                    .unwrap_or(false),
            max_shutdown_secs: cli
                .maxshutdownsecs
                .or_else(|| file_get("maxshutdownsecs").and_then(|v| v.parse().ok()))
                .unwrap_or(30),
            rpc_default_units: {
                let raw = cli
                    .rpcdefaultunits
                    .or_else(|| file_get("rpcdefaultunits"))
                    .unwrap_or_else(|| "btc".to_string());
                node::rpc::amounts::AmountUnit::parse(&raw)
                    .unwrap_or(node::rpc::amounts::AmountUnit::Btc)
            },
            log_format: {
                let raw = cli
                    .log_format
                    .or_else(|| file_get("logformat"))
                    .unwrap_or_else(|| "text".to_string());
                LogFormat::parse(&raw).unwrap_or_default()
            },
            profile,
            reorg_webhook: cli.reorg_webhook.or_else(|| file_get("reorgwebhook")),
            reorg_webhook_secret: cli
                .reorg_webhook_secret
                .or_else(|| file_get("reorgwebhooksecret")),
            events_node_id: cli.events_node_id.or_else(|| file_get("eventsnodeid")),
            events_region: cli.events_region.or_else(|| file_get("eventsregion")),
            events_grpc_bind: cli.events_grpc_bind.or_else(|| file_get("eventsgrpcbind")),
            events_grpc_allow_remote: cli.events_grpc_allow_remote
                || file_get("eventsgrpcallowremote")
                    .and_then(|v| parse_bool(&v))
                    .unwrap_or(false),
            events_zmq_bind: cli.events_zmq_bind.or_else(|| file_get("eventszmqbind")),
            events_zmq_hashtx: cli
                .events_zmq_hashtx
                .or_else(|| file_get("eventszmqhashtx").and_then(|v| parse_bool(&v))),
            events_zmq_hashblock: cli
                .events_zmq_hashblock
                .or_else(|| file_get("eventszmqhashblock").and_then(|v| parse_bool(&v))),
            events_zmq_mpevict: cli
                .events_zmq_mpevict
                .or_else(|| file_get("eventszmqmpevict").and_then(|v| parse_bool(&v))),
            events_zmq_mpreplace: cli
                .events_zmq_mpreplace
                .or_else(|| file_get("eventszmqmpreplace").and_then(|v| parse_bool(&v))),
            events_zmq_mpconfirm: cli
                .events_zmq_mpconfirm
                .or_else(|| file_get("eventszmqmpconfirm").and_then(|v| parse_bool(&v))),
            events_zmq_nodeevent: cli
                .events_zmq_nodeevent
                .or_else(|| file_get("eventszmqnodeevent").and_then(|v| parse_bool(&v))),
            pending_notes,
        })
    }

    /// Drain operator-facing notes that the resolver collected before
    /// tracing was initialized. Called by `main.rs` immediately after
    /// the subscriber starts so the messages reach the same log stream
    /// as the rest of the daemon. Idempotent — second call returns an
    /// empty vec.
    pub fn take_pending_notes(&mut self) -> Vec<ConfigNote> {
        std::mem::take(&mut self.pending_notes)
    }

    /// Serialize a privacy-safe view of the current config for `getconfig`.
    /// Secret fields (rpcpassword, tor password) are replaced with a
    /// placeholder so the output can be safely logged or shared.
    pub fn effective_view(&self) -> serde_json::Value {
        serde_json::json!({
            "network": self.network.to_string(),
            "datadir": self.datadir.display().to_string(),
            "blocksdir": self.blocksdir.as_ref().map(|p| p.display().to_string()),
            "signet_seed_nodes": self.signet_seed_nodes,
            "profile": self.profile.map(|p| p.as_str()).unwrap_or("(none)"),
            "rpc": {
                "port": self.rpcport,
                "bind": self.rpcbind.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "allowip": self.rpcallowip.iter().map(|e| e.raw.clone()).collect::<Vec<_>>(),
                "user": self.rpcuser.as_deref().unwrap_or("(cookie)"),
                "password": if self.rpcpassword.is_some() { "(set)" } else { "(none)" },
                "rpcauth_users": self.rpcauth.iter().map(|e| e.username.clone()).collect::<Vec<_>>(),
                "cookie_file": self.rpc_cookie_file.as_ref().map(|p| p.display().to_string()),
                "cookie_perms": self.rpc_cookie_perms.as_str(),
                "extended_errors": self.rpc_extended_errors,
                "default_units": self.rpc_default_units.as_str(),
                "tls_bind": self.rpc_tls_bind.clone(),
                "mtls": self.rpc_mtls,
                "mtls_client_allow_count": self.rpc_mtls_client_allow.len(),
                // The plain-HTTP surface always keeps auth; this flag
                // only affects the TLS-with-mTLS surface. Surfacing
                // the bool here lets `getconfig` show the operator
                // exactly which knob is on.
                "disable_auth_on_tls": self.rpc_disable_auth,
                "tls_handshake_timeout_secs": self.rpc_tls_handshake_timeout,
            },
            "p2p": {
                "listen": self.listen,
                "port": self.port,
                "max_connections": self.maxconnections,
                "max_inbound_per_ip": self.maxinboundperip,
                "bind": self.bind,
                "dns": self.dns,
                "connect": self.connect,
                "addnode": self.addnode,
            },
            "mempool": {
                "max_bytes_mb": self.maxmempool,
                "min_relay_tx_fee_sat_per_kvb": self.minrelaytxfee,
                "full_rbf": self.mempoolfullrbf,
                "expiry_hours": self.mempoolexpiry,
            },
            "storage": {
                "txindex": self.txindex,
                "prune_mb": self.prune,
                "dbcache_mb": self.dbcache,
                "dbcache_mode": format!("{:?}", self.dbcache_mode),
            },
            "consensus": format!("{:?}", self.consensus),
            "metrics": {
                "port": self.metricsport,
                "bind": self.metricsbind,
            },
            "log_format": match self.log_format {
                LogFormat::Text => "text",
                LogFormat::Json => "json",
            },
            "max_shutdown_secs": self.max_shutdown_secs,
            "tor": {
                "proxy": self.proxy,
                "onion": self.onion,
                "control": self.torcontrol,
                "password": if self.torpassword.is_some() { "(set)" } else { "(none)" },
            },
            "esplora": {
                "enabled": self.esplora,
                "bind": if self.esplora { Some(self.esplora_bind.clone()) } else { None },
                "tls_bind": if self.esplora { self.esplora_tls_bind.clone() } else { None },
                "mtls": if self.esplora { Some(self.esplora_mtls) } else { None },
                "mtls_client_allow_count": if self.esplora {
                    Some(self.esplora_mtls_client_allow.len())
                } else {
                    None
                },
            },
            "electrum": {
                "enabled": self.electrum,
                "bind": if self.electrum { Some(self.electrum_bind.clone()) } else { None },
                "tls_bind": if self.electrum { self.electrum_tls_bind.clone() } else { None },
                "mtls": if self.electrum { Some(self.electrum_mtls) } else { None },
                "mtls_client_allow_count": if self.electrum {
                    Some(self.electrum_mtls_client_allow.len())
                } else {
                    None
                },
            },
            "block_filter_index": {
                "enabled": self.blockfilterindex,
                "peer_serve": self.peerblockfilters,
            },
        })
    }

    /// Returns the network-specific data directory (e.g. ~/.bitcoin/regtest/).
    pub fn network_datadir(&self) -> PathBuf {
        match self.network {
            Network::Regtest => self.datadir.join("regtest"),
            Network::Testnet => self.datadir.join("testnet3"),
            Network::Signet => self.datadir.join("signet"),
            Network::Bitcoin => self.datadir.clone(),
            _ => self.datadir.clone(),
        }
    }
}

/// CLI arguments compatible with bitcoind flags.
#[derive(Parser, Debug)]
#[command(name = "satd", version, about = "Bitcoin Core-compatible node in Rust")]
pub struct CliArgs {
    #[arg(long, help = "Use regtest network")]
    pub regtest: bool,

    #[arg(long, help = "Use testnet network")]
    pub testnet: bool,

    #[arg(long, help = "Use signet network")]
    pub signet: bool,

    /// Bitcoin Core's unified network selector. Accepted values:
    /// `main`, `test`, `signet`, `regtest`. `testnet4` is recognised
    /// but currently rejected with a clear error — the underlying
    /// chain params are not yet wired through satd (tracked
    /// separately; see SATD_CLI_COMPAT_AUDIT.md). Conflicts with the
    /// older `--regtest`/`--testnet`/`--signet` flags; the operator
    /// must pick one form.
    #[arg(
        long,
        value_name = "NAME",
        help = "Network selector: main|test|signet|regtest. Alternative to --regtest/--testnet/--signet."
    )]
    pub chain: Option<String>,

    #[arg(long, value_name = "DIR", help = "Data directory")]
    pub datadir: Option<PathBuf>,

    /// Alternative location for `blocks/` and the flat-file undo
    /// data. Mirrors Bitcoin Core's `-blocksdir=<dir>`: blocks live
    /// here, chainstate and everything else live under `--datadir`.
    /// Lets operators put a large block archive on a slow disk while
    /// keeping the UTXO set on SSD.
    #[arg(
        long,
        value_name = "DIR",
        help = "Directory holding blocks/ (default: <datadir>/blocks)"
    )]
    pub blocksdir: Option<PathBuf>,

    #[arg(long, value_name = "FILE", help = "Config file path")]
    pub conf: Option<PathBuf>,

    /// Additional signet seed nodes. Mirrors Bitcoin Core's
    /// `-signetseednode=<host[:port]>`. Repeatable. Useful when
    /// running a private signet that isn't in the built-in seed
    /// list. Has no effect on non-signet networks.
    #[arg(
        long,
        value_name = "HOST[:PORT]",
        help = "Additional signet seed node (repeatable). Signet only."
    )]
    pub signetseednode: Vec<String>,

    #[arg(long, value_name = "PORT", help = "RPC server port")]
    pub rpcport: Option<u16>,

    #[arg(long, value_name = "USER", help = "RPC username")]
    pub rpcuser: Option<String>,

    #[arg(long, value_name = "PASS", help = "RPC password")]
    pub rpcpassword: Option<String>,

    /// Address (and optional port) for the plain-HTTP JSON-RPC
    /// listener. Repeatable to listen on multiple interfaces; mirrors
    /// Bitcoin Core's `-rpcbind=<addr>[:port]`. Defaults to
    /// `127.0.0.1:rpcport` only when unset (Core's same posture when
    /// `-rpcallowip` is empty). Non-loopback values REQUIRE at least
    /// one `--rpcallowip` entry or satd refuses to start.
    #[arg(
        long,
        value_name = "ADDR[:PORT]",
        help = "Bind plain-HTTP JSON-RPC to this address (repeatable; default 127.0.0.1:<rpcport>)"
    )]
    pub rpcbind: Vec<String>,

    /// Source-IP allowlist for the JSON-RPC HTTP listener. Mirrors
    /// Bitcoin Core's `-rpcallowip=<ip|cidr>`. Repeatable. Empty list
    /// means loopback only (matches Core). The middleware refuses
    /// non-allowlisted source IPs with HTTP 403 before the auth layer
    /// runs.
    #[arg(
        long,
        value_name = "IP|CIDR",
        help = "Allow JSON-RPC connections from this IP / CIDR (repeatable). Empty list = loopback only."
    )]
    pub rpcallowip: Vec<String>,

    /// Bitcoin-Core-compatible HMAC-SHA256 RPC credential. Format:
    /// `user:salt$hash`. Generated by Core's `share/rpcauth/rpcauth.py`
    /// — paste those lines unchanged. Repeatable.
    #[arg(
        long,
        value_name = "USER:SALT$HASH",
        help = "RPC credential in Bitcoin Core's rpcauth format (repeatable). Use rpcauth.py to generate."
    )]
    pub rpcauth: Vec<String>,

    /// Override the cookie file path. Default `$DATADIR/.cookie`.
    #[arg(
        long,
        value_name = "PATH",
        help = "Override the auto-generated cookie file path (default: $DATADIR/.cookie)"
    )]
    pub rpccookiefile: Option<PathBuf>,

    /// Cookie file filesystem permissions. owner=0600, group=0640,
    /// all=0644. Default `owner`.
    #[arg(
        long,
        value_name = "MODE",
        help = "Cookie file permissions: owner (0600, default) | group (0640) | all (0644)"
    )]
    pub rpccookieperms: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the JSON-RPC TLS listener (requires --rpctlscert and --rpctlskey)"
    )]
    pub rpctlsbind: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS certificate for the JSON-RPC server"
    )]
    pub rpctlscert: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS private key for the JSON-RPC server"
    )]
    pub rpctlskey: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        help = "Require mutual TLS on the JSON-RPC TLS listener (default: false). Requires --rpctlsbind and --rpcmtlsclientca."
    )]
    pub rpcmtls: Option<bool>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM CA bundle used to verify client certificates when --rpcmtls=1"
    )]
    pub rpcmtlsclientca: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Allowlist of accepted client-cert CN / DNS-SAN values (repeatable, comma-separated). Empty = any cert validly signed by the CA."
    )]
    pub rpcmtlsclientallow: Vec<String>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        help = "Disable HTTP Basic auth on the JSON-RPC TLS surface (default: false). Only accepted with --rpcmtls=1. Plain HTTP keeps full auth."
    )]
    pub rpcdisableauth: Option<bool>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Per-handshake timeout for the JSON-RPC TLS surface (default: 10). Lower than Electrum/Esplora (30s) because JSON-RPC clients are typically local. Raise for high-latency links."
    )]
    pub rpctlshandshaketimeout: Option<u64>,

    #[arg(long, value_name = "BOOL", help = "Accept P2P connections")]
    pub listen: Option<bool>,

    #[arg(long, value_name = "PORT", help = "P2P listen port")]
    pub port: Option<u16>,

    #[arg(long, value_name = "ADDR", help = "Connect to specific peer")]
    pub connect: Vec<String>,

    #[arg(
        long,
        value_name = "HASH",
        help = "Skip script verification up to HASH (default: per-network hash, 0=verify all, all=skip old blocks)"
    )]
    pub assumevalid: Option<String>,

    #[arg(
        long,
        value_name = "SECS",
        help = "With --assumevalid=all, verify scripts for blocks newer than SECS (default: 86400)"
    )]
    pub assumevalidage: Option<u64>,

    #[arg(
        long,
        value_name = "HEIGHT",
        help = "Stop running after the active-chain tip reaches HEIGHT (matches Core's -stopatheight)"
    )]
    pub stopatheight: Option<u32>,

    // Mempool policy flags (Bitcoin Core compatible + extensions)
    #[arg(
        long,
        value_name = "BOOL",
        help = "Enable full replace-by-fee (default: true)"
    )]
    pub mempoolfullrbf: Option<bool>,

    #[arg(
        long,
        value_name = "MB",
        help = "Maximum mempool size in MB (default: 300)"
    )]
    pub maxmempool: Option<usize>,

    #[arg(
        long,
        value_name = "RATE",
        help = "Minimum relay fee rate in sat/kvB (default: 1000)"
    )]
    pub minrelaytxfee: Option<u64>,

    #[arg(
        long,
        value_name = "RATE",
        help = "Dust relay fee rate in sat/kvB (default: 3000)"
    )]
    pub dustrelayfee: Option<u64>,

    #[arg(
        long,
        value_name = "BYTES",
        help = "Maximum OP_RETURN size in bytes (default: 83, 0 = reject all)"
    )]
    pub datacarriersize: Option<usize>,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Accept OP_RETURN outputs (default: true)"
    )]
    pub datacarrier: Option<bool>,

    #[arg(
        long,
        value_name = "N",
        help = "Maximum unconfirmed ancestor count (default: 25)"
    )]
    pub limitancestorcount: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Maximum unconfirmed descendant count (default: 25)"
    )]
    pub limitdescendantcount: Option<usize>,

    #[arg(
        long,
        value_name = "HOURS",
        help = "Mempool expiry in hours (default: 336)"
    )]
    pub mempoolexpiry: Option<u64>,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Allow bare multisig outputs (default: true)"
    )]
    pub permitbaremultisig: Option<bool>,

    #[arg(long, help = "Maintain a full transaction index")]
    pub txindex: bool,

    #[arg(long, value_name = "BOOL", value_parser = parse_bool_arg, help = "Maintain an address-history index (default: true). Accepts 0/1/true/false.")]
    pub addressindex: Option<bool>,

    #[arg(
        long,
        value_name = "N",
        help = "Maximum concurrent per-scripthash subscriptions (default: 10000)"
    )]
    pub addrindexsubscriptions: Option<usize>,

    #[arg(long, value_name = "BOOL", value_parser = parse_bool_arg, help = "Run the native Esplora REST server (default: true). Requires --addressindex=1.")]
    pub esplora: Option<bool>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the Esplora REST listener (default: 127.0.0.1:3000)"
    )]
    pub esplorabind: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the Esplora TLS listener (requires --esploratlscert and --esploratlskey)"
    )]
    pub esploratlsbind: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS certificate for the Esplora server"
    )]
    pub esploratlscert: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS private key for the Esplora server"
    )]
    pub esploratlskey: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        help = "Require mutual TLS on the Esplora TLS listener (default: false). Requires --esploratlsbind and --esploramtlsclientca."
    )]
    pub esploramtls: Option<bool>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM CA bundle used to verify client certificates when --esploramtls=1"
    )]
    pub esploramtlsclientca: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Allowlist of accepted client-cert CN / DNS-SAN values (repeatable, comma-separated). Empty = any cert validly signed by the CA."
    )]
    pub esploramtlsclientallow: Vec<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "URL prefix to mount the Esplora API under (default: /)"
    )]
    pub esploraprefix: Option<String>,

    #[arg(
        long,
        value_name = "ORIGIN",
        help = "Allowed CORS origin for the Esplora server (repeat for multiple)"
    )]
    pub esploracors: Vec<String>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Per-request handler timeout for Esplora (default: 30)"
    )]
    pub esplorarequesttimeout: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        help = "Hard cap on concurrent in-flight Esplora requests (default: 256)"
    )]
    pub esploramaxconns: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Hard cap on simultaneously-open Esplora SSE streams (default: same as --esploramaxconns; 0 disables)"
    )]
    pub esplorasseconns: Option<usize>,

    #[arg(
        long,
        value_name = "MODE",
        help = "Esplora authentication: none|cookie|userpass (default: none)"
    )]
    pub esploraauth: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to cookie file when --esploraauth=cookie (default: shared with JSON-RPC)"
    )]
    pub esploracookiefile: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "USER:PASS",
        help = "Static credentials when --esploraauth=userpass"
    )]
    pub esplorauserpass: Option<String>,

    #[arg(long, value_name = "BOOL", value_parser = parse_bool_arg, help = "Run the native Electrum protocol server (default: false). Requires --addressindex=1 and --txindex=1.")]
    pub electrum: Option<bool>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the Electrum plain-TCP listener (default: 127.0.0.1:50001)"
    )]
    pub electrumbind: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the Electrum TLS listener (requires --electrumtlscert and --electrumtlskey)"
    )]
    pub electrumtlsbind: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS certificate for the Electrum server"
    )]
    pub electrumtlscert: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS private key for the Electrum server"
    )]
    pub electrumtlskey: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        help = "Require mutual TLS on the Electrum TLS listener (default: false). Requires --electrumtlsbind and --electrummtlsclientca."
    )]
    pub electrummtls: Option<bool>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM CA bundle used to verify client certificates when --electrummtls=1"
    )]
    pub electrummtlsclientca: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Allowlist of accepted client-cert CN / DNS-SAN values (repeatable, comma-separated). Empty = any cert validly signed by the CA."
    )]
    pub electrummtlsclientallow: Vec<String>,

    #[arg(
        long,
        value_name = "N",
        help = "Hard cap on simultaneously-open Electrum connections (default: 64)"
    )]
    pub electrummaxconns: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Per-connection scripthash subscription cap (default: 100)"
    )]
    pub electrummaxsubsperconn: Option<usize>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Per-request handler timeout for Electrum (default: 30)"
    )]
    pub electrumrequesttimeout: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        help = "Max requests per JSON-RPC batch line (default: 16)"
    )]
    pub electrummaxbatchrequests: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Max txs per blockchain.transaction.broadcast_package (default: 25)"
    )]
    pub electrummaxbroadcastpackagetxs: Option<usize>,

    #[arg(
        long,
        value_name = "SECS",
        help = "TTL (seconds) for mempool.get_fee_histogram cache (default: 10)"
    )]
    pub electrumfeehistogramttl: Option<u64>,

    #[arg(
        long,
        value_name = "TEXT",
        help = "Custom banner returned by server.banner"
    )]
    pub electrumbanner: Option<String>,

    #[arg(
        long,
        value_name = "BOOL_OR_BASIC",
        value_parser = parse_blockfilterindex_arg,
        help = "Build a BIP 158 compact-block-filter index (default: false). Accepts 0/1/basic; \"basic\" is the BIP 158 SCRIPT_FILTER (the only filter type defined today). Required by --peerblockfilters=1 and `getblockfilter`."
    )]
    pub blockfilterindex: Option<bool>,
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        help = "Advertise NODE_COMPACT_FILTERS and answer getcfilters / getcfheaders / getcfcheckpt over P2P (default: false). Implies --blockfilterindex=basic."
    )]
    pub peerblockfilters: Option<bool>,

    #[arg(
        long,
        value_name = "MB",
        help = "Prune block data to target size in MB (0 = no pruning, default: 0)"
    )]
    pub prune: Option<u64>,

    #[arg(
        long,
        help = "Rebuild block index and chain state from block files on disk"
    )]
    pub reindex: bool,

    #[arg(
        long = "reindex-chainstate",
        help = "Rebuild UTXO set from existing block files"
    )]
    pub reindex_chainstate: bool,

    // P2P flags
    #[arg(
        long,
        value_name = "N",
        help = "Maximum total connections (default: 125)"
    )]
    pub maxconnections: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Maximum simultaneous inbound peers from the same source IP (default: 3)"
    )]
    pub maxinboundperip: Option<usize>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Bind P2P to this address (default: 0.0.0.0)"
    )]
    pub bind: Option<String>,

    #[arg(
        long,
        value_name = "SECS",
        help = "P2P connection timeout in seconds (default: 10)"
    )]
    pub timeout: Option<u64>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Add a node to connect to (does not disable DNS seeding)"
    )]
    pub addnode: Vec<String>,

    #[arg(long, value_name = "BOOL", help = "Allow DNS seeding (default: true)")]
    pub dns: Option<bool>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Ban duration in seconds (default: 86400)"
    )]
    pub bantime: Option<u64>,

    // Proxy / Tor flags
    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "SOCKS5 proxy for all outbound connections (e.g. 127.0.0.1:9050)"
    )]
    pub proxy: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "SOCKS5 proxy for .onion connections (defaults to -proxy)"
    )]
    pub onion: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Tor control port for hidden service (e.g. 127.0.0.1:9051)"
    )]
    pub torcontrol: Option<String>,

    #[arg(long, value_name = "PASS", help = "Tor control port password")]
    pub torpassword: Option<String>,

    #[arg(
        long,
        value_name = "NET",
        help = "Restrict to network types: ipv4, ipv6, onion"
    )]
    pub onlynet: Vec<String>,

    // Mining flags
    #[arg(
        long,
        value_name = "WU",
        help = "Maximum block weight for templates (default: 4000000)"
    )]
    pub blockmaxweight: Option<usize>,

    #[arg(
        long,
        value_name = "RATE",
        help = "Minimum tx fee for block template in sat/kvB (default: 1000)"
    )]
    pub blockmintxfee: Option<u64>,

    // Misc flags
    #[arg(long, value_name = "FILE", help = "Write PID to file")]
    pub pid: Option<String>,

    // Cache
    #[arg(
        long,
        value_name = "MB|auto",
        help = "Total write cache size: integer MB, or 'auto' for adaptive sizing (default: 450)"
    )]
    pub dbcache: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help = "Number of IBD prefetch worker threads (default: CPU core count)"
    )]
    pub prefetchworkers: Option<usize>,

    #[arg(
        long,
        value_name = "VALUE",
        help = "Max blocks ahead during IBD: number, 'N%', or 'all' (default: 50000)"
    )]
    pub maxahead: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help = "RocksDB max_open_files cap; -1 = unlimited (default: 2048)"
    )]
    pub maxopenfiles: Option<i32>,

    #[arg(
        long,
        value_name = "PROFILE",
        help = "Storage class for chainstate tuning: ssd (default) or hdd. \
                ssd maxes background parallelism; hdd avoids seek thrash."
    )]
    pub storageprofile: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help = "Override RocksDB max_background_jobs (advanced; default from \
                --storageprofile). Caps concurrent flush + compaction jobs."
    )]
    pub rocksdbbackgroundjobs: Option<i32>,

    #[arg(
        long,
        value_name = "N",
        help = "Override RocksDB max_subcompactions (advanced; default from \
                --storageprofile). Sub-thread parallelism per compaction job."
    )]
    pub rocksdbsubcompactions: Option<u32>,

    #[arg(
        long,
        value_name = "MB",
        help = "Override RocksDB max_total_wal_size in MB (advanced; default \
                from --storageprofile). Must exceed sum of per-CF write \
                buffers (~680 MB on stock schema) to avoid WAL-pressure flushes."
    )]
    pub rocksdbwalmb: Option<u64>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Per-CF pending-compaction diagnostic log interval; 0 disables (default: 60)"
    )]
    pub compactiondiagintervalsecs: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        help = "Pause IBD connector when chainstate L0 SST count >= N; 0 disables (default: 64)"
    )]
    pub ibdl0pauseat: Option<u32>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Periodic forced-compaction interval in seconds; 0 disables (default: 1800)"
    )]
    pub compactionintervalsecs: Option<u64>,

    #[arg(
        long,
        value_name = "N",
        help = "Force chainstate compaction when L0 SST count >= N (default: 16)"
    )]
    pub compactionl0at: Option<u64>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Stall watchdog forensic-dump threshold; 0 disables (default: 300)"
    )]
    pub stallwatchdogsecs: Option<u64>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Stall watchdog additional grace before abort (default: 300)"
    )]
    pub stallabortsecs: Option<u64>,

    #[arg(
        long,
        value_name = "ENGINE",
        help = "Consensus engine: cpp, rust, rust-shadow, cpp-shadow (default: rust-shadow)"
    )]
    pub consensus: Option<String>,

    #[arg(
        long,
        value_name = "N",
        help = "Shadow verification queue capacity (default: 4194304)"
    )]
    pub shadowqueuesize: Option<usize>,

    #[arg(
        long,
        value_name = "N",
        help = "Shadow verification worker threads (default: 4)"
    )]
    pub shadowworkers: Option<usize>,

    // MCP server flags
    #[arg(long, help = "Enable MCP (Model Context Protocol) server")]
    pub mcp: bool,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Enable MCP stdio transport (default: true when --mcp)"
    )]
    pub mcpstdio: Option<bool>,

    #[arg(
        long,
        value_name = "PORT",
        help = "Enable MCP HTTP transport on this port"
    )]
    pub mcpport: Option<u16>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "MCP HTTP bind address (default: 127.0.0.1)"
    )]
    pub mcpbind: Option<String>,

    // Metrics / health HTTP server (unauthenticated — bind to loopback or firewall)
    #[arg(
        long,
        value_name = "PORT",
        help = "Enable Prometheus /metrics + /healthz + /readyz on this port (unauthenticated)"
    )]
    pub metricsport: Option<u16>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Metrics/health HTTP bind address (default: 127.0.0.1)"
    )]
    pub metricsbind: Option<String>,

    // No-op compatibility flags (accepted silently, not wired)
    #[arg(
        long,
        help = "Accept RPC commands (always on, accepted for compatibility)"
    )]
    pub server: bool,

    #[arg(
        long,
        help = "Run in background (use systemd instead, accepted for compatibility)"
    )]
    pub daemon: bool,

    #[arg(
        long,
        value_name = "N",
        help = "Script verification threads (accepted for compatibility)"
    )]
    pub par: Option<usize>,

    #[arg(
        long,
        help = "Emit structured error payloads (category, suggestion, debug) on RPC errors. Default: off (Core-compat)"
    )]
    pub rpcextendederrors: bool,

    #[arg(
        long,
        value_name = "SECS",
        help = "Maximum graceful-shutdown flush duration before force exit (default: 30)"
    )]
    pub maxshutdownsecs: Option<u64>,

    #[arg(
        long,
        value_name = "UNIT",
        help = "Default units for RPC amount fields: 'btc' (Core-compatible, default) or 'sats' (integer satoshis)"
    )]
    pub rpcdefaultunits: Option<String>,

    #[arg(
        long = "log-format",
        value_name = "FORMAT",
        help = "Log output format: 'text' (default, human) or 'json' (one JSON object per event)"
    )]
    pub log_format: Option<String>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Named preset: archival | pruned-home | mining | regtest-dev | signet-watchtower. CLI flags override profile values."
    )]
    pub profile: Option<String>,

    #[arg(
        long = "reorg-webhook",
        value_name = "URL",
        help = "HTTP(S) endpoint receiving POST bodies on reorg detection"
    )]
    pub reorg_webhook: Option<String>,

    #[arg(
        long = "reorg-webhook-secret",
        value_name = "SECRET",
        help = "HMAC-SHA256 secret used to sign webhook bodies via X-Satd-Signature"
    )]
    pub reorg_webhook_secret: Option<String>,

    #[arg(
        long = "events-node-id",
        value_name = "HEX32",
        help = "Stable per-node identifier stamped on every events envelope (32-char hex). Default: auto-generated and persisted to <datadir>/node_id"
    )]
    pub events_node_id: Option<String>,

    #[arg(
        long = "events-region",
        value_name = "TAG",
        help = "Optional region tag stamped on every events envelope (\u{2264}8 printable ASCII bytes, e.g. 'us-east1')"
    )]
    pub events_region: Option<String>,

    #[arg(
        long = "events-grpc-bind",
        value_name = "ADDR",
        help = "host:port to bind the events gRPC streaming server. UNAUTHENTICATED — bind to loopback or use --events-grpc-allow-remote for explicit remote exposure. Default: disabled"
    )]
    pub events_grpc_bind: Option<String>,

    #[arg(
        long = "events-grpc-allow-remote",
        help = "Permit --events-grpc-bind to point at a non-loopback address. Operator must firewall or auth-proxy the endpoint — the sink has no auth"
    )]
    pub events_grpc_allow_remote: bool,

    #[arg(
        long = "events-zmq-bind",
        value_name = "ENDPOINT",
        help = "ZMQ endpoint for the events PUB sink (e.g. 'tcp://0.0.0.0:28332'). Default: disabled"
    )]
    pub events_zmq_bind: Option<String>,

    #[arg(
        long = "events-zmq-hashtx",
        value_name = "BOOL",
        help = "Enable Bitcoin Core-compatible 'hashtx' topic on the events ZMQ sink (default: enabled when --events-zmq-bind is set)"
    )]
    pub events_zmq_hashtx: Option<bool>,

    #[arg(
        long = "events-zmq-hashblock",
        value_name = "BOOL",
        help = "Enable Bitcoin Core-compatible 'hashblock' topic on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_hashblock: Option<bool>,

    #[arg(
        long = "events-zmq-mpevict",
        value_name = "BOOL",
        help = "Enable 'mpevict' topic (mempool eviction with reason) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpevict: Option<bool>,

    #[arg(
        long = "events-zmq-mpreplace",
        value_name = "BOOL",
        help = "Enable 'mpreplace' topic (RBF replacement) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpreplace: Option<bool>,

    #[arg(
        long = "events-zmq-mpconfirm",
        value_name = "BOOL",
        help = "Enable 'mpconfirm' topic (mempool tx confirmed in block) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpconfirm: Option<bool>,

    #[arg(
        long = "events-zmq-nodeevent",
        value_name = "BOOL",
        help = "Enable 'nodeevent' topic (full envelope JSON) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_nodeevent: Option<bool>,
}

/// Translate Bitcoin-Core-compatible index-control aliases that don't
/// have a direct clap counterpart.
///
/// `-noindex=address` / `-index=address` (from Bitcoin Core's
/// `-noindex` / `-index` family) become `--addressindex=0` /
/// `--addressindex=1` so the existing clap parsing applies. Unknown
/// index names are passed through unchanged so the user sees a
/// "no such argument" error instead of silent dropping.
fn translate_index_aliases(args: Vec<String>) -> Vec<String> {
    args.into_iter()
        .map(|arg| match arg.as_str() {
            "-noindex=address" | "--noindex=address" => "--addressindex=0".to_string(),
            "-index=address" | "--index=address" => "--addressindex=1".to_string(),
            // BIP 158 filter-index aliases. Bitcoin Core treats
            // `-blockfilterindex=basic` as the canonical form; we
            // translate both the legacy single-dash and the
            // `-noindex=blockfilter` shorthand here.
            "-noindex=blockfilter" | "--noindex=blockfilter" => "--blockfilterindex=0".to_string(),
            "-index=blockfilter" | "--index=blockfilter" => "--blockfilterindex=basic".to_string(),
            _ => arg,
        })
        .collect()
}

/// Convert Bitcoin Core-style single-dash long flags to clap-compatible double-dash.
/// e.g. `-regtest` → `--regtest`, `-datadir=/path` → `--datadir=/path`
pub fn normalize_args(args: Vec<String>) -> Vec<String> {
    // Translate index-control aliases first so the rest of the
    // pipeline sees the canonical `--addressindex` form.
    let args = translate_index_aliases(args);

    // Known long flags that Bitcoin Core accepts with a single dash
    let known_flags = [
        "regtest",
        "testnet",
        "signet",
        "chain",
        "datadir",
        "blocksdir",
        "signetseednode",
        "conf",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "rpctlsbind",
        "rpctlscert",
        "rpctlskey",
        "rpcmtls",
        "rpcmtlsclientca",
        "rpcmtlsclientallow",
        "rpcdisableauth",
        "rpctlshandshaketimeout",
        "rpcbind",
        "rpcallowip",
        "rpcauth",
        "rpccookiefile",
        "rpccookieperms",
        "listen",
        "port",
        "connect",
        "assumevalid",
        "assumevalidage",
        "stopatheight",
        "mempoolfullrbf",
        "maxmempool",
        "minrelaytxfee",
        "dustrelayfee",
        "datacarriersize",
        "datacarrier",
        "limitancestorcount",
        "limitdescendantcount",
        "mempoolexpiry",
        "permitbaremultisig",
        "txindex",
        "addressindex",
        "addrindexsubscriptions",
        "esplora",
        "esplorabind",
        "esploratlsbind",
        "esploratlscert",
        "esploratlskey",
        "esploramtls",
        "esploramtlsclientca",
        "esploramtlsclientallow",
        "esploraprefix",
        "esploracors",
        "esplorarequesttimeout",
        "esploramaxconns",
        "esplorasseconns",
        "esploraauth",
        "esploracookiefile",
        "esplorauserpass",
        "electrum",
        "electrumbind",
        "electrumtlsbind",
        "electrumtlscert",
        "electrumtlskey",
        "electrummtls",
        "electrummtlsclientca",
        "electrummtlsclientallow",
        "electrummaxconns",
        "electrummaxsubsperconn",
        "electrumrequesttimeout",
        "electrummaxbatchrequests",
        "electrummaxbroadcastpackagetxs",
        "electrumfeehistogramttl",
        "electrumbanner",
        "prune",
        "reindex",
        "reindex-chainstate",
        "maxconnections",
        "maxinboundperip",
        "bind",
        "timeout",
        "addnode",
        "dns",
        "bantime",
        "proxy",
        "onion",
        "torcontrol",
        "torpassword",
        "onlynet",
        "blockmaxweight",
        "blockmintxfee",
        "pid",
        "mcp",
        "mcpstdio",
        "mcpport",
        "mcpbind",
        "metricsport",
        "metricsbind",
        "server",
        "daemon",
        "dbcache",
        "par",
        "maxahead",
        "rpcextendederrors",
        "maxshutdownsecs",
        "rpcdefaultunits",
        "log-format",
        "logformat",
        "profile",
        "reorg-webhook",
        "reorgwebhook",
        "reorg-webhook-secret",
        "reorgwebhooksecret",
    ];

    args.into_iter()
        .map(|arg| {
            // Skip the binary name or already double-dashed args
            if !arg.starts_with('-') || arg.starts_with("--") {
                return arg;
            }
            // Strip the single dash
            let rest = &arg[1..];
            // Check if the rest (before any =) matches a known flag
            let flag_name = rest.split('=').next().unwrap_or(rest);
            if known_flags.contains(&flag_name) {
                format!("-{}", arg) // prepend another dash
            } else {
                arg
            }
        })
        .collect()
}

/// Parsed bitcoin.conf file.
#[derive(Debug, Default)]
pub struct ConfigFile {
    pub global: HashMap<String, Vec<String>>,
    pub sections: HashMap<String, HashMap<String, Vec<String>>>,
}

impl ConfigFile {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut file = ConfigFile::default();
        let mut current_section: Option<String> = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Section header: [name]
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let name = trimmed[1..trimmed.len() - 1].trim().to_string();
                current_section = Some(name);
                continue;
            }

            // Key=value or bare key
            let (key, value) = if let Some(eq_pos) = trimmed.find('=') {
                let k = trimmed[..eq_pos].trim().to_string();
                let v = trimmed[eq_pos + 1..].trim().to_string();
                (k, v)
            } else {
                (trimmed.to_string(), "1".to_string())
            };

            let map = match &current_section {
                Some(section) => file.sections.entry(section.clone()).or_default(),
                None => &mut file.global,
            };
            map.entry(key).or_default().push(value);
        }

        Ok(file)
    }
}

fn default_datadir() -> PathBuf {
    dirs_home().join(".bitcoin")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
        _ => 8332,
    }
}

fn default_p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
        _ => 8333,
    }
}

/// Parse a single `-rpcbind=<addr>[:port]` value. Accepts:
///   - `127.0.0.1`                  → 127.0.0.1:<default_port>
///   - `127.0.0.1:18443`            → 127.0.0.1:18443
///   - `[::1]`                      → [::1]:<default_port>
///   - `[::1]:18443`                → [::1]:18443
///   - `0.0.0.0`, `::`              → wildcards (also legal in Core)
///
/// Bare IPv6 without brackets is rejected — `::1:18443` is ambiguous
/// (could be the IPv6 address `::1:18443` or the address `::1` with
/// port `18443`). Matches Core's behaviour: square brackets are
/// mandatory for IPv6 with port.
fn parse_rpcbind_entry(s: &str, default_port: u16) -> Result<SocketAddr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".to_string());
    }
    // Bracketed IPv6 form
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "missing closing `]` for IPv6 address".to_string())?;
        let ip: Ipv6Addr = host
            .parse()
            .map_err(|e| format!("invalid IPv6 address {host:?}: {e}"))?;
        let port = if after.is_empty() {
            default_port
        } else if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|e| format!("invalid port {p:?}: {e}"))?
        } else {
            return Err(format!("unexpected suffix after IPv6 address: {after:?}"));
        };
        return Ok(SocketAddr::new(IpAddr::V6(ip), port));
    }
    // Already-formed addr:port (no brackets) — accept if it parses
    // directly as a SocketAddr (covers IPv4:port and bare IPv4-mapped
    // forms that std accepts).
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // Bare host: parse as IpAddr, then attach default port. Reject
    // bare IPv6 without brackets per the doc comment above; std's
    // IpAddr::from_str accepts `::1` so we have to filter
    // post-hoc — anything that parses as IPv4 is fine.
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(IpAddr::V4(ip), default_port));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return Err(format!(
            "bare IPv6 address {s:?} requires square brackets: use `[{s}]`"
        ));
    }
    Err(
        "could not parse as IPv4/IPv6 address (with optional :port). Examples: \
        `127.0.0.1`, `127.0.0.1:8332`, `[::1]`, `[::1]:8332`, `0.0.0.0`."
            .to_string(),
    )
}

/// Parse a Bitcoin Core `-chain=<name>` value to a `bitcoin::Network`.
/// Accepts every canonical name Core does plus a few common aliases.
/// `testnet4` is recognised but rejected with a clear error — the
/// chain params aren't wired through satd yet, and silently mapping
/// it to `Network::Testnet` (testnet3) would land an operator's
/// node on the wrong chain.
fn parse_chain_name(s: &str) -> Result<Network, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "test" | "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        "testnet4" => Err(
            "--chain=testnet4 is not yet supported by satd. Use --chain=test for \
            testnet3, or wait for the testnet4 plumbing PR (see \
            SATD_CLI_COMPAT_AUDIT.md)."
                .to_string(),
        ),
        other => Err(format!(
            "--chain: unknown network {other:?}. Accepted values: main, test, signet, regtest."
        )),
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// Clap value-parser wrapper for `parse_bool` so CLI flags can accept
/// the Bitcoin Core convention `=0` / `=1` alongside `true` / `false`.
fn parse_bool_arg(s: &str) -> Result<bool, String> {
    parse_bool(s).ok_or_else(|| format!("expected one of 0/1/true/false/yes/no, got '{s}'"))
}

/// Parse the `blockfilterindex` config value. Bitcoin Core accepts
/// `0`, `1`, and the string `basic` (alias for `1`); we mirror that
/// plus the usual bool spellings. Any other value yields `None` so
/// the caller can fall back to the default (off).
fn parse_blockfilterindex_value(s: String) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "basic" => Some(true),
        other => parse_bool(other),
    }
}

/// Clap value-parser wrapper for `parse_blockfilterindex_value` so the
/// CLI can take `--blockfilterindex=basic` alongside `=0` / `=1`.
fn parse_blockfilterindex_arg(s: &str) -> Result<bool, String> {
    parse_blockfilterindex_value(s.to_string())
        .ok_or_else(|| format!("expected one of 0/1/basic/true/false/yes/no, got '{s}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_args() {
        let args = vec![
            "satd".to_string(),
            "-regtest".to_string(),
            "-datadir=/tmp/test".to_string(),
            "-rpcport".to_string(),
            "18443".to_string(),
        ];
        let normalized = normalize_args(args);
        assert_eq!(normalized[1], "--regtest");
        assert_eq!(normalized[2], "--datadir=/tmp/test");
        assert_eq!(normalized[3], "--rpcport");
    }

    #[test]
    fn test_config_file_parse() {
        let content = r#"
# Global settings
rpcuser=alice
rpcpassword=secret

[regtest]
rpcport=18443
listen=0

[main]
rpcport=8332
"#;
        let cf = ConfigFile::parse(content).unwrap();
        assert_eq!(cf.global.get("rpcuser").unwrap().last().unwrap(), "alice");
        assert_eq!(
            cf.sections
                .get("regtest")
                .unwrap()
                .get("rpcport")
                .unwrap()
                .last()
                .unwrap(),
            "18443"
        );
        assert_eq!(
            cf.sections
                .get("main")
                .unwrap()
                .get("rpcport")
                .unwrap()
                .last()
                .unwrap(),
            "8332"
        );
    }

    #[test]
    fn test_config_file_bare_keys() {
        let content = "listen\nserver\n";
        let cf = ConfigFile::parse(content).unwrap();
        assert_eq!(cf.global.get("listen").unwrap().last().unwrap(), "1");
        assert_eq!(cf.global.get("server").unwrap().last().unwrap(), "1");
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(default_rpc_port(Network::Regtest), 18443);
        assert_eq!(default_rpc_port(Network::Bitcoin), 8332);
        assert_eq!(default_p2p_port(Network::Regtest), 18444);
    }

    #[test]
    fn test_config_from_cli_regtest() {
        let cli = CliArgs {
            regtest: true,
            testnet: false,
            signet: false,
            chain: None,
            blocksdir: None,
            signetseednode: Vec::new(),
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: None,
            rpcpassword: None,
            rpcbind: Vec::new(),
            rpcallowip: Vec::new(),
            rpcauth: Vec::new(),
            rpccookiefile: None,
            rpccookieperms: None,
            rpctlsbind: None,
            rpctlscert: None,
            rpctlskey: None,
            rpcmtls: None,
            rpcmtlsclientca: None,
            rpcmtlsclientallow: vec![],
            rpcdisableauth: None,
            rpctlshandshaketimeout: None,
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            assumevalidage: None,
            stopatheight: None,
            mempoolfullrbf: None,
            maxmempool: None,
            minrelaytxfee: None,
            dustrelayfee: None,
            datacarriersize: None,
            datacarrier: None,
            limitancestorcount: None,
            limitdescendantcount: None,
            mempoolexpiry: None,
            permitbaremultisig: None,
            txindex: false,
            addressindex: None,
            addrindexsubscriptions: None,
            esplora: None,
            esplorabind: None,
            esploratlsbind: None,
            esploratlscert: None,
            esploratlskey: None,
            esploramtls: None,
            esploramtlsclientca: None,
            esploramtlsclientallow: vec![],
            esploraprefix: None,
            esploracors: vec![],
            esplorarequesttimeout: None,
            esploramaxconns: None,
            esplorasseconns: None,
            esploraauth: None,
            esploracookiefile: None,
            esplorauserpass: None,
            electrum: None,
            electrumbind: None,
            electrumtlsbind: None,
            electrumtlscert: None,
            electrumtlskey: None,
            electrummtls: None,
            electrummtlsclientca: None,
            electrummtlsclientallow: vec![],
            electrummaxconns: None,
            electrummaxsubsperconn: None,
            electrumrequesttimeout: None,
            electrummaxbatchrequests: None,
            electrummaxbroadcastpackagetxs: None,
            electrumfeehistogramttl: None,
            electrumbanner: None,
            blockfilterindex: None,
            peerblockfilters: None,
            prune: None,
            reindex: false,
            reindex_chainstate: false,
            maxconnections: None,
            maxinboundperip: None,
            bind: None,
            timeout: None,
            addnode: vec![],
            dns: None,
            bantime: None,
            blockmaxweight: None,
            blockmintxfee: None,
            pid: None,
            server: false,
            daemon: false,
            dbcache: None,
            prefetchworkers: None,
            par: None,
            proxy: None,
            onion: None,
            torcontrol: None,
            torpassword: None,
            onlynet: vec![],
            mcp: false,
            mcpstdio: None,
            mcpport: None,
            mcpbind: None,
            metricsport: None,
            metricsbind: None,
            maxahead: None,
            maxopenfiles: None,
            storageprofile: None,
            rocksdbbackgroundjobs: None,
            rocksdbsubcompactions: None,
            rocksdbwalmb: None,
            compactiondiagintervalsecs: None,
            ibdl0pauseat: None,
            compactionintervalsecs: None,
            compactionl0at: None,
            stallwatchdogsecs: None,
            stallabortsecs: None,
            consensus: None,
            shadowqueuesize: None,
            shadowworkers: None,
            rpcextendederrors: false,
            maxshutdownsecs: None,
            rpcdefaultunits: None,
            log_format: None,
            profile: None,
            reorg_webhook: None,
            reorg_webhook_secret: None,
            events_node_id: None,
            events_region: None,
            events_grpc_bind: None,
            events_grpc_allow_remote: false,
            events_zmq_bind: None,
            events_zmq_hashtx: None,
            events_zmq_hashblock: None,
            events_zmq_mpevict: None,
            events_zmq_mpreplace: None,
            events_zmq_mpconfirm: None,
            events_zmq_nodeevent: None,
        };
        let config = Config::from_cli(cli).unwrap();
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.rpcport, 18443);
        assert_eq!(
            config.network_datadir(),
            PathBuf::from("/tmp/satd-test/regtest")
        );
        assert!(config.mempoolfullrbf); // full RBF on by default
    }

    #[test]
    fn test_config_auth_validation() {
        let cli = CliArgs {
            regtest: true,
            testnet: false,
            signet: false,
            chain: None,
            blocksdir: None,
            signetseednode: Vec::new(),
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: Some("alice".to_string()),
            rpcpassword: None, // missing password
            rpcbind: Vec::new(),
            rpcallowip: Vec::new(),
            rpcauth: Vec::new(),
            rpccookiefile: None,
            rpccookieperms: None,
            rpctlsbind: None,
            rpctlscert: None,
            rpctlskey: None,
            rpcmtls: None,
            rpcmtlsclientca: None,
            rpcmtlsclientallow: vec![],
            rpcdisableauth: None,
            rpctlshandshaketimeout: None,
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            assumevalidage: None,
            stopatheight: None,
            mempoolfullrbf: None,
            maxmempool: None,
            minrelaytxfee: None,
            dustrelayfee: None,
            datacarriersize: None,
            datacarrier: None,
            limitancestorcount: None,
            limitdescendantcount: None,
            mempoolexpiry: None,
            permitbaremultisig: None,
            txindex: false,
            addressindex: None,
            addrindexsubscriptions: None,
            esplora: None,
            esplorabind: None,
            esploratlsbind: None,
            esploratlscert: None,
            esploratlskey: None,
            esploramtls: None,
            esploramtlsclientca: None,
            esploramtlsclientallow: vec![],
            esploraprefix: None,
            esploracors: vec![],
            esplorarequesttimeout: None,
            esploramaxconns: None,
            esplorasseconns: None,
            esploraauth: None,
            esploracookiefile: None,
            esplorauserpass: None,
            electrum: None,
            electrumbind: None,
            electrumtlsbind: None,
            electrumtlscert: None,
            electrumtlskey: None,
            electrummtls: None,
            electrummtlsclientca: None,
            electrummtlsclientallow: vec![],
            electrummaxconns: None,
            electrummaxsubsperconn: None,
            electrumrequesttimeout: None,
            electrummaxbatchrequests: None,
            electrummaxbroadcastpackagetxs: None,
            electrumfeehistogramttl: None,
            electrumbanner: None,
            blockfilterindex: None,
            peerblockfilters: None,
            prune: None,
            reindex: false,
            reindex_chainstate: false,
            maxconnections: None,
            maxinboundperip: None,
            bind: None,
            timeout: None,
            addnode: vec![],
            dns: None,
            bantime: None,
            blockmaxweight: None,
            blockmintxfee: None,
            pid: None,
            server: false,
            daemon: false,
            dbcache: None,
            prefetchworkers: None,
            par: None,
            proxy: None,
            onion: None,
            torcontrol: None,
            torpassword: None,
            onlynet: vec![],
            mcp: false,
            mcpstdio: None,
            mcpport: None,
            mcpbind: None,
            metricsport: None,
            metricsbind: None,
            maxahead: None,
            maxopenfiles: None,
            storageprofile: None,
            rocksdbbackgroundjobs: None,
            rocksdbsubcompactions: None,
            rocksdbwalmb: None,
            compactiondiagintervalsecs: None,
            ibdl0pauseat: None,
            compactionintervalsecs: None,
            compactionl0at: None,
            stallwatchdogsecs: None,
            stallabortsecs: None,
            consensus: None,
            shadowqueuesize: None,
            shadowworkers: None,
            rpcextendederrors: false,
            maxshutdownsecs: None,
            rpcdefaultunits: None,
            log_format: None,
            profile: None,
            reorg_webhook: None,
            reorg_webhook_secret: None,
            events_node_id: None,
            events_region: None,
            events_grpc_bind: None,
            events_grpc_allow_remote: false,
            events_zmq_bind: None,
            events_zmq_hashtx: None,
            events_zmq_hashblock: None,
            events_zmq_mpevict: None,
            events_zmq_mpreplace: None,
            events_zmq_mpconfirm: None,
            events_zmq_nodeevent: None,
        };
        assert!(Config::from_cli(cli).is_err());
    }

    /// `--esploratlsbind` without the matching cert/key flags must be
    /// rejected at config-load time. Catching it here surfaces a
    /// friendlier message than the server-side check; the server still
    /// validates so a programmatic caller that bypasses `Config::load`
    /// hits the same hard error. Mirrors the documented Electrum-TLS
    /// behaviour so an operator who learned the one rule applies it
    /// uniformly.
    #[test]
    fn test_esplora_tls_partial_config_is_rejected() {
        // Missing both cert and key.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esploratlsbind=127.0.0.1:3001",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("esploratlsbind"),
            "expected partial-TLS error, got: {err}"
        );

        // Cert without key.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlscert=/tmp/cert.pem",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        // Key without cert.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlskey=/tmp/key.pem",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        // All three present — config loads cleanly. The actual cert
        // parsing happens at server bind time; here we only verify the
        // flag-shape gate is satisfied.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlscert=/tmp/cert.pem",
            "--esploratlskey=/tmp/key.pem",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("complete --esploratls* triple should load");
        assert_eq!(
            config.esplora_tls_bind.as_deref(),
            Some("127.0.0.1:3001")
        );
    }

    /// `--rpctlsbind` without the matching cert/key flags must be
    /// rejected at config-load time. Mirrors the Electrum and Esplora
    /// TLS shape so an operator who learned the one rule applies it
    /// uniformly across all three surfaces.
    #[test]
    fn test_rpc_tls_partial_config_is_rejected() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpctlsbind"),
            "expected partial-TLS error, got: {err}"
        );

        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlscert=/tmp/cert.pem",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlskey=/tmp/key.pem",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        // All three present — config loads cleanly. Cert parsing
        // happens at server bind time; here we only verify the
        // flag-shape gate is satisfied.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlscert=/tmp/cert.pem",
            "--rpctlskey=/tmp/key.pem",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("complete --rpctls* triple should load");
        assert_eq!(config.rpc_tls_bind.as_deref(), Some("127.0.0.1:8333"));
    }

    /// Electrum mTLS flag-shape validation. `--electrummtls=1` must
    /// pair with `--electrumtlsbind` AND `--electrummtlsclientca`;
    /// either alone is a config-load error. With all three set, the
    /// load proceeds (cert/CA parsing happens later at bind time).
    #[test]
    fn test_electrum_mtls_partial_config_is_rejected() {
        // No TLS surface at all — `--electrummtls=1` without
        // `--electrumtlsbind` must error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--electrum=1",
            "--electrummtls=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("electrumtlsbind") || err.contains("electrummtls"),
            "expected mTLS-without-TLS error, got: {err}"
        );

        // TLS surface present, but no CA bundle — must error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--electrum=1",
            "--electrumtlsbind=127.0.0.1:50002",
            "--electrumtlscert=/tmp/cert.pem",
            "--electrumtlskey=/tmp/key.pem",
            "--electrummtls=1",
            // missing --electrummtlsclientca
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("electrummtlsclientca"),
            "expected missing-CA error, got: {err}"
        );

        // All four present — config loads.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--electrum=1",
            "--electrumtlsbind=127.0.0.1:50002",
            "--electrumtlscert=/tmp/cert.pem",
            "--electrumtlskey=/tmp/key.pem",
            "--electrummtls=1",
            "--electrummtlsclientca=/tmp/ca.pem",
        ])
        .unwrap();
        let config = Config::from_cli(cli)
            .expect("complete --electrummtls* triple plus TLS triple should load");
        assert!(config.electrum_mtls);
        assert_eq!(
            config.electrum_mtls_client_ca.as_deref(),
            Some(std::path::Path::new("/tmp/ca.pem"))
        );
    }

    /// Esplora mTLS flag-shape validation. Mirrors the electrum test.
    #[test]
    fn test_esplora_mtls_partial_config_is_rejected() {
        // mTLS=1 without esplora TLS surface — must error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esplora=1",
            "--esploramtls=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("esploratlsbind") || err.contains("esploramtls"),
            "expected mTLS-without-TLS error, got: {err}"
        );

        // TLS surface present, but no CA bundle — must error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esplora=1",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlscert=/tmp/cert.pem",
            "--esploratlskey=/tmp/key.pem",
            "--esploramtls=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("esploramtlsclientca"),
            "expected missing-CA error, got: {err}"
        );

        // All four present — config loads.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esplora=1",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlscert=/tmp/cert.pem",
            "--esploratlskey=/tmp/key.pem",
            "--esploramtls=1",
            "--esploramtlsclientca=/tmp/ca.pem",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("complete mTLS quad should load");
        assert!(config.esplora_mtls);
        assert_eq!(
            config.esplora_mtls_client_ca.as_deref(),
            Some(std::path::Path::new("/tmp/ca.pem"))
        );
    }

    /// review C3: `--esploramtlsclientallow` without `--esploramtls=1`
    /// would reject every TLS connection (no peer cert to match).
    /// Reject the misconfiguration at startup.
    #[test]
    fn test_esplora_mtls_clientallow_requires_mtls() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--esplora=1",
            "--esploratlsbind=127.0.0.1:3001",
            "--esploratlscert=/tmp/cert.pem",
            "--esploratlskey=/tmp/key.pem",
            "--esploramtlsclientallow=alice",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("esploramtlsclientallow") && err.contains("esploramtls"),
            "expected allowlist-without-mtls error, got: {err}"
        );
    }

    /// RPC mTLS flag-shape validation. Mirrors the Electrum / Esplora
    /// tests so an operator who learned one rule applies it uniformly.
    #[test]
    fn test_rpc_mtls_partial_config_is_rejected() {
        // mTLS without TLS bind — error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpcmtls=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpctlsbind") || err.contains("rpcmtls"),
            "expected mTLS-without-TLS error, got: {err}"
        );

        // TLS bind + cert + key, mTLS on, no CA — error.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlscert=/tmp/cert.pem",
            "--rpctlskey=/tmp/key.pem",
            "--rpcmtls=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpcmtlsclientca"),
            "expected missing-CA error, got: {err}"
        );

        // Full quad — config loads.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlscert=/tmp/cert.pem",
            "--rpctlskey=/tmp/key.pem",
            "--rpcmtls=1",
            "--rpcmtlsclientca=/tmp/ca.pem",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("complete mTLS config should load");
        assert!(config.rpc_mtls);
        assert!(!config.rpc_disable_auth);
    }

    /// `--rpcdisableauth=1` without `--rpcmtls=1` is rejected. Without
    /// the gate an operator could accidentally open a no-auth HTTP
    /// port; we refuse to start to surface the misconfiguration.
    #[test]
    fn test_rpc_disable_auth_requires_mtls() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpcdisableauth=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpcdisableauth") || err.contains("rpcmtls"),
            "expected disable-auth-without-mtls error, got: {err}"
        );
    }

    /// review C3 for the RPC surface: `--rpcmtlsclientallow` without
    /// `--rpcmtls=1` would reject every TLS connection.
    #[test]
    fn test_rpc_mtls_clientallow_requires_mtls() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlsbind=127.0.0.1:8333",
            "--rpctlscert=/tmp/cert.pem",
            "--rpctlskey=/tmp/key.pem",
            "--rpcmtlsclientallow=alice",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpcmtlsclientallow") && err.contains("rpcmtls"),
            "expected allowlist-without-mtls error, got: {err}"
        );
    }

    /// review H2: `--rpctlshandshaketimeout` is parsed and surfaced
    /// on the Config. Default 10s when unset.
    #[test]
    fn test_rpc_tls_handshake_timeout_parses() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
        ])
        .unwrap();
        let config = Config::from_cli(cli).unwrap();
        assert_eq!(config.rpc_tls_handshake_timeout, 10);

        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--rpctlshandshaketimeout=45",
        ])
        .unwrap();
        let config = Config::from_cli(cli).unwrap();
        assert_eq!(config.rpc_tls_handshake_timeout, 45);
    }

    /// Allowlist parsing: comma-separated single flag, repeated
    /// flags, and a mix all collapse to the same `Vec<String>` shape.
    #[test]
    fn test_electrum_mtls_clientallow_parses() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--electrum=1",
            "--electrumtlsbind=127.0.0.1:50002",
            "--electrumtlscert=/tmp/cert.pem",
            "--electrumtlskey=/tmp/key.pem",
            "--electrummtls=1",
            "--electrummtlsclientca=/tmp/ca.pem",
            "--electrummtlsclientallow=alice,bob",
            "--electrummtlsclientallow=carol",
        ])
        .unwrap();
        let config = Config::from_cli(cli).unwrap();
        // Order is not guaranteed (we flatten through iterator), but
        // contents must be exactly the three names with no commas
        // hiding inside.
        let mut names = config.electrum_mtls_client_allow.clone();
        names.sort();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }

    /// review C3: an allowlist set without `--electrummtls=1` would
    /// reject every connection at runtime (no peer cert to match).
    /// Surface that misconfiguration at startup.
    #[test]
    fn test_electrum_mtls_clientallow_requires_mtls() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--electrum=1",
            "--electrumtlsbind=127.0.0.1:50002",
            "--electrumtlscert=/tmp/cert.pem",
            "--electrumtlskey=/tmp/key.pem",
            "--electrummtlsclientallow=alice",
            // Deliberately omit --electrummtls=1.
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("electrummtlsclientallow") && err.contains("electrummtls"),
            "expected allowlist-without-mtls error, got: {err}"
        );
    }

    // ---- PR-1: --rpcbind / --rpcallowip / --rpcauth / cookie tests ----

    #[test]
    fn rpcbind_single_dash_alias_translates() {
        // The five new RPC compat flags must work in Core-style
        // single-dash form via the normalize_args shim. Regression
        // guard so PR-1 doesn't accidentally rely on GNU `--`.
        let args = vec![
            "satd".to_string(),
            "-rpcbind=0.0.0.0".to_string(),
            "-rpcallowip=192.168.1.0/24".to_string(),
            "-rpcauth=alice:abc$def".to_string(),
            "-rpccookiefile=/var/run/satd.cookie".to_string(),
            "-rpccookieperms=group".to_string(),
        ];
        let n = normalize_args(args);
        assert_eq!(n[1], "--rpcbind=0.0.0.0");
        assert_eq!(n[2], "--rpcallowip=192.168.1.0/24");
        assert_eq!(n[3], "--rpcauth=alice:abc$def");
        assert_eq!(n[4], "--rpccookiefile=/var/run/satd.cookie");
        assert_eq!(n[5], "--rpccookieperms=group");
    }

    #[test]
    fn rpcbind_parses_addr_port_combinations() {
        // Bare IPv4 inherits default port.
        let sa = parse_rpcbind_entry("127.0.0.1", 8332).unwrap();
        assert_eq!(sa, "127.0.0.1:8332".parse().unwrap());
        // IPv4 with explicit port.
        let sa = parse_rpcbind_entry("127.0.0.1:18443", 8332).unwrap();
        assert_eq!(sa, "127.0.0.1:18443".parse().unwrap());
        // IPv6 bracketed, no port.
        let sa = parse_rpcbind_entry("[::1]", 8332).unwrap();
        assert_eq!(sa, "[::1]:8332".parse().unwrap());
        // IPv6 bracketed, with port.
        let sa = parse_rpcbind_entry("[::1]:18443", 8332).unwrap();
        assert_eq!(sa, "[::1]:18443".parse().unwrap());
        // Wildcard.
        let sa = parse_rpcbind_entry("0.0.0.0", 8332).unwrap();
        assert_eq!(sa, "0.0.0.0:8332".parse().unwrap());
    }

    #[test]
    fn rpcbind_rejects_bare_ipv6_without_brackets() {
        // `::1:8332` is ambiguous (IPv6 address or `::1` with port?);
        // Core requires brackets for IPv6 + port, satd matches.
        let err = parse_rpcbind_entry("::1", 8332).unwrap_err();
        assert!(
            err.contains("square brackets"),
            "expected brackets advice, got: {err}"
        );
    }

    #[test]
    fn rpcbind_rejects_garbage() {
        assert!(parse_rpcbind_entry("", 8332).is_err());
        assert!(parse_rpcbind_entry("not-an-ip", 8332).is_err());
        assert!(parse_rpcbind_entry("999.0.0.1", 8332).is_err());
    }

    #[test]
    fn rpcauth_entry_parses_core_format() {
        // user:salt$hash. The salt is kept VERBATIM as the string from
        // the line (Core HMAC-keys on its ASCII bytes, not hex-decoded);
        // only the hash is hex-decoded to the 32-byte tag.
        let salt = "000102030405060708090a0b0c0d0e0f";
        let hash_hex = "0".repeat(64); // 32 bytes
        let entry = RpcAuthEntry::parse(&format!("alice:{salt}${hash_hex}")).unwrap();
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.salt, salt);
        assert_eq!(entry.hash.len(), 32);
    }

    #[test]
    fn rpcauth_entry_keeps_non_hex_salt() {
        // Core's rpcauth.py salt is always hex, but the salt field is an
        // opaque HMAC key — we must not require it to be hex-decodable.
        let hash_hex = "0".repeat(64);
        let entry = RpcAuthEntry::parse(&format!("bob:zzNotHex!!${hash_hex}")).unwrap();
        assert_eq!(entry.salt, "zzNotHex!!");
    }

    #[test]
    fn rpcauth_entry_rejects_short_hash() {
        // 16-byte hash is not a valid HMAC-SHA256 tag — guard against
        // truncation typos.
        let err = RpcAuthEntry::parse("alice:abcd$00112233445566778899aabbccddeeff").unwrap_err();
        assert!(err.contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn rpcauth_entry_rejects_missing_separator() {
        let err = RpcAuthEntry::parse("alice-no-colon").unwrap_err();
        assert!(err.contains("user:salt$hash"), "got: {err}");
        let err = RpcAuthEntry::parse("alice:no-dollar").unwrap_err();
        assert!(err.contains("$"), "got: {err}");
    }

    #[test]
    fn cookie_perms_parses_three_modes() {
        assert_eq!(CookiePerms::parse("owner").unwrap(), CookiePerms::Owner);
        assert_eq!(CookiePerms::parse("group").unwrap(), CookiePerms::Group);
        assert_eq!(CookiePerms::parse("all").unwrap(), CookiePerms::All);
        assert_eq!(CookiePerms::parse("OWNER").unwrap(), CookiePerms::Owner);
        assert!(CookiePerms::parse("world").is_err());
    }

    #[test]
    fn cookie_perms_octal_modes() {
        assert_eq!(CookiePerms::Owner.as_mode(), 0o600);
        assert_eq!(CookiePerms::Group.as_mode(), 0o640);
        assert_eq!(CookiePerms::All.as_mode(), 0o644);
    }

    #[test]
    fn non_loopback_bind_requires_allowlist() {
        // Operator binds to 0.0.0.0 without setting --rpcallowip ->
        // Config::load must refuse. This is the misconfigured-
        // exposure case Core specifically guards against, and the
        // single most important static check in PR-1.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-rpc-compat-test1",
            "--rpcbind=0.0.0.0",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("--rpcallowip"),
            "expected allowlist requirement error, got: {err}"
        );
        assert!(
            err.contains("0.0.0.0"),
            "error should echo the offending bind, got: {err}"
        );
    }

    #[test]
    fn loopback_bind_does_not_require_allowlist() {
        // Default + loopback explicit binds both bypass the
        // allowlist-required check.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-rpc-compat-test2",
            "--rpcbind=127.0.0.1",
            "--rpcbind=[::1]",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).expect("loopback-only binds should be accepted");
        assert_eq!(cfg.rpcbind.len(), 2);
        assert!(cfg.rpcbind.iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn non_loopback_bind_with_allowlist_is_accepted() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-rpc-compat-test3",
            "--rpcbind=0.0.0.0",
            "--rpcallowip=192.168.1.0/24",
            "--rpcallowip=10.0.0.0/8",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).expect("non-loopback bind with allowlist should pass");
        assert_eq!(cfg.rpcbind.len(), 1);
        assert_eq!(cfg.rpcallowip.len(), 2);
        assert_eq!(cfg.rpcallowip[0].raw, "192.168.1.0/24");
    }

    #[test]
    fn default_rpcbind_is_single_loopback() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-rpc-compat-test4",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.rpcbind.len(), 1);
        assert!(cfg.rpcbind[0].ip().is_loopback());
        assert_eq!(cfg.rpcbind[0].port(), cfg.rpcport);
    }

    #[test]
    fn rpccookiefile_must_be_absolute() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-rpc-compat-test5",
            "--rpccookiefile=relative/path/.cookie",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("absolute path"),
            "expected absolute-path error, got: {err}"
        );
    }

    // ---- PR-2: --chain / [signet] / --blocksdir / --signetseednode ----

    #[test]
    fn chain_selector_parses_core_names() {
        assert_eq!(parse_chain_name("main").unwrap(), Network::Bitcoin);
        assert_eq!(parse_chain_name("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_chain_name("bitcoin").unwrap(), Network::Bitcoin);
        assert_eq!(parse_chain_name("test").unwrap(), Network::Testnet);
        assert_eq!(parse_chain_name("testnet").unwrap(), Network::Testnet);
        assert_eq!(parse_chain_name("testnet3").unwrap(), Network::Testnet);
        assert_eq!(parse_chain_name("signet").unwrap(), Network::Signet);
        assert_eq!(parse_chain_name("regtest").unwrap(), Network::Regtest);
        // Case-insensitive.
        assert_eq!(parse_chain_name("REGTEST").unwrap(), Network::Regtest);
        assert_eq!(parse_chain_name("Signet").unwrap(), Network::Signet);
    }

    #[test]
    fn chain_selector_rejects_testnet4_with_helpful_error() {
        let err = parse_chain_name("testnet4").unwrap_err();
        assert!(
            err.contains("not yet supported") && err.contains("--chain=test"),
            "expected explicit testnet4 deferral error, got: {err}"
        );
    }

    #[test]
    fn chain_selector_rejects_garbage() {
        let err = parse_chain_name("mainnett").unwrap_err();
        assert!(err.contains("unknown network"), "got: {err}");
    }

    #[test]
    fn chain_flag_routes_to_network() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--chain=regtest",
            "--datadir=/tmp/satd-chain-test1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Regtest);
    }

    #[test]
    fn chain_flag_conflicts_with_old_form() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--chain=regtest",
            "--signet",
            "--datadir=/tmp/satd-chain-test2",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("--chain conflicts"),
            "expected conflict error, got: {err}"
        );
    }

    #[test]
    fn chain_single_dash_alias() {
        let args = vec![
            "satd".to_string(),
            "-chain=signet".to_string(),
            "-blocksdir=/data/blocks".to_string(),
            "-signetseednode=seed.example.com".to_string(),
        ];
        let n = normalize_args(args);
        assert_eq!(n[1], "--chain=signet");
        assert_eq!(n[2], "--blocksdir=/data/blocks");
        assert_eq!(n[3], "--signetseednode=seed.example.com");
    }

    #[test]
    fn blocksdir_must_be_absolute() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-chain-test3",
            "--blocksdir=relative/blocks",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("absolute path"),
            "expected absolute-path error, got: {err}"
        );
    }

    #[test]
    fn blocksdir_absolute_is_accepted() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-chain-test4",
            "--blocksdir=/var/lib/satd-blocks",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(
            cfg.blocksdir.as_ref().unwrap().display().to_string(),
            "/var/lib/satd-blocks"
        );
    }

    #[test]
    fn blocksdir_defaults_to_none() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-chain-test5",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.blocksdir.is_none());
    }

    #[test]
    fn signetseednode_collects_repeated_values() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--signet",
            "--datadir=/tmp/satd-chain-test6",
            "--signetseednode=seed-a.example",
            "--signetseednode=seed-b.example:39333",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.signet_seed_nodes.len(), 2);
        assert_eq!(cfg.signet_seed_nodes[0], "seed-a.example");
        assert_eq!(cfg.signet_seed_nodes[1], "seed-b.example:39333");
    }

    #[test]
    fn signet_section_takes_priority_for_signet() {
        // Before this PR Signet fell through to [main]; verify the
        // [signet] section now routes to Signet correctly. We use
        // rpcport as the marker since it's a simple integer.
        let content = "\
[main]
rpcport=8332
[signet]
rpcport=39999
";
        let tmpdir = tempfile::tempdir().unwrap();
        let conf_path = tmpdir.path().join("bitcoin.conf");
        std::fs::write(&conf_path, content).unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--signet",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.rpcport, 39999, "signet section should win on signet");
    }

    #[test]
    fn chain_from_config_file_global() {
        let content = "chain=regtest\nrpcport=18443\n";
        let tmpdir = tempfile::tempdir().unwrap();
        let conf_path = tmpdir.path().join("bitcoin.conf");
        std::fs::write(&conf_path, content).unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Regtest);
    }
}
