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
/// Controls which script verification engine is used. The default,
/// `rust-shadow`, runs two independent engines and cross-checks every script;
/// the single-engine modes forgo that cross-check.
/// - `rust-shadow` *(default)*: both engines, cpp authoritative, rust shadow
/// - `cpp-shadow`: both engines, rust authoritative, cpp shadow
/// - `cpp`: C++ libbitcoinconsensus FFI only (single engine)
/// - `rust`: pure Rust consensus engine only (single engine)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusEngine {
    /// C++ libbitcoinconsensus FFI, single engine (no shadow cross-check).
    Cpp,
    /// Pure Rust consensus engine, single engine (no shadow cross-check).
    /// The Rust engine passes Core's script test suite and is shadow-validated
    /// against libbitcoinconsensus across mainnet history; the caution here is
    /// only that single-engine mode forgoes the dual-engine cross-check.
    Rust,
    /// Both engines: cpp is authoritative, rust runs in shadow, mismatches logged (default).
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
                txindex: None,
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
    /// Custom signet challenge script (BIP 325), parsed from the
    /// `-signetchallenge` hex. `Some` only on signet; when set, the node
    /// validates each block's signet solution against it and derives the
    /// P2P magic from it. `None` = default signet (or non-signet).
    pub signet_challenge: Option<Vec<u8>>,
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
    /// Max concurrent in-flight RPC method calls (Bitcoin Core
    /// `-rpcthreads`). Bounds how many requests are serviced at once; the
    /// rest queue up to [`Config::rpc_workqueue`]. Default: 16.
    pub rpc_threads: usize,
    /// Max RPC requests allowed to wait beyond [`Config::rpc_threads`]
    /// before the server sheds load (HTTP 429). Bitcoin Core
    /// `-rpcworkqueue`. Default: 64.
    pub rpc_workqueue: usize,
    /// Worker-thread count for the **separate, bounded tokio runtime** that
    /// serves the remotely-consumed *read* surfaces (Esplora, Electrum,
    /// events gRPC, metrics). Isolating these from the consensus/P2P core
    /// runtime means their load can never starve block connection or mempool
    /// acceptance. JSON-RPC and MCP stay on the core runtime (control plane /
    /// block-connecting methods). Default: `max(2, available_parallelism()/4)`.
    pub api_threads: usize,
    /// Opt-in read-only JSON-RPC listener bind addresses
    /// (`-rpcreadonlybind=<addr>[:port]`, repeatable). Non-empty enables a
    /// second listener serving the same methods as `rpcbind` but behind a
    /// read-only filter (reads + mempool submit only) on the bounded API
    /// runtime, so high-volume consumer read traffic can never starve block
    /// connection. Empty (default) = no read-only listener, i.e.
    /// Core-compatible single-listener behavior. Block-connecting and
    /// node-control methods are never served here — they stay on `rpcbind`.
    pub rpc_readonly_bind: Vec<SocketAddr>,
    /// Default TCP port for `rpc_readonly_bind` entries that omit one
    /// (`-rpcreadonlyport`). Default: 8330.
    pub rpc_readonly_port: u16,
    /// Source-IP allowlist for the read-only listener
    /// (`-rpcreadonlyallowip`, repeatable), independent of `rpcallowip`.
    /// Same loopback-only default and non-loopback-requires-allowlist guard.
    pub rpc_readonly_allowip: Vec<IpAllowEntry>,
    /// Max concurrent in-flight calls on the read-only listener
    /// (`-rpcreadonlythreads`). Independent admission budget. Default: same
    /// as `rpc_threads`.
    pub rpc_readonly_threads: usize,
    /// Read-only listener work-queue depth before shedding with HTTP 429
    /// (`-rpcreadonlyworkqueue`). Default: same as `rpc_workqueue`.
    pub rpc_readonly_workqueue: usize,
    /// Optional TLS bind for the read-only listener (`-rpcreadonlytlsbind`).
    /// When set, `rpc_readonly_tls_cert` and `rpc_readonly_tls_key` are
    /// required. Independent of the main listener's `rpctls*`, mirroring the
    /// per-surface TLS shape Esplora/Electrum use. The TLS surface serves the
    /// same read-only-filtered methods on the API runtime.
    pub rpc_readonly_tls_bind: Option<String>,
    pub rpc_readonly_tls_cert: Option<std::path::PathBuf>,
    pub rpc_readonly_tls_key: Option<std::path::PathBuf>,
    /// Require + verify a client certificate on the read-only TLS surface
    /// (`-rpcreadonlymtls`). Requires `rpc_readonly_tls_bind` and
    /// `rpc_readonly_mtls_client_ca`.
    pub rpc_readonly_mtls: bool,
    /// CA bundle that client certs must chain to on the read-only TLS
    /// surface (`-rpcreadonlymtlsclientca`). Required when
    /// `rpc_readonly_mtls = true`.
    pub rpc_readonly_mtls_client_ca: Option<std::path::PathBuf>,
    /// Optional allowlist of client-cert subjects accepted on the read-only
    /// TLS surface (`-rpcreadonlymtlsclientallow`); only meaningful with
    /// mTLS enabled.
    pub rpc_readonly_mtls_client_allow: Vec<String>,
    /// Bitcoin-Core-compatible HMAC-SHA256 RPC credentials. Each entry
    /// is `user:salt$hash` where `hash = hex(HMAC-SHA256(salt, password))`.
    /// Generated by Core's `share/rpcauth/rpcauth.py` — satd consumes
    /// the same format verbatim so a Core operator's existing rpcauth
    /// lines work unchanged. Repeatable so multiple users can be
    /// configured. Coexists with `--rpcuser`/`--rpcpassword` and cookie
    /// auth; any valid credential opens the door.
    pub rpcauth: Vec<RpcAuthEntry>,
    /// Path to the unified-auth bearer-token file (TOML), Core-shaped switch
    /// `authfile=<path>`. `None` (default) keeps today's behavior exactly:
    /// only the Core-compatible cookie/userpass/rpcauth operator path is live.
    /// When set, the TOML token table is loaded at startup (and re-read on
    /// SIGHUP for live revocation) and per-surface participation flags decide
    /// where bearer tokens are honored. Absolute paths only — relative paths
    /// would be ambiguous against the network-suffixed datadir. The file itself
    /// is loaded/validated at startup (see `satd_auth::TokenStore::load`).
    pub authfile: Option<PathBuf>,
    /// Per-surface participation flag: when true, the full read/write JSON-RPC
    /// listeners additionally honor `Authorization: Bearer <token>` (resolving
    /// to a capability-scoped token principal) on top of the Core-compatible
    /// cookie/userpass/rpcauth operator credential. Requires `authfile`. Default
    /// false (operator-only, today's behavior).
    pub rpc_auth_bearer: bool,
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
    /// Bitcoin Core's `-blocksonly`: suppress P2P transaction relay
    /// (advertise relay=false, ignore inbound tx, don't request txs).
    /// Locally submitted (RPC) transactions are still relayed.
    pub blocksonly: bool,
    /// Bitcoin Core's `-v2transport`: offer/accept the BIP 324 v2 encrypted
    /// transport. Defaults to true, matching Bitcoin Core (since v26).
    pub v2transport: bool,
    /// satd-specific `-v2only`: refuse peers that do not speak BIP 324 v2
    /// (drop inbound v1, do not downgrade outbound). Implies `v2transport`.
    /// Defaults to false. Privacy lever — see CORE_DIFFERENCES.md.
    pub v2only: bool,
    pub port: u16,
    pub connect: Vec<String>,
    /// Operator-declared external addresses (Bitcoin Core's
    /// `-externalip`), resolved to socket addresses. Advertised to peers.
    pub externalip: Vec<SocketAddr>,
    /// `-whitelist` permission entries by source subnet (NetPermissions).
    pub whitelist: Vec<node::net::permissions::WhitelistEntry>,
    /// `-whitebind` listeners: an extra bind address plus the permissions
    /// granted to peers that connect to it.
    pub whitebind: Vec<(SocketAddr, node::net::permissions::NetPermissions)>,
    /// Path to a Bitcoin Core `-asmap` file. When set, the addrman
    /// buckets by ASN instead of `/16` for eclipse resistance.
    pub asmap: Option<PathBuf>,
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
    /// Bitcoin Core's `-persistmempool`: save the mempool to
    /// `<datadir>/<chain>/mempool.dat` on clean shutdown and re-admit
    /// it (re-validated) on startup. Default true, matching Core.
    pub persistmempool: bool,
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
    /// Native Esplora REST server (see `docs/manual/src/native-protocol-surfaces.md`). On by
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
    /// Per-surface participation flag: when true, the Esplora server also honors
    /// `Authorization: Bearer <token>` for tokens holding the `esplora:read`
    /// capability, on top of the legacy `esplora_auth` credential. Requires
    /// `authfile`. Default false.
    pub esplora_auth_bearer: bool,
    /// Native Electrum protocol server (see `docs/manual/src/native-protocol-surfaces.md`).
    /// Off by default; `--electrum=1` enables. Requires
    /// `--addressindex=1` AND a complete `--txindex` for the
    /// confirmed-tx and merkle-proof endpoints. Both invariants
    /// are enforced at startup.
    pub electrum: bool,
    /// `host:port` for the plain-TCP Electrum listener. Defaults to
    /// loopback on port 50001 (Electrum's standard plain-TCP port);
    /// expose via Tor / .onion rather than directly on the LAN per
    /// the operator advice in `docs/manual/src/configuration.md`.
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
    /// BIP 158 compact-block-filter index (see
    /// `docs/manual/src/native-protocol-surfaces.md`). Off by default; enable via
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
    pub check_block_index: bool,
    // P2P
    pub maxconnections: usize,
    /// Maximum simultaneous inbound peers from the same source IP
    /// (Core-style flood guard; default 3).
    pub maxinboundperip: usize,
    /// Bitcoin Core's `-maxuploadtarget`: soft cap in bytes on historical
    /// block upload per rolling 24h. 0 = unlimited.
    pub max_upload_target: u64,
    pub bind: String,
    /// P2P connection timeout in **milliseconds**, matching Bitcoin
    /// Core's `-timeout` semantics. Defaults to 5000 (5s) when unset.
    /// Parsed via [`parse_timeout_value`] which also accepts the
    /// suffix-disambiguated forms `5s` / `5000ms`.
    #[allow(dead_code)]
    pub timeout: u64,
    pub addnode: Vec<String>,
    /// One-shot seed peers (Bitcoin Core's `-seednode`, repeatable).
    /// Connected at startup to bootstrap peer discovery, across all
    /// networks (unlike `signet_seed_nodes`, which is signet-only).
    pub seednode: Vec<String>,
    pub dns: bool,
    /// Bitcoin Core's `-dnsseed`: query the DNS seeds for peer
    /// addresses. Default true. satd gates DNS seeding on both `dns`
    /// and `dnsseed`, so either set to false disables it.
    pub dnsseed: bool,
    /// Bitcoin Core's `-forcednsseed`: query DNS seeds even when the
    /// address book already has entries. Default false.
    pub forcednsseed: bool,
    /// Bitcoin Core's `-fixedseeds`: allow falling back to the compiled-in
    /// fixed seed list when the address book is empty and DNS seeding is
    /// off. Default true.
    pub fixedseeds: bool,
    pub bantime: u64,
    // Proxy / Tor
    pub proxy: Option<String>,
    /// Bitcoin Core's `-proxyrandomize`: use fresh random SOCKS5 credentials
    /// per outbound connection so Tor isolates each peer on its own circuit.
    /// Default true; only has effect when `-proxy`/`-onion` is set.
    pub proxyrandomize: bool,
    pub onion: Option<String>,
    pub torcontrol: Option<String>,
    pub torpassword: Option<String>,
    /// Bitcoin Core's `-listenonion`: create a Tor v3 hidden service
    /// via the control port and accept inbound P2P over it. Resolved
    /// to a single bool at load time — see [`Config::load`] for the
    /// default rule (off, unless `-torcontrol` is set). The control
    /// port address is `torcontrol`, defaulting to `127.0.0.1:9051`.
    pub listenonion: bool,
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
    pub mcp_port: Option<u16>,
    pub mcp_bind: String,
    /// Path to PEM-encoded TLS certificate for the MCP HTTP server. When set
    /// (with `mcp_tls_key`), the MCP listener serves HTTPS. Required for any
    /// non-loopback bind so bearer tokens never cross the wire in cleartext.
    pub mcp_tls_cert: Option<std::path::PathBuf>,
    /// Path to PEM-encoded TLS private key for the MCP HTTP server.
    pub mcp_tls_key: Option<std::path::PathBuf>,
    /// Require mutual TLS on the MCP listener. When `true`, `mcp_tls_cert` /
    /// `mcp_tls_key` and `mcp_mtls_client_ca` MUST be set; clients without a
    /// cert validly signed by the CA are refused. Strictly additive — the
    /// `mcp_auth` bearer layer still runs on top.
    pub mcp_mtls: bool,
    /// PEM CA bundle used to verify client certificates when `mcp_mtls = true`.
    pub mcp_mtls_client_ca: Option<std::path::PathBuf>,
    /// Optional allowlist of accepted client-cert subject identities (CN /
    /// DNS-SAN, case-insensitive). Empty means "any CA-signed cert"; non-empty
    /// narrows further.
    pub mcp_mtls_client_allow: Vec<String>,
    /// Require bearer tokens (`mcp:*`) on the MCP HTTP server. Requires
    /// `authfile`. Default false (loopback-trust). Also the precondition for a
    /// non-loopback MCP bind.
    pub mcp_auth: bool,
    /// Permit a non-loopback MCP HTTP bind. Requires `mcp_auth` (and thus
    /// `authfile`). Default false — a non-loopback `mcpbind` without this is
    /// refused at startup, so MCP can never be exposed remotely unauthenticated.
    pub mcp_allow_remote: bool,
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
    /// Bitcoin Core `-debug=<category>` (repeatable). Enables
    /// debug-level tracing for the matching satd subsystem(s). The
    /// special values `1` / `all` enable debug everywhere. See
    /// [`debug_directives`] for the category → tracing-target map.
    pub debug: Vec<String>,
    /// Bitcoin Core `-debugexclude=<category>` (repeatable). Suppresses
    /// debug logging for a category that `debug` would otherwise enable.
    pub debugexclude: Vec<String>,
    /// Named profile the operator selected (if any). Informational —
    /// the profile's effects are already baked into the other fields.
    pub profile: Option<Profile>,
    /// Optional HTTP endpoint receiving reorg-event POSTs. None = the
    /// dispatcher is not started.
    pub reorg_webhook: Option<String>,
    /// Optional HMAC-SHA256 secret for `X-Satd-Signature`. If set, the
    /// dispatcher signs each webhook body. Absent = unsigned POSTs.
    pub reorg_webhook_secret: Option<String>,
    /// AssumeUTXO `--fast-start`: a snapshot source to download and load
    /// at startup. Either an `https://` URL or a local filesystem path
    /// (optionally `file://`). `None` = disabled. Validated at config
    /// time: plain `http://` and `-prune > 0` are rejected. The snapshot
    /// content is verified against the hardcoded anchor hash at load.
    pub fast_start: Option<String>,
    /// Optional expected SHA-256 (lowercased 64-hex) of the `--fast-start`
    /// snapshot file, checked immediately after download as a fast-fail
    /// guard. Opt-in (no canonical published file digest exists, so there
    /// is no default); the mandatory anchor-hash check at load is the
    /// authoritative integrity gate regardless. Validated at config time
    /// to be 32 bytes of hex and to require `--fast-start`.
    pub fast_start_sha256: Option<String>,
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
    /// Per-surface participation flag: when true, every events gRPC `Subscribe`
    /// must present `authorization: Bearer <token>` for a token holding the
    /// `stream:subscribe` capability. Requires `authfile`. Default false
    /// (unauthenticated, loopback-trust — today's behavior).
    pub events_grpc_auth: bool,
    /// Hard cap on simultaneously-open events gRPC connections. A new TCP
    /// connection beyond the cap is dropped at accept. Default: 64. `0`
    /// disables the cap.
    pub events_grpc_max_conns: usize,
    /// Hard cap on concurrent events gRPC `Subscribe` streams across all
    /// connections. A `Subscribe` beyond the cap is rejected with
    /// `RESOURCE_EXHAUSTED`. Default: 256. `0` disables the cap.
    pub events_grpc_max_subscriptions: usize,
    /// `host:port` to bind the streaming JSON-over-WebSocket + SSE transport
    /// (`--streamws`). `None` (default) leaves it disabled. Serves `/ws`
    /// (bidi JSON: firehose + watch-set control + matches) and `/sse`
    /// (read-only JSON firehose) on a dedicated port, on the API runtime —
    /// never the consensus core. Non-loopback bindings are rejected unless
    /// `streamws_allow_remote` is also set.
    pub streamws_bind: Option<String>,
    /// Permit `streamws_bind` to point at a non-loopback address. Default
    /// `false`. Requires `streamws_auth` (a remote bind must be
    /// authenticated).
    pub streamws_allow_remote: bool,
    /// When true, every streamws connection must present
    /// `authorization: Bearer <token>` for a token holding `stream:subscribe`
    /// (watch additions additionally need `stream:watch` + quota). Requires
    /// `authfile`. Default false (unauthenticated, loopback-trust).
    pub streamws_auth: bool,
    /// Hard cap on simultaneously-open streamws connections (`/ws` + `/sse`
    /// combined). A new connection beyond the cap is rejected with HTTP 503.
    /// Mirrors `events_grpc_max_conns`. Default: 256.
    pub streamws_max_conns: usize,
    /// Hard cap on watch-set entries per streamws connection. An add that would
    /// exceed it is shed (the connection stays up). Mirrors
    /// `events_grpc_max_subscriptions` (which is node-wide; this is per-conn).
    /// Default: 256.
    pub streamws_max_subscriptions: usize,
    /// Cap on a single inbound WebSocket message/frame (bytes). Bounds the
    /// `serde_json` parse an authenticated peer can force. Default: 262144
    /// (256 KiB).
    pub streamws_max_message_bytes: usize,
    /// Upper bound on the number of blocks the decoupled watch matcher will
    /// re-scan in one catch-up after it lags behind the chain event broadcast
    /// (see `events::watch`). On a lag the matcher rescans from its last
    /// scanned height to the current tip so watchers do not silently miss
    /// matches; this caps that span so a far-behind matcher cannot stall on an
    /// unbounded rescan. Older blocks beyond the cap are skipped (logged, never
    /// silent); a client can still backfill them via `Subscribe(from_cursor)`.
    /// Default: 10_000. `0` disables the cap (rescan all the way back).
    pub stream_max_resync_blocks: u32,
    /// Minimum allowed bit-length for a privacy-preserving script-prefix watch
    /// (§7.5). A coarser (smaller-`bits`) prefix is a bigger anonymity bucket
    /// but more delivered traffic; this floor bounds the bandwidth/quota a
    /// single prefix can pull. Default: 8.
    pub stream_prefix_min_bits: u32,
    /// Maximum allowed bit-length for a script-prefix watch (§7.5). The
    /// load-bearing privacy bound: capped well short of a full 256-bit
    /// scripthash so a prefix bucket always spans many scripts and cannot
    /// degrade into an exact (leaking) script watch. Also the reference point
    /// for coarseness pricing (a `bits == max` prefix costs one unit). Range
    /// `[stream_prefix_min_bits, 32]`. Default: 32.
    pub stream_prefix_max_bits: u32,
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
    ///
    /// Retained as the canonical entry point (and for the intra-doc links that
    /// reference it); `main` uses [`Config::load_with_cli`] so it can keep the
    /// parsed CLI for SIGHUP reloads.
    #[allow(dead_code)]
    pub fn load() -> Result<Self, String> {
        Self::load_with_cli().map(|(config, _cli)| config)
    }

    /// Like [`Config::load`], but also returns the parsed [`CliArgs`] so the
    /// caller can retain it for the lifetime of the process. The SIGHUP config
    /// reload (`satd::reload`) re-runs [`Config::from_cli`] with this same
    /// `CliArgs`, so CLI flags stay authoritative across reloads and only the
    /// config file is re-read from disk.
    pub fn load_with_cli() -> Result<(Self, CliArgs), String> {
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
        let config = Self::from_cli(cli.clone())?;
        Ok((config, cli))
    }

    /// Build a `Config` from already-parsed CLI args by merging in the config
    /// file and profile/hardcoded defaults.
    ///
    /// Reload-safety contract — the SIGHUP reload path (`satd::reload`) calls
    /// this on every `kill -HUP`, so it MUST be safe to re-run repeatedly:
    /// - never writes to disk (cookie/PID files are written in `main`, not here),
    /// - never mutates global/process state,
    /// - never calls `process::exit` (bad input returns `Err`, which the reload
    ///   path logs while keeping the running config — so a typo'd or unknown
    ///   key can never crash the daemon),
    /// - never panics on operator input.
    ///
    /// The only side effect is a pair of benign `eprintln!` warnings on a
    /// malformed `storageprofile`/`consensus` value (it falls back to the
    /// default). These are idempotent and acceptable; do not add others.
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
        let mut config_file = if conf_path.exists() {
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
        if cli.chain.is_some()
            && (cli.regtest == Some(true)
                || cli.testnet == Some(true)
                || cli.testnet4 == Some(true)
                || cli.signet == Some(true))
        {
            return Err(
                "--chain conflicts with --regtest/--testnet/--testnet4/--signet — pass only one"
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
        } else if cli.regtest == Some(true) || profile_defaults.network_regtest {
            Network::Regtest
        } else if cli.testnet == Some(true) {
            Network::Testnet
        } else if cli.testnet4 == Some(true) {
            Network::Testnet4
        } else if cli.signet == Some(true) || profile_defaults.network_signet {
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
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Bitcoin => "main",
        };

        // Resolve `includeconf` directives now that the active network
        // section is known. Core processes includes from the global
        // scope plus the running network's section; an included file's
        // settings are merged into `config_file` before any `file_get`
        // lookup below sees them. Notes (ignored nested includes) are
        // carried into `pending_notes` for main.rs to emit. A config
        // chain= inside an included file does NOT change the network —
        // network is resolved from the main file + CLI above, matching
        // Core's need to know the chain before section selection.
        let mut include_notes: Vec<ConfigNote> = Vec::new();
        if let Some(cf) = config_file.as_mut() {
            include_notes = cf.resolve_includes(&base_datadir, section)?;
        }
        // Command-line -includeconf is rejected, the same as Bitcoin Core:
        // includes are a config-file-only feature (a command-line include
        // can't be processed before the config file is read), and Core
        // hard-errors rather than starting up having silently dropped a
        // config the operator asked for. This also upholds this stack's
        // rule: every recognised key is honoured or explicitly rejected,
        // never accepted-and-ignored.
        if !cli.includeconf.is_empty() {
            return Err(format!(
                "-includeconf cannot be used from commandline; -includeconf={} \
                 (includeconf is only honoured inside a config file, matching Bitcoin Core)",
                cli.includeconf[0]
            ));
        }

        // Helper: look up a single-valued key from the config file. The
        // active network section wins over the global scope (Core merges
        // the network-specific section ahead of the default section).
        // Within a scope we take the FIRST occurrence, matching Bitcoin
        // Core's `reverse_precedence` for config-file settings
        // (common/settings.cpp: "Take first assigned value instead of last
        // ... for backwards compatibility in the config file the precedence
        // is reversed for all settings except chain type settings"). Since
        // `includeconf` appends an included file's values *after* the main
        // file's (see `merge_from`), first-wins means the main file always
        // beats an included file for a key set in both — independent of
        // where the `includeconf=` directive sits. The `chain=` selector
        // above is Core's documented exception and keeps last-wins.
        let file_get = |key: &str| -> Option<String> {
            config_file.as_ref().and_then(|cf| {
                cf.sections
                    .get(section)
                    .and_then(|s| s.get(key))
                    .and_then(|v| v.first().cloned())
                    .or_else(|| cf.global.get(key).and_then(|v| v.first().cloned()))
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

        // Unified-auth bearer-token file. CLI > file > unset. Absolute paths
        // only (same rationale as the cookie file). The TOML is loaded and
        // validated at startup (`satd_auth::TokenStore::load`), not here —
        // config parsing stays IO-light and reload-safe.
        let authfile = cli
            .authfile
            .or_else(|| file_get("authfile").map(PathBuf::from));
        if let Some(p) = &authfile
            && p.is_relative()
        {
            return Err(format!(
                "--authfile must be an absolute path, got {p:?}. Relative paths would be \
                ambiguous against satd's network-suffixed datadir (regtest/, signet/, \
                testnet3/)."
            ));
        }

        // Per-surface participation flag for the JSON-RPC listeners. Honoring
        // bearer tokens requires a token table to honor them against.
        let rpc_auth_bearer = cli
            .rpcauthbearer
            .or_else(|| file_get("rpcauthbearer").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if rpc_auth_bearer && authfile.is_none() {
            return Err(
                "--rpcauthbearer requires --authfile (there is no token table to honor \
                 bearer tokens against)"
                    .to_string(),
            );
        }

        let rpcuser = cli.rpcuser.or_else(|| file_get("rpcuser"));
        let rpcpassword = cli.rpcpassword.or_else(|| file_get("rpcpassword"));

        // RPC admission control (Core-compatible knobs). `-rpcthreads`
        // bounds concurrent in-flight method calls; `-rpcworkqueue` bounds
        // how many more may wait before the server sheds load (HTTP 429).
        // Defaults match Bitcoin Core (16 / 64).
        let rpc_threads = cli
            .rpcthreads
            .or_else(|| file_get("rpcthreads").and_then(|v| v.parse().ok()))
            .unwrap_or(16);
        let rpc_workqueue = cli
            .rpcworkqueue
            .or_else(|| file_get("rpcworkqueue").and_then(|v| v.parse().ok()))
            .unwrap_or(64);

        // Worker count for the isolated API runtime. Default is a modest
        // fraction of host parallelism (the core runtime keeps the rest),
        // floored at 2 so the API surfaces always have more than one worker.
        // Clamped to a sane ceiling so a fat-fingered value can't make the
        // tokio runtime builder fail to spawn the threads and panic the
        // daemon at boot (the builder is `.expect()`-ed in main); no real
        // host benefits from more than this many API worker threads.
        let api_threads = cli
            .apithreads
            .or_else(|| file_get("apithreads").and_then(|v| v.parse().ok()))
            .unwrap_or_else(default_api_threads)
            .clamp(1, 1024);

        // --- Opt-in read-only JSON-RPC listener (satd extension) ---
        // A second listener serving the same methods behind a read-only
        // filter (reads + mempool submit), on the bounded API runtime. Off by
        // default (empty bind list) for Core-compatible single-listener
        // behavior. Resolution mirrors `rpcbind`/`rpcallowip`: CLI list wins,
        // else config file (repeatable).
        let rpc_readonly_port = cli
            .rpcreadonlyport
            .or_else(|| file_get("rpcreadonlyport").and_then(|v| v.parse().ok()))
            .unwrap_or(8330);
        let rpc_readonly_bind_raw: Vec<String> = if !cli.rpcreadonlybind.is_empty() {
            cli.rpcreadonlybind.clone()
        } else {
            file_get_all("rpcreadonlybind")
        };
        let mut rpc_readonly_bind: Vec<SocketAddr> = Vec::new();
        for entry in &rpc_readonly_bind_raw {
            let parsed = parse_rpcbind_entry(entry, rpc_readonly_port)
                .map_err(|e| format!("invalid --rpcreadonlybind value {entry:?}: {e}"))?;
            rpc_readonly_bind.push(parsed);
        }
        let rpc_readonly_allowip_raw: Vec<String> = if !cli.rpcreadonlyallowip.is_empty() {
            cli.rpcreadonlyallowip.clone()
        } else {
            file_get_all("rpcreadonlyallowip")
        };
        let mut rpc_readonly_allowip: Vec<IpAllowEntry> = Vec::new();
        for entry in &rpc_readonly_allowip_raw {
            rpc_readonly_allowip.push(IpAllowEntry::parse(entry)?);
        }
        // Same accidental-exposure guard as the main listener: a non-loopback
        // read-only bind requires an explicit allowlist. (The read-only
        // listener is the surface most likely to be exposed publicly, so this
        // guard matters even more here.)
        if !rpc_readonly_bind.is_empty() {
            let any_non_loopback = rpc_readonly_bind.iter().any(|a| !a.ip().is_loopback());
            if any_non_loopback && rpc_readonly_allowip.is_empty() {
                let exposed: Vec<String> = rpc_readonly_bind
                    .iter()
                    .filter(|a| !a.ip().is_loopback())
                    .map(|a| a.to_string())
                    .collect();
                return Err(format!(
                    "--rpcreadonlybind on non-loopback address(es) {exposed:?} requires at least \
                     one --rpcreadonlyallowip entry (refusing to expose the read-only RPC listener \
                     without a source-IP allowlist)"
                ));
            }
        }
        // Read-only admission budget defaults to the main listener's values.
        let rpc_readonly_threads = cli
            .rpcreadonlythreads
            .or_else(|| file_get("rpcreadonlythreads").and_then(|v| v.parse().ok()))
            .unwrap_or(rpc_threads)
            .max(1);
        let rpc_readonly_workqueue = cli
            .rpcreadonlyworkqueue
            .or_else(|| file_get("rpcreadonlyworkqueue").and_then(|v| v.parse().ok()))
            .unwrap_or(rpc_workqueue);

        // Read-only listener TLS + optional mTLS. Independent of the main
        // listener's `rpctls*`, mirroring the per-surface TLS shape used by
        // Esplora/Electrum. The handshake timeout is shared with the main RPC
        // TLS surface (`rpc_tls_handshake_timeout`), not a separate knob.
        let rpc_readonly_tls_bind =
            cli.rpcreadonlytlsbind.or_else(|| file_get("rpcreadonlytlsbind"));
        let rpc_readonly_tls_cert = cli
            .rpcreadonlytlscert
            .or_else(|| file_get("rpcreadonlytlscert").map(std::path::PathBuf::from));
        let rpc_readonly_tls_key = cli
            .rpcreadonlytlskey
            .or_else(|| file_get("rpcreadonlytlskey").map(std::path::PathBuf::from));
        if rpc_readonly_tls_bind.is_some()
            && (rpc_readonly_tls_cert.is_none() || rpc_readonly_tls_key.is_none())
        {
            return Err(
                "--rpcreadonlytlsbind requires --rpcreadonlytlscert AND --rpcreadonlytlskey"
                    .to_string(),
            );
        }
        let rpc_readonly_mtls = cli
            .rpcreadonlymtls
            .or_else(|| file_get("rpcreadonlymtls").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let rpc_readonly_mtls_client_ca = cli
            .rpcreadonlymtlsclientca
            .or_else(|| file_get("rpcreadonlymtlsclientca").map(std::path::PathBuf::from));
        let rpc_readonly_mtls_client_allow: Vec<String> = {
            let mut values: Vec<String> = cli.rpcreadonlymtlsclientallow.clone();
            if values.is_empty() {
                values = file_get_all("rpcreadonlymtlsclientallow");
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
        if rpc_readonly_mtls && rpc_readonly_tls_bind.is_none() {
            return Err("--rpcreadonlymtls=1 requires --rpcreadonlytlsbind".to_string());
        }
        if rpc_readonly_mtls && rpc_readonly_mtls_client_ca.is_none() {
            return Err("--rpcreadonlymtls=1 requires --rpcreadonlymtlsclientca".to_string());
        }
        if !rpc_readonly_mtls && !rpc_readonly_mtls_client_allow.is_empty() {
            return Err("--rpcreadonlymtlsclientallow requires --rpcreadonlymtls=1".to_string());
        }

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

        // -signetchallenge selects a custom signet (BIP 325). Parsed
        // from hex; rejected on non-signet networks (it has no meaning
        // there and silently ignoring it would be the accept-and-ignore
        // hazard the strict parser exists to prevent).
        let signet_challenge: Option<Vec<u8>> = {
            let raw = cli
                .signetchallenge
                .clone()
                .or_else(|| file_get("signetchallenge"));
            match raw {
                Some(hex) => {
                    if network != Network::Signet {
                        return Err(format!(
                            "signetchallenge is only valid on signet (network is {network:?}); \
                             remove it or select signet with --signet / --chain=signet"
                        ));
                    }
                    let bytes = <Vec<u8> as bitcoin::hashes::hex::FromHex>::from_hex(hex.trim())
                        .map_err(|e| format!("signetchallenge is not valid hex: {e}"))?;
                    if bytes.is_empty() {
                        return Err("signetchallenge must not be empty".to_string());
                    }
                    Some(bytes)
                }
                None => None,
            }
        };

        // -torcontrol address is needed both for the `torcontrol`
        // Config field and to resolve -listenonion's default below, so
        // hoist it out of the struct literal.
        let torcontrol = cli.torcontrol.clone().or_else(|| file_get("torcontrol"));

        // -listenonion gates Tor hidden-service creation. Bitcoin Core
        // defaults it on (but it's a silent no-op without a reachable
        // control port); satd defaults it OFF to avoid dialing the
        // control port on every boot, with one backward-compat
        // carve-out: an explicitly-set -torcontrol implies opting in
        // (that was satd's original trigger for the hidden service),
        // unless -listenonion=0 overrides. The control-port address
        // defaults to Core's 127.0.0.1:9051 at use time (see main.rs).
        let listenonion = cli
            .listenonion
            .or_else(|| file_get("listenonion").and_then(|v| parse_bool(&v)))
            .unwrap_or_else(|| torcontrol.is_some());

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

        let blocksonly = cli
            .blocksonly
            .or_else(|| file_get("blocksonly").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);

        // -v2transport defaults on, matching Bitcoin Core since v26.
        let v2transport = cli
            .v2transport
            .or_else(|| file_get("v2transport").and_then(|v| parse_bool(&v)))
            .unwrap_or(true);
        // -v2only is satd-specific and off by default; it implies v2transport.
        let v2only = cli
            .v2only
            .or_else(|| file_get("v2only").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);

        // -externalip: CLI list wins, else config (multi). Each entry is
        // `IP` or `IP:port`; a bare IP inherits the network P2P port.
        let externalip_raw: Vec<String> = if !cli.externalip.is_empty() {
            cli.externalip.clone()
        } else {
            file_get_all("externalip")
        };
        let mut externalip: Vec<SocketAddr> = Vec::with_capacity(externalip_raw.len());
        for raw in &externalip_raw {
            let s = raw.trim();
            if let Ok(sa) = s.parse::<SocketAddr>() {
                externalip.push(sa);
            } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                externalip.push(SocketAddr::new(ip, default_p2p_port(network)));
            } else {
                return Err(format!(
                    "externalip: {s:?} is not an IP or IP:port. satd's externalip accepts \
                     literal addresses only (hostnames/.onion are not resolved here)."
                ));
            }
        }

        // -whitelist: per-subnet net permissions.
        let whitelist_raw: Vec<String> = if !cli.whitelist.is_empty() {
            cli.whitelist.clone()
        } else {
            file_get_all("whitelist")
        };
        let mut whitelist: Vec<node::net::permissions::WhitelistEntry> =
            Vec::with_capacity(whitelist_raw.len());
        for raw in &whitelist_raw {
            whitelist.push(
                node::net::permissions::WhitelistEntry::parse(raw)
                    .map_err(|e| format!("whitelist: {e}"))?,
            );
        }

        // -whitebind: extra permissioned listeners. `[perms@]addr`, addr
        // is a literal `IP:port` (a bare IP inherits the network port).
        let whitebind_raw: Vec<String> = if !cli.whitebind.is_empty() {
            cli.whitebind.clone()
        } else {
            file_get_all("whitebind")
        };
        let mut whitebind: Vec<(SocketAddr, node::net::permissions::NetPermissions)> =
            Vec::with_capacity(whitebind_raw.len());
        for raw in &whitebind_raw {
            let (perms, addr_str) = match raw.split_once('@') {
                Some((p, a)) => (
                    node::net::permissions::NetPermissions::parse_list(p)
                        .map_err(|e| format!("whitebind: {e}"))?,
                    a.trim(),
                ),
                None => (
                    node::net::permissions::NetPermissions::implicit(),
                    raw.trim(),
                ),
            };
            let sa = if let Ok(sa) = addr_str.parse::<SocketAddr>() {
                sa
            } else if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, default_p2p_port(network))
            } else {
                return Err(format!(
                    "whitebind: {addr_str:?} is not an IP or IP:port"
                ));
            };
            whitebind.push((sa, perms));
        }

        // -asmap: path to the ASN map file, resolved against datadir.
        let asmap: Option<PathBuf> = {
            let raw = cli.asmap.clone().or_else(|| file_get("asmap"));
            match raw {
                Some(p) => {
                    let path = if Path::new(&p).is_absolute() {
                        PathBuf::from(&p)
                    } else {
                        base_datadir.join(&p)
                    };
                    if !path.exists() {
                        return Err(format!("asmap file not found: {}", path.display()));
                    }
                    Some(path)
                }
                None => None,
            }
        };

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
        let txindex_explicitly_disabled = cli.txindex == Some(false)
            || (cli.txindex.is_none() && matches!(txindex_file, Some(false)));
        let mut txindex = cli.txindex.unwrap_or_else(|| {
            matches!(txindex_file, Some(true)) || profile_defaults.txindex.unwrap_or(false)
        });

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
        let esplora_auth_bearer = cli
            .esploraauthbearer
            .or_else(|| file_get("esploraauthbearer").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if esplora_auth_bearer && authfile.is_none() {
            return Err(
                "--esploraauthbearer requires --authfile (there is no token table to honor \
                 bearer tokens against)"
                    .to_string(),
            );
        }
        let events_grpc_auth = cli
            .events_grpc_auth
            .or_else(|| file_get("eventsgrpcauth").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if events_grpc_auth && authfile.is_none() {
            return Err(
                "--events-grpc-auth requires --authfile (there is no token table to honor \
                 bearer tokens against)"
                    .to_string(),
            );
        }
        let events_grpc_allow_remote = cli.events_grpc_allow_remote.unwrap_or_else(|| {
            file_get("eventsgrpcallowremote").and_then(|v| parse_bool(&v)).unwrap_or(false)
        });
        // A routable events-gRPC bind must be authenticated. The sink has no
        // transport TLS/mTLS of its own, so without bearer auth a public bind is
        // an unauthenticated firehose of mempool/chain activity. This mirrors the
        // MCP rule (`mcpallowremote` requires `mcpauth`). A proxy/mTLS-terminated
        // deployment keeps the loopback bind and does NOT set allow-remote.
        if events_grpc_allow_remote && !events_grpc_auth {
            return Err(
                "--events-grpc-allow-remote requires --events-grpc-auth (a remote events-gRPC \
                 bind must be authenticated; --events-grpc-auth in turn requires --authfile). \
                 For a proxy/mTLS-terminated setup, bind loopback and omit \
                 --events-grpc-allow-remote."
                    .to_string(),
            );
        }
        let streamws_auth = cli
            .streamws_auth
            .or_else(|| file_get("streamwsauth").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if streamws_auth && authfile.is_none() {
            return Err(
                "--streamws-auth requires --authfile (there is no token table to honor \
                 bearer tokens against)"
                    .to_string(),
            );
        }
        let streamws_allow_remote = cli.streamws_allow_remote.unwrap_or_else(|| {
            file_get("streamwsallowremote").and_then(|v| parse_bool(&v)).unwrap_or(false)
        });
        // A routable streamws bind must be authenticated — same rule as the
        // events-gRPC sink. The transport has no TLS of its own, so a public
        // bind without bearer auth would be an unauthenticated firehose.
        if streamws_allow_remote && !streamws_auth {
            return Err(
                "--streamws-allow-remote requires --streamws-auth (a remote streamws bind \
                 must be authenticated; --streamws-auth in turn requires --authfile). For a \
                 proxy/mTLS-terminated setup, bind loopback and omit --streamws-allow-remote."
                    .to_string(),
            );
        }
        let mcp_auth = cli
            .mcpauth
            .or_else(|| file_get("mcpauth").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if mcp_auth && authfile.is_none() {
            return Err(
                "--mcpauth requires --authfile (there is no token table to honor bearer \
                 tokens against)"
                    .to_string(),
            );
        }
        let mcp_allow_remote = cli
            .mcpallowremote
            .or_else(|| file_get("mcpallowremote").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        if mcp_allow_remote && !mcp_auth {
            return Err(
                "--mcpallowremote requires --mcpauth (a remote MCP bind must be \
                 authenticated; --mcpauth in turn requires --authfile)"
                    .to_string(),
            );
        }
        // MCP native TLS. The MCP listener serves HTTPS when both cert and key
        // are set; mTLS layers client-cert verification on top. Same partial-
        // config / allowlist validation shape as the Esplora / Electrum / RPC
        // surfaces.
        let mcp_tls_cert = cli
            .mcpcert
            .or_else(|| file_get("mcpcert").map(std::path::PathBuf::from));
        let mcp_tls_key = cli
            .mcpkey
            .or_else(|| file_get("mcpkey").map(std::path::PathBuf::from));
        let mcp_mtls = cli
            .mcpmtls
            .or_else(|| file_get("mcpmtls").and_then(|v| parse_bool(&v)))
            .unwrap_or(false);
        let mcp_mtls_client_ca = cli
            .mcpmtlsclientca
            .or_else(|| file_get("mcpmtlsclientca").map(std::path::PathBuf::from));
        let mcp_mtls_client_allow: Vec<String> = {
            let mut values: Vec<String> = cli.mcpmtlsclientallow.clone();
            if values.is_empty() {
                values = file_get_all("mcpmtlsclientallow");
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
        if mcp_tls_cert.is_some() != mcp_tls_key.is_some() {
            return Err("--mcpcert and --mcpkey must be set together".to_string());
        }
        if mcp_mtls && mcp_tls_cert.is_none() {
            return Err("--mcpmtls=1 requires --mcpcert and --mcpkey".to_string());
        }
        if mcp_mtls && mcp_mtls_client_ca.is_none() {
            return Err("--mcpmtls=1 requires --mcpmtlsclientca".to_string());
        }
        if !mcp_mtls && !mcp_mtls_client_allow.is_empty() {
            return Err("--mcpmtlsclientallow requires --mcpmtls=1".to_string());
        }
        // A remote MCP bind must be encrypted: bearer tokens cross the wire, so
        // TLS is mandatory whenever the listener is reachable off-host. This is
        // enforced here (`mcpallowremote`) and again in main.rs against the
        // resolved bind IP, so a non-loopback `mcpbind` without TLS is refused
        // even if `mcpallowremote` is unset.
        if mcp_allow_remote && mcp_tls_cert.is_none() {
            return Err(
                "--mcpallowremote requires --mcpcert and --mcpkey (a remote MCP listener must \
                 use TLS so the bearer token is never sent in cleartext)"
                    .to_string(),
            );
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

        // AssumeUTXO --fast-start source resolution + validation.
        //   - Remote sources MUST be https:// (TLS, validated certs).
        //     Plain http:// is rejected, not silently downgraded, so a
        //     MITM cannot feed a snapshot URL; the file is still verified
        //     against the hardcoded anchor hash at load, but transport
        //     authentication is defense-in-depth and protects operator
        //     opsec (the URL/content is never sent in cleartext).
        //   - A bare path or file:// is the operator's own disk and is
        //     allowed (no transport to secure).
        //   - Incompatible with pruning (same as the loadtxoutset RPC).
        let fast_start = cli.fast_start.or_else(|| file_get("faststart"));
        if let Some(ref src) = fast_start {
            if src.contains("://") {
                let scheme = src.split("://").next().unwrap_or("");
                if scheme.eq_ignore_ascii_case("http") {
                    return Err(
                        "--fast-start requires https:// (plain http:// is refused). Use an \
                         https URL or a local file path."
                            .into(),
                    );
                }
                if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("file") {
                    return Err(format!(
                        "--fast-start scheme '{scheme}://' is unsupported; use https:// or a \
                         local file path"
                    ));
                }
            }
            if prune > 0 {
                return Err(format!(
                    "--fast-start is incompatible with --prune={prune} (loadtxoutset cannot run \
                     under pruning). Remove one of them."
                ));
            }
        }
        let fast_start_sha256 = cli
            .fast_start_sha256
            .or_else(|| file_get("faststartsha256"))
            .map(|s| s.to_ascii_lowercase());
        if let Some(ref digest) = fast_start_sha256 {
            if fast_start.is_none() {
                return Err("--fast-start-sha256 requires --fast-start".into());
            }
            match hex::decode(digest) {
                Ok(bytes) if bytes.len() == 32 => {}
                _ => {
                    return Err(
                        "--fast-start-sha256 must be exactly 64 hex characters (a 32-byte SHA-256)"
                            .into(),
                    );
                }
            }
        }

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
        let mut pending_notes: Vec<ConfigNote> = std::mem::take(&mut include_notes);
        // Surface warnings for recognized-but-unsupported Core keys that were
        // skipped (drop-in bitcoin.conf compatibility) so the operator knows
        // each ignored line, even though the node started.
        if let Some(cf) = config_file.as_ref() {
            for msg in &cf.ignored {
                pending_notes.push(ConfigNote {
                    level: NoteLevel::Warn,
                    message: msg.clone(),
                });
            }
        }
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
            signet_challenge,
            rpcport,
            rpcbind,
            rpcallowip,
            rpcuser,
            rpcpassword,
            rpc_threads,
            rpc_workqueue,
            api_threads,
            rpc_readonly_bind,
            rpc_readonly_port,
            rpc_readonly_allowip,
            rpc_readonly_threads,
            rpc_readonly_workqueue,
            rpc_readonly_tls_bind,
            rpc_readonly_tls_cert,
            rpc_readonly_tls_key,
            rpc_readonly_mtls,
            rpc_readonly_mtls_client_ca,
            rpc_readonly_mtls_client_allow,
            rpcauth,
            authfile,
            rpc_auth_bearer,
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
            blocksonly,
            v2transport,
            v2only,
            externalip,
            whitelist,
            whitebind,
            asmap,
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
            persistmempool: cli
                .persistmempool
                .or_else(|| file_get("persistmempool").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
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
            esplora_auth_bearer,
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
            reindex: cli.reindex.unwrap_or(false),
            reindex_chainstate: cli.reindex_chainstate.unwrap_or(false),
            // Default on for regtest (matches Core's -checkblockindex), off
            // elsewhere — on a mainnet index the walk is ~1M point lookups.
            check_block_index: cli
                .checkblockindex
                .unwrap_or(network == Network::Regtest),
            maxconnections: cli
                .maxconnections
                .or_else(|| file_get("maxconnections").and_then(|v| v.parse().ok()))
                .or(profile_defaults.maxconnections)
                .unwrap_or(125),
            maxinboundperip: cli
                .maxinboundperip
                .or_else(|| file_get("maxinboundperip").and_then(|v| v.parse().ok()))
                .unwrap_or(3),
            max_upload_target: {
                let raw = cli
                    .maxuploadtarget
                    .clone()
                    .or_else(|| file_get("maxuploadtarget"));
                match raw {
                    Some(s) => parse_maxuploadtarget(&s)?,
                    None => 0,
                }
            },
            bind: cli
                .bind
                .or_else(|| file_get("bind"))
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            timeout: {
                // Resolve in CLI > config > default(5000ms) order.
                // `parse_timeout_value` returns milliseconds and
                // emits a one-time stderr warning if a bare integer
                // looks like seconds-style legacy (≤300 — anything
                // below that is way too short for a real ms timeout
                // and almost certainly came from an old satd config
                // where the field was seconds).
                let raw = cli.timeout.clone().or_else(|| file_get("timeout"));
                match raw {
                    Some(s) => parse_timeout_value(&s)?,
                    None => 5000,
                }
            },
            addnode: {
                let mut nodes = cli.addnode;
                if nodes.is_empty() {
                    nodes = file_get_all("addnode");
                }
                nodes
            },
            seednode: {
                let mut nodes = cli.seednode;
                if nodes.is_empty() {
                    nodes = file_get_all("seednode");
                }
                nodes
            },
            dns: cli
                .dns
                .or_else(|| file_get("dns").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
            dnsseed: cli
                .dnsseed
                .or_else(|| file_get("dnsseed").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
            forcednsseed: cli
                .forcednsseed
                .or_else(|| file_get("forcednsseed").and_then(|v| parse_bool(&v)))
                .unwrap_or(false),
            fixedseeds: cli
                .fixedseeds
                .or_else(|| file_get("fixedseeds").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
            bantime: cli
                .bantime
                .or_else(|| file_get("bantime").and_then(|v| v.parse().ok()))
                .unwrap_or(86400),
            proxy: cli.proxy.or_else(|| file_get("proxy")),
            proxyrandomize: cli
                .proxyrandomize
                .or_else(|| file_get("proxyrandomize").and_then(|v| parse_bool(&v)))
                .unwrap_or(true),
            onion: cli.onion.or_else(|| file_get("onion")),
            torcontrol,
            torpassword: cli.torpassword.or_else(|| file_get("torpassword")),
            listenonion,
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
            mcp: cli.mcp.unwrap_or_else(|| {
                file_get("mcp").and_then(|v| parse_bool(&v)).unwrap_or(false)
            }),
            mcp_port: cli
                .mcpport
                .or_else(|| file_get("mcpport").and_then(|v| v.parse().ok())),
            mcp_bind: cli
                .mcpbind
                .or_else(|| file_get("mcpbind"))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            mcp_auth,
            mcp_allow_remote,
            mcp_tls_cert,
            mcp_tls_key,
            mcp_mtls,
            mcp_mtls_client_ca,
            mcp_mtls_client_allow,
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
                    eprintln!(
                        "Warning: unknown consensus engine '{}', using default 'rust-shadow'",
                        raw
                    );
                    ConsensusEngine::RustShadow
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
            server: cli.server.unwrap_or_else(|| {
                file_get("server").and_then(|v| parse_bool(&v)).unwrap_or(false)
            }),
            daemon: cli.daemon.unwrap_or_else(|| {
                file_get("daemon").and_then(|v| parse_bool(&v)).unwrap_or(false)
            }),
            metricsport: cli
                .metricsport
                .or_else(|| file_get("metricsport").and_then(|v| v.parse().ok())),
            metricsbind: cli
                .metricsbind
                .or_else(|| file_get("metricsbind"))
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            rpc_extended_errors: cli.rpcextendederrors.unwrap_or_else(|| {
                file_get("rpcextendederrors").and_then(|v| parse_bool(&v)).unwrap_or(false)
            }),
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
            debug: {
                let mut v = cli.debug;
                if v.is_empty() {
                    v = file_get_all("debug");
                }
                v
            },
            debugexclude: {
                let mut v = cli.debugexclude;
                if v.is_empty() {
                    v = file_get_all("debugexclude");
                }
                v
            },
            profile,
            reorg_webhook: cli.reorg_webhook.or_else(|| file_get("reorgwebhook")),
            reorg_webhook_secret: cli
                .reorg_webhook_secret
                .or_else(|| file_get("reorgwebhooksecret")),
            fast_start,
            fast_start_sha256,
            events_node_id: cli.events_node_id.or_else(|| file_get("eventsnodeid")),
            events_region: cli.events_region.or_else(|| file_get("eventsregion")),
            events_grpc_bind: cli.events_grpc_bind.or_else(|| file_get("eventsgrpcbind")),
            events_grpc_allow_remote,
            events_grpc_max_conns: cli
                .events_grpc_max_conns
                .or_else(|| file_get("eventsgrpcmaxconns").and_then(|v| v.parse().ok()))
                .unwrap_or(64),
            events_grpc_auth,
            events_grpc_max_subscriptions: cli
                .events_grpc_max_subscriptions
                .or_else(|| file_get("eventsgrpcmaxsubscriptions").and_then(|v| v.parse().ok()))
                .unwrap_or(256),
            streamws_bind: cli.streamws_bind.or_else(|| file_get("streamws")),
            streamws_allow_remote,
            streamws_auth,
            streamws_max_conns: cli
                .streamws_max_conns
                .or_else(|| file_get("streamwsmaxconns").and_then(|v| v.parse().ok()))
                .unwrap_or(256),
            streamws_max_subscriptions: cli
                .streamws_max_subscriptions
                .or_else(|| file_get("streamwsmaxsubscriptions").and_then(|v| v.parse().ok()))
                .unwrap_or(256),
            streamws_max_message_bytes: cli
                .streamws_max_message_bytes
                .or_else(|| file_get("streamwsmaxmessagebytes").and_then(|v| v.parse().ok()))
                .unwrap_or(262_144),
            stream_max_resync_blocks: cli
                .stream_max_resync_blocks
                .or_else(|| file_get("streammaxresyncblocks").and_then(|v| v.parse().ok()))
                .unwrap_or(10_000),
            stream_prefix_min_bits: cli
                .stream_prefix_min_bits
                .or_else(|| file_get("streamprefixminbits").and_then(|v| v.parse().ok()))
                .unwrap_or(8),
            stream_prefix_max_bits: cli
                .stream_prefix_max_bits
                .or_else(|| file_get("streamprefixmaxbits").and_then(|v| v.parse().ok()))
                .unwrap_or(32),
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
            "prune": self.prune,
            "dbcache": self.dbcache,
            "blocksdir": self.blocksdir.as_ref().map(|p| p.display().to_string()),
            "signet_seed_nodes": self.signet_seed_nodes,
            "signet_challenge": self.signet_challenge.as_ref().map(|c| {
                use bitcoin::hashes::hex::DisplayHex;
                c.as_hex().to_string()
            }),
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
                "dnsseed": self.dnsseed,
                "forcednsseed": self.forcednsseed,
                "fixedseeds": self.fixedseeds,
                "connect": self.connect,
                "addnode": self.addnode,
                "seednode": self.seednode,
                "blocksonly": self.blocksonly,
                "v2transport": self.v2transport,
                "v2only": self.v2only,
                "externalip": self.externalip.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "whitelist": self.whitelist.iter().map(|e| e.raw.clone()).collect::<Vec<_>>(),
                "whitebind": self.whitebind.iter().map(|(a, _)| a.to_string()).collect::<Vec<_>>(),
                "max_upload_target_bytes": self.max_upload_target,
                "asmap": self.asmap.as_ref().map(|p| p.display().to_string()),
            },
            "mempool": {
                "max_bytes_mb": self.maxmempool,
                "min_relay_tx_fee_sat_per_kvb": self.minrelaytxfee,
                "full_rbf": self.mempoolfullrbf,
                "expiry_hours": self.mempoolexpiry,
                "persist": self.persistmempool,
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
            "debug": self.debug,
            "debugexclude": self.debugexclude,
            "max_shutdown_secs": self.max_shutdown_secs,
            "tor": {
                "proxy": self.proxy,
                "proxyrandomize": self.proxyrandomize,
                "onion": self.onion,
                "control": self.torcontrol,
                "password": if self.torpassword.is_some() { "(set)" } else { "(none)" },
                "listenonion": self.listenonion,
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
        match chain_subdir(self.network) {
            Some(sub) => self.datadir.join(sub),
            None => self.datadir.clone(),
        }
    }

    /// Resolve the directory that holds the block flat-files (`blk*.dat`),
    /// matching Bitcoin Core's `-blocksdir` semantics. See
    /// [`resolve_blocks_dir`] for the path rules.
    pub fn blocks_dir(&self) -> PathBuf {
        resolve_blocks_dir(self.blocksdir.as_deref(), &self.datadir, self.network)
    }
}

/// The chain-specific subdirectory name Bitcoin Core uses under the
/// data/blocks roots: `None` for mainnet (no subdir), else the Core
/// directory name. Centralised so `network_datadir` and `blocks_dir`
/// can't drift apart.
fn chain_subdir(network: Network) -> Option<&'static str> {
    match network {
        Network::Bitcoin => None,
        Network::Regtest => Some("regtest"),
        Network::Testnet => Some("testnet3"),
        Network::Testnet4 => Some("testnet4"),
        Network::Signet => Some("signet"),
    }
}

/// Resolve the block flat-file directory per Bitcoin Core's `-blocksdir`
/// semantics.
///
/// Core treats `-blocksdir` as the ROOT under which the chain-specific
/// `blocks/` subtree lives — NOT as the flat-files directory itself. So
/// `-blocksdir=/data` puts mainnet blocks at `/data/blocks` and regtest
/// blocks at `/data/regtest/blocks`. Reusing one `-blocksdir` across
/// networks therefore keeps each chain's blocks separated instead of
/// dumping every network's `blk*.dat` into the same directory.
///
/// When `blocksdir` is `None`, blocks live under the network datadir
/// (`<datadir>/<chain>/blocks`) — the same path satd produced before
/// this helper existed.
pub fn resolve_blocks_dir(
    blocksdir: Option<&std::path::Path>,
    datadir: &std::path::Path,
    network: Network,
) -> PathBuf {
    let mut p = match blocksdir {
        Some(root) => root.to_path_buf(),
        None => datadir.to_path_buf(),
    };
    if let Some(sub) = chain_subdir(network) {
        p.push(sub);
    }
    p.push("blocks");
    p
}

/// CLI arguments compatible with bitcoind flags.
///
/// `Clone` is required so the parsed CLI can be captured once at startup and
/// reused on every SIGHUP config reload (see [`Config::load_with_cli`] and
/// `satd::reload`): the CLI stays authoritative while only the config file is
/// re-read.
#[derive(Parser, Debug, Clone)]
#[command(name = "satd", version, about = "Bitcoin Core-compatible node in Rust")]
pub struct CliArgs {
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Use regtest network"
    )]
    pub regtest: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Use testnet network"
    )]
    pub testnet: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Use signet network"
    )]
    pub signet: Option<bool>,

    /// Use the testnet4 network (Bitcoin Core's `-testnet4`).
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Use testnet4 network"
    )]
    pub testnet4: Option<bool>,

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

    /// Additional config files to splice in, resolved relative to
    /// `--datadir`. Mirrors Bitcoin Core's `-includeconf=<file>`.
    /// Repeatable. Recognised on the command line for compatibility
    /// but, like Core, only honoured inside a config file — a
    /// command-line value is ignored with a warning.
    #[arg(long, value_name = "FILE", help = "Additional config file (config-file only)")]
    pub includeconf: Vec<String>,

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

    /// Custom signet challenge script, hex-encoded. Mirrors Bitcoin
    /// Core's `-signetchallenge=<hex>`. Selects a private/custom signet:
    /// the node validates block solutions against this script (BIP 325)
    /// and derives the P2P network magic from it. Signet only.
    #[arg(
        long,
        value_name = "HEX",
        help = "Custom signet challenge script, hex (BIP 325). Signet only."
    )]
    pub signetchallenge: Option<String>,

    #[arg(long, value_name = "PORT", help = "RPC server port")]
    pub rpcport: Option<u16>,

    #[arg(long, value_name = "USER", help = "RPC username")]
    pub rpcuser: Option<String>,

    #[arg(long, value_name = "PASS", help = "RPC password")]
    pub rpcpassword: Option<String>,

    /// Max concurrent in-flight RPC method calls (Bitcoin Core
    /// `-rpcthreads`). Requests beyond this queue up to `-rpcworkqueue`
    /// before being shed. Default: 16 (Core's default).
    #[arg(
        long,
        value_name = "N",
        help = "Max concurrent in-flight RPC method calls (Core -rpcthreads; default 16)"
    )]
    pub rpcthreads: Option<usize>,

    /// Max RPC requests allowed to wait for a worker beyond `-rpcthreads`
    /// before the server sheds load with HTTP 429. Bitcoin Core
    /// `-rpcworkqueue`. Default: 64 (Core's default). Note: Core returns
    /// 503 on a full queue; satd returns 429 (Too Many Requests) with a
    /// `Retry-After` header — an intentional, documented divergence.
    #[arg(
        long,
        value_name = "N",
        help = "Max queued RPC requests beyond -rpcthreads before HTTP 429 (Core -rpcworkqueue; default 64)"
    )]
    pub rpcworkqueue: Option<usize>,

    /// Worker-thread count for the separate, bounded tokio runtime that
    /// serves the remotely-consumed API surfaces, isolating them from the
    /// consensus/P2P core runtime. Default: `max(2, cores/4)`.
    #[arg(
        long = "api-threads",
        value_name = "N",
        help = "Worker threads for the isolated API runtime serving read surfaces (Esplora, Electrum, events gRPC, metrics). JSON-RPC/MCP stay on the core runtime. Default: max(2, cores/4)"
    )]
    pub apithreads: Option<usize>,

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

    /// Bind address(es) for the opt-in read-only JSON-RPC listener. Serves
    /// the same methods as `--rpcbind` but behind a read-only filter (reads
    /// and mempool submit only) on the bounded API runtime. Repeatable.
    /// Unset by default, meaning no read-only listener. Non-loopback values
    /// REQUIRE at least one `--rpcreadonlyallowip` entry.
    #[arg(
        long,
        value_name = "ADDR[:PORT]",
        help = "Bind a read-only JSON-RPC listener (reads + mempool submit) on the API runtime (repeatable; opt-in)"
    )]
    pub rpcreadonlybind: Vec<String>,

    /// Default port for `--rpcreadonlybind` entries that omit one. Default 8330.
    #[arg(
        long,
        value_name = "PORT",
        help = "Default port for --rpcreadonlybind entries without an explicit port (default 8330)"
    )]
    pub rpcreadonlyport: Option<u16>,

    /// Source-IP allowlist for the read-only listener, independent of
    /// `--rpcallowip`. Empty = loopback only.
    #[arg(
        long,
        value_name = "IP|CIDR",
        help = "Allow read-only JSON-RPC connections from this IP / CIDR (repeatable). Empty = loopback only."
    )]
    pub rpcreadonlyallowip: Vec<String>,

    /// Max concurrent in-flight calls on the read-only listener. Default:
    /// same as `--rpcthreads`.
    #[arg(
        long,
        value_name = "N",
        help = "Max concurrent in-flight calls on the read-only RPC listener (default: same as -rpcthreads)"
    )]
    pub rpcreadonlythreads: Option<usize>,

    /// Read-only listener work-queue depth before HTTP 429. Default: same as
    /// `--rpcworkqueue`.
    #[arg(
        long,
        value_name = "N",
        help = "Max queued requests on the read-only RPC listener before HTTP 429 (default: same as -rpcworkqueue)"
    )]
    pub rpcreadonlyworkqueue: Option<usize>,

    /// TLS bind for the read-only listener (requires --rpcreadonlytlscert and
    /// --rpcreadonlytlskey). Serves the same read-only-filtered methods over
    /// TLS on the API runtime.
    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "Bind the read-only JSON-RPC TLS listener (requires --rpcreadonlytlscert and --rpcreadonlytlskey)"
    )]
    pub rpcreadonlytlsbind: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "PEM certificate (chain) for the read-only TLS listener"
    )]
    pub rpcreadonlytlscert: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "PEM private key for the read-only TLS listener"
    )]
    pub rpcreadonlytlskey: Option<PathBuf>,

    /// Require and verify a client certificate on the read-only TLS surface.
    #[arg(
        long,
        value_name = "BOOL",
        help = "Require a client certificate on the read-only TLS listener (mTLS). Requires --rpcreadonlytlsbind and --rpcreadonlymtlsclientca."
    )]
    pub rpcreadonlymtls: Option<bool>,

    #[arg(
        long,
        value_name = "PATH",
        help = "CA bundle client certs must chain to on the read-only TLS listener (required with --rpcreadonlymtls=1)"
    )]
    pub rpcreadonlymtlsclientca: Option<PathBuf>,

    #[arg(
        long,
        value_name = "SUBJECT",
        help = "Allow only these client-cert subjects on the read-only TLS listener (repeatable; requires --rpcreadonlymtls=1)"
    )]
    pub rpcreadonlymtlsclientallow: Vec<String>,

    /// Bitcoin-Core-compatible HMAC-SHA256 RPC credential. Format:
    /// `user:salt$hash`. Generated by Core's `share/rpcauth/rpcauth.py`
    /// — paste those lines unchanged. Repeatable.
    #[arg(
        long,
        value_name = "USER:SALT$HASH",
        help = "RPC credential in Bitcoin Core's rpcauth format (repeatable). Use rpcauth.py to generate."
    )]
    pub rpcauth: Vec<String>,

    /// Path to the unified-auth bearer-token file (TOML).
    #[arg(
        long,
        value_name = "PATH",
        help = "Path to the unified-auth bearer-token file (TOML). Enables the opt-in auth layer; per-surface flags decide where tokens are honored."
    )]
    pub authfile: Option<PathBuf>,

    /// Honor bearer tokens on the JSON-RPC read/write listeners.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Honor Authorization: Bearer tokens on the JSON-RPC listeners (default: false). Requires --authfile. The operator credential keeps full access."
    )]
    pub rpcauthbearer: Option<bool>,

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
        num_args = 0..=1,
        default_missing_value = "1",
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
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Disable HTTP Basic auth on the JSON-RPC TLS surface (default: false). Only accepted with --rpcmtls=1. Plain HTTP keeps full auth."
    )]
    pub rpcdisableauth: Option<bool>,

    #[arg(
        long,
        value_name = "SECS",
        help = "Per-handshake timeout for the JSON-RPC TLS surface (default: 10). Lower than Electrum/Esplora (30s) because JSON-RPC clients are typically local. Raise for high-latency links."
    )]
    pub rpctlshandshaketimeout: Option<u64>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Accept P2P connections"
    )]
    pub listen: Option<bool>,

    /// Bitcoin Core's `-blocksonly`: don't relay transactions over P2P.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Suppress P2P transaction relay (default: false)"
    )]
    pub blocksonly: Option<bool>,

    /// Bitcoin Core's `-v2transport`: BIP 324 v2 encrypted transport.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Offer/accept BIP 324 v2 encrypted transport (default: true)"
    )]
    pub v2transport: Option<bool>,

    /// satd-specific `-v2only`: refuse non-v2 peers.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Refuse peers that do not speak BIP 324 v2 (default: false)"
    )]
    pub v2only: Option<bool>,

    #[arg(long, value_name = "PORT", help = "P2P listen port")]
    pub port: Option<u16>,

    #[arg(long, value_name = "ADDR", help = "Connect to specific peer")]
    pub connect: Vec<String>,

    /// Declare an external address to advertise to peers. Mirrors Bitcoin
    /// Core's `-externalip=<ip[:port]>`. Repeatable. `IP` or `IP:port`
    /// (bare IP inherits the network's default P2P port).
    #[arg(long, value_name = "IP[:PORT]", help = "External address to advertise (repeatable)")]
    pub externalip: Vec<String>,

    /// Grant net permissions to peers from a subnet. Mirrors Bitcoin
    /// Core's `-whitelist=[perms@]IP/subnet`. Repeatable. `perms` is a
    /// comma list (noban,relay,forcerelay,mempool,download,addr,all);
    /// omitted = the implicit default set.
    #[arg(long, value_name = "[PERMS@]NET", help = "Whitelist peers by subnet (repeatable)")]
    pub whitelist: Vec<String>,

    /// Bind an extra P2P listener whose inbound peers get net
    /// permissions. Mirrors Bitcoin Core's `-whitebind=[perms@]addr`.
    /// Repeatable.
    #[arg(long, value_name = "[PERMS@]ADDR", help = "Permissioned bind address (repeatable)")]
    pub whitebind: Vec<String>,

    /// Path to a Bitcoin Core `-asmap` file for ASN-based addrman
    /// bucketing (eclipse resistance). Relative paths resolve against
    /// `--datadir`.
    #[arg(long, value_name = "FILE", help = "asmap file for ASN-based peer bucketing")]
    pub asmap: Option<String>,

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
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
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
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
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
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Persist the mempool to mempool.dat across restarts (default: true)"
    )]
    pub persistmempool: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Allow bare multisig outputs (default: true)"
    )]
    pub permitbaremultisig: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Maintain a full transaction index"
    )]
    pub txindex: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Maintain an address-history index (default: true). Accepts 0/1/true/false."
    )]
    pub addressindex: Option<bool>,

    #[arg(
        long,
        value_name = "N",
        help = "Maximum concurrent per-scripthash subscriptions (default: 10000)"
    )]
    pub addrindexsubscriptions: Option<usize>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Run the native Esplora REST server (default: true). Requires --addressindex=1."
    )]
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
        num_args = 0..=1,
        default_missing_value = "1",
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

    /// Honor bearer tokens on the Esplora server.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Honor Authorization: Bearer tokens (esplora:read) on the Esplora server (default: false). Requires --authfile."
    )]
    pub esploraauthbearer: Option<bool>,

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

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Run the native Electrum protocol server (default: false). Requires --addressindex=1 and --txindex=1."
    )]
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
        num_args = 0..=1,
        default_missing_value = "1",
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
        num_args = 0..=1,
        default_missing_value = "1",
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
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Rebuild block index and chain state from block files on disk"
    )]
    pub reindex: Option<bool>,

    #[arg(
        long = "reindex-chainstate",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Rebuild UTXO set from existing block files"
    )]
    pub reindex_chainstate: Option<bool>,

    #[arg(
        long = "checkblockindex",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Audit block-index/active-chain consistency at startup (default: on for regtest)"
    )]
    pub checkblockindex: Option<bool>,

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

    /// Bitcoin Core's `-maxuploadtarget`: cap historical block upload per
    /// 24h. Plain number = MiB; suffix `B/K/M/G/T` (or `KiB`/`MiB`/…)
    /// overrides. 0 = unlimited.
    #[arg(long, value_name = "SIZE", help = "Max historical upload per 24h (e.g. 500M; 0=off)")]
    pub maxuploadtarget: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Bind P2P to this address (default: 0.0.0.0)"
    )]
    pub bind: Option<String>,

    /// P2P connection timeout. Bitcoin Core's `-timeout` takes
    /// milliseconds (default 5000); satd matches that interpretation
    /// for bare integers. Suffix-disambiguated forms — `5s`, `5000ms`
    /// — are also accepted so an operator can be explicit. Stored in
    /// `Config::timeout` as milliseconds.
    #[arg(
        long,
        value_name = "MS|Ns|Nms",
        help = "P2P connection timeout, in milliseconds (default 5000). Accepts `5s` or `5000ms` for explicit units."
    )]
    pub timeout: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Add a node to connect to (does not disable DNS seeding)"
    )]
    pub addnode: Vec<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Connect to a node to retrieve peer addresses (repeatable). All networks."
    )]
    pub seednode: Vec<String>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Allow DNS seeding (default: true)"
    )]
    pub dns: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Query DNS seeds for peer addresses (default: true; requires -dns)"
    )]
    pub dnsseed: Option<bool>,

    /// Bitcoin Core's `-forcednsseed`: always query DNS seeds, even when
    /// the address book is already populated.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Always query DNS seeds even with a populated address book (default: false)"
    )]
    pub forcednsseed: Option<bool>,

    /// Bitcoin Core's `-fixedseeds`: allow the compiled-in fixed-seed
    /// fallback (default true; set 0 to forbid it).
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Allow the compiled-in fixed seed fallback (default: true)"
    )]
    pub fixedseeds: Option<bool>,

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
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Randomize SOCKS5 credentials per connection so Tor isolates each peer on its own circuit (default: true)"
    )]
    pub proxyrandomize: Option<bool>,

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

    #[arg(
        long,
        value_name = "PASS",
        help = "Tor control port password (HashedControlPassword). Omit to use SAFECOOKIE cookie auth."
    )]
    pub torpassword: Option<String>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Create a Tor hidden service via the control port (default: off; an explicit -torcontrol implies on)"
    )]
    pub listenonion: Option<bool>,

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
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable MCP (Model Context Protocol) server"
    )]
    pub mcp: Option<bool>,

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

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS certificate for the MCP HTTP server (enables HTTPS; requires --mcpkey)"
    )]
    pub mcpcert: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM-encoded TLS private key for the MCP HTTP server (requires --mcpcert)"
    )]
    pub mcpkey: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Require mutual TLS on the MCP listener (default: false). Requires --mcpcert/--mcpkey and --mcpmtlsclientca."
    )]
    pub mcpmtls: Option<bool>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to PEM CA bundle used to verify client certificates when --mcpmtls=1"
    )]
    pub mcpmtlsclientca: Option<std::path::PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        help = "Allowlist of accepted client-cert CN / DNS-SAN values (repeatable, comma-separated). Empty = any cert validly signed by the CA."
    )]
    pub mcpmtlsclientallow: Vec<String>,

    /// Require bearer tokens (mcp:*) on the MCP HTTP server.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Require Authorization: Bearer tokens (mcp:*) on the MCP HTTP server (default: false). Requires --authfile."
    )]
    pub mcpauth: Option<bool>,

    /// Permit a non-loopback MCP HTTP bind.
    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Permit a non-loopback MCP HTTP bind (default: false). Requires --mcpauth (and --authfile)."
    )]
    pub mcpallowremote: Option<bool>,

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
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Accept RPC commands (always on, accepted for compatibility)"
    )]
    pub server: Option<bool>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Run in background (use systemd instead, accepted for compatibility)"
    )]
    pub daemon: Option<bool>,

    #[arg(
        long,
        value_name = "N",
        help = "Script verification threads (accepted for compatibility)"
    )]
    pub par: Option<usize>,

    #[arg(
        long,
        value_name = "CATEGORY",
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable debug logging for a category (repeatable; bare/'all'/'1' = everything)"
    )]
    pub debug: Vec<String>,

    #[arg(
        long,
        value_name = "CATEGORY",
        help = "Disable debug logging for a category that -debug would enable (repeatable)"
    )]
    pub debugexclude: Vec<String>,

    #[arg(
        long,
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Emit structured error payloads (category, suggestion, debug) on RPC errors. Default: off (Core-compat)"
    )]
    pub rpcextendederrors: Option<bool>,

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
        long = "fast-start",
        value_name = "URL",
        help = "AssumeUTXO: download a UTXO snapshot from URL and load it at startup (https:// or a local file path). The snapshot is verified against satd's hardcoded anchor hash; a bad file is rejected. Incompatible with -prune."
    )]
    pub fast_start: Option<String>,

    #[arg(
        long = "fast-start-sha256",
        value_name = "HEX64",
        help = "Optional expected SHA-256 (64 hex chars) of the --fast-start snapshot file, checked right after download as a fast-fail integrity guard. Independent of the mandatory anchor-hash verification at load."
    )]
    pub fast_start_sha256: Option<String>,

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
        help = "host:port to bind the events gRPC streaming server. Loopback bind is unauthenticated by default; a remote bind requires --events-grpc-allow-remote AND --events-grpc-auth. Default: disabled"
    )]
    pub events_grpc_bind: Option<String>,

    #[arg(
        long = "events-grpc-allow-remote",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Permit --events-grpc-bind to point at a non-loopback address. Requires --events-grpc-auth (a remote bind must be authenticated)"
    )]
    pub events_grpc_allow_remote: Option<bool>,

    /// Require bearer tokens (stream:subscribe) on the events gRPC server.
    #[arg(
        long = "events-grpc-auth",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Require Authorization: Bearer tokens (stream:subscribe) on the events gRPC server (default: false). Requires --authfile."
    )]
    pub events_grpc_auth: Option<bool>,

    #[arg(
        long = "events-grpc-max-conns",
        value_name = "N",
        help = "Hard cap on simultaneously-open events gRPC connections (default: 64; 0 disables the cap)"
    )]
    pub events_grpc_max_conns: Option<usize>,

    #[arg(
        long = "events-grpc-max-subscriptions",
        value_name = "N",
        help = "Hard cap on concurrent events gRPC Subscribe streams across all connections (default: 256; 0 disables the cap)"
    )]
    pub events_grpc_max_subscriptions: Option<usize>,

    #[arg(
        long = "streamws",
        value_name = "ADDR",
        help = "host:port to bind the streaming JSON-over-WebSocket + SSE transport (/ws + /sse). Loopback bind is unauthenticated by default; a remote bind requires --streamws-allow-remote AND --streamws-auth. Default: disabled"
    )]
    pub streamws_bind: Option<String>,

    #[arg(
        long = "streamws-allow-remote",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Permit --streamws to point at a non-loopback address. Requires --streamws-auth (a remote bind must be authenticated)"
    )]
    pub streamws_allow_remote: Option<bool>,

    #[arg(
        long = "streamws-auth",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Require Authorization: Bearer tokens (stream:subscribe) on the streamws transport (default: false). Requires --authfile."
    )]
    pub streamws_auth: Option<bool>,

    #[arg(
        long = "streamws-max-conns",
        value_name = "N",
        help = "Hard cap on simultaneously-open streamws connections (/ws + /sse). A connection beyond the cap gets HTTP 503 (default: 256)"
    )]
    pub streamws_max_conns: Option<usize>,

    #[arg(
        long = "streamws-max-subscriptions",
        value_name = "N",
        help = "Hard cap on watch-set entries per streamws connection; an add beyond it is shed without dropping the connection (default: 256)"
    )]
    pub streamws_max_subscriptions: Option<usize>,

    #[arg(
        long = "streamws-max-message-bytes",
        value_name = "N",
        help = "Cap on a single inbound WebSocket message/frame in bytes (default: 262144)"
    )]
    pub streamws_max_message_bytes: Option<usize>,

    #[arg(
        long = "stream-max-resync-blocks",
        value_name = "N",
        help = "Max blocks the watch matcher re-scans in one catch-up after lagging the chain event broadcast (default: 10000; 0 disables the cap)"
    )]
    pub stream_max_resync_blocks: Option<u32>,

    #[arg(
        long = "stream-prefix-min-bits",
        value_name = "K",
        help = "Minimum bit-length for a privacy-preserving script-prefix watch; floors the bucket coarseness (default: 8)"
    )]
    pub stream_prefix_min_bits: Option<u32>,

    #[arg(
        long = "stream-prefix-max-bits",
        value_name = "K",
        help = "Maximum bit-length for a script-prefix watch; caps precision so a bucket always spans many scripts (default: 32, range [min,32])"
    )]
    pub stream_prefix_max_bits: Option<u32>,

    #[arg(
        long = "events-zmq-bind",
        value_name = "ENDPOINT",
        help = "ZMQ endpoint for the events PUB sink (e.g. 'tcp://0.0.0.0:28332'). Default: disabled"
    )]
    pub events_zmq_bind: Option<String>,

    #[arg(
        long = "events-zmq-hashtx",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable Bitcoin Core-compatible 'hashtx' topic on the events ZMQ sink (default: enabled when --events-zmq-bind is set)"
    )]
    pub events_zmq_hashtx: Option<bool>,

    #[arg(
        long = "events-zmq-hashblock",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable Bitcoin Core-compatible 'hashblock' topic on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_hashblock: Option<bool>,

    #[arg(
        long = "events-zmq-mpevict",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable 'mpevict' topic (mempool eviction with reason) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpevict: Option<bool>,

    #[arg(
        long = "events-zmq-mpreplace",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable 'mpreplace' topic (RBF replacement) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpreplace: Option<bool>,

    #[arg(
        long = "events-zmq-mpconfirm",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
        help = "Enable 'mpconfirm' topic (mempool tx confirmed in block) on the events ZMQ sink (default: enabled)"
    )]
    pub events_zmq_mpconfirm: Option<bool>,

    #[arg(
        long = "events-zmq-nodeevent",
        value_name = "BOOL",
        value_parser = parse_bool_arg,
        num_args = 0..=1,
        default_missing_value = "1",
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
        "testnet4",
        "signet",
        "chain",
        "datadir",
        "blocksdir",
        "signetseednode",
        "signetchallenge",
        "conf",
        "includeconf",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "rpcthreads",
        "rpcworkqueue",
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
        "rpcreadonlybind",
        "rpcreadonlyport",
        "rpcreadonlyallowip",
        "rpcreadonlythreads",
        "rpcreadonlyworkqueue",
        "rpcreadonlytlsbind",
        "rpcreadonlytlscert",
        "rpcreadonlytlskey",
        "rpcreadonlymtls",
        "rpcreadonlymtlsclientca",
        "rpcreadonlymtlsclientallow",
        "rpcauth",
        "authfile",
        "rpcauthbearer",
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
        "persistmempool",
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
        "esploraauthbearer",
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
        "checkblockindex",
        "maxconnections",
        "maxinboundperip",
        "maxuploadtarget",
        "bind",
        "timeout",
        "addnode",
        "seednode",
        "dns",
        "dnsseed",
        "forcednsseed",
        "fixedseeds",
        "blocksonly",
        "v2transport",
        "v2only",
        "externalip",
        "whitelist",
        "whitebind",
        "asmap",
        "bantime",
        "proxy",
        "proxyrandomize",
        "onion",
        "torcontrol",
        "torpassword",
        "listenonion",
        "onlynet",
        "blockmaxweight",
        "blockmintxfee",
        "pid",
        "mcp",
        "mcpport",
        "mcpbind",
        "mcpcert",
        "mcpkey",
        "mcpmtls",
        "mcpmtlsclientca",
        "mcpmtlsclientallow",
        "mcpauth",
        "mcpallowremote",
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
        "debug",
        "debugexclude",
        "profile",
        "reorg-webhook",
        "reorgwebhook",
        "reorg-webhook-secret",
        "reorgwebhooksecret",
    ];

    // Bitcoin Core negates a boolean option with a `-no` prefix
    // (`-nolistenonion` == `-listenonion=0`, `-noserver` == `-server=0`).
    // satd now mirrors this comprehensively: every boolean CLI flag is
    // value-accepting and listed here, so `-no<flag>` / `--no<flag>`
    // rewrites to `--<flag>=0` for all of them. Entries are the clap
    // long-name spelling (dash form for renamed flags) so the rewritten
    // `--<flag>=0` is a flag clap recognises. `blockfilterindex` is
    // intentionally absent: it is not a plain bool (accepts `basic`), so
    // its `-no` form is handled via translate_index_aliases instead.
    const NEGATABLE_BOOL_FLAGS: &[&str] = &[
        "regtest",
        "testnet",
        "testnet4",
        "signet",
        "listen",
        "blocksonly",
        "v2transport",
        "v2only",
        "dns",
        "dnsseed",
        "forcednsseed",
        "fixedseeds",
        "listenonion",
        "proxyrandomize",
        "txindex",
        "addressindex",
        "peerblockfilters",
        "mempoolfullrbf",
        "datacarrier",
        "permitbaremultisig",
        "persistmempool",
        "esplora",
        "esploramtls",
        "esploraauthbearer",
        "electrum",
        "electrummtls",
        "rpcmtls",
        "rpcdisableauth",
        "rpcauthbearer",
        "rpcextendederrors",
        "reindex",
        "reindex-chainstate",
        "checkblockindex",
        "mcp",
        "mcpmtls",
        "mcpauth",
        "mcpallowremote",
        "server",
        "daemon",
        "events-grpc-allow-remote",
        "streamws-allow-remote",
        "streamws-auth",
        "events-zmq-hashtx",
        "events-zmq-hashblock",
        "events-zmq-mpevict",
        "events-zmq-mpreplace",
        "events-zmq-mpconfirm",
        "events-zmq-nodeevent",
    ];

    args.into_iter()
        .map(|arg| {
            // `-no<flag>` / `--no<flag>` negation (no explicit value).
            if arg.starts_with('-') && !arg.contains('=') {
                let stripped = arg.trim_start_matches('-');
                if let Some(flag) = stripped.strip_prefix("no")
                    && NEGATABLE_BOOL_FLAGS.contains(&flag)
                {
                    return format!("--{flag}=0");
                }
            }
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
    /// Warnings for recognized-but-unsupported Core keys that were skipped
    /// (drop-in compatibility). Surfaced to the operator via config notes.
    pub ignored: Vec<String>,
}

impl ConfigFile {
    pub fn parse_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        Self::parse(&content)
    }

    /// Parse Bitcoin-Core-format `bitcoin.conf` content. Returns an
    /// error on any unrecognised key (key not in [`KNOWN_CONFIG_KEYS`]):
    /// Bitcoin Core hard-errors here too, and silent acceptance of
    /// typos is the kind of misconfiguration nobody catches until it
    /// matters in production (e.g. `rpcusser=alice` in a hardened
    /// node config that never opens the RPC).
    pub fn parse(content: &str) -> Result<Self, String> {
        let mut file = ConfigFile::default();
        let mut current_section: Option<String> = None;

        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
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

            // Hard-error on Bitcoin Core keys we RECOGNISE but do not
            // accept. Silently accepting them is the dangerous case the
            // strict parser exists to prevent: e.g. `includeconf` would
            // make a config look valid while every setting in the
            // included file is silently dropped. The message differs by
            // reason so the operator knows whether to wait for support
            // (not-yet-implemented) or remove the line for good
            // (intentionally-excluded).
            // Disposition for a key satd does not honor. The goal is drop-in
            // bitcoin.conf compatibility, so an unsupported-but-recognized Core
            // key is skipped with a warning (the node still starts) rather than
            // being fatal — except where skipping would mislead the operator
            // about the node's security / exposure / privacy posture. A key that
            // is neither a satd option nor a known Core v30 option is a typo.
            if !is_known_config_key(&key) {
                if let Some(reason) = classify_unsupported_key(&key) {
                    // Fatal to skip (auth / exposure / privacy).
                    return Err(format!(
                        "Error reading configuration file: parse error on line {line_no}: \
                        '{key}' is a Bitcoin Core option that satd does not support. \
                        {reason} Remove this line before starting satd."
                    ));
                } else if is_core_v30_key(&key) {
                    // Recognized Core v30 option satd does not implement and is
                    // safe to skip: warn and continue so the config still loads.
                    let msg = match skip_guidance(&key) {
                        Some(g) => format!(
                            "ignoring unsupported Bitcoin Core option '{key}' (bitcoin.conf line {line_no}); the node will run without it. {g}"
                        ),
                        None => format!(
                            "ignoring unsupported Bitcoin Core v30 option '{key}' (bitcoin.conf line {line_no}); satd does not implement it, so the node will run without it."
                        ),
                    };
                    file.ignored.push(msg);
                    continue;
                } else {
                    // Neither a satd key nor a known Core v30 key — almost
                    // certainly a typo. Reject so a fat-fingered security option
                    // (e.g. `rpcusser=`) can't silently disable auth.
                    return Err(format!(
                        "Error reading configuration file: parse error on line {line_no}: \
                        unrecognized key '{key}'. This is neither a satd option nor a \
                        known Bitcoin Core v30 option — check for a typo."
                    ));
                }
            }

            let map = match &current_section {
                Some(section) => file.sections.entry(section.clone()).or_default(),
                None => &mut file.global,
            };
            map.entry(key).or_default().push(value);
        }

        Ok(file)
    }

    /// Drain `includeconf` directives from the global scope and the
    /// active-network `section`, in that order. Other sections are
    /// ignored: Bitcoin Core only processes includes from the global
    /// scope plus the section matching the running network.
    fn drain_includeconf(&mut self, section: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(v) = self.global.remove("includeconf") {
            out.extend(v);
        }
        if let Some(s) = self.sections.get_mut(section)
            && let Some(v) = s.remove("includeconf")
        {
            out.extend(v);
        }
        out
    }

    /// Merge another parsed config into this one. Included values are
    /// appended after existing values, matching Bitcoin Core, which reads
    /// the whole main config file before reading any `includeconf` file
    /// (common/config.cpp `ReadConfigFiles`). Single-valued keys are read
    /// first-wins (see `file_get`), so a key set in both the main file and
    /// an included file resolves to the main file's value; repeatable keys
    /// keep main-then-included order. The common case is an included file
    /// holding keys (e.g. `rpcpassword`) the main file never sets, which
    /// take effect unopposed.
    fn merge_from(&mut self, mut other: ConfigFile) {
        for (k, mut v) in other.global {
            self.global.entry(k).or_default().append(&mut v);
        }
        for (sec, map) in other.sections {
            let dst = self.sections.entry(sec).or_default();
            for (k, mut v) in map {
                dst.entry(k).or_default().append(&mut v);
            }
        }
        // Carry skipped-key warnings from included files up to the parent so
        // they surface even when an exotic key lives in an `includeconf` file.
        self.ignored.append(&mut other.ignored);
    }

    /// Resolve `includeconf` directives (global + active `section`)
    /// relative to `datadir`, parsing and merging each referenced file.
    ///
    /// Matches Bitcoin Core's semantics: paths are resolved against the
    /// data directory (absolute paths are used as-is), and an
    /// `includeconf` found *inside* an included file is ignored with a
    /// warning rather than followed — this is what prevents infinite
    /// include recursion. Returns operator-facing notes for any such
    /// ignored nested includes.
    pub fn resolve_includes(
        &mut self,
        datadir: &Path,
        section: &str,
    ) -> Result<Vec<ConfigNote>, String> {
        let mut notes = Vec::new();
        let includes = self.drain_includeconf(section);
        for rel in includes {
            let inc_path = if Path::new(&rel).is_absolute() {
                PathBuf::from(&rel)
            } else {
                datadir.join(&rel)
            };
            let mut included = ConfigFile::parse_file(&inc_path).map_err(|e| {
                format!("includeconf='{rel}' (resolved to {}): {e}", inc_path.display())
            })?;
            // No recursion: drain any includeconf the included file
            // carries (global or any section) and warn, matching Core.
            let mut nested = included.global.remove("includeconf").unwrap_or_default();
            for s in included.sections.values_mut() {
                if let Some(v) = s.remove("includeconf") {
                    nested.extend(v);
                }
            }
            for n in nested {
                notes.push(ConfigNote {
                    level: NoteLevel::Warn,
                    message: format!(
                        "includeconf='{n}' inside included file {} ignored: nested includes \
                         are not processed (matches Bitcoin Core; prevents recursion)",
                        inc_path.display()
                    ),
                });
            }
            self.merge_from(included);
        }
        Ok(notes)
    }
}

/// Every config-file key satd recognises today. Sorted by source-of-
/// truth: this list is derived from the union of (a) every `file_get`
/// / `file_get_all` call in `Config::load`, (b) the CLI flags that
/// have a `clap` long form, and (c) the Bitcoin-Core-compatibility
/// aliases tracked in `SATD_CLI_COMPAT_AUDIT.md`.
///
/// Keys for Core features satd recognises but has NOT yet implemented
/// are deliberately NOT in this list — see [`RECOGNIZED_UNSUPPORTED_KEYS`].
/// Those hard-error rather than being silently accepted, because an
/// accepted-but-ignored option (e.g. `includeconf`) is more dangerous
/// than a rejected one.
pub const KNOWN_CONFIG_KEYS: &[&str] = &[
    // Network selection
    "regtest",
    "testnet",
    "testnet4",
    "signet",
    "chain",
    // Filesystem
    "datadir",
    "blocksdir",
    "conf",
    "includeconf",
    "pid",
    "profile",
    // Daemon control
    "daemon",
    "server",
    "logformat",
    "debug",
    "debugexclude",
    "maxshutdownsecs",
    // RPC server
    "rpcport",
    "rpcbind",
    "rpcallowip",
    "rpcuser",
    "rpcpassword",
    "rpcthreads",
    "rpcworkqueue",
    "apithreads",
    "rpcreadonlybind",
    "rpcreadonlyport",
    "rpcreadonlyallowip",
    "rpcreadonlythreads",
    "rpcreadonlyworkqueue",
    "rpcreadonlytlsbind",
    "rpcreadonlytlscert",
    "rpcreadonlytlskey",
    "rpcreadonlymtls",
    "rpcreadonlymtlsclientca",
    "rpcreadonlymtlsclientallow",
    "rpcauth",
    "authfile",
    "rpcauthbearer",
    "rpccookiefile",
    "rpccookieperms",
    "rpcdefaultunits",
    "rpcdisableauth",
    "rpcextendederrors",
    // RPC TLS
    "rpctlsbind",
    "rpctlscert",
    "rpctlskey",
    "rpctlshandshaketimeout",
    "rpcmtls",
    "rpcmtlsclientca",
    "rpcmtlsclientallow",
    // P2P
    "listen",
    "blocksonly",
    "v2transport",
    "v2only",
    "externalip",
    "whitelist",
    "whitebind",
    "asmap",
    "port",
    "bind",
    "connect",
    "addnode",
    "seednode",
    "maxconnections",
    "maxinboundperip",
    "maxuploadtarget",
    "dns",
    "dnsseed",
    "forcednsseed",
    "fixedseeds",
    "bantime",
    "timeout",
    "onlynet",
    "signetseednode",
    "signetchallenge",
    // Proxy / Tor
    "proxy",
    "proxyrandomize",
    "onion",
    "torcontrol",
    "torpassword",
    "listenonion",
    // Consensus
    "assumevalid",
    "assumevalidage",
    "stopatheight",
    "consensus",
    // Indexing
    "txindex",
    "addressindex",
    "addrindexsubscriptions",
    "blockfilterindex",
    "peerblockfilters",
    // Mempool / relay policy
    "mempoolfullrbf",
    "maxmempool",
    "minrelaytxfee",
    "dustrelayfee",
    "datacarrier",
    "datacarriersize",
    "limitancestorcount",
    "limitdescendantcount",
    "mempoolexpiry",
    "persistmempool",
    "permitbaremultisig",
    // Esplora
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
    "esploraauthbearer",
    "esploracookiefile",
    "esplorauserpass",
    // Electrum
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
    // Storage / pruning / reindex
    "prune",
    "reindex",
    "reindexchainstate",
    "checkblockindex",
    "dbcache",
    "storageprofile",
    "prefetchworkers",
    "maxahead",
    "maxopenfiles",
    "rocksdbbackgroundjobs",
    "rocksdbsubcompactions",
    "rocksdbwalmb",
    "compactiondiagintervalsecs",
    "compactionintervalsecs",
    "compactionl0at",
    "ibdl0pauseat",
    "stallwatchdogsecs",
    "stallabortsecs",
    "shadowqueuesize",
    "shadowworkers",
    // Mining
    "blockmaxweight",
    "blockmintxfee",
    "par",
    // Events
    "eventsnodeid",
    "eventsregion",
    "eventsgrpcbind",
    "eventsgrpcallowremote",
    "eventsgrpcauth",
    "eventsgrpcmaxconns",
    "eventsgrpcmaxsubscriptions",
    "streamws",
    "streamwsallowremote",
    "streamwsauth",
    "streamwsmaxconns",
    "streamwsmaxsubscriptions",
    "streamwsmaxmessagebytes",
    "streammaxresyncblocks",
    "streamprefixminbits",
    "streamprefixmaxbits",
    "eventszmqbind",
    "eventszmqhashtx",
    "eventszmqhashblock",
    "eventszmqmpevict",
    "eventszmqmpreplace",
    "eventszmqmpconfirm",
    "eventszmqnodeevent",
    // Webhooks
    "reorgwebhook",
    "reorgwebhooksecret",
    // MCP
    "mcp",
    "mcpport",
    "mcpbind",
    "mcpcert",
    "mcpkey",
    "mcpmtls",
    "mcpmtlsclientca",
    "mcpmtlsclientallow",
    "mcpauth",
    "mcpallowremote",
    // Metrics / health
    "metricsport",
    "metricsbind",
];

// Disposition of a Bitcoin Core config key that satd does not honor.
//
// The goal is drop-in `bitcoin.conf` compatibility: an existing Core config
// should start satd with little or no editing. So an unsupported-but-recognized
// Core key is **skipped with a warning** (the node still starts) rather than
// being a fatal error — *except* a small set where silently skipping would
// mislead the operator about the node's security / exposure / privacy posture,
// which stay fatal. A key that is neither a satd option nor a known Core v30
// option is treated as a typo and rejected (this is what protects a fat-
// fingered `rpcusser=` from silently disabling auth).
//
// See `SATD_CORE_CONFIG_SUPERSET_GAP.md` (monorepo) for the policy.

/// Core keys that are **fatal** to skip: skipping them would leave the operator
/// believing the node is more locked-down / private than it is. Each carries an
/// actionable reason naming the satd equivalent. (Default is warn-and-continue;
/// only auth / exposure / privacy keys belong here.)
const FATAL_UNSUPPORTED_KEYS: &[(&str, &str)] = &[
    ("i2psam", "I2P is out of scope; Tor is satd's supported anonymity network (-proxy / -onion / -torcontrol). Leaving this in place would route traffic over clearnet instead of the privacy network you configured."),
    ("i2pacceptincoming", "I2P is out of scope (see i2psam); Tor is satd's supported anonymity network."),
    ("rpcwhitelist", "satd uses capability-scoped bearer tokens (-authfile) instead of per-user RPC method allowlists; silently skipping this would leave RPC less restricted than your Core config intends. See the Authentication chapter of the manual."),
    ("rpcwhitelistdefault", "satd uses capability-scoped bearer tokens (-authfile) instead of Core's RPC whitelists; silently skipping this would leave RPC less restricted than your Core config intends. See the Authentication chapter of the manual."),
];

/// Optional, richer guidance appended to the warning when a *skipped* Core key
/// has a satd-specific replacement the operator should switch to. Keys not
/// listed here get a generic "recognized but not implemented" warning.
const SKIP_GUIDANCE: &[(&str, &str)] = &[
    ("rest", "satd ships a native Esplora REST API instead of Core's /rest/ surface; enable it with -esplora (on by default)."),
    ("peerbloomfilters", "BIP37 bloom filters are intentionally unsupported (privacy / DoS); use BIP157/158 compact filters via -blockfilterindex / -peerblockfilters."),
    ("discover", "external-IP auto-discovery is not supported; advertise your address explicitly with -externalip."),
    ("maxorphantx", "this option was removed in Bitcoin Core v30 as well."),
    ("natpmp", "satd does not implement PCP/NAT-PMP port mapping; configure port forwarding externally."),
    ("debuglogfile", "satd logs to stdout/journald and has no debug.log; manage retention via journald or your container runtime."),
    ("shrinkdebugfile", "satd logs to stdout/journald and has no debug.log to shrink; manage retention via journald or your container runtime."),
    ("printtoconsole", "satd always logs to stdout; there is no debug.log alternative to toggle."),
    ("zmqpubhashtx", "use -eventszmqbind + -eventszmqhashtx (Core wire-format) instead of per-topic -zmqpub* flags."),
    ("zmqpubhashblock", "use -eventszmqbind + -eventszmqhashblock (Core wire-format) instead of per-topic -zmqpub* flags."),
    ("zmqpubrawtx", "satd's events bus (-eventszmqbind) replaces Core's per-topic -zmqpub* model; raw-tx publication is not currently provided. See CORE_DIFFERENCES.md."),
    ("zmqpubrawblock", "satd's events bus (-eventszmqbind) replaces Core's per-topic -zmqpub* model; raw-block publication is not currently provided. See CORE_DIFFERENCES.md."),
    ("zmqpubsequence", "satd's events bus (-eventszmqbind) replaces Core's per-topic -zmqpub* model. See CORE_DIFFERENCES.md."),
];

/// The frozen set of Bitcoin Core **v30** config keys (bitcoind node + wallet +
/// chainparams + logging args). Used purely to tell a real-but-unsupported Core
/// option (→ warn and skip) apart from a typo (→ reject). Extracted from the
/// `v30.0` tag:
/// ```text
/// for f in src/init.cpp src/init/common.cpp src/common/args.cpp \
///          src/chainparamsbase.cpp src/wallet/init.cpp; do git show v30.0:$f; done \
///   | perl -0777 -ne 'while(/AddArg\(\s*"-([a-zA-Z0-9-]+)/g){print "$1\n"}' | sort -u
/// ```
/// Note: the logging / `-debug` family (`debug`, `debuglogfile`, `printtoconsole`,
/// `shrinkdebugfile`, `log*`, …) lives in `src/init/common.cpp`, and many AddArg
/// calls wrap the option name onto a second line — hence the slurp-mode perl
/// rather than a line-oriented `grep`.
/// Compatibility is pinned to v30: keys Core adds in later releases are not
/// listed here and would be treated as typos until this list is bumped.
const CORE_V30_KEYS: &[&str] = &[
    "acceptnonstdtxn", "acceptstalefeeestimates", "addnode", "addresstype", "alertnotify", "allowignoredconf",
    "asmap", "assumevalid", "avoidpartialspends", "bantime", "bind", "blockfilterindex",
    "blockmaxweight", "blockmintxfee", "blocknotify", "blockreconstructionextratxn", "blockreservedweight", "blocksdir",
    "blocksonly", "blocksxor", "blockversion", "bytespersigop", "capturemessages", "chain",
    "changetype", "checkaddrman", "checkblockindex", "checkblocks", "checklevel", "checkmempool",
    "checkpoints", "cjdnsreachable", "coinstatsindex", "conf", "connect", "consolidatefeerate",
    "daemon", "daemonwait", "datacarrier", "datacarriersize", "datadir", "dbbatchsize",
    "dbcache", "debug", "debugexclude", "debuglogfile", "deprecatedrpc", "disablewallet",
    "discardfee", "discover", "dns",
    "dnsseed", "dustrelayfee", "externalip", "fallbackfee", "fastprune", "fixedseeds",
    "forcednsseed", "help", "help-debug", "i2pacceptincoming", "i2psam", "includeconf",
    "incrementalrelayfee", "ipcbind", "keypool", "limitancestorcount", "limitancestorsize", "limitdescendantcount",
    "limitdescendantsize", "listen", "listenonion", "loadblock", "logips", "loglevel",
    "loglevelalways", "logratelimit", "logsourcelocations", "logthreadnames", "logtimemicros", "logtimestamps",
    "maxapsfee", "maxconnections", "maxmempool", "maxorphantx", "maxreceivebuffer", "maxsendbuffer",
    "maxsigcachesize", "maxtipage", "maxtxfee", "maxuploadtarget", "mempoolexpiry", "minimumchainwork",
    "minrelaytxfee", "mintxfee", "mocktime", "natpmp", "networkactive", "onion",
    "onlynet", "par", "paytxfee", "peerblockfilters", "peerbloomfilters", "peertimeout",
    "permitbaremultisig", "persistmempool", "persistmempoolv1", "pid", "port", "printpriority",
    "printtoconsole", "proxy", "proxyrandomize", "prune", "regtest", "reindex",
    "reindex-chainstate",
    "rest", "rpcallowip", "rpcauth", "rpcbind", "rpccookiefile", "rpccookieperms",
    "rpcdoccheck", "rpcpassword", "rpcport", "rpcservertimeout", "rpcthreads", "rpcuser",
    "rpcwhitelist", "rpcwhitelistdefault", "rpcworkqueue", "seednode", "server", "settings",
    "shrinkdebugfile", "shutdownnotify", "signer", "signet", "signetchallenge", "signetseednode",
    "spendzeroconfchange",
    "startupnotify", "stopafterblockimport", "stopatheight", "test", "testactivationheight", "testnet",
    "testnet4", "timeout", "torcontrol", "torpassword", "txconfirmtarget", "txindex",
    "txreconciliation", "uacomment", "unsafesqlitesync", "v2transport", "vbparams", "version",
    "wallet", "walletbroadcast", "walletcrosschain", "walletdir", "walletnotify", "walletrbf",
    "walletrejectlongchains", "whitebind", "whitelist", "whitelistforcerelay", "whitelistrelay", "zmqpubhashblock",
    "zmqpubhashblockhwm", "zmqpubhashtx", "zmqpubhashtxhwm", "zmqpubrawblock", "zmqpubrawblockhwm", "zmqpubrawtx",
    "zmqpubrawtxhwm", "zmqpubsequence", "zmqpubsequencehwm",
];

/// Is the given config-file key recognised? Returns true for any
/// entry in [`KNOWN_CONFIG_KEYS`]. Case-sensitive — Bitcoin Core's
/// behaviour is too.
pub fn is_known_config_key(key: &str) -> bool {
    KNOWN_CONFIG_KEYS.contains(&key)
}

/// If `key` is a Core option that is **fatal to skip** (auth / exposure /
/// privacy), return the actionable reason; otherwise `None`. Kept as the
/// public classifier name for callers/tests.
pub fn classify_unsupported_key(key: &str) -> Option<&'static str> {
    FATAL_UNSUPPORTED_KEYS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, reason)| *reason)
}

/// Is `key` a recognized Bitcoin Core v30 option (whether or not satd honors
/// it)? Distinguishes a real-but-unsupported Core key from a typo.
pub fn is_core_v30_key(key: &str) -> bool {
    CORE_V30_KEYS.contains(&key)
}

/// Optional richer guidance for a *skipped* (warned) Core key.
fn skip_guidance(key: &str) -> Option<&'static str> {
    SKIP_GUIDANCE
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, g)| *g)
}

/// Map a Bitcoin Core `-debug` category to the satd `tracing` target
/// prefix it controls. Core's categories don't correspond 1:1 to Rust
/// module paths, so this is a best-effort grouping onto satd's
/// subsystems. Returns `None` for categories satd has no equivalent
/// for (e.g. `qt`, `zmq`, `walletdb`, `leveldb`) — those are accepted
/// but produce no directive, matching the spirit of Core where a
/// category for an inactive subsystem simply yields no extra output.
fn debug_category_target(category: &str) -> Option<&'static str> {
    match category {
        "net" | "addrman" | "cmpctblock" | "txreconciliation" | "proxy" => Some("node::net"),
        "tor" | "i2p" => Some("node::net::tor"),
        "mempool" | "mempoolrej" | "estimatefee" | "txpackages" => Some("node::mempool"),
        "rpc" | "http" => Some("node::rpc"),
        "validation" | "bench" => Some("node::validation"),
        "coindb" | "blockstorage" | "leveldb" | "prune" | "reindex" => Some("node::storage"),
        _ => None,
    }
}

/// Translate Bitcoin Core `-debug` / `-debugexclude` categories into
/// `tracing_subscriber` `EnvFilter` directives layered on the base
/// filter. Returns `(enable_all, directives)`:
///
/// - `enable_all` is true when any `-debug` value is `1` or `all` — the
///   caller should base the filter on `debug` rather than `info`.
/// - `directives` are per-target overrides to add: `target=debug` for
///   each included subsystem (when not enabling all), or `target=info`
///   for each excluded subsystem (when enabling all, to claw it back).
///
/// Categories with no satd subsystem (see [`debug_category_target`])
/// are silently dropped from the directive set.
pub fn debug_directives(debug: &[String], debugexclude: &[String]) -> (bool, Vec<String>) {
    let norm = |s: &str| s.trim().to_ascii_lowercase();
    let enable_all = debug.iter().any(|c| matches!(norm(c).as_str(), "1" | "all"));

    let excluded: std::collections::BTreeSet<&'static str> = debugexclude
        .iter()
        .filter_map(|c| debug_category_target(&norm(c)))
        .collect();

    let mut directives = Vec::new();
    if enable_all {
        for t in &excluded {
            directives.push(format!("{t}=info"));
        }
    } else {
        let mut included: std::collections::BTreeSet<&'static str> = debug
            .iter()
            .filter_map(|c| debug_category_target(&norm(c)))
            .collect();
        for t in &excluded {
            included.remove(t);
        }
        for t in &included {
            directives.push(format!("{t}=debug"));
        }
    }
    (enable_all, directives)
}

/// Build the tracing `EnvFilter` for the current config.
///
/// This is the single source of truth for log verbosity, shared by the initial
/// subscriber init at startup and the SIGHUP reload path (`satd::reload`), so
/// the two can never drift. The base filter follows the historical behavior:
/// with no `-debug`/`-debugexclude` flags it honors `RUST_LOG` (else `info`);
/// when debug flags are present an explicit `RUST_LOG` still wins as the base,
/// otherwise the base is `debug` for `-debug=all/1` else `info`, and each mapped
/// category from [`debug_directives`] is layered on top.
pub fn build_env_filter(config: &Config) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;

    let (debug_all, debug_directives) = debug_directives(&config.debug, &config.debugexclude);
    let debug_flags_given = !config.debug.is_empty() || !config.debugexclude.is_empty();
    let mut env_filter = if !debug_flags_given {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        match std::env::var("RUST_LOG") {
            Ok(rl) if !rl.trim().is_empty() => EnvFilter::new(rl),
            _ => EnvFilter::new(if debug_all { "debug" } else { "info" }),
        }
    };
    for d in &debug_directives {
        match d.parse() {
            Ok(directive) => env_filter = env_filter.add_directive(directive),
            Err(e) => eprintln!("Warning: ignoring invalid debug directive {d:?}: {e}"),
        }
    }
    env_filter
}

fn default_datadir() -> PathBuf {
    dirs_home().join(".bitcoin")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Default worker count for the isolated API runtime: a modest fraction of
/// host parallelism (the consensus/P2P core runtime keeps the rest),
/// floored at 2 so the API surfaces always have more than one worker.
/// `available_parallelism()` honors cgroup CPU quota on modern Linux, so
/// this auto-fits a constrained container.
fn default_api_threads() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cores / 4).max(2)
}

fn default_rpc_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    }
}

fn default_p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Testnet4 => 48333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
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

/// Parse a `-timeout=<value>` argument, returning milliseconds.
///
/// Accepts:
///   - bare integer (`5000`)      → treated as ms (matches Bitcoin Core)
///   - `Nms` suffix (`5000ms`)    → explicit ms
///   - `Ns` suffix (`5s`)         → seconds × 1000
///
/// A bare integer ≤ 300 emits a one-time stderr warning: that range
/// is suspiciously short for a real ms timeout (300ms ≈ 0.3s) and is
/// almost certainly a leftover from satd's old `-timeout=N` interpretation
/// where N was seconds. The value is still treated as ms — the
/// warning is purely informational, the operator can update or use
/// `Ns` to be explicit. Future release: turn into a hard error.
pub fn parse_timeout_value(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("--timeout: empty value".to_string());
    }
    // Suffix forms first so `5ms` doesn't trip the bare-int warning
    // on the substring "5".
    if let Some(rest) = trimmed.strip_suffix("ms") {
        let n: u64 = rest
            .parse()
            .map_err(|e| format!("--timeout: invalid ms value {rest:?}: {e}"))?;
        return Ok(n);
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let n: u64 = rest
            .parse()
            .map_err(|e| format!("--timeout: invalid seconds value {rest:?}: {e}"))?;
        return Ok(n.saturating_mul(1000));
    }
    // Bare integer: ms (Core semantics). Warn if it looks like
    // seconds-style legacy.
    let n: u64 = trimmed
        .parse()
        .map_err(|e| format!("--timeout: expected integer or N[ms|s], got {trimmed:?}: {e}"))?;
    if n > 0 && n <= 300 {
        eprintln!(
            "warning: --timeout={n} interpreted as {n} milliseconds (matches Bitcoin Core's \
            -timeout=). If you meant {n} seconds, write --timeout={n}s explicitly. \
            satd-of-the-past used seconds; this warning will become an error in a future release."
        );
    }
    Ok(n)
}

/// Parse a Bitcoin Core `-chain=<name>` value to a `bitcoin::Network`.
/// Accepts every canonical name Core does plus a few common aliases.
/// Parse a `-maxuploadtarget` size into bytes. A bare number is MiB
/// (Bitcoin Core's historical unit); a `B/K/M/G/T` suffix (optionally
/// `iB`) overrides. `0` means unlimited.
fn parse_maxuploadtarget(s: &str) -> Result<u64, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("maxuploadtarget: empty value".to_string());
    }
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let (num_str, unit) = s.split_at(split);
    let num: f64 = num_str
        .parse()
        .map_err(|_| format!("maxuploadtarget: invalid number in {s:?}"))?;
    let mult: u64 = match unit.trim() {
        "" | "m" | "mb" | "mib" => 1024 * 1024, // bare = MiB (Core default)
        "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024u64.pow(4),
        other => {
            return Err(format!(
                "maxuploadtarget: unknown unit {other:?}; use B, K, M, G or T"
            ));
        }
    };
    Ok((num * mult as f64) as u64)
}

fn parse_chain_name(s: &str) -> Result<Network, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "main" | "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "test" | "testnet" | "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!(
            "--chain: unknown network {other:?}. Accepted values: main, test, testnet4, signet, regtest."
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
    fn rpc_admission_keys_recognized() {
        // A Core-shaped config carrying `-rpcthreads` / `-rpcworkqueue` (and
        // satd's events gRPC caps) must parse rather than hit the
        // unknown-key hard error — that rejection was the Core-compat gap
        // this change closes.
        for key in [
            "rpcthreads",
            "rpcworkqueue",
            "eventsgrpcmaxconns",
            "eventsgrpcmaxsubscriptions",
        ] {
            assert!(is_known_config_key(key), "{key} should be a known key");
        }
        let content = "rpcthreads=8\nrpcworkqueue=128\n";
        let cf = ConfigFile::parse(content)
            .expect("config carrying rpcthreads/rpcworkqueue should parse");
        assert_eq!(cf.global.get("rpcthreads").unwrap().last().unwrap(), "8");
        assert_eq!(cf.global.get("rpcworkqueue").unwrap().last().unwrap(), "128");
    }

    #[test]
    fn rpc_admission_defaults_match_core() {
        use clap::Parser;
        let dir =
            std::env::temp_dir().join(format!("satd-admission-default-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir", dir.to_str().unwrap()])
                .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        // Bitcoin Core's defaults.
        assert_eq!(cfg.rpc_threads, 16);
        assert_eq!(cfg.rpc_workqueue, 64);
        // satd's events gRPC defaults.
        assert_eq!(cfg.events_grpc_max_conns, 64);
        assert_eq!(cfg.events_grpc_max_subscriptions, 256);
        // streamws cap defaults.
        assert_eq!(cfg.streamws_max_conns, 256);
        assert_eq!(cfg.streamws_max_subscriptions, 256);
        assert_eq!(cfg.streamws_max_message_bytes, 262_144);
        // Script-prefix watch granularity defaults (§7.5).
        assert_eq!(cfg.stream_prefix_min_bits, 8);
        assert_eq!(cfg.stream_prefix_max_bits, 32);
    }

    #[test]
    fn rpc_readonly_listener_disabled_by_default() {
        use clap::Parser;
        let dir = std::env::temp_dir().join(format!("satd-ro-default-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir", dir.to_str().unwrap()])
                .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        // Opt-in: no read-only listener unless -rpcreadonlybind is set.
        assert!(cfg.rpc_readonly_bind.is_empty());
        assert_eq!(cfg.rpc_readonly_port, 8330);
        // Admission budget defaults to the main listener's.
        assert_eq!(cfg.rpc_readonly_threads, cfg.rpc_threads);
        assert_eq!(cfg.rpc_readonly_workqueue, cfg.rpc_workqueue);
    }

    #[test]
    fn rpc_readonly_listener_cli_enables_and_overrides() {
        use clap::Parser;
        let dir = std::env::temp_dir().join(format!("satd-ro-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcreadonlybind",
            "127.0.0.1",
            "--rpcreadonlyport",
            "9330",
            "--rpcreadonlythreads",
            "32",
            "--rpcreadonlyworkqueue",
            "256",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.rpc_readonly_bind.len(), 1);
        // The port-less bind picked up -rpcreadonlyport.
        assert_eq!(cfg.rpc_readonly_bind[0].port(), 9330);
        assert!(cfg.rpc_readonly_bind[0].ip().is_loopback());
        assert_eq!(cfg.rpc_readonly_threads, 32);
        assert_eq!(cfg.rpc_readonly_workqueue, 256);
    }

    #[test]
    fn rpc_readonly_nonloopback_requires_allowip() {
        use clap::Parser;
        let dir = std::env::temp_dir().join(format!("satd-ro-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A non-loopback read-only bind with no allowlist must be rejected,
        // mirroring the main listener's accidental-exposure guard.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcreadonlybind",
            "0.0.0.0:9330",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("rpcreadonlyallowip"), "got: {err}");
    }

    #[test]
    fn rpc_readonly_keys_recognized_in_config_file() {
        // A Core-shaped config carrying the read-only keys must load, not
        // hard-error (satd rejects unknown keys).
        for key in [
            "rpcreadonlybind",
            "rpcreadonlyport",
            "rpcreadonlyallowip",
            "rpcreadonlythreads",
            "rpcreadonlyworkqueue",
            "rpcreadonlytlsbind",
            "rpcreadonlytlscert",
            "rpcreadonlytlskey",
            "rpcreadonlymtls",
            "rpcreadonlymtlsclientca",
            "rpcreadonlymtlsclientallow",
        ] {
            assert!(is_known_config_key(key), "{key} must be a known config key");
        }
    }

    #[test]
    fn rpc_readonly_tls_partial_config_is_rejected() {
        use clap::Parser;
        let dir = std::env::temp_dir().join(format!("satd-ro-tls-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // TLS bind without cert/key must be rejected, mirroring -rpctlsbind.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcreadonlytlsbind",
            "127.0.0.1:9443",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("rpcreadonlytlscert") && err.contains("rpcreadonlytlskey"),
            "got: {err}"
        );
    }

    #[test]
    fn rpc_readonly_mtls_requires_tls_bind_and_ca() {
        use clap::Parser;
        let dir = std::env::temp_dir().join(format!("satd-ro-mtls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // mTLS without a TLS bind is rejected.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcreadonlymtls",
            "true",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("rpcreadonlytlsbind"), "got: {err}");
    }

    #[test]
    fn rpc_readonly_mtls_clientallow_requires_mtls() {
        use clap::Parser;
        let dir =
            std::env::temp_dir().join(format!("satd-ro-mtls-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcreadonlymtlsclientallow",
            "CN=foo",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("rpcreadonlymtls"), "got: {err}");
    }

    #[test]
    fn rpc_admission_cli_overrides() {
        use clap::Parser;
        let dir =
            std::env::temp_dir().join(format!("satd-admission-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcthreads",
            "8",
            "--rpcworkqueue",
            "128",
            "--events-grpc-max-conns",
            "10",
            "--events-grpc-max-subscriptions",
            "20",
            "--streamws-max-conns",
            "30",
            "--streamws-max-subscriptions",
            "40",
            "--streamws-max-message-bytes",
            "50000",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.rpc_threads, 8);
        assert_eq!(cfg.rpc_workqueue, 128);
        assert_eq!(cfg.events_grpc_max_conns, 10);
        assert_eq!(cfg.events_grpc_max_subscriptions, 20);
        assert_eq!(cfg.streamws_max_conns, 30);
        assert_eq!(cfg.streamws_max_subscriptions, 40);
        assert_eq!(cfg.streamws_max_message_bytes, 50_000);
    }

    #[test]
    fn api_threads_default_and_override() {
        use clap::Parser;
        // Default: max(2, cores/4), and never below the floor of 2.
        assert!(default_api_threads() >= 2, "API thread floor is 2");
        assert!(is_known_config_key("apithreads"), "apithreads must be known");

        let dir = std::env::temp_dir().join(format!("satd-apithreads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = Config::from_cli(
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir", dir.to_str().unwrap()])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cfg.api_threads, default_api_threads());

        // CLI override (kebab `--api-threads`), with the >=1 clamp.
        let cfg = Config::from_cli(
            CliArgs::try_parse_from([
                "satd",
                "--regtest",
                "--datadir",
                dir.to_str().unwrap(),
                "--api-threads",
                "3",
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(cfg.api_threads, 3);

        // A pathological value is clamped to the ceiling, not passed to the
        // runtime builder (which would fail to spawn the threads and panic
        // the daemon at boot).
        let cfg = Config::from_cli(
            CliArgs::try_parse_from([
                "satd",
                "--regtest",
                "--datadir",
                dir.to_str().unwrap(),
                "--api-threads",
                "1000000000",
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(cfg.api_threads, 1024);

        // Config-file form (`apithreads`) is accepted, not rejected.
        assert!(
            ConfigFile::parse("apithreads=6\n").is_ok(),
            "apithreads config key should parse"
        );
    }

    #[test]
    fn test_config_from_cli_regtest() {
        let cli = CliArgs {
            regtest: Some(true),
            testnet: Some(false),
            signet: Some(false),
            testnet4: None,
            chain: None,
            blocksdir: None,
            signetseednode: Vec::new(),
            signetchallenge: None,
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            includeconf: Vec::new(),
            rpcport: None,
            rpcuser: None,
            rpcpassword: None,
            rpcthreads: None,
            rpcworkqueue: None,
            apithreads: None,
            rpcbind: Vec::new(),
            rpcallowip: Vec::new(),
            rpcreadonlybind: Vec::new(),
            rpcreadonlyport: None,
            rpcreadonlyallowip: Vec::new(),
            rpcreadonlythreads: None,
            rpcreadonlyworkqueue: None,
            rpcreadonlytlsbind: None,
            rpcreadonlytlscert: None,
            rpcreadonlytlskey: None,
            rpcreadonlymtls: None,
            rpcreadonlymtlsclientca: None,
            rpcreadonlymtlsclientallow: Vec::new(),
            rpcauth: Vec::new(),
            authfile: None,
            rpcauthbearer: None,
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
            blocksonly: None,
            v2transport: None,
            v2only: None,
            port: None,
            connect: vec![],
            externalip: vec![],
            whitelist: vec![],
            whitebind: vec![],
            asmap: None,
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
            persistmempool: None,
            permitbaremultisig: None,
            txindex: None,
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
            esploraauthbearer: None,
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
            reindex: Some(false),
            reindex_chainstate: Some(false),
            checkblockindex: None,
            maxconnections: None,
            maxinboundperip: None,
            maxuploadtarget: None,
            bind: None,
            timeout: None,
            addnode: vec![],
            seednode: vec![],
            dns: None,
            dnsseed: None,
            forcednsseed: None,
            fixedseeds: None,
            bantime: None,
            blockmaxweight: None,
            blockmintxfee: None,
            pid: None,
            server: Some(false),
            daemon: Some(false),
            dbcache: None,
            prefetchworkers: None,
            par: None,
            proxy: None,
            proxyrandomize: None,
            onion: None,
            torcontrol: None,
            torpassword: None,
            listenonion: None,
            onlynet: vec![],
            mcp: Some(false),
            mcpport: None,
            mcpbind: None,
            mcpcert: None,
            mcpkey: None,
            mcpmtls: None,
            mcpmtlsclientca: None,
            mcpmtlsclientallow: Vec::new(),
            mcpauth: None,
            mcpallowremote: None,
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
            rpcextendederrors: Some(false),
            maxshutdownsecs: None,
            rpcdefaultunits: None,
            log_format: None,
            debug: vec![],
            debugexclude: vec![],
            profile: None,
            reorg_webhook: None,
            reorg_webhook_secret: None,
            fast_start: None,
            fast_start_sha256: None,
            events_node_id: None,
            events_region: None,
            events_grpc_bind: None,
            events_grpc_allow_remote: Some(false),
            events_grpc_auth: None,
            events_grpc_max_conns: None,
            events_grpc_max_subscriptions: None,
            streamws_bind: None,
            streamws_allow_remote: Some(false),
            streamws_auth: None,
            streamws_max_conns: None,
            streamws_max_subscriptions: None,
            streamws_max_message_bytes: None,
            stream_max_resync_blocks: None,
            stream_prefix_min_bits: None,
            stream_prefix_max_bits: None,
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
    fn blocks_dir_matches_core_layout() {
        use std::path::Path;
        let data = Path::new("/data");
        let blk = Path::new("/mnt/blocks");

        // No -blocksdir: blocks live under the network datadir. Mainnet
        // has no chain subdir; the others do.
        assert_eq!(
            resolve_blocks_dir(None, data, Network::Bitcoin),
            PathBuf::from("/data/blocks")
        );
        assert_eq!(
            resolve_blocks_dir(None, data, Network::Regtest),
            PathBuf::from("/data/regtest/blocks")
        );
        assert_eq!(
            resolve_blocks_dir(None, data, Network::Signet),
            PathBuf::from("/data/signet/blocks")
        );
        assert_eq!(
            resolve_blocks_dir(None, data, Network::Testnet),
            PathBuf::from("/data/testnet3/blocks")
        );

        // With -blocksdir: the flag is the ROOT; the chain subdir + blocks
        // are appended so different networks never share a flat-file dir.
        assert_eq!(
            resolve_blocks_dir(Some(blk), data, Network::Bitcoin),
            PathBuf::from("/mnt/blocks/blocks")
        );
        assert_eq!(
            resolve_blocks_dir(Some(blk), data, Network::Regtest),
            PathBuf::from("/mnt/blocks/regtest/blocks")
        );
        assert_eq!(
            resolve_blocks_dir(Some(blk), data, Network::Signet),
            PathBuf::from("/mnt/blocks/signet/blocks")
        );
    }

    #[test]
    fn test_config_auth_validation() {
        let cli = CliArgs {
            regtest: Some(true),
            testnet: Some(false),
            signet: Some(false),
            testnet4: None,
            chain: None,
            blocksdir: None,
            signetseednode: Vec::new(),
            signetchallenge: None,
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            includeconf: Vec::new(),
            rpcport: None,
            rpcuser: Some("alice".to_string()),
            rpcpassword: None, // missing password
            rpcthreads: None,
            rpcworkqueue: None,
            apithreads: None,
            rpcbind: Vec::new(),
            rpcallowip: Vec::new(),
            rpcreadonlybind: Vec::new(),
            rpcreadonlyport: None,
            rpcreadonlyallowip: Vec::new(),
            rpcreadonlythreads: None,
            rpcreadonlyworkqueue: None,
            rpcreadonlytlsbind: None,
            rpcreadonlytlscert: None,
            rpcreadonlytlskey: None,
            rpcreadonlymtls: None,
            rpcreadonlymtlsclientca: None,
            rpcreadonlymtlsclientallow: Vec::new(),
            rpcauth: Vec::new(),
            authfile: None,
            rpcauthbearer: None,
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
            blocksonly: None,
            v2transport: None,
            v2only: None,
            port: None,
            connect: vec![],
            externalip: vec![],
            whitelist: vec![],
            whitebind: vec![],
            asmap: None,
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
            persistmempool: None,
            permitbaremultisig: None,
            txindex: None,
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
            esploraauthbearer: None,
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
            reindex: Some(false),
            reindex_chainstate: Some(false),
            checkblockindex: None,
            maxconnections: None,
            maxinboundperip: None,
            maxuploadtarget: None,
            bind: None,
            timeout: None,
            addnode: vec![],
            seednode: vec![],
            dns: None,
            dnsseed: None,
            forcednsseed: None,
            fixedseeds: None,
            bantime: None,
            blockmaxweight: None,
            blockmintxfee: None,
            pid: None,
            server: Some(false),
            daemon: Some(false),
            dbcache: None,
            prefetchworkers: None,
            par: None,
            proxy: None,
            proxyrandomize: None,
            onion: None,
            torcontrol: None,
            torpassword: None,
            listenonion: None,
            onlynet: vec![],
            mcp: Some(false),
            mcpport: None,
            mcpbind: None,
            mcpcert: None,
            mcpkey: None,
            mcpmtls: None,
            mcpmtlsclientca: None,
            mcpmtlsclientallow: Vec::new(),
            mcpauth: None,
            mcpallowremote: None,
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
            rpcextendederrors: Some(false),
            maxshutdownsecs: None,
            rpcdefaultunits: None,
            log_format: None,
            debug: vec![],
            debugexclude: vec![],
            profile: None,
            reorg_webhook: None,
            reorg_webhook_secret: None,
            fast_start: None,
            fast_start_sha256: None,
            events_node_id: None,
            events_region: None,
            events_grpc_bind: None,
            events_grpc_allow_remote: Some(false),
            events_grpc_auth: None,
            events_grpc_max_conns: None,
            events_grpc_max_subscriptions: None,
            streamws_bind: None,
            streamws_allow_remote: Some(false),
            streamws_auth: None,
            streamws_max_conns: None,
            streamws_max_subscriptions: None,
            streamws_max_message_bytes: None,
            stream_max_resync_blocks: None,
            stream_prefix_min_bits: None,
            stream_prefix_max_bits: None,
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
    fn test_fast_start_validation() {
        // Plain http:// is refused (must be https).
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=http://example.com/utxo-840000.dat",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("https://"), "expected https-required error, got: {err}");

        // https:// is accepted and preserved.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=https://example.com/utxo-840000.dat",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("https fast-start should load");
        assert_eq!(
            config.fast_start.as_deref(),
            Some("https://example.com/utxo-840000.dat")
        );

        // A bare local path is accepted (operator's own disk).
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=/opt/utxo-840000.dat",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("local-path fast-start should load");
        assert_eq!(config.fast_start.as_deref(), Some("/opt/utxo-840000.dat"));

        // fast-start is incompatible with pruning.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=https://example.com/utxo-840000.dat",
            "--prune=550",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("prune"), "expected prune-conflict error, got: {err}");

        // An unsupported scheme is rejected.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=ftp://example.com/utxo-840000.dat",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        // --fast-start-sha256 requires --fast-start.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start-sha256=b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("--fast-start"), "got: {err}");

        // A malformed (short) digest is rejected.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=https://example.com/utxo-840000.dat",
            "--fast-start-sha256=deadbeef",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).is_err());

        // A valid digest is accepted and normalized to lowercase.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-test",
            "--fast-start=https://example.com/utxo-840000.dat",
            "--fast-start-sha256=B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9",
        ])
        .unwrap();
        let config = Config::from_cli(cli).expect("valid digest should load");
        assert_eq!(
            config.fast_start_sha256.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
    }

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

    #[test]
    fn authfile_defaults_to_none() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-authfile-test1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.authfile.is_none());
    }

    #[test]
    fn authfile_cli_sets_path() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-authfile-test2",
            "--authfile=/etc/satd/auth.toml",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.authfile.as_deref(), Some(std::path::Path::new("/etc/satd/auth.toml")));
    }

    #[test]
    fn authfile_must_be_absolute() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-authfile-test3",
            "--authfile=relative/auth.toml",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("absolute path"),
            "expected absolute-path error, got: {err}"
        );
    }

    #[test]
    fn authfile_is_a_known_config_key() {
        assert!(is_known_config_key("authfile"));
        assert!(is_known_config_key("rpcauthbearer"));
    }

    #[test]
    fn rpcauthbearer_defaults_off() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-bearer-test1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(!cfg.rpc_auth_bearer);
    }

    #[test]
    fn rpcauthbearer_requires_authfile() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-bearer-test2",
            "--rpcauthbearer=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("authfile"), "expected authfile requirement, got: {err}");
    }

    #[test]
    fn mcpauth_requires_authfile() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-mcp-test1",
            "--mcpauth=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("authfile"), "got: {err}");
    }

    #[test]
    fn mcpallowremote_requires_mcpauth() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-mcp-test2",
            "--authfile=/etc/satd/auth.toml",
            "--mcpallowremote=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("mcpauth"), "got: {err}");
    }

    #[test]
    fn eventsgrpcallowremote_requires_eventsgrpcauth() {
        // A remote events-gRPC bind without bearer auth would be an
        // unauthenticated public firehose — must hard-error at startup.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-grpc-remote-test",
            "--authfile=/etc/satd/auth.toml",
            "--events-grpc-allow-remote=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("events-grpc-auth"), "got: {err}");
    }

    #[test]
    fn eventsgrpc_remote_auth_chain_is_accepted() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-grpc-remote-test2",
            "--authfile=/etc/satd/auth.toml",
            "--events-grpc-auth=1",
            "--events-grpc-allow-remote=1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.events_grpc_auth && cfg.events_grpc_allow_remote);
    }

    #[test]
    fn streamws_allow_remote_requires_streamws_auth() {
        // A remote streamws bind without bearer auth would be an
        // unauthenticated public firehose — must hard-error at startup.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-streamws-remote-test",
            "--authfile=/etc/satd/auth.toml",
            "--streamws-allow-remote=1",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("streamws-auth"), "got: {err}");
    }

    #[test]
    fn streamws_remote_auth_chain_is_accepted() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-streamws-remote-test2",
            "--authfile=/etc/satd/auth.toml",
            "--streamws-auth=1",
            "--streamws-allow-remote=1",
            "--streamws=0.0.0.0:7799",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.streamws_auth && cfg.streamws_allow_remote);
        assert_eq!(cfg.streamws_bind.as_deref(), Some("0.0.0.0:7799"));
    }

    #[test]
    fn mcp_remote_auth_chain_is_accepted() {
        // A remote MCP bind needs auth AND TLS: bearer tokens must never cross
        // the wire in cleartext.
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-mcp-test3",
            "--authfile=/etc/satd/auth.toml",
            "--mcpauth=1",
            "--mcpallowremote=1",
            "--mcpcert=/etc/satd/mcp.crt",
            "--mcpkey=/etc/satd/mcp.key",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.mcp_auth && cfg.mcp_allow_remote);
        assert!(cfg.mcp_tls_cert.is_some() && cfg.mcp_tls_key.is_some());
    }

    #[test]
    fn mcp_allow_remote_requires_tls() {
        // Without --mcpcert/--mcpkey the remote bind is refused even with auth.
        let err = Config::from_cli(
            CliArgs::try_parse_from([
                "satd",
                "--regtest",
                "--datadir=/tmp/satd-mcp-notls",
                "--authfile=/etc/satd/auth.toml",
                "--mcpauth=1",
                "--mcpallowremote=1",
            ])
            .unwrap(),
        )
        .unwrap_err();
        assert!(err.contains("--mcpcert"), "got: {err}");
    }

    #[test]
    fn mcp_cert_and_key_must_pair() {
        let err = Config::from_cli(
            CliArgs::try_parse_from([
                "satd",
                "--regtest",
                "--datadir=/tmp/satd-mcp-halftls",
                "--mcpcert=/etc/satd/mcp.crt",
            ])
            .unwrap(),
        )
        .unwrap_err();
        assert!(err.contains("must be set together"), "got: {err}");
    }

    #[test]
    fn mcp_mtls_requires_cert_and_ca() {
        let err = Config::from_cli(
            CliArgs::try_parse_from([
                "satd",
                "--regtest",
                "--datadir=/tmp/satd-mcp-mtls",
                "--mcpmtls=1",
            ])
            .unwrap(),
        )
        .unwrap_err();
        assert!(err.contains("--mcpmtls=1 requires --mcpcert"), "got: {err}");
    }

    #[test]
    fn rpcauthbearer_with_authfile_is_accepted() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-bearer-test3",
            "--authfile=/etc/satd/auth.toml",
            "--rpcauthbearer=1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.rpc_auth_bearer);
        assert!(cfg.authfile.is_some());
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

    // ---- includeconf: chained config files ----

    /// Build a datadir with a main `bitcoin.conf` plus named included
    /// files, then load via `from_cli` on regtest. Returns the loaded
    /// Config (or the load error) for assertions.
    fn load_with_files(
        main: &str,
        included: &[(&str, &str)],
    ) -> (tempfile::TempDir, Result<Config, String>) {
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("bitcoin.conf"), main).unwrap();
        for (name, body) in included {
            std::fs::write(tmpdir.path().join(name), body).unwrap();
        }
        let conf_path = tmpdir.path().join("bitcoin.conf");
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
        ])
        .unwrap();
        let cfg = Config::from_cli(cli);
        (tmpdir, cfg)
    }

    #[test]
    fn includeconf_merges_included_file() {
        // The classic use: secrets live in a separate, tighter-perms
        // file pulled in via includeconf. The key set only there must
        // take effect.
        let (_d, cfg) = load_with_files(
            "includeconf=secrets.conf\n",
            &[("secrets.conf", "rpcuser=alice\nrpcpassword=topsecret\n")],
        );
        let cfg = cfg.unwrap();
        assert_eq!(cfg.rpcuser.as_deref(), Some("alice"));
        assert_eq!(cfg.rpcpassword.as_deref(), Some("topsecret"));
    }

    #[test]
    fn includeconf_main_value_beats_included() {
        // Bitcoin Core reads the whole main file, then appends included
        // files, and resolves single-valued config keys first-wins
        // (`reverse_precedence`). So a key set in both the main file and an
        // included file resolves to the MAIN file's value.
        let (_d, cfg) = load_with_files(
            "rpcport=18443\nincludeconf=override.conf\n",
            &[("override.conf", "rpcport=19999\n")],
        );
        assert_eq!(cfg.unwrap().rpcport, 18443);
    }

    #[test]
    fn includeconf_main_wins_regardless_of_directive_position() {
        // Core does NOT splice the include at the directive's position —
        // it appends after the entire main file. So the main value wins
        // whether `includeconf=` precedes or follows the setting.
        let (_d, before) = load_with_files(
            "includeconf=override.conf\nrpcport=18443\n",
            &[("override.conf", "rpcport=19999\n")],
        );
        assert_eq!(before.unwrap().rpcport, 18443, "includeconf before the setting");

        let (_d2, after) = load_with_files(
            "rpcport=18443\nincludeconf=override.conf\n",
            &[("override.conf", "rpcport=19999\n")],
        );
        assert_eq!(after.unwrap().rpcport, 18443, "includeconf after the setting");
    }

    #[test]
    fn includeconf_multiple_files_in_order() {
        let (_d, cfg) = load_with_files(
            "includeconf=a.conf\nincludeconf=b.conf\n",
            &[("a.conf", "rpcuser=from_a\n"), ("b.conf", "rpcpassword=from_b\n")],
        );
        let cfg = cfg.unwrap();
        assert_eq!(cfg.rpcuser.as_deref(), Some("from_a"));
        assert_eq!(cfg.rpcpassword.as_deref(), Some("from_b"));
    }

    #[test]
    fn includeconf_nested_is_ignored_with_warning() {
        // An includeconf inside an included file must NOT be followed
        // (Core's recursion guard). deep.conf would set maxconnections,
        // but it's never read; instead a warning is queued.
        let (_d, cfg) = load_with_files(
            "includeconf=mid.conf\n",
            &[
                ("mid.conf", "maxconnections=42\nincludeconf=deep.conf\n"),
                ("deep.conf", "maxconnections=999\n"),
            ],
        );
        let cfg = cfg.unwrap();
        assert_eq!(cfg.maxconnections, 42, "mid.conf value should apply");
        assert_ne!(cfg.maxconnections, 999, "nested include must not be followed");
        assert!(
            cfg.pending_notes
                .iter()
                .any(|n| n.message.contains("nested includes are not processed")),
            "expected a warning about the ignored nested include"
        );
    }

    #[test]
    fn includeconf_missing_file_hard_errors() {
        let (_d, cfg) = load_with_files("includeconf=nope.conf\n", &[]);
        let err = cfg.unwrap_err();
        assert!(err.contains("includeconf"), "error should name includeconf: {err}");
        assert!(err.contains("nope.conf"), "error should name the missing file: {err}");
    }

    #[test]
    fn includeconf_bad_key_in_included_file_hard_errors() {
        // The included file is held to the same strict allowlist.
        let (_d, cfg) =
            load_with_files("includeconf=bad.conf\n", &[("bad.conf", "rpusser=typo\n")]);
        let err = cfg.unwrap_err();
        assert!(err.contains("rpusser"), "should reject the typo'd key: {err}");
    }

    #[test]
    fn includeconf_section_scoped_to_active_network() {
        // includeconf under [regtest] only fires on regtest. Loading on
        // regtest pulls it in; loading the same file on mainnet does not.
        let main = "[regtest]\nincludeconf=rt.conf\n";
        let inc = [("rt.conf", "rpcport=19999\n")];

        let (_d, cfg) = load_with_files(main, &inc);
        assert_eq!(cfg.unwrap().rpcport, 19999, "regtest section include should apply");

        // Same files, but loaded on mainnet → the [regtest] include is
        // never processed.
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("bitcoin.conf"), main).unwrap();
        std::fs::write(tmpdir.path().join("rt.conf"), inc[0].1).unwrap();
        let conf_path = tmpdir.path().join("bitcoin.conf");
        let cli = CliArgs::try_parse_from([
            "satd",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.rpcport, 8332, "mainnet must not process the [regtest] include");
    }

    #[test]
    fn command_line_includeconf_is_rejected() {
        // Matches Core: -includeconf on the command line is rejected with
        // an error ("cannot be used from commandline"), not accepted and
        // ignored — so a config that fails fast under Core also fails fast
        // under satd instead of booting without the included settings.
        let tmpdir = tempfile::tempdir().unwrap();
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--includeconf",
            "would-be-ignored.conf",
        ])
        .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(
            err.contains("includeconf cannot be used from commandline"),
            "expected a hard error rejecting command-line includeconf, got: {err}"
        );
    }

    // ---- comprehensive `-no` negation + value-accepting boolean flags ----

    /// Run `args` through the full CLI pipeline (normalize_args →
    /// clap → from_cli) the same way `main` does.
    fn parse_negation(args: &[&str]) -> Result<Config, String> {
        let normalized = normalize_args(args.iter().map(|s| s.to_string()).collect());
        let cli = CliArgs::try_parse_from(normalized).map_err(|e| e.to_string())?;
        Config::from_cli(cli)
    }

    #[test]
    fn noserver_negates_former_settrue_flag_and_overrides_config() {
        // The key correctness test: `-noserver` (a flag that used to be
        // clap SetTrue and rejected a value) must both parse AND defeat
        // a config-file `server=1`.
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("bitcoin.conf"), "server=1\n").unwrap();
        let conf_path = tmpdir.path().join("bitcoin.conf");
        let cfg = parse_negation(&[
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
            "-noserver",
        ])
        .unwrap();
        assert!(!cfg.server, "-noserver must override config server=1");
    }

    #[test]
    fn noregtest_resolves_to_mainnet() {
        // `-noregtest` on a former network-selector should disable the
        // regtest selection, leaving mainnet.
        let tmpdir = tempfile::tempdir().unwrap();
        let cfg = parse_negation(&[
            "satd",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "-noregtest",
        ])
        .unwrap();
        assert_eq!(cfg.network, Network::Bitcoin, "-noregtest should leave mainnet");
    }

    #[test]
    fn txindex_zero_overrides_config_one() {
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("bitcoin.conf"), "txindex=1\n").unwrap();
        let conf_path = tmpdir.path().join("bitcoin.conf");
        let cfg = parse_negation(&[
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "--conf",
            conf_path.to_str().unwrap(),
            "--txindex=0",
            // esplora defaults on and refuses to start with txindex
            // explicitly disabled; disable it to isolate the assertion.
            "--esplora=0",
        ])
        .unwrap();
        assert!(!cfg.txindex, "--txindex=0 must override config txindex=1");
    }

    #[test]
    fn bare_former_settrue_flag_still_enables() {
        // A bare `-server` (no value) must still turn the flag on via
        // default_missing_value.
        let tmpdir = tempfile::tempdir().unwrap();
        let cfg = parse_negation(&[
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "-server",
        ])
        .unwrap();
        assert!(cfg.server, "bare -server should enable server");
    }

    #[test]
    fn listen_negation_and_value_forms() {
        // `listen` was already Option<bool>; verify both `-nolisten`
        // and `--listen=0` disable it now that it is value-accepting.
        let tmpdir = tempfile::tempdir().unwrap();
        let dd = tmpdir.path().to_str().unwrap();

        let cfg = parse_negation(&["satd", "--regtest", "--datadir", dd, "-nolisten"]).unwrap();
        assert!(!cfg.listen, "-nolisten should disable listen");

        let cfg = parse_negation(&["satd", "--regtest", "--datadir", dd, "--listen=0"]).unwrap();
        assert!(!cfg.listen, "--listen=0 should disable listen");
    }

    #[test]
    fn nodnsseed_still_works_regression() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cfg = parse_negation(&[
            "satd",
            "--regtest",
            "--datadir",
            tmpdir.path().to_str().unwrap(),
            "-nodnsseed",
        ])
        .unwrap();
        assert!(!cfg.dnsseed, "-nodnsseed should disable dnsseed");
    }

    // ---- testnet4 ----

    #[test]
    fn testnet4_via_chain_selector() {
        let cli = CliArgs::try_parse_from(["satd", "--chain=testnet4"]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Testnet4);
        assert_eq!(cfg.rpcport, 48332);
        assert_eq!(cfg.port, 48333);
    }

    #[test]
    fn testnet4_via_flag() {
        let cli = CliArgs::try_parse_from(["satd", "--testnet4"]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Testnet4);
    }

    #[test]
    fn testnet4_negation_resolves_to_mainnet() {
        let argv = normalize_args(vec!["satd".into(), "-notestnet4".into()]);
        let cli = CliArgs::try_parse_from(argv).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Bitcoin);
    }

    #[test]
    fn testnet4_conflicts_with_chain() {
        let cli = CliArgs::try_parse_from(["satd", "--chain=main", "--testnet4"]).unwrap();
        assert!(Config::from_cli(cli).is_err());
    }

    #[test]
    fn parse_chain_name_accepts_testnet4() {
        assert_eq!(parse_chain_name("testnet4").unwrap(), Network::Testnet4);
    }

    // ---- forcednsseed / fixedseeds ----

    #[test]
    fn forcednsseed_fixedseeds_defaults() {
        let cfg = Config::from_cli(CliArgs::try_parse_from(["satd", "--regtest"]).unwrap()).unwrap();
        assert!(!cfg.forcednsseed, "forcednsseed defaults off");
        assert!(cfg.fixedseeds, "fixedseeds defaults on");
    }

    #[test]
    fn forcednsseed_and_fixedseeds_flags() {
        let cfg = Config::from_cli(
            CliArgs::try_parse_from(["satd", "--regtest", "--forcednsseed", "--fixedseeds=0"])
                .unwrap(),
        )
        .unwrap();
        assert!(cfg.forcednsseed);
        assert!(!cfg.fixedseeds);
    }

    #[test]
    fn forcednsseed_fixedseeds_negation() {
        let argv = normalize_args(
            ["satd", "--regtest", "-nofixedseeds"].iter().map(|s| s.to_string()).collect(),
        );
        let cfg = Config::from_cli(CliArgs::try_parse_from(argv).unwrap()).unwrap();
        assert!(!cfg.fixedseeds);
    }

    #[test]
    fn forcednsseed_fixedseeds_recognised() {
        assert_eq!(classify_unsupported_key("forcednsseed"), None);
        assert_eq!(classify_unsupported_key("fixedseeds"), None);
        assert!(is_known_config_key("forcednsseed") && is_known_config_key("fixedseeds"));
    }

    // ---- asmap ----

    #[test]
    fn asmap_resolves_relative_to_datadir_and_requires_file() {
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("ip_asn.map"), b"\x00\x00").unwrap();
        let cli = CliArgs::try_parse_from([
            "satd", "--regtest",
            "--datadir", tmpdir.path().to_str().unwrap(),
            "--asmap", "ip_asn.map",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.asmap, Some(tmpdir.path().join("ip_asn.map")));
    }

    #[test]
    fn asmap_missing_file_errors() {
        let tmpdir = tempfile::tempdir().unwrap();
        let cli = CliArgs::try_parse_from([
            "satd", "--regtest",
            "--datadir", tmpdir.path().to_str().unwrap(),
            "--asmap", "nope.map",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).unwrap_err().contains("asmap file not found"));
    }

    #[test]
    fn asmap_now_recognised() {
        assert_eq!(classify_unsupported_key("asmap"), None);
        assert!(is_known_config_key("asmap"));
    }

    // ---- maxuploadtarget ----

    #[test]
    fn maxuploadtarget_size_parsing() {
        // bare number = MiB
        assert_eq!(parse_maxuploadtarget("500").unwrap(), 500 * 1024 * 1024);
        assert_eq!(parse_maxuploadtarget("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_maxuploadtarget("10mib").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_maxuploadtarget("2048k").unwrap(), 2048 * 1024);
        assert_eq!(parse_maxuploadtarget("0").unwrap(), 0); // unlimited
        assert!(parse_maxuploadtarget("5Z").is_err());
        assert!(parse_maxuploadtarget("abc").is_err());
    }

    #[test]
    fn maxuploadtarget_flows_to_config() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--maxuploadtarget", "250M"]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.max_upload_target, 250 * 1024 * 1024);
        // default off
        let cli2 = CliArgs::try_parse_from(["satd", "--regtest"]).unwrap();
        assert_eq!(Config::from_cli(cli2).unwrap().max_upload_target, 0);
    }

    // ---- whitelist / whitebind ----

    #[test]
    fn whitelist_parses_perms_and_subnet() {
        let cli = CliArgs::try_parse_from([
            "satd", "--regtest",
            "--whitelist", "noban,relay@10.0.0.0/8",
            "--whitelist", "192.168.1.5",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.whitelist.len(), 2);
        assert!(cfg.whitelist[0].perms.noban && cfg.whitelist[0].perms.relay);
        // bare subnet → implicit perms
        assert_eq!(
            cfg.whitelist[1].perms,
            node::net::permissions::NetPermissions::implicit()
        );
    }

    #[test]
    fn whitebind_parses_addr_and_perms() {
        let cli = CliArgs::try_parse_from([
            "satd", "--regtest",
            "--whitebind", "noban@127.0.0.1:19999",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.whitebind.len(), 1);
        assert_eq!(cfg.whitebind[0].0.to_string(), "127.0.0.1:19999");
        assert!(cfg.whitebind[0].1.noban);
    }

    #[test]
    fn whitelist_invalid_subnet_errors() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--whitelist", "relay@not-an-ip"])
                .unwrap();
        assert!(Config::from_cli(cli).unwrap_err().contains("whitelist"));
    }

    #[test]
    fn whitelist_whitebind_now_recognised() {
        assert_eq!(classify_unsupported_key("whitelist"), None);
        assert_eq!(classify_unsupported_key("whitebind"), None);
        assert!(is_known_config_key("whitelist") && is_known_config_key("whitebind"));
    }

    // ---- externalip ----

    #[test]
    fn externalip_parses_ip_and_ip_port() {
        let cli = CliArgs::try_parse_from([
            "satd", "--regtest",
            "--externalip", "203.0.113.7",
            "--externalip", "198.51.100.9:12345",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.externalip.len(), 2);
        // bare IP inherits the regtest default P2P port (18444)
        assert_eq!(cfg.externalip[0].to_string(), "203.0.113.7:18444");
        assert_eq!(cfg.externalip[1].to_string(), "198.51.100.9:12345");
    }

    #[test]
    fn externalip_rejects_hostname() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--externalip", "node.example.com"])
                .unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("externalip"), "got: {err}");
    }

    // ---- blocksonly ----

    #[test]
    fn blocksonly_defaults_false() {
        let cli = CliArgs::try_parse_from(["satd", "--regtest"]).unwrap();
        assert!(!Config::from_cli(cli).unwrap().blocksonly);
    }

    #[test]
    fn blocksonly_flag_and_negation() {
        let cli = CliArgs::try_parse_from(["satd", "--regtest", "--blocksonly"]).unwrap();
        assert!(Config::from_cli(cli).unwrap().blocksonly);

        let argv = normalize_args(
            ["satd", "--regtest", "-noblocksonly"].iter().map(|s| s.to_string()).collect(),
        );
        let cli = CliArgs::try_parse_from(argv).unwrap();
        assert!(!Config::from_cli(cli).unwrap().blocksonly);
    }

    // ---- v2transport / v2only ----

    #[test]
    fn v2transport_defaults_true_v2only_false() {
        let cli = CliArgs::try_parse_from(["satd", "--regtest"]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.v2transport, "v2transport should default on (Core parity)");
        assert!(!cfg.v2only);
    }

    #[test]
    fn v2transport_negation_and_v2only_flag() {
        let argv = normalize_args(
            ["satd", "--regtest", "-nov2transport"].iter().map(|s| s.to_string()).collect(),
        );
        let cli = CliArgs::try_parse_from(argv).unwrap();
        assert!(!Config::from_cli(cli).unwrap().v2transport);

        let cli = CliArgs::try_parse_from(["satd", "--regtest", "--v2only"]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.v2only);
    }

    // ---- signetchallenge: custom signet (BIP 325) ----

    #[test]
    fn signetchallenge_parses_hex_on_signet() {
        let hex = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
        let cli = CliArgs::try_parse_from(["satd", "--signet", "--signetchallenge", hex]).unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.network, Network::Signet);
        let ch = cfg.signet_challenge.expect("challenge should be set");
        use bitcoin::hashes::hex::DisplayHex;
        assert_eq!(ch.as_hex().to_string(), hex);
    }

    #[test]
    fn signetchallenge_rejected_off_signet() {
        // On mainnet the flag is meaningless — must hard-error, not be
        // silently accepted-and-ignored.
        let cli = CliArgs::try_parse_from(["satd", "--signetchallenge", "5187"]).unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("signetchallenge"), "got: {err}");
        assert!(err.contains("signet"), "error should mention signet: {err}");
    }

    #[test]
    fn signetchallenge_invalid_hex_errors() {
        let cli =
            CliArgs::try_parse_from(["satd", "--signet", "--signetchallenge", "zzzz"]).unwrap();
        let err = Config::from_cli(cli).unwrap_err();
        assert!(err.contains("not valid hex"), "got: {err}");
    }

    #[test]
    fn signetchallenge_is_now_recognised() {
        assert_eq!(classify_unsupported_key("signetchallenge"), None);
        assert!(is_known_config_key("signetchallenge"));
    }

    // ---- PR-3: hard-error on unknown keys + --timeout unit fix ----

    #[test]
    fn unknown_config_key_hard_errors() {
        // Typo in rpcuser → rpusser. This is exactly the silent-
        // misconfiguration scenario this PR exists to prevent. The
        // operator's config file should fail to load, citing the
        // specific line number.
        let content = "\
rpcuser=alice
rpusser=oops
rpcpassword=secret
";
        let err = ConfigFile::parse(content).unwrap_err();
        assert!(
            err.contains("line 2"),
            "expected line 2 in error, got: {err}"
        );
        assert!(
            err.contains("rpusser"),
            "expected the bad key in the error, got: {err}"
        );
        assert!(
            err.contains("Error reading configuration file"),
            "expected Core-style prefix, got: {err}"
        );
    }

    #[test]
    fn unknown_key_in_section_hard_errors() {
        let content = "\
[regtest]
notarealkey=1
";
        let err = ConfigFile::parse(content).unwrap_err();
        assert!(err.contains("notarealkey"));
        assert!(err.contains("line 2"));
    }

    #[test]
    fn wallet_keys_skipped_with_warning_not_fatal() {
        // satd is keyless (no wallet), but a Core operator's bitcoin.conf
        // commonly carries `wallet=` lines. For drop-in compatibility these
        // are recognized Core keys → skipped with a warning, NOT fatal, so the
        // node still starts. (They are not auth/exposure/privacy keys.)
        let cf = ConfigFile::parse("wallet=mywallet.dat\nserver=1\n").unwrap();
        assert!(!cf.global.contains_key("wallet"), "wallet should be skipped");
        assert!(cf.global.contains_key("server"));
        assert!(
            cf.ignored.iter().any(|m| m.contains("wallet")),
            "expected a skip warning naming the wallet key, got: {:?}",
            cf.ignored
        );
    }

    #[test]
    fn all_known_keys_round_trip() {
        // Every entry in KNOWN_CONFIG_KEYS must round-trip through
        // ConfigFile::parse. This catches the case where someone
        // adds a key to the allowlist without making it actually
        // parseable (e.g. accidentally introducing whitespace in
        // the constant).
        for key in KNOWN_CONFIG_KEYS {
            let content = format!("{key}=1\n");
            let cf = ConfigFile::parse(&content)
                .unwrap_or_else(|e| panic!("known key {key:?} failed to parse: {e}"));
            assert!(
                cf.global.contains_key(*key),
                "key {key:?} parsed but didn't land in global map"
            );
        }
    }

    #[test]
    fn pr1_and_pr2_keys_are_known() {
        // Cross-PR guard: PR-1's keys (rpcbind family, rpcauth,
        // cookie controls) and PR-2's IMPLEMENTED keys (chain,
        // blocksdir, signetseednode) MUST be in the allowlist even
        // though those clap bindings live on other branches. This way
        // PR-3's hard-error doesn't immediately break an operator
        // running PR-1+PR-2+PR-3 post-merge.
        let pr1_keys = [
            "rpcbind",
            "rpcallowip",
            "rpcauth",
            "rpccookiefile",
            "rpccookieperms",
        ];
        let pr2_keys = ["chain", "blocksdir", "signetseednode"];
        for k in pr1_keys.iter().chain(pr2_keys.iter()) {
            assert!(
                is_known_config_key(k),
                "{k:?} should be in KNOWN_CONFIG_KEYS"
            );
        }
    }

    #[test]
    fn fatal_unsupported_keys_hard_error_with_guidance() {
        // The small set where silently skipping would mislead the operator
        // about security / exposure / privacy. These stay fatal with an
        // actionable, per-key message.
        for (k, _) in FATAL_UNSUPPORTED_KEYS {
            assert!(classify_unsupported_key(k).is_some(), "{k:?} should be fatal");
            assert!(!is_known_config_key(k), "{k:?} must not be honored");
            let err = ConfigFile::parse(&format!("{k}=1")).unwrap_err();
            assert!(
                err.contains("does not support")
                    && err.contains("Remove this line")
                    && err.contains(k),
                "expected a fatal error for {k:?}, got: {err}"
            );
        }
    }

    #[test]
    fn skip_guidance_entries_are_reachable() {
        // Invariant: every key with prepared SKIP_GUIDANCE must actually reach
        // the warn-and-skip path. If a key is not a recognized Core v30 key it
        // is typo-rejected before guidance is consulted; if it is honored the
        // guidance is dead; if it is fatal the guidance is also unreachable.
        // This guards against guidance silently rotting (e.g. a key that Core
        // later removes, or one that satd starts honoring).
        for (k, _) in SKIP_GUIDANCE {
            assert!(
                is_core_v30_key(k),
                "{k:?} has skip guidance but isn't a Core v30 key — it would be \
                 rejected as a typo before the guidance is ever shown"
            );
            assert!(
                !is_known_config_key(k),
                "{k:?} has skip guidance but is honored — the guidance is dead code"
            );
            assert!(
                classify_unsupported_key(k).is_none(),
                "{k:?} has skip guidance but is also fatal — guidance unreachable"
            );
            // And it must genuinely be reachable end-to-end.
            let cf = ConfigFile::parse(&format!("{k}=1\n"))
                .unwrap_or_else(|e| panic!("{k:?} should warn-and-skip, not error: {e}"));
            assert!(
                cf.ignored.iter().any(|m| m.contains(*k)),
                "{k:?} produced no warn-and-skip notice"
            );
        }
    }

    #[test]
    fn logging_file_keys_are_dropin_skipped_not_typos() {
        // Core's debug.log knobs are real v30 options satd has no analogue for
        // (it logs to stdout/journald). A dropped-in Core config carrying them
        // — `printtoconsole` is near-ubiquitous in containerized setups — must
        // boot, not hard-error as a typo.
        for k in ["printtoconsole", "debuglogfile", "shrinkdebugfile"] {
            let cf = ConfigFile::parse(&format!("{k}=1\nserver=1\n"))
                .unwrap_or_else(|e| panic!("{k:?} should be skipped, not rejected: {e}"));
            assert!(!cf.global.contains_key(k), "{k:?} should not be honored");
            assert!(
                cf.ignored.iter().any(|m| m.contains(k) && m.contains("debug.log")),
                "{k:?} warning should explain the no-debug.log behavior, got: {:?}",
                cf.ignored
            );
        }
    }

    #[test]
    fn unsupported_core_keys_warn_and_skip_for_dropin() {
        // Drop-in goal: a recognized-but-unsupported Core v30 key does NOT
        // stop the node — it is skipped with a warning and the rest of the
        // config still loads.
        let cf = ConfigFile::parse(
            "maxorphantx=100\ncoinstatsindex=1\nprintpriority=1\nserver=1\n",
        )
        .unwrap();
        // The supported key is stored; the skipped ones are not.
        assert!(cf.global.contains_key("server"));
        assert!(!cf.global.contains_key("maxorphantx"));
        assert!(!cf.global.contains_key("coinstatsindex"));
        // Each skipped key produced a warning naming it.
        assert_eq!(cf.ignored.len(), 3, "got: {:?}", cf.ignored);
        assert!(cf.ignored.iter().any(|m| m.contains("maxorphantx")));
        assert!(cf.ignored.iter().any(|m| m.contains("coinstatsindex")));
    }

    #[test]
    fn skipped_key_warnings_name_the_satd_equivalent() {
        // Where a skipped key has a satd replacement, the warning points to it.
        let cases = [
            ("rest", "-esplora"),
            ("zmqpubrawtx", "-eventszmqbind"),
            ("peerbloomfilters", "-blockfilterindex"),
            ("maxorphantx", "removed in Bitcoin Core v30"),
        ];
        for (k, needle) in cases {
            let cf = ConfigFile::parse(&format!("{k}=1\n")).unwrap();
            assert!(
                cf.ignored.iter().any(|m| m.contains(needle) && m.contains(k)),
                "expected {k:?} warning to mention {needle:?}, got: {:?}",
                cf.ignored
            );
        }
    }

    #[test]
    fn typo_keys_still_hard_error() {
        // A key that is neither a satd option nor a known Core v30 option is
        // treated as a typo and rejected — this protects a fat-fingered
        // security option (e.g. `rpcusser=`) from silently disabling auth.
        for typo in ["rpcusser", "rpcpasword", "totallymadeup"] {
            let err = ConfigFile::parse(&format!("{typo}=x")).unwrap_err();
            assert!(
                err.contains("unrecognized key") && err.contains("typo"),
                "expected a typo error for {typo:?}, got: {err}"
            );
        }
    }

    #[test]
    fn includeconf_is_now_a_recognised_key() {
        // includeconf used to hard-error (not-yet-implemented). It is
        // now honoured, so the bare parse stores it rather than
        // rejecting it; resolution happens later against the datadir.
        let cf = ConfigFile::parse("includeconf=secrets.conf\nserver=1\n").unwrap();
        assert_eq!(cf.global.get("includeconf").map(|v| v.as_slice()), Some(&["secrets.conf".to_string()][..]));
        assert_eq!(classify_unsupported_key("includeconf"), None);
        assert!(is_known_config_key("includeconf"));
    }

    #[test]
    fn timeout_bare_integer_is_milliseconds() {
        // Bare integer ≥ 1000 = clearly intentional ms; no warning.
        assert_eq!(parse_timeout_value("5000").unwrap(), 5000);
        assert_eq!(parse_timeout_value("60000").unwrap(), 60000);
    }

    #[test]
    fn timeout_explicit_seconds_suffix() {
        assert_eq!(parse_timeout_value("5s").unwrap(), 5000);
        assert_eq!(parse_timeout_value("60s").unwrap(), 60_000);
        // Whitespace-tolerant.
        assert_eq!(parse_timeout_value("  10s  ").unwrap(), 10_000);
    }

    #[test]
    fn timeout_explicit_milliseconds_suffix() {
        assert_eq!(parse_timeout_value("5000ms").unwrap(), 5000);
        assert_eq!(parse_timeout_value("250ms").unwrap(), 250);
    }

    #[test]
    fn timeout_small_bare_integer_still_works() {
        // The legacy seconds-style value (e.g. `10` from satd-of-the-
        // past) is interpreted as 10 ms. Operator gets a stderr
        // warning (not asserted here — captured warnings need a
        // separate harness) but the value passes through.
        assert_eq!(parse_timeout_value("10").unwrap(), 10);
    }

    #[test]
    fn timeout_garbage_errors() {
        assert!(parse_timeout_value("").is_err());
        assert!(parse_timeout_value("abc").is_err());
        assert!(parse_timeout_value("5seconds").is_err());
        assert!(parse_timeout_value("5x").is_err());
        // Suffix-stripping path: `abcs` strips trailing `s` → "abc"
        // → fails to parse as integer via the seconds-path error.
        let err = parse_timeout_value("abcs").unwrap_err();
        assert!(err.contains("seconds"), "got: {err}");
        // Suffix-stripping path: `xms` strips trailing `ms` → "x"
        // → fails the ms-path int parse.
        let err = parse_timeout_value("xms").unwrap_err();
        assert!(err.contains("ms value"), "got: {err}");
    }

    #[test]
    fn unknown_key_error_flags_a_typo() {
        // A key that is neither a satd option nor a known Core v30 option is
        // rejected as a likely typo (it is not a real Core key we could skip).
        let err = ConfigFile::parse("garbagekey=1\n").unwrap_err();
        assert!(
            err.contains("unrecognized key") && err.contains("typo"),
            "expected a typo rejection, got: {err}"
        );
    }

    // ---- config-migration completeness: listenonion / seeds / debug /
    //      persistmempool ----

    #[test]
    fn listenonion_defaults_off() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir=/tmp/satd-lo-1"]).unwrap();
        assert!(!Config::from_cli(cli).unwrap().listenonion);
    }

    #[test]
    fn listenonion_torcontrol_implies_on() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-lo-2",
            "--torcontrol=127.0.0.1:9051",
        ])
        .unwrap();
        assert!(Config::from_cli(cli).unwrap().listenonion);
    }

    #[test]
    fn listenonion_explicit_off_overrides_torcontrol() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-lo-3",
            "--torcontrol=127.0.0.1:9051",
            "--listenonion=0",
        ])
        .unwrap();
        assert!(!Config::from_cli(cli).unwrap().listenonion);
    }

    #[test]
    fn listenonion_explicit_on_without_torcontrol() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-lo-4",
            "--listenonion=1",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert!(cfg.listenonion);
        assert!(cfg.torcontrol.is_none());
    }

    #[test]
    fn dnsseed_defaults_true_and_parses_false() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir=/tmp/satd-ds-1"]).unwrap();
        assert!(Config::from_cli(cli).unwrap().dnsseed);
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-ds-2",
            "--dnsseed=0",
        ])
        .unwrap();
        assert!(!Config::from_cli(cli).unwrap().dnsseed);
    }

    #[test]
    fn seednode_collects_repeated_values() {
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-sn-1",
            "--seednode=1.2.3.4:8333",
            "--seednode=5.6.7.8",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.seednode, vec!["1.2.3.4:8333", "5.6.7.8"]);
    }

    #[test]
    fn persistmempool_defaults_on_and_parses_off() {
        let cli =
            CliArgs::try_parse_from(["satd", "--regtest", "--datadir=/tmp/satd-pm-1"]).unwrap();
        assert!(Config::from_cli(cli).unwrap().persistmempool);
        let cli = CliArgs::try_parse_from([
            "satd",
            "--regtest",
            "--datadir=/tmp/satd-pm-2",
            "--persistmempool=0",
        ])
        .unwrap();
        assert!(!Config::from_cli(cli).unwrap().persistmempool);
    }

    #[test]
    fn debug_directives_maps_known_categories() {
        let (all, dirs) =
            debug_directives(&["net".to_string(), "mempool".to_string()], &[]);
        assert!(!all);
        assert!(dirs.contains(&"node::net=debug".to_string()));
        assert!(dirs.contains(&"node::mempool=debug".to_string()));
    }

    #[test]
    fn debug_directives_all_enables_and_exclude_claws_back() {
        let (all, dirs) = debug_directives(&["all".to_string()], &["net".to_string()]);
        assert!(all);
        assert!(dirs.contains(&"node::net=info".to_string()));
    }

    #[test]
    fn debug_directives_unknown_category_is_noop() {
        let (all, dirs) = debug_directives(&["qt".to_string(), "zmq".to_string()], &[]);
        assert!(!all);
        assert!(dirs.is_empty());
    }

    #[test]
    fn debug_directives_exclude_removes_included_target() {
        let (_all, dirs) = debug_directives(&["net".to_string()], &["net".to_string()]);
        assert!(dirs.is_empty());
    }

    // ---- H1: raw Core-style single-dash + bare + -no invocations ----

    fn parse_raw(args: &[&str]) -> Config {
        let argv = normalize_args(args.iter().map(|s| s.to_string()).collect());
        let cli = CliArgs::try_parse_from(argv).expect("clap parse");
        Config::from_cli(cli).expect("config build")
    }

    #[test]
    fn bare_single_dash_listenonion_parses_true() {
        // `satd -listenonion` (Core-style bare boolean) must enable it,
        // not error with "a value is required".
        let cfg = parse_raw(&["satd", "-regtest", "-listenonion", "-datadir=/tmp/satd-h1-1"]);
        assert!(cfg.listenonion);
    }

    #[test]
    fn bare_single_dash_dnsseed_and_persistmempool_parse_true() {
        let cfg = parse_raw(&[
            "satd",
            "-regtest",
            "-dnsseed",
            "-persistmempool",
            "-datadir=/tmp/satd-h1-2",
        ]);
        assert!(cfg.dnsseed);
        assert!(cfg.persistmempool);
    }

    #[test]
    fn bare_single_dash_debug_means_all() {
        let cfg = parse_raw(&["satd", "-regtest", "-debug", "-datadir=/tmp/satd-h1-3"]);
        let (enable_all, _) = debug_directives(&cfg.debug, &cfg.debugexclude);
        assert!(enable_all, "bare -debug should enable all categories");
    }

    #[test]
    fn no_prefix_negates_boolean_flags() {
        // `-nolistenonion` / `-nodnsseed` / `-nopersistmempool` map to
        // `--flag=0`. -nolistenonion must even override the
        // torcontrol-implies-on rule.
        let cfg = parse_raw(&[
            "satd",
            "-regtest",
            "-torcontrol=127.0.0.1:9051",
            "-nolistenonion",
            "-nodnsseed",
            "-nopersistmempool",
            "-datadir=/tmp/satd-h1-4",
        ]);
        assert!(!cfg.listenonion);
        assert!(!cfg.dnsseed);
        assert!(!cfg.persistmempool);
    }

    #[test]
    fn valued_single_dash_forms_still_work() {
        let cfg = parse_raw(&[
            "satd",
            "-regtest",
            "-listenonion=1",
            "-dnsseed=0",
            "-datadir=/tmp/satd-h1-5",
        ]);
        assert!(cfg.listenonion);
        assert!(!cfg.dnsseed);
    }
}
