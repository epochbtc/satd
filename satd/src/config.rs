use bitcoin::Network;
use clap::Parser;
use std::collections::HashMap;
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
    pub rpcport: u16,
    pub rpcbind: String,
    pub rpcuser: Option<String>,
    pub rpcpassword: Option<String>,
    pub listen: bool,
    pub port: u16,
    pub connect: Vec<String>,
    pub assumevalid: Option<String>,
    pub assumevalidage: u64,
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
    /// Address-history index (per `ADDRESS_INDEX.md`). On by default;
    /// disable via `--addressindex=0` or `-noindex=address`. Backs the
    /// future native Electrum and Esplora subsystems.
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
    pub prune: u64,
    pub reindex: bool,
    pub reindex_chainstate: bool,
    // P2P
    pub maxconnections: usize,
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
        let cli = CliArgs::try_parse_from(normalized).map_err(|e| e.to_string())?;
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

        // Determine network from CLI flags
        let network = if cli.regtest || profile_defaults.network_regtest {
            Network::Regtest
        } else if cli.testnet {
            Network::Testnet
        } else if cli.signet || profile_defaults.network_signet {
            Network::Signet
        } else {
            Network::Bitcoin
        };

        // Determine datadir
        let base_datadir = cli.datadir.unwrap_or_else(default_datadir);

        // Determine config file path and parse it
        let conf_path = cli
            .conf
            .unwrap_or_else(|| base_datadir.join("bitcoin.conf"));
        let config_file = if conf_path.exists() {
            Some(ConfigFile::parse_file(&conf_path)?)
        } else {
            None
        };

        // Section name for the active network
        let section = match network {
            Network::Regtest => "regtest",
            Network::Testnet => "test",
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

        let rpcbind = file_get("rpcbind").unwrap_or_else(|| "127.0.0.1".to_string());

        let rpcuser = cli.rpcuser.or_else(|| file_get("rpcuser"));
        let rpcpassword = cli.rpcpassword.or_else(|| file_get("rpcpassword"));

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
            rpcport,
            rpcbind,
            rpcuser,
            rpcpassword,
            listen,
            port,
            connect,
            assumevalid,
            assumevalidage,
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
            electrum_max_conns,
            electrum_max_subs_per_conn,
            electrum_request_timeout,
            electrum_max_batch_requests,
            electrum_max_broadcast_package_txs,
            electrum_fee_histogram_ttl,
            electrum_banner,
            prune,
            reindex: cli.reindex,
            reindex_chainstate: cli.reindex_chainstate,
            maxconnections: cli
                .maxconnections
                .or_else(|| file_get("maxconnections").and_then(|v| v.parse().ok()))
                .or(profile_defaults.maxconnections)
                .unwrap_or(125),
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
            "profile": self.profile.map(|p| p.as_str()).unwrap_or("(none)"),
            "rpc": {
                "port": self.rpcport,
                "bind": self.rpcbind,
                "user": self.rpcuser.as_deref().unwrap_or("(cookie)"),
                "password": if self.rpcpassword.is_some() { "(set)" } else { "(none)" },
                "extended_errors": self.rpc_extended_errors,
                "default_units": self.rpc_default_units.as_str(),
            },
            "p2p": {
                "listen": self.listen,
                "port": self.port,
                "max_connections": self.maxconnections,
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

    #[arg(long, value_name = "DIR", help = "Data directory")]
    pub datadir: Option<PathBuf>,

    #[arg(long, value_name = "FILE", help = "Config file path")]
    pub conf: Option<PathBuf>,

    #[arg(long, value_name = "PORT", help = "RPC server port")]
    pub rpcport: Option<u16>,

    #[arg(long, value_name = "USER", help = "RPC username")]
    pub rpcuser: Option<String>,

    #[arg(long, value_name = "PASS", help = "RPC password")]
    pub rpcpassword: Option<String>,

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
        "datadir",
        "conf",
        "rpcport",
        "rpcuser",
        "rpcpassword",
        "listen",
        "port",
        "connect",
        "assumevalid",
        "assumevalidage",
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
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: None,
            rpcpassword: None,
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            assumevalidage: None,
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
            electrummaxconns: None,
            electrummaxsubsperconn: None,
            electrumrequesttimeout: None,
            electrummaxbatchrequests: None,
            electrummaxbroadcastpackagetxs: None,
            electrumfeehistogramttl: None,
            electrumbanner: None,
            prune: None,
            reindex: false,
            reindex_chainstate: false,
            maxconnections: None,
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
            datadir: Some(PathBuf::from("/tmp/satd-test")),
            conf: None,
            rpcport: None,
            rpcuser: Some("alice".to_string()),
            rpcpassword: None, // missing password
            listen: None,
            port: None,
            connect: vec![],
            assumevalid: None,
            assumevalidage: None,
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
            electrummaxconns: None,
            electrummaxsubsperconn: None,
            electrumrequesttimeout: None,
            electrummaxbatchrequests: None,
            electrummaxbroadcastpackagetxs: None,
            electrumfeehistogramttl: None,
            electrumbanner: None,
            prune: None,
            reindex: false,
            reindex_chainstate: false,
            maxconnections: None,
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
}
