//! File-descriptor budget at startup, after Bitcoin Core's
//! `AppInitParameterInteraction` (v32.1 `src/init.cpp`) and its
//! `RaiseFileDescriptorLimit` (`src/util/fs_helpers.cpp`).
//!
//! Core asks for enough descriptors for its own needs plus every automatic
//! peer, raises the soft `RLIMIT_NOFILE` toward that (never past the hard
//! limit), and then:
//!
//! - refuses to start, "Not enough file descriptors available. X available,
//!   Y required.", when even its own needs do not fit;
//! - otherwise lowers `-maxconnections` to what is left, "Reducing
//!   -maxconnections from X to Y, because of system limitations."
//!
//! satd does the same with its own needs, which are larger than Core's:
//!
//! ```text
//! required = MIN_SATD_FDS                       stdio, logs, block files, RocksDB's
//!                                               own WAL/MANIFEST/LOG files, runtime
//!          + maxopenfiles                       RocksDB table files (when > 0)
//!          + 8                                  -addnode peers (MAX_ADDNODE_CONNECTIONS)
//!          + max(1, bind + whitebind)           P2P listeners
//!          + 1 with -listenonion                Tor control (the onion listener is a bind)
//!          + 2 with -nap                        attestation pulls
//!          + 1 with -peersurvey                 the survey connection (not
//!                                               with -crawl, which supersedes it)
//!          + with -crawl, up to                 crawl sessions, fitted last:
//!            crawlconcurrency                   lowered with a line in the log
//!            + crawltorconcurrency              to what is left, never -maxconnections
//!          + per RPC listener (plain, TLS,
//!            read-only, read-only TLS):  1 + RPC_MAX_CONNECTIONS (100)
//!          + Esplora:   listeners + esploramaxsockets
//!                       (esploramaxconns + esplorasseconns if 0)
//!          + Electrum:  listeners + electrummaxconns
//!          + Stratum:   listeners + stratummaxconns
//!          + events gRPC: 1 + eventsgrpcmaxconns
//!          + streamws:  1 + streamwsmaxsockets (streamwsmaxconns if 0)
//!          + MCP HTTP:  1 + 128
//!          + metrics:   1 + 64, and 1 + 64 for its TLS listener
//!          + 1 per ZMQ endpoint
//! total    = required + maxconnections
//! ```
//!
//! A surface counts only when it is enabled. A cap that is off
//! (`maxopenfiles=-1`, an Esplora or streamws socket cap and its
//! connection caps all `0`) has no number to budget and counts nothing; neither do ZMQ subscribers or an
//! AssumeUTXO background chainstate, whose RocksDB keeps every file open.
//!
//! `MIN_SATD_FDS` is Core's `MIN_CORE_FDS` (150 for LevelDB plus one for
//! message capture). An idle regtest node holds 39 descriptors, eight of
//! them sockets; a mainnet node adds block and undo files (eight cached
//! readers plus the writers) and more RocksDB WAL and directory handles,
//! which the margin covers. RocksDB's table files are counted apart, by
//! `maxopenfiles`.
//!
//! The descriptors left after `required` go to automatic peers. A SIGHUP
//! that raises `-maxconnections` is fitted into the same room, since the
//! limit was set at startup.

use crate::config::Config;

/// satd's descriptors outside RocksDB's table files, the listeners and the
/// peers. Core's `MIN_CORE_FDS` (`src/init.cpp`).
pub const MIN_SATD_FDS: u64 = 151;

/// Core's text when even the minimum does not fit (`InitError` in
/// `AppInitParameterInteraction`).
#[derive(Debug, PartialEq, Eq)]
pub struct NotEnough {
    pub available: u64,
    pub required: u64,
}

impl std::fmt::Display for NotEnough {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Not enough file descriptors available. {} available, {} required.",
            self.available, self.required
        )
    }
}

/// The descriptor limit the node runs under and what it needs before any
/// automatic peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdBudget {
    pub available: u64,
    pub required: u64,
}

impl FdBudget {
    /// `-maxconnections` fitted into what is left, Core's
    /// `std::min(available_fds - min_required_fds, user_max_connections)`.
    /// The note carries Core's warning when the value had to be lowered.
    pub fn fit(&self, maxconnections: usize) -> (usize, Option<String>) {
        let room = self.available.saturating_sub(self.required);
        let fitted = usize::try_from(room).unwrap_or(usize::MAX).min(maxconnections);
        let note = (fitted < maxconnections).then(|| {
            format!(
                "Reducing -maxconnections from {maxconnections} to {fitted}, because of system limitations."
            )
        });
        (fitted, note)
    }
}

/// Check the budget the way Core does: refuse when `required` does not
/// fit in `available`.
pub fn check(available: u64, required: u64) -> Result<FdBudget, NotEnough> {
    if available < required {
        return Err(NotEnough { available, required });
    }
    Ok(FdBudget { available, required })
}

/// The least a cap left at its default is shrunk to: 64, Core's LevelDB
/// `max_open_files` on hosts where its table files hold real descriptors
/// (`SetMaxOpenFiles`, `src/dbwrapper.cpp`), and the default of satd's
/// smallest connection caps. A default below it is its own floor.
pub const DEFAULT_CAP_FLOOR: u64 = 64;

/// One line of satd's needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Descriptors satd needs whatever the limit: the base, listeners,
    /// constant caps, and every cap the operator set.
    Fixed(u64),
    /// A cap left at its default (`option` names it): it needs `floor`,
    /// and takes up to `default` from what is left once the fixed needs
    /// and `-maxconnections` are met.
    Default { option: &'static str, default: u64, floor: u64 },
}

impl Need {
    fn hard(&self) -> u64 {
        match *self {
            Need::Fixed(n) => n,
            Need::Default { floor, .. } => floor,
        }
    }

    fn headroom(&self) -> u64 {
        match *self {
            Need::Fixed(_) => 0,
            Need::Default { default, floor, .. } => default - floor,
        }
    }
}

/// A cap that was shrunk to fit: its option, its default and the value
/// the node runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FittedCap {
    pub option: &'static str,
    pub default: u64,
    pub fitted: u64,
}

impl FittedCap {
    /// The line logged for it, after Core's `-maxconnections` warning.
    pub fn note(&self) -> String {
        format!(
            "Reducing -{} from {} to {}, because of system limitations.",
            self.option, self.default, self.fitted
        )
    }
}

/// What the budget decided at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The limit and everything but the automatic peers, as the node runs;
    /// a reloaded `-maxconnections` is fitted into it.
    pub budget: FdBudget,
    /// `-maxconnections` as fitted, and Core's warning if it was lowered.
    pub max_connections: usize,
    pub max_connections_note: Option<String>,
    /// The default caps that were lowered.
    pub fitted: Vec<FittedCap>,
}

/// The descriptors to ask the system for: every need at its full value,
/// plus `-maxconnections`.
pub fn wanted(items: &[(&'static str, Need)], maxconnections: usize) -> u64 {
    items
        .iter()
        .fold(maxconnections as u64, |acc, (_, n)| acc.saturating_add(n.hard()).saturating_add(n.headroom()))
}

/// The hard minimum: the fixed needs and each default cap's floor.
pub fn required(items: &[(&'static str, Need)]) -> u64 {
    items.iter().fold(0u64, |acc, (_, n)| acc.saturating_add(n.hard()))
}

/// Fit the node into `available`, in Core's order: refuse if the hard
/// minimum does not fit, then fit `-maxconnections` as Core does, then
/// give what is left to the caps left at their defaults, each in
/// proportion to its headroom above its floor.
pub fn plan(items: &[(&'static str, Need)], maxconnections: usize, available: u64) -> Result<Plan, NotEnough> {
    let hard = check(available, required(items))?;
    let (max_connections, max_connections_note) = hard.fit(maxconnections);
    let left = available - hard.required - max_connections as u64;
    let headroom: u64 = items.iter().fold(0u64, |acc, (_, n)| acc.saturating_add(n.headroom()));
    let mut used = hard.required;
    let mut fitted = Vec::new();
    for (_, need) in items {
        let Need::Default { option, default, floor } = *need else { continue };
        let extra = if left >= headroom {
            default - floor
        } else {
            (u128::from(default - floor) * u128::from(left) / u128::from(headroom)) as u64
        };
        used += extra;
        if floor + extra < default {
            fitted.push(FittedCap { option, default, fitted: floor + extra });
        }
    }
    Ok(Plan { budget: FdBudget { available, required: used }, max_connections, max_connections_note, fitted })
}

/// A connection cap as the surface applies it: clamped to
/// [`node::http_serve::CAP_CEILING`], `0` read as `0` (no cap, nothing to
/// budget) unless the surface takes `0` as `1`.
fn cap(n: usize) -> u64 {
    node::http_serve::clamp_cap(n) as u64
}

/// The need for cap `option` with value `n`: [`Need::Default`] if the
/// operator left it at its default, else fixed at its value.
fn cap_need(config: &Config, option: &'static str, n: u64) -> Need {
    if config.caps_at_default.contains(&option) && n > 0 {
        Need::Default { option, default: n, floor: n.min(DEFAULT_CAP_FLOOR) }
    } else {
        Need::Fixed(n)
    }
}

/// A crawl limit's need: all of it is headroom over a floor of none.
fn crawl_need(option: &'static str, n: usize) -> Need {
    Need::Default { option, default: n as u64, floor: 0 }
}

/// satd's needs apart from the automatic peers, itemized. See the module
/// docs for the formula.
pub fn needs(config: &Config) -> Vec<(&'static str, Need)> {
    let fixed = |n: u64| Need::Fixed(n);
    let mut items: Vec<(&'static str, Need)> = vec![("base", fixed(MIN_SATD_FDS))];
    if config.max_open_files > 0 {
        items.push(("rocksdb", cap_need(config, "maxopenfiles", config.max_open_files as u64)));
    }
    items.push(("addnode", fixed(node::net::manager::MAX_ADDNODE_CONNECTIONS as u64)));
    // Core: `std::max(num_user_p2p_bind, size_t(1))`, counted whether or
    // not the node listens.
    items.push(("p2p listeners", fixed((config.binds.len() + config.whitebind.len()).max(1) as u64)));
    if config.listenonion {
        items.push(("tor control", fixed(1)));
    }
    if config.nap {
        items.push(("nap pulls", fixed(node::nap::pull::MAX_PULL_CONNECTIONS as u64)));
    }
    // One survey connection at a time, outside the peer budget. The crawl
    // supersedes it: with `-crawl` the survey opens none.
    if config.peersurvey && !config.crawl {
        items.push(("survey connection", fixed(1)));
    }
    // The crawl's sessions are fitted into what is left once
    // `-maxconnections` is met, as a cap left at its default is, whether or
    // not the operator set them: the node's peers outrank its crawler. With
    // no floor, a limit too tight for any session leaves the crawl none.
    if config.crawl {
        items.push(("crawl", crawl_need("crawlconcurrency", config.crawlconcurrency)));
        items.push(("crawl tor", crawl_need("crawltorconcurrency", config.crawltorconcurrency)));
    }
    let rpc_listeners = config.rpcbind.len()
        + usize::from(config.rpc_tls_bind.is_some())
        + config.rpc_readonly_bind.len()
        + usize::from(config.rpc_readonly_tls_bind.is_some());
    items.push((
        "rpc",
        fixed(rpc_listeners as u64 * (1 + node::rpc::server::RPC_MAX_CONNECTIONS as u64)),
    ));
    if config.esplora {
        items.push(("esplora listeners", fixed(1 + u64::from(config.esplora_tls_bind.is_some()))));
        if config.esplora_max_sockets == 0 {
            // Without a socket cap, requests in flight (`esploramaxconns`)
            // and open SSE streams (`esplorasseconns`, its own semaphore)
            // both hold sockets.
            items.push(("esplora requests", cap_need(config, "esploramaxconns", cap(config.esplora_max_conns))));
            items.push(("esplora sse", cap_need(config, "esplorasseconns", cap(config.esplora_sse_max_conns))));
        } else {
            items.push(("esplora sockets", cap_need(config, "esploramaxsockets", cap(config.esplora_max_sockets))));
        }
    }
    if config.electrum {
        items.push(("electrum listeners", fixed(1 + u64::from(config.electrum_tls_bind.is_some()))));
        items.push(("electrum", cap_need(config, "electrummaxconns", cap(config.electrum_max_conns).max(1))));
    }
    if config.stratum {
        let listeners = 1
            + u64::from(config.stratum_tls_bind.is_some())
            + u64::from(config.stratum_v2_bind.is_some());
        items.push(("stratum listeners", fixed(listeners)));
        items.push(("stratum", cap_need(config, "stratummaxconns", cap(config.stratum_max_conns).max(1))));
    }
    if config.events_grpc_bind.is_some() {
        items.push(("events grpc listener", fixed(1)));
        items.push(("events grpc", cap_need(config, "eventsgrpcmaxconns", cap(config.events_grpc_max_conns))));
    }
    if config.streamws_bind.is_some() {
        items.push(("streamws listener", fixed(1)));
        // Without a socket cap, the connection cap bounds the sockets that
        // hold a stream (idle sockets stay unbounded).
        items.push(if config.streamws_max_sockets == 0 {
            ("streamws", cap_need(config, "streamwsmaxconns", cap(config.streamws_max_conns)))
        } else {
            ("streamws", cap_need(config, "streamwsmaxsockets", cap(config.streamws_max_sockets)))
        });
    }
    if config.mcp && config.mcp_port.is_some() {
        items.push(("mcp", fixed(1 + satd_mcp::MCP_MAX_CONNECTIONS as u64)));
    }
    if config.metricsport.is_some() {
        let per = 1 + node::metrics::METRICS_HTTP_MAX_CONNECTIONS as u64;
        let tls = 1 + node::metrics::METRICS_TLS_MAX_CONNECTIONS as u64;
        items.push(("metrics", fixed(per + if config.metrics_tls_bind.is_some() { tls } else { 0 })));
    }
    let mut zmq: Vec<&str> = config.zmq_pub.iter().map(|(_, e)| e.as_str()).collect();
    zmq.extend(config.events_zmq_bind.as_deref());
    zmq.sort_unstable();
    zmq.dedup();
    if !zmq.is_empty() {
        items.push(("zmq", fixed(zmq.len() as u64)));
    }
    items
}

/// Run the node with the fitted caps: set each one that is still at its
/// default in `config`. At startup that is every one of them; on a reload
/// a cap the operator has since set keeps the new value (and is reported
/// as needing a restart), and the rest keep the startup split.
pub fn apply(config: &mut Config, fitted: &[FittedCap]) {
    for cap in fitted {
        // The crawl's limits are fitted whether or not they were set.
        match cap.option {
            "crawlconcurrency" => {
                config.crawlconcurrency = cap.fitted as usize;
                continue;
            }
            "crawltorconcurrency" => {
                config.crawltorconcurrency = cap.fitted as usize;
                continue;
            }
            _ => {}
        }
        if !config.caps_at_default.contains(&cap.option) {
            continue;
        }
        let n = cap.fitted as usize;
        match cap.option {
            "maxopenfiles" => config.max_open_files = cap.fitted as i32,
            "esploramaxsockets" => config.esplora_max_sockets = n,
            "esploramaxconns" => config.esplora_max_conns = n,
            "esplorasseconns" => config.esplora_sse_max_conns = n,
            "electrummaxconns" => config.electrum_max_conns = n,
            "stratummaxconns" => config.stratum_max_conns = n,
            "eventsgrpcmaxconns" => config.events_grpc_max_conns = n,
            "streamwsmaxsockets" => config.streamws_max_sockets = n,
            "streamwsmaxconns" => config.streamws_max_conns = n,
            other => unreachable!("fd budget names no cap {other}"),
        }
    }
}

/// Core's `RaiseFileDescriptorLimit` (`src/util/fs_helpers.cpp`): raise the
/// soft `RLIMIT_NOFILE` to `want`, never past the hard limit, and return
/// the soft limit in effect afterwards (`u64::MAX` for unlimited).
#[cfg(unix)]
// `rlim_t` is `u64` on Linux and macOS but signed on some BSDs.
#[allow(clippy::unnecessary_cast)]
pub fn raise_fd_limit(want: u64) -> u64 {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        // Core returns its request when the limit cannot be read.
        return want;
    }
    if lim.rlim_cur != libc::RLIM_INFINITY && (lim.rlim_cur as u64) < want {
        let current = lim.rlim_cur;
        let mut raised = want as libc::rlim_t;
        if lim.rlim_max != libc::RLIM_INFINITY && raised > lim.rlim_max {
            raised = lim.rlim_max;
        }
        if raised != current {
            lim.rlim_cur = raised;
            // SAFETY: as above.
            unsafe {
                libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            }
        }
    }
    if lim.rlim_cur == libc::RLIM_INFINITY { u64::MAX } else { lim.rlim_cur as u64 }
}

/// No `RLIMIT_NOFILE` to read: the limit is unknown, so nothing is
/// lowered. (Core's Windows branch returns 2048, which fits Core's ~150
/// descriptor minimum but not satd's; satd ships no non-unix build.)
#[cfg(not(unix))]
pub fn raise_fd_limit(_want: u64) -> u64 {
    u64::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shortfall_lowers_maxconnections_with_cores_warning() {
        let budget = check(1024, 900).unwrap();
        let (n, note) = budget.fit(200);
        assert_eq!(n, 124);
        assert_eq!(
            note.as_deref(),
            Some("Reducing -maxconnections from 200 to 124, because of system limitations.")
        );
    }

    #[test]
    fn room_to_spare_keeps_maxconnections() {
        let budget = check(65536, 2500).unwrap();
        assert_eq!(budget.fit(200), (200, None));
        assert_eq!(budget.fit(0), (0, None));
        assert_eq!(check(u64::MAX, 2500).unwrap().fit(2000), (2000, None));
    }

    #[test]
    fn exactly_the_minimum_leaves_no_peer() {
        let budget = check(900, 900).unwrap();
        let (n, note) = budget.fit(200);
        assert_eq!(n, 0);
        assert!(note.is_some());
    }

    #[test]
    fn below_the_minimum_refuses_with_cores_error() {
        let err = check(256, 900).unwrap_err();
        assert_eq!(err, NotEnough { available: 256, required: 900 });
        assert_eq!(err.to_string(), "Not enough file descriptors available. 256 available, 900 required.");
    }

    fn config(extra: &[&str]) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let dd = format!("--datadir={}", dir.path().display());
        let mut args = vec!["satd", "--regtest", dd.as_str()];
        args.extend_from_slice(extra);
        let cli = crate::config::parse_cli(crate::config::normalize_args(
            args.iter().map(|s| s.to_string()).collect(),
        ))
        .unwrap();
        Config::from_cli(cli).unwrap()
    }

    fn item(items: &[(&'static str, Need)], name: &str) -> Option<Need> {
        items.iter().find(|(k, _)| *k == name).map(|(_, n)| *n)
    }

    fn default_cap(option: &'static str, default: u64) -> Option<Need> {
        Some(Need::Default { option, default, floor: default.min(64) })
    }

    /// The defaults: the base, eight addnode peers, one P2P listener, two
    /// RPC loopback listeners of 1 + 100, Esplora's listener (Esplora is on
    /// by default), and two caps left at their defaults, RocksDB's 2048
    /// table files and Esplora's 1024 sockets, which need only their floor.
    #[test]
    fn default_needs() {
        let items = needs(&config(&[]));
        assert_eq!(item(&items, "base"), Some(Need::Fixed(151)));
        assert_eq!(item(&items, "rocksdb"), default_cap("maxopenfiles", 2048));
        assert_eq!(item(&items, "addnode"), Some(Need::Fixed(8)));
        assert_eq!(item(&items, "p2p listeners"), Some(Need::Fixed(1)));
        assert_eq!(item(&items, "rpc"), Some(Need::Fixed(2 * 101)));
        assert_eq!(item(&items, "esplora listeners"), Some(Need::Fixed(1)));
        assert_eq!(item(&items, "esplora sockets"), default_cap("esploramaxsockets", 1024));
        assert_eq!(required(&items), 151 + 8 + 1 + 202 + 1 + 64 + 64);
        assert_eq!(wanted(&items, 200), 151 + 8 + 1 + 202 + 1 + 2048 + 1024 + 200);
    }

    /// A cap the operator set is fixed at its value, even when it equals
    /// the default; an uncapped one (`0`, `-1`) counts nothing.
    #[test]
    fn each_surface_counts_its_cap() {
        let items = needs(&config(&[
            "--maxopenfiles=500",
            "--esploramaxsockets=10",
            "--stratum=1",
            "--stratummaxconns=5",
            "--metricsport=19399",
            "--rpcbind=127.0.0.1",
            "--rpcallowip=127.0.0.1",
        ]));
        assert_eq!(item(&items, "rocksdb"), Some(Need::Fixed(500)));
        assert_eq!(item(&items, "esplora sockets"), Some(Need::Fixed(10)));
        assert_eq!(item(&items, "stratum listeners"), Some(Need::Fixed(1)));
        assert_eq!(item(&items, "stratum"), Some(Need::Fixed(5)));
        assert_eq!(item(&items, "metrics"), Some(Need::Fixed(1 + 64)));
        assert_eq!(item(&items, "rpc"), Some(Need::Fixed(101)));

        let items = needs(&config(&["--esploramaxsockets=1024"]));
        assert_eq!(item(&items, "esplora sockets"), Some(Need::Fixed(1024)), "set to the default value");

        let items = needs(&config(&[
            "--maxopenfiles=-1",
            "--esploramaxsockets=0",
            "--esploramaxconns=7",
            "--esplorasseconns=3",
        ]));
        assert_eq!(item(&items, "rocksdb"), None);
        assert_eq!(item(&items, "esplora requests"), Some(Need::Fixed(7)), "socket cap off: requests");
        assert_eq!(item(&items, "esplora sse"), Some(Need::Fixed(3)), "and SSE streams");

        let items = needs(&config(&["--esploramaxsockets=0"]));
        assert_eq!(item(&items, "esplora requests"), default_cap("esploramaxconns", 256));
        assert_eq!(item(&items, "esplora sse"), default_cap("esplorasseconns", 256));

        let items = needs(&config(&["--esploramaxsockets=0", "--esploramaxconns=0", "--esplorasseconns=0"]));
        assert_eq!(item(&items, "esplora requests"), Some(Need::Fixed(0)), "both caps off: nothing to budget");

        let items = needs(&config(&["--esplora=0"]));
        assert_eq!(item(&items, "esplora listeners"), None);
    }

    /// A default config under the common shell limit of 1,024: the hard
    /// minimum (491) fits, `-maxconnections` keeps its 200, and the 333
    /// descriptors left go to RocksDB's table files and Esplora's sockets
    /// in proportion to their headroom above the floor (1984 : 960).
    #[test]
    fn default_caps_shrink_to_fit_a_1024_limit() {
        let items = needs(&config(&[]));
        let plan = plan(&items, 200, 1024).expect("a default node starts under 1,024");
        assert_eq!(plan.max_connections, 200);
        assert_eq!(plan.max_connections_note, None);
        assert_eq!(
            plan.fitted,
            vec![
                FittedCap { option: "maxopenfiles", default: 2048, fitted: 64 + 224 },
                FittedCap { option: "esploramaxsockets", default: 1024, fitted: 64 + 108 },
            ]
        );
        assert!(plan.budget.required + 200 <= 1024);
        assert_eq!(plan.budget, FdBudget { available: 1024, required: 491 + 224 + 108 });
        assert_eq!(
            plan.fitted[1].note(),
            "Reducing -esploramaxsockets from 1024 to 172, because of system limitations."
        );

        let mut cfg = config(&[]);
        apply(&mut cfg, &plan.fitted);
        assert_eq!((cfg.max_open_files, cfg.esplora_max_sockets), (288, 172));
    }

    /// The order is Core's: `-maxconnections` is fitted before the default
    /// caps grow past their floors, and with room for everything nothing is
    /// lowered.
    #[test]
    fn maxconnections_is_fitted_before_the_default_caps() {
        let items = needs(&config(&[]));
        let plan = plan(&items, 200, 600).unwrap();
        assert_eq!(plan.max_connections, 109, "600 - 491");
        assert!(plan.max_connections_note.is_some());
        assert_eq!(plan.fitted.iter().map(|c| c.fitted).collect::<Vec<_>>(), vec![64, 64]);

        let plan = plan_for(&items, 200, 65_536);
        assert_eq!(plan.max_connections, 200);
        assert!(plan.fitted.is_empty());
        assert_eq!(plan.budget.required, 151 + 8 + 1 + 202 + 1 + 2048 + 1024);
    }

    fn plan_for(items: &[(&'static str, Need)], maxconnections: usize, available: u64) -> Plan {
        plan(items, maxconnections, available).unwrap()
    }

    /// A cap the operator set stays in the hard minimum: an oversized one
    /// still refuses, where the same value left as a default could not
    /// arise.
    #[test]
    fn an_explicit_cap_stays_in_the_hard_minimum() {
        let items = needs(&config(&["--esploramaxsockets=5000"]));
        assert_eq!(
            plan(&items, 200, 1024).unwrap_err(),
            NotEnough { available: 1024, required: 151 + 8 + 1 + 202 + 1 + 64 + 5000 }
        );
    }

    /// A reload re-parses the file: caps still at their defaults get the
    /// startup split back, so restart-only diffs see no change and the
    /// peer room stays what it was; a cap the operator has since set keeps
    /// its new value.
    #[test]
    fn a_reload_keeps_the_startup_split() {
        let mut running = config(&[]);
        let plan = plan(&needs(&running), 200, 1024).unwrap();
        apply(&mut running, &plan.fitted);

        let mut reloaded = config(&[]);
        apply(&mut reloaded, &plan.fitted);
        assert_eq!(
            (reloaded.max_open_files, reloaded.esplora_max_sockets),
            (running.max_open_files, running.esplora_max_sockets)
        );
        assert_eq!(plan.budget.fit(200), (200, None));
        assert_eq!(plan.budget.fit(400).0, 201, "a raised maxconnections gets only the peer room");

        let mut set = config(&["--esploramaxsockets=100"]);
        apply(&mut set, &plan.fitted);
        assert_eq!((set.max_open_files, set.esplora_max_sockets), (288, 100));
    }
    /// `-crawl` adds its sessions as soft needs, fitted after
    /// `-maxconnections`: a limit too tight for them lowers the crawl's
    /// concurrency with a line in the log, never `-maxconnections`, even
    /// when the operator set the concurrency. The survey's connection is
    /// not counted, as the crawl supersedes it.
    #[test]
    fn the_crawl_is_fitted_after_maxconnections() {
        let items = needs(&config(&["--crawl=1", "--crawlconcurrency=200", "--peersurvey=1"]));
        assert_eq!(item(&items, "crawl"), Some(Need::Default { option: "crawlconcurrency", default: 200, floor: 0 }));
        assert_eq!(item(&items, "crawl tor"), Some(Need::Default { option: "crawltorconcurrency", default: 8, floor: 0 }));
        assert_eq!(item(&items, "survey connection"), None);
        let base = required(&needs(&config(&[])));
        assert_eq!(required(&items), base, "nothing of the crawl's is in the hard minimum");

        // Room for 200 peers and the minimum, and little else.
        let available = base + 200 + 20;
        let plan = plan_for(&items, 200, available);
        assert_eq!(plan.max_connections, 200);
        assert!(plan.max_connections_note.is_none());
        let crawl = plan.fitted.iter().find(|c| c.option == "crawlconcurrency").expect("lowered");
        assert!(crawl.fitted < 200);
        assert_eq!(crawl.note(), format!("Reducing -crawlconcurrency from 200 to {}, because of system limitations.", crawl.fitted));
        let mut running = config(&["--crawl=1", "--crawlconcurrency=200"]);
        apply(&mut running, &plan.fitted);
        assert_eq!(running.crawlconcurrency, crawl.fitted as usize, "applied though set by hand");

        // With room for everything the crawl keeps its limits.
        let plan = plan_for(&items, 200, 65_536);
        assert!(plan.fitted.iter().all(|c| !c.option.starts_with("crawl")));
        assert_eq!(wanted(&items, 200), wanted(&needs(&config(&[])), 200) + 208);
    }
}
