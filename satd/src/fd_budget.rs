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
//!          + per RPC listener (plain, TLS,
//!            read-only, read-only TLS):  1 + RPC_MAX_CONNECTIONS (100)
//!          + Esplora:   listeners + esploramaxsockets (esploramaxconns if 0)
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
//! (`maxopenfiles=-1`, an Esplora or streamws socket cap and connection cap
//! both `0`) has no number to budget and counts nothing; neither do ZMQ subscribers or an
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

/// A connection cap as the surface applies it: clamped to
/// [`node::http_serve::CAP_CEILING`], `0` read as `0` (no cap, nothing to
/// budget) unless the surface takes `0` as `1`.
fn cap(n: usize) -> u64 {
    node::http_serve::clamp_cap(n) as u64
}

/// A surface with a socket cap and a connection cap taken inside its
/// handlers: the socket cap, or, when that is off, the connection cap,
/// which bounds the sockets that hold a request or a stream (idle sockets
/// stay unbounded).
fn socket_cap(sockets: usize, conns: usize) -> u64 {
    if sockets == 0 { cap(conns) } else { cap(sockets) }
}

/// satd's needs apart from the automatic peers, itemized. See the module
/// docs for the formula.
pub fn needs(config: &Config) -> Vec<(&'static str, u64)> {
    let mut items: Vec<(&'static str, u64)> = vec![("base", MIN_SATD_FDS)];
    if config.max_open_files > 0 {
        items.push(("rocksdb", config.max_open_files as u64));
    }
    items.push(("addnode", node::net::manager::MAX_ADDNODE_CONNECTIONS as u64));
    // Core: `std::max(num_user_p2p_bind, size_t(1))`, counted whether or
    // not the node listens.
    items.push(("p2p listeners", (config.binds.len() + config.whitebind.len()).max(1) as u64));
    if config.listenonion {
        items.push(("tor control", 1));
    }
    if config.nap {
        items.push(("nap pulls", node::nap::pull::MAX_PULL_CONNECTIONS as u64));
    }
    let rpc_listeners = config.rpcbind.len()
        + usize::from(config.rpc_tls_bind.is_some())
        + config.rpc_readonly_bind.len()
        + usize::from(config.rpc_readonly_tls_bind.is_some());
    items.push((
        "rpc",
        rpc_listeners as u64 * (1 + node::rpc::server::RPC_MAX_CONNECTIONS as u64),
    ));
    if config.esplora {
        let listeners = 1 + u64::from(config.esplora_tls_bind.is_some());
        items.push(("esplora", listeners + socket_cap(config.esplora_max_sockets, config.esplora_max_conns)));
    }
    if config.electrum {
        let listeners = 1 + u64::from(config.electrum_tls_bind.is_some());
        items.push(("electrum", listeners + cap(config.electrum_max_conns).max(1)));
    }
    if config.stratum {
        let listeners = 1
            + u64::from(config.stratum_tls_bind.is_some())
            + u64::from(config.stratum_v2_bind.is_some());
        items.push(("stratum", listeners + cap(config.stratum_max_conns).max(1)));
    }
    if config.events_grpc_bind.is_some() {
        items.push(("events grpc", 1 + cap(config.events_grpc_max_conns)));
    }
    if config.streamws_bind.is_some() {
        items.push(("streamws", 1 + socket_cap(config.streamws_max_sockets, config.streamws_max_conns)));
    }
    if config.mcp && config.mcp_port.is_some() {
        items.push(("mcp", 1 + satd_mcp::MCP_MAX_CONNECTIONS as u64));
    }
    if config.metricsport.is_some() {
        let per = 1 + node::metrics::METRICS_HTTP_MAX_CONNECTIONS as u64;
        let tls = 1 + node::metrics::METRICS_TLS_MAX_CONNECTIONS as u64;
        items.push(("metrics", per + if config.metrics_tls_bind.is_some() { tls } else { 0 }));
    }
    let mut zmq: Vec<&str> = config.zmq_pub.iter().map(|(_, e)| e.as_str()).collect();
    zmq.extend(config.events_zmq_bind.as_deref());
    zmq.sort_unstable();
    zmq.dedup();
    if !zmq.is_empty() {
        items.push(("zmq", zmq.len() as u64));
    }
    items
}

/// The sum of [`needs`].
pub fn required(items: &[(&'static str, u64)]) -> u64 {
    items.iter().fold(0u64, |acc, (_, n)| acc.saturating_add(*n))
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

    fn item(items: &[(&'static str, u64)], name: &str) -> Option<u64> {
        items.iter().find(|(k, _)| *k == name).map(|(_, n)| *n)
    }

    /// The defaults: the base, RocksDB's 2048 table files, eight addnode
    /// peers, one P2P listener, two RPC loopback listeners of 1 + 100, and
    /// Esplora (on by default) with its 1024-socket cap.
    #[test]
    fn default_needs() {
        let items = needs(&config(&[]));
        assert_eq!(item(&items, "base"), Some(151));
        assert_eq!(item(&items, "rocksdb"), Some(2048));
        assert_eq!(item(&items, "addnode"), Some(8));
        assert_eq!(item(&items, "p2p listeners"), Some(1));
        assert_eq!(item(&items, "rpc"), Some(2 * 101));
        assert_eq!(item(&items, "esplora"), Some(1 + 1024));
        assert_eq!(required(&items), 151 + 2048 + 8 + 1 + 202 + 1025);
    }

    /// Every enabled surface counts its listeners and its client cap; an
    /// uncapped one (`0`, `-1`) counts no clients.
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
        assert_eq!(item(&items, "rocksdb"), Some(500));
        assert_eq!(item(&items, "esplora"), Some(1 + 10));
        assert_eq!(item(&items, "stratum"), Some(1 + 5));
        assert_eq!(item(&items, "metrics"), Some(1 + 64));
        assert_eq!(item(&items, "rpc"), Some(101));

        let items = needs(&config(&["--maxopenfiles=-1", "--esploramaxsockets=0", "--esploramaxconns=7"]));
        assert_eq!(item(&items, "rocksdb"), None);
        assert_eq!(item(&items, "esplora"), Some(1 + 7), "socket cap off: the connection cap");

        let items = needs(&config(&["--esploramaxsockets=0", "--esploramaxconns=0"]));
        assert_eq!(item(&items, "esplora"), Some(1), "both caps off: nothing to budget");

        let items = needs(&config(&["--esplora=0"]));
        assert_eq!(item(&items, "esplora"), None);
    }
}
