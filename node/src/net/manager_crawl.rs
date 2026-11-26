//! The crawl's connections (`-crawl`): its loop, the scheduler's ticks, the
//! seeding rounds, and the session each connection runs. The frontier is
//! [`crate::net::crawlbook`], the limits and their scheduler
//! [`crate::net::crawl`].
//!
//! # Isolation
//!
//! A crawl session is a [`ConnType::Crawl`] connection the crawl opens and
//! runs itself: it never enters the node's peer table, so it takes no slot
//! of any connection budget or grant, is never in `getpeerinfo`,
//! `getconnectioncount`, `getpeerbehavior`, eviction or the behaviour
//! flags, and no block, transaction or address is ever relayed over it.
//! The crawl reads the address book to seed itself and never writes it:
//! no `Good`, no attempt, no new entry, no service update. What it learns
//! stays in its own book: it is not relayed, not served on `getaddr`, and
//! not given to the node's dialer, the alt-slots or the extra-network peer.
//!
//! A session's `version` declares a crawler (protocol 70016, services 0,
//! relay off, our real tip, a fresh random nonce, the dummy `addr_from`,
//! `/satd:<version>(crawler)/`), then `wtxidrelay`, `sendaddrv2` and
//! `verack`, and nothing else unsolicited. It answers `ping`, gives a
//! `getaddr` nothing, and ignores everything else it does not need. A
//! discovery session then sends one `getaddr` and, under `-crawlprobes`,
//! the four vetted probes in a random order (checked against Core v32.1 in
//! `satd/tests/core_crawl_session.rs`); a liveness session sends nothing
//! more. A session ends with our FIN and a short wait for the peer's, so
//! unread bytes do not turn the close into a reset.
//!
//! # Verdicts
//!
//! A session whose peer closes the connection during the passive wait,
//! before its handshake transcript settles, is closed early
//! ([`Verdict::ClosedEarly`](crate::net::survey::Verdict::ClosedEarly)): the
//! node is reached (it sent its `version` and `verack`) and its observation
//! keeps what the `version` said, but it has no fingerprint. A Core node
//! with full inbound slots evicts the youngest connection of its largest
//! network group, which a crawl session seconds old often is. One that
//! claims Core and sends nothing but `version` and `verack` through the
//! whole wait, the connection open, is fake ([`survey::is_fake_core`]).
//! Neither changes the reachability, transport or timers a session that
//! ended records.
//!
//! A closed-early session never replaces a settled observation: the entry
//! keeps its fingerprint. An address with no settled observation is dialled
//! again on a schedule ([`survey::ClosedEarlyRetry`]: 15 min, 30 min, 1 h,
//! 2 h, then every 4 h, each spread at random, at most ten times): its next
//! session (a liveness session, or a discovery once one is due) comes
//! forward, under the same limits and dial rules as every session.
//!
//! # Transport
//!
//! BIP 324 first only to a node known to advertise `NODE_P2P_V2`, as Core
//! dials its own outbound peers: the services of the node's own last
//! `version` once a handshake has completed, before that the services its
//! address was last advertised with
//! ([`CrawlEntry::dials_v2_first`](crate::net::crawlbook::CrawlEntry::dials_v2_first)).
//! A seed (`-crawlseed`, a fixed seed, a DNS seed) carries no services, so
//! it is dialled over v1 until a handshake or an answer naming it says
//! otherwise. Any other target is dialled over v1 with no v2 bytes sent:
//! some v1-only implementations close on them, and one bans the dialler's
//! address. A node that speaks v2 without advertising it is therefore
//! counted v1 (`v1_v2_untried`), not v1-only.
//!
//! A v2 attempt that fails as a v1-only node fails it (it closes the
//! connection, or never answers, with nothing received) is redialled over
//! v1, as Core does (`V2Transport::ShouldReconnectV1`); one that received
//! bytes and failed is not. A v1 recheck dials v1 alone. The node's
//! `-v2transport` and `-v2only` do not apply: the crawl measures both
//! transports.
//!
//! # Networks
//!
//! The crawl dials what the node's dialer may (`-onlynet`, `-proxy`,
//! `-onion`), narrowed by `-crawlnet`, and never clearnet through the
//! proxy: that would put crawl volume on Tor exit operators. A Tor-only
//! node therefore crawls onions alone. Each onion dial gets SOCKS
//! credentials of its own, whatever `-proxyrandomize` says, so no crawl
//! circuit is shared with another or with the node's peers. Direct dials
//! leave from `-crawlbind` when it names an address of the family.
//!
//! `-crawlproxy` names a SOCKS5 proxy that is not a Tor exit (an SSH
//! dynamic forward to another host, say): every IPv4 and IPv6 crawl dial
//! then goes through it, so the crawl's source address is the proxy
//! host's. It decides how clearnet is dialled, never whether: `-onlynet`
//! and `-crawlnet` still narrow, and clearnet is crawled under `-proxy`
//! too. Onion dials keep `-onion`/`-proxy`, and the node's own connections
//! never use it. `-crawlbind` does not apply to a proxied dial, and its
//! `version` names the dummy address as the receiver, as an onion dial's
//! does. There is no fallback: a dial the proxy fails
//! ([`proxy::Socks5Failure::Proxy`]: unreachable, a failed greeting, a
//! CONNECT it cannot serve) is never made direct and never held against
//! the target. The session ends with nothing recorded
//! ([`CrawlBook::release`]), the address stays due, proxied dials pause
//! for [`PROXY_PAUSE`], and `getcrawlinfo` counts the failure; the log
//! says once when the proxy fails and once when it answers again. A
//! failure the proxy reports for the target (a SOCKS5 reply 0x01 to 0x06,
//! or no reply in time) is the target's, as a failed direct dial is, with
//! one backstop: [`PROXY_SILENT_STREAK`] dials in a row with no answer from
//! any target (no success, no refusal) put the proxy down too, and while
//! it is down such a dial is the proxy's. A success or a refusal (0x02,
//! 0x05) ends the outage.
//!
//! # Failure
//!
//! A panic in a crawl task stops the crawl, with an error in the log; the
//! node keeps running.

use super::survey_conn::{Next, listen_passive, next_message, send_probes};
use super::*;
use crate::net::behavior::PeerBehavior;
use crate::net::crawl::{self, CrawlConfig, Scheduler};
use crate::net::crawlbook::{
    Attempt, BookParams, CrawlAddr, CrawlBook, GetaddrResult, Network, Observation, SessionKind,
    SessionResult, UnknownShape,
};
use crate::net::crawlreport;
use crate::net::crawlsnapshot::{self, SnapshotStore};
use crate::net::fingerprint::{AddrKind, CrawlFeatures};
use crate::net::survey::{self, ProbeContext, ProbeResults, Verdict};
use crate::net::v2transport::V2Greeting;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use rand::seq::SliceRandom as _;

/// The crawl while it runs.
pub(super) struct CrawlRun {
    pub(super) config: CrawlConfig,
    /// The user agent every session states.
    user_agent: String,
    pub(super) book: parking_lot::Mutex<CrawlBook>,
    pub(super) scheduler: parking_lot::Mutex<Scheduler>,
    /// The scheduler's clock starts here.
    epoch: Instant,
    /// The nonces of crawl `version`s whose handshake is under way: an
    /// inbound peer that sends one back is the crawl itself.
    nonces: parking_lot::Mutex<HashSet<u64>>,
    /// The crawl's traffic, apart from the node's (`getnettotals`).
    totals: Arc<NetTotals>,
    /// Past the IBD hold: sessions may start.
    pub(super) started: AtomicBool,
    /// Stopped after a panic in one of its tasks.
    pub(super) stopped: AtomicBool,
    /// Sessions that ended, reached or not, this run.
    pub(super) reached: AtomicU64,
    pub(super) unreached: AtomicU64,
    /// Dials `-crawlproxy` failed this run (the proxy's failures, not the
    /// targets').
    pub(super) proxy_failures: AtomicU64,
    /// `-crawlproxy` failed its last dial: the log has said so, and says
    /// so again only after the proxy answers once more.
    pub(super) proxy_down: AtomicBool,
    /// No proxied dial starts before this, on the crawl's clock
    /// ([`CrawlRun::now_ms`]): set by a proxy failure.
    pub(super) proxy_paused_until_ms: AtomicU64,
    /// Proxied dials in a row whose target gave no answer
    /// ([`PROXY_SILENT_STREAK`]).
    pub(super) proxy_silent_streak: std::sync::atomic::AtomicU32,
    /// The aggregate the metrics and the status page read, and when it was
    /// taken: they are polled often, and a walk of a full book is not free.
    pub(super) aggregate: parking_lot::Mutex<Option<(Instant, crawlreport::Aggregate)>>,
    /// The hourly snapshots; `None` without a data directory.
    snapshots: Option<parking_lot::Mutex<SnapshotStore>>,
    /// Every target dialled, in order: for tests.
    #[cfg(test)]
    pub(super) dialled: parking_lot::Mutex<Vec<PeerAddr>>,
    /// The probes every discovery session sends, in place of all of them
    /// in a random order: for tests.
    #[cfg(test)]
    pub(super) forced_probes: parking_lot::Mutex<Option<Vec<survey::Probe>>>,
    /// Take the node as out of initial block download: for tests, whose
    /// chain is at genesis.
    #[cfg(test)]
    pub(super) out_of_ibd: AtomicBool,
    /// Panic in the next session: for tests.
    #[cfg(test)]
    pub(super) panic_in_session: AtomicBool,
}

impl CrawlRun {
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Whether a proxied dial may start now: `-crawlproxy` has not failed
    /// within [`PROXY_PAUSE`].
    fn proxy_ready(&self) -> bool {
        self.now_ms() >= self.proxy_paused_until_ms.load(Ordering::Relaxed)
    }

    /// `-crawlproxy` failed a dial: count it, pause proxied dials, and
    /// warn if it answered the dial before.
    fn proxy_failed(&self, error: &str) {
        self.proxy_failures.fetch_add(1, Ordering::Relaxed);
        self.proxy_paused_until_ms.store(
            self.now_ms() + PROXY_PAUSE.as_millis() as u64,
            Ordering::Relaxed,
        );
        if !self.proxy_down.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "The crawl proxy (-crawlproxy) failed: clearnet crawl dials wait for it, none is made direct ({error})"
            );
        }
    }

    /// A proxied dial got no answer from its target (reply 0x01, 0x03,
    /// 0x04, 0x06, no reply, or a close instead of one). Whether it is
    /// taken as the proxy's failure: while the proxy is down, or when it
    /// makes [`PROXY_SILENT_STREAK`] such dials in a row with no success
    /// and no refusal, which puts the proxy down.
    fn proxy_silent(&self, error: &str) -> bool {
        if self.proxy_down.load(Ordering::Relaxed) {
            self.proxy_failed(error);
            return true;
        }
        let streak = self.proxy_silent_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak < PROXY_SILENT_STREAK {
            return false;
        }
        self.proxy_silent_streak.store(0, Ordering::Relaxed);
        self.proxy_failed(&format!(
            "{PROXY_SILENT_STREAK} dials in a row without an answer from any target; the last: {error}"
        ));
        true
    }

    /// `-crawlproxy` connected a dial or relayed a target's refusal: the
    /// proxy is up and reaches the network.
    fn proxy_answered(&self) {
        self.proxy_silent_streak.store(0, Ordering::Relaxed);
        if self.proxy_down.swap(false, Ordering::Relaxed) {
            tracing::info!("The crawl proxy (-crawlproxy) answers again: clearnet crawl dials resume");
        }
    }
}

/// How long proxied dials wait after `-crawlproxy` fails one, so a proxy
/// that is down is tried every few seconds, not at the crawl's rate.
pub(super) const PROXY_PAUSE: Duration = Duration::from_secs(5);

/// Proxied dials in a row that got no answer from their target (reply
/// 0x01, 0x03, 0x04 or 0x06, no reply, a close instead of one), with no
/// success and no refusal between them, after which the proxy is taken as
/// down: a SOCKS server that greets but whose own uplink is down answers
/// every CONNECT that way, and charging each to its target would decay the
/// clearnet book while `proxy.failures` stays 0.
///
/// Why 200: on a working uplink a crawl dial reaches a handshake a few per
/// cent of the time, and a large share of the rest are refusals (a closed
/// port answers with a reset, which a SOCKS server reports as 0x05), each
/// of which breaks the streak. Even counting successes alone at 3 %, 200
/// silent dials in a row happen with probability 0.97^200, about 0.2 %, per
/// window; with refusals as well it is vanishingly small. The bound it
/// leaves: at most `PROXY_SILENT_STREAK - 1` silent failures of an outage
/// begun this way are recorded against their targets before it is seen.
/// The estimate of the failure mix is a reasoned one, not one measured on
/// a crawl.
pub(super) const PROXY_SILENT_STREAK: u32 = 200;

/// How long the metrics and the status page reuse an aggregate before they
/// take a new one.
pub(super) const AGGREGATE_MAX_AGE: Duration = Duration::from_secs(10);

/// How long `getcrawlinfo` reuses one. The aggregate walks the whole book
/// under its lock, which the sessions need too; `getcrawlinfo` is a read
/// call, so a client polling it in a loop must not keep the crawl waiting.
pub(super) const INFO_AGGREGATE_MAX_AGE: Duration = Duration::from_secs(1);

/// Why the crawl starts no session now, as `getcrawlinfo` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlHold {
    /// The node is in initial block download.
    InitialBlockDownload,
    /// `-connect`: the node makes no automatic connection.
    Connect,
    /// Networking is off (`setnetworkactive false`, `-networkactive=0`).
    NetworkInactive,
}

impl CrawlHold {
    pub fn name(self) -> &'static str {
        match self {
            CrawlHold::InitialBlockDownload => "initial_block_download",
            CrawlHold::Connect => "connect",
            CrawlHold::NetworkInactive => "network_inactive",
        }
    }
}

/// What the metrics and the status page read: counts only, no address.
#[derive(Debug, Clone, Default)]
pub struct CrawlMetrics {
    /// Sessions may start now: not held and not stopped.
    pub running: bool,
    /// Stopped after a panic in a crawl task.
    pub stopped: bool,
    pub aggregate: crawlreport::Aggregate,
    /// Sessions that ended this run: a handshake completed, or not.
    pub reached: u64,
    pub unreached: u64,
    /// Sessions open: clearnet, then Tor.
    pub in_flight: (usize, usize),
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Removes a session's nonce once its handshake is over, however it ends.
struct NonceGuard<'a>(&'a parking_lot::Mutex<HashSet<u64>>, u64);

impl Drop for NonceGuard<'_> {
    fn drop(&mut self) {
        self.0.lock().remove(&self.1);
    }
}

/// Why a crawl dial failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DialFailure {
    /// The target's: nothing reached it, as a direct dial that fails.
    Target(String),
    /// `-crawlproxy`'s: nothing is known of the target.
    Proxy(String),
}

/// How one transport attempt went.
enum Opened {
    /// The dial itself failed: nothing reached.
    NoDial,
    /// The dial failed at `-crawlproxy`: nothing is known of the target.
    ProxyFailed,
    /// The v2 key exchange failed with nothing received, as against a
    /// v1-only node.
    V1Only,
    /// It failed some other way.
    Failed,
    /// Open, with what the peer sent inside BIP 324 before its first
    /// message when `v2`.
    Open(Box<Connection>, Option<V2Greeting>),
}

/// What the handshake showed.
struct Handshaken {
    version: VersionMessage,
    behavior: PeerBehavior,
    wtxid_relay: bool,
    /// From our `version` to the peer's `verack`.
    rtt_ms: u32,
    our_height: u32,
    /// The peer's `version` timestamp less our clock, when it came.
    clock_offset_secs: i64,
}

/// A session's result, and the `getaddr` answer when one came.
pub(super) struct SessionOutput {
    pub(super) result: SessionResult,
    pub(super) answer: Option<Vec<AddrV2Message>>,
    /// A dial failed at `-crawlproxy`: the session is not the target's
    /// and records nothing.
    pub(super) proxy_failed: bool,
}

/// A `getaddr` answer: its entries, the message it came in, and its delay
/// in milliseconds.
type GetaddrAnswer = (Vec<AddrV2Message>, AddrKind, u32);

/// The next message on a connection still in its handshake, by `deadline`.
async fn recv_by(
    conn: &mut Connection,
    deadline: tokio::time::Instant,
) -> Result<NetworkMessage, String> {
    match tokio::time::timeout_at(deadline, conn.recv()).await {
        Ok(Ok(m)) => Ok(m),
        Ok(Err(e)) => Err(format!("recv: {e}")),
        Err(_) => Err("handshake timeout".into()),
    }
}

/// A legacy `addr` entry as BIP 155 has it; `None` for one that names no
/// IP address.
fn addr_entry_v2(time: u32, addr: &bitcoin::p2p::Address) -> Option<AddrV2Message> {
    let sa = addr.socket_addr().ok()?;
    let addr_v2 = match sa.ip().to_canonical() {
        IpAddr::V4(v4) => AddrV2::Ipv4(v4),
        IpAddr::V6(v6) => AddrV2::Ipv6(v6),
    };
    Some(AddrV2Message {
        time,
        services: addr.services,
        addr: addr_v2,
        port: sa.port(),
    })
}

impl PeerManager {
    /// Turn the crawl on: read the book from `config.path`. Call once, at
    /// startup, before [`Self::spawn_crawl`]. A book that does not read is
    /// set aside with a warning and the crawl starts empty. Refuses a
    /// `-crawluacomment` that cannot go in a user agent.
    pub fn enable_crawl(&self, config: CrawlConfig) -> Result<(), String> {
        let user_agent = crawl::user_agent(config.ua_comment.as_deref())?;
        let now = crate::time::now_secs();
        let params = BookParams {
            liveness_secs: config.liveness_secs,
            max_age_secs: config.max_age_secs,
            ..BookParams::for_network(self.chain_state.network)
        };
        let magic = self.chain_state.p2p_magic().to_bytes();
        let book = match &config.path {
            Some(path) => match CrawlBook::load(path, magic, now, params) {
                Ok(book) => {
                    tracing::info!(entries = book.len(), "Loaded the crawl book");
                    if book.dropped_old_observations() > 0 {
                        tracing::info!(
                            dropped = book.dropped_old_observations(),
                            "The crawl book is in an older format (version 2 or 3); its entries are kept and their last observations dropped, each to be observed again at its next session"
                        );
                    }
                    book
                }
                Err(e) => {
                    let aside = path.with_extension(format!("dat.bad-{now}"));
                    let _ = std::fs::rename(path, &aside);
                    tracing::warn!(
                        file = %path.display(),
                        moved_to = %aside.display(),
                        "Could not read the crawl book, starting empty: {e}"
                    );
                    CrawlBook::new(params)
                }
            },
            None => CrawlBook::new(params),
        };
        let epoch = Instant::now();
        let snapshots = config
            .snapshot_dir
            .clone()
            .map(|dir| parking_lot::Mutex::new(SnapshotStore::open(dir)));
        let run = CrawlRun {
            scheduler: parking_lot::Mutex::new(Scheduler::new(config.limits, 0)),
            config,
            user_agent,
            book: parking_lot::Mutex::new(book),
            epoch,
            nonces: Default::default(),
            totals: NetTotals::new(),
            started: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            reached: AtomicU64::new(0),
            unreached: AtomicU64::new(0),
            proxy_failures: AtomicU64::new(0),
            proxy_down: AtomicBool::new(false),
            proxy_paused_until_ms: AtomicU64::new(0),
            proxy_silent_streak: std::sync::atomic::AtomicU32::new(0),
            aggregate: parking_lot::Mutex::new(None),
            snapshots,
            #[cfg(test)]
            dialled: Default::default(),
            #[cfg(test)]
            forced_probes: Default::default(),
            #[cfg(test)]
            out_of_ibd: AtomicBool::new(false),
            #[cfg(test)]
            panic_in_session: AtomicBool::new(false),
        };
        if self.crawl.set(run).is_err() {
            tracing::warn!("the crawl was enabled twice; the second call is ignored");
        }
        Ok(())
    }

    /// Whether the crawl is on.
    pub fn crawl_enabled(&self) -> bool {
        self.crawl.get().is_some()
    }

    /// Whether `nonce` is a crawl session's, still in its handshake.
    pub(super) fn is_crawl_nonce(&self, nonce: u64) -> bool {
        self.crawl
            .get()
            .is_some_and(|run| run.nonces.lock().contains(&nonce))
    }

    /// Write the crawl's book to its file. A no-op with the crawl off.
    pub fn dump_crawl(&self) {
        let Some(run) = self.crawl.get() else {
            return;
        };
        let Some(path) = &run.config.path else {
            return;
        };
        let magic = self.chain_state.p2p_magic().to_bytes();
        // Copied under the lock, encoded and written outside it.
        let book = run.book.lock().clone();
        if let Err(e) = book.save(path, magic) {
            tracing::warn!(file = %path.display(), "Could not write the crawl book: {e}");
        }
    }

    /// Start the crawl: its loop, and a watch on it that logs and stops the
    /// crawl if a crawl task panics. Nothing without [`Self::enable_crawl`].
    pub fn spawn_crawl(self: &Arc<Self>) {
        if self.crawl.get().is_none() {
            return;
        }
        let pm = Arc::clone(self);
        let main = tokio::spawn(async move { pm.crawl_loop().await });
        let pm = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = main.await
                && e.is_panic()
            {
                pm.stop_crawl_after_panic();
            }
        });
    }

    fn stop_crawl_after_panic(&self) {
        tracing::error!("A crawl task panicked: the crawl has stopped, and the node keeps running");
        if let Some(run) = self.crawl.get() {
            run.stopped.store(true, Ordering::Relaxed);
        }
    }

    /// Whether sessions may start: the node is out of initial block
    /// download (the crawl states a real tip, and IBD needs the
    /// bandwidth), networking is on, and the node makes automatic
    /// connections (not under `-connect`).
    pub(super) fn crawl_may_run(&self) -> bool {
        let Some(run) = self.crawl.get() else {
            return false;
        };
        !run.stopped.load(Ordering::Relaxed) && self.crawl_holds().is_empty()
    }

    /// Why sessions may not start now, in the order `getcrawlinfo` lists
    /// them; empty while they may. A stopped crawl is not held: it is
    /// stopped.
    pub fn crawl_holds(&self) -> Vec<CrawlHold> {
        if self.crawl.get().is_none() {
            return Vec::new();
        }
        let ibd = self.chain_state.is_initial_block_download();
        #[cfg(test)]
        let ibd = ibd
            && !self
                .crawl
                .get()
                .is_some_and(|run| run.out_of_ibd.load(Ordering::Relaxed));
        let mut holds = Vec::new();
        if ibd {
            holds.push(CrawlHold::InitialBlockDownload);
        }
        if !self.automatic_outbound.load(Ordering::Relaxed) {
            holds.push(CrawlHold::Connect);
        }
        if !self.is_network_active() {
            holds.push(CrawlHold::NetworkInactive);
        }
        holds
    }

    /// The networks the crawl dials: those the node's dialer reaches,
    /// `-crawlnet` kept, and clearnet only when it goes through
    /// `-crawlproxy` or does not go through the proxy. As
    /// [`Self::crawl_may_dial`]: only a routable address goes through the
    /// proxy, so where the book admits local addresses (regtest) clearnet
    /// is dialled with a proxy set too.
    pub fn crawl_networks(&self) -> Vec<Network> {
        use crate::net::reachable::Network as Reach;
        let Some(run) = self.crawl.get() else {
            return Vec::new();
        };
        let direct = run.config.proxy.is_some()
            || self.proxy.is_none()
            || run.book.lock().params().allow_local;
        crawlreport::DIALLED
            .into_iter()
            .filter(|n| {
                run.config
                    .networks
                    .as_ref()
                    .is_none_or(|nets| nets.contains(n))
            })
            .filter(|n| match n {
                Network::Ipv4 => direct && self.network_reachable(Reach::Ipv4),
                Network::Ipv6 => direct && self.network_reachable(Reach::Ipv6),
                Network::Onion => self.network_reachable(Reach::Onion),
                Network::I2p | Network::Cjdns => false,
            })
            .collect()
    }

    /// The last aggregate if younger than `max_age`, else a fresh one.
    fn crawl_aggregate(&self, run: &CrawlRun, max_age: Duration) -> crawlreport::Aggregate {
        let cached = run
            .aggregate
            .lock()
            .clone()
            .filter(|(at, _)| at.elapsed() < max_age);
        match cached {
            Some((_, agg)) => agg,
            None => self.crawl_aggregate_now(run),
        }
    }

    /// A fresh aggregate of the book, kept for reuse. With `-countryfile`,
    /// its per-country totals over the reachable set, folded under
    /// `-crawlexportmink`.
    fn crawl_aggregate_now(&self, run: &CrawlRun) -> crawlreport::Aggregate {
        let now = crate::time::now_secs();
        let book = run.book.lock();
        let mut agg = crawlreport::aggregate(&book, now);
        agg.countries = self.country_map.get().map(|map| {
            crate::net::country::totals(
                book.snapshot(now).map(|(peer, _)| peer),
                map,
                run.config.export_min_k,
            )
        });
        drop(book);
        *run.aggregate.lock() = Some((Instant::now(), agg.clone()));
        agg
    }

    /// `-countryfile`'s map, for the crawl's per-country totals. Call once,
    /// at startup; a second map is ignored.
    pub fn set_country_map(&self, map: Arc<crate::net::country::CountryMap>) {
        let _ = self.country_map.set(map);
    }

    /// `getcrawlinfo`: the crawl's state, its limits, its book's size, its
    /// sessions and traffic, and the aggregate. Counts only: no address.
    /// With the crawl off, `enabled` is false and the counts are zero.
    pub fn get_crawl_info(&self) -> serde_json::Value {
        let Some(run) = self.crawl.get() else {
            let mut out = crawlreport::aggregate_json(&crawlreport::Aggregate::default(), 0);
            out["enabled"] = serde_json::json!(false);
            out["state"] = serde_json::json!("off");
            out["held_by"] = serde_json::json!([]);
            out["peersurvey_superseded"] = serde_json::json!(false);
            // The same keys as with the crawl on, every count zero.
            out["stopped_by"] = serde_json::Value::Null;
            out["started"] = serde_json::json!(false);
            out["limits"] = serde_json::json!({
                "concurrency": 0, "tor_concurrency": 0, "rate": 0, "liveness": 0, "max_age": 0,
                "probes": false, "networks": [], "bind": false,
            });
            out["proxy"] = serde_json::json!({ "set": false, "failures": 0 });
            out["sessions"] = serde_json::json!({ "reached": 0, "unreached": 0, "in_flight": { "clearnet": 0, "tor": 0 } });
            out["totals"] = serde_json::json!({ "totalbytessent": 0, "totalbytesrecv": 0 });
            return out;
        };
        let agg = self.crawl_aggregate(run, INFO_AGGREGATE_MAX_AGE);
        let max_entries = run.book.lock().params().max_entries;
        let mut out = crawlreport::aggregate_json(&agg, max_entries);
        let stopped = run.stopped.load(Ordering::Relaxed);
        let holds = self.crawl_holds();
        let state = if stopped {
            "stopped"
        } else if !holds.is_empty() {
            "held"
        } else {
            "running"
        };
        let limits = run.scheduler.lock().limits();
        let (clearnet, tor) = run.scheduler.lock().open();
        let settings = serde_json::json!({
            "enabled": true,
            "state": state,
            "held_by": holds.iter().map(|h| h.name()).collect::<Vec<_>>(),
            "stopped_by": stopped.then_some("panic"),
            "started": run.started.load(Ordering::Relaxed),
            "peersurvey_superseded": self.survey_enabled(),
            "limits": {
                "concurrency": limits.clearnet,
                "tor_concurrency": limits.tor,
                "rate": limits.rate,
                "liveness": run.config.liveness_secs,
                "max_age": run.config.max_age_secs,
                "probes": run.config.probes,
                "networks": self.crawl_networks().iter().map(|n| n.name()).collect::<Vec<_>>(),
                "bind": run.config.bind_v4.is_some() || run.config.bind_v6.is_some(),
            },
            // Whether one is set, never its address.
            "proxy": {
                "set": run.config.proxy.is_some(),
                "failures": run.proxy_failures.load(Ordering::Relaxed),
            },
            "sessions": {
                "reached": run.reached.load(Ordering::Relaxed),
                "unreached": run.unreached.load(Ordering::Relaxed),
                "in_flight": { "clearnet": clearnet, "tor": tor },
            },
            "totals": {
                "totalbytessent": run.totals.bytes_sent(),
                "totalbytesrecv": run.totals.bytes_recv(),
            },
        });
        if let (Some(o), Some(s)) = (out.as_object_mut(), settings.as_object()) {
            for (k, v) in s {
                o.insert(k.clone(), v.clone());
            }
        }
        out
    }

    /// `getcrawlnodes`: a row per address in the book, raw addresses
    /// included; with `verbose` every field. An empty list with the crawl
    /// off.
    pub fn get_crawl_nodes(&self, verbose: bool) -> serde_json::Value {
        let Some(run) = self.crawl.get() else {
            return serde_json::json!([]);
        };
        // Copied under the lock, serialized outside it.
        let book = run.book.lock().clone();
        crawlreport::nodes_json(&book, crate::time::now_secs(), verbose)
    }

    /// What an export states besides the book, as of `now`.
    fn crawl_export_context(&self, run: &CrawlRun, now: u64) -> crawlsnapshot::ExportContext<'_> {
        crawlsnapshot::ExportContext {
            now,
            latest_height: self.chain_state.tip_height(),
            default_port: crate::net::peer::default_p2p_port(self.chain_state.network),
            chain: self.chain_state.network.to_core_arg(),
            countries: self.country_map.get().map(|map| crawlsnapshot::Countries {
                map,
                min_k: run.config.export_min_k,
            }),
        }
    }

    /// Write the hourly snapshot if one is due at `now`, and prune the old
    /// ones. Whether one was written.
    pub(super) fn crawl_snapshot_tick(&self, now: u64) -> bool {
        let Some(run) = self.crawl.get() else {
            return false;
        };
        let Some(store) = &run.snapshots else {
            return false;
        };
        let mut store = store.lock();
        if !store.due(now) {
            return false;
        }
        // The reachable set's lines are built under the book's lock: a
        // copy of the whole book would cost more.
        let ctx = self.crawl_export_context(run, now);
        let lines = crawlsnapshot::snapshot_lines(&run.book.lock(), &ctx);
        match store.write(now, &lines) {
            Ok(w) => {
                tracing::debug!(file = %w.path.display(), bytes = w.bytes, pruned = w.pruned, "Wrote a crawl snapshot");
                true
            }
            Err(e) => {
                store.failed(now);
                tracing::warn!(
                    dir = %store.dir().display(),
                    "Could not write a crawl snapshot (next try in {} min): {e}",
                    crawlsnapshot::SNAPSHOT_RETRY_SECS / 60
                );
                false
            }
        }
    }

    /// `dumpcrawlsnapshot`: the reachable set now, shaped as a Bitnodes
    /// snapshot. Keyed unless `raw`; the first keyed export creates the
    /// default key file. An error with the crawl off, or when the key does
    /// not read.
    pub fn dump_crawl_snapshot(&self, raw: bool) -> Result<serde_json::Value, String> {
        let run = self.crawl.get().ok_or("The crawl is off (-crawl)")?;
        let mode = if raw {
            crawlsnapshot::Mode::Raw
        } else {
            let source = run
                .config
                .export_key
                .as_ref()
                .ok_or("No export key: the crawl keeps no files")?;
            crawlsnapshot::Mode::Keyed {
                key: crawlsnapshot::load_key(source)?,
                min_k: run.config.export_min_k,
            }
        };
        let ctx = self.crawl_export_context(run, crate::time::now_secs());
        Ok(crawlsnapshot::export_json(&run.book.lock(), &ctx, &mode))
    }

    /// The crawl's counts for the metrics and the status page; `None` with
    /// the crawl off. The aggregate is reused for up to
    /// [`AGGREGATE_MAX_AGE`].
    pub fn crawl_metrics(&self) -> Option<CrawlMetrics> {
        let run = self.crawl.get()?;
        let aggregate = self.crawl_aggregate(run, AGGREGATE_MAX_AGE);
        let stopped = run.stopped.load(Ordering::Relaxed);
        Some(CrawlMetrics {
            running: !stopped && self.crawl_holds().is_empty(),
            stopped,
            aggregate,
            reached: run.reached.load(Ordering::Relaxed),
            unreached: run.unreached.load(Ordering::Relaxed),
            in_flight: run.scheduler.lock().open(),
            bytes_sent: run.totals.bytes_sent(),
            bytes_recv: run.totals.bytes_recv(),
        })
    }

    async fn crawl_loop(self: Arc<Self>) {
        let Some(run) = self.crawl.get() else { return };
        let mut shutdown = self.shutdown.clone();
        // The IBD hold.
        let mut waited = false;
        loop {
            if *shutdown.borrow() || run.stopped.load(Ordering::Relaxed) {
                return;
            }
            if self.crawl_may_run() {
                break;
            }
            if !waited {
                tracing::info!("The crawl waits for the node to leave initial block download");
                waited = true;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                // A dropped sender is a shutdown too.
                r = shutdown.changed() => if r.is_err() {
                    return;
                },
            }
        }
        run.started.store(true, Ordering::Relaxed);
        let limits = run.scheduler.lock().limits();
        tracing::info!(
            concurrency = limits.clearnet,
            tor_concurrency = limits.tor,
            rate = limits.rate,
            "Crawl started"
        );
        self.crawl_seed_round().await;
        let mut tick = tokio::time::interval(crawl::TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut save = tokio::time::interval(crawl::SAVE_INTERVAL);
        save.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        save.tick().await;
        let mut seed = tokio::time::interval(crawl::SEED_INTERVAL);
        seed.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        seed.tick().await;
        // Its first tick is now: a snapshot is due unless one was written
        // this hour.
        let mut snapshot = tokio::time::interval(crawlsnapshot::CHECK_INTERVAL);
        snapshot.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                r = shutdown.changed() => {
                    if r.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                Some(joined) = sessions.join_next(), if !sessions.is_empty() => {
                    if let Err(e) = joined
                        && e.is_panic()
                    {
                        sessions.abort_all();
                        self.stop_crawl_after_panic();
                        return;
                    }
                }
                _ = tick.tick() => self.crawl_tick(&mut sessions),
                _ = save.tick() => {
                    let pm = Arc::clone(&self);
                    let _ = tokio::task::spawn_blocking(move || pm.dump_crawl()).await;
                }
                _ = seed.tick() => self.crawl_seed_round().await,
                _ = snapshot.tick() => {
                    let pm = Arc::clone(&self);
                    let _ = tokio::task::spawn_blocking(move || pm.crawl_snapshot_tick(crate::time::now_secs())).await;
                }
            }
        }
        sessions.abort_all();
    }

    /// Whether the crawl may dial `addr`: on a network the node's dialer
    /// reaches and `-crawlnet` keeps, not clearnet through the proxy (but
    /// through `-crawlproxy`, while it is not paused after a failure), not
    /// banned, not one of the node's own addresses, and not a bad port.
    pub(super) fn crawl_may_dial(&self, addr: &PeerAddr) -> bool {
        let Some(run) = self.crawl.get() else {
            return false;
        };
        if run
            .config
            .networks
            .as_ref()
            .is_some_and(|nets| !nets.contains(&crawl::network_of(addr)))
        {
            return false;
        }
        let reachable = match addr {
            PeerAddr::Socket(sa) => {
                crate::net::is_valid(sa.ip())
                    && self.reachable.read().contains_socket(sa)
                    && match run.config.proxy {
                        Some(_) => run.proxy_ready(),
                        None => !self.dials_through_proxy(*sa),
                    }
            }
            PeerAddr::Onion { .. } => self.network_reachable(crate::net::reachable::Network::Onion),
        };
        reachable
            && !crate::net::is_bad_port(addr.port())
            && !self.is_peer_addr_banned(addr)
            && !self.is_own_address(addr)
    }

    /// One turn of the scheduler: start the sessions the limits allow now,
    /// spread over the next second at the rate.
    pub(super) fn crawl_tick(self: &Arc<Self>, sessions: &mut tokio::task::JoinSet<()>) {
        let Some(run) = self.crawl.get() else { return };
        if !self.crawl_may_run() {
            return;
        }
        let now = crate::time::now_secs();
        let now_ms = run.now_ms();
        let mut sched = run.scheduler.lock();
        let budget = sched.budget(now_ms);
        if budget == 0 || !sched.has_room() {
            return;
        }
        let candidates = run
            .book
            .lock()
            .next_due_where(now, budget * 4 + 16, |a| self.crawl_may_dial(a));
        let rate = u64::from(sched.limits().rate.max(1));
        let mut started = 0u64;
        for (addr, kind) in candidates {
            // The scheduler alone holds every limit, the rate included.
            match sched.try_start(&addr, now_ms) {
                Ok(()) => {}
                Err(crate::net::crawl::Refusal::Rate) => break,
                Err(_) => continue,
            }
            let Some(session) = run.book.lock().mark_dialling(&addr, now) else {
                sched.finish(&addr);
                continue;
            };
            let delay = Duration::from_millis(started * 1000 / rate);
            started += 1;
            let pm = Arc::clone(self);
            sessions.spawn(async move {
                tokio::time::sleep(delay).await;
                pm.run_crawl_session(addr, kind, Some(session)).await;
            });
        }
    }

    /// One session, bounded as a whole, and its record: whatever the session
    /// ends with, its result goes to the book under `session`, the token
    /// [`CrawlBook::mark_dialling`] gave it.
    pub(super) async fn run_crawl_session(
        self: &Arc<Self>,
        addr: PeerAddr,
        kind: SessionKind,
        session: Option<u64>,
    ) {
        let Some(run) = self.crawl.get() else { return };
        #[cfg(test)]
        if run.panic_in_session.swap(false, Ordering::Relaxed) {
            panic!("a crawl session panicked, as the test asked");
        }
        let cap = run.config.timings.session_cap(kind, addr.is_onion());
        let out = match tokio::time::timeout(cap, self.crawl_session(&addr, kind)).await {
            Ok(out) => out,
            Err(_) => {
                tracing::debug!(%addr, "crawl session past its {}s bound, closed", cap.as_secs());
                SessionOutput {
                    result: SessionResult::default(),
                    answer: None,
                    proxy_failed: false,
                }
            }
        };
        if out.proxy_failed {
            // Not the target's: no attempt, failure or back-off, and the
            // address is due again once the proxy is.
            tracing::debug!(%addr, kind = ?kind, "crawl session ended at the crawl proxy");
            run.book.lock().release(&addr, session);
            run.scheduler.lock().finish(&addr);
            return;
        }
        let reached = out.result.v2 == Attempt::Ok || out.result.v1 == Attempt::Ok;
        let obs = out.result.observation.as_ref();
        tracing::debug!(
            %addr,
            kind = ?kind,
            v2 = ?out.result.v2,
            v1 = ?out.result.v1,
            answer = out.answer.as_ref().map(Vec::len),
            fingerprint = %obs.map_or_else(|| "-".to_string(), |o| o.fingerprint.to_string()),
            user_agent = obs.map_or("-", |o| o.user_agent.as_str()),
            probes = ?obs.map(|o| o.probes),
            chain_check = ?obs.and_then(|o| o.chain_check),
            shape = ?obs.and_then(|o| o.shape.as_ref()),
            verdict = ?obs.map(|o| o.verdict),
            "crawl session done"
        );
        let now = crate::time::now_secs();
        {
            let mut book = run.book.lock();
            if let Some(answer) = &out.answer {
                book.admit(&addr, answer, now);
            }
            book.record_result(&addr, session, kind, out.result, now);
        }
        run.scheduler.lock().finish(&addr);
        let counter = if reached {
            &run.reached
        } else {
            &run.unreached
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// A seeding round: `-crawlseed`, the fixed seeds, a uniform sample of
    /// the address book (read only), and the DNS seeds. Under a proxy the
    /// DNS round looks nothing up locally: it takes the onion seeds, as the
    /// node's own seeding does, and what the node's proxied seed fetches
    /// put in the address book reaches the crawl through the sample.
    pub(super) async fn crawl_seed_round(self: &Arc<Self>) {
        let Some(run) = self.crawl.get() else { return };
        let network = self.chain_state.network;
        let mut seeds: Vec<(PeerAddr, u64)> =
            run.config.seeds.iter().map(|a| (a.clone(), 0)).collect();
        if run.config.fixed_seeds {
            seeds.extend(
                crate::net::dns::fixed_seeds_for_network(network)
                    .into_iter()
                    .map(|a| (a, 0)),
            );
        }
        seeds.extend(self.crawl_addrman_sample(crawl::ADDRMAN_SAMPLE));
        if run.config.dns_seeds {
            let found = crate::net::dns::resolve_seeds_with(
                network,
                self.proxy.as_deref(),
                &run.config.signet_seeds,
            )
            .await;
            seeds.extend(found.into_iter().map(|a| (a, 0)));
        }
        let now = crate::time::now_secs();
        let mut book = run.book.lock();
        let seeded = seeds
            .into_iter()
            .filter(|(a, services)| book.seed(a.clone(), *services, now))
            .count();
        book.expire(now);
        tracing::debug!(seeded, entries = book.len(), "Crawl seeding round");
    }

    /// Up to `n` address-book entries, drawn uniformly, with their
    /// services. Reads the book; writes nothing.
    pub(super) fn crawl_addrman_sample(&self, n: usize) -> Vec<(PeerAddr, u64)> {
        let mut all: Vec<(PeerAddr, u64)> = self
            .addrman
            .read()
            .iter()
            .map(|e| (e.addr.clone(), e.services))
            .collect();
        all.sort_unstable();
        all.shuffle(&mut rand::thread_rng());
        all.truncate(n);
        all
    }

    /// A crawl session's `version` (see the module docs). `receiver` is the
    /// target's address on a direct dial; through a proxy the dummy.
    pub(super) fn crawl_version_message(&self, receiver: SocketAddr) -> VersionMessage {
        let timestamp = crate::time::now_secs() as i64;
        let user_agent = self
            .crawl
            .get()
            .map(|run| run.user_agent.clone())
            .unwrap_or_else(|| {
                crawl::user_agent(None).expect("the bare crawler user agent is valid")
            });
        let dummy = SocketAddr::from(([0, 0, 0, 0], 0));
        VersionMessage {
            version: crawl::CRAWL_PROTOCOL_VERSION,
            services: ServiceFlags::NONE,
            timestamp,
            receiver: Address::new(&receiver, ServiceFlags::NONE),
            sender: Address::new(&dummy, ServiceFlags::NONE),
            nonce: rand::random(),
            user_agent,
            start_height: self.chain_state.tip_height() as i32,
            relay: false,
        }
    }

    /// Reach `target` within `connect`: through `-crawlproxy` when it is set
    /// and `target` is clearnet, else directly from `-crawlbind`'s address
    /// for its family; an onion through the proxy with credentials of its
    /// own.
    pub(super) async fn crawl_dial(
        &self,
        target: &PeerAddr,
        connect: Duration,
    ) -> Result<TcpStream, DialFailure> {
        let Some(run) = self.crawl.get() else {
            return Err(DialFailure::Target("the crawl is off".into()));
        };
        #[cfg(test)]
        run.dialled.lock().push(target.clone());
        let timed_out = || DialFailure::Target("connect timeout".into());
        match target {
            PeerAddr::Socket(sa) => {
                let sa = SocketAddr::new(sa.ip().to_canonical(), sa.port());
                if let Some(proxy_addr) = run.config.proxy {
                    // -crawlbind does not apply: the source is the proxy's
                    // host. No fallback: a proxy failure is never dialled
                    // direct.
                    let deadline = tokio::time::Instant::now() + connect;
                    let proxy_connect = self.socks_dial_timeouts().proxy_connect;
                    return match proxy::connect_socks5_staged(
                        proxy_addr,
                        sa,
                        proxy_connect,
                        deadline,
                    )
                    .await
                    {
                        Ok(stream) => {
                            run.proxy_answered();
                            Ok(stream)
                        }
                        // The target answered: the proxy reaches the network.
                        Err(proxy::Socks5Failure::Refused(e)) => {
                            run.proxy_answered();
                            Err(DialFailure::Target(e))
                        }
                        Err(proxy::Socks5Failure::Target(e)) => {
                            if run.proxy_silent(&e) {
                                Err(DialFailure::Proxy(e))
                            } else {
                                Err(DialFailure::Target(e))
                            }
                        }
                        Err(proxy::Socks5Failure::Proxy(e)) => {
                            run.proxy_failed(&e);
                            Err(DialFailure::Proxy(e))
                        }
                    };
                }
                let (socket, bind) = match sa.ip() {
                    IpAddr::V4(_) => (
                        tokio::net::TcpSocket::new_v4(),
                        run.config.bind_v4.map(IpAddr::V4),
                    ),
                    IpAddr::V6(_) => (
                        tokio::net::TcpSocket::new_v6(),
                        run.config.bind_v6.map(IpAddr::V6),
                    ),
                };
                let socket = socket.map_err(|e| DialFailure::Target(format!("socket: {e}")))?;
                if let Some(ip) = bind {
                    socket
                        .bind(SocketAddr::new(ip, 0))
                        .map_err(|e| DialFailure::Target(format!("bind {ip}: {e}")))?;
                }
                tokio::time::timeout(connect, socket.connect(sa))
                    .await
                    .map_err(|_| timed_out())?
                    .map_err(|e| DialFailure::Target(format!("connect: {e}")))
            }
            PeerAddr::Onion { host, port } => {
                if self.onion_disabled.load(Ordering::Relaxed) {
                    return Err(DialFailure::Target(
                        ".onion connections are disabled (-onion=0)".into(),
                    ));
                }
                let proxy_addr = self
                    .onion_proxy
                    .as_deref()
                    .or(self.proxy.as_deref())
                    .ok_or_else(|| {
                        DialFailure::Target("no proxy configured for .onion connections".into())
                    })?;
                // A circuit of its own, whatever -proxyrandomize says.
                let token = format!("{:016x}", rand::random::<u64>());
                tokio::time::timeout(
                    connect,
                    proxy::connect_socks5_onion(
                        proxy_addr,
                        host,
                        *port,
                        Some((&token, &token)),
                        self.socks_dial_timeouts(),
                    ),
                )
                .await
                .map_err(|_| timed_out())?
                .map_err(|e| DialFailure::Target(format!("connect to onion via proxy: {e}")))
            }
        }
    }

    /// One transport attempt: the dial, then the BIP 324 key exchange when
    /// `v2`. Returns the connection and the handshake's deadline.
    async fn crawl_open(&self, target: &PeerAddr, v2: bool) -> (Opened, tokio::time::Instant) {
        let run = self.crawl.get().expect("the crawl is on");
        let t = run.config.timings;
        let (connect, handshake) = if target.is_onion() {
            (t.tor_connect, t.tor_handshake)
        } else {
            (t.connect, t.handshake)
        };
        let stream = self.crawl_dial(target, connect).await;
        let deadline = tokio::time::Instant::now() + handshake;
        let mut stream = match stream {
            Ok(s) => s,
            Err(DialFailure::Proxy(_)) => return (Opened::ProxyFailed, deadline),
            Err(DialFailure::Target(_)) => return (Opened::NoDial, deadline),
        };
        let _ = stream.set_nodelay(true);
        let magic = self.chain_state.p2p_magic();
        if !v2 {
            return (
                Opened::Open(Box::new(Connection::with_magic(stream, magic)), None),
                deadline,
            );
        }
        let stats = PeerStats::new(run.totals.clone());
        let exchange = tokio::time::timeout_at(
            deadline,
            crate::net::v2transport::initiator_handshake_observed(
                &mut stream,
                self.chain_state.network,
                0,
                Some(&stats),
            ),
        )
        .await;
        match exchange {
            Ok(Ok((cipher, leftover, greeting))) => (
                Opened::Open(
                    Box::new(Connection::v2(crate::net::v2transport::V2Connection::new(
                        stream, cipher, leftover,
                    ))),
                    Some(greeting),
                ),
                deadline,
            ),
            // Core redials v1 only when nothing came back.
            _ if stats.bytes_recv() == 0 => (Opened::V1Only, deadline),
            _ => (Opened::Failed, deadline),
        }
    }

    /// The handshake: our `version`, the peer's, `wtxidrelay` and
    /// `sendaddrv2` at a common version of 70016, our `verack`, and the
    /// peer's, by `deadline`. The peer's messages go into a transcript as
    /// [`crate::net::behavior::HandshakeCapture`] records one.
    async fn crawl_handshake(
        &self,
        conn: &mut Connection,
        target: &PeerAddr,
        deadline: tokio::time::Instant,
    ) -> Result<Handshaken, String> {
        let run = self.crawl.get().expect("the crawl is on");
        // Through a proxy the dummy, as Core sends for a proxied peer.
        let receiver = match target {
            PeerAddr::Socket(sa) if run.config.proxy.is_none() => *sa,
            _ => SocketAddr::from(([0, 0, 0, 0], 0)),
        };
        let ours = self.build_version_message(receiver, ConnType::Crawl);
        run.nonces.lock().insert(ours.nonce);
        let _nonce = NonceGuard(&run.nonces, ours.nonce);
        let sent = Instant::now();
        conn.send(NetworkMessage::Version(ours.clone()))
            .await
            .map_err(|e| format!("send version: {e}"))?;
        let their = loop {
            match recv_by(conn, deadline).await? {
                NetworkMessage::Version(v)
                    if v.user_agent.len() <= crate::MAX_SUBVERSION_LENGTH =>
                {
                    break v;
                }
                _ => {}
            }
        };
        if their.nonce == ours.nonce {
            return Err("connected to self".into());
        }
        // The peer's timestamp is its own to set: i64::MIN must not overflow.
        let clock_offset_secs = their
            .timestamp
            .saturating_sub(crate::time::now_secs() as i64);
        let our_height = self.chain_state.tip_height();
        let mut behavior = PeerBehavior::default();
        behavior.note_version(&their, our_height);
        behavior.handshake.observe("version", false);
        let at_70016 = their.version.min(crawl::CRAWL_PROTOCOL_VERSION) >= WTXID_RELAY_VERSION;
        self.send_feature_negotiation(conn, at_70016).await?;
        conn.send(NetworkMessage::Verack)
            .await
            .map_err(|e| format!("send verack: {e}"))?;
        let mut wtxid_relay = false;
        loop {
            let msg = recv_by(conn, deadline).await?;
            behavior.handshake.observe(
                crate::net::behavior::wire_command(&msg),
                matches!(msg, NetworkMessage::Pong(_)),
            );
            match msg {
                NetworkMessage::Verack => break,
                NetworkMessage::WtxidRelay if at_70016 => wtxid_relay = true,
                _ => {}
            }
        }
        Ok(Handshaken {
            version: their,
            behavior,
            wtxid_relay,
            rtt_ms: u32::try_from(sent.elapsed().as_millis()).unwrap_or(u32::MAX),
            our_height,
            clock_offset_secs,
        })
    }

    /// A whole session to `target`: the transport (v2 to a node known to
    /// advertise it, then v1 if v2 failed as a v1-only node fails it; v1
    /// alone to any other node and for a recheck), the handshake, the
    /// passive wait, and for a discovery session `getaddr` and, under
    /// `-crawlprobes`, the probes.
    pub(super) async fn crawl_session(
        &self,
        target: &PeerAddr,
        kind: SessionKind,
    ) -> SessionOutput {
        let run = self.crawl.get().expect("the crawl is on");
        let mut result = SessionResult::default();
        let v2_first = kind != SessionKind::V1Recheck
            && run
                .book
                .lock()
                .get(&CrawlAddr::Peer(target.clone()))
                .is_some_and(|e| e.dials_v2_first());
        let proxy_failed = || SessionOutput {
            result: SessionResult::default(),
            answer: None,
            proxy_failed: true,
        };
        let opened = if !v2_first {
            match self.crawl_open(target, false).await {
                (Opened::Open(c, g), d) => Some((*c, g, d)),
                (Opened::ProxyFailed, _) => return proxy_failed(),
                _ => None,
            }
        } else {
            match self.crawl_open(target, true).await {
                (Opened::Open(c, g), d) => Some((*c, g, d)),
                (Opened::ProxyFailed, _) => return proxy_failed(),
                (Opened::NoDial, _) => None,
                (Opened::Failed, _) => {
                    result.v2 = Attempt::Failed;
                    None
                }
                (Opened::V1Only, _) => {
                    result.v2 = Attempt::Failed;
                    match self.crawl_open(target, false).await {
                        (Opened::Open(c, g), d) => Some((*c, g, d)),
                        // The v1 redial says nothing of the target either.
                        (Opened::ProxyFailed, _) => return proxy_failed(),
                        _ => None,
                    }
                }
            }
        };
        let Some((mut conn, greeting, deadline)) = opened else {
            return SessionOutput {
                result,
                answer: None,
                proxy_failed: false,
            };
        };
        let v2 = greeting.is_some();
        let shook = self.crawl_handshake(&mut conn, target, deadline).await;
        let slot = if v2 { &mut result.v2 } else { &mut result.v1 };
        let mut hs = match shook {
            Ok(hs) => {
                *slot = Attempt::Ok;
                hs
            }
            Err(e) => {
                tracing::debug!(%target, v2, "crawl handshake failed: {e}");
                *slot = Attempt::Failed;
                return SessionOutput {
                    result,
                    answer: None,
                    proxy_failed: false,
                };
            }
        };

        let (mut reader, mut writer) = conn.split();
        let stats = PeerStats::new(run.totals.clone());
        reader.set_counters(stats.clone());
        writer.set_counters(stats);
        let (read_tx, mut read_rx) = mpsc::channel::<NetworkMessage>(64);
        let read_task = tokio::spawn(async move {
            while let Ok(msg) = reader.recv().await {
                if read_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });
        // The session ends with the crawl's loop, which drops it; nothing
        // else aborts it.
        let abort = tokio::sync::Notify::new();
        let t = run.config.timings;
        let passive_deadline = tokio::time::Instant::now() + t.passive;
        let capture = &mut hs.behavior.handshake;
        let listened = listen_passive(
            0,
            &mut writer,
            &mut read_rx,
            &abort,
            passive_deadline,
            |msg| {
                capture.observe(
                    crate::net::behavior::wire_command(msg),
                    matches!(msg, NetworkMessage::Pong(_)),
                )
            },
        )
        .await;
        let mut closed = listened.closed();
        // Judged on the handshake and the passive wait alone: nothing after
        // it enters the transcript.
        let user_agent = crate::net::limits::sanitize_string(&hs.version.user_agent);
        let verdict = survey::session_verdict(
            listened.passive_end(),
            &hs.behavior.handshake,
            &user_agent,
            hs.version.version,
            crawl::CRAWL_PROTOCOL_VERSION,
        );

        let mut getaddr = None;
        let mut answer = None;
        let mut answer_kind = None;
        let mut probes = ProbeResults::default();
        let mut chain_check = None;
        if kind == SessionKind::Discovery && !closed {
            let deadline = tokio::time::Instant::now() + t.discovery;
            let (got, was_closed) = self
                .crawl_getaddr(&mut writer, &mut read_rx, &abort, deadline)
                .await;
            closed = was_closed;
            getaddr = Some(match &got {
                Some((entries, _, delay_ms)) => GetaddrResult::Answered {
                    entries: entries.len() as u32,
                    delay_ms: *delay_ms,
                },
                None => GetaddrResult::NoAnswer,
            });
            answer_kind = got.as_ref().map(|(_, kind, _)| *kind);
            answer = got.map(|(entries, _, _)| entries);
            if run.config.probes && !closed {
                // Every vetted probe, in a random order: a declared crawler
                // has no shape to vary, and the record wants them all.
                let mut chosen = survey::Probe::ALL.to_vec();
                chosen.shuffle(&mut rand::thread_rng());
                #[cfg(test)]
                let chosen = run.forced_probes.lock().clone().unwrap_or(chosen);
                let locator = self.survey_locator();
                let zero = bitcoin::BlockHash::all_zeros();
                let (top, stop) = locator.unwrap_or((zero, zero));
                let ctx = ProbeContext::new(&mut rand::thread_rng(), top, stop, hs.wtxid_relay);
                let waits = (t.probe_reply, t.unknown_probe);
                let mut headers = None;
                send_probes(
                    0,
                    &mut writer,
                    &mut read_rx,
                    &abort,
                    chosen,
                    &ctx,
                    locator.is_some(),
                    waits,
                    Some(deadline),
                    Some(&mut headers),
                    |p, o| probes.set(p, o),
                )
                .await;
                // The chain check reads the `getheaders` probe's answer.
                if let Some(headers) = headers {
                    chain_check =
                        self.crawl_chain_check(&top, &stop, &headers, hs.version.start_height);
                }
            }
        }
        // Close as the peer would want: our FIN, then what it still sends
        // until it closes too, so unread bytes do not turn the close into
        // a reset.
        if !closed {
            let close_deadline = tokio::time::Instant::now() + t.close;
            let _ = tokio::time::timeout_at(close_deadline, writer.shutdown()).await;
            while let Next::Msg(_) = next_message(&mut read_rx, close_deadline, &abort).await {}
        }
        read_task.abort();
        drop(writer);

        // A session that sent no probe keeps the last one's answers in the
        // book, and is judged with them.
        let judged_probes = if probes.any() {
            probes
        } else {
            run.book
                .lock()
                .get(&CrawlAddr::Peer(target.clone()))
                .and_then(|e| e.observation.as_ref())
                .map(|o| o.probes)
                .unwrap_or_default()
        };
        let features = CrawlFeatures {
            v2: greeting,
            probes: judged_probes,
            getaddr: answer_kind,
        };
        let capture = &hs.behavior.handshake;
        // A peer that closed before its transcript settled showed nothing
        // of its implementation: no fingerprint.
        let fingerprint = if verdict == Verdict::ClosedEarly {
            crate::net::fingerprint::Fingerprint::Unknown
        } else {
            crate::net::fingerprint::classify_crawl(
                capture,
                hs.behavior.version.as_ref(),
                &features,
            )
        };
        // A shape no row matched (unknown, or only claimed by its user
        // agent) keeps its raw features, so a new implementation or release
        // shows up as many records of one shape before it has a row.
        let shape = fingerprint.observed().is_none().then(|| UnknownShape {
            commands: capture.commands().collect(),
            relay: hs.version.relay,
            v2: greeting,
            getaddr: answer_kind,
        });
        let asn = match target {
            PeerAddr::Socket(sa) if crate::net::is_routable(sa.ip()) => self
                .asmap
                .get()
                .map(|m| m.lookup(sa.ip()))
                .filter(|a| *a != 0),
            _ => None,
        };
        result.observation = Some(Observation {
            at: crate::time::now_secs(),
            fingerprint,
            user_agent,
            protocol_version: hs.version.version,
            services: hs.version.services.to_u64(),
            asn,
            probes,
            v2,
            height: hs.version.start_height,
            our_height: hs.our_height,
            chain_check,
            clock_offset_secs: Some(hs.clock_offset_secs),
            handshake_rtt_ms: Some(hs.rtt_ms),
            getaddr,
            shape,
            verdict,
        });
        SessionOutput {
            result,
            answer,
            proxy_failed: false,
        }
    }

    /// The chain check (`crawl::chain_check`) on the `getheaders` probe's
    /// answer: `locator` and `stop` are the probe's. `None` when the
    /// locator has left our block index.
    fn crawl_chain_check(
        &self,
        locator: &bitcoin::BlockHash,
        stop: &bitcoin::BlockHash,
        headers: &[bitcoin::block::Header],
        peer_height: i32,
    ) -> Option<crate::net::crawlbook::ChainCheck> {
        use crate::net::crawl::OurBlock;
        let chain = &self.chain_state;
        let locator_height = chain.get_block_index(locator)?.height;
        // The index's answer, with no walk: a wrong row would mislabel one
        // record, and a walk per header would cost a crawl too much.
        let ours = |hash: &bitcoin::BlockHash| match chain.get_block_index(hash) {
            None => OurBlock::Unknown,
            Some(e) if chain.active_chain_hash_at_height_indexed(e.height) == Some(*hash) => {
                OurBlock::Active(e.height)
            }
            Some(_) => OurBlock::Stale,
        };
        Some(crawl::chain_check(
            locator,
            locator_height,
            stop,
            headers,
            peer_height,
            ours,
        ))
    }

    /// Send one `getaddr` and wait for the answer: the first `addr` or
    /// `addrv2` with more than one entry (a single one is the peer's own
    /// announcement), by `deadline`. Returns the answer with its delay in
    /// milliseconds, and whether the connection closed. A `ping` is
    /// answered; a `getaddr` from the peer gets nothing; the rest is
    /// ignored.
    async fn crawl_getaddr(
        &self,
        writer: &mut ConnectionWriter,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
        abort: &tokio::sync::Notify,
        deadline: tokio::time::Instant,
    ) -> (Option<GetaddrAnswer>, bool) {
        if writer.send(NetworkMessage::GetAddr).await.is_err() {
            return (None, true);
        }
        let sent = Instant::now();
        loop {
            let msg = match next_message(read_rx, deadline, abort).await {
                Next::Msg(m) => m,
                Next::Timeout => return (None, false),
                Next::Closed | Next::Aborted => return (None, true),
            };
            let delay = || u32::try_from(sent.elapsed().as_millis()).unwrap_or(u32::MAX);
            match msg {
                NetworkMessage::AddrV2(entries) if entries.len() > 1 => {
                    return (Some((entries, AddrKind::AddrV2, delay())), false);
                }
                NetworkMessage::Addr(entries) if entries.len() > 1 => {
                    let v2 = entries
                        .iter()
                        .filter_map(|(time, a)| addr_entry_v2(*time, a))
                        .collect();
                    return (Some((v2, AddrKind::Addr, delay())), false);
                }
                NetworkMessage::Ping(n) => {
                    if writer.send(NetworkMessage::Pong(n)).await.is_err() {
                        return (None, true);
                    }
                }
                _ => {}
            }
        }
    }

    /// The crawl's book, for tests.
    #[cfg(test)]
    pub(super) fn crawl_book(&self) -> Option<CrawlBook> {
        self.crawl.get().map(|run| run.book.lock().clone())
    }
}
