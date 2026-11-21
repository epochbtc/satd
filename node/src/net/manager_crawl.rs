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
//! # Transport
//!
//! BIP 324 first. A v2 attempt that fails as a v1-only node fails it (it
//! closes the connection, or never answers, with nothing received) is
//! redialled over v1, as Core does (`V2Transport::ShouldReconnectV1`); one
//! that received bytes and failed is not. A v1 recheck dials v1 alone. The
//! node's `-v2transport` and `-v2only` do not apply: the crawl measures both
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
//! # Failure
//!
//! A panic in a crawl task stops the crawl, with an error in the log; the
//! node keeps running.

use super::*;
use super::survey_conn::{listen_passive, next_message, send_probes, Listened, Next};
use crate::net::behavior::PeerBehavior;
use crate::net::crawl::{self, CrawlConfig, Scheduler};
use crate::net::crawlbook::{
    Attempt, BookParams, CrawlBook, GetaddrResult, Network, Observation, SessionKind, SessionResult,
};
use crate::net::crawlreport;
use crate::net::survey::{self, ProbeContext, ProbeResults};
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
    /// The aggregate the metrics and the status page read, and when it was
    /// taken: they are polled often, and a walk of a full book is not free.
    aggregate: parking_lot::Mutex<Option<(Instant, crawlreport::Aggregate)>>,
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
}

/// How long the metrics and the status page reuse an aggregate before they
/// take a new one. `getcrawlinfo` always takes a new one.
pub(super) const AGGREGATE_MAX_AGE: Duration = Duration::from_secs(10);

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

/// How one transport attempt went.
enum Opened {
    /// The dial itself failed: nothing reached.
    NoDial,
    /// The v2 key exchange failed with nothing received, as against a
    /// v1-only node.
    V1Only,
    /// It failed some other way.
    Failed,
    Open(Box<Connection>),
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
}

/// The next message on a connection still in its handshake, by `deadline`.
async fn recv_by(conn: &mut Connection, deadline: tokio::time::Instant) -> Result<NetworkMessage, String> {
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
    Some(AddrV2Message { time, services: addr.services, addr: addr_v2, port: sa.port() })
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
            aggregate: parking_lot::Mutex::new(None),
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
        self.crawl.get().is_some_and(|run| run.nonces.lock().contains(&nonce))
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
        let Some(run) = self.crawl.get() else { return false };
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
        let ibd = ibd && !self.crawl.get().is_some_and(|run| run.out_of_ibd.load(Ordering::Relaxed));
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
    /// `-crawlnet` kept, and clearnet only when it does not go through the
    /// proxy.
    pub fn crawl_networks(&self) -> Vec<Network> {
        use crate::net::reachable::Network as Reach;
        let Some(run) = self.crawl.get() else { return Vec::new() };
        crawlreport::DIALLED
            .into_iter()
            .filter(|n| run.config.networks.as_ref().is_none_or(|nets| nets.contains(n)))
            .filter(|n| match n {
                Network::Ipv4 => self.proxy.is_none() && self.network_reachable(Reach::Ipv4),
                Network::Ipv6 => self.proxy.is_none() && self.network_reachable(Reach::Ipv6),
                Network::Onion => self.network_reachable(Reach::Onion),
                Network::I2p | Network::Cjdns => false,
            })
            .collect()
    }

    /// A fresh aggregate of the book, kept for [`Self::crawl_metrics`].
    fn crawl_aggregate_now(&self, run: &CrawlRun) -> crawlreport::Aggregate {
        let agg = crawlreport::aggregate(&run.book.lock(), crate::time::now_secs());
        *run.aggregate.lock() = Some((Instant::now(), agg.clone()));
        agg
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
            return out;
        };
        let agg = self.crawl_aggregate_now(run);
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
        let Some(run) = self.crawl.get() else { return serde_json::json!([]) };
        // Copied under the lock, serialized outside it.
        let book = run.book.lock().clone();
        crawlreport::nodes_json(&book, crate::time::now_secs(), verbose)
    }

    /// The crawl's counts for the metrics and the status page; `None` with
    /// the crawl off. The aggregate is reused for up to
    /// [`AGGREGATE_MAX_AGE`].
    pub fn crawl_metrics(&self) -> Option<CrawlMetrics> {
        let run = self.crawl.get()?;
        let cached = run.aggregate.lock().clone().filter(|(at, _)| at.elapsed() < AGGREGATE_MAX_AGE);
        let aggregate = match cached {
            Some((_, agg)) => agg,
            None => self.crawl_aggregate_now(run),
        };
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
            }
        }
        sessions.abort_all();
    }

    /// Whether the crawl may dial `addr`: on a network the node's dialer
    /// reaches and `-crawlnet` keeps, not clearnet through the proxy, not
    /// banned, not one of the node's own addresses, and not a bad port.
    pub(super) fn crawl_may_dial(&self, addr: &PeerAddr) -> bool {
        let Some(run) = self.crawl.get() else { return false };
        if run.config.networks.as_ref().is_some_and(|nets| !nets.contains(&crawl::network_of(addr))) {
            return false;
        }
        let reachable = match addr {
            PeerAddr::Socket(sa) => {
                crate::net::is_valid(sa.ip())
                    && self.reachable.read().contains_socket(sa)
                    && !self.dials_through_proxy(*sa)
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
        let candidates = run.book.lock().next_due_where(now, budget * 4 + 16, |a| self.crawl_may_dial(a));
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
    pub(super) async fn run_crawl_session(self: &Arc<Self>, addr: PeerAddr, kind: SessionKind, session: Option<u64>) {
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
                SessionOutput { result: SessionResult::default(), answer: None }
            }
        };
        let reached = out.result.v2 == Attempt::Ok || out.result.v1 == Attempt::Ok;
        tracing::debug!(
            %addr,
            kind = ?kind,
            v2 = ?out.result.v2,
            v1 = ?out.result.v1,
            answer = out.answer.as_ref().map(Vec::len),
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
        let counter = if reached { &run.reached } else { &run.unreached };
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
        let mut seeds: Vec<(PeerAddr, u64)> = run.config.seeds.iter().map(|a| (a.clone(), 0)).collect();
        if run.config.fixed_seeds {
            seeds.extend(crate::net::dns::fixed_seeds_for_network(network).into_iter().map(|a| (a, 0)));
        }
        seeds.extend(self.crawl_addrman_sample(crawl::ADDRMAN_SAMPLE));
        if run.config.dns_seeds {
            let found =
                crate::net::dns::resolve_seeds_with(network, self.proxy.as_deref(), &run.config.signet_seeds).await;
            seeds.extend(found.into_iter().map(|a| (a, 0)));
        }
        let now = crate::time::now_secs();
        let mut book = run.book.lock();
        let seeded = seeds.into_iter().filter(|(a, services)| book.seed(a.clone(), *services, now)).count();
        book.expire(now);
        tracing::debug!(seeded, entries = book.len(), "Crawl seeding round");
    }

    /// Up to `n` address-book entries, drawn uniformly, with their
    /// services. Reads the book; writes nothing.
    pub(super) fn crawl_addrman_sample(&self, n: usize) -> Vec<(PeerAddr, u64)> {
        let mut all: Vec<(PeerAddr, u64)> =
            self.addrman.read().iter().map(|e| (e.addr.clone(), e.services)).collect();
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
            .unwrap_or_else(|| crawl::user_agent(None).expect("the bare crawler user agent is valid"));
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

    /// Reach `target`: directly from `-crawlbind`'s address for its family,
    /// or an onion through the proxy with credentials of its own.
    async fn crawl_dial(&self, target: &PeerAddr) -> Result<TcpStream, String> {
        let Some(run) = self.crawl.get() else { return Err("the crawl is off".into()) };
        #[cfg(test)]
        run.dialled.lock().push(target.clone());
        match target {
            PeerAddr::Socket(sa) => {
                let sa = SocketAddr::new(sa.ip().to_canonical(), sa.port());
                let (socket, bind) = match sa.ip() {
                    IpAddr::V4(_) => (tokio::net::TcpSocket::new_v4(), run.config.bind_v4.map(IpAddr::V4)),
                    IpAddr::V6(_) => (tokio::net::TcpSocket::new_v6(), run.config.bind_v6.map(IpAddr::V6)),
                };
                let socket = socket.map_err(|e| format!("socket: {e}"))?;
                if let Some(ip) = bind {
                    socket.bind(SocketAddr::new(ip, 0)).map_err(|e| format!("bind {ip}: {e}"))?;
                }
                socket.connect(sa).await.map_err(|e| format!("connect: {e}"))
            }
            PeerAddr::Onion { host, port } => {
                if self.onion_disabled.load(Ordering::Relaxed) {
                    return Err(".onion connections are disabled (-onion=0)".into());
                }
                let proxy_addr = self
                    .onion_proxy
                    .as_deref()
                    .or(self.proxy.as_deref())
                    .ok_or("no proxy configured for .onion connections")?;
                // A circuit of its own, whatever -proxyrandomize says.
                let token = format!("{:016x}", rand::random::<u64>());
                proxy::connect_socks5_onion(proxy_addr, host, *port, Some((&token, &token)), self.socks_dial_timeouts())
                    .await
                    .map_err(|e| format!("connect to onion via proxy: {e}"))
            }
        }
    }

    /// One transport attempt: the dial, then the BIP 324 key exchange when
    /// `v2`. Returns the connection and the handshake's deadline.
    async fn crawl_open(&self, target: &PeerAddr, v2: bool) -> (Opened, tokio::time::Instant) {
        let run = self.crawl.get().expect("the crawl is on");
        let t = run.config.timings;
        let (connect, handshake) = if target.is_onion() { (t.tor_connect, t.tor_handshake) } else { (t.connect, t.handshake) };
        let stream = tokio::time::timeout(connect, self.crawl_dial(target)).await;
        let deadline = tokio::time::Instant::now() + handshake;
        let mut stream = match stream {
            Ok(Ok(s)) => s,
            _ => return (Opened::NoDial, deadline),
        };
        let _ = stream.set_nodelay(true);
        let magic = self.chain_state.p2p_magic();
        if !v2 {
            return (Opened::Open(Box::new(Connection::with_magic(stream, magic))), deadline);
        }
        let stats = PeerStats::new(run.totals.clone());
        let exchange = tokio::time::timeout_at(
            deadline,
            crate::net::v2transport::initiator_handshake(&mut stream, self.chain_state.network, 0, Some(&stats)),
        )
        .await;
        match exchange {
            Ok(Ok((cipher, leftover))) => (
                Opened::Open(Box::new(Connection::v2(crate::net::v2transport::V2Connection::new(stream, cipher, leftover)))),
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
        let receiver = match target {
            PeerAddr::Socket(sa) => *sa,
            PeerAddr::Onion { .. } => SocketAddr::from(([0, 0, 0, 0], 0)),
        };
        let ours = self.build_version_message(receiver, ConnType::Crawl);
        run.nonces.lock().insert(ours.nonce);
        let _nonce = NonceGuard(&run.nonces, ours.nonce);
        let sent = Instant::now();
        conn.send(NetworkMessage::Version(ours.clone())).await.map_err(|e| format!("send version: {e}"))?;
        let their = loop {
            match recv_by(conn, deadline).await? {
                NetworkMessage::Version(v) if v.user_agent.len() <= crate::MAX_SUBVERSION_LENGTH => break v,
                _ => {}
            }
        };
        if their.nonce == ours.nonce {
            return Err("connected to self".into());
        }
        // The peer's timestamp is its own to set: i64::MIN must not overflow.
        let clock_offset_secs = their.timestamp.saturating_sub(crate::time::now_secs() as i64);
        let our_height = self.chain_state.tip_height();
        let mut behavior = PeerBehavior::default();
        behavior.note_version(&their, our_height);
        behavior.handshake.observe("version", false);
        let at_70016 = their.version.min(crawl::CRAWL_PROTOCOL_VERSION) >= WTXID_RELAY_VERSION;
        self.send_feature_negotiation(conn, at_70016).await?;
        conn.send(NetworkMessage::Verack).await.map_err(|e| format!("send verack: {e}"))?;
        let mut wtxid_relay = false;
        loop {
            let msg = recv_by(conn, deadline).await?;
            behavior.handshake.observe(crate::net::behavior::wire_command(&msg), matches!(msg, NetworkMessage::Pong(_)));
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

    /// A whole session to `target`: the transport (v2, then v1 if v2
    /// failed as a v1-only node fails it; v1 alone for a recheck), the
    /// handshake, the passive wait, and for a discovery session `getaddr`
    /// and, under `-crawlprobes`, the probes.
    pub(super) async fn crawl_session(&self, target: &PeerAddr, kind: SessionKind) -> SessionOutput {
        let run = self.crawl.get().expect("the crawl is on");
        let mut result = SessionResult::default();
        let opened = if kind == SessionKind::V1Recheck {
            match self.crawl_open(target, false).await {
                (Opened::Open(c), d) => Some((*c, false, d)),
                _ => None,
            }
        } else {
            match self.crawl_open(target, true).await {
                (Opened::Open(c), d) => Some((*c, true, d)),
                (Opened::NoDial, _) => None,
                (Opened::Failed, _) => {
                    result.v2 = Attempt::Failed;
                    None
                }
                (Opened::V1Only, _) => {
                    result.v2 = Attempt::Failed;
                    match self.crawl_open(target, false).await {
                        (Opened::Open(c), d) => Some((*c, false, d)),
                        _ => None,
                    }
                }
            }
        };
        let Some((mut conn, v2, deadline)) = opened else {
            return SessionOutput { result, answer: None };
        };
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
                return SessionOutput { result, answer: None };
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
        let mut closed = matches!(
            listen_passive(0, &mut writer, &mut read_rx, &abort, passive_deadline, |msg| {
                capture.observe(crate::net::behavior::wire_command(msg), matches!(msg, NetworkMessage::Pong(_)))
            })
            .await,
            Listened::Closed
        );

        let mut getaddr = None;
        let mut answer = None;
        let mut probes = ProbeResults::default();
        if kind == SessionKind::Discovery && !closed {
            let deadline = tokio::time::Instant::now() + t.discovery;
            let (got, was_closed) = self.crawl_getaddr(&mut writer, &mut read_rx, &abort, deadline).await;
            closed = was_closed;
            getaddr = Some(match &got {
                Some((entries, delay_ms)) => {
                    GetaddrResult::Answered { entries: entries.len() as u32, delay_ms: *delay_ms }
                }
                None => GetaddrResult::NoAnswer,
            });
            answer = got.map(|(entries, _)| entries);
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
                    |p, o| probes.set(p, o),
                )
                .await;
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

        let fingerprint = crate::net::fingerprint::classify(false, &hs.behavior.handshake, hs.behavior.version.as_ref(), true);
        let asn = match target {
            PeerAddr::Socket(sa) if crate::net::is_routable(sa.ip()) => {
                self.asmap.get().map(|m| m.lookup(sa.ip())).filter(|a| *a != 0)
            }
            _ => None,
        };
        result.observation = Some(Observation {
            at: crate::time::now_secs(),
            fingerprint,
            user_agent: crate::net::limits::sanitize_string(&hs.version.user_agent),
            protocol_version: hs.version.version,
            services: hs.version.services.to_u64(),
            asn,
            probes,
            v2,
            height: hs.version.start_height,
            our_height: hs.our_height,
            chain_check: None,
            clock_offset_secs: Some(hs.clock_offset_secs),
            handshake_rtt_ms: Some(hs.rtt_ms),
            getaddr,
        });
        SessionOutput { result, answer }
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
    ) -> (Option<(Vec<AddrV2Message>, u32)>, bool) {
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
                NetworkMessage::AddrV2(entries) if entries.len() > 1 => return (Some((entries, delay())), false),
                NetworkMessage::Addr(entries) if entries.len() > 1 => {
                    let v2 = entries.iter().filter_map(|(time, a)| addr_entry_v2(*time, a)).collect();
                    return (Some((v2, delay())), false);
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
