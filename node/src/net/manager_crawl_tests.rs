//! The crawl's connections (`crawl_conn`) against a live `PeerManager` and
//! scripted peers on loopback. A regtest manager's book admits loopback
//! addresses; nothing here dials off the host.

use super::survey_tests::{book_add, mk_pm_live, mk_pm_proxied, mk_pm_with, ONION};
use super::*;
use crate::net::crawl::{CrawlConfig, Limits, Timings};
use crate::net::crawlbook::{Attempt, CrawlAddr, GetaddrResult, SessionKind, SessionResult};
use crate::net::survey::{Probe, ProbeOutcome};
use bitcoin::p2p::Magic;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};

/// Short phases, so a test sees a whole session in seconds.
fn quick() -> Timings {
    Timings {
        connect: Duration::from_secs(2),
        tor_connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        tor_handshake: Duration::from_secs(2),
        passive: Duration::from_millis(500),
        discovery: Duration::from_secs(4),
        probe_reply: Duration::from_millis(500),
        unknown_probe: Duration::from_millis(300),
        close: Duration::from_millis(300),
    }
}

fn config() -> CrawlConfig {
    CrawlConfig { dns_seeds: false, fixed_seeds: false, timings: quick(), ..CrawlConfig::default() }
}

fn enable(pm: &PeerManager, config: CrawlConfig) -> &crawl_conn::CrawlRun {
    pm.enable_crawl(config).unwrap();
    let run = pm.crawl.get().unwrap();
    run.out_of_ibd.store(true, Ordering::Relaxed);
    run
}

/// How a scripted peer behaves once dialled. It speaks v1 only: a v2
/// handshake reads as a bad magic and it hangs up, as a v1-only node does.
#[derive(Clone)]
struct Script {
    user_agent: &'static str,
    /// Sent between the dialler's `version` and our `verack`.
    negotiation: Vec<NetworkMessage>,
    /// Sent once the dialler's `verack` arrives.
    after_verack: Vec<NetworkMessage>,
    /// The answer to `getaddr`; none when `None`.
    answer: Option<Vec<AddrV2Message>>,
    /// Send `ping` this often while connected.
    ping_every: Option<Duration>,
    /// Accept the connection and say nothing.
    silent: bool,
    /// Answer the first bytes with garbage and hang up.
    garbage: bool,
    /// Close a connection that opens with anything but v1.
    v1_only: bool,
    /// The `version` timestamp; three seconds behind the clock when `None`.
    timestamp: Option<i64>,
}

fn core_script() -> Script {
    Script {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![
            NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct { send_compact: false, version: 2 }),
            NetworkMessage::Ping(77),
            NetworkMessage::FeeFilter(1000),
        ],
        answer: None,
        ping_every: None,
        silent: false,
        garbage: false,
        v1_only: true,
        timestamp: None,
    }
}

fn silent() -> Script {
    Script { silent: true, ..core_script() }
}

/// Public IPv4 entries for a `getaddr` answer.
fn answer(n: u8) -> Vec<AddrV2Message> {
    let now = crate::time::now_secs() as u32;
    (0..n)
        .map(|i| AddrV2Message {
            time: now,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(23, 1, i, 7)),
            port: 8333,
        })
        .collect()
}

/// What every connection to a scripted peer received, in order.
type Log = Arc<parking_lot::Mutex<Vec<Vec<NetworkMessage>>>>;

/// A scripted peer listening on `ip`: its address and what each
/// connection received.
async fn scripted(ip: &str, script: Script) -> (PeerAddr, Log) {
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Log = Default::default();
    let conns = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let i = {
                let mut l = conns.lock();
                l.push(Vec::new());
                l.len() - 1
            };
            let conns = conns.clone();
            let script = script.clone();
            tokio::spawn(async move { serve(stream, script, conns, i).await });
        }
    });
    (PeerAddr::Socket(addr), log)
}

async fn serve(mut stream: TcpStream, script: Script, log: Log, i: usize) {
    use tokio::io::AsyncWriteExt as _;
    if script.silent {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return;
    }
    let mut first = [0u8; 4];
    if stream.peek(&mut first).await.is_err() {
        return;
    }
    if script.garbage {
        let _ = stream.write_all(&[0x5a; 200]).await;
        return;
    }
    if script.v1_only && first != Magic::REGTEST.to_bytes() {
        return;
    }
    let mut conn = Connection::with_magic(stream, Magic::REGTEST);
    let mut ping = script.ping_every.map(tokio::time::interval);
    loop {
        let tick = async {
            match ping.as_mut() {
                Some(p) => {
                    p.tick().await;
                }
                None => std::future::pending().await,
            }
        };
        let msg = tokio::select! {
            r = tokio::time::timeout(Duration::from_secs(30), conn.recv()) => match r {
                Ok(Ok(m)) => m,
                _ => return,
            },
            _ = tick => {
                let _ = conn.send(NetworkMessage::Ping(5)).await;
                continue;
            }
        };
        log.lock()[i].push(msg.clone());
        match msg {
            NetworkMessage::Version(_) => {
                let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                let _ = conn
                    .send(NetworkMessage::Version(VersionMessage {
                        version: 70016,
                        services,
                        timestamp: script.timestamp.unwrap_or(crate::time::now_secs() as i64 - 3),
                        receiver: Address::new(&zero, ServiceFlags::NONE),
                        sender: Address::new(&zero, services),
                        nonce: 0x5eed,
                        user_agent: script.user_agent.into(),
                        start_height: 0,
                        relay: true,
                    }))
                    .await;
                for m in &script.negotiation {
                    let _ = conn.send(m.clone()).await;
                }
                let _ = conn.send(NetworkMessage::Verack).await;
            }
            NetworkMessage::Verack => {
                for m in &script.after_verack {
                    let _ = conn.send(m.clone()).await;
                }
            }
            NetworkMessage::Ping(n) => {
                let _ = conn.send(NetworkMessage::Pong(n)).await;
            }
            NetworkMessage::GetAddr => {
                // Our own announcement first, as Core's trickle sends it.
                let _ = conn.send(NetworkMessage::AddrV2(answer(1))).await;
                if let Some(a) = &script.answer {
                    let _ = conn.send(NetworkMessage::AddrV2(a.clone())).await;
                }
            }
            NetworkMessage::GetHeaders(_) => {
                let _ = conn.send(NetworkMessage::Headers(vec![])).await;
            }
            NetworkMessage::GetData(inv) => {
                let _ = conn.send(NetworkMessage::NotFound(inv)).await;
            }
            _ => {}
        }
    }
}

fn loopback(a: u8, b: u8) -> String {
    format!("127.{a}.{b}.1")
}

/// Wait until `f` holds, up to `secs`.
async fn until(secs: u64, f: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

// ---- Our version ----

/// A crawl session's `version` declares a crawler: protocol 70016,
/// services 0, relay off, our tip, the dummy `addr_from` with no services,
/// `/satd:<version>(crawler)/` with `-crawluacomment`, and a fresh random
/// nonce, never the node's own.
#[test]
fn crawl_version_fields_are_exact() {
    let (pm, _dir) = mk_pm_with(None);
    pm.enable_crawl(CrawlConfig { ua_comment: Some("census".into()), ..config() }).unwrap();
    let to: SocketAddr = "203.0.113.5:8333".parse().unwrap();
    let v = pm.build_version_message(to, ConnType::Crawl);
    assert_eq!(v.version, 70016);
    assert_eq!(v.services, ServiceFlags::NONE);
    assert!(!v.relay);
    assert_eq!(v.start_height, pm.chain_state.tip_height() as i32);
    assert_eq!(v.user_agent, format!("/satd:{}(crawler; census)/", env!("CARGO_PKG_VERSION")));
    assert_eq!(v.receiver, Address::new(&to, ServiceFlags::NONE));
    assert_eq!(v.sender, Address::new(&"0.0.0.0:0".parse().unwrap(), ServiceFlags::NONE));
    let now = crate::time::now_secs() as i64;
    assert!((v.timestamp - now).abs() <= 2);
    // The node's own -uacomment is not in it.
    assert!(!v.user_agent.contains(crate::user_agent().trim_matches('/')) || crate::user_agent() == crate::USER_AGENT);
    let nonces: HashSet<u64> = (0..64).map(|_| pm.build_version_message(to, ConnType::Crawl).nonce).collect();
    assert_eq!(nonces.len(), 64, "a fresh nonce every time");
    let node = pm.build_version_message(to, ConnType::OutboundFullRelay);
    assert_ne!(node.user_agent, v.user_agent);
    assert!(node.services != ServiceFlags::NONE && node.relay, "the node's own version is unchanged");
}

// ---- The session ----

/// A liveness session sends the handshake and nothing else unsolicited:
/// `version`, `wtxidrelay`, `sendaddrv2`, `verack`, then only `pong`s for
/// the peer's pings. No `getaddr`, no `sendheaders`, `sendcmpct`,
/// `feefilter` or `getheaders`, and none of our addresses; a `getaddr`
/// the peer sends gets nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_liveness_session_sends_the_handshake_and_nothing_else() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let mut script = core_script();
    script.after_verack.push(NetworkMessage::GetAddr);
    script.ping_every = Some(Duration::from_millis(150));
    let (target, log) = scripted("127.0.0.1", script).await;
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!((out.result.v2, out.result.v1), (Attempt::Failed, Attempt::Ok), "v1-only: v2, then the v1 redial");
    let conns = log.lock().clone();
    assert_eq!(conns.len(), 2, "the v2 attempt and the v1 redial");
    assert!(conns[0].is_empty(), "the v2 attempt got no v1 message through");
    let got = &conns[1];
    let cmds: Vec<&str> = got.iter().map(|m| m.cmd()).collect();
    assert_eq!(&cmds[..4], ["version", "wtxidrelay", "sendaddrv2", "verack"], "{cmds:?}");
    assert!(cmds[4..].iter().all(|c| *c == "pong"), "nothing but pongs after the handshake: {cmds:?}");
    assert!(cmds.len() > 4, "the pings were answered: {cmds:?}");
    let obs = out.result.observation.expect("an observation");
    assert_eq!(obs.getaddr, None, "a liveness session sends no getaddr");
    assert!(!obs.v2);
    assert_eq!(obs.user_agent, "/Satoshi:32.1.0/");
    assert_eq!(obs.height, 0);
    assert!(obs.clock_offset_secs.is_some_and(|o| (-6..=0).contains(&o)), "{obs:?}");
    assert!(obs.handshake_rtt_ms.is_some());
    assert!(out.answer.is_none());
}

/// A discovery session sends one `getaddr`, takes the first answer of more
/// than one entry (a single one is the peer's announcement), sends the four
/// probes, and records all of it. A `getaddr` from the peer still gets
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_session_asks_once_probes_and_records() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let mut script = core_script();
    script.after_verack.push(NetworkMessage::GetAddr);
    script.answer = Some(answer(3));
    let (target, log) = scripted("127.0.0.1", script).await;
    assert!(run.book.lock().seed(target.clone(), 0, crate::time::now_secs()));
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None).await;
    let got = log.lock()[1].clone();
    assert_eq!(got.iter().filter(|m| matches!(m, NetworkMessage::GetAddr)).count(), 1);
    assert!(!got.iter().any(|m| matches!(m, NetworkMessage::Addr(_) | NetworkMessage::AddrV2(_))), "no address to the peer");
    for probe in ["ping", "getdata"] {
        assert!(got.iter().any(|m| m.cmd() == probe), "{probe} sent: {got:?}");
    }
    // At genesis no stop hash lies past a locator: no getheaders probe.
    assert!(!got.iter().any(|m| m.cmd() == "getheaders"), "{got:?}");
    let book = pm.crawl_book().unwrap();
    let e = book.get(&CrawlAddr::Peer(target)).unwrap();
    assert_eq!(e.v1_ok, Some(true));
    assert_eq!(e.v2_ok, Some(false));
    assert!(e.last_discovery.is_some());
    let obs = e.observation.as_ref().unwrap();
    assert_eq!(obs.getaddr.map(|g| matches!(g, GetaddrResult::Answered { entries: 3, .. })), Some(true), "{obs:?}");
    assert!(matches!(obs.probes.get(Probe::Ping), Some(ProbeOutcome::Answered(_))));
    assert_eq!(obs.probes.get(Probe::GetData), Some(ProbeOutcome::Answered(1)));
    assert_eq!(obs.probes.get(Probe::Unknown), Some(ProbeOutcome::Silent));
    assert_eq!(obs.probes.get(Probe::GetHeaders), None);
    // The answer entered the crawl's book, and only that.
    assert_eq!(book.len(), 4);
    assert_eq!(pm.addrman_len(), 0);
}

/// A v2 attempt answered with bytes that are not a v2 handshake is not
/// redialled over v1: Core redials only when nothing came back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_v2_attempt_that_received_bytes_is_not_redialled() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let (target, log) = scripted("127.0.0.1", Script { garbage: true, ..core_script() }).await;
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!((out.result.v2, out.result.v1), (Attempt::Failed, Attempt::NotTried));
    assert_eq!(log.lock().len(), 1, "no v1 redial");
    // A v1 recheck dials v1 alone.
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    let out = pm.crawl_session(&target, SessionKind::V1Recheck).await;
    assert_eq!((out.result.v2, out.result.v1), (Attempt::NotTried, Attempt::Ok));
    assert_eq!(log.lock().len(), 1);
}

/// A discovery session whose `getaddr` is never answered ends at its bound,
/// though the peer keeps pinging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_session_ends_by_its_bound() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, CrawlConfig { probes: false, ..config() });
    let script = Script { ping_every: Some(Duration::from_millis(100)), ..core_script() };
    let (target, _log) = scripted("127.0.0.1", script).await;
    let started = Instant::now();
    let out = tokio::time::timeout(Duration::from_secs(20), pm.crawl_session(&target, SessionKind::Discovery))
        .await
        .expect("the session ended");
    let t = quick();
    assert!(started.elapsed() <= t.session_cap(SessionKind::Discovery, false), "{:?}", started.elapsed());
    assert!(started.elapsed() >= t.discovery, "it waited for the answer");
    assert_eq!(out.result.observation.unwrap().getaddr, Some(GetaddrResult::NoAnswer));
}

// ---- Isolation ----

/// A crawl connection is none of the node's peers: while one is open the
/// peer table is empty, and `getpeerinfo`, `getconnectioncount`,
/// `getpeerbehavior` and the peer summary show nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crawl_connections_are_no_peers() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, CrawlConfig { timings: Timings { passive: Duration::from_secs(3), ..quick() }, ..config() });
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    let pm2 = Arc::clone(&pm);
    let session = tokio::spawn(async move { pm2.crawl_session(&target, SessionKind::Liveness).await });
    assert!(until(10, || log.lock().get(1).is_some_and(|c| c.iter().any(|m| m.cmd() == "verack"))).await);
    assert!(pm.peers.read().is_empty());
    assert!(pm.get_peer_info().is_empty());
    assert_eq!(pm.connection_count(), 0);
    assert!(pm.get_peer_behavior(None).unwrap().is_empty());
    assert_eq!(pm.peer_summary(), PeerSummary::default());
    assert_eq!(session.await.unwrap().result.v1, Attempt::Ok);
}

/// The crawl never writes the address book: a target in it keeps its
/// entry exactly, tried state, attempts, services and times, and the
/// addresses its answer names do not enter it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_crawl_writes_nothing_to_the_address_book() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let (target, _log) = scripted("127.0.0.1", Script { answer: Some(answer(5)), ..core_script() }).await;
    let PeerAddr::Socket(sa) = target.clone() else { unreachable!() };
    book_add(&pm, sa);
    let snapshot = |pm: &PeerManager| {
        let book = pm.addrman.read();
        let mut rows: Vec<String> = book.iter().map(|e| format!("{e:?}")).collect();
        rows.sort();
        rows
    };
    let before = snapshot(&pm);
    assert_eq!(before.len(), 1);
    pm.crawl_seed_round().await;
    assert!(run.book.lock().get(&CrawlAddr::Peer(target.clone())).is_some(), "seeded from the address book");
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None).await;
    assert_eq!(run.reached.load(Ordering::Relaxed), 1);
    assert_eq!(pm.crawl_book().unwrap().len(), 6, "the answer is in the crawl's book");
    assert_eq!(snapshot(&pm), before, "and nothing changed in the address book");
}

/// A Tor-only node crawls onions only: with clearnet addresses in the book
/// ahead of an onion, every dial is the onion's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_only_node_dials_no_clearnet() {
    let (pm, _dir, _shutdown) = mk_pm_live(Some("127.0.0.1:1"));
    pm.set_reachable(crate::net::reachable::ReachableNets { ipv4: false, ipv6: false, onion: true, ..Default::default() });
    let run = enable(&pm, config());
    let now = crate::time::now_secs();
    for i in 1..=20 {
        assert!(run.book.lock().seed(PeerAddr::Socket(SocketAddr::from(([127, i, 0, 1], 8333))), 0, now - 100));
    }
    let onion = PeerAddr::Onion { host: ONION.to_string(), port: 8333 };
    assert!(run.book.lock().seed(onion.clone(), 0, now));
    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    while sessions.join_next().await.is_some() {}
    assert_eq!(*run.dialled.lock(), vec![onion], "only the onion");
}

/// Clearnet is never crawled through the proxy, and `-crawlnet` only
/// narrows what the node reaches.
#[test]
fn clearnet_through_the_proxy_is_never_crawled_and_crawlnet_only_narrows() {
    use crate::net::crawlbook::Network as Net;
    let public = PeerAddr::Socket("23.1.2.3:8333".parse().unwrap());
    let local = PeerAddr::Socket("127.0.0.5:8333".parse().unwrap());
    let onion = PeerAddr::Onion { host: ONION.to_string(), port: 8333 };

    let (pm, _dir) = mk_pm_proxied("127.0.0.1:1");
    enable(&pm, config());
    assert!(!pm.crawl_may_dial(&public), "routable clearnet would go through the proxy");
    assert!(pm.crawl_may_dial(&local), "a local address is dialled directly");
    assert!(pm.crawl_may_dial(&onion));

    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, CrawlConfig { networks: Some(vec![Net::Onion, Net::Ipv6]), ..config() });
    assert!(!pm.crawl_may_dial(&public), "-crawlnet left IPv4 out");
    assert!(!pm.crawl_may_dial(&onion), "-crawlnet cannot add onion to a node without a proxy");
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    assert!(pm.crawl_may_dial(&public));
    pm.set_onion_disabled(true);
    assert!(!pm.crawl_may_dial(&onion));
    // A banned address is passed over.
    let _ = pm.ban_list.write().add(
        &crate::net::ban::BanTarget::Net(ipnet::IpNet::from("23.1.2.3".parse::<IpAddr>().unwrap())),
        crate::time::now_secs(),
        crate::time::now_secs() + 3_600,
    );
    assert!(!pm.crawl_may_dial(&public));
}

// ---- The scheduler's limits, through the tick ----

/// Book `n` scripted silent peers, each on an address of `ip(i)`, and run
/// one tick: the sessions it started.
async fn tick_over(limits: Limits, ip: impl Fn(u8) -> String, n: u8) -> (Arc<PeerManager>, tempfile::TempDir, usize) {
    let (pm, dir, _shutdown) = mk_pm_live(None);
    let run = enable(&pm, CrawlConfig { limits, ..config() });
    let now = crate::time::now_secs();
    for i in 0..n {
        let (addr, _) = scripted(&ip(i), silent()).await;
        assert!(run.book.lock().seed(addr, 0, now));
    }
    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    let open = run.scheduler.lock().open().0;
    sessions.abort_all();
    (pm, dir, open)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_holds_the_clearnet_concurrency() {
    let (.., open) = tick_over(Limits::new(3, 8, 100), |i| loopback(i + 1, 0), 6).await;
    assert_eq!(open, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_holds_the_rate() {
    let (.., open) = tick_over(Limits::new(100, 8, 2), |i| loopback(i + 1, 0), 6).await;
    assert_eq!(open, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_holds_two_sessions_per_netgroup() {
    let (.., open) = tick_over(Limits::new(100, 8, 100), |i| format!("127.0.{}.1", i + 1), 6).await;
    assert_eq!(open, 2, "all in 127.0.0.0/16");
}

/// One session per target: a second tick while the first session is open
/// dials nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_session_per_target() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(&pm, config());
    let (target, log) = scripted("127.0.0.1", silent()).await;
    assert!(run.book.lock().seed(target.clone(), 0, crate::time::now_secs()));
    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    assert!(until(5, || log.lock().len() == 1).await);
    for _ in 0..3 {
        pm.crawl_tick(&mut sessions);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(log.lock().len(), 1, "one connection");
    assert_eq!(*run.dialled.lock(), vec![target]);
    assert_eq!(run.scheduler.lock().open(), (1, 0));
    sessions.abort_all();
}

/// No session starts during initial block download.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_session_in_initial_block_download() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(&pm, config());
    run.out_of_ibd.store(false, Ordering::Relaxed);
    assert!(pm.chain_state.is_initial_block_download(), "fixture: a genesis chain is in IBD");
    let (target, log) = scripted("127.0.0.1", silent()).await;
    assert!(run.book.lock().seed(target, 0, crate::time::now_secs()));
    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    assert!(sessions.is_empty());
    assert!(!pm.crawl_may_run());
    run.out_of_ibd.store(true, Ordering::Relaxed);
    assert!(pm.crawl_may_run());
    pm.crawl_tick(&mut sessions);
    assert!(until(5, || log.lock().len() == 1).await);
    sessions.abort_all();
}

// ---- The survey, failure, restart ----

/// With the crawl on, the survey opens no connection, and `getpeersurvey`
/// says it is superseded while still reporting its store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_survey_is_superseded_by_the_crawl() {
    let (pm, _dir) = mk_pm_with(None);
    pm.enable_survey(SurveyConfig { interval: Duration::from_secs(60), probes: false, path: None });
    book_add(&pm, SocketAddr::from(([5, 5, 5, 5], 8333)));
    assert_eq!(pm.get_peer_survey(false)["superseded_by_crawl"], false);
    enable(&pm, config());
    assert!(pm.survey_superseded());
    assert_eq!(pm.survey_tick(), None);
    pm.spawn_survey();
    assert!(pm.pending_connections.read().is_empty());
    let json = pm.get_peer_survey(false);
    assert_eq!(json["superseded_by_crawl"], true);
    assert_eq!(json["enabled"], false);
    assert_eq!(json["addresses"], 0);
    // With the survey off too.
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    assert_eq!(pm.get_peer_survey(false)["superseded_by_crawl"], true);
}

/// A panic in a crawl session stops the crawl, and only the crawl.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panic_stops_the_crawl_and_the_node_runs_on() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(&pm, config());
    let (target, _log) = scripted("127.0.0.1", core_script()).await;
    assert!(run.book.lock().seed(target, 0, crate::time::now_secs()));
    run.panic_in_session.store(true, Ordering::Relaxed);
    pm.spawn_crawl();
    assert!(until(10, || run.stopped.load(Ordering::Relaxed)).await, "the crawl stopped");
    assert!(!pm.crawl_may_run());
    // The node's own surfaces still answer.
    assert!(pm.get_peer_info().is_empty());
    assert_eq!(pm.get_peer_survey(false)["superseded_by_crawl"], true);
}

/// The book and its timers survive a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_book_and_its_timers_survive_a_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join(crate::net::crawlbook::CRAWL_FILE);
    let (pm, _d) = mk_pm_with(None);
    let run = enable(&pm, CrawlConfig { path: Some(path.clone()), ..config() });
    let (reached, _) = scripted("127.0.0.1", core_script()).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let down = PeerAddr::Socket(closed);
    let now = crate::time::now_secs();
    for a in [&reached, &down] {
        assert!(run.book.lock().seed(a.clone(), 0, now));
        pm.run_crawl_session(a.clone(), SessionKind::Discovery, None).await;
    }
    pm.dump_crawl();
    let before = pm.crawl_book().unwrap();
    assert!(before.get(&CrawlAddr::Peer(reached.clone())).unwrap().last_success.is_some());
    assert!(before.get(&CrawlAddr::Peer(down.clone())).unwrap().retry_at.is_some());

    let (pm2, _d2) = mk_pm_with(None);
    enable(&pm2, CrawlConfig { path: Some(path), ..config() });
    let after = pm2.crawl_book().unwrap();
    assert_eq!(after.len(), before.len());
    for a in [reached, down] {
        let key = CrawlAddr::Peer(a);
        assert_eq!(after.get(&key), before.get(&key));
    }
    let due = |b: &crate::net::crawlbook::CrawlBook| b.next_due(now + 3 * 3600, 10);
    assert_eq!(due(&after), due(&before), "the same sessions fall due");
}

/// A session's own handshake nonce marks an inbound connection as the
/// crawl reaching this node, only while that handshake runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crawl_nonce_is_known_during_its_handshake_only() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = PeerAddr::Socket(listener.local_addr().unwrap());
    let pm2 = Arc::clone(&pm);
    let session = tokio::spawn(async move { pm2.crawl_session(&target, SessionKind::V1Recheck).await });
    let (stream, _) = listener.accept().await.unwrap();
    let mut conn = Connection::with_magic(stream, Magic::REGTEST);
    let NetworkMessage::Version(v) = conn.recv().await.unwrap() else { panic!("a version first") };
    assert!(pm.is_crawl_nonce(v.nonce));
    drop(conn);
    let out = session.await.unwrap();
    assert_eq!(out.result.v1, Attempt::Failed);
    assert!(!pm.is_crawl_nonce(v.nonce));
    let _ = SessionResult::default();
}

/// A peer's `version` timestamp is its own to set: `i64::MIN` saturates the
/// clock offset instead of overflowing (a panic, which stops the crawl, in
/// a debug build; a wrapped offset written to the book in release).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_extreme_version_timestamp_does_not_overflow_the_clock_offset() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let script = Script { timestamp: Some(i64::MIN), ..core_script() };
    let (target, _log) = scripted("127.0.0.1", script).await;
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!(out.result.v1, Attempt::Ok);
    let obs = out.result.observation.expect("an observation");
    assert_eq!(obs.clock_offset_secs, Some(i64::MIN));
}

// ---- getcrawlinfo, getcrawlnodes, the metrics ----

/// With the crawl off, `getcrawlinfo` says so with every count zero,
/// `getcrawlnodes` is empty and the metrics have no crawl.
#[test]
fn getcrawlinfo_with_the_crawl_off() {
    let (pm, _dir) = mk_pm_with(None);
    let info = pm.get_crawl_info();
    assert_eq!(info["enabled"], false);
    assert_eq!(info["state"], "off");
    assert_eq!(info["held_by"], serde_json::json!([]));
    assert_eq!(info["book"]["entries"], 0);
    assert_eq!(info["reachable"]["total"], 0);
    assert_eq!(info["families"]["core"]["count"], 0);
    assert_eq!(pm.get_crawl_nodes(true), serde_json::json!([]));
    assert!(pm.crawl_metrics().is_none());
}

/// `getcrawlinfo` names every reason the crawl starts no session (initial
/// block download, `-connect`, networking off), says `running` with none,
/// and `stopped` after a panic; `crawl_may_run` agrees with it each time.
#[test]
fn getcrawlinfo_names_why_the_crawl_is_held() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let state = |pm: &PeerManager| {
        let info = pm.get_crawl_info();
        (info["state"].as_str().unwrap().to_string(), info["held_by"].clone())
    };
    assert_eq!(state(&pm), ("running".to_string(), serde_json::json!([])));
    assert!(pm.crawl_may_run() && pm.crawl_metrics().unwrap().running);

    run.out_of_ibd.store(false, Ordering::Relaxed);
    assert_eq!(state(&pm), ("held".to_string(), serde_json::json!(["initial_block_download"])));
    assert!(!pm.crawl_may_run());
    run.out_of_ibd.store(true, Ordering::Relaxed);

    pm.set_automatic_outbound(false);
    assert_eq!(state(&pm), ("held".to_string(), serde_json::json!(["connect"])));
    assert!(!pm.crawl_may_run());
    pm.set_network_active(false);
    assert_eq!(state(&pm), ("held".to_string(), serde_json::json!(["connect", "network_inactive"])));
    let m = pm.crawl_metrics().unwrap();
    assert!(!m.running && !m.stopped);
    pm.set_automatic_outbound(true);
    pm.set_network_active(true);
    assert!(pm.crawl_may_run());

    run.stopped.store(true, Ordering::Relaxed);
    let info = pm.get_crawl_info();
    assert_eq!((info["state"].clone(), info["stopped_by"].clone()), ("stopped".into(), "panic".into()));
    assert!(!pm.crawl_may_run());
    let m = pm.crawl_metrics().unwrap();
    assert!(!m.running && m.stopped);
}

/// `getcrawlinfo`'s limits are the scheduler's (after the ceilings and any
/// fd fitting), its networks what the crawl dials, and it says whether
/// `-peersurvey` was asked for and is superseded.
#[test]
fn getcrawlinfo_reports_the_limits_in_force() {
    let (pm, _dir) = mk_pm_with(None);
    pm.enable_survey(SurveyConfig { interval: Duration::from_secs(60), probes: false, path: None });
    let limits = Limits::new(1000, 3, 500);
    enable(&pm, CrawlConfig { limits, networks: Some(vec![crate::net::crawlbook::Network::Ipv4]), ..config() });
    let info = pm.get_crawl_info();
    let l = &info["limits"];
    assert_eq!((l["concurrency"].clone(), l["tor_concurrency"].clone(), l["rate"].clone()), (256.into(), 3.into(), 100.into()));
    assert_eq!(l["liveness"], crate::net::crawlbook::DEFAULT_LIVENESS_SECS);
    assert_eq!(l["networks"], serde_json::json!(["ipv4"]), "-crawlnet narrows");
    assert_eq!(l["bind"], false);
    assert_eq!(info["peersurvey_superseded"], true);
    assert_eq!(info["book"]["max_entries"], crate::net::crawlbook::MAX_ENTRIES);
}

/// After a discovery session to a scripted Core peer, `getcrawlinfo`
/// counts it reachable over IPv4 and v1 only, as core; the crawl's own
/// traffic is counted and the node's is not; nothing in the answer or the
/// metrics' counts names the peer. `getcrawlnodes` has its row, with the
/// observation only under `verbose`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn getcrawlinfo_and_getcrawlnodes_after_a_session() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let mut script = core_script();
    script.answer = Some(answer(3));
    let (target, _log) = scripted("127.0.0.1", script).await;
    assert!(run.book.lock().seed(target.clone(), 0, crate::time::now_secs()));
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None).await;

    let info = pm.get_crawl_info();
    assert_eq!(info["book"]["entries"], 4, "the peer and the three it named");
    assert_eq!(info["book"]["learned"]["ipv4"], 4);
    assert_eq!(info["reachable"], serde_json::json!({ "total": 1, "ipv4": 1, "ipv6": 0, "onion": 0 }));
    assert_eq!(info["transport"]["v1_only"]["count"], 1);
    assert_eq!(info["families"]["core"]["count"], 1);
    assert_eq!(info["sessions"]["reached"], 1);
    assert_eq!(info["sessions"]["unreached"], 0);
    assert_eq!(info["sessions"]["in_flight"], serde_json::json!({ "clearnet": 0, "tor": 0 }));
    assert!(info["totals"]["totalbytessent"].as_u64().unwrap() > 0);
    assert!(info["totals"]["totalbytesrecv"].as_u64().unwrap() > 0);
    assert_eq!(pm.net_totals().bytes_sent(), 0, "the crawl's traffic is not the node's");
    let text = info.to_string();
    assert!(!text.contains("127.0.0.1") && !text.contains("23.1.") && !text.contains("Satoshi"), "{text}");

    let m = pm.crawl_metrics().unwrap();
    assert_eq!((m.aggregate.reachable, m.reached), ([1, 0, 0], 1));

    let rows = pm.get_crawl_nodes(false);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["addr"], target.to_string(), "the reached address first");
    assert_eq!(rows[0]["family"], "core");
    assert!(rows[0].get("observation").is_none());
    let rows = pm.get_crawl_nodes(true);
    let obs = &rows[0]["observation"];
    assert_eq!(obs["subver"], "/Satoshi:32.1.0/");
    assert_eq!(obs["getaddr"]["entries"], 3);
}

/// The metrics and the status page reuse an aggregate for
/// [`crawl_conn::AGGREGATE_MAX_AGE`]; `getcrawlinfo` for
/// [`crawl_conn::INFO_AGGREGATE_MAX_AGE`], and a new one refreshes theirs.
#[test]
fn the_metrics_reuse_a_recent_aggregate() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    assert_eq!(pm.crawl_metrics().unwrap().aggregate.entries, 0);
    let now = crate::time::now_secs();
    assert!(run.book.lock().seed(PeerAddr::Socket(SocketAddr::from(([23, 1, 1, 7], 8333))), 0, now));
    assert_eq!(pm.crawl_metrics().unwrap().aggregate.entries, 0, "within the window: the aggregate taken before");
    assert_eq!(pm.get_crawl_info()["book"]["entries"], 0, "getcrawlinfo reuses one under a second old");
    // Age the kept aggregate past getcrawlinfo's window, not the metrics'.
    if let Some((at, _)) = run.aggregate.lock().as_mut() {
        *at -= crawl_conn::INFO_AGGREGATE_MAX_AGE;
    }
    assert_eq!(pm.get_crawl_info()["book"]["entries"], 1, "older: getcrawlinfo takes a new one");
    assert_eq!(pm.crawl_metrics().unwrap().aggregate.entries, 1, "and the metrics read it");
}

/// With `-proxy` set, only a routable address goes through the proxy, so
/// where the book admits local addresses (regtest) the crawl still dials
/// clearnet, and `getcrawlinfo` says so: the networks it reports are the
/// ones `crawl_may_dial` lets through.
#[test]
fn getcrawlinfo_networks_agree_with_what_the_crawl_dials_under_a_proxy() {
    let (pm, _dir) = mk_pm_proxied("127.0.0.1:9");
    enable(&pm, CrawlConfig { networks: Some(vec![crate::net::crawlbook::Network::Ipv4]), ..config() });
    let local = PeerAddr::Socket(SocketAddr::from(([127, 0, 0, 1], 18444)));
    assert!(pm.crawl_may_dial(&local), "a local address is dialled direct");
    assert_eq!(pm.get_crawl_info()["limits"]["networks"], serde_json::json!(["ipv4"]));
}
