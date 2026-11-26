//! The crawl's connections (`crawl_conn`) against a live `PeerManager` and
//! scripted peers on loopback. A regtest manager's book admits loopback
//! addresses; nothing here dials off the host.

use super::survey_tests::{ONION, book_add, mk_pm_live, mk_pm_proxied, mk_pm_proxies, mk_pm_with};
use super::*;
use crate::net::crawl::{CrawlConfig, Limits, Timings};
use crate::net::crawlbook::{Attempt, CrawlAddr, GetaddrResult, SessionKind, SessionResult};
use crate::net::survey::{Probe, ProbeOutcome, Verdict};
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
    CrawlConfig {
        dns_seeds: false,
        fixed_seeds: false,
        timings: quick(),
        ..CrawlConfig::default()
    }
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
    /// The answer to `getheaders`.
    headers: Vec<bitcoin::block::Header>,
    /// Answer `getdata` with `notfound` (as satd does); stay silent when
    /// false (as Core does on a connection that set relay off).
    notfound: bool,
    /// Close the connection on a `getdata`.
    hang_up_on_getdata: bool,
    /// The services of its `version`.
    services: ServiceFlags,
    /// Close the connection once `after_verack` is sent: with nothing
    /// after `verack`, as a Core node with full inbound slots evicts the
    /// connection.
    close_after_verack: bool,
    /// The connections (counted from 0) on which it closes on the dialler's
    /// `verack`, sending nothing after it, as a node with full inbound
    /// slots evicts a new connection.
    evict_on: Vec<usize>,
}

fn core_script() -> Script {
    Script {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![
            NetworkMessage::SendCmpct(bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact: false,
                version: 2,
            }),
            NetworkMessage::Ping(77),
            NetworkMessage::FeeFilter(1000),
        ],
        answer: None,
        ping_every: None,
        silent: false,
        garbage: false,
        v1_only: true,
        timestamp: None,
        headers: Vec::new(),
        notfound: true,
        hang_up_on_getdata: false,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        close_after_verack: false,
        evict_on: Vec::new(),
    }
}

/// Core with its inbound slots full: the handshake, then the close.
fn evicting_core() -> Script {
    Script {
        after_verack: vec![],
        close_after_verack: true,
        ..core_script()
    }
}

/// An impostor claiming Core 25.0: `version` and `verack`, nothing between
/// them, nothing after, the connection held open.
fn fake_core() -> Script {
    Script {
        user_agent: "/Satoshi:25.0.0/",
        negotiation: vec![],
        after_verack: vec![],
        ..core_script()
    }
}

fn silent() -> Script {
    Script {
        silent: true,
        ..core_script()
    }
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
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
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
                let services = script.services;
                let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                let _ = conn
                    .send(NetworkMessage::Version(VersionMessage {
                        version: 70016,
                        services,
                        timestamp: script
                            .timestamp
                            .unwrap_or(crate::time::now_secs() as i64 - 3),
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
                if script.evict_on.contains(&i) {
                    return;
                }
                for m in &script.after_verack {
                    let _ = conn.send(m.clone()).await;
                }
                if script.close_after_verack {
                    return;
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
                let _ = conn
                    .send(NetworkMessage::Headers(script.headers.clone()))
                    .await;
            }
            NetworkMessage::GetData(_) if script.hang_up_on_getdata => return,
            NetworkMessage::GetData(inv) if script.notfound => {
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

/// Put `target` in the book as an address advertised with `NODE_P2P_V2`.
fn seed_v2(pm: &PeerManager, target: &PeerAddr) {
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2;
    let run = pm.crawl.get().unwrap();
    assert!(
        run.book
            .lock()
            .seed(target.clone(), services.to_u64(), crate::time::now_secs())
    );
}

/// A listener that records the first four bytes of every connection and
/// hangs up: a v1 dial opens with the network magic, a v2 one with the
/// first bytes of its ElligatorSwift key.
async fn first_bytes() -> (PeerAddr, Arc<parking_lot::Mutex<Vec<[u8; 4]>>>) {
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let firsts: Arc<parking_lot::Mutex<Vec<[u8; 4]>>> = Default::default();
    let seen = firsts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut first = [0u8; 4];
            if stream.read_exact(&mut first).await.is_ok() {
                seen.lock().push(first);
            }
        }
    });
    (PeerAddr::Socket(addr), firsts)
}

// ---- Our version ----

/// A crawl session's `version` declares a crawler: protocol 70016,
/// services 0, relay off, our tip, the dummy `addr_from` with no services,
/// `/satd:<version>(crawler)/` with `-crawluacomment`, and a fresh random
/// nonce, never the node's own.
#[test]
fn crawl_version_fields_are_exact() {
    let (pm, _dir) = mk_pm_with(None);
    pm.enable_crawl(CrawlConfig {
        ua_comment: Some("census".into()),
        ..config()
    })
    .unwrap();
    let to: SocketAddr = "203.0.113.5:8333".parse().unwrap();
    let v = pm.build_version_message(to, ConnType::Crawl);
    assert_eq!(v.version, 70016);
    assert_eq!(v.services, ServiceFlags::NONE);
    assert!(!v.relay);
    assert_eq!(v.start_height, pm.chain_state.tip_height() as i32);
    assert_eq!(
        v.user_agent,
        format!("/satd:{}(crawler; census)/", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(v.receiver, Address::new(&to, ServiceFlags::NONE));
    assert_eq!(
        v.sender,
        Address::new(&"0.0.0.0:0".parse().unwrap(), ServiceFlags::NONE)
    );
    let now = crate::time::now_secs() as i64;
    assert!((v.timestamp - now).abs() <= 2);
    // The node's own -uacomment is not in it.
    assert!(
        !v.user_agent.contains(crate::user_agent().trim_matches('/'))
            || crate::user_agent() == crate::USER_AGENT
    );
    let nonces: HashSet<u64> = (0..64)
        .map(|_| pm.build_version_message(to, ConnType::Crawl).nonce)
        .collect();
    assert_eq!(nonces.len(), 64, "a fresh nonce every time");
    let node = pm.build_version_message(to, ConnType::OutboundFullRelay);
    assert_ne!(node.user_agent, v.user_agent);
    assert!(
        node.services != ServiceFlags::NONE && node.relay,
        "the node's own version is unchanged"
    );
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
    seed_v2(&pm, &target);
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!(
        (out.result.v2, out.result.v1),
        (Attempt::Failed, Attempt::Ok),
        "v1-only: v2, then the v1 redial"
    );
    let conns = log.lock().clone();
    assert_eq!(conns.len(), 2, "the v2 attempt and the v1 redial");
    assert!(
        conns[0].is_empty(),
        "the v2 attempt got no v1 message through"
    );
    let got = &conns[1];
    let cmds: Vec<&str> = got.iter().map(|m| m.cmd()).collect();
    assert_eq!(
        &cmds[..4],
        ["version", "wtxidrelay", "sendaddrv2", "verack"],
        "{cmds:?}"
    );
    assert!(
        cmds[4..].iter().all(|c| *c == "pong"),
        "nothing but pongs after the handshake: {cmds:?}"
    );
    assert!(cmds.len() > 4, "the pings were answered: {cmds:?}");
    let obs = out.result.observation.expect("an observation");
    assert_eq!(obs.getaddr, None, "a liveness session sends no getaddr");
    assert!(!obs.v2);
    assert_eq!(obs.user_agent, "/Satoshi:32.1.0/");
    assert_eq!(obs.height, 0);
    assert!(
        obs.clock_offset_secs.is_some_and(|o| (-6..=0).contains(&o)),
        "{obs:?}"
    );
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
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;
    assert_eq!(log.lock().len(), 1, "a seed advertises nothing: v1 alone");
    let got = log.lock()[0].clone();
    assert_eq!(
        got.iter()
            .filter(|m| matches!(m, NetworkMessage::GetAddr))
            .count(),
        1
    );
    assert!(
        !got.iter()
            .any(|m| matches!(m, NetworkMessage::Addr(_) | NetworkMessage::AddrV2(_))),
        "no address to the peer"
    );
    for probe in ["ping", "getdata"] {
        assert!(
            got.iter().any(|m| m.cmd() == probe),
            "{probe} sent: {got:?}"
        );
    }
    // At genesis no stop hash lies past a locator: no getheaders probe.
    assert!(!got.iter().any(|m| m.cmd() == "getheaders"), "{got:?}");
    let book = pm.crawl_book().unwrap();
    let e = book.get(&CrawlAddr::Peer(target)).unwrap();
    assert_eq!(e.v1_ok, Some(true));
    assert_eq!(e.v2_ok, None, "v2 never tried");
    assert!(e.last_discovery.is_some());
    let obs = e.observation.as_ref().unwrap();
    assert_eq!(
        obs.getaddr
            .map(|g| matches!(g, GetaddrResult::Answered { entries: 3, .. })),
        Some(true),
        "{obs:?}"
    );
    assert!(matches!(
        obs.probes.get(Probe::Ping),
        Some(ProbeOutcome::Answered(_))
    ));
    assert_eq!(
        obs.probes.get(Probe::GetData),
        Some(ProbeOutcome::Answered(1))
    );
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
    let (target, log) = scripted(
        "127.0.0.1",
        Script {
            garbage: true,
            ..core_script()
        },
    )
    .await;
    seed_v2(&pm, &target);
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!(
        (out.result.v2, out.result.v1),
        (Attempt::Failed, Attempt::NotTried)
    );
    assert_eq!(log.lock().len(), 1, "no v1 redial");
    // A v1 recheck dials v1 alone, to a node advertising v2 too.
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    seed_v2(&pm, &target);
    let out = pm.crawl_session(&target, SessionKind::V1Recheck).await;
    assert_eq!(
        (out.result.v2, out.result.v1),
        (Attempt::NotTried, Attempt::Ok)
    );
    assert_eq!(log.lock().len(), 1);
}

/// A target not known to advertise `NODE_P2P_V2` (a seed, or an address
/// advertised without it) is dialled over v1 with no v2 bytes: the
/// connection opens with the network magic, and there is one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_not_advertising_v2_is_dialled_v1_with_no_v2_bytes() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let now = crate::time::now_secs();
    let (seed, firsts) = first_bytes().await;
    assert!(run.book.lock().seed(seed.clone(), 0, now));
    let (named, named_firsts) = first_bytes().await;
    let without = (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64();
    assert!(run.book.lock().seed(named.clone(), without, now));
    for (target, firsts) in [(&seed, &firsts), (&named, &named_firsts)] {
        let out = pm.crawl_session(target, SessionKind::Discovery).await;
        assert_eq!(
            (out.result.v2, out.result.v1),
            (Attempt::NotTried, Attempt::Failed)
        );
        assert_eq!(
            *firsts.lock(),
            vec![Magic::REGTEST.to_bytes()],
            "one v1 dial, no v2 bytes"
        );
    }
    // A target not in the book at all is dialled the same way.
    let (stray, firsts) = first_bytes().await;
    let out = pm.crawl_session(&stray, SessionKind::Liveness).await;
    assert_eq!(out.result.v2, Attempt::NotTried);
    assert_eq!(*firsts.lock(), vec![Magic::REGTEST.to_bytes()]);
}

/// A target advertised with `NODE_P2P_V2` is dialled over BIP 324 first,
/// and redialled over v1 when the v2 attempt got nothing back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_advertising_v2_is_dialled_v2_first() {
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let (target, firsts) = first_bytes().await;
    seed_v2(&pm, &target);
    let out = pm.crawl_session(&target, SessionKind::Discovery).await;
    assert_eq!(
        (out.result.v2, out.result.v1),
        (Attempt::Failed, Attempt::Failed)
    );
    let firsts = firsts.lock().clone();
    assert_eq!(
        firsts.len(),
        2,
        "the v2 attempt and the v1 redial: {firsts:?}"
    );
    assert_ne!(firsts[0], Magic::REGTEST.to_bytes(), "v2 first");
    assert_eq!(firsts[1], Magic::REGTEST.to_bytes(), "then v1");
}

/// Once a handshake has completed, the node's own `version` services
/// decide, not what its address was advertised with: a node advertised
/// without v2 whose `version` carries it is dialled v2 first next time, and
/// one advertised with v2 whose `version` does not is dialled v1 alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_a_handshake_the_nodes_version_services_decide() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let with_v2 = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2;
    let (says_v2, log) = scripted(
        "127.0.0.1",
        Script {
            services: with_v2,
            ..core_script()
        },
    )
    .await;
    assert!(
        run.book
            .lock()
            .seed(says_v2.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(says_v2.clone(), SessionKind::Liveness, None)
        .await;
    assert_eq!(log.lock().len(), 1, "advertised nothing: v1 alone");
    pm.run_crawl_session(says_v2.clone(), SessionKind::Liveness, None)
        .await;
    let conns = log.lock().clone();
    assert_eq!(
        conns.len(),
        3,
        "its version said v2: the v2 attempt, then the v1 redial"
    );
    assert!(
        conns[1].is_empty(),
        "the v2 attempt got no v1 message through"
    );
    let book = pm.crawl_book().unwrap();
    let e = book.get(&CrawlAddr::Peer(says_v2)).unwrap();
    assert_eq!((e.v2_ok, e.v1_ok), (Some(false), Some(true)));
    drop(book);

    let (says_v1, log) = scripted("127.0.0.1", core_script()).await;
    seed_v2(&pm, &says_v1);
    pm.run_crawl_session(says_v1.clone(), SessionKind::Liveness, None)
        .await;
    assert_eq!(
        log.lock().len(),
        2,
        "advertised v2: the v2 attempt and the v1 redial"
    );
    pm.run_crawl_session(says_v1.clone(), SessionKind::Liveness, None)
        .await;
    assert_eq!(log.lock().len(), 3, "its version said no v2: v1 alone");
    assert!(!log.lock()[2].is_empty());
}

/// A discovery session whose `getaddr` is never answered ends at its bound,
/// though the peer keeps pinging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_session_ends_by_its_bound() {
    let (pm, _dir) = mk_pm_with(None);
    enable(
        &pm,
        CrawlConfig {
            probes: false,
            ..config()
        },
    );
    let script = Script {
        ping_every: Some(Duration::from_millis(100)),
        ..core_script()
    };
    let (target, _log) = scripted("127.0.0.1", script).await;
    let started = Instant::now();
    let out = tokio::time::timeout(
        Duration::from_secs(20),
        pm.crawl_session(&target, SessionKind::Discovery),
    )
    .await
    .expect("the session ended");
    let t = quick();
    assert!(
        started.elapsed() <= t.session_cap(SessionKind::Discovery, false),
        "{:?}",
        started.elapsed()
    );
    assert!(started.elapsed() >= t.discovery, "it waited for the answer");
    assert_eq!(
        out.result.observation.unwrap().getaddr,
        Some(GetaddrResult::NoAnswer)
    );
}

// ---- Isolation ----

/// A crawl connection is none of the node's peers: while one is open the
/// peer table is empty, and `getpeerinfo`, `getconnectioncount`,
/// `getpeerbehavior` and the peer summary show nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crawl_connections_are_no_peers() {
    let (pm, _dir) = mk_pm_with(None);
    enable(
        &pm,
        CrawlConfig {
            timings: Timings {
                passive: Duration::from_secs(3),
                ..quick()
            },
            ..config()
        },
    );
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    let pm2 = Arc::clone(&pm);
    let session =
        tokio::spawn(async move { pm2.crawl_session(&target, SessionKind::Liveness).await });
    assert!(
        until(10, || log
            .lock()
            .first()
            .is_some_and(|c| c.iter().any(|m| m.cmd() == "verack")))
        .await
    );
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
    let (target, _log) = scripted(
        "127.0.0.1",
        Script {
            answer: Some(answer(5)),
            ..core_script()
        },
    )
    .await;
    let PeerAddr::Socket(sa) = target.clone() else {
        unreachable!()
    };
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
    assert!(
        run.book
            .lock()
            .get(&CrawlAddr::Peer(target.clone()))
            .is_some(),
        "seeded from the address book"
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;
    assert_eq!(run.reached.load(Ordering::Relaxed), 1);
    assert_eq!(
        pm.crawl_book().unwrap().len(),
        6,
        "the answer is in the crawl's book"
    );
    assert_eq!(
        snapshot(&pm),
        before,
        "and nothing changed in the address book"
    );
}

/// A Tor-only node crawls onions only: with clearnet addresses in the book
/// ahead of an onion, every dial is the onion's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_only_node_dials_no_clearnet() {
    let (pm, _dir, _shutdown) = mk_pm_live(Some("127.0.0.1:1"));
    pm.set_reachable(crate::net::reachable::ReachableNets {
        ipv4: false,
        ipv6: false,
        onion: true,
        ..Default::default()
    });
    let run = enable(&pm, config());
    let now = crate::time::now_secs();
    for i in 1..=20 {
        assert!(run.book.lock().seed(
            PeerAddr::Socket(SocketAddr::from(([127, i, 0, 1], 8333))),
            0,
            now - 100
        ));
    }
    let onion = PeerAddr::Onion {
        host: ONION.to_string(),
        port: 8333,
    };
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
    let onion = PeerAddr::Onion {
        host: ONION.to_string(),
        port: 8333,
    };

    let (pm, _dir) = mk_pm_proxied("127.0.0.1:1");
    enable(&pm, config());
    assert!(
        !pm.crawl_may_dial(&public),
        "routable clearnet would go through the proxy"
    );
    assert!(
        pm.crawl_may_dial(&local),
        "a local address is dialled directly"
    );
    assert!(pm.crawl_may_dial(&onion));

    let (pm, _dir) = mk_pm_with(None);
    enable(
        &pm,
        CrawlConfig {
            networks: Some(vec![Net::Onion, Net::Ipv6]),
            ..config()
        },
    );
    assert!(!pm.crawl_may_dial(&public), "-crawlnet left IPv4 out");
    assert!(
        !pm.crawl_may_dial(&onion),
        "-crawlnet cannot add onion to a node without a proxy"
    );
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
async fn tick_over(
    limits: Limits,
    ip: impl Fn(u8) -> String,
    n: u8,
) -> (Arc<PeerManager>, tempfile::TempDir, usize) {
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
    let (.., open) = tick_over(
        Limits::new(100, 8, 100),
        |i| format!("127.0.{}.1", i + 1),
        6,
    )
    .await;
    assert_eq!(open, 2, "all in 127.0.0.0/16");
}

/// One session per target: a second tick while the first session is open
/// dials nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_session_per_target() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(&pm, config());
    let (target, log) = scripted("127.0.0.1", silent()).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
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
    assert!(
        pm.chain_state.is_initial_block_download(),
        "fixture: a genesis chain is in IBD"
    );
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
    pm.enable_survey(SurveyConfig {
        interval: Duration::from_secs(60),
        probes: false,
        path: None,
    });
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
    assert!(
        until(10, || run.stopped.load(Ordering::Relaxed)).await,
        "the crawl stopped"
    );
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
    let run = enable(
        &pm,
        CrawlConfig {
            path: Some(path.clone()),
            ..config()
        },
    );
    let (reached, _) = scripted("127.0.0.1", core_script()).await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let down = PeerAddr::Socket(closed);
    let now = crate::time::now_secs();
    for a in [&reached, &down] {
        assert!(run.book.lock().seed(a.clone(), 0, now));
        pm.run_crawl_session(a.clone(), SessionKind::Discovery, None)
            .await;
    }
    pm.dump_crawl();
    let before = pm.crawl_book().unwrap();
    assert!(
        before
            .get(&CrawlAddr::Peer(reached.clone()))
            .unwrap()
            .last_success
            .is_some()
    );
    assert!(
        before
            .get(&CrawlAddr::Peer(down.clone()))
            .unwrap()
            .retry_at
            .is_some()
    );

    let (pm2, _d2) = mk_pm_with(None);
    enable(
        &pm2,
        CrawlConfig {
            path: Some(path),
            ..config()
        },
    );
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
    let session =
        tokio::spawn(async move { pm2.crawl_session(&target, SessionKind::V1Recheck).await });
    let (stream, _) = listener.accept().await.unwrap();
    let mut conn = Connection::with_magic(stream, Magic::REGTEST);
    let NetworkMessage::Version(v) = conn.recv().await.unwrap() else {
        panic!("a version first")
    };
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
    let script = Script {
        timestamp: Some(i64::MIN),
        ..core_script()
    };
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
        (
            info["state"].as_str().unwrap().to_string(),
            info["held_by"].clone(),
        )
    };
    assert_eq!(state(&pm), ("running".to_string(), serde_json::json!([])));
    assert!(pm.crawl_may_run() && pm.crawl_metrics().unwrap().running);

    run.out_of_ibd.store(false, Ordering::Relaxed);
    assert_eq!(
        state(&pm),
        (
            "held".to_string(),
            serde_json::json!(["initial_block_download"])
        )
    );
    assert!(!pm.crawl_may_run());
    run.out_of_ibd.store(true, Ordering::Relaxed);

    pm.set_automatic_outbound(false);
    assert_eq!(
        state(&pm),
        ("held".to_string(), serde_json::json!(["connect"]))
    );
    assert!(!pm.crawl_may_run());
    pm.set_network_active(false);
    assert_eq!(
        state(&pm),
        (
            "held".to_string(),
            serde_json::json!(["connect", "network_inactive"])
        )
    );
    let m = pm.crawl_metrics().unwrap();
    assert!(!m.running && !m.stopped);
    pm.set_automatic_outbound(true);
    pm.set_network_active(true);
    assert!(pm.crawl_may_run());

    run.stopped.store(true, Ordering::Relaxed);
    let info = pm.get_crawl_info();
    assert_eq!(
        (info["state"].clone(), info["stopped_by"].clone()),
        ("stopped".into(), "panic".into())
    );
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
    pm.enable_survey(SurveyConfig {
        interval: Duration::from_secs(60),
        probes: false,
        path: None,
    });
    let limits = Limits::new(1000, 3, 500);
    enable(
        &pm,
        CrawlConfig {
            limits,
            networks: Some(vec![crate::net::crawlbook::Network::Ipv4]),
            ..config()
        },
    );
    let info = pm.get_crawl_info();
    let l = &info["limits"];
    assert_eq!(
        (
            l["concurrency"].clone(),
            l["tor_concurrency"].clone(),
            l["rate"].clone()
        ),
        (256.into(), 3.into(), 100.into())
    );
    assert_eq!(l["liveness"], crate::net::crawlbook::DEFAULT_LIVENESS_SECS);
    assert_eq!(
        l["networks"],
        serde_json::json!(["ipv4"]),
        "-crawlnet narrows"
    );
    assert_eq!(l["bind"], false);
    assert_eq!(info["peersurvey_superseded"], true);
    assert_eq!(
        info["book"]["max_entries"],
        crate::net::crawlbook::MAX_ENTRIES
    );
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
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;

    let info = pm.get_crawl_info();
    assert_eq!(
        info["book"]["entries"], 4,
        "the peer and the three it named"
    );
    assert_eq!(info["book"]["learned"]["ipv4"], 4);
    assert_eq!(
        info["reachable"],
        serde_json::json!({ "total": 1, "ipv4": 1, "ipv6": 0, "onion": 0 })
    );
    assert_eq!(
        info["transport"]["v1_v2_untried"]["count"], 1,
        "a seed advertises no v2"
    );
    assert_eq!(info["transport"]["v1_only"]["count"], 0);
    assert_eq!(info["families"]["core"]["count"], 1);
    assert_eq!(info["sessions"]["reached"], 1);
    assert_eq!(info["sessions"]["unreached"], 0);
    assert_eq!(
        info["sessions"]["in_flight"],
        serde_json::json!({ "clearnet": 0, "tor": 0 })
    );
    assert!(info["totals"]["totalbytessent"].as_u64().unwrap() > 0);
    assert!(info["totals"]["totalbytesrecv"].as_u64().unwrap() > 0);
    assert_eq!(
        pm.net_totals().bytes_sent(),
        0,
        "the crawl's traffic is not the node's"
    );
    let text = info.to_string();
    assert!(
        !text.contains("127.0.0.1") && !text.contains("23.1.") && !text.contains("Satoshi"),
        "{text}"
    );

    let m = pm.crawl_metrics().unwrap();
    assert_eq!((m.aggregate.reachable, m.reached), ([1, 0, 0], 1));

    let rows = pm.get_crawl_nodes(false);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows[0]["addr"],
        target.to_string(),
        "the reached address first"
    );
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
    assert!(run.book.lock().seed(
        PeerAddr::Socket(SocketAddr::from(([23, 1, 1, 7], 8333))),
        0,
        now
    ));
    assert_eq!(
        pm.crawl_metrics().unwrap().aggregate.entries,
        0,
        "within the window: the aggregate taken before"
    );
    assert_eq!(
        pm.get_crawl_info()["book"]["entries"],
        0,
        "getcrawlinfo reuses one under a second old"
    );
    // Age the kept aggregate past getcrawlinfo's window, not the metrics'.
    if let Some((at, _)) = run.aggregate.lock().as_mut() {
        *at -= crawl_conn::INFO_AGGREGATE_MAX_AGE;
    }
    assert_eq!(
        pm.get_crawl_info()["book"]["entries"],
        1,
        "older: getcrawlinfo takes a new one"
    );
    assert_eq!(
        pm.crawl_metrics().unwrap().aggregate.entries,
        1,
        "and the metrics read it"
    );
}

/// With `-proxy` set, only a routable address goes through the proxy, so
/// where the book admits local addresses (regtest) the crawl still dials
/// clearnet, and `getcrawlinfo` says so: the networks it reports are the
/// ones `crawl_may_dial` lets through.
#[test]
fn getcrawlinfo_networks_agree_with_what_the_crawl_dials_under_a_proxy() {
    let (pm, _dir) = mk_pm_proxied("127.0.0.1:9");
    enable(
        &pm,
        CrawlConfig {
            networks: Some(vec![crate::net::crawlbook::Network::Ipv4]),
            ..config()
        },
    );
    let local = PeerAddr::Socket(SocketAddr::from(([127, 0, 0, 1], 18444)));
    assert!(
        pm.crawl_may_dial(&local),
        "a local address is dialled direct"
    );
    assert_eq!(
        pm.get_crawl_info()["limits"]["networks"],
        serde_json::json!(["ipv4"])
    );
}

/// With the crawl off, `getcrawlinfo` has every key it has with the crawl
/// on, counts zero: a client reads one schema.
#[test]
fn getcrawlinfo_off_has_the_same_keys() {
    fn keys(v: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        if let Some(o) = v.as_object() {
            for (k, v) in o {
                let path = format!("{prefix}{k}");
                out.push(path.clone());
                keys(v, &format!("{path}."), out);
            }
        }
    }
    let (off, _d1) = mk_pm_with(None);
    let (on, _d2) = mk_pm_with(None);
    enable(&on, config());
    let (mut a, mut b) = (Vec::new(), Vec::new());
    keys(&off.get_crawl_info(), "", &mut a);
    keys(&on.get_crawl_info(), "", &mut b);
    a.sort();
    b.sort();
    assert_eq!(a, b);
    let info = off.get_crawl_info();
    assert_eq!(info["sessions"]["reached"], 0);
    assert_eq!(info["totals"]["totalbytessent"], 0);
}

// ---- the hourly snapshots and dumpcrawlsnapshot ----

/// A config whose snapshots and export key are under `dir`.
fn with_files(dir: &std::path::Path) -> CrawlConfig {
    use crate::net::crawlsnapshot::{EXPORT_KEY_FILE, KeySource, SNAPSHOT_DIR};
    CrawlConfig {
        snapshot_dir: Some(dir.join(SNAPSHOT_DIR)),
        export_key: Some(KeySource::Default(dir.join(EXPORT_KEY_FILE))),
        ..config()
    }
}

/// With the crawl off, `dumpcrawlsnapshot` is an error and writes no key.
#[test]
fn dumpcrawlsnapshot_with_the_crawl_off() {
    let (pm, dir) = mk_pm_with(None);
    assert!(
        pm.dump_crawl_snapshot(false)
            .unwrap_err()
            .contains("crawl is off")
    );
    assert!(pm.dump_crawl_snapshot(true).is_err());
    assert!(
        !dir.path()
            .join(crate::net::crawlsnapshot::EXPORT_KEY_FILE)
            .exists()
    );
    assert!(!pm.crawl_snapshot_tick(crate::time::now_secs()));
}

/// After a session to a scripted peer: the keyed export lists it by node
/// ID under the key it created, with no address and no port; the raw one
/// by its address. The hourly tick writes one snapshot an hour, with the
/// peer's raw address in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dumpcrawlsnapshot_and_the_hourly_snapshot_after_a_session() {
    use crate::net::crawlsnapshot;
    let (pm, dir) = mk_pm_with(None);
    let run = enable(&pm, with_files(dir.path()));
    let (target, _log) = scripted("127.0.0.1", core_script()).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Liveness, None)
        .await;
    let PeerAddr::Socket(sa) = target else {
        unreachable!()
    };

    let keyed = pm.dump_crawl_snapshot(false).unwrap();
    assert_eq!(keyed["total_nodes"], 1, "{keyed}");
    let key =
        crawlsnapshot::read_key(&dir.path().join(crawlsnapshot::EXPORT_KEY_FILE)).expect("created");
    let node = &keyed["nodes"][crawlsnapshot::node_id(&key, &sa)];
    assert_eq!(node[1], "/Satoshi:32.1.0/", "{keyed}");
    assert_eq!(node[13]["port"], "other");
    let text = keyed.to_string();
    assert!(
        !text.contains("127.0.0.1") && !text.contains(&format!(":{}", sa.port())),
        "{text}"
    );
    assert_eq!(keyed["satd"]["chain"], "regtest");
    assert_eq!(
        pm.dump_crawl_snapshot(false).unwrap()["nodes"],
        keyed["nodes"],
        "the same key, the same IDs"
    );

    let raw = pm.dump_crawl_snapshot(true).unwrap();
    assert!(raw["nodes"].get(sa.to_string()).is_some(), "{raw}");

    let hour = crawl_hour();
    assert!(pm.crawl_snapshot_tick(hour + 5));
    assert!(!pm.crawl_snapshot_tick(hour + 1800), "one an hour");
    let snaps = dir.path().join(crawlsnapshot::SNAPSHOT_DIR);
    let files = crawlsnapshot::list_snapshots(&snaps).unwrap();
    assert_eq!(files, vec![hour + 5]);
    let gz = std::fs::read(snaps.join(crawlsnapshot::snapshot_file_name(hour + 5))).unwrap();
    let lines = String::from_utf8(crawlsnapshot::gunzip(&gz).unwrap()).unwrap();
    assert_eq!(lines.lines().count(), 1, "{lines}");
    assert!(
        lines.contains(&sa.to_string()),
        "the hourly snapshot holds the raw address"
    );
}

/// The start of the current UTC hour, a few minutes back so the session
/// above is within the liveness window of every time the test uses.
fn crawl_hour() -> u64 {
    let now = crate::time::now_secs();
    now - now % 3600
}

/// A `-crawlexportkeyfile` key is the one used, and never created when it
/// is missing: the keyed export is refused, the raw one is not.
#[test]
fn dumpcrawlsnapshot_honours_crawlexportkeyfile() {
    use crate::net::crawlsnapshot::{self, KeySource};
    let (pm, dir) = mk_pm_with(None);
    let path = dir.path().join("census.key");
    let run = enable(
        &pm,
        CrawlConfig {
            export_key: Some(KeySource::Supplied(path.clone())),
            ..config()
        },
    );
    let now = crate::time::now_secs();
    let peer = PeerAddr::Socket(SocketAddr::from(([127, 0, 0, 1], 18444)));
    assert!(run.book.lock().seed(peer.clone(), 0, now));
    let ok = crate::net::crawlbook::SessionResult {
        v2: Attempt::Failed,
        v1: Attempt::Ok,
        observation: None,
    };
    run.book
        .lock()
        .record_result(&peer, None, SessionKind::Liveness, ok, now);
    assert!(
        pm.dump_crawl_snapshot(false)
            .unwrap_err()
            .contains("census.key")
    );
    assert!(!path.exists(), "never created");
    assert!(
        !dir.path().join(crawlsnapshot::EXPORT_KEY_FILE).exists(),
        "nor the default"
    );
    assert!(pm.dump_crawl_snapshot(true).is_ok());
    std::fs::write(&path, [7u8; 32]).unwrap();
    let out = pm.dump_crawl_snapshot(false).unwrap();
    let PeerAddr::Socket(sa) = peer else {
        unreachable!()
    };
    let id = crawlsnapshot::node_id(&crawlsnapshot::ExportKey([7; 32]), &sa);
    assert_eq!(out["nodes"][&id][13]["port"], "default", "{out}");
}

// ---- The chain check and the crawl classifier ----

/// Mine `n` blocks on the manager's chain.
fn mine(pm: &PeerManager, n: u32) {
    let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
    crate::mining::miner::mine_blocks(
        &pm.chain_state,
        &pm.mempool,
        addr,
        n,
        crate::mining::miner::DEFAULT_MAX_TRIES,
    )
    .unwrap();
}

/// The header of our block at `height`.
fn our_header(pm: &PeerManager, height: u32) -> bitcoin::block::Header {
    let hash = pm.chain_state.active_chain_hash_at_height(height).unwrap();
    pm.chain_state.get_block_index(&hash).unwrap().header
}

/// A discovery session from `pm` to a scripted peer that answers
/// `getheaders` with `headers`: its chain check, and the `getheaders` the
/// peer received.
async fn chain_check_against(
    pm: &Arc<PeerManager>,
    headers: Vec<bitcoin::block::Header>,
) -> (
    Option<crate::net::crawlbook::ChainCheck>,
    Vec<NetworkMessage>,
) {
    let (target, log) = scripted(
        "127.0.0.1",
        Script {
            headers,
            answer: Some(answer(3)),
            ..core_script()
        },
    )
    .await;
    let out = pm.crawl_session(&target, SessionKind::Discovery).await;
    let obs = out.result.observation.expect("an observation");
    let sent = log
        .lock()
        .last()
        .unwrap()
        .iter()
        .filter(|m| m.cmd() == "getheaders")
        .cloned()
        .collect();
    (obs.chain_check, sent)
}

/// The chain check is the `getheaders` probe: one, with our tip's parent
/// as its locator and our tip as its stop hash. A peer that answers with
/// our tip is on chain; one with nothing past our locator, or our blocks
/// from its genesis, is behind; one with another block after our locator
/// is on a fork; one whose answer starts from a block we do not know is
/// on another chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chain_check_tells_the_four_outcomes_apart() {
    use crate::net::crawlbook::ChainCheck;
    let (pm, _dir) = mk_pm_with(None);
    mine(&pm, 3);
    let run = enable(&pm, config());
    *run.forced_probes.lock() = Some(vec![Probe::GetHeaders]);
    let (b1, b2, b3) = (our_header(&pm, 1), our_header(&pm, 2), our_header(&pm, 3));
    let mut sibling = b3;
    sibling.nonce ^= 1;
    let mut stranger = b1;
    stranger.prev_blockhash = bitcoin::BlockHash::from_byte_array([7; 32]);
    let cases = [
        (vec![b3], ChainCheck::OnChain),
        (vec![], ChainCheck::Behind),
        (vec![b1], ChainCheck::Behind),
        (vec![sibling], ChainCheck::Fork),
        (vec![stranger], ChainCheck::OtherChain),
    ];
    for (headers, want) in cases {
        let (got, sent) = chain_check_against(&pm, headers.clone()).await;
        assert_eq!(got, Some(want), "{headers:?}");
        assert_eq!(sent.len(), 1, "one getheaders: {sent:?}");
        let NetworkMessage::GetHeaders(g) = &sent[0] else {
            unreachable!()
        };
        assert_eq!(
            (g.locator_hashes.as_slice(), g.stop_hash),
            ([b2.block_hash()].as_slice(), b3.block_hash())
        );
    }
}

/// No chain check without probes (`-crawlprobes=0`) or on a liveness
/// session: no `getheaders` is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_chain_check_without_probes_or_on_a_liveness_session() {
    let (pm, _dir) = mk_pm_with(None);
    mine(&pm, 3);
    enable(
        &pm,
        CrawlConfig {
            probes: false,
            ..config()
        },
    );
    let tip = our_header(&pm, 3);
    let (target, log) = scripted(
        "127.0.0.1",
        Script {
            headers: vec![tip],
            answer: Some(answer(3)),
            ..core_script()
        },
    )
    .await;
    for kind in [SessionKind::Discovery, SessionKind::Liveness] {
        let out = pm.crawl_session(&target, kind).await;
        assert_eq!(
            out.result.observation.expect("an observation").chain_check,
            None,
            "{kind:?}"
        );
    }
    assert!(log.lock().iter().flatten().all(|m| m.cmd() != "getheaders"));
}

/// A crawl session is judged against the crawl rows: a peer that greets
/// the crawler as Core does is Core with high confidence; the same
/// transcript closing the connection on a probe is no capture's shape: its
/// user agent's family is only claimed, and its raw features are kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crawl_session_is_judged_on_its_crawl_features() {
    use crate::net::fingerprint::{AddrKind, Confidence, Family, Fingerprint};
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, config());
    let core = Script {
        notfound: false,
        answer: Some(answer(3)),
        ..core_script()
    };
    let (target, _log) = scripted("127.0.0.1", core.clone()).await;
    let obs = pm
        .crawl_session(&target, SessionKind::Discovery)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(obs.probes.get(Probe::GetData), Some(ProbeOutcome::Silent));
    assert_eq!(
        obs.fingerprint,
        Fingerprint::Known(Family::Core, Confidence::High)
    );
    assert_eq!(obs.shape, None, "a known shape keeps no raw features");

    // Answering with `notfound` is Core too (relay granted by its operator).
    let (target, _log) = scripted(
        "127.0.0.1",
        Script {
            notfound: true,
            ..core.clone()
        },
    )
    .await;
    let obs = pm
        .crawl_session(&target, SessionKind::Discovery)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(
        obs.fingerprint,
        Fingerprint::Known(Family::Core, Confidence::High)
    );

    // No row matches: the user agent's claim, never observed, and the
    // raw features are kept as for an unknown shape.
    let (target, _log) = scripted(
        "127.0.0.1",
        Script {
            hang_up_on_getdata: true,
            ..core
        },
    )
    .await;
    let obs = pm
        .crawl_session(&target, SessionKind::Discovery)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(
        obs.fingerprint,
        Fingerprint::Known(Family::Core, Confidence::Claimed)
    );
    assert_eq!(
        obs.verdict,
        Verdict::Classified,
        "it closed after its transcript settled: not closed early"
    );
    assert_eq!(obs.fingerprint.observed(), None);
    let shape = obs
        .shape
        .expect("a shape no row matched keeps its raw features");
    assert_eq!(
        shape.commands,
        [
            "version",
            "wtxidrelay",
            "sendaddrv2",
            "verack",
            "sendcmpct",
            "ping"
        ]
    );
    assert!(shape.relay);
    assert_eq!(shape.v2, None, "a v1 session");
    assert_eq!(shape.getaddr, Some(AddrKind::AddrV2));
}

/// A session that sends no probe is judged with the probe answers the
/// book keeps from the last one that did, so a liveness session does not
/// undo what a discovery session found.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_without_probes_is_judged_with_the_last_answers() {
    use crate::net::fingerprint::{Confidence, Family, Fingerprint};
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    // Core's transcript, closing the connection on a probe: no row, so
    // only the user agent's claim.
    // (An answer to `getaddr`, so the probes go out before the session's bound.)
    let script = Script {
        answer: Some(answer(3)),
        hang_up_on_getdata: true,
        ..core_script()
    };
    let (target, _log) = scripted("127.0.0.1", script).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;
    let fp = |pm: &PeerManager| {
        pm.crawl_book()
            .unwrap()
            .get(&CrawlAddr::Peer(target.clone()))
            .unwrap()
            .observation
            .clone()
            .unwrap()
            .fingerprint
    };
    let claimed = Fingerprint::Known(Family::Core, Confidence::Claimed);
    assert_eq!(fp(&pm), claimed);
    pm.run_crawl_session(target.clone(), SessionKind::Liveness, None)
        .await;
    assert_eq!(
        fp(&pm),
        claimed,
        "the liveness session is judged with the disconnect"
    );
}

/// A peer that closes the connection during the passive wait, before its
/// transcript settles (a Core node with full inbound slots evicting the
/// crawl's connection), is closed early: reached, over the transport it
/// was reached on, with what its `version` said, and no fingerprint, so
/// the transcript it cut short matches no row. A discovery session to it
/// sends no `getaddr`, as to any peer that closed. One that closes once
/// its transcript has settled is judged as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_closes_before_its_transcript_settles_is_closed_early() {
    use crate::net::fingerprint::Fingerprint;
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let (target, log) = scripted("127.0.0.1", evicting_core()).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;
    assert!(
        !log.lock()[0]
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetAddr)),
        "closed: no getaddr"
    );
    let book = pm.crawl_book().unwrap();
    let e = book.get(&CrawlAddr::Peer(target.clone())).unwrap();
    assert_eq!(
        (e.v1_ok, e.v2_ok, e.failures),
        (Some(true), None, 0),
        "reached over v1, v2 never tried"
    );
    assert!(e.last_success.is_some() && e.retry_at.is_none());
    let obs = e.observation.as_ref().unwrap();
    assert_eq!(obs.verdict, Verdict::ClosedEarly);
    assert_eq!(obs.fingerprint, Fingerprint::Unknown, "no fingerprint");
    assert_eq!(obs.user_agent, "/Satoshi:32.1.0/");
    assert_eq!(obs.protocol_version, 70016);
    assert_eq!(
        obs.services,
        (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64()
    );
    assert_eq!(obs.getaddr, None);
    assert_eq!(
        obs.shape.as_ref().map(|s| s.commands.clone()).unwrap(),
        ["version", "wtxidrelay", "sendaddrv2", "verack"]
    );
    assert_eq!(run.reached.load(Ordering::Relaxed), 1, "a reached session");
    let agg = crate::net::crawlreport::aggregate(&book, crate::time::now_secs());
    assert_eq!(
        (agg.reachable_total(), agg.closed_early, agg.unknown),
        (1, 1, 0)
    );
    assert_eq!(
        agg.claimed.iter().sum::<usize>(),
        0,
        "counted under no claim"
    );
    *run.aggregate.lock() = None;
    let info = pm.get_crawl_info();
    assert_eq!(
        info["closed_early"],
        serde_json::json!({ "count": 1, "share": 1.0 }),
        "{info}"
    );
    assert_eq!(info["families"]["unknown"]["count"], 0);

    // The same peer settling on a later session replaces the verdict.
    let (settled, _log) = scripted("127.0.0.1", core_script()).await;
    let obs = pm
        .crawl_session(&settled, SessionKind::Liveness)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(obs.verdict, Verdict::Classified);
    // Closing once its transcript has settled is no early close.
    let late = Script {
        close_after_verack: true,
        ..core_script()
    };
    let (target, _log) = scripted("127.0.0.1", late).await;
    let obs = pm
        .crawl_session(&target, SessionKind::Liveness)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(obs.verdict, Verdict::Classified, "{obs:?}");
}

/// A peer that claims Core, sends only `version` and `verack` and stays
/// connected and silent through the passive wait is fake, its family
/// claimed; one that sends Core's negotiation is not, nor one claiming
/// btcd with the same bare transcript.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_core_claimant_is_fake() {
    use crate::net::fingerprint::Family;
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let (target, _log) = scripted("127.0.0.1", fake_core()).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Liveness, None)
        .await;
    let book = pm.crawl_book().unwrap();
    let e = book.get(&CrawlAddr::Peer(target.clone())).unwrap();
    assert_eq!(e.v1_ok, Some(true), "reached");
    let obs = e.observation.as_ref().unwrap();
    assert_eq!(obs.verdict, Verdict::Fake(Family::Core), "{obs:?}");
    assert_eq!(obs.fingerprint_text(), "fake/core");
    assert_eq!(obs.observed_family(), None);
    let agg = crate::net::crawlreport::aggregate(&book, crate::time::now_secs());
    assert_eq!(agg.fake[0], 1, "core, fake");
    assert_eq!(
        (
            agg.unknown,
            agg.claimed.iter().sum::<usize>(),
            agg.families.iter().sum::<usize>()
        ),
        (0, 0, 0)
    );

    let (negotiated, _log) = scripted(
        "127.0.0.1",
        Script {
            after_verack: vec![],
            ..core_script()
        },
    )
    .await;
    let obs = pm
        .crawl_session(&negotiated, SessionKind::Liveness)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(
        obs.verdict,
        Verdict::Classified,
        "Core's negotiation: no fake"
    );
    let btcd = Script {
        user_agent: "/btcwire:0.5.0/btcd:0.27.0/",
        ..fake_core()
    };
    let (btcd, _log) = scripted("127.0.0.1", btcd).await;
    let obs = pm
        .crawl_session(&btcd, SessionKind::Liveness)
        .await
        .result
        .observation
        .unwrap();
    assert_eq!(obs.verdict, Verdict::Classified, "only Core has the rule");
}

// ---- Closed-early retries ----

/// A closed-early address is dialled again by the tick once its retry is
/// due, and not before: with a liveness window past the test, only the
/// retry makes it due. The retry's settled session clears the schedule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tick_dials_a_due_retry_and_a_settled_session_clears_it() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(
        &pm,
        CrawlConfig {
            liveness_secs: 30 * 24 * 60 * 60,
            ..config()
        },
    );
    let (target, log) = scripted(
        "127.0.0.1",
        Script {
            evict_on: vec![0],
            ..core_script()
        },
    )
    .await;
    let key = CrawlAddr::Peer(target.clone());
    // The first session, closed early, two hours ago: its retry is due.
    let then = crate::time::now_secs() - 2 * 60 * 60;
    assert!(run.book.lock().seed(target.clone(), 0, then));
    let out = pm.crawl_session(&target, SessionKind::Discovery).await;
    assert_eq!(
        out.result.observation.as_ref().unwrap().verdict,
        Verdict::ClosedEarly,
        "fixture"
    );
    assert!(
        run.book
            .lock()
            .record_result(&target, None, SessionKind::Discovery, out.result, then)
    );
    let r = pm
        .crawl_book()
        .unwrap()
        .get(&key)
        .unwrap()
        .closed_early_retry;
    assert_eq!(r.count, 1);
    assert!(r.due(crate::time::now_secs()));
    *run.aggregate.lock() = None;
    let info = pm.get_crawl_info();
    assert_eq!(
        info["retries"],
        serde_json::json!({ "pending": 1, "exhausted": 0 }),
        "{info}"
    );
    assert_eq!(pm.crawl_metrics().unwrap().aggregate.retries_pending, 1);
    let rows = pm.get_crawl_nodes(false);
    assert_eq!(
        rows[0]["retry"],
        serde_json::json!({ "count": 1, "next_due": r.next_due }),
        "{rows}"
    );

    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    while sessions.join_next().await.is_some() {}
    assert_eq!(log.lock().len(), 2, "the retry was dialled");
    let e = pm.crawl_book().unwrap().get(&key).cloned().unwrap();
    let obs = e.observation.as_ref().unwrap();
    assert_eq!(obs.verdict, Verdict::Classified, "{obs:?}");
    assert_eq!(e.closed_early_retry, Default::default(), "settled: cleared");
    assert!(pm.get_crawl_nodes(false)[0].get("retry").is_none());

    // Nothing is due now: another tick dials nothing.
    pm.crawl_tick(&mut sessions);
    while sessions.join_next().await.is_some() {}
    assert_eq!(log.lock().len(), 2);
}

/// A closed-early retry that is not due yet does not make the address due.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_not_yet_due_dials_nothing() {
    let (pm, _dir, _shutdown) = mk_pm_live(None);
    let run = enable(
        &pm,
        CrawlConfig {
            liveness_secs: 30 * 24 * 60 * 60,
            ..config()
        },
    );
    let (target, log) = scripted("127.0.0.1", evicting_core()).await;
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Discovery, None)
        .await;
    let r = pm
        .crawl_book()
        .unwrap()
        .get(&CrawlAddr::Peer(target.clone()))
        .unwrap()
        .closed_early_retry;
    assert_eq!(r.count, 1);
    assert!(!r.due(crate::time::now_secs()));
    let mut sessions = tokio::task::JoinSet::new();
    pm.crawl_tick(&mut sessions);
    while sessions.join_next().await.is_some() {}
    assert_eq!(log.lock().len(), 1, "not dialled again");
}

/// A settled address whose later session closes early keeps its
/// fingerprint: the observation is the settled one, the reachability and
/// timers are the later session's, and no retry is scheduled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settled_address_keeps_its_fingerprint_when_a_later_session_closes_early() {
    let (pm, _dir) = mk_pm_with(None);
    let run = enable(&pm, config());
    let (target, log) = scripted(
        "127.0.0.1",
        Script {
            evict_on: vec![1],
            ..core_script()
        },
    )
    .await;
    let key = CrawlAddr::Peer(target.clone());
    assert!(
        run.book
            .lock()
            .seed(target.clone(), 0, crate::time::now_secs())
    );
    pm.run_crawl_session(target.clone(), SessionKind::Liveness, None)
        .await;
    let first = pm.crawl_book().unwrap().get(&key).cloned().unwrap();
    let settled = first.observation.clone().unwrap();
    assert_eq!(settled.verdict, Verdict::Classified, "fixture: {settled:?}");
    pm.run_crawl_session(target.clone(), SessionKind::Liveness, None)
        .await;
    assert_eq!(log.lock().len(), 2);
    let e = pm.crawl_book().unwrap().get(&key).cloned().unwrap();
    assert_eq!(
        e.observation.as_ref(),
        Some(&settled),
        "the settled observation stands"
    );
    assert_eq!(e.reachable_count, 2, "the session counts as reached");
    assert!(e.last_success >= first.last_success);
    assert_eq!(e.closed_early_retry, Default::default(), "no retry");
    *run.aggregate.lock() = None;
    let info = pm.get_crawl_info();
    assert_eq!(info["closed_early"]["count"], 0, "{info}");
    assert_eq!(
        info["retries"],
        serde_json::json!({ "pending": 0, "exhausted": 0 })
    );
}

// ---- Per-country totals (-countryfile) ----

/// A manager whose crawl reached, under the test country file: two nodes
/// in `DE`, one in `JP`, one IP the file has no country for and an onion.
/// The export minimum is 2, so `JP` is `other`. Its snapshots and export
/// key are under the returned directory.
fn crawl_with_countries(map: bool) -> (Arc<PeerManager>, tempfile::TempDir, Vec<PeerAddr>) {
    let (pm, dir) = mk_pm_with(None);
    if map {
        let m = crate::net::country::CountryMap::from_bytes(crate::net::country::testing::mmdb(
            crate::net::country::testing::FIXTURE,
        ))
        .unwrap();
        pm.set_country_map(Arc::new(m));
    }
    let run = enable(
        &pm,
        CrawlConfig {
            export_min_k: 2,
            ..with_files(dir.path())
        },
    );
    let now = crate::time::now_secs();
    let peers = vec![
        PeerAddr::Socket(SocketAddr::from(([192, 0, 2, 1], 8333))),
        PeerAddr::Socket(SocketAddr::from(([192, 0, 2, 2], 8333))),
        PeerAddr::Socket(SocketAddr::from(([192, 0, 2, 130], 8333))),
        PeerAddr::Socket(SocketAddr::from(([203, 0, 113, 200], 8333))),
        PeerAddr::Onion {
            host: ONION.to_string(),
            port: 8333,
        },
    ];
    for peer in &peers {
        assert!(run.book.lock().seed(peer.clone(), 0, now), "{peer}");
        let ok = SessionResult {
            v2: Attempt::Failed,
            v1: Attempt::Ok,
            observation: None,
        };
        run.book
            .lock()
            .record_result(peer, None, SessionKind::Liveness, ok, now);
    }
    (pm, dir, peers)
}

/// With `-countryfile`, `getcrawlinfo` and the snapshot summary, keyed and
/// raw, give the reachable nodes per country under the one fold: `JP`,
/// below the minimum of 2, is `other`; the IP the file has no country for
/// is `unknown`; the onion is `onion`; every node is counted once.
#[test]
fn country_totals_in_getcrawlinfo_and_the_snapshot_summary() {
    let (pm, _dir, peers) = crawl_with_countries(true);
    let info = pm.get_crawl_info();
    let c = &info["countries"];
    assert_eq!(c["DE"]["count"], 2, "{c}");
    assert_eq!(c["other"]["count"], 1, "JP folded: {c}");
    assert!(c.get("JP").is_none(), "{c}");
    assert_eq!(c["unknown"]["count"], 1, "{c}");
    assert_eq!(c["onion"]["count"], 1, "{c}");
    assert_eq!(c["DE"]["share"], 0.4, "{c}");
    assert_eq!(c.as_object().unwrap().len(), 4, "{c}");
    let total: u64 = c
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, peers.len() as u64);
    let want = serde_json::json!({ "DE": 2, "other": 1, "unknown": 1, "onion": 1 });
    for raw in [false, true] {
        let snap = pm.dump_crawl_snapshot(raw).unwrap();
        assert_eq!(snap["satd"]["countries"], want, "raw={raw}: {snap}");
        assert_eq!(snap["satd"]["country_min_count"], 2);
    }
    let metrics = pm.crawl_metrics().unwrap();
    assert_eq!(
        metrics.aggregate.countries.as_ref().unwrap()["other"],
        1,
        "the metrics read the same fold"
    );
}

/// Without `-countryfile` the country totals are null, not an empty
/// object that would read as no nodes: in `getcrawlinfo` with the crawl on
/// and off, and in both exports.
#[test]
fn without_a_country_file_the_country_totals_are_null() {
    let (off, _d) = mk_pm_with(None);
    assert!(off.get_crawl_info()["countries"].is_null());
    let (pm, _dir, _peers) = crawl_with_countries(false);
    let info = pm.get_crawl_info();
    assert!(info["countries"].is_null(), "{info}");
    assert_eq!(info["reachable"]["total"], 5, "the nodes are there: {info}");
    for raw in [false, true] {
        let snap = pm.dump_crawl_snapshot(raw).unwrap();
        assert!(snap["satd"]["countries"].is_null(), "{snap}");
        assert!(snap["satd"].get("country_min_count").is_none(), "{snap}");
    }
    assert!(pm.crawl_metrics().unwrap().aggregate.countries.is_none());
}

/// No per-node row carries a country, with a country file that names one
/// for most nodes: not `getcrawlnodes` (verbose or not), not a node of
/// the keyed or the raw export (Bitnodes' country field, index 7, stays
/// null, and the `satd` object has none), not an hourly snapshot line.
#[test]
fn no_per_node_row_carries_a_country() {
    let (pm, dir, _peers) = crawl_with_countries(true);
    let check = |what: &str, row: &serde_json::Value| {
        let text = row.to_string();
        for needle in ["\"DE\"", "\"JP\"", "country", "countries"] {
            assert!(!text.contains(needle), "{what} has {needle}: {text}");
        }
    };
    for verbose in [false, true] {
        let rows = pm.get_crawl_nodes(verbose);
        assert_eq!(rows.as_array().unwrap().len(), 5);
        for row in rows.as_array().unwrap() {
            check("a getcrawlnodes row", row);
        }
    }
    for raw in [false, true] {
        let snap = pm.dump_crawl_snapshot(raw).unwrap();
        let nodes = snap["nodes"].as_object().unwrap();
        assert_eq!(nodes.len(), 5);
        for node in nodes.values() {
            assert!(node[7].is_null(), "Bitnodes' country: {node}");
            check("an export node", node);
        }
        assert_eq!(snap["satd"]["countries"]["DE"], 2, "the totals are there");
    }
    assert!(pm.crawl_snapshot_tick(crate::time::now_secs()));
    let snaps = dir.path().join(crate::net::crawlsnapshot::SNAPSHOT_DIR);
    let t = crate::net::crawlsnapshot::list_snapshots(&snaps).unwrap()[0];
    let gz = std::fs::read(snaps.join(crate::net::crawlsnapshot::snapshot_file_name(t))).unwrap();
    let lines = String::from_utf8(crate::net::crawlsnapshot::gunzip(&gz).unwrap()).unwrap();
    assert_eq!(lines.lines().count(), 5);
    for line in lines.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v["node"][7].is_null(), "{line}");
        check("an hourly line", &v);
    }
}

// ---- -crawlproxy ----

/// How the in-test SOCKS5 proxy answers a CONNECT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyMode {
    /// Connect to the target and relay; reply 0x05 when it refuses.
    Relay,
    /// Reply with this code, and close.
    Refuse(u8),
    /// Accept, then close before the greeting reply: a proxy that is up
    /// on its port and cannot serve.
    Broken,
}

/// An in-test SOCKS5 proxy: no authentication, CONNECT to an IPv4 or IPv6
/// address or a name. It records every target asked for (`ip:port` or
/// `name:port`).
struct TestProxy {
    addr: SocketAddr,
    asked: Arc<parking_lot::Mutex<Vec<String>>>,
    mode: Arc<parking_lot::Mutex<ProxyMode>>,
}

async fn test_proxy(mode: ProxyMode) -> TestProxy {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let asked: Arc<parking_lot::Mutex<Vec<String>>> = Default::default();
    let mode = Arc::new(parking_lot::Mutex::new(mode));
    let (seen, how) = (asked.clone(), mode.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (seen, how) = (seen.clone(), *how.lock());
            tokio::spawn(async move {
                if how == ProxyMode::Broken {
                    return None;
                }
                let mut head = [0u8; 2];
                sock.read_exact(&mut head).await.ok()?;
                let mut methods = vec![0u8; head[1] as usize];
                sock.read_exact(&mut methods).await.ok()?;
                sock.write_all(&[0x05, 0x00]).await.ok()?;
                let mut req = [0u8; 4];
                sock.read_exact(&mut req).await.ok()?;
                let host = match req[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        sock.read_exact(&mut a).await.ok()?;
                        IpAddr::from(a).to_string()
                    }
                    0x04 => {
                        let mut a = [0u8; 16];
                        sock.read_exact(&mut a).await.ok()?;
                        format!("[{}]", IpAddr::from(a))
                    }
                    _ => {
                        let mut len = [0u8; 1];
                        sock.read_exact(&mut len).await.ok()?;
                        let mut name = vec![0u8; len[0] as usize];
                        sock.read_exact(&mut name).await.ok()?;
                        String::from_utf8_lossy(&name).into_owned()
                    }
                };
                let mut port = [0u8; 2];
                sock.read_exact(&mut port).await.ok()?;
                let target = format!("{host}:{}", u16::from_be_bytes(port));
                seen.lock().push(target.clone());
                let reply = |code: u8| [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                if let ProxyMode::Refuse(code) = how {
                    let _ = sock.write_all(&reply(code)).await;
                    return None;
                }
                match TcpStream::connect(target).await {
                    Ok(mut out) => {
                        sock.write_all(&reply(0x00)).await.ok()?;
                        let _ = tokio::io::copy_bidirectional(&mut sock, &mut out).await;
                    }
                    Err(_) => {
                        let _ = sock.write_all(&reply(0x05)).await;
                    }
                }
                None::<()>
            });
        }
    });
    TestProxy { addr, asked, mode }
}

/// A loopback address nothing listens on: a proxy that is down.
async fn down_proxy() -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    l.local_addr().unwrap()
}

fn with_crawl_proxy(proxy: SocketAddr) -> CrawlConfig {
    CrawlConfig {
        proxy: Some(proxy),
        ..config()
    }
}

/// The book's record of `addr` that a session's result moves: its
/// attempts, reachability, failures, back-off, retry and observation.
fn record_of(pm: &PeerManager, addr: &PeerAddr) -> impl PartialEq + std::fmt::Debug {
    let e = pm
        .crawl_book()
        .unwrap()
        .get(&CrawlAddr::Peer(addr.clone()))
        .cloned()
        .expect("in the book");
    (
        (e.attempts, e.last_attempt, e.last_success),
        (e.failures, e.failing_since, e.retry_at),
        (e.v2_ok, e.v1_ok, e.reachable_count),
        e.observation,
        e.closed_early_retry,
    )
}

/// Seed `addr`, mark a session open and run it as the tick would.
async fn crawl_once(pm: &Arc<PeerManager>, addr: &PeerAddr) {
    let run = pm.crawl.get().unwrap();
    let now = crate::time::now_secs();
    run.book.lock().seed(addr.clone(), 0, now);
    let token = run.book.lock().mark_dialling(addr, now);
    assert!(token.is_some());
    pm.run_crawl_session(addr.clone(), SessionKind::Discovery, token)
        .await;
}

/// With `-crawlproxy`, a clearnet crawl dial goes through it: the proxy is
/// asked for the target, the session reaches it and is recorded, and the
/// `version` names the dummy address as the receiver, not the target.
/// Perturbation: dial direct when `-crawlproxy` is set and the proxy is
/// asked for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clearnet_crawl_dial_goes_through_the_crawl_proxy() {
    let (pm, _dir) = mk_pm_with(None);
    let proxy = test_proxy(ProxyMode::Relay).await;
    enable(&pm, with_crawl_proxy(proxy.addr));
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!(out.result.v1, Attempt::Ok, "reached through the proxy");
    assert!(!out.proxy_failed);
    assert_eq!(*proxy.asked.lock(), vec![target.to_string()]);
    let conns = log.lock().clone();
    let Some(NetworkMessage::Version(v)) = conns[0].first() else {
        panic!("a version first: {conns:?}");
    };
    assert_eq!(
        v.receiver.socket_addr().unwrap(),
        SocketAddr::from(([0, 0, 0, 0], 0)),
        "the dummy receiver through a proxy"
    );
    assert_eq!(pm.get_crawl_info()["proxy"]["failures"], 0);
}

/// Under `-proxy` (a Tor proxy, say) clearnet is never crawled; with
/// `-crawlproxy` set too it is, through `-crawlproxy` and never `-proxy`,
/// a routable address included. `-crawlnet` still narrows.
/// Perturbation: keep the `-proxy` rule ahead of `-crawlproxy` in
/// `crawl_may_dial` and the routable address is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_proxy_clearnet_is_crawled_through_the_crawl_proxy() {
    use crate::net::crawlbook::Network as Net;
    let tor = test_proxy(ProxyMode::Relay).await;
    let crawl_proxy = test_proxy(ProxyMode::Relay).await;
    let tor_addr = tor.addr.to_string();
    let (pm, _dir) = mk_pm_proxied(&tor_addr);
    enable(&pm, with_crawl_proxy(crawl_proxy.addr));
    let public = PeerAddr::Socket("23.1.2.3:8333".parse().unwrap());
    assert!(pm.crawl_may_dial(&public), "clearnet, through -crawlproxy");
    let nets = pm.crawl_networks();
    assert!(nets.contains(&Net::Ipv4) && nets.contains(&Net::Ipv6), "{nets:?}");
    let (target, _log) = scripted("127.0.0.1", core_script()).await;
    let out = pm.crawl_session(&target, SessionKind::Liveness).await;
    assert_eq!(out.result.v1, Attempt::Ok);
    assert_eq!(*crawl_proxy.asked.lock(), vec![target.to_string()]);
    assert!(tor.asked.lock().is_empty(), "-proxy was not used");

    let (pm, _dir) = mk_pm_proxied(&tor_addr);
    enable(
        &pm,
        CrawlConfig {
            networks: Some(vec![Net::Ipv6, Net::Onion]),
            ..with_crawl_proxy(crawl_proxy.addr)
        },
    );
    assert!(!pm.crawl_may_dial(&public), "-crawlnet left IPv4 out");
    pm.set_reachable(crate::net::reachable::ReachableNets {
        ipv4: false,
        ipv6: false,
        onion: true,
        ..Default::default()
    });
    let v6 = PeerAddr::Socket("[2600::1]:8333".parse().unwrap());
    assert!(!pm.crawl_may_dial(&v6), "-onlynet still narrows");
}

/// With the crawl proxy down, a clearnet dial is never made direct: the
/// target sees no connection, the failure is the proxy's (counted in
/// `getcrawlinfo`, the session in neither reached nor unreached), and the
/// target's record is unchanged: no attempt, failure, back-off or
/// reachability. The address stays due; proxied dials pause, then resume.
/// A proxy that accepts and cannot greet is down the same way. Once the
/// proxy answers again a session reaches the target.
/// Perturbation: record the session as the target's (no `release`) and
/// the record moves; fall back to a direct dial and the target sees a
/// connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crawl_proxy_failure_is_never_held_against_the_target() {
    let (pm, _dir) = mk_pm_with(None);
    let proxy = test_proxy(ProxyMode::Broken).await;
    let run = enable(&pm, with_crawl_proxy(proxy.addr));
    let (target, log) = scripted("127.0.0.1", core_script()).await;
    let now = crate::time::now_secs();
    run.book.lock().seed(target.clone(), 0, now);
    let before = record_of(&pm, &target);

    crawl_once(&pm, &target).await;
    assert!(log.lock().is_empty(), "no direct dial");
    assert_eq!(record_of(&pm, &target), before, "not held against the target");
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 1);
    assert_eq!(
        (run.reached.load(Ordering::Relaxed), run.unreached.load(Ordering::Relaxed)),
        (0, 0)
    );
    let book = pm.crawl_book().unwrap();
    assert!(
        book.next_due(now, 10).iter().any(|(a, _)| *a == target),
        "still due"
    );
    assert!(!pm.crawl_may_dial(&target), "proxied dials pause");
    run.proxy_paused_until_ms.store(0, Ordering::Relaxed);
    assert!(pm.crawl_may_dial(&target), "and resume");

    // A proxy nothing listens on.
    let (pm2, _dir2) = mk_pm_with(None);
    let run2 = enable(&pm2, with_crawl_proxy(down_proxy().await));
    let before2 = {
        run2.book.lock().seed(target.clone(), 0, now);
        record_of(&pm2, &target)
    };
    crawl_once(&pm2, &target).await;
    assert!(log.lock().is_empty(), "no direct dial");
    assert_eq!(record_of(&pm2, &target), before2);
    assert_eq!(pm2.get_crawl_info()["proxy"]["failures"], 1);

    // The proxy is back.
    *proxy.mode.lock() = ProxyMode::Relay;
    crawl_once(&pm, &target).await;
    assert_eq!(run.reached.load(Ordering::Relaxed), 1, "reached once it is back");
    assert_eq!(log.lock().len(), 1);
    assert_eq!(*proxy.asked.lock(), vec![target.to_string()]);
}

/// A refusal the proxy reports for the target (SOCKS5 reply 0x05, and
/// 0x01, general failure) is the target's: recorded as a failed dial,
/// backed off, and not counted against the proxy. A reply the proxy gives
/// for itself (0x08, address type not supported) is the proxy's.
/// Perturbation: treat every SOCKS reply as the proxy's and the refusal
/// is not recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socks_refusal_is_the_targets_failed_dial() {
    for code in [0x05u8, 0x01] {
        let (pm, _dir) = mk_pm_with(None);
        let proxy = test_proxy(ProxyMode::Refuse(code)).await;
        let run = enable(&pm, with_crawl_proxy(proxy.addr));
        let target = PeerAddr::Socket("127.0.0.9:8333".parse().unwrap());
        crawl_once(&pm, &target).await;
        let e = pm
            .crawl_book()
            .unwrap()
            .get(&CrawlAddr::Peer(target.clone()))
            .cloned()
            .unwrap();
        assert_eq!((e.attempts, e.failures), (1, 1), "{code:#04x}");
        assert!(e.retry_at.is_some(), "backed off");
        assert_eq!(run.unreached.load(Ordering::Relaxed), 1);
        assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 0);
        assert!(pm.crawl_may_dial(&target), "no pause for the target's failure");
    }
    let (pm, _dir) = mk_pm_with(None);
    let proxy = test_proxy(ProxyMode::Refuse(0x08)).await;
    let run = enable(&pm, with_crawl_proxy(proxy.addr));
    let target = PeerAddr::Socket("127.0.0.9:8333".parse().unwrap());
    crawl_once(&pm, &target).await;
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 1);
    assert_eq!(run.unreached.load(Ordering::Relaxed), 0);
}

/// Onion crawl dials keep `-onion` (or `-proxy`), with credentials of
/// their own: `-crawlproxy` is never asked for an onion.
/// Perturbation: send onions through `-crawlproxy` and its record is not
/// empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onion_crawl_dials_keep_the_onion_proxy() {
    let tor = test_proxy(ProxyMode::Refuse(0x04)).await;
    let crawl_proxy = test_proxy(ProxyMode::Relay).await;
    let tor_addr = tor.addr.to_string();
    let onion = PeerAddr::Onion {
        host: ONION.to_string(),
        port: 8333,
    };
    for (proxy, onion_proxy) in [(Some(tor_addr.as_str()), None), (None, Some(tor_addr.as_str()))] {
        let (pm, _dir, _shutdown) = mk_pm_proxies(proxy, onion_proxy);
        enable(&pm, with_crawl_proxy(crawl_proxy.addr));
        assert!(pm.crawl_may_dial(&onion));
        let got = pm.crawl_dial(&onion, Duration::from_secs(2)).await;
        assert!(matches!(got, Err(crawl_conn::DialFailure::Target(_))), "{got:?}");
    }
    assert_eq!(
        *tor.asked.lock(),
        vec![format!("{ONION}:8333"), format!("{ONION}:8333")]
    );
    assert!(crawl_proxy.asked.lock().is_empty(), "never -crawlproxy");
}

/// `-crawlbind` does not apply to a proxied dial: with an address no
/// interface has, a direct dial fails to bind, and the same dial through
/// `-crawlproxy` connects.
/// Perturbation: bind the proxied dial's socket and it fails too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crawlbind_does_not_apply_to_a_proxied_dial() {
    let (target, _log) = scripted("127.0.0.1", core_script()).await;
    let unbindable = CrawlConfig {
        bind_v4: Some("192.0.2.1".parse().unwrap()),
        ..config()
    };
    let (pm, _dir) = mk_pm_with(None);
    enable(&pm, unbindable.clone());
    let direct = pm.crawl_dial(&target, Duration::from_secs(2)).await;
    assert!(
        matches!(&direct, Err(crawl_conn::DialFailure::Target(e)) if e.contains("bind")),
        "the control: {direct:?}"
    );
    let proxy = test_proxy(ProxyMode::Relay).await;
    let (pm, _dir) = mk_pm_with(None);
    enable(
        &pm,
        CrawlConfig {
            proxy: Some(proxy.addr),
            ..unbindable
        },
    );
    let proxied = pm.crawl_dial(&target, Duration::from_secs(2)).await;
    assert!(proxied.is_ok(), "{proxied:?}");
}

/// `getcrawlinfo` says whether a crawl proxy is set and counts its
/// failures, and never names its address or port; with the crawl off, or
/// on without one, it is not set.
/// Perturbation: put the address in the object and the text check fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn getcrawlinfo_states_a_crawl_proxy_and_never_its_address() {
    let (pm, _dir) = mk_pm_with(None);
    assert_eq!(
        pm.get_crawl_info()["proxy"],
        serde_json::json!({ "set": false, "failures": 0 })
    );
    enable(&pm, config());
    assert_eq!(
        pm.get_crawl_info()["proxy"],
        serde_json::json!({ "set": false, "failures": 0 })
    );

    let (pm, _dir) = mk_pm_with(None);
    let proxy = down_proxy().await;
    enable(&pm, with_crawl_proxy(proxy));
    let target = PeerAddr::Socket("127.0.0.9:8333".parse().unwrap());
    crawl_once(&pm, &target).await;
    let info = pm.get_crawl_info();
    assert_eq!(info["proxy"], serde_json::json!({ "set": true, "failures": 1 }));
    let text = info.to_string();
    assert!(
        !text.contains(&proxy.to_string()) && !text.contains("127.0.0.1"),
        "no proxy address in {text}"
    );
}

/// The book's failure count for `addr`: 0 when nothing was recorded.
fn failures_of(pm: &PeerManager, addr: &PeerAddr) -> u32 {
    pm.crawl_book()
        .unwrap()
        .get(&CrawlAddr::Peer(addr.clone()))
        .map_or(0, |e| e.failures)
}

fn loopback_target(i: u8) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from(([127, 0, 9, i], 8333)))
}

/// A proxy that greets but whose targets never answer (0x04 for every
/// CONNECT, as a SOCKS server with its own uplink down gives) is taken as
/// down after `PROXY_SILENT_STREAK` such dials in a row: those before it
/// are recorded against their targets; the dial that completes the streak
/// and every silent one after it while the proxy is down are the proxy's
/// (released, counted in `proxy.failures`); a success ends the outage and
/// the streak, after which a silent failure is the target's again.
/// Perturbation: never trip on the streak, or record a silent failure while
/// the proxy is down, and this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_whose_targets_never_answer_is_taken_as_down() {
    use super::crawl_conn::PROXY_SILENT_STREAK;
    let (pm, _dir) = mk_pm_with(None);
    let proxy = test_proxy(ProxyMode::Refuse(0x04)).await;
    let run = enable(&pm, with_crawl_proxy(proxy.addr));

    let below = loopback_target(1);
    crawl_once(&pm, &below).await;
    assert_eq!(failures_of(&pm, &below), 1, "below the streak: the target's");
    for _ in 0..PROXY_SILENT_STREAK - 2 {
        let got = pm.crawl_dial(&loopback_target(2), Duration::from_secs(2)).await;
        assert!(matches!(got, Err(crawl_conn::DialFailure::Target(_))), "{got:?}");
    }
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 0);
    assert!(!run.proxy_down.load(Ordering::Relaxed));

    let trips = loopback_target(3);
    run.book.lock().seed(trips.clone(), 0, crate::time::now_secs());
    let before = record_of(&pm, &trips);
    crawl_once(&pm, &trips).await;
    assert!(run.proxy_down.load(Ordering::Relaxed), "the streak puts the proxy down");
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 1);
    assert_eq!(record_of(&pm, &trips), before, "the tripping dial is released");
    assert!(!pm.crawl_may_dial(&trips), "proxied dials pause");

    let next = loopback_target(4);
    run.book.lock().seed(next.clone(), 0, crate::time::now_secs());
    let before = record_of(&pm, &next);
    crawl_once(&pm, &next).await;
    assert_eq!(record_of(&pm, &next), before, "released while the proxy is down");
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 2);

    *proxy.mode.lock() = ProxyMode::Relay;
    let (live, _log) = scripted("127.0.0.1", core_script()).await;
    let out = pm.crawl_session(&live, SessionKind::Liveness).await;
    assert_eq!(out.result.v1, Attempt::Ok);
    assert!(!run.proxy_down.load(Ordering::Relaxed), "a success ends the outage");
    assert_eq!(run.proxy_silent_streak.load(Ordering::Relaxed), 0);

    *proxy.mode.lock() = ProxyMode::Refuse(0x04);
    let after = loopback_target(5);
    crawl_once(&pm, &after).await;
    assert_eq!(failures_of(&pm, &after), 1, "the target's again");
    assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 2);
}

/// A refusal (0x05, and 0x02) proves the proxy reaches the network: it is
/// the target's failed dial, never counts toward the silent streak, and
/// resets it, so a streak one short of the limit does not trip on it nor on
/// the silent failure after it. A refusal also ends an outage.
/// Perturbation: count a refusal toward the streak and it trips here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_resets_the_silent_streak() {
    use super::crawl_conn::PROXY_SILENT_STREAK;
    for code in [0x05u8, 0x02] {
        let (pm, _dir) = mk_pm_with(None);
        let proxy = test_proxy(ProxyMode::Refuse(code)).await;
        let run = enable(&pm, with_crawl_proxy(proxy.addr));
        run.proxy_silent_streak
            .store(PROXY_SILENT_STREAK - 1, Ordering::Relaxed);
        let refused = loopback_target(1);
        crawl_once(&pm, &refused).await;
        assert_eq!(failures_of(&pm, &refused), 1, "{code:#04x}: the target's");
        assert_eq!(run.proxy_silent_streak.load(Ordering::Relaxed), 0);
        assert!(!run.proxy_down.load(Ordering::Relaxed));
        assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 0);

        *proxy.mode.lock() = ProxyMode::Refuse(0x04);
        let silent = loopback_target(2);
        crawl_once(&pm, &silent).await;
        assert_eq!(failures_of(&pm, &silent), 1, "no trip after the reset");
        assert_eq!(run.proxy_failures.load(Ordering::Relaxed), 0);

        run.proxy_down.store(true, Ordering::Relaxed);
        *proxy.mode.lock() = ProxyMode::Refuse(code);
        crawl_once(&pm, &loopback_target(3)).await;
        assert!(!run.proxy_down.load(Ordering::Relaxed), "a refusal ends an outage");
    }
}
