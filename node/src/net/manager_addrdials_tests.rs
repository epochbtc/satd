//! The addresses a peer may hand the node, and the outbound dials the node
//! starts from them: Core's address rate limit (`ProcessAddrs`), and the
//! separate limits on automatic and manual connections (`semOutbound`,
//! `semAddnode`; `net.cpp` `ThreadOpenConnections`,
//! `ThreadOpenAddedConnections`), against a live `PeerManager`.

use super::*;
use crate::net::flow::InFlight;
use std::sync::atomic::AtomicUsize;

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let store = Box::new(InMemoryStore::new());
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    (over(chain_state), dir)
}

/// [`mk_pm`] with an onion proxy, so that onions are reachable and the
/// automatic dials take them. Nothing listens on it: every onion dial fails,
/// at once, and records a backoff entry, the trace of a dial attempted.
fn mk_pm_tor() -> (Arc<PeerManager>, tempfile::TempDir) {
    let (pm, dir) = mk_pm();
    let chain_state = Arc::clone(&pm.chain_state);
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = PeerManager::with_config(
        chain_state,
        mempool,
        fee_estimator,
        Network::Regtest,
        shutdown_rx,
        0,
        125,
        DEFAULT_MAX_INBOUND_PER_IP,
        86400,
        None,
        Some("127.0.0.1:1".to_string()),
        1,
        50_000,
        0,
        None,
    );
    (pm, dir)
}

fn over(chain_state: Arc<ChainState>) -> Arc<PeerManager> {
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx)
}

/// Out of IBD, so the automatic outbound target is 8 rather than 64: a
/// peer has announced a headers tip the node's tip is within 24 of.
fn leave_ibd(pm: &PeerManager) {
    pm.headers_tip.store(1, Ordering::Relaxed);
    assert!(!pm.is_ibd(), "fixture: out of IBD");
}

fn add_peer(pm: &PeerManager, info: PeerInfo) {
    let (tx, _rx) = mpsc::channel::<NetworkMessage>(8);
    pm.peers.write().insert(
        info.id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            last_mempool_served: None,
            tx_relay: Default::default(),
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
}

/// A connected peer.
fn peer(id: PeerId, addr: SocketAddr, direction: Direction) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = PeerState::Connected;
    info
}

/// `n` connected automatic (`outbound-full-relay`) peers, ids from 1000.
fn fill_automatic(pm: &PeerManager, n: usize) {
    for i in 0..n {
        let addr = SocketAddr::from(([203, 0, 113, i as u8 + 1], 8333));
        add_peer(pm, peer(1000 + i as PeerId, addr, Direction::Outbound));
    }
}

/// `n` addresses, each in a /16 of its own so the address book's
/// per-group limit does not apply, starting at first octet `base`.
fn spread(base: u8, n: usize) -> Vec<SocketAddr> {
    (0..n)
        .map(|i| SocketAddr::from(([base + (i / 250) as u8, (i % 250) as u8, 7, 7], 8333)))
        .collect()
}

fn addr_msg(addrs: &[SocketAddr]) -> NetworkMessage {
    NetworkMessage::Addr(
        addrs
            .iter()
            .map(|a| (1_700_000_000, Address::new(a, ServiceFlags::NETWORK | ServiceFlags::WITNESS)))
            .collect(),
    )
}

fn addr_counts(pm: &PeerManager, id: PeerId) -> (u64, u64) {
    let peers = pm.peers.read();
    let rate = &peers.get(&id).expect("peer").info.addr_rate;
    (rate.processed, rate.rate_limited)
}

/// A listener on loopback that accepts every connection and keeps it open,
/// counting the accepts.
struct Listener {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Listener {
    async fn bind() -> Self {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = socket.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });
        Self { addr, accepts, task }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn listeners(n: usize) -> Vec<Listener> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(Listener::bind().await);
    }
    out
}

fn total_accepts(ls: &[Listener]) -> usize {
    ls.iter().map(Listener::accepts).sum()
}

/// Wait until `cond` holds.
async fn wait_for(pm: &PeerManager, cond: impl Fn() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cond() {
        assert!(
            Instant::now() < deadline,
            "timed out: {what} (in flight {:?}, dialling {:?}, backoff {:?})",
            pm.dials_in_flight.lock(),
            pm.pending_connections.read(),
            pm.reconnect_backoff.read().iter().map(|(a, s)| (*a, s.attempts)).collect::<Vec<_>>(),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Wait for the dials a reconnect tick started to finish, one way or the
/// other: nothing is in flight any more.
async fn settle(pm: &PeerManager) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let in_flight = {
            let d = pm.dials_in_flight.lock();
            d.automatic + d.added_node
        };
        if in_flight == 0 && pm.pending_connections.read().is_empty() && pm.pending_onion_dials.read().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "dials still in flight");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Accepts land on the listener tasks a moment after the dial returns.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

// ---- Address rate limit ----

/// Core gives each peer a token bucket for the addresses it announces: one
/// token to start, 0.1 a second after that. satd took every entry of every
/// `addr`, so one peer could put a thousand addresses into the address book
/// per message. A peer with the `addr` permission is
/// not limited, as in Core.
#[test]
fn a_peers_addresses_are_rate_limited_unless_it_has_the_addr_permission() {
    let (pm, _dir) = mk_pm();
    let limited = SocketAddr::from(([127, 0, 0, 1], 40001));
    add_peer(&pm, peer(1, limited, Direction::Inbound));
    pm.handle_message(1, addr_msg(&spread(1, 1000)), InFlight::adopt(None));
    assert_eq!(addr_counts(&pm, 1), (1, 999), "one token: one address processed, the rest rate-limited");
    assert_eq!(pm.addrman.read().len(), 1, "one address reached the address book");

    let mut exempt = peer(2, SocketAddr::from(([127, 0, 0, 1], 40002)), Direction::Inbound);
    exempt.permissions.addr = true;
    add_peer(&pm, exempt);
    pm.handle_message(2, addr_msg(&spread(20, 1000)), InFlight::adopt(None));
    assert_eq!(addr_counts(&pm, 2), (1000, 0), "the addr permission takes them all");
    assert_eq!(pm.addrman.read().len(), 1001);
}

/// Core adds `MAX_ADDR_TO_SEND` tokens when it sends a peer `getaddr`, so
/// the answer is taken whole. satd sends one to an addr-fetch peer, and to
/// outbound peers under a proxy.
#[test]
fn the_answer_to_a_getaddr_is_taken_whole() {
    let (pm, _dir) = mk_pm();
    add_peer(&pm, peer(1, SocketAddr::from(([198, 51, 100, 1], 8333)), Direction::Outbound));
    pm.note_getaddr_sent(1);
    pm.handle_message(1, addr_msg(&spread(1, 1000)), InFlight::adopt(None));
    let (processed, limited) = addr_counts(&pm, 1);
    assert_eq!((processed, limited), (1000, 0));
}

/// The same limit applies to `addrv2`.
#[test]
fn addrv2_is_rate_limited_too() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    let (pm, _dir) = mk_pm();
    add_peer(&pm, peer(1, SocketAddr::from(([127, 0, 0, 1], 40001)), Direction::Inbound));
    let msg = NetworkMessage::AddrV2(
        spread(1, 500)
            .into_iter()
            .map(|a| AddrV2Message {
                time: 1_700_000_000,
                services: ServiceFlags::NETWORK,
                addr: match a.ip() {
                    IpAddr::V4(v4) => AddrV2::Ipv4(v4),
                    IpAddr::V6(v6) => AddrV2::Ipv6(v6),
                },
                port: a.port(),
            })
            .collect(),
    );
    pm.handle_message(1, msg, InFlight::adopt(None));
    assert_eq!(addr_counts(&pm, 1), (1, 499));
}

// ---- The automatic dial candidates ----

/// Put `addr` in the address book, which the automatic dials draw from.
fn learn(pm: &PeerManager, addr: SocketAddr) {
    assert!(pm.addrman.write().add(addr, now_unix_secs()), "fixture: the book takes {addr}");
}

// ---- Outbound dials ----

/// The automatic limit counts the dials in flight along with the peers.
/// satd counted connected peers only, so a reconnect tick started a dial
/// for every eligible learned address at once: twenty listeners, three
/// automatic peers connected and a target of eight got twenty dials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_tick_starts_no_more_automatic_dials_than_free_slots() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 3);
    let ls = listeners(20).await;
    for l in &ls {
        learn(&pm, l.addr);
    }

    pm.reconnect_tick();
    wait_for(&pm, || total_accepts(&ls) >= 5, "five dials reach a listener").await;
    settle(&pm).await;
    assert_eq!(total_accepts(&ls), 5, "five free slots, five dials");
    assert_eq!(pm.automatic_outbound_peers(), 8, "the target is reached");

    // Full now: the next tick starts nothing.
    pm.reconnect_tick();
    settle(&pm).await;
    assert_eq!(total_accepts(&ls), 5);
}

/// Manual connections are outside the automatic target, as in Core, where
/// added nodes have their own limit (`semAddnode`). satd counted them
/// against it, and redialled named peers only while the automatic count
/// was below the target: with eight automatic peers, an added node was not
/// dialled at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_added_node_is_dialled_with_the_automatic_slots_full() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 8);
    let l = Listener::bind().await;
    assert!(pm.addnode_add(&l.addr.to_string(), PeerAddr::Socket(l.addr)));

    pm.reconnect_tick();
    wait_for(&pm, || l.accepts() == 1, "the added node is dialled").await;
    settle(&pm).await;
    let conn_type = pm.peers.read().values().find(|h| h.info.addr == l.addr).map(|h| h.info.conn_type);
    assert_eq!(conn_type, Some(ConnType::Manual));

    // The automatic limit still holds for an automatic dial.
    let spare = Listener::bind().await;
    let err = pm.connect_outbound(spare.addr).await.expect_err("the automatic slots are full");
    assert_eq!(err, "max outbound connections reached");
}

/// Core's `MAX_ADDNODE_CONNECTIONS`: eight added nodes at a time. The other
/// manual connections (`-connect`, `-seednode`) have no limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn added_nodes_stop_at_eight_and_other_manual_peers_do_not() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let added = listeners(10).await;
    for l in &added {
        assert!(pm.addnode_add(&l.addr.to_string(), PeerAddr::Socket(l.addr)));
    }
    let connect = listeners(10).await;
    for l in &connect {
        assert!(pm.add_peer_addr(PeerAddr::Socket(l.addr)));
    }

    pm.reconnect_tick();
    wait_for(
        &pm,
        || total_accepts(&added) >= MAX_ADDNODE_CONNECTIONS && total_accepts(&connect) >= 10,
        "the dials reach their listeners",
    )
    .await;
    settle(&pm).await;
    assert_eq!(total_accepts(&added), MAX_ADDNODE_CONNECTIONS, "eight added nodes");
    assert_eq!(total_accepts(&connect), 10, "every other manual peer");
    assert_eq!(pm.added_node_peers(), MAX_ADDNODE_CONNECTIONS);

    // One added node goes away: the next tick dials one more.
    let gone = pm
        .peers
        .read()
        .iter()
        .find(|(_, h)| added.iter().any(|l| l.addr == h.info.addr))
        .map(|(id, _)| *id)
        .unwrap();
    pm.peers.write().remove(&gone);
    pm.reconnect_tick();
    wait_for(&pm, || total_accepts(&added) > MAX_ADDNODE_CONNECTIONS, "a ninth dial").await;
    settle(&pm).await;
    assert_eq!(total_accepts(&added), MAX_ADDNODE_CONNECTIONS + 1);
}

/// `addnode onetry` is outside every limit, as Core's takes no grant, and
/// answers success for a peer already connected, as Core's answers null.
/// satd refused it with "max outbound connections reached" once the
/// automatic peers were all connected, and with "already connected".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onetry_is_outside_the_limits_and_succeeds_for_a_connected_peer() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 8);
    let l = Listener::bind().await;
    let target = PeerAddr::Socket(l.addr);

    pm.connect_peer_addr_onetry(&target, None).await.expect("onetry with the automatic slots full");
    wait_for(&pm, || l.accepts() == 1, "the onetry dial reaches the listener").await;

    pm.connect_peer_addr_onetry(&target, None).await.expect("onetry to a connected peer");
    settle(&pm).await;
    assert_eq!(l.accepts(), 1, "no second connection");

    // A dial that fails is still reported.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    assert!(pm.connect_peer_addr_onetry(&PeerAddr::Socket(closed_addr), None).await.is_err());
}

/// A peer the operator named waits at most a minute between dials, Core's
/// added-node retry interval. satd backed it off to five minutes, like a
/// learned address.
#[test]
fn a_manual_peers_backoff_stops_at_a_minute() {
    let mut manual = ReconnectState::new();
    let mut automatic = ReconnectState::new();
    for _ in 0..10 {
        manual.record_failure(MANUAL_RECONNECT_MAX_BACKOFF);
        automatic.record_failure(AUTOMATIC_RECONNECT_MAX_BACKOFF);
    }
    assert_eq!(manual.backoff_duration(MANUAL_RECONNECT_MAX_BACKOFF), Duration::from_secs(60));
    assert_eq!(automatic.backoff_duration(AUTOMATIC_RECONNECT_MAX_BACKOFF), Duration::from_secs(300));
}

/// A failed dial backs off, and in the reconnect loop that is per address:
/// a manual peer's failure uses the manual cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_manual_redial_backs_off_by_the_manual_cap() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    assert!(pm.addnode_add(&addr.to_string(), PeerAddr::Socket(addr)));
    for _ in 0..10 {
        pm.reconnect_backoff.write().entry(addr).or_insert_with(ReconnectState::new).next_attempt =
            Instant::now();
        pm.reconnect_tick();
        settle(&pm).await;
    }
    let backoff = pm.reconnect_backoff.read();
    let state = backoff.get(&addr).expect("a backoff entry");
    assert_eq!(state.attempts, 10);
    assert!(
        state.next_attempt <= Instant::now() + MANUAL_RECONNECT_MAX_BACKOFF,
        "the next dial is at most a minute away"
    );
}

/// Backoff ends when a dial to that address connects, and not otherwise.
/// satd cleared every address's backoff whenever the tip moved, which
/// during IBD is every tick, so nothing ever backed off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_tip_leaves_reconnect_backoff_alone() {
    use crate::chain::state::tests::{build_test_block, make_chain_state};

    let (cs, dir) = make_chain_state();
    let chain_state = Arc::new(cs);
    let pm = over(chain_state.clone());
    let waiting = SocketAddr::from(([198, 51, 100, 9], 8333));
    {
        let mut backoff = pm.reconnect_backoff.write();
        let state = backoff.entry(waiting).or_insert_with(ReconnectState::new);
        for _ in 0..3 {
            state.record_failure(AUTOMATIC_RECONNECT_MAX_BACKOFF);
        }
    }
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    chain_state
        .accept_block(&build_test_block(genesis, 1, 1_707_000_000))
        .expect("connect block 1");

    let pm_run = pm.clone();
    let run = tokio::spawn(async move { pm_run.run().await });
    // The run loop sees the new tip on its first maintenance pass, 500 ms in.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let attempts = pm.reconnect_backoff.read().get(&waiting).map(|s| s.attempts);
    run.abort();
    *pm.ibd.write() = None;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(attempts, Some(3), "a new tip does not clear backoff");
}

/// The other half: a dial that connects clears its address's backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_that_connects_clears_its_backoff() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let l = Listener::bind().await;
    learn(&pm, l.addr);
    {
        let mut backoff = pm.reconnect_backoff.write();
        let state = backoff.entry(l.addr).or_insert_with(ReconnectState::new);
        state.record_failure(AUTOMATIC_RECONNECT_MAX_BACKOFF);
        state.record_failure(AUTOMATIC_RECONNECT_MAX_BACKOFF);
        state.next_attempt = Instant::now();
    }
    pm.reconnect_tick();
    wait_for(&pm, || l.accepts() == 1, "the address is dialled").await;
    settle(&pm).await;
    assert_eq!(pm.reconnect_backoff.read().get(&l.addr).map(|s| s.attempts), Some(0));
}

// ---- Bans and dials ----

fn ban(pm: &PeerManager, target: crate::net::ban::BanTarget) {
    let now = crate::time::now_secs();
    pm.ban_list.write().add(&target, now, now + 3600).expect("ban");
}

/// Core checks bans for automatic connections only: a manual one is opened
/// by the name the operator gave, banned or not (`OpenNetworkConnection`,
/// `net.cpp`). satd skipped a banned added node in the reconnect loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_banned_manual_peer_is_dialled_and_a_banned_learned_one_is_not() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let manual = Listener::bind().await;
    let learned = Listener::bind().await;
    assert!(pm.addnode_add(&manual.addr.to_string(), PeerAddr::Socket(manual.addr)));
    learn(&pm, learned.addr);
    ban(&pm, crate::net::ban::BanTarget::Net(ipnet::IpNet::from(IpAddr::from([127, 0, 0, 1]))));

    pm.reconnect_tick();
    wait_for(&pm, || manual.accepts() == 1, "the banned added node is dialled").await;
    settle(&pm).await;
    assert_eq!(learned.accepts(), 0, "the banned learned address is not");
    let err = pm
        .connect_peer_addr_automatic(&PeerAddr::Socket(learned.addr))
        .await
        .expect_err("nor does a seed dial reach it");
    assert!(err.contains("banned"), "{err}");
    assert_eq!(learned.accepts(), 0);
}

/// The same for onion peers. satd never looked at the ban of an onion host
/// in the reconnect loop or when gossip named one, so `setban <host>.onion`,
/// or a ban for misbehaviour, did not stop automatic dials to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_banned_onion_host_is_neither_learned_nor_dialled_automatically() {
    let (pm, _dir) = mk_pm_tor();
    leave_ibd(&pm);
    let host = onion_host;
    let (banned, open, named) = (host(1), host(2), host(3));

    // Learned before the ban, so only the reconnect loop can hold it back.
    learn_onion(&pm, &banned, 8333);
    learn_onion(&pm, &open, 8333);
    assert!(pm.add_peer_addr(PeerAddr::Onion { host: named.clone(), port: 8333 }));
    for h in [&banned, &named] {
        ban(&pm, crate::net::ban::BanTarget::Onion(h.clone()));
    }

    pm.reconnect_tick();
    let tried = |h: &str| pm.onion_reconnect_backoff.read().contains_key(&format!("{h}:8333"));
    wait_for(&pm, || tried(&open) && tried(&named), "the open host and the named one are dialled").await;
    settle(&pm).await;
    assert!(!tried(&banned), "the banned learned host is not");

    // Gossip naming a banned host does not add it.
    let later = host(4);
    ban(&pm, crate::net::ban::BanTarget::Onion(later.clone()));
    let mut announcer = peer(7, SocketAddr::from(([198, 51, 100, 7], 8333)), Direction::Inbound);
    announcer.permissions.addr = true;
    add_peer(&pm, announcer);
    pm.handle_message(7, onion_addrv2(&[(later.clone(), 8333), (host(5), 8333)]), InFlight::adopt(None));
    assert!(!book_holds_onion(&pm, &later), "a banned onion host is not learned");
    assert!(book_holds_onion(&pm, &host(5)), "an open one is");
}

/// `setban <host>.onion` disconnects a connected peer at that onion host, as
/// Core's `setban` disconnects the peers the ban covers. satd matched a ban
/// against peers' IP addresses only, and an onion peer's is the `0.0.0.0`
/// placeholder, so the peer stayed.
#[test]
fn setban_of_an_onion_host_disconnects_that_peer_only() {
    let (pm, _dir) = mk_pm();
    let placeholder = SocketAddr::from(([0, 0, 0, 0], 8333));
    let host = |c: char| format!("{}.onion", c.to_string().repeat(56));
    for (id, h) in [(1, host('a')), (2, host('b'))] {
        let mut info = peer(id, placeholder, Direction::Outbound);
        info.onion_host = Some(h);
        add_peer(&pm, info);
    }
    add_peer(&pm, peer(3, SocketAddr::from(([198, 51, 100, 3], 8333)), Direction::Outbound));
    let now = crate::time::now_secs();
    pm.set_ban_subnet(&crate::net::ban::BanTarget::Onion(host('a')), true, now, now + 3600).unwrap();
    let ids: std::collections::BTreeSet<PeerId> = pm.peers.read().keys().copied().collect();
    assert_eq!(ids, [2, 3].into_iter().collect(), "only the banned onion peer is disconnected");

    // A ban of an IP range does not reach onion peers through their placeholder.
    pm.set_ban_subnet(
        &crate::net::ban::BanTarget::Net("0.0.0.0/8".parse().unwrap()),
        true,
        now,
        now + 3600,
    )
    .unwrap();
    assert!(pm.peers.read().contains_key(&2), "the other onion peer stays");
}

/// A full address book makes room for a new address by dropping a terrible
/// entry (tried three times, never reached), as Core's does, and the dropped
/// address leaves the dial list. satd's book refused every new address once
/// full, for good. With nothing terrible to drop it still refuses.
#[test]
fn a_full_book_replaces_a_terrible_entry() {
    let (pm, _dir) = mk_pm();
    let source = IpAddr::from([198, 51, 100, 1]);
    let full = crate::net::addrman::MAX_ENTRIES;
    // 64 per /16, across enough groups to fill the book.
    let addr_at = |i: usize| SocketAddr::from(([11 + (i / 64 / 256) as u8, ((i / 64) % 256) as u8, 1, (i % 64) as u8 + 1], 8333));
    for i in 0..full {
        pm.add_learned_addr_from(addr_at(i), 9, source);
    }
    assert_eq!(pm.addrman.read().len(), full, "fixture: the book is full");

    let fresh = SocketAddr::from(([99, 1, 1, 1], 8333));
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(!pm.addrman.read().contains(&fresh.into()), "nothing terrible: refused");

    let stale = addr_at(0);
    for _ in 0..3 {
        pm.addrman.write().mark_attempt(&stale.into(), now_unix_secs() - 120);
    }
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(pm.addrman.read().contains(&fresh.into()), "the new address takes the terrible one's place");
    assert!(!pm.addrman.read().contains(&stale.into()));
    assert_eq!(pm.addrman.read().len(), full);
}

/// A failed redial counts as an attempt in the address book: what makes an
/// unreachable address terrible.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_redial_counts_as_an_attempt() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    pm.add_learned_addr_from(addr, 9, IpAddr::from([198, 51, 100, 1]));
    pm.reconnect_tick();
    wait_for(&pm, || pm.reconnect_backoff.read().contains_key(&addr), "the dial fails").await;
    settle(&pm).await;
    let attempts = pm.addrman.read().iter().find(|e| e.addr == addr.into()).map(|e| e.attempts);
    assert_eq!(attempts, Some(1));
}

/// The same within a network group: a full group (64 new addresses) makes
/// room by dropping a terrible entry of that group, and the dropped
/// address's reconnect backoff goes with it.
#[test]
fn a_full_group_replaces_a_terrible_entry_and_its_backoff() {
    let (pm, _dir) = mk_pm();
    let source = IpAddr::from([198, 51, 100, 1]);
    let in_group = |i: u8| SocketAddr::from(([44, 1, 0, i + 1], 8333));
    for i in 0..64 {
        pm.add_learned_addr_from(in_group(i), 9, source);
    }
    let fresh = in_group(100);
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(!pm.addrman.read().contains(&fresh.into()), "nothing terrible: refused");

    let stale = in_group(0);
    for _ in 0..3 {
        pm.addrman.write().mark_attempt(&stale.into(), now_unix_secs() - 120);
    }
    pm.reconnect_backoff.write().insert(stale, ReconnectState::new());
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(pm.addrman.read().contains(&fresh.into()));
    assert!(!pm.addrman.read().contains(&stale.into()));
    assert!(!pm.reconnect_backoff.read().contains_key(&stale), "its backoff is dropped");
}

/// A book full of tried addresses, all unseen for over 30 days, still makes
/// room for a new one: Core keeps its tried table apart from its new one, so
/// tried entries never shut new addresses out.
#[test]
fn a_book_full_of_stale_tried_entries_takes_a_new_address() {
    let (pm, _dir) = mk_pm();
    let full = crate::net::addrman::MAX_ENTRIES;
    let long_ago = crate::time::now_secs() - 31 * 24 * 60 * 60;
    {
        let mut book = pm.addrman.write();
        // A /16 each, so neither table's per-group bound refuses one; an
        // address whose tried slot another took stays new.
        for i in 0..full {
            let a = SocketAddr::from(([11 + (i / 256) as u8, (i % 256) as u8, 1, 1], 8333));
            book.mark_good(a, long_ago);
        }
        assert_eq!(book.len(), full, "fixture: the book is full");
        assert!(book.iter().filter(|e| e.tried).count() > full / 2, "fixture: mostly tried");
    }
    let fresh = SocketAddr::from(([99, 1, 1, 1], 8333));
    pm.add_learned_addr_from(fresh, 9, IpAddr::from([198, 51, 100, 1]));
    assert!(pm.addrman.read().contains(&fresh.into()));
    assert_eq!(pm.addrman.read().len(), full);
}

/// Under `-onlynet`, an automatic dial and a gossiped address both need a
/// reachable network (Core's `g_reachable_nets`); a manual peer does not.
/// Perturbation: drop the reachability test from `may_dial` and the IPv6
/// address is dialable; drop it from `add_learned_addr_from` and it is
/// learned.
#[test]
fn onlynet_gates_automatic_dials_and_gossip_but_not_manual_peers() {
    use crate::net::reachable::ReachableNets;
    let (pm, _dir) = mk_pm();
    pm.set_reachable(ReachableNets { ipv4: true, ipv6: false, onion: false, cjdns: false, cjdns_flip: false });
    let source = IpAddr::from([198, 51, 100, 1]);
    let v4 = SocketAddr::from(([44, 1, 2, 3], 8333));
    let v6: SocketAddr = "[2001:4860::7]:8333".parse().unwrap();

    pm.add_learned_addr_from(v4, 9, source);
    pm.add_learned_addr_from(v6, 9, source);
    assert!(pm.addrman.read().contains(&v4.into()));
    assert!(!pm.addrman.read().contains(&v6.into()), "an unreachable network's address is not kept");

    assert!(pm.may_dial(&v4.into()));
    assert!(!pm.may_dial(&v6.into()), "no automatic dial to an unreachable network");
    pm.manual_addrs.write().insert(v6);
    assert!(pm.may_dial(&v6.into()), "-onlynet does not affect manual connections");

    // Seeds go through the same gate, onion seeds included.
    let v6b: SocketAddr = "[2001:4860::8]:8333".parse().unwrap();
    pm.add_learned_peer_addr(&PeerAddr::Socket(v6b));
    assert!(!pm.addrman.read().contains(&v6b.into()));
    pm.add_learned_peer_addr(&PeerAddr::Onion { host: onion_host(1), port: 8333 });
    assert!(!book_holds_onion(&pm, &onion_host(1)), "onion is not reachable");
}

/// `-onion=0` refuses every `.onion` dial, a manual peer's included, before
/// any proxy is chosen (Core has no `NET_ONION` proxy). Perturbation: drop
/// the check and the dial fails on the missing proxy instead.
#[tokio::test]
async fn onion_zero_refuses_even_a_manual_onion_dial() {
    let (pm, _dir) = mk_pm();
    pm.set_onion_disabled(true);
    let err = pm.dial_onion(&("a".repeat(56) + ".onion"), 8333).await.expect_err("disabled");
    assert!(err.contains("-onion=0"), "{err}");
}

/// A clearnet address book is no reason to skip seeding on a node whose
/// `-onlynet` leaves clearnet out: `addrman_has_reachable` counts only
/// addresses on reachable networks. Perturbation: answer with
/// `!addrman_is_empty()` and the onion-only case reports a reachable book.
#[test]
fn an_address_book_of_unreachable_addresses_does_not_count() {
    use crate::net::reachable::ReachableNets;
    let (pm, _dir) = mk_pm();
    let v4 = SocketAddr::from(([44, 1, 2, 3], 8333));
    pm.add_learned_addr_from(v4, 9, IpAddr::from([198, 51, 100, 1]));
    assert!(!pm.addrman_is_empty());
    assert!(pm.addrman_has_reachable());
    pm.set_reachable(ReachableNets { ipv4: false, ipv6: false, onion: true, cjdns: false, cjdns_flip: false });
    assert!(!pm.addrman_is_empty(), "the clearnet entry is still in the book");
    assert!(!pm.addrman_has_reachable(), "but it is not on a reachable network");
}

// ---- Services an outbound peer states (Core's `SetServices`) ----

/// Dial a listener as an outbound full-relay peer and run our side of the
/// handshake against a remote that states `services`. Returns the
/// handshake's result and the book's services for the address afterwards.
async fn handshake_stating(services: ServiceFlags) -> (Result<VersionMessage, String>, u64) {
    let (pm, _dir) = mk_pm();
    let (result, target) = handshake_as(&pm, ConnType::OutboundFullRelay, services).await;
    let book = pm.addrman.read().iter().find(|e| e.addr == target.into()).map(|e| e.services).unwrap();
    (result, book)
}

/// [`handshake_stating`] for a connection of type `conn_type`, on `pm`,
/// whose book holds the listener's address as a new entry. Returns the
/// handshake's result and the address.
async fn handshake_as(
    pm: &PeerManager,
    conn_type: ConnType,
    services: ServiceFlags,
) -> (Result<VersionMessage, String>, SocketAddr) {
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::address::Address;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    pm.addrman.write().add_from(target, now_unix_secs(), 1 | 8, "198.51.100.7".parse::<IpAddr>().unwrap());
    let (dialed, accepted) = tokio::join!(tokio::net::TcpStream::connect(target), listener.accept());
    let (dialed, (accepted, _)) = (dialed.unwrap(), accepted.unwrap());
    let mut info = peer(1, target, Direction::Outbound);
    info.state = PeerState::Connecting;
    info.conn_type = conn_type;
    add_peer(pm, info);
    let mut ours = Connection::with_magic(dialed, Magic::REGTEST);
    let mut theirs = Connection::with_magic(accepted, Magic::REGTEST);

    let handshake = pm.perform_handshake(1, &mut ours, Direction::Outbound, crate::time::now_secs());
    let remote = async {
        loop {
            if matches!(theirs.recv().await, Ok(NetworkMessage::Version(_)) | Err(_)) {
                break;
            }
        }
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let _ = theirs
            .send(NetworkMessage::Version(VersionMessage {
                version: 70016,
                services,
                timestamp: crate::time::now_secs() as i64,
                receiver: Address::new(&zero, ServiceFlags::NONE),
                sender: Address::new(&zero, services),
                nonce: 0x5eed,
                user_agent: "/remote/".into(),
                start_height: 0,
                relay: true,
            }))
            .await;
        let _ = theirs.send(NetworkMessage::Verack).await;
        // Read until our side verack's or hangs up.
        while let Ok(Ok(msg)) = tokio::time::timeout(Duration::from_secs(2), theirs.recv()).await {
            if matches!(msg, NetworkMessage::Verack) {
                break;
            }
        }
    };
    let (result, ()) = tokio::join!(handshake, remote);
    (result, target)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbound_peers_version_sets_its_addresss_services() {
    let stated = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::from(1 << 30);
    let (result, book) = handshake_stating(stated).await;
    result.expect("the handshake completes");
    assert_eq!(book, stated.to_u64(), "the book holds what the peer stated, not what gossip said");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_dropped_for_lacking_services_is_recorded_as_lacking_them() {
    let (result, book) = handshake_stating(ServiceFlags::WITNESS).await;
    assert!(result.is_err(), "an automatic peer without NODE_NETWORK is dropped");
    assert_eq!(book, ServiceFlags::WITNESS.to_u64());
}

#[test]
fn a_peer_the_book_first_learns_by_connecting_keeps_its_stated_services() {
    use bitcoin::p2p::address::Address;
    // A manual or seed peer: dialled without a book entry, which
    // `mark_good` creates once it connects.
    let (pm, _dir) = mk_pm();
    let target: SocketAddr = "203.0.113.9:18444".parse().unwrap();
    let mut info = peer(1, target, Direction::Outbound);
    info.conn_type = ConnType::Manual;
    add_peer(&pm, info);
    let stated = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::from(1 << 30);
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    pm.handle_peer_connected(
        1,
        VersionMessage {
            version: 70016,
            services: stated,
            timestamp: crate::time::now_secs() as i64,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, stated),
            nonce: 0x5eed,
            user_agent: "/remote/".into(),
            start_height: 0,
            relay: true,
        },
    );
    let book = pm.addrman.read().iter().find(|e| e.addr == target.into()).map(|e| e.services);
    assert_eq!(book, Some(stated.to_u64()));
}

// ---- Onion addresses in the address book (#1157) ----

/// A well-formed v3 onion host for index `i`. The key's first byte is `i`'s
/// low byte, so its top four bits, and with them the onion's network group,
/// follow `i / 16`.
fn onion_host(i: usize) -> String {
    let mut key = [0x5a_u8; 32];
    key[..8].copy_from_slice(&(i as u64).to_le_bytes());
    crate::net::peer::torv3_to_onion_host(&key)
}

/// Put an onion in the address book, as gossip or `peers.dat` would.
fn learn_onion(pm: &PeerManager, host: &str, port: u16) {
    let addr = PeerAddr::Onion { host: host.to_string(), port };
    assert!(pm.addrman.write().add(addr.clone(), now_unix_secs()), "fixture: the book takes {addr}");
}

fn book_holds_onion(pm: &PeerManager, host: &str) -> bool {
    pm.addrman.read().iter().any(|e| matches!(&e.addr, PeerAddr::Onion { host: h, .. } if h == host))
}

/// An `addrv2` announcing `onions` as BIP 155 `TorV3` entries.
fn onion_addrv2(onions: &[(String, u16)]) -> NetworkMessage {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    NetworkMessage::AddrV2(
        onions
            .iter()
            .map(|(host, port)| AddrV2Message {
                time: 1_700_000_000,
                services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                addr: AddrV2::TorV3(crate::net::peer::onion_host_to_torv3_pubkey(host).expect("a v3 onion")),
                port: *port,
            })
            .collect(),
    )
}

/// The onions a reconnect pass would dial now.
fn onions_dialled(pm: &Arc<PeerManager>) -> Vec<PeerAddr> {
    pm.reserve_automatic_dials(Instant::now())
        .into_iter()
        .map(|(a, _slot)| a)
        .filter(PeerAddr::is_onion)
        .collect()
}

/// #1157: an onion learned from gossip goes in the address book, so it is
/// written to `peers.dat` and is there after a restart, with its source and
/// services, for the automatic dials to draw. satd kept the onions it
/// learned on an in-memory list, and a restart forgot every one.
#[test]
fn an_onion_learned_from_gossip_survives_a_restart() {
    let (pm, dir) = mk_pm_tor();
    let announcer = SocketAddr::from(([198, 51, 100, 7], 8333));
    let mut info = peer(7, announcer, Direction::Inbound);
    info.permissions.addr = true;
    add_peer(&pm, info);
    let host = onion_host(1);
    pm.handle_message(7, onion_addrv2(&[(host.clone(), 9333)]), InFlight::adopt(None));
    assert!(book_holds_onion(&pm, &host), "gossip puts the onion in the book");

    let path = dir.path().join("peers.dat");
    pm.dump_addrman(&path);
    let (restarted, _dir2) = mk_pm_tor();
    restarted.load_addrman(&path);
    let entry = restarted
        .addrman_snapshot()
        .into_iter()
        .find(|e| matches!(&e.addr, PeerAddr::Onion { host: h, port: 9333 } if *h == host))
        .expect("the onion is there after a restart");
    assert_eq!(entry.source, crate::net::addrman::NetAddr::Ip(announcer.ip()));
    assert_eq!(entry.services, (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64());
    assert_eq!(restarted.addrman_counts()["onion"].new, 1);

    leave_ibd(&restarted);
    assert_eq!(
        onions_dialled(&restarted),
        vec![PeerAddr::Onion { host, port: 9333 }],
        "and the automatic dials draw it"
    );
}

/// An onion announced by an onion peer has that onion as its source, as a
/// clearnet address announced by it has; one announced by a clearnet peer
/// has the peer's address.
#[test]
fn an_onion_peers_announcements_have_its_onion_as_their_source() {
    let (pm, _dir) = mk_pm_tor();
    let mut via_tor = peer(3, SocketAddr::from(([0, 0, 0, 0], 9333)), Direction::Outbound);
    via_tor.onion_host = Some(onion_host(7));
    via_tor.permissions.addr = true;
    add_peer(&pm, via_tor);
    pm.handle_message(3, onion_addrv2(&[(onion_host(8), 9333)]), InFlight::adopt(None));
    let entry = pm.addrman_snapshot().into_iter().find(|e| e.addr.is_onion()).expect("learned");
    assert_eq!(entry.source.addr_string(), onion_host(7));
    assert_eq!(entry.source.network_name(), "onion");
}

/// An onion is tried like any other address: a dial that connects promotes
/// it to the tried table, keyed by its onion and port rather than the
/// `0.0.0.0` placeholder its peer carries, and records the services its
/// `version` stated. satd skipped onion peers here, as the book could not
/// hold them.
#[test]
fn a_connected_onion_moves_to_tried() {
    use bitcoin::p2p::address::Address;
    let (pm, _dir) = mk_pm_tor();
    let host = onion_host(2);
    learn_onion(&pm, &host, 9333);
    let mut info = peer(1, SocketAddr::from(([0, 0, 0, 0], 9333)), Direction::Outbound);
    info.onion_host = Some(host.clone());
    info.conn_type = ConnType::OutboundFullRelay;
    add_peer(&pm, info);
    let stated = ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS;
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    pm.handle_peer_connected(
        1,
        VersionMessage {
            version: 70016,
            services: stated,
            timestamp: crate::time::now_secs() as i64,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, stated),
            nonce: 0x0e10,
            user_agent: "/remote/".into(),
            start_height: 0,
            relay: true,
        },
    );
    let target = PeerAddr::Onion { host, port: 9333 };
    let book = pm.addrman.read();
    assert!(book.is_tried(&target), "the onion is tried");
    assert_eq!(book.get(&target).map(|e| e.services), Some(stated.to_u64()));
    assert!(!book.contains(&PeerAddr::Socket(SocketAddr::from(([0, 0, 0, 0], 9333)))), "not the placeholder");
}

/// A tried-collision incumbent passes its test only by a connection to the
/// entry itself: for an onion, the same host and port. A peer on another
/// port of the host, a manual twin say, used to count, and kept an untested
/// entry in its tried slot.
#[test]
fn an_onion_twin_on_another_port_does_not_test_the_entry() {
    let (pm, _dir) = mk_pm_tor();
    let host = onion_host(4);
    let mut twin = peer(1, SocketAddr::from(([0, 0, 0, 0], 9444)), Direction::Outbound);
    twin.onion_host = Some(host.clone());
    add_peer(&pm, twin);
    assert!(!pm.is_book_addr_connected(&PeerAddr::Onion { host: host.clone(), port: 9333 }));
    assert!(pm.is_book_addr_connected(&PeerAddr::Onion { host, port: 9444 }));
}

/// The reconnect loop's onion dials count as attempts in the book, which is
/// what makes a dead onion terrible and replaceable there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_onion_dial_counts_against_the_onion() {
    let (pm, _dir) = mk_pm_tor();
    leave_ibd(&pm);
    let host = onion_host(5);
    learn_onion(&pm, &host, 9333);
    pm.reconnect_tick();
    let tried = || pm.onion_reconnect_backoff.read().contains_key(&format!("{host}:9333"));
    wait_for(&pm, tried, "the onion is dialled").await;
    settle(&pm).await;
    let target = PeerAddr::Onion { host, port: 9333 };
    let entry = pm.addrman.read().get(&target).cloned().expect("still in the book");
    assert_eq!(entry.attempts, 1);
    assert_eq!(entry.last_success, 0);
}

/// `-onlynet=onion` draws only onion entries, whatever else `peers.dat`
/// holds, and the onions are drawn from the book with the rest.
#[test]
fn onlynet_onion_draws_only_onion_entries() {
    use crate::net::reachable::ReachableNets;
    let (pm, _dir) = mk_pm_tor();
    pm.set_reachable(ReachableNets { ipv4: false, ipv6: false, onion: true, cjdns: false, cjdns_flip: false });
    leave_ibd(&pm);
    // As `peers.dat` would hold them from before the flag.
    for a in spread(44, 6) {
        learn(&pm, a);
    }
    for i in 0..3 {
        learn_onion(&pm, &onion_host(i * 16), 9333);
    }
    let all: Vec<PeerAddr> =
        pm.reserve_automatic_dials(Instant::now()).into_iter().map(|(a, _slot)| a).collect();
    assert_eq!(all.len(), 3, "{all:?}");
    assert!(all.iter().all(PeerAddr::is_onion), "only onions: {all:?}");
}

/// Without a proxy that reaches Tor, the onions in the book are not dialled
/// (Core leaves `NET_ONION` out of its reachable networks then): a book
/// written while the node had a proxy can hold them.
#[test]
fn onions_in_the_book_wait_for_a_proxy() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    assert!(pm.addrman.write().add(PeerAddr::Onion { host: onion_host(1), port: 9333 }, now_unix_secs()));
    assert!(onions_dialled(&pm).is_empty());

    let (tor, _dir) = mk_pm_tor();
    leave_ibd(&tor);
    learn_onion(&tor, &onion_host(1), 9333);
    tor.set_onion_disabled(true);
    assert!(onions_dialled(&tor).is_empty(), "nor under -onion=0");
}

/// Each onion dial holds a circuit through the one proxy, so a pass starts
/// at most [`MAX_ONION_DIALS_PER_TICK`] of them however many slots are open
/// (64 in IBD) and however many onions the book holds.
#[test]
fn a_pass_starts_a_bounded_burst_of_onion_dials() {
    let (pm, _dir) = mk_pm_tor();
    assert!(pm.is_ibd(), "fixture: in IBD, 64 automatic slots");
    for i in 0..40 {
        learn_onion(&pm, &onion_host(i), 9333);
    }
    assert_eq!(onions_dialled(&pm).len(), MAX_ONION_DIALS_PER_TICK);
}

/// The onion dials follow the rule clearnet ones do: an onion peer that hung
/// up just after the handshake was dialled again on the next tick, since a
/// dial that connected cleared its backoff.
#[test]
fn an_onion_dial_passes_over_a_peer_it_just_tried() {
    let (pm, _dir) = mk_pm_tor();
    leave_ibd(&pm);
    // Seven of the eight automatic slots taken: room for one onion dial.
    fill_automatic(&pm, MAX_OUTBOUND - 1);
    let onions: Vec<PeerAddr> = (0..3).map(|i| PeerAddr::Onion { host: onion_host(i), port: 8333 }).collect();
    for o in &onions {
        assert!(pm.addrman.write().add(o.clone(), now_unix_secs()));
    }
    let tried_now = || ReconnectState { attempts: 0, next_attempt: Instant::now(), last_try: Some(Instant::now()) };
    {
        let mut backoff = pm.onion_reconnect_backoff.write();
        for o in &onions[..2] {
            backoff.insert(o.to_string(), tried_now());
        }
    }
    assert_eq!(onions_dialled(&pm), vec![onions[2].clone()], "the one not tried lately");

    // Tried lately, all of them: there is nothing else, so one is dialled.
    pm.onion_reconnect_backoff.write().insert(onions[2].to_string(), tried_now());
    assert_eq!(onions_dialled(&pm).len(), 1);
}

/// A manual onion stays off the book, as a manual clearnet peer does until
/// it connects; one on another port of a learned onion leaves the learned
/// entry alone when it is removed.
#[test]
fn removing_a_manual_twin_keeps_the_learned_onion() {
    let (pm, _dir) = mk_pm_tor();
    let host = onion_host(3);
    learn_onion(&pm, &host, 9333);
    let twin = PeerAddr::Onion { host: host.clone(), port: 9444 };
    assert!(pm.add_peer_addr(twin.clone()));
    assert!(!pm.addrman.read().contains(&twin), "a named onion is not a book entry");
    assert!(pm.manual_onion_addrs.read().contains(&twin));
    assert!(pm.remove_peer_addr(&twin));
    assert!(!pm.manual_onion_addrs.read().contains(&twin));
    assert!(pm.addrman.read().contains(&PeerAddr::Onion { host, port: 9333 }), "the learned entry stays");
}

/// A dial to an onion that left the book while it ran leaves no backoff
/// behind, as for a clearnet address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_onion_dropped_mid_dial_leaves_no_backoff() {
    let (pm, _dir) = mk_pm_tor();
    leave_ibd(&pm);
    let gone = PeerAddr::Onion { host: onion_host(8), port: 9333 };
    let slot = pm.reserve_dial(DialBudget::Automatic).unwrap();
    pm.spawn_redial(gone.clone(), slot, AUTOMATIC_RECONNECT_MAX_BACKOFF);
    settle(&pm).await;
    assert!(!pm.onion_reconnect_backoff.read().contains_key(&gone.to_string()));
    // One in the book gets its backoff, as before.
    let listed = onion_host(9);
    learn_onion(&pm, &listed, 9333);
    pm.reconnect_tick();
    let key = format!("{listed}:9333");
    wait_for(&pm, || pm.onion_reconnect_backoff.read().contains_key(&key), "the listed onion backs off").await;
}

// ---- Feelers (#1149) ----

/// Make the feeler timer due.
fn feeler_due(pm: &PeerManager) {
    *pm.next_feeler.lock() = Instant::now() - Duration::from_secs(1);
}

/// The address a feeler would test now, the timer made due first. The
/// grant goes back at the end of this call.
fn feeler_target(pm: &Arc<PeerManager>) -> Option<PeerAddr> {
    feeler_due(pm);
    pm.reserve_feeler(Instant::now()).map(|(target, _grant)| target)
}

/// #1149: Core opens a feeler only once the outbound targets are met, its
/// timer checked in the `else if` after them. One short of the target, the
/// slot goes to a full-relay dial and the timer is left as it is.
#[test]
fn no_feeler_while_the_automatic_target_is_unmet() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    learn(&pm, SocketAddr::from(([44, 1, 2, 3], 8333)));
    fill_automatic(&pm, 7);
    feeler_due(&pm);
    let due = *pm.next_feeler.lock();
    assert_eq!(pm.reserve_feeler(Instant::now()).map(|(t, _)| t), None);
    assert_eq!(*pm.next_feeler.lock(), due, "the timer waits for the target");

    fill_automatic(&pm, 8);
    assert_eq!(feeler_target(&pm), Some(SocketAddr::from(([44, 1, 2, 3], 8333)).into()));
}

/// The timer is set again by each feeler, to a time drawn around Core's
/// two-minute mean: the next pass opens none.
#[test]
fn a_feeler_sets_the_timer_again() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    learn(&pm, SocketAddr::from(([44, 1, 2, 3], 8333)));
    fill_automatic(&pm, 8);
    assert!(feeler_target(&pm).is_some());
    let now = Instant::now();
    assert!(*pm.next_feeler.lock() > now - Duration::from_millis(100));
    assert!(pm.reserve_feeler(now).is_none(), "not due again yet");
}

/// A feeler draws from the new table alone (Core's `Select(true)`), and
/// the network group of a peer the node already holds is no reason to skip
/// one, as it is for every other automatic dial.
#[test]
fn a_feeler_tests_a_new_entry_in_any_group() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 7);
    add_peer(&pm, peer(1, SocketAddr::from(([44, 1, 0, 1], 8333)), Direction::Outbound));
    let tried = SocketAddr::from(([45, 1, 2, 3], 8333));
    // In the group of a peer the node holds, 44.1.0.0/16.
    let fresh = SocketAddr::from(([44, 1, 9, 9], 8333));
    {
        let mut book = pm.addrman.write();
        assert!(book.mark_good(tried, now_unix_secs()));
        assert!(book.add(fresh, now_unix_secs()));
    }
    assert!(pm.reserve_automatic_dials(Instant::now()).is_empty(), "fixture: the target is met");
    for _ in 0..20 {
        assert_eq!(feeler_target(&pm), Some(fresh.into()));
    }
}

/// A feeler needs only the services that make a peer's address book worth
/// having: `NODE_NETWORK` or `NODE_NETWORK_LIMITED` (Core's
/// `MayHaveUsefulAddressDB`), not every desirable one.
#[test]
fn a_feeler_needs_only_a_useful_address_book() {
    let source: IpAddr = "198.51.100.7".parse().unwrap();
    let limited = SocketAddr::from(([44, 1, 2, 3], 8333));
    let neither = SocketAddr::from(([45, 1, 2, 3], 8333));
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 8);
    let now = now_unix_secs();
    assert!(pm.addrman.write().add_from(neither, now, ServiceFlags::WITNESS.to_u64(), source));
    assert_eq!(feeler_target(&pm), None, "no address book worth testing");
    let services = (ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS).to_u64();
    assert!(pm.addrman.write().add_from(limited, now, services, source));
    assert_eq!(feeler_target(&pm), Some(limited.into()));
}

/// A feeler takes no slot of the automatic target: Core sizes `semOutbound`
/// with one place for it. With a feeler open, a dropped full-relay peer is
/// still replaced.
#[test]
fn a_feeler_takes_no_automatic_slot() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 7);
    let mut feeler = peer(1, SocketAddr::from(([44, 1, 2, 3], 8333)), Direction::Outbound);
    feeler.conn_type = ConnType::Feeler;
    feeler.state = PeerState::Connecting;
    add_peer(&pm, feeler);
    pm.pending_typed_dials.write().push(ConnType::Feeler);
    assert!(pm.reserve_dial(DialBudget::Automatic).is_ok());
}

/// A feeler's `version` moves its address to tried (Core's `Good`, before
/// the feeler is dropped), and the connection closes without a verack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feeler_moves_a_new_entry_to_tried() {
    let (pm, _dir) = mk_pm();
    let (result, target) = handshake_as(&pm, ConnType::Feeler, ServiceFlags::NETWORK | ServiceFlags::WITNESS).await;
    assert!(result.unwrap_err().contains("feeler"), "closed after version");
    assert!(pm.addrman.read().is_tried(&target.into()));
    assert!(pm.peers.read().is_empty(), "the feeler is gone");
}

/// The reconnect loop opens the feeler, and one that finds nothing
/// listening counts an attempt against the address, as a failed automatic
/// dial does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_feeler_counts_an_attempt() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    fill_automatic(&pm, 8);
    let closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    learn(&pm, closed);
    feeler_due(&pm);
    pm.reconnect_tick();
    let tried = || pm.reconnect_backoff.read().contains_key(&closed);
    wait_for(&pm, tried, "the feeler dials").await;
    let entry = pm.addrman.read().get(&closed.into()).cloned().expect("still in the book");
    assert_eq!(entry.attempts, 1);
    assert!(!pm.addrman.read().is_tried(&closed.into()));
    assert!(pm.pending_typed_dials.read().is_empty(), "the grant went back");
}
