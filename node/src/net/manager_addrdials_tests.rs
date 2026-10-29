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
/// and onto the dial list per message. A peer with the `addr` permission is
/// not limited, as in Core.
#[test]
fn a_peers_addresses_are_rate_limited_unless_it_has_the_addr_permission() {
    let (pm, _dir) = mk_pm();
    let limited = SocketAddr::from(([127, 0, 0, 1], 40001));
    add_peer(&pm, peer(1, limited, Direction::Inbound));
    pm.handle_message(1, addr_msg(&spread(1, 1000)), InFlight::adopt(None));
    assert_eq!(addr_counts(&pm, 1), (1, 999), "one token: one address processed, the rest rate-limited");
    assert_eq!(pm.addrman.read().len(), 1, "one address reached the address book");
    assert_eq!(pm.learned_addrs.read().iter().count(), 1, "and the dial list");

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

// ---- The automatic dial list ----

/// Only an address the address book holds goes on the dial list. The book
/// keeps at most 64 new addresses per network group; satd put every
/// gossiped address on the dial list whether the book took it or not.
#[test]
fn an_address_the_book_has_no_room_for_is_not_dialled() {
    let (pm, _dir) = mk_pm();
    let source = IpAddr::from([198, 51, 100, 1]);
    let one_group: Vec<SocketAddr> =
        (0..100).map(|i| SocketAddr::from(([44, 1, (i / 250) as u8, (i % 250) as u8 + 1], 8333))).collect();
    for a in &one_group {
        pm.add_learned_addr_from(*a, 9, source);
    }
    let book = pm.addrman.read().len();
    assert_eq!(book, 64, "fixture: the book's per-group limit");
    assert_eq!(pm.learned_addrs.read().iter().count(), 64, "the dial list holds what the book holds");
    for a in &one_group[..64] {
        assert!(pm.learned_addrs.read().contains(a));
    }
    // An address the book already holds, announced again, stays listed once.
    pm.add_learned_addr_from(one_group[0], 9, source);
    assert_eq!(pm.learned_addrs.read().iter().count(), 64);
}

/// The list holds each address once and stops at its cap.
#[test]
fn the_dial_list_stops_at_its_cap() {
    let mut list = LearnedAddrs::default();
    let all: Vec<SocketAddr> = (0..=MAX_LEARNED_ADDRS as u32)
        .map(|i| SocketAddr::from((std::net::Ipv4Addr::from(0x0b00_0000 + i), 8333)))
        .collect();
    for a in &all[..MAX_LEARNED_ADDRS] {
        assert!(list.push(*a));
    }
    assert!(!list.push(all[0]), "a duplicate is refused");
    assert!(!list.push(all[MAX_LEARNED_ADDRS]), "past the cap is refused");
    assert_eq!(list.iter().count(), MAX_LEARNED_ADDRS);
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
        pm.learned_addrs.write().push(l.addr);
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
    pm.learned_addrs.write().push(l.addr);
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
    pm.learned_addrs.write().push(learned.addr);
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
/// or a ban for misbehaviour, did not stop automatic dials to it. With no
/// proxy here every onion dial fails, which records a backoff entry: that
/// entry is the trace of a dial attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_banned_onion_host_is_neither_learned_nor_dialled_automatically() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let host = |c: char| format!("{}.onion", c.to_string().repeat(56));
    let (banned, open, named) = (host('a'), host('b'), host('c'));

    // Learned before the ban, so only the reconnect loop can hold it back.
    pm.add_onion_connect_addr(banned.clone(), 8333);
    pm.add_onion_connect_addr(open.clone(), 8333);
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
    let later = host('d');
    ban(&pm, crate::net::ban::BanTarget::Onion(later.clone()));
    pm.add_onion_connect_addr(later.clone(), 8333);
    pm.add_onion_connect_addr(host('e'), 8333);
    let listed = |h: &str| {
        pm.connect_peer_addrs.read().iter().any(|a| matches!(a, PeerAddr::Onion { host, .. } if host == h))
    };
    assert!(!listed(&later), "a banned onion host is not learned");
    assert!(listed(&host('e')), "an open one is");
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
    assert!(!pm.addrman.read().contains(&fresh), "nothing terrible: refused");

    let stale = addr_at(0);
    for _ in 0..3 {
        pm.addrman.write().mark_attempt(stale, now_unix_secs() - 120);
    }
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(pm.addrman.read().contains(&fresh), "the new address takes the terrible one's place");
    assert!(!pm.addrman.read().contains(&stale));
    assert_eq!(pm.addrman.read().len(), full);
    assert!(pm.learned_addrs.read().contains(&fresh), "and is dialled");
    assert!(!pm.learned_addrs.read().contains(&stale), "the dropped one is not");
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
    let attempts = pm.addrman.read().iter().find(|e| e.addr == addr).map(|e| e.attempts);
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
    assert!(!pm.addrman.read().contains(&fresh), "nothing terrible: refused");

    let stale = in_group(0);
    for _ in 0..3 {
        pm.addrman.write().mark_attempt(stale, now_unix_secs() - 120);
    }
    pm.reconnect_backoff.write().insert(stale, ReconnectState::new());
    pm.add_learned_addr_from(fresh, 9, source);
    assert!(pm.addrman.read().contains(&fresh));
    assert!(!pm.addrman.read().contains(&stale));
    assert!(pm.learned_addrs.read().contains(&fresh));
    assert!(!pm.learned_addrs.read().contains(&stale));
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
    assert!(pm.addrman.read().contains(&fresh));
    assert!(pm.learned_addrs.read().contains(&fresh));
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
    assert!(pm.learned_addrs.read().contains(&v4));
    assert!(!pm.learned_addrs.read().contains(&v6), "an unreachable network's address is not kept");
    assert!(!pm.addrman.read().contains(&v6));

    assert!(pm.may_dial(&v4));
    assert!(!pm.may_dial(&v6), "no automatic dial to an unreachable network");
    pm.manual_addrs.write().insert(v6);
    assert!(pm.may_dial(&v6), "-onlynet does not affect manual connections");

    // Seeds go through the same gate, and onion candidates need onion.
    let v6b: SocketAddr = "[2001:4860::8]:8333".parse().unwrap();
    pm.add_learned_peer_addr(&PeerAddr::Socket(v6b));
    assert!(!pm.learned_addrs.read().contains(&v6b));
    pm.add_learned_peer_addr(&PeerAddr::Onion { host: "a".repeat(56) + ".onion", port: 8333 });
    assert!(pm.connect_peer_addrs.read().is_empty(), "onion is not reachable");
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
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::address::Address;

    let (pm, _dir) = mk_pm();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    pm.addrman.write().add_from(target, now_unix_secs(), 1 | 8, "198.51.100.7".parse().unwrap());
    let (dialed, accepted) = tokio::join!(tokio::net::TcpStream::connect(target), listener.accept());
    let (dialed, (accepted, _)) = (dialed.unwrap(), accepted.unwrap());
    let mut info = peer(1, target, Direction::Outbound);
    info.state = PeerState::Connecting;
    info.conn_type = ConnType::OutboundFullRelay;
    add_peer(&pm, info);
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
    let book = pm.addrman.read().iter().find(|e| e.addr == target).map(|e| e.services).unwrap();
    (result, book)
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
    let book = pm.addrman.read().iter().find(|e| e.addr == target).map(|e| e.services);
    assert_eq!(book, Some(stated.to_u64()));
}

/// A distinct 56-character onion host for index `i`.
fn onion_host(i: usize) -> String {
    format!("{i:0>56}.onion")
}

fn onions_listed(pm: &PeerManager) -> usize {
    pm.connect_peer_addrs.read().iter().filter(|a| a.is_onion()).count()
}

/// #1120: one source's `getaddr` answer used to fill the onion list on its
/// first message and keep every later onion out for the life of the
/// process. A source now holds at most its share, and the next source's
/// onions are still learned.
#[test]
fn one_source_cannot_fill_the_onion_list() {
    let (pm, _dir) = mk_pm();
    let source = Some(b"g\x2c\x01".to_vec());
    for i in 0..MAX_ONION_CONNECT_ADDRS + 10 {
        pm.add_onion_candidate(onion_host(i), 9333, source.clone());
    }
    assert_eq!(onions_listed(&pm), MAX_ONION_ADDRS_PER_SOURCE);
    let other = Some(b"g\x2d\x01".to_vec());
    pm.add_onion_candidate(onion_host(10_000), 9333, other);
    assert_eq!(onions_listed(&pm), MAX_ONION_ADDRS_PER_SOURCE + 1, "another source's onion is learned");
    // A seed counts against no source.
    pm.add_onion_connect_addr(onion_host(10_001), 9333);
    assert_eq!(onions_listed(&pm), MAX_ONION_ADDRS_PER_SOURCE + 2);
}

/// #1120: a full list of onions that never answered makes room for a new
/// one, as Core's `AddSingle` overwrites a terrible entry; while none is
/// terrible, the new one is refused. A peer the operator named is never
/// the one dropped.
#[test]
fn a_full_list_of_dead_onions_makes_room_for_a_new_one() {
    let (pm, _dir) = mk_pm();
    let named = PeerAddr::Onion { host: onion_host(99_999), port: 9333 };
    assert!(pm.add_peer_addr(named.clone()));
    let sources = MAX_ONION_CONNECT_ADDRS / MAX_ONION_ADDRS_PER_SOURCE;
    for i in 0..MAX_ONION_CONNECT_ADDRS - 1 {
        let source = Some(vec![b'g', (i % sources) as u8]);
        pm.add_onion_candidate(onion_host(i), 9333, source);
    }
    assert_eq!(pm.connect_peer_addrs.read().len(), MAX_ONION_CONNECT_ADDRS, "fixture: full");
    // A learned onion the operator then names is manual from then on.
    let renamed = PeerAddr::Onion { host: onion_host(1), port: 9333 };
    assert!(!pm.add_peer_addr(renamed.clone()), "already listed");

    let fresh = onion_host(50_000);
    pm.add_onion_candidate(fresh.clone(), 9333, Some(b"gnew".to_vec()));
    let listed = |h: &str| {
        pm.connect_peer_addrs.read().iter().any(|a| matches!(a, PeerAddr::Onion { host, .. } if host == h))
    };
    assert!(!listed(&fresh), "nothing terrible: refused");

    // Every learned onion fails three dials and never connects.
    for i in 0..MAX_ONION_CONNECT_ADDRS - 1 {
        let target = PeerAddr::Onion { host: onion_host(i), port: 9333 };
        pm.onion_reconnect_backoff.write().insert(target.to_string(), ReconnectState::new());
        for _ in 0..3 {
            pm.note_onion_dial(&onion_host(i), false);
        }
    }
    pm.add_onion_candidate(fresh.clone(), 9333, Some(b"gnew".to_vec()));
    assert!(!listed(&fresh), "within a minute of their last dial, none is terrible yet");
    // One that failed as often but connected once is not terrible.
    pm.note_onion_dial(&onion_host(0), true);
    pm.note_onion_dial(&onion_host(0), false);
    pm.note_onion_dial(&onion_host(0), false);
    // Past Core's minute of grace after the last dial.
    let fresh_tries: Vec<String> = pm.onion_candidates.read().keys().cloned().collect();
    {
        let mut candidates = pm.onion_candidates.write();
        for h in &fresh_tries {
            candidates.get_mut(h).unwrap().last_try -= 120;
        }
    }

    pm.add_onion_candidate(fresh.clone(), 9333, Some(b"gnew".to_vec()));
    assert!(listed(&fresh), "a dead onion gave up its place");
    assert_eq!(pm.connect_peer_addrs.read().len(), MAX_ONION_CONNECT_ADDRS);
    assert!(listed(&onion_host(0)), "an onion that once connected stays");
    assert!(!listed(&onion_host(2)), "the first dead one went");
    assert!(!pm.onion_candidates.read().contains_key(&onion_host(2)));
    assert!(
        !pm.onion_reconnect_backoff.read().contains_key(&format!("{}:9333", onion_host(2))),
        "its backoff went with it"
    );
    assert!(pm.connect_peer_addrs.read().contains(&named), "the named peer stays");
    assert!(pm.connect_peer_addrs.read().contains(&renamed), "and so does the renamed one");

    // Room is made one entry at a time, and only from what is terrible.
    for i in 0..MAX_ONION_CONNECT_ADDRS {
        pm.add_onion_candidate(onion_host(60_000 + i), 9333, Some(vec![b'h', (i % sources) as u8]));
    }
    assert_eq!(pm.connect_peer_addrs.read().len(), MAX_ONION_CONNECT_ADDRS);
    assert!(listed(&onion_host(0)) && pm.connect_peer_addrs.read().contains(&named));
    assert!(pm.connect_peer_addrs.read().contains(&renamed));
}

/// The source of an announced onion: a clearnet announcer's network group,
/// or an onion announcer's own host.
#[test]
fn an_onions_source_is_the_announcers_group_or_its_host() {
    let (pm, _dir) = mk_pm();
    add_peer(&pm, peer(1, SocketAddr::from(([44, 1, 2, 3], 8333)), Direction::Outbound));
    add_peer(&pm, peer(2, SocketAddr::from(([44, 1, 9, 9], 8333)), Direction::Outbound));
    let mut via_tor = peer(3, SocketAddr::from(([0, 0, 0, 0], 0)), Direction::Outbound);
    via_tor.onion_host = Some(onion_host(7));
    add_peer(&pm, via_tor);
    assert_eq!(pm.onion_source(1), pm.onion_source(2), "one /16, one source");
    assert_ne!(pm.onion_source(3), pm.onion_source(1));
    assert_eq!(pm.onion_source(3), [b"o".as_slice(), onion_host(7).as_bytes()].concat());
    // A peer gone mid-message is a source of its own, not an unbounded one.
    assert_ne!(pm.onion_source(42), pm.onion_source(43));
    assert_eq!(pm.onion_source(42), pm.onion_source(42));
}

/// The reconnect loop's onion dials feed the record that decides whether an
/// onion is terrible. With no proxy here every onion dial fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_onion_dial_counts_against_the_onion() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let host = onion_host(5);
    pm.add_onion_candidate(host.clone(), 9333, Some(b"g\x2c\x01".to_vec()));
    pm.reconnect_tick();
    let tried = || pm.onion_reconnect_backoff.read().contains_key(&format!("{host}:9333"));
    wait_for(&pm, tried, "the onion is dialled").await;
    settle(&pm).await;
    assert_eq!(pm.onion_candidates.read()[&host].attempts, 1);
    assert_eq!(pm.onion_candidates.read()[&host].last_success, 0);
}

/// A manual onion on another port of a learned host shares the host's
/// record; removing it must leave the learned entry's record, or that entry
/// could never become terrible and would hold its place for good.
#[test]
fn removing_a_manual_twin_keeps_the_learned_onions_record() {
    let (pm, _dir) = mk_pm();
    let host = onion_host(3);
    pm.add_onion_candidate(host.clone(), 9333, Some(b"g\x2c\x01".to_vec()));
    let twin = PeerAddr::Onion { host: host.clone(), port: 9444 };
    assert!(pm.add_peer_addr(twin.clone()));
    assert!(pm.remove_peer_addr(&twin));
    assert!(pm.onion_candidates.read().contains_key(&host));
    // With the last entry for the host gone, the record goes too.
    assert!(pm.remove_peer_addr(&PeerAddr::Onion { host: host.clone(), port: 9333 }));
    assert!(!pm.onion_candidates.read().contains_key(&host));
}

/// A dial to an onion that left the list while it ran leaves no backoff
/// behind, as for a clearnet address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_onion_dropped_mid_dial_leaves_no_backoff() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let gone = PeerAddr::Onion { host: onion_host(8), port: 9333 };
    let slot = pm.reserve_dial(DialBudget::Automatic).unwrap();
    pm.spawn_redial(gone.clone(), slot, AUTOMATIC_RECONNECT_MAX_BACKOFF);
    settle(&pm).await;
    assert!(!pm.onion_reconnect_backoff.read().contains_key(&gone.to_string()));
    // A listed one gets its backoff, as before.
    let listed = onion_host(9);
    pm.add_onion_candidate(listed.clone(), 9333, None);
    pm.reconnect_tick();
    let key = format!("{listed}:9333");
    wait_for(&pm, || pm.onion_reconnect_backoff.read().contains_key(&key), "the listed onion backs off").await;
}
