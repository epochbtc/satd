//! Outbound peer diversity and the outbound full-relay count: one automatic
//! outbound peer per network group (Core's `ThreadOpenConnections`,
//! `net.cpp`), and the surplus outbound peers of initial block download
//! disconnected one at a time once the target drops (Core's
//! `EvictExtraOutboundPeers`, `net_processing.cpp`).

use super::*;
use bitcoin::hashes::Hash;

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
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    (PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx), dir)
}

/// Out of IBD: a peer has announced a headers tip the node's tip is within
/// 24 of, so the automatic outbound target is 8.
fn leave_ibd(pm: &PeerManager) {
    pm.headers_tip.store(1, Ordering::Relaxed);
    assert!(!pm.is_ibd(), "fixture: out of IBD");
    assert_eq!(pm.automatic_outbound_target(), MAX_OUTBOUND);
}

/// In IBD: the best header is far ahead of the tip, so the target is 64.
fn enter_ibd(pm: &PeerManager) {
    pm.headers_tip.store(1000, Ordering::Relaxed);
    assert!(pm.is_ibd(), "fixture: in IBD");
    assert_eq!(pm.automatic_outbound_target(), MAX_OUTBOUND_IBD);
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

/// A connected outbound peer of `conn_type`, connected for a minute, past
/// Core's `MINIMUM_CONNECT_TIME`.
fn outbound(id: PeerId, addr: SocketAddr, conn_type: ConnType) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr, Direction::Outbound);
    info.state = PeerState::Connected;
    info.conn_type = conn_type;
    info.conn_time -= Duration::from_secs(60);
    info
}

/// An address in a /16 of its own for each `i`, all routable.
fn own_group(i: usize) -> SocketAddr {
    SocketAddr::from(([60 + (i / 200) as u8, (i % 200) as u8, 1, 1], 8333))
}

/// `n` addresses in the one /16 44.1.0.0/16.
fn one_group(n: usize) -> Vec<SocketAddr> {
    (0..n).map(|i| SocketAddr::from(([44, 1, (i / 250) as u8, (i % 250) as u8 + 1], 8333))).collect()
}

fn in_44_1(addr: &SocketAddr) -> bool {
    matches!(addr.ip(), IpAddr::V4(v4) if v4.octets()[..2] == [44, 1])
}

fn learn(pm: &PeerManager, addrs: &[SocketAddr]) {
    let mut learned = pm.learned_addrs.write();
    for a in addrs {
        learned.push(*a);
    }
}

fn dialled(pm: &Arc<PeerManager>) -> Vec<SocketAddr> {
    // The slots go back when the reservations drop at the end of this call.
    pm.reserve_automatic_dials(Instant::now()).into_iter().map(|(a, _slot)| a).collect()
}

fn full_relay_count(pm: &PeerManager) -> usize {
    pm.peers
        .read()
        .values()
        .filter(|h| h.info.conn_type == ConnType::OutboundFullRelay)
        .count()
}

// ---- One automatic outbound peer per network group ----

/// Twenty learned addresses in one /16, listed first, and others each in a
/// /16 of its own: a pass with a target of 8 dials one address in that /16
/// and fills the rest from the other groups. satd walked the list in order
/// and dialled the first eight, all in the one /16.
#[test]
fn a_dial_pass_takes_one_address_per_network_group() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let crowded = one_group(20);
    learn(&pm, &crowded);
    learn(&pm, &(0..10).map(own_group).collect::<Vec<_>>());

    let dials = dialled(&pm);
    assert_eq!(dials.len(), MAX_OUTBOUND, "every slot is filled: {dials:?}");
    assert_eq!(dials.iter().filter(|a| in_44_1(a)).count(), 1, "one dial in 44.1.0.0/16: {dials:?}");
    let groups: HashSet<[u8; 2]> = dials
        .iter()
        .map(|a| match a.ip() {
            IpAddr::V4(v4) => [v4.octets()[0], v4.octets()[1]],
            IpAddr::V6(_) => unreachable!(),
        })
        .collect();
    assert_eq!(groups.len(), dials.len(), "no two dials share a /16");
}

/// The partner: with a learned address in each of eight groups, a pass
/// dials all eight. The rule takes nothing but a second peer in a group.
#[test]
fn a_dial_pass_fills_every_slot_from_distinct_groups() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let addrs: Vec<SocketAddr> = (0..MAX_OUTBOUND).map(own_group).collect();
    learn(&pm, &addrs);
    let mut dials = dialled(&pm);
    dials.sort();
    assert_eq!(dials, addrs);
}

/// A manual, full-relay or block-relay-only peer holds its group, as Core
/// collects `outbound_ipv46_peer_netgroups`; an inbound peer and a feeler
/// do not.
#[test]
fn outbound_peers_hold_their_group_and_inbound_peers_and_feelers_do_not() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let held = [
        (SocketAddr::from(([44, 1, 9, 9], 8333)), ConnType::Manual),
        (SocketAddr::from(([45, 1, 9, 9], 8333)), ConnType::OutboundFullRelay),
        (SocketAddr::from(([46, 1, 9, 9], 8333)), ConnType::BlockRelay),
    ];
    for (i, (addr, conn_type)) in held.iter().enumerate() {
        add_peer(&pm, outbound(i as PeerId + 1, *addr, *conn_type));
    }
    let mut inbound = PeerInfo::new(10, SocketAddr::from(([47, 1, 9, 9], 50000)), Direction::Inbound);
    inbound.state = PeerState::Connected;
    add_peer(&pm, inbound);
    add_peer(&pm, outbound(11, SocketAddr::from(([48, 1, 9, 9], 8333)), ConnType::Feeler));

    let candidates: Vec<SocketAddr> =
        [44u8, 45, 46, 47, 48].iter().map(|b| SocketAddr::from(([*b, 1, 1, 1], 8333))).collect();
    learn(&pm, &candidates);
    // Automatic dials are drawn at random from the book, so compare sets.
    let mut dials = dialled(&pm);
    dials.sort();
    assert_eq!(dials, candidates[3..].to_vec(), "only the inbound and feeler groups are free");
}

/// A dial still in flight holds its group: dials run in parallel, so a
/// later pass must not start a second one in the group.
#[test]
fn a_dial_in_flight_holds_its_group() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    pm.pending_connections.write().insert(SocketAddr::from(([44, 1, 200, 1], 8333)));
    learn(&pm, &one_group(5));
    learn(&pm, &[own_group(0)]);
    assert_eq!(dialled(&pm), vec![own_group(0)]);
}

/// The group is the address book's, so `-asmap` groups by ASN: with every
/// address mapped to one AS, one is dialled.
#[test]
fn the_rule_uses_the_address_books_groups() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    pm.set_addrman_group_fn(Box::new(|_| vec![0xA0, 0, 0, 0, 1]));
    learn(&pm, &(0..10).map(own_group).collect::<Vec<_>>());
    assert_eq!(dialled(&pm).len(), 1);
}

/// Addresses that are not publicly routable reach the dial list on regtest
/// only, where local nodes find each other; Core's book never holds one, so
/// Core never dials one automatically. They are left out of the rule:
/// twenty loopback addresses fill all eight slots, with a manual peer on
/// loopback too.
#[test]
fn local_and_private_addresses_are_outside_the_rule() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    add_peer(&pm, outbound(1, SocketAddr::from(([127, 0, 0, 1], 18444)), ConnType::Manual));
    let local: Vec<SocketAddr> = (0..20).map(|i| SocketAddr::from(([127, 0, 0, 1], 20000 + i))).collect();
    learn(&pm, &local);
    assert_eq!(dialled(&pm).len(), MAX_OUTBOUND);

    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let private: Vec<SocketAddr> = (0..20).map(|i| SocketAddr::from(([10, 0, 0, i as u8 + 1], 18444))).collect();
    learn(&pm, &private);
    assert_eq!(dialled(&pm).len(), MAX_OUTBOUND);
}

// ---- Surplus outbound peers after IBD ----

/// `n` connected full-relay peers, ids 100.., each in a group of its own;
/// peer `100 + i` last announced a block at time `1000 + i`.
fn full_relay_peers(pm: &PeerManager, n: usize) {
    for i in 0..n {
        let mut info = outbound(100 + i as PeerId, own_group(i), ConnType::OutboundFullRelay);
        info.last_block_announcement = 1000 + i as u64;
        add_peer(pm, info);
    }
}

/// A node that reached more than 8 outbound full-relay peers during IBD
/// is back at 8 within a bounded number of passes once IBD ends, one peer
/// a pass, the peer that least recently announced a block first. satd had
/// nothing that closed them.
#[test]
fn surplus_outbound_peers_are_trimmed_to_eight_after_ibd() {
    let (pm, _dir) = mk_pm();
    enter_ibd(&pm);
    full_relay_peers(&pm, 20);
    assert_eq!(pm.evict_extra_outbound_peer(), None, "20 of 64 is no surplus");

    leave_ibd(&pm);
    let mut evicted = Vec::new();
    for _ in 0..20 {
        if let Some(id) = pm.evict_extra_outbound_peer() {
            evicted.push(id);
        }
        if full_relay_count(&pm) <= MAX_OUTBOUND {
            break;
        }
    }
    assert_eq!(full_relay_count(&pm), MAX_OUTBOUND, "back to the target");
    assert_eq!(evicted, (100..112).collect::<Vec<PeerId>>(), "oldest announcement first, one per pass");
    assert_eq!(pm.evict_extra_outbound_peer(), None, "and no further");
}

/// Manual and block-relay-only connections are never trimmed, and do not
/// count toward the full-relay surplus.
#[test]
fn manual_and_block_relay_peers_are_not_trimmed() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    full_relay_peers(&pm, 10);
    for i in 0..5 {
        add_peer(&pm, outbound(200 + i, own_group(50 + i as usize), ConnType::Manual));
    }
    for i in 0..2 {
        add_peer(&pm, outbound(300 + i, own_group(60 + i as usize), ConnType::BlockRelay));
    }
    for _ in 0..20 {
        pm.evict_extra_outbound_peer();
    }
    let peers = pm.peers.read();
    let count = |t: ConnType| peers.values().filter(|h| h.info.conn_type == t).count();
    assert_eq!(count(ConnType::OutboundFullRelay), MAX_OUTBOUND);
    assert_eq!(count(ConnType::Manual), 5);
    assert_eq!(count(ConnType::BlockRelay), 2);
}

/// The peer chosen is kept, and nothing is disconnected on that pass, while
/// it has blocks in flight or has been connected under 30 seconds, as in
/// Core. A chain-sync-protected peer is never chosen.
#[test]
fn a_busy_young_or_protected_peer_is_kept() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    full_relay_peers(&pm, MAX_OUTBOUND + 2);
    // Peer 100 is the worst; give it a block in flight.
    pm.record_block_requests(100, &[bitcoin::BlockHash::all_zeros()], false);
    assert_eq!(pm.evict_extra_outbound_peer(), None, "a peer with a block in flight stays");
    pm.in_flight_blocks.write().clear();
    // Now young.
    pm.peers.write().get_mut(&100).unwrap().info.conn_time = std::time::UNIX_EPOCH
        + Duration::from_secs(crate::time::now_secs());
    assert_eq!(pm.evict_extra_outbound_peer(), None, "a peer connected under 30 s stays");
    // Protected: the next worst goes instead.
    pm.peers.write().get_mut(&100).unwrap().info.chain_sync_protect = true;
    assert_eq!(pm.evict_extra_outbound_peer(), Some(101));
    assert!(pm.peers.read().contains_key(&100));
}

/// Two peers in one network group: one of them goes first, though both
/// announced blocks more recently than the rest.
#[test]
fn a_peer_sharing_its_group_goes_first() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    full_relay_peers(&pm, MAX_OUTBOUND);
    for (id, last) in [(150, 5000), (151, 6000)] {
        let mut info = outbound(id, SocketAddr::from(([44, 1, id as u8, 1], 8333)), ConnType::OutboundFullRelay);
        info.last_block_announcement = last;
        add_peer(&pm, info);
    }
    assert_eq!(pm.evict_extra_outbound_peer(), Some(150));
    assert_eq!(pm.evict_extra_outbound_peer(), Some(100), "then the oldest announcement");
}

/// The only manual or full-relay connection on its network is kept, as
/// Core's `MultipleManualOrFullOutboundConns` keeps it.
#[test]
fn the_only_peer_on_its_network_is_kept() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    full_relay_peers(&pm, MAX_OUTBOUND);
    let mut v6 = outbound(150, "[2001:4860::1]:8333".parse().unwrap(), ConnType::OutboundFullRelay);
    v6.last_block_announcement = 0;
    add_peer(&pm, v6);
    assert_eq!(pm.evict_extra_outbound_peer(), Some(100), "the lone IPv6 peer is passed over");
    assert!(pm.peers.read().contains_key(&150));
}

/// A header with more work than the tip stamps the peer's announcement
/// time, and protects up to four outbound full-relay peers, as Core's
/// `UpdatePeerStateForReceivedHeaders` does.
#[test]
fn a_new_header_stamps_the_announcement_and_protects_four_peers() {
    use crate::chain::state::tests::build_test_block;

    let (pm, _dir) = mk_pm();
    for i in 0..6 {
        add_peer(&pm, outbound(100 + i, own_group(i as usize), ConnType::OutboundFullRelay));
    }
    let mut inbound = PeerInfo::new(10, SocketAddr::from(([47, 1, 9, 9], 50000)), Direction::Inbound);
    inbound.state = PeerState::Connected;
    add_peer(&pm, inbound);

    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let header = build_test_block(genesis, 1, 1_707_000_000).header;
    pm.handle_headers(10, vec![header]);
    for id in 100..106 {
        pm.handle_headers(id, vec![header]);
    }
    let peers = pm.peers.read();
    let info = |id: PeerId| &peers.get(&id).unwrap().info;
    assert!(info(10).last_block_announcement > 0, "the first to send it announced it");
    assert!(!info(10).chain_sync_protect, "inbound peers are not protected");
    assert_eq!(info(100).last_block_announcement, 0, "a header already known is no announcement");
    let protected: Vec<PeerId> = (100..106).filter(|id| info(*id).chain_sync_protect).collect();
    assert_eq!(protected, vec![100, 101, 102, 103], "the first four");
}

/// Seed addresses learned at startup are dialled by the automatic dial pass
/// (`dial_learned_peers`), which applies the outbound target and the group
/// rule, rather than one task each that bypassed both: here a seed on
/// loopback is dialled and becomes an outbound full-relay peer, and with
/// networking paused nothing is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seeds_are_dialled_by_the_automatic_pass() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seed = listener.local_addr().unwrap();
    pm.add_learned_peer_addr(&PeerAddr::Socket(seed));

    pm.set_network_active(false);
    pm.dial_learned_peers();
    assert_eq!(pm.dials_in_flight.lock().automatic, 0, "nothing while networking is paused");

    pm.set_network_active(true);
    pm.dial_learned_peers();
    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
    assert!(accepted.is_ok(), "the seed is dialled");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let conn_type = pm.peers.read().values().find(|h| h.info.addr == seed).map(|h| h.info.conn_type);
        if conn_type.is_some() {
            assert_eq!(conn_type, Some(ConnType::OutboundFullRelay));
            break;
        }
        assert!(Instant::now() < deadline, "the seed peer appears");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Mark `addrs` as dialled a moment ago, connected or not.
fn tried_just_now(pm: &PeerManager, addrs: &[SocketAddr]) {
    let mut backoff = pm.reconnect_backoff.write();
    for a in addrs {
        backoff.insert(
            *a,
            ReconnectState { attempts: 0, next_attempt: Instant::now(), last_try: Some(Instant::now()) },
        );
    }
}

/// Core passes over an address it tried in the last ten minutes until it
/// has looked at 30 candidates. satd dialled the first candidates on its
/// list that were not backing off, and a dial that connected cleared the
/// backoff, so a peer that hung up just after the handshake was dialled
/// again on the next pass: about a thousand times a day for each of the
/// two peers at the front of one node's list.
#[test]
fn an_automatic_dial_passes_over_a_peer_it_just_tried() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let addrs: Vec<SocketAddr> = (0..20).map(own_group).collect();
    learn(&pm, &addrs);
    tried_just_now(&pm, &addrs[1..]);
    for _ in 0..20 {
        let got = dialled(&pm);
        assert_eq!(got.first(), Some(&addrs[0]), "the one not tried lately goes first: {got:?}");
        assert_eq!(got.len(), MAX_OUTBOUND, "the passed-over ones fill the rest: {got:?}");
    }
}

/// Core draws its candidates with replacement, so a book of fewer than 30
/// addresses, all tried lately, still gives it one to dial. Each address
/// comes up once in a satd pass; the ones passed over are dialled once
/// every other candidate has been looked at.
#[test]
fn a_book_smaller_than_the_skip_count_still_redials_its_peers() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    let addrs: Vec<SocketAddr> = (0..3).map(own_group).collect();
    learn(&pm, &addrs);
    tried_just_now(&pm, &addrs);
    let mut got = dialled(&pm);
    got.sort();
    assert_eq!(got, addrs);
}

/// Core's `AddrMan::Select` takes the tried table or the new table at the
/// toss of a coin, then an entry at random. satd walked its list in the
/// order it learned the addresses, so the ones loaded from `peers.dat` were
/// first on every pass, and a book of a few tried addresses and many new
/// ones dialled the same few first every time.
#[test]
fn automatic_dials_draw_tried_and_new_at_even_odds() {
    use rand::SeedableRng as _;
    let (pm, _dir) = mk_pm();
    let tried: Vec<SocketAddr> = (0..10).map(own_group).collect();
    let new: Vec<SocketAddr> = (10..1010).map(own_group).collect();
    {
        let mut book = pm.addrman.write();
        for a in &new {
            assert!(book.add(*a, 1));
        }
        for a in &tried {
            book.mark_good(*a, 1);
        }
    }
    learn(&pm, &tried);
    learn(&pm, &new);
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let mut tried_first = 0;
    for _ in 0..400 {
        let order = pm.automatic_dial_order(&mut rng);
        assert_eq!(order.len(), tried.len() + new.len());
        if tried.contains(&order[0]) {
            tried_first += 1;
        }
    }
    assert!((140..=260).contains(&tried_first), "tried first in {tried_first} of 400");
    let mut order = pm.automatic_dial_order(&mut rng);
    order.sort();
    let mut all: Vec<SocketAddr> = tried.iter().chain(&new).copied().collect();
    all.sort();
    assert_eq!(order, all, "every learned address, once");
}

/// The onion half of the pass follows the same rule: an onion peer that
/// hung up just after the handshake was dialled again on the next tick,
/// since a dial that connected cleared its backoff.
#[test]
fn an_onion_dial_passes_over_a_peer_it_just_tried() {
    let (pm, _dir) = mk_pm();
    leave_ibd(&pm);
    pm.reachable.write().onion = true;
    // Seven of the eight automatic slots taken: room for one onion dial.
    for i in 0..MAX_OUTBOUND - 1 {
        add_peer(&pm, outbound(i as PeerId + 1, own_group(100 + i), ConnType::OutboundFullRelay));
    }
    let onions: Vec<PeerAddr> = (0..3)
        .map(|i| PeerAddr::Onion { host: format!("{}.onion", "a".repeat(55) + &i.to_string()), port: 8333 })
        .collect();
    *pm.connect_peer_addrs.write() = onions.clone();
    {
        let mut backoff = pm.onion_reconnect_backoff.write();
        for o in &onions[..2] {
            backoff.insert(
                o.to_string(),
                ReconnectState { attempts: 0, next_attempt: Instant::now(), last_try: Some(Instant::now()) },
            );
        }
    }
    let got: Vec<PeerAddr> = pm.reserve_onion_dials(Instant::now()).into_iter().map(|(t, _slot)| t).collect();
    assert_eq!(got, vec![onions[2].clone()], "the one not tried lately");

    // Tried lately, all of them: there is nothing else, so one is dialled.
    pm.onion_reconnect_backoff.write().insert(
        onions[2].to_string(),
        ReconnectState { attempts: 0, next_attempt: Instant::now(), last_try: Some(Instant::now()) },
    );
    assert_eq!(pm.reserve_onion_dials(Instant::now()).len(), 1);
}
