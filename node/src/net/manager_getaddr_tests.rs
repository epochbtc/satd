//! `getaddr`, answered as Core answers it (`ProcessMessage`,
//! `CConnman::GetAddresses`): inbound peers only, once per connection, from
//! a sample of the address book cached per listener, with no live peers and
//! none of our own addresses in it.

use super::*;
use crate::net::flow::InFlight;

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


fn add_peer(pm: &PeerManager, info: PeerInfo) -> mpsc::Receiver<NetworkMessage> {
    let (tx, rx) = mpsc::channel::<NetworkMessage>(64);
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
    rx
}

fn peer(id: PeerId, addr: SocketAddr, direction: Direction) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = PeerState::Connected;
    info
}

/// `n` gossiped addresses, each in a /16 of its own.
fn fill_book(pm: &PeerManager, n: usize) {
    let source = IpAddr::from([198, 51, 100, 1]);
    for i in 0..n {
        let a = SocketAddr::from(([1 + (i / 250) as u8, (i % 250) as u8, 9, 9], 8333));
        pm.add_learned_addr_from(a, 9, source);
    }
}

/// The addresses in every addr/addrv2 message waiting on `rx`.
fn answered(rx: &mut mpsc::Receiver<NetworkMessage>) -> Option<Vec<SocketAddr>> {
    let mut got: Option<Vec<SocketAddr>> = None;
    while let Ok(m) = rx.try_recv() {
        match m {
            NetworkMessage::Addr(a) => got
                .get_or_insert_with(Vec::new)
                .extend(a.iter().filter_map(|(_, x)| x.socket_addr().ok())),
            NetworkMessage::AddrV2(a) => got.get_or_insert_with(Vec::new).extend(a.iter().filter_map(|m| {
                match m.addr {
                    bitcoin::p2p::address::AddrV2::Ipv4(ip) => Some(SocketAddr::from((ip, m.port))),
                    bitcoin::p2p::address::AddrV2::Ipv6(ip) => Some(SocketAddr::from((ip, m.port))),
                    _ => None,
                }
            })),
            _ => {}
        }
    }
    got
}

/// An inbound peer gets one answer, a sample of the address book of at most
/// 23% of it, with neither the node's live peers nor its own addresses in
/// it. Asking again on the same connection gets nothing. Perturbation:
/// drop the once-per-connection check and the second request is answered.
#[test]
fn an_inbound_peer_gets_one_sample_of_the_address_book() {
    let (pm, _dir) = mk_pm();
    fill_book(&pm, 200);
    let external = SocketAddr::from(([44, 33, 22, 11], 8333));
    pm.external_addrs.write().push(external);
    let connected = SocketAddr::from(([44, 44, 44, 44], 8333));
    let _c = add_peer(&pm, peer(9, connected, Direction::Outbound));
    let mut rx = add_peer(&pm, peer(1, SocketAddr::from(([10, 1, 1, 1], 50000)), Direction::Inbound));

    pm.handle_message(1, NetworkMessage::GetAddr, InFlight::adopt(None));
    let got = answered(&mut rx).expect("an inbound peer is answered");
    assert_eq!(got.len(), 200 * 23 / 100, "23% of the book");
    let book: std::collections::HashSet<SocketAddr> = pm.addrman.read().iter().map(|e| e.addr).collect();
    assert!(got.iter().all(|a| book.contains(a)), "only address-book entries");
    assert!(!got.contains(&connected), "no live peer list");
    assert!(!got.contains(&external), "not our own address");

    pm.handle_message(1, NetworkMessage::GetAddr, InFlight::adopt(None));
    assert_eq!(answered(&mut rx), None, "one answer per connection");
}

/// An outbound peer is not answered: Core's defence against a peer that
/// plants addresses in our book and asks for them back.
/// Perturbation: drop the inbound check and this is answered.
#[test]
fn an_outbound_peer_is_not_answered() {
    let (pm, _dir) = mk_pm();
    fill_book(&pm, 50);
    let mut rx = add_peer(&pm, peer(1, SocketAddr::from(([198, 51, 100, 7], 8333)), Direction::Outbound));
    pm.handle_message(1, NetworkMessage::GetAddr, InFlight::adopt(None));
    assert_eq!(answered(&mut rx), None);
}

/// Two inbound peers on the same listener get the same cached sample; each
/// other listener (the onion one, another bind) has a cache of its own, and
/// a peer with the `addr` permission a fresh one. Perturbation: key the
/// cache on nothing and the onion peer gets the clearnet sample.
#[test]
fn the_sample_is_cached_per_listener() {
    let (pm, _dir) = mk_pm();
    fill_book(&pm, 400);
    let mut a = add_peer(&pm, peer(1, SocketAddr::from(([10, 1, 1, 1], 50000)), Direction::Inbound));
    let mut b = add_peer(&pm, peer(2, SocketAddr::from(([10, 1, 1, 2], 50000)), Direction::Inbound));
    let mut onion = peer(3, SocketAddr::from(([127, 0, 0, 1], 50003)), Direction::Inbound);
    onion.inbound_onion = true;
    let mut o = add_peer(&pm, onion);
    for id in [1, 2, 3] {
        pm.handle_message(id, NetworkMessage::GetAddr, InFlight::adopt(None));
    }
    let (sa, sb, so) = (answered(&mut a).unwrap(), answered(&mut b).unwrap(), answered(&mut o).unwrap());
    assert_eq!(sa, sb, "one listener, one cached sample");
    assert_ne!(sa, so, "the onion listener's sample is its own");

    // Two onion binds are two listeners (Core's p2p_getaddr_caching.py).
    let mut onion2 = peer(5, SocketAddr::from(([127, 0, 0, 1], 50005)), Direction::Inbound);
    onion2.inbound_onion = true;
    onion2.bind_addr = Some(SocketAddr::from(([127, 0, 0, 1], 18446)));
    let mut o2 = add_peer(&pm, onion2);
    pm.handle_message(5, NetworkMessage::GetAddr, InFlight::adopt(None));
    assert_ne!(answered(&mut o2).unwrap(), so, "another bind, another sample");

    let mut fresh = peer(4, SocketAddr::from(([10, 1, 1, 4], 50000)), Direction::Inbound);
    fresh.permissions.addr = true;
    let mut f = add_peer(&pm, fresh);
    pm.handle_message(4, NetworkMessage::GetAddr, InFlight::adopt(None));
    assert_ne!(answered(&mut f).unwrap(), sa, "the addr permission skips the cache");
}

/// Our `-externalip` addresses go to an outbound peer on the same IP family
/// at the handshake (Core's `GetLocalAddrForPeer` push), not in `getaddr`.
#[test]
fn externals_are_advertised_to_outbound_peers_on_their_family() {
    let (pm, _dir) = mk_pm();
    let v4 = SocketAddr::from(([44, 33, 22, 11], 8333));
    let v6: SocketAddr = "[2a01:4f8::50]:8333".parse().unwrap();
    pm.external_addrs.write().extend([v4, v6]);
    let _r = add_peer(&pm, peer(1, SocketAddr::from(([198, 51, 100, 7], 8333)), Direction::Outbound));
    let Some(NetworkMessage::Addr(a)) = pm.self_advertise_externals(1) else { panic!("a legacy addr") };
    let got: Vec<SocketAddr> = a.iter().filter_map(|(_, x)| x.socket_addr().ok()).collect();
    assert_eq!(got, vec![v4]);
    let mut onion = peer(2, SocketAddr::from(([0, 0, 0, 0], 8333)), Direction::Outbound);
    onion.onion_host = Some("a".repeat(56) + ".onion");
    let _o = add_peer(&pm, onion);
    assert!(pm.self_advertise_externals(2).is_none(), "nothing clearnet to an onion peer");
}

/// An `-externalip` address Core calls unroutable is never claimed: not
/// self-advertised, not the version message's sender, not in
/// `localaddresses` (Core's `AddLocal` refuses it). An `fc00::/8` address is
/// left out even under `-cjdnsreachable`: satd cannot encode it as CJDNS.
/// Perturbation: read `external_addrs` unfiltered and the private address
/// goes out.
#[test]
fn an_unroutable_externalip_is_never_advertised() {
    let (pm, _dir) = mk_pm();
    let public = SocketAddr::from(([44, 33, 22, 11], 8333));
    let cjdns: SocketAddr = "[fc32::1]:8333".parse().unwrap();
    pm.set_external_addrs(vec![
        SocketAddr::from(([10, 1, 2, 3], 8333)),
        SocketAddr::from(([127, 0, 0, 1], 8333)),
        SocketAddr::from(([100, 64, 0, 1], 8333)),
        SocketAddr::from(([192, 0, 2, 1], 8333)),
        public,
        cjdns,
    ]);
    let _r = add_peer(&pm, peer(1, SocketAddr::from(([198, 51, 100, 7], 8333)), Direction::Outbound));
    let Some(NetworkMessage::Addr(a)) = pm.self_advertise_externals(1) else { panic!("a legacy addr") };
    let got: Vec<SocketAddr> = a.iter().filter_map(|(_, x)| x.socket_addr().ok()).collect();
    assert_eq!(got, vec![public], "only the routable address is advertised");
    let local: Vec<String> = pm.local_addresses().into_iter().map(|(h, _, _)| h).collect();
    assert_eq!(local, vec!["44.33.22.11".to_string()]);

    pm.set_reachable(crate::net::reachable::ReachableNets { cjdns: true, cjdns_flip: true, ..Default::default() });
    let local: Vec<String> = pm.local_addresses().into_iter().map(|(h, _, _)| h).collect();
    assert_eq!(local, vec!["44.33.22.11".to_string()], "no CJDNS encoding, so no CJDNS self-advertisement");

    pm.set_external_addrs(vec![SocketAddr::from(([10, 1, 2, 3], 8333)), public]);
    let version = pm.build_version_message(SocketAddr::from(([198, 51, 100, 7], 8333)), ConnType::OutboundFullRelay);
    assert_eq!(version.sender.socket_addr().ok(), Some(public), "the sender is the first routable address");
}

/// A block-relay-only link carries no address traffic, so neither our
/// `-externalip` addresses nor our onion go out on one (Core's
/// `SetupAddressRelay`).
#[test]
fn nothing_is_self_advertised_to_a_block_relay_only_peer() {
    let (pm, _dir) = mk_pm();
    pm.external_addrs.write().push(SocketAddr::from(([44, 33, 22, 11], 8333)));
    *pm.advertised_onion.write() = Some(PeerAddr::Onion { host: "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion".to_string(), port: 8333 });
    let mut full = peer(1, SocketAddr::from(([198, 51, 100, 7], 8333)), Direction::Outbound);
    full.wants_addrv2 = true;
    let _f = add_peer(&pm, full);
    let mut blocks_only = peer(2, SocketAddr::from(([198, 51, 100, 8], 8333)), Direction::Outbound);
    blocks_only.wants_addrv2 = true;
    blocks_only.conn_type = ConnType::BlockRelay;
    let _b = add_peer(&pm, blocks_only);
    assert!(pm.self_advertise_externals(1).is_some() && pm.self_advertise_addrv2(1).is_some());
    assert!(pm.self_advertise_externals(2).is_none(), "no -externalip on a block-relay-only link");
    assert!(pm.self_advertise_addrv2(2).is_none(), "no onion on a block-relay-only link");
}
