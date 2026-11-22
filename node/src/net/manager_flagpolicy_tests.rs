//! `-peerflagpolicy`: under `evict` an inbound peer flagged `C`, `S` or `F`
//! loses its eviction protection and goes first when an inbound slot is
//! needed; under `observe`, the default, the flags change nothing.

use super::*;
use crate::net::flags::{Flag, FlagPolicy, FlagSet};

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
    let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
    // Out of IBD, so the outbound target is the full-relay count.
    pm.headers_tip.store(1, Ordering::Relaxed);
    (pm, dir)
}

/// A connected peer in a /16 of its own, the lower `id` the older.
fn peer(id: PeerId, direction: Direction) -> PeerInfo {
    let addr = SocketAddr::from(([60 + (id / 200) as u8, (id % 200) as u8, 1, 1], 8333));
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = PeerState::Connected;
    if direction == Direction::Outbound {
        info.conn_type = ConnType::OutboundFullRelay;
    }
    info.tx_relay_requested = true;
    info.has_all_wanted_services = true;
    info.conn_time -= Duration::from_secs(10_000 - id);
    info
}

fn flagged(mut info: PeerInfo, flags: &[Flag]) -> PeerInfo {
    let fp = info.flags.fingerprint;
    info.flags.update(fp, true, flags.iter().map(|f| (*f, Vec::new())).collect());
    info
}

fn add(pm: &PeerManager, info: PeerInfo) -> Arc<PeerStats> {
    let (tx, _rx) = mpsc::channel::<NetworkMessage>(8);
    let stats = PeerStats::new(NetTotals::new());
    pm.peers.write().insert(
        info.id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            header_sync: Default::default(),
            last_mempool_served: None,
            tx_relay: Default::default(),
            fee_filter_sent: None,
            stats: stats.clone(),
        },
    );
    stats
}

fn set_flags(pm: &PeerManager, id: PeerId, flags: &[Flag]) {
    let mut peers = pm.peers.write();
    let info = &mut peers.get_mut(&id).unwrap().info;
    let taken = std::mem::replace(info, PeerInfo::new(id, info.addr, info.direction));
    *info = flagged(taken, flags);
}

fn ids(pm: &PeerManager) -> std::collections::BTreeSet<PeerId> {
    pm.peers.read().keys().copied().collect()
}

/// The inbound eviction's choice for a full set, without disconnecting.
fn victim(pm: &PeerManager) -> EvictionVictim {
    pm.eviction_victim(false, None, &|_| true)
}

/// Accept one real loopback connection through the inbound accept path,
/// returning the dialing end, which must stay open for the peer to stay.
async fn accept_one(pm: &Arc<PeerManager>) -> tokio::net::TcpStream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let (dialed, accepted) = tokio::join!(dialer, listener.accept());
    let (accepted, peer_addr) = accepted.unwrap();
    pm.accept_inbound(accepted, peer_addr);
    dialed.unwrap()
}

fn loopback_peers(pm: &PeerManager) -> usize {
    pm.peers.read().values().filter(|h| h.info.addr.ip().is_loopback()).count()
}

/// 30 inbound peers fill `-maxconnections=41`'s 30 inbound slots. Peer 1,
/// the oldest, which sent the latest mempool transaction and the latest
/// block, is one Core's rules protect three times over.
fn full_inbound_set(pm: &PeerManager) {
    pm.set_max_connections(41);
    assert_eq!(pm.max_inbound(), 30);
    for id in 1..=30 {
        let stats = add(pm, peer(id, Direction::Inbound));
        if id == 1 {
            stats.record_transaction();
            stats.record_block();
        }
    }
}

#[test]
fn the_policy_defaults_to_observe() {
    let (pm, _dir) = mk_pm();
    assert_eq!(pm.flag_policy(), FlagPolicy::Observe);
    pm.set_flag_policy(FlagPolicy::Evict);
    assert_eq!(pm.flag_policy(), FlagPolicy::Evict);
}

/// One test per flag the policy acts on: under `evict` a full inbound set
/// evicts the flagged peer, though Core's rules protect it, records the
/// reason `evicted-flagged`, and keeps the newcomer.
#[tokio::test]
async fn each_eviction_flag_takes_a_protected_inbound_peer_first() {
    for flag in [Flag::Crawler, Flag::Spy, Flag::FingerprintMismatch] {
        let (pm, _dir) = mk_pm();
        pm.set_flag_policy(FlagPolicy::Evict);
        full_inbound_set(&pm);
        assert!(
            !matches!(victim(&pm), EvictionVictim::Peer(1, _)),
            "fixture: Core's rules protect peer 1"
        );
        set_flags(&pm, 1, &[flag]);
        let before = ids(&pm);

        let _dialer = accept_one(&pm).await;

        let gone: Vec<PeerId> = before.difference(&ids(&pm)).copied().collect();
        assert_eq!(gone, vec![1], "{flag:?}: the flagged peer, and only it");
        assert!(pm.retired_behavior.lock().contains(&(1, Some("evicted-flagged"))), "{flag:?}");
        assert_eq!(loopback_peers(&pm), 1, "{flag:?}: the newcomer is kept");
    }
}

/// The inbound tx-relay cap takes the same path: a flagged tx-relay peer
/// goes first there too.
#[test]
fn the_tx_relay_cap_takes_a_flagged_peer_first() {
    let (pm, _dir) = mk_pm();
    pm.set_flag_policy(FlagPolicy::Evict);
    pm.set_max_connections(31);
    assert_eq!(pm.max_inbound_full_relay(), 10);
    for id in 1..=11 {
        add(&pm, flagged(peer(id, Direction::Inbound), if id == 2 { &[Flag::Spy] } else { &[] }));
    }
    // Eleven candidates: Core protects every one.
    assert!(pm.evict_tx_peer_if_full(Some(11)));
    assert!(!ids(&pm).contains(&2), "the flagged peer went");
    assert_eq!(ids(&pm).len(), 10);
    assert!(pm.retired_behavior.lock().contains(&(2, Some("evicted-flagged"))));
}

/// The other flags (`A`, `H`, `N`, `T`) change nothing under `evict`.
#[test]
fn the_other_flags_change_nothing() {
    let (pm, _dir) = mk_pm();
    pm.set_flag_policy(FlagPolicy::Evict);
    full_inbound_set(&pm);
    let core = victim(&pm);
    assert!(matches!(core, EvictionVictim::Peer(_, f) if f.is_empty()));
    for id in 1..=30 {
        set_flags(&pm, id, &[Flag::AddrAbuse, Flag::HeightLie, Flag::NotfoundPattern, Flag::Stalling]);
    }
    assert_eq!(victim(&pm), core);
}

/// One test per exempt permission: a flagged peer with `noban`, `relay` or
/// `forcerelay` keeps the protection Core gives it, and the choice is
/// Core's.
#[test]
fn a_peer_with_noban_or_relay_permission_is_exempt() {
    type Grant = fn(&mut crate::net::permissions::NetPermissions);
    let grants: [(&str, Grant); 3] = [
        ("noban", |p| p.noban = true),
        ("relay", |p| p.relay = true),
        ("forcerelay", |p| p.force_relay = true),
    ];
    for (name, grant) in grants {
        let (pm, _dir) = mk_pm();
        pm.set_flag_policy(FlagPolicy::Evict);
        full_inbound_set(&pm);
        grant(&mut pm.peers.write().get_mut(&1).unwrap().info.permissions);
        let core = victim(&pm);
        set_flags(&pm, 1, &[Flag::Crawler, Flag::Spy, Flag::FingerprintMismatch]);
        grant(&mut pm.peers.write().get_mut(&1).unwrap().info.permissions);
        assert_eq!(victim(&pm), core, "{name}");
        assert!(!matches!(core, EvictionVictim::Peer(1, _)), "{name}");
    }
}

/// Nothing is disconnected while an inbound slot is free, however many
/// peers are flagged.
#[tokio::test]
async fn no_disconnect_while_slots_are_free() {
    let (pm, _dir) = mk_pm();
    pm.set_flag_policy(FlagPolicy::Evict);
    pm.set_max_connections(41);
    for id in 1..=29 {
        add(&pm, flagged(peer(id, Direction::Inbound), &[Flag::Crawler, Flag::Spy]));
    }
    let before = ids(&pm);
    pm.evaluate_peer_flags();
    let _dialer = accept_one(&pm).await;
    assert!(before.is_subset(&ids(&pm)), "nobody evicted below the cap");
    assert_eq!(loopback_peers(&pm), 1);
    assert!(pm.retired_behavior.lock().is_empty());
}

/// Outbound peers are never touched: a flagged outbound peer is never the
/// inbound eviction's choice, and the surplus outbound eviction picks the
/// same peer under either policy.
#[test]
fn outbound_peers_are_untouched() {
    let all = [Flag::Crawler, Flag::Spy, Flag::FingerprintMismatch];
    let (pm, _dir) = mk_pm();
    pm.set_flag_policy(FlagPolicy::Evict);
    full_inbound_set(&pm);
    for id in 40..45 {
        add(&pm, flagged(peer(id, Direction::Outbound), &all));
    }
    assert!(matches!(victim(&pm), EvictionVictim::Peer(id, f) if (1..=30).contains(&id) && f.is_empty()));

    let surplus = |policy: FlagPolicy| {
        let (pm, _dir) = mk_pm();
        pm.set_flag_policy(policy);
        for id in 1..=9 {
            add(&pm, flagged(peer(id, Direction::Outbound), if id % 2 == 0 { &all } else { &[] }));
        }
        assert!(!pm.is_ibd());
        pm.evict_extra_outbound_peer().expect("one over the target of 8")
    };
    assert_eq!(surplus(FlagPolicy::Evict), surplus(FlagPolicy::Observe));
}

/// `observe`, the default, leaves the eviction exactly as it was: over
/// many inbound sets, with every flag on a random subset of the peers, the
/// choice is the one made with no flags at all, and never names a flag.
#[test]
fn observe_leaves_the_eviction_as_it_was() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let (pm, _dir) = mk_pm();
    assert_eq!(pm.flag_policy(), FlagPolicy::Observe);
    pm.set_max_connections(41);
    let mut differs_under_evict = 0;
    for _ in 0..50 {
        pm.peers.write().clear();
        let n = rng.gen_range(21..=60u64);
        for id in 1..=n {
            let stats = add(&pm, peer(id, Direction::Inbound));
            if rng.gen_bool(0.2) {
                stats.record_transaction();
            }
            if rng.gen_bool(0.2) {
                stats.record_block();
            }
        }
        let core = victim(&pm);
        for id in 1..=n {
            let flags: Vec<Flag> = Flag::ALL.into_iter().filter(|_| rng.gen_bool(0.3)).collect();
            set_flags(&pm, id, &flags);
        }
        assert_eq!(victim(&pm), core);
        assert!(!matches!(victim(&pm), EvictionVictim::Peer(_, f) if f != FlagSet::default()));
        pm.set_flag_policy(FlagPolicy::Evict);
        if victim(&pm) != core {
            differs_under_evict += 1;
        }
        pm.set_flag_policy(FlagPolicy::Observe);
    }
    assert!(differs_under_evict > 0, "fixture: the flags would have mattered under evict");
}
