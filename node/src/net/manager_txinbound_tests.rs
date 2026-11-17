//! The inbound transaction-relay cap: Bitcoin Core v32's
//! `CConnman::EvictTxPeerIfFull` (`src/net.cpp`) and the default of 200
//! connections (`DEFAULT_MAX_PEER_CONNECTIONS`, `src/net.h`).

use super::*;

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

/// A connected peer in a /16 of its own, connected `id` seconds before the
/// others' reference point so connect times differ.
fn peer(id: PeerId, direction: Direction, tx_relay: bool) -> PeerInfo {
    let addr = SocketAddr::from(([60 + (id / 200) as u8, (id % 200) as u8, 1, 1], 8333));
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = PeerState::Connected;
    info.tx_relay_requested = tx_relay;
    info.has_all_wanted_services = true;
    info.conn_time -= Duration::from_secs(10_000 - id);
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

fn ids(pm: &PeerManager) -> std::collections::BTreeSet<PeerId> {
    pm.peers.read().keys().copied().collect()
}

/// `-maxconnections=31`: 20 inbound slots past the 11 automatic outbound
/// ones, 10 of them for transaction-relaying peers.
fn small(pm: &PeerManager) {
    pm.set_max_connections(31);
    assert_eq!(pm.max_inbound(), 20);
    assert_eq!(pm.max_inbound_full_relay(), 10);
}

/// Core v32's defaults: 200 connections, 189 inbound past the 11 automatic
/// outbound slots, and half of those, 94, for transaction relay.
#[test]
fn the_default_is_200_connections_and_half_the_inbound_for_tx_relay() {
    let (pm, _dir) = mk_pm();
    assert_eq!(pm.max_connections.load(Ordering::Relaxed), 200);
    assert_eq!(pm.max_inbound(), 189);
    assert_eq!(pm.max_inbound_full_relay(), 94);
}

/// `-inboundrelaypercent` scales the cap the way Core computes it, in
/// floating point and truncated, and is clamped to 0..=100.
#[test]
fn the_inbound_relay_percent_scales_the_cap_as_core_computes_it() {
    let (pm, _dir) = mk_pm();
    pm.set_max_connections(111);
    assert_eq!(pm.max_inbound(), 100);
    pm.set_inbound_relay_percent(29);
    assert_eq!(pm.max_inbound_full_relay(), 28, "0.29 * 100 truncates to 28 in Core");
    pm.set_inbound_relay_percent(250);
    assert_eq!(pm.max_inbound_full_relay(), 100);
    pm.set_inbound_relay_percent(0);
    assert_eq!(pm.max_inbound_full_relay(), 0);
    // At or below the automatic outbound slots there is no inbound at all.
    pm.set_max_connections(11);
    assert_eq!(pm.max_inbound(), 0);
}

/// One transaction-relaying inbound peer past the cap evicts another one,
/// chosen by the inbound eviction rules. The newcomer, a `noban` peer,
/// outbound peers, block-relay-only inbound peers and the four peers that
/// most recently sent the mempool a transaction all survive.
#[test]
fn a_tx_relay_inbound_peer_past_the_cap_evicts_another() {
    let (pm, _dir) = mk_pm();
    small(&pm);
    // 22 tx-relaying inbound peers, more than the eviction rules protect.
    for id in 1..=22 {
        let stats = add(&pm, peer(id, Direction::Inbound, true));
        if (1..=4).contains(&id) {
            stats.record_transaction();
        }
    }
    let mut noban = peer(23, Direction::Inbound, true);
    noban.permissions.noban = true;
    add(&pm, noban);
    for id in 30..35 {
        add(&pm, peer(id, Direction::Outbound, true));
    }
    for id in 40..60 {
        add(&pm, peer(id, Direction::Inbound, false));
    }
    let newcomer = 22;
    let before = ids(&pm);

    assert!(pm.evict_tx_peer_if_full(Some(newcomer)), "an eviction makes room");

    let gone: Vec<PeerId> = before.difference(&ids(&pm)).copied().collect();
    assert_eq!(gone.len(), 1, "exactly one peer evicted: {gone:?}");
    assert!((5..=21).contains(&gone[0]), "evicted an unprotected tx-relay inbound peer, not {}", gone[0]);
}

/// Past the cap with every tx-relaying inbound candidate protected (Core
/// protects at least 20 before it evicts any), nothing is evicted and the
/// caller is told to drop the newcomer.
#[test]
fn past_the_cap_with_every_candidate_protected_the_newcomer_is_refused() {
    let (pm, _dir) = mk_pm();
    small(&pm);
    for id in 1..=11 {
        add(&pm, peer(id, Direction::Inbound, true));
    }
    let before = ids(&pm);
    assert!(!pm.evict_tx_peer_if_full(Some(11)));
    assert_eq!(ids(&pm), before, "no peer was evicted");
}

/// Inbound peers whose `version` turned transaction relay off are neither
/// counted against the cap nor evicted to make room under it.
#[test]
fn block_relay_only_inbound_peers_do_not_count() {
    let (pm, _dir) = mk_pm();
    small(&pm);
    for id in 1..=10 {
        add(&pm, peer(id, Direction::Inbound, true));
    }
    for id in 100..140 {
        add(&pm, peer(id, Direction::Inbound, false));
    }
    let before = ids(&pm);
    assert!(pm.evict_tx_peer_if_full(Some(10)), "10 tx-relaying inbound peers are at the cap, not past it");
    assert_eq!(ids(&pm), before);

    // An eleventh is past it, and the 40 block-relay-only peers are no
    // candidates: the 10 tx-relaying ones are all protected.
    add(&pm, peer(11, Direction::Inbound, true));
    assert!(!pm.evict_tx_peer_if_full(Some(11)));
    assert_eq!(ids(&pm).len(), before.len() + 1);
}

/// The cap applies before satd's `verack` to an inbound peer: past it, with
/// no candidate to evict, a peer asking for transactions is dropped, and one
/// that is not is let in.
#[tokio::test]
async fn the_inbound_handshake_drops_a_tx_relay_peer_past_the_cap() {
    use crate::net::connection::Connection;
    use bitcoin::p2p::Magic;

    for relay in [true, false] {
        let (pm, _dir) = mk_pm();
        small(&pm);
        for id in 1..=10 {
            add(&pm, peer(id, Direction::Inbound, true));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
        let (dialed, accepted) = tokio::join!(dialer, listener.accept());
        let (dialed, (accepted, peer_addr)) = (dialed.unwrap(), accepted.unwrap());
        let mut handle = PeerInfo::new(50, peer_addr, Direction::Inbound);
        handle.state = PeerState::Connecting;
        add(&pm, handle);
        let mut ours = Connection::with_magic(accepted, Magic::REGTEST);
        let mut theirs = Connection::with_magic(dialed, Magic::REGTEST);

        let mut version = pm.build_version_message(peer_addr, ConnType::OutboundFullRelay);
        version.relay = relay;
        let remote = async {
            theirs.send(NetworkMessage::Version(version)).await.unwrap();
            let mut seen = Vec::new();
            while let Ok(msg) = theirs.recv().await {
                let verack = matches!(msg, NetworkMessage::Verack);
                seen.push(msg.cmd().to_string());
                if verack {
                    theirs.send(NetworkMessage::Verack).await.unwrap();
                    break;
                }
            }
            seen
        };
        let (handshake, seen) = tokio::join!(
            async {
                let r = pm.perform_handshake(50, &mut ours, Direction::Inbound, crate::time::now_secs()).await;
                drop(ours);
                r
            },
            remote
        );
        if relay {
            assert!(handshake.is_err(), "a tx-relay peer past the cap is dropped");
            assert!(!seen.iter().any(|c| c == "verack"), "dropped before satd's verack: {seen:?}");
        } else {
            handshake.expect("a block-relay-only peer is let in");
            assert!(!pm.peers.read()[&50].info.tx_relay_requested);
        }
        assert_eq!(ids(&pm).len(), 11, "no tx-relay inbound peer was evicted");
    }
}
