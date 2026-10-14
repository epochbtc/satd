//! What happens to a peer whose misbehaviour reaches the threshold: Core's
//! `MaybeDiscourageAndDisconnect` (`net_processing.cpp`), against a live
//! `PeerManager`.

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
    let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
    (pm, dir)
}

/// A connected peer at `addr`.
fn peer(id: PeerId, addr: &str, direction: Direction) -> PeerInfo {
    let mut info = PeerInfo::new(id, addr.parse().unwrap(), direction);
    info.state = PeerState::Connected;
    info
}

fn add_peer(pm: &PeerManager, info: PeerInfo) -> mpsc::Receiver<NetworkMessage> {
    let (tx, rx) = mpsc::channel::<NetworkMessage>(8);
    pm.peers.write().insert(
        info.id,
        PeerHandle {
            info,
            msg_tx: tx.into(),
            disconnect: Arc::new(tokio::sync::Notify::new()),
            flow: Arc::new(crate::net::flow::PeerFlow::new()),
            last_getheaders_sent: None,
            last_mempool_served: None,
            fee_filter_sent: None,
            stats: PeerStats::new(NetTotals::new()),
        },
    );
    rx
}

/// What became of a peer after it misbehaved.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Still connected, nothing banned.
    Kept,
    /// Disconnected, nothing banned.
    Disconnected,
    /// Disconnected, and a ban entry added.
    Banned,
}

fn outcome(pm: &PeerManager, id: PeerId) -> Outcome {
    let connected = pm.peers.read().contains_key(&id);
    let banned = !pm.list_banned().is_empty();
    match (connected, banned) {
        (true, false) => Outcome::Kept,
        (false, false) => Outcome::Disconnected,
        (false, true) => Outcome::Banned,
        (true, true) => panic!("peer {id} is still connected, but something was banned"),
    }
}

/// Core's ladder, rung by rung. A `noban` peer and a manual connection are
/// never punished ("Not punishing noban peer", "Not punishing manually
/// connected peer"), whatever their address. A peer on a local address is
/// disconnected but its address is not discouraged, "since that would
/// discourage all peers on the same local address": every inbound onion peer
/// and every local integration shares 127.0.0.1. Anyone else is disconnected
/// and its address punished (satd bans it for `-bantime`).
#[test]
fn misbehaviour_follows_cores_ladder() {
    use crate::net::permissions::NetPermissions;
    let noban = |mut info: PeerInfo| {
        info.permissions = NetPermissions { noban: true, ..NetPermissions::NONE };
        info
    };
    let manual = |mut info: PeerInfo| {
        info.conn_type = ConnType::Manual;
        info
    };
    let onion = |mut info: PeerInfo| {
        info.inbound_onion = true;
        info
    };
    let cases: Vec<(&str, PeerInfo, Outcome)> = vec![
        ("an inbound peer", peer(1, "10.62.0.1:50000", Direction::Inbound), Outcome::Banned),
        ("an outbound peer", peer(1, "10.62.0.2:8333", Direction::Outbound), Outcome::Banned),
        // Private, but not local: Core's `IsLocal` is loopback and 0.0.0.0/8.
        ("a peer on a private network", peer(1, "192.168.7.5:8333", Direction::Inbound), Outcome::Banned),
        ("a noban peer", noban(peer(1, "10.62.0.3:50000", Direction::Inbound)), Outcome::Kept),
        ("a manual peer", manual(peer(1, "10.62.0.4:8333", Direction::Outbound)), Outcome::Kept),
        // Manual comes before local in the ladder.
        ("a manual peer on loopback", manual(peer(1, "127.0.0.1:8333", Direction::Outbound)), Outcome::Kept),
        ("a peer on 127.0.0.1", peer(1, "127.0.0.1:50000", Direction::Inbound), Outcome::Disconnected),
        ("a peer elsewhere in 127.0.0.0/8", peer(1, "127.5.6.7:50000", Direction::Inbound), Outcome::Disconnected),
        ("a peer on ::1", peer(1, "[::1]:50000", Direction::Inbound), Outcome::Disconnected),
        // What a dual-stack listener reports for an IPv4 loopback peer.
        (
            "a peer on ::ffff:127.0.0.1",
            peer(1, "[::ffff:127.0.0.1]:50000", Direction::Inbound),
            Outcome::Disconnected,
        ),
        ("an inbound onion peer", onion(peer(1, "127.0.0.1:50000", Direction::Inbound)), Outcome::Disconnected),
        // Tor on another host (`-bind=<lan address>:<port>=onion`): the
        // address is the Tor host's, shared by every onion peer, so it is not
        // banned either. See `misbehaviour_action`.
        (
            "an inbound onion peer forwarded from another host",
            onion(peer(1, "192.168.1.20:50000", Direction::Inbound)),
            Outcome::Disconnected,
        ),
        ("an outbound peer on loopback", peer(1, "127.0.0.1:8333", Direction::Outbound), Outcome::Disconnected),
    ];
    for (case, info, expected) in cases {
        let (pm, _dir) = mk_pm();
        let _rx = add_peer(&pm, info);
        pm.add_ban_score(1, BAN_THRESHOLD, "test");
        assert_eq!(outcome(&pm, 1), expected, "{case}");
    }
}

/// An outbound onion peer's socket address is the `0.0.0.0` placeholder all
/// onion peers share, not its address. Core punishes the onion address
/// itself, which is not a local one; satd bans that host, and leaves the
/// placeholder alone.
#[test]
fn a_misbehaving_outbound_onion_peer_is_banned_by_its_onion_host() {
    let host = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    let (pm, _dir) = mk_pm();
    let mut info = peer(1, "0.0.0.0:8333", Direction::Outbound);
    info.onion_host = Some(host.to_string());
    let _rx = add_peer(&pm, info);
    pm.add_ban_score(1, BAN_THRESHOLD, "test");

    assert!(!pm.peers.read().contains_key(&1), "the peer is disconnected");
    let now = crate::time::now_secs();
    assert!(pm.ban_list.read().is_onion_banned(host, now), "its onion host is banned");
    assert!(
        !pm.is_addr_banned(&"0.0.0.0:8333".parse().unwrap()),
        "the shared placeholder is not a peer's address"
    );
}

/// Neither a `noban` peer nor a manual one is punished however often it
/// misbehaves, and a score that stays under the threshold punishes no one.
#[test]
fn kept_peers_stay_however_often_they_misbehave() {
    use crate::net::permissions::NetPermissions;
    for case in ["noban", "manual"] {
        let (pm, _dir) = mk_pm();
        let mut info = peer(1, "10.62.0.5:8333", Direction::Outbound);
        match case {
            "noban" => info.permissions = NetPermissions { noban: true, ..NetPermissions::NONE },
            _ => info.conn_type = ConnType::Manual,
        }
        let _rx = add_peer(&pm, info);
        for _ in 0..5 {
            pm.add_ban_score(1, BAN_THRESHOLD, "test");
        }
        pm.add_ban_score(1, 1, "test");
        assert_eq!(outcome(&pm, 1), Outcome::Kept, "{case}");
    }

    // The must-succeed half: an ordinary peer is punished once its score
    // reaches the threshold, and not before.
    let (pm, _dir) = mk_pm();
    let _rx = add_peer(&pm, peer(1, "10.62.0.6:8333", Direction::Outbound));
    pm.add_ban_score(1, BAN_THRESHOLD - 1, "test");
    assert_eq!(outcome(&pm, 1), Outcome::Kept, "under the threshold");
    pm.add_ban_score(1, 1, "test");
    assert_eq!(outcome(&pm, 1), Outcome::Banned, "at the threshold");
}

/// The case that matters most, through the message handler: a `getblocktxn`
/// naming an index past the end of the block is `Misbehaving` in Core
/// (`SendBlockTransactions`, "getblocktxn with out-of-bounds tx indices").
/// From an inbound onion peer it disconnects that peer and bans nothing, so
/// the next onion peer still gets in; from an ordinary peer the address is
/// banned as before.
#[test]
fn an_out_of_range_getblocktxn_from_an_inbound_onion_peer_bans_nothing() {
    let (pm, _dir) = mk_pm();
    let mempool = Mempool::new(1_000_000, 0);
    let block = crate::mining::miner::build_block_to_script(
        &pm.chain_state,
        &mempool,
        bitcoin::ScriptBuf::new_op_return([0x2au8; 4]),
        None,
    )
    .expect("mine a regtest block");
    pm.chain_state.accept_block(&block).expect("accept the block");
    let request = || {
        NetworkMessage::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: bitcoin::bip152::BlockTransactionsRequest {
                block_hash: block.block_hash(),
                indexes: vec![5],
            },
        })
    };

    let mut onion = peer(1, "127.0.0.1:50000", Direction::Inbound);
    onion.inbound_onion = true;
    let _rx = add_peer(&pm, onion);
    pm.handle_message(1, request(), InFlight::adopt(None));
    assert!(!pm.peers.read().contains_key(&1), "the onion peer is disconnected");
    assert!(pm.list_banned().is_empty(), "and nothing is banned");
    assert!(
        !pm.is_addr_banned(&"127.0.0.1:50001".parse().unwrap()),
        "the next onion peer is not refused"
    );

    let ordinary: SocketAddr = "10.62.0.7:50000".parse().unwrap();
    let _rx = add_peer(&pm, peer(2, "10.62.0.7:50000", Direction::Inbound));
    pm.handle_message(2, request(), InFlight::adopt(None));
    assert!(!pm.peers.read().contains_key(&2), "the ordinary peer is disconnected");
    assert!(pm.is_addr_banned(&ordinary), "and its address banned");
}

/// Core's `ConnectedThroughNetwork`: a peer that came in on the onion
/// listener is on the onion network, whatever its socket address, and
/// `getpeerinfo.network` says so (`net.cpp`, `rpc/net.cpp`).
#[test]
fn getpeerinfo_reports_an_inbound_onion_peer_as_onion() {
    let stats = PeerStats::new(NetTotals::new());
    let mut info = peer(1, "127.0.0.1:50000", Direction::Inbound);
    assert_eq!(info.to_rpc_json(&stats)["network"], "not_publicly_routable");
    info.inbound_onion = true;
    assert_eq!(info.to_rpc_json(&stats)["network"], "onion");
}

/// The accept path records which listener a peer came in on.
#[tokio::test]
async fn a_peer_accepted_on_the_onion_listener_is_marked_inbound_onion() {
    use crate::net::permissions::NetPermissions;
    for inbound_onion in [false, true] {
        let (pm, _dir) = mk_pm();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
        let (dialed, accepted) = tokio::join!(dialer, listener.accept());
        let (_dialed, (accepted, peer_addr)) = (dialed.unwrap(), accepted.unwrap());
        pm.accept_inbound_with_perms(accepted, peer_addr, NetPermissions::NONE, inbound_onion);
        let peers = pm.peers.read();
        let marked: Vec<bool> = peers.values().map(|h| h.info.inbound_onion).collect();
        assert_eq!(marked, vec![inbound_onion], "accepted with inbound_onion = {inbound_onion}");
    }
}
