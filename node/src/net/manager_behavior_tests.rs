//! The per-peer behaviour record (`crate::net::behavior`), counter by
//! counter, against a live `PeerManager`: a scripted peer does the thing,
//! and the counter moves. Each test names the counter it covers.

use super::p1c_tests::{coin_at, pm_with_coins, spend, COIN};
use super::txrequest_tests::{add_peer_with, MockClock};
use super::*;
use crate::net::flow::InFlight;

const SECOND: u64 = 1_000_000;

/// A connected, handshaken peer relaying by wtxid.
fn handshaken(pm: &PeerManager, id: PeerId, direction: Direction) -> mpsc::Receiver<NetworkMessage> {
    let rx = add_peer_with(pm, id, direction, |_| {});
    pm.start_tx_relay(id);
    rx
}

fn deliver(pm: &PeerManager, id: PeerId, msg: NetworkMessage) {
    pm.handle_message(id, msg, InFlight::new(None));
}

fn behavior<T>(pm: &PeerManager, id: PeerId, f: impl FnOnce(&crate::net::behavior::PeerBehavior) -> T) -> T {
    f(&pm.peers.read()[&id].info.behavior)
}

fn wtx(n: u8) -> Inventory {
    Inventory::WTx(bitcoin::Wtxid::from_byte_array([n; 32]))
}

fn version(start_height: i32) -> VersionMessage {
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    VersionMessage {
        version: 70016,
        services,
        timestamp: crate::time::now_secs() as i64,
        receiver: bitcoin::p2p::Address::new(&zero, ServiceFlags::NONE),
        sender: bitcoin::p2p::Address::new(&zero, services),
        nonce: 0xbe4a,
        user_agent: "/behavior-test:1/".into(),
        start_height,
        relay: true,
    }
}

/// `handshake`, over a real socket: the commands from the peer's `version`
/// to its `verack`, and its `version` fields.
#[tokio::test]
async fn handshake_records_the_commands_to_verack_and_the_version_fields() {
    use crate::net::connection::Connection;
    use bitcoin::p2p::Magic;

    let (pm, _dir) = pm_with_coins(&[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dialer = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let (dialed, accepted) = tokio::join!(dialer, listener.accept());
    let (dialed, (accepted, peer_addr)) = (dialed.unwrap(), accepted.unwrap());
    let mut info = PeerInfo::new(7, peer_addr, Direction::Inbound);
    info.state = PeerState::Connecting;
    let _rx = add_peer_with(&pm, 7, Direction::Inbound, |i| *i = info);
    let mut ours = Connection::with_magic(accepted, Magic::REGTEST);
    let mut theirs = Connection::with_magic(dialed, Magic::REGTEST);

    let remote = async {
        theirs.send(NetworkMessage::Version(version(500))).await.unwrap();
        loop {
            if matches!(theirs.recv().await.unwrap(), NetworkMessage::Verack) {
                break;
            }
        }
        theirs.send(NetworkMessage::WtxidRelay).await.unwrap();
        theirs.send(NetworkMessage::SendAddrV2).await.unwrap();
        theirs.send(NetworkMessage::Verack).await.unwrap();
    };
    let (handshake, ()) = tokio::join!(pm.perform_handshake(7, &mut ours, Direction::Inbound, crate::time::now_secs()), remote);
    handshake.unwrap();

    behavior(&pm, 7, |b| {
        assert_eq!(b.handshake.commands().collect::<Vec<_>>(), ["version", "wtxidrelay", "sendaddrv2", "verack"]);
        assert!(b.handshake.is_open(), "the announcements after verack are still to come");
        let v = b.version.as_ref().expect("version fields");
        assert_eq!(v.protocol_version, 70016);
        assert_eq!(v.services, (ServiceFlags::NETWORK | ServiceFlags::WITNESS).to_u64());
        assert!(v.relay);
        assert_eq!(v.start_height, 500);
        assert_eq!(v.user_agent, "/behavior-test:1/");
        assert!(b.claim_above_tip, "start_height 500 is above our tip");
    });
}

/// `handshake`, past `verack`: replies to our requests are left out, the
/// peer's announcements are kept, and its first other message closes the
/// transcript.
#[test]
fn handshake_after_verack_skips_replies_and_ends_at_the_first_non_announcement() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Outbound);
    {
        let mut peers = pm.peers.write();
        let h = peers.get_mut(&7).unwrap();
        h.info.behavior.handshake.observe("version", false);
        h.info.behavior.handshake.observe("verack", false);
        // Our initial `getheaders` is out.
        h.last_getheaders_sent = Some(Instant::now());
    }
    assert!(pm.capture_handshake(7, &NetworkMessage::Pong(1)));
    assert!(pm.capture_handshake(7, &NetworkMessage::Headers(Vec::new())));
    assert!(pm.capture_handshake(7, &NetworkMessage::SendHeaders));
    assert!(pm.capture_handshake(7, &NetworkMessage::FeeFilter(1000)));
    assert!(!pm.capture_handshake(7, &NetworkMessage::GetAddr), "getaddr ends the transcript");
    assert!(!pm.capture_handshake(7, &NetworkMessage::Ping(2)));
    behavior(&pm, 7, |b| {
        assert_eq!(b.handshake.commands().collect::<Vec<_>>(), ["version", "verack", "sendheaders", "feefilter", "getaddr"]);
    });

    // With no `getheaders` out, a `headers` is the peer's own, and counts.
    let _rx = handshaken(&pm, 8, Direction::Outbound);
    {
        let mut peers = pm.peers.write();
        let b = &mut peers.get_mut(&8).unwrap().info.behavior;
        b.handshake.observe("version", false);
        b.handshake.observe("verack", false);
    }
    assert!(!pm.capture_handshake(8, &NetworkMessage::Headers(Vec::new())));
    behavior(&pm, 8, |b| assert_eq!(b.handshake.commands().collect::<Vec<_>>(), ["version", "verack", "headers"]));
}

/// `inv_tx_in`: the transaction entries of the peer's `inv`s.
#[test]
fn inv_tx_in_counts_announced_transactions() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let block = Inventory::Block(bitcoin::BlockHash::from_byte_array([3; 32]));
    deliver(&pm, 7, NetworkMessage::Inv(vec![wtx(1), wtx(2), block]));
    deliver(&pm, 7, NetworkMessage::Inv(vec![wtx(3)]));
    assert_eq!(behavior(&pm, 7, |b| b.inv_tx_in), 3);
}

/// `inv_tx_announced_to`: each transaction a flush sends the peer.
#[test]
fn inv_tx_announced_to_counts_what_a_flush_sends() {
    let (pm, _dir) = pm_with_coins(&[20, 21]);
    let mut clock = MockClock::install();
    let _rx = handshaken(&pm, 10, Direction::Outbound);
    pm.handle_tx(1, spend(coin_at(20), COIN, 1_000, 20));
    pm.handle_tx(1, spend(coin_at(21), COIN, 1_000, 21));
    pm.send_tx_invs();
    assert_eq!(behavior(&pm, 10, |b| b.inv_tx_announced_to), 0, "queued, not yet announced");
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(behavior(&pm, 10, |b| b.inv_tx_announced_to), 2);
}

/// `getdata_tx_in`: the transaction entries of the peer's `getdata`s,
/// announced to it or not. Block entries are not counted here.
#[test]
fn getdata_tx_in_counts_requested_transactions() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let block = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([3; 32]));
    deliver(&pm, 7, NetworkMessage::GetData(vec![wtx(1), wtx(2), block]));
    assert_eq!(behavior(&pm, 7, |b| b.getdata_tx_in), 2);
    assert_eq!(behavior(&pm, 7, |b| b.getdata_latency.count()), 0, "nothing was announced to pair with");
}

/// `getdata_latency`: the delay from our `inv` to the peer's `getdata` for
/// the same transaction, once per announcement.
#[test]
fn getdata_latency_pairs_a_getdata_with_our_announcement() {
    let (pm, _dir) = pm_with_coins(&[22]);
    let mut clock = MockClock::install();
    let _rx = handshaken(&pm, 10, Direction::Outbound);
    let tx = spend(coin_at(22), COIN, 1_000, 22);
    pm.handle_tx(1, tx.clone());
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    let ask = Inventory::WTx(tx.compute_wtxid());
    deliver(&pm, 10, NetworkMessage::GetData(vec![ask]));
    deliver(&pm, 10, NetworkMessage::GetData(vec![ask]));
    behavior(&pm, 10, |b| {
        assert_eq!(b.getdata_latency.count(), 1, "one announcement, one sample");
        // Asked at once: well inside a second, whatever the test machine.
        assert!(b.getdata_latency.median_ms().is_some_and(|ms| ms <= 1_000), "{:?}", b.getdata_latency);
        assert_eq!(b.getdata_tx_in, 2);
    });
}

/// `headers_req`: `getheaders` the peer sent.
#[test]
fn headers_req_counts_getheaders() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let msg = bitcoin::p2p::message_blockdata::GetHeadersMessage::new(
        vec![pm.chain_state.tip_hash()],
        bitcoin::BlockHash::all_zeros(),
    );
    deliver(&pm, 7, NetworkMessage::GetHeaders(msg.clone()));
    deliver(&pm, 7, NetworkMessage::GetHeaders(msg));
    assert_eq!(behavior(&pm, 7, |b| b.headers_req), 2);
}

/// `blocks_req`: block entries of `getdata` (full, witness and compact) and
/// `getblocktxn`.
#[test]
fn blocks_req_counts_block_getdata_and_getblocktxn() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let h = bitcoin::BlockHash::from_byte_array([3; 32]);
    deliver(
        &pm,
        7,
        NetworkMessage::GetData(vec![Inventory::Block(h), Inventory::WitnessBlock(h), Inventory::CompactBlock(h), wtx(1)]),
    );
    deliver(
        &pm,
        7,
        NetworkMessage::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
            txs_request: bitcoin::bip152::BlockTransactionsRequest { block_hash: h, indexes: vec![0] },
        }),
    );
    assert_eq!(behavior(&pm, 7, |b| b.blocks_req), 4);
}

/// `getaddr_in`: every `getaddr`, the repeats Core ignores included.
#[test]
fn getaddr_in_counts_every_getaddr() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    assert_eq!(behavior(&pm, 7, |b| b.getaddr_in), 2);
}

/// `addr_in`: the entries of the peer's `addr` and `addrv2`.
#[test]
fn addr_in_counts_addresses_received() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let a: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    let b: SocketAddr = "1.2.3.5:8333".parse().unwrap();
    deliver(
        &pm,
        7,
        NetworkMessage::Addr(vec![
            (1, bitcoin::p2p::Address::new(&a, ServiceFlags::NETWORK)),
            (1, bitcoin::p2p::Address::new(&b, ServiceFlags::NETWORK)),
        ]),
    );
    deliver(
        &pm,
        7,
        NetworkMessage::AddrV2(vec![bitcoin::p2p::address::AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: bitcoin::p2p::address::AddrV2::Ipv4([1, 2, 3, 6].into()),
            port: 8333,
        }]),
    );
    assert_eq!(behavior(&pm, 7, |b| b.addr_in), 3);
}

/// `addr_out`: the addresses of our answer to its `getaddr`.
#[test]
fn addr_out_counts_addresses_sent() {
    let (pm, _dir) = pm_with_coins(&[]);
    let source = std::net::IpAddr::from([198, 51, 100, 1]);
    for i in 0..100u8 {
        pm.add_learned_addr_from(SocketAddr::from(([1, i, 9, 9], 8333)), 9, source);
    }
    let mut rx = handshaken(&pm, 7, Direction::Inbound);
    deliver(&pm, 7, NetworkMessage::GetAddr);
    let mut sent = 0;
    while let Ok(m) = rx.try_recv() {
        match m {
            NetworkMessage::Addr(a) => sent += a.len(),
            NetworkMessage::AddrV2(a) => sent += a.len(),
            _ => {}
        }
    }
    assert!(sent > 0, "the getaddr was answered");
    assert_eq!(behavior(&pm, 7, |b| b.addr_out), sent as u64);
}

/// `notfound_after_inv`: a `notfound` for a transaction the peer announced
/// and was asked for. One for anything else is not counted.
#[test]
fn notfound_after_inv_counts_announced_then_refused() {
    let _clock = MockClock::install();
    let (pm, _dir) = pm_with_coins(&[]);
    let mut rx = handshaken(&pm, 7, Direction::Outbound);
    deliver(&pm, 7, NetworkMessage::Inv(vec![wtx(1)]));
    let asked = std::iter::from_fn(|| rx.try_recv().ok()).any(|m| matches!(m, NetworkMessage::GetData(_)));
    assert!(asked, "the announcer is asked at once");
    deliver(&pm, 7, NetworkMessage::NotFound(vec![wtx(1), wtx(9)]));
    assert_eq!(behavior(&pm, 7, |b| b.notfound_after_inv), 1);
}

/// `height_claim_gap`: a short answer to our `getheaders` is held against
/// the peer's `start_height`. An empty one says its chain ends at our
/// locator's top.
#[test]
fn height_claim_gap_measures_start_height_against_a_short_answer() {
    let (pm, _dir) = pm_with_coins(&[]);
    let tip = pm.chain_state.tip_height();
    let _rx = handshaken(&pm, 7, Direction::Outbound);
    {
        let mut peers = pm.peers.write();
        let h = peers.get_mut(&7).unwrap();
        h.info.behavior.note_version(&version(tip as i32 + 50), tip);
    }
    pm.send_getheaders(7, sync::make_getheaders(&pm.chain_state));
    assert_eq!(behavior(&pm, 7, |b| b.last_locator_top), Some(tip));
    pm.handle_headers(7, Vec::new());
    assert_eq!(behavior(&pm, 7, |b| b.height_claim_gap), 50);

    // A `headers` with no `getheaders` out is not an answer.
    let _rx = handshaken(&pm, 8, Direction::Outbound);
    pm.peers.write().get_mut(&8).unwrap().info.behavior.note_version(&version(tip as i32 + 50), tip);
    pm.handle_headers(8, Vec::new());
    assert_eq!(behavior(&pm, 8, |b| b.height_claim_gap), 0);
}

/// `stalls`: each height a peer is charged with for not delivering while
/// another peer does, and a stall disconnect.
#[test]
fn stalls_count_charged_heights_and_a_stall_disconnect() {
    let (pm, _dir) = pm_with_coins(&[]);
    let mut prev = pm.chain_state.tip_hash();
    let base = pm.chain_state.tip_height();
    let now = crate::time::now_secs() as u32;
    for i in 1..=20u32 {
        let b = crate::chain::state::tests::build_test_block(prev, base + i, now + i);
        pm.chain_state.accept_header(&b.header).unwrap();
        prev = b.block_hash();
    }
    *pm.ibd.write() = Some(crate::net::ibd::IbdScheduler::new(base + 20, base, &pm.chain_state, 1024));
    let _rx7 = handshaken(&pm, 7, Direction::Outbound);
    let _rx8 = handshaken(&pm, 8, Direction::Outbound);

    // Peer 7 holds heights it was asked for two minutes ago, still active
    // otherwise; peer 8 is delivering.
    let held = {
        let mut ibd = pm.ibd.write();
        let s = ibd.as_mut().unwrap();
        let held = s.assign_blocks(7).len();
        s.note_delivering_peer(8);
        s.backdate_for_test(7, Duration::from_secs(120), false, true);
        held
    };
    assert!(held > 0);
    let (stalled, released, _) = pm.take_download_stalls();
    assert!(stalled.is_empty());
    assert_eq!(released, held);
    assert_eq!(behavior(&pm, 7, |b| b.stalls), held as u32, "one per charged height");

    // Now quiet for two minutes with blocks owed: a stall disconnect.
    {
        let mut ibd = pm.ibd.write();
        let s = ibd.as_mut().unwrap();
        s.assign_blocks(7);
        s.note_delivering_peer(8);
        s.backdate_for_test(7, Duration::from_secs(120), true, false);
    }
    let (stalled, _, _) = pm.take_download_stalls();
    assert_eq!(stalled, vec![7]);
    assert_eq!(behavior(&pm, 7, |b| b.stalls), held as u32 + 1);
}

/// `disconnect_reason`: set on the record as the peer goes, to the node's
/// reason when the node drops it and to `peer-closed` when the connection
/// ends on its own.
#[test]
fn disconnect_reason_is_set_as_the_peer_goes() {
    let (pm, _dir) = pm_with_coins(&[]);
    let _rx = handshaken(&pm, 7, Direction::Inbound);
    let _rx = handshaken(&pm, 8, Direction::Inbound);
    assert!(pm.disconnect_on_request(7));
    pm.handle_peer_disconnected(8);
    assert_eq!(*pm.retired_behavior.lock(), vec![(7, Some("rpc_request")), (8, Some("peer-closed"))]);

    // Turning networking off closes every record.
    let _rx = handshaken(&pm, 9, Direction::Inbound);
    pm.retired_behavior.lock().clear();
    pm.set_network_active(false);
    assert!(pm.retired_behavior.lock().contains(&(9, Some("network-inactive"))));
}
