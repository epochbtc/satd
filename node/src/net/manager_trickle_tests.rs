//! Core's transaction announcement schedule, through the manager: a
//! transaction is queued, announced at the peer's next flush, and served to
//! a peer only once announced to it (`p2p_leak_tx.py`,
//! `p2p_orphan_handling.py` `test_arrival_timing_orphan`).

use super::p1c_tests::{coin_at, pm_with_coins, spend, COIN};
use super::txrequest_tests::{add_peer_with, MockClock};
use super::*;

const SECOND: u64 = 1_000_000;

/// A connected peer that has finished the handshake, with its queue.
fn handshaken(
    pm: &PeerManager,
    id: PeerId,
    direction: Direction,
    tweak: impl FnOnce(&mut PeerInfo),
) -> mpsc::Receiver<NetworkMessage> {
    let rx = add_peer_with(pm, id, direction, tweak);
    pm.start_tx_relay(id);
    rx
}

/// Every transaction `inv` waiting for the peer, flattened.
fn invs(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<Inventory> {
    let mut out = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        if let NetworkMessage::Inv(inv) = msg {
            out.extend(inv);
        }
    }
    out
}

fn relay_state(pm: &PeerManager, id: PeerId) -> (usize, u64) {
    let peers = pm.peers.read();
    let r = &peers[&id].tx_relay;
    (r.inv_to_send(), r.last_inv_sequence())
}

/// A transaction is queued, not announced, until the peer's timer passes.
#[test]
fn a_transaction_is_announced_at_the_peer_s_next_flush_not_at_once() {
    let (pm, _dir) = pm_with_coins(&[1]);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let tx = spend(coin_at(1), COIN, 1_000, 1);
    pm.handle_tx(1, tx.clone());
    assert!(pm.mempool.get(&tx.compute_txid()).is_some());

    pm.send_tx_invs();
    assert!(invs(&mut rx).is_empty(), "announced before the timer");
    assert_eq!(relay_state(&pm, 10).0, 1, "queued");

    // Outbound flushes average 2 s; a minute is past any timer drawn.
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(tx.compute_wtxid())]);
    assert_eq!(relay_state(&pm, 10), (0, pm.mempool.mempool_sequence()));
}

/// Core's `info_for_relay`: a transaction that entered the mempool after
/// the peer's last flush is `notfound`, and served once it is announced.
#[test]
fn a_transaction_not_yet_announced_is_not_served() {
    let (pm, _dir) = pm_with_coins(&[2]);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Inbound, |_| {});
    let tx = spend(coin_at(2), COIN, 1_000, 2);
    pm.handle_tx(1, tx.clone());
    let ask = Inventory::WTx(tx.compute_wtxid());

    pm.handle_getdata(10, vec![ask]);
    match rx.try_recv() {
        Ok(NetworkMessage::NotFound(inv)) => assert_eq!(inv, vec![ask]),
        other => panic!("expected notfound, got {other:?}"),
    }

    clock.advance(600 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![ask]);
    pm.handle_getdata(10, vec![ask]);
    match rx.try_recv() {
        Ok(NetworkMessage::Tx(got)) => assert_eq!(got, tx),
        other => panic!("expected the tx, got {other:?}"),
    }
}

/// Core's `m_most_recent_block_txs`: a transaction that left the mempool
/// for the most recent block is still served.
#[test]
fn a_transaction_in_the_most_recent_block_is_served() {
    let (pm, _dir) = pm_with_coins(&[3]);
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let tx = spend(coin_at(3), COIN, 1_000, 3);
    let tip = pm.chain_state.tip_hash();
    let mut block = crate::chain::state::tests::build_test_block(tip, 2, crate::time::now_secs() as u32);
    block.txdata.push(tx.clone());
    pm.compact_for(&block, 2, false);

    pm.handle_getdata(10, vec![Inventory::WTx(tx.compute_wtxid()), Inventory::Transaction(tx.compute_txid())]);
    for _ in 0..2 {
        match rx.try_recv() {
            Ok(NetworkMessage::Tx(got)) => assert_eq!(got, tx),
            other => panic!("expected the tx, got {other:?}"),
        }
    }
}

/// Core's `CompareInvMempoolOrder`: a parent is announced before its
/// child, whatever their feerates.
#[test]
fn a_parent_is_announced_before_its_child() {
    let (pm, _dir) = pm_with_coins(&[4]);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let parent = spend(coin_at(4), COIN, 1_000, 4);
    let child = spend(bitcoin::OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 1_000, 50_000, 5);
    pm.handle_tx(1, parent.clone());
    pm.handle_tx(1, child.clone());
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(parent.compute_wtxid()), Inventory::WTx(child.compute_wtxid())]);
}

/// Core's `broadcast_max`: one flush announces 70 of a short queue; the
/// rest wait for the next.
#[test]
fn a_flush_announces_at_most_seventy() {
    let tags: Vec<u8> = (10..110).collect();
    let (pm, _dir) = pm_with_coins(&tags);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    for t in &tags {
        pm.handle_tx(1, spend(coin_at(*t), COIN, 1_000, *t));
    }
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx).len(), 70);
    assert_eq!(relay_state(&pm, 10).0, 30);
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx).len(), 30);
}

/// Core's `AddKnownTx`: the peer that sent a transaction is not announced
/// it back, nor is one that announced it.
#[test]
fn a_peer_is_not_announced_what_it_sent_or_announced() {
    let (pm, _dir) = pm_with_coins(&[5, 6]);
    let mut clock = MockClock::install();
    let mut sender = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let mut announcer = handshaken(&pm, 11, Direction::Outbound, |_| {});
    let mut other = handshaken(&pm, 12, Direction::Outbound, |_| {});
    let tx = spend(coin_at(5), COIN, 1_000, 5);
    pm.handle_inv(11, vec![Inventory::WTx(tx.compute_wtxid())]);
    pm.handle_tx(10, tx.clone());
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert!(invs(&mut sender).is_empty());
    assert!(invs(&mut announcer).iter().all(|i| *i != Inventory::WTx(tx.compute_wtxid())));
    assert_eq!(invs(&mut other), vec![Inventory::WTx(tx.compute_wtxid())]);
}

/// A transaction below the peer's `feefilter` is not announced to it.
#[test]
fn a_flush_applies_the_peer_s_fee_filter() {
    let (pm, _dir) = pm_with_coins(&[7]);
    let mut clock = MockClock::install();
    let mut picky = handshaken(&pm, 10, Direction::Outbound, |i| i.fee_filter = 1_000_000);
    let mut easy = handshaken(&pm, 11, Direction::Outbound, |_| {});
    let tx = spend(coin_at(7), COIN, 1_000, 7);
    pm.handle_tx(1, tx.clone());
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert!(invs(&mut picky).is_empty());
    assert_eq!(invs(&mut easy).len(), 1);
    assert_eq!(relay_state(&pm, 10).0, 0, "passed over, not kept");
}

/// Inbound peers that reached the node on the same listener and network
/// share one timer (Core's `NextInvToInbounds`); a `noban` peer is flushed
/// every time.
#[test]
fn inbound_peers_share_a_timer_and_noban_peers_wait_for_none() {
    let (pm, _dir) = pm_with_coins(&[8]);
    let _clock = MockClock::install();
    let now = crate::time::now_micros();
    let bind: SocketAddr = "127.0.0.1:18444".parse().unwrap();
    let info = |id: PeerId, dir: Direction| {
        let mut i = PeerInfo::new(id, format!("10.0.0.{id}:8333").parse().unwrap(), dir);
        i.bind_addr = Some(bind);
        i
    };
    let a = pm.next_inv_send_time(&info(20, Direction::Inbound), now);
    let b = pm.next_inv_send_time(&info(21, Direction::Inbound), now);
    assert_eq!(a, b, "one timer for the listener");
    assert!(a > now);
    let mut other_listener = info(22, Direction::Inbound);
    other_listener.bind_addr = Some("127.0.0.1:18445".parse().unwrap());
    assert_ne!(pm.next_inv_send_time(&other_listener, now), a, "another listener has its own");
    let outbound: Vec<u64> = (0..8).map(|i| pm.next_inv_send_time(&info(30 + i, Direction::Outbound), now)).collect();
    assert!(outbound.iter().any(|t| *t != outbound[0]), "outbound peers draw their own");

    let mut rx = handshaken(&pm, 10, Direction::Inbound, |i| i.permissions.noban = true);
    let tx = spend(coin_at(8), COIN, 1_000, 8);
    pm.handle_tx(1, tx.clone());
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(tx.compute_wtxid())], "noban is not kept waiting");
}

/// Nothing is queued for a peer before its handshake; after it, the
/// peer's `last_inv_sequence` is the mempool's (`p2p_leak_tx.py`), and
/// `getpeerinfo` reports both.
#[test]
fn the_handshake_starts_the_queue_and_getpeerinfo_reports_it() {
    let (pm, _dir) = pm_with_coins(&[9, 12]);
    let _clock = MockClock::install();
    let _rx = add_peer_with(&pm, 10, Direction::Inbound, |_| {});
    let tx = spend(coin_at(9), COIN, 1_000, 9);
    pm.handle_tx(1, tx.clone());
    assert_eq!(relay_state(&pm, 10), (0, 1), "nothing queued before the handshake");

    pm.start_tx_relay(10);
    let sequence = pm.mempool.mempool_sequence();
    assert_eq!(relay_state(&pm, 10), (0, sequence));
    let tx2 = spend(coin_at(12), COIN, 1_000, 12);
    pm.handle_tx(1, tx2);
    let info = pm.get_peer_info();
    let entry = info.iter().find(|e| e["id"] == 10).unwrap();
    assert_eq!(entry["inv_to_send"], 1);
    assert_eq!(entry["last_inv_sequence"], sequence);
}

/// A BIP 35 `mempool` request is answered at the peer's next flush, not
/// at once.
#[test]
fn a_mempool_request_is_answered_at_the_next_flush() {
    let (pm, _dir) = pm_with_coins(&[11]);
    let mut clock = MockClock::install();
    let tx = spend(coin_at(11), COIN, 1_000, 11);
    pm.handle_tx(1, tx.clone());
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |i| i.permissions.mempool = true);
    pm.handle_mempool_request(10);
    assert!(invs(&mut rx).is_empty(), "answered before the flush");
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(tx.compute_wtxid())]);
}

/// Core's `ProcessInvalidTx`: the peer that sent an orphan has its
/// parents, by txid, so a parent is not announced to it by txid when it
/// arrives from another peer. (A wtxid relay peer is still announced it
/// by wtxid, as in Core.)
#[test]
fn the_sender_of_an_orphan_is_not_announced_its_parent() {
    let (pm, _dir) = pm_with_coins(&[13]);
    let mut clock = MockClock::install();
    let mut orphan_sender = handshaken(&pm, 10, Direction::Outbound, |i| i.wtxid_relay = false);
    let mut other = handshaken(&pm, 11, Direction::Outbound, |_| {});
    let parent = spend(coin_at(13), COIN, 1_000, 13);
    let child = spend(bitcoin::OutPoint { txid: parent.compute_txid(), vout: 0 }, COIN - 1_000, 1_000, 14);
    pm.handle_tx(10, child.clone());
    assert!(pm.orphanage.contains(&child.compute_txid()));
    pm.handle_tx(1, parent.clone());
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    let to_sender = invs(&mut orphan_sender);
    assert!(to_sender.is_empty(), "{to_sender:?}");
    assert!(invs(&mut other).contains(&Inventory::WTx(parent.compute_wtxid())));
}

/// A peer that announces a transaction after it was queued for it is not
/// announced it back: the flush looks at what the peer knows then.
#[test]
fn a_transaction_the_peer_announced_since_it_was_queued_is_passed_over() {
    let (pm, _dir) = pm_with_coins(&[15]);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let tx = spend(coin_at(15), COIN, 1_000, 15);
    pm.handle_tx(1, tx.clone());
    assert_eq!(relay_state(&pm, 10).0, 1);
    pm.handle_inv(10, vec![Inventory::WTx(tx.compute_wtxid())]);
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert!(invs(&mut rx).is_empty());
    assert_eq!(relay_state(&pm, 10).0, 0);
}

/// Core's `ReattemptInitialBroadcast` queues through `RelayTransaction`: a
/// local transaction rebroadcast before the peer's next flush is not
/// announced early, and is fetchable once it is announced.
#[test]
fn a_rebroadcast_waits_for_the_peer_s_flush() {
    let (pm, _dir) = pm_with_coins(&[16]);
    let mut clock = MockClock::install();
    let mut rx = handshaken(&pm, 10, Direction::Outbound, |_| {});
    let tx = spend(coin_at(16), COIN, 1_000, 16);
    let txid = pm.submit_and_announce(tx.clone(), crate::mempool::pool::TxSource::Rpc, false).unwrap();
    pm.rebroadcast_unbroadcast_txs();
    assert!(invs(&mut rx).is_empty(), "announced outside the flush");
    let ask = Inventory::WTx(tx.compute_wtxid());
    pm.handle_getdata(10, vec![ask]);
    assert!(matches!(rx.try_recv(), Ok(NetworkMessage::NotFound(_))));

    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![ask]);
    pm.handle_getdata(10, vec![ask]);
    match rx.try_recv() {
        Ok(NetworkMessage::Tx(got)) => assert_eq!(got.compute_txid(), txid),
        other => panic!("expected the tx, got {other:?}"),
    }
}

/// An announcement that does not fit on the peer's full queue is not
/// recorded as made: it stays queued, the peer's `last_inv_sequence` stays,
/// and the next flush with room announces it.
#[test]
fn an_announcement_that_could_not_be_sent_is_kept_for_the_next_flush() {
    let (pm, _dir) = pm_with_coins(&[17]);
    let mut clock = MockClock::install();
    let mut rx = super::txrequest_tests::add_peer_cap(&pm, 10, Direction::Outbound, 1, |_| {});
    pm.start_tx_relay(10);
    let before = relay_state(&pm, 10).1;
    let tx = spend(coin_at(17), COIN, 1_000, 17);
    pm.handle_tx(1, tx.clone());
    // Fill the peer's one-message queue.
    assert!(pm.send_to_peer(10, NetworkMessage::Ping(1)));

    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(relay_state(&pm, 10), (1, before), "kept, and nothing newly servable");
    assert!(matches!(rx.try_recv(), Ok(NetworkMessage::Ping(1))));

    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(tx.compute_wtxid())]);
    assert_eq!(relay_state(&pm, 10), (0, pm.mempool.mempool_sequence()));
}

/// A BIP 35 answer spanning two `inv` messages, of which only the first
/// fits on the peer's queue: what it announced may be fetched, though the
/// peer's `last_inv_sequence` stays where it was; what it did not announce
/// may not.
#[test]
fn a_partly_sent_mempool_answer_is_fetchable_where_it_was_sent() {
    let (pm, _dir) = pm_with_coins(&[18]);
    let mut clock = MockClock::install();
    let mut rx = super::txrequest_tests::add_peer_cap(&pm, 10, Direction::Outbound, 1, |i| i.permissions.mempool = true);
    pm.start_tx_relay(10);
    let before = relay_state(&pm, 10).1;
    for nonce in 0..(MAX_INV_PER_MSG as u64 + 1) {
        pm.mempool.insert_scoped_for_test(1_000 + nonce, 1_000, crate::mempool::pool::QuarantineScope::acting());
    }
    pm.mempool.resequence_for_test();
    pm.handle_mempool_request(10);
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(relay_state(&pm, 10).1, before, "not everything chosen was sent");

    let sent = match rx.try_recv() {
        Ok(NetworkMessage::Inv(inv)) => inv,
        other => panic!("expected the first chunk, got {other:?}"),
    };
    assert_eq!(sent.len(), MAX_INV_PER_MSG);
    // Served one entry at a time: the test drained the raw channel, so the
    // queue still counts the inv's bytes and `handle_getdata` would wait.
    let sender = pm.peers.read()[&10].msg_tx.clone();
    let last = relay_state(&pm, 10).1;
    let mut not_found = Vec::new();
    assert!(pm.serve_getdata_entry(10, &sender, sent[0], last, &mut not_found));
    match rx.try_recv() {
        Ok(NetworkMessage::Tx(_)) => {}
        other => panic!("an announced transaction must be served, got {other:?}"),
    }
    assert!(not_found.is_empty());
    let all: HashSet<bitcoin::Wtxid> = pm.mempool.relay_ids_above_feerate(0).into_iter().map(|(_, w)| w).collect();
    let announced: HashSet<bitcoin::Wtxid> =
        sent.iter().filter_map(|i| if let Inventory::WTx(w) = i { Some(*w) } else { None }).collect();
    let unsent = *all.difference(&announced).next().expect("one left out");
    assert!(pm.serve_getdata_entry(10, &sender, Inventory::WTx(unsent), last, &mut not_found));
    assert_eq!(not_found, vec![Inventory::WTx(unsent)], "not announced, not served");
    let _ = rx.try_recv();

    // The next flush sends what did not fit, not the whole answer again.
    assert_eq!(relay_state(&pm, 10).0, 1);
    clock.advance(60 * SECOND);
    pm.send_tx_invs();
    assert_eq!(invs(&mut rx), vec![Inventory::WTx(unsent)]);
    assert_eq!(relay_state(&pm, 10), (0, pm.mempool.mempool_sequence()));
}
