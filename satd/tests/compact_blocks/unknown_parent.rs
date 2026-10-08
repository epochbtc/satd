//! Blocks whose parent the node does not know, over a raw P2P connection.
//!
//! Core refuses such a block as `prev-blk-not-found` and keeps nothing
//! (`validation.cpp:4216`). satd keeps one only if it asked for it, and asks
//! the sender for headers either way.

use super::*;

fn is_getheaders(m: &NetworkMessage) -> bool {
    matches!(m, NetworkMessage::GetHeaders(_))
}

/// A pong for `nonce` within `within`.
fn pong_within(peer: &mut RawPeer, nonce: u64, within: Duration) -> bool {
    peer.send(NetworkMessage::Ping(nonce));
    peer.recv_until(|m| matches!(m, NetworkMessage::Pong(n) if *n == nonce), within).is_some()
}

/// A block the node did not ask for, on a parent it does not know, is
/// dropped, and the sender is asked for headers: that is how the node learns
/// the parent. The block does not connect when its parent does.
///
/// Fails without the fix: no `getheaders` followed the block, and the block
/// waited in the buffer and connected right after its parent.
#[test]
fn an_unrequested_block_on_an_unknown_parent_is_dropped_and_headers_are_asked_for() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    let tip = block_at(&node, &best_hash(&node));
    let parent = build_block(&tip, height(&node) + 1, vec![], true, 81);
    let child = build_block(&parent, height(&node) + 2, vec![], true, 82);

    // The node also sends every peer a `getheaders` every ten seconds. Start
    // right after one, so the next one cannot land in the window below.
    peer.recv_until(is_getheaders, test_timeout(30)).expect("the opening getheaders");
    peer.recv_until(is_getheaders, test_timeout(30)).expect("a periodic getheaders");

    peer.send(NetworkMessage::Block(child.clone()));
    assert!(
        peer.recv_until(is_getheaders, Duration::from_secs(4)).is_some(),
        "a block on an unknown parent must be answered with getheaders"
    );

    peer.send(NetworkMessage::Block(parent.clone()));
    assert!(pong_within(&mut peer, 0x0b0b_0001, test_timeout(20)), "pong after the parent");
    poll_until(|| best_hash(&node) == parent.block_hash(), test_timeout(20), "the parent must connect");
    // The pong came after the parent's processing, which is where a waiting
    // child would have been connected.
    assert_eq!(best_hash(&node), parent.block_hash(), "the unrequested child must not have been kept");
    assert!(!peer.is_closed());
    assert_eq!(banned_count(&node), 0);
}

/// A block the node asked for after an `inv` waits for its parent and
/// connects after it, and a ping sent behind it is answered while it waits.
///
/// Fails without the fix: the waiting block held the peer's pong until its
/// parent connected, so the pong came only after the 60-second bound.
#[test]
fn a_requested_block_waits_for_its_parent_without_holding_the_pong() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    let tip = block_at(&node, &best_hash(&node));
    let parent = build_block(&tip, height(&node) + 1, vec![], true, 83);
    let child = build_block(&parent, height(&node) + 2, vec![], true, 84);

    peer.send(NetworkMessage::Inv(vec![Inventory::Block(child.block_hash())]));
    collect_until(&mut peer, is_getdata_for(child.block_hash()), test_timeout(20), "a getdata for the child");
    peer.send(NetworkMessage::Block(child.clone()));
    assert!(
        pong_within(&mut peer, 0x0b0b_0002, Duration::from_secs(10)),
        "the pong must not wait for the child's parent"
    );
    assert_eq!(height(&node), 1, "fixture: the child cannot connect yet");

    peer.send(NetworkMessage::Block(parent.clone()));
    poll_until(|| best_hash(&node) == child.block_hash(), test_timeout(20), "the child must follow its parent");
}
