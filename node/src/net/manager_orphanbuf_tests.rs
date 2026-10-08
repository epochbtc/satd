//! Blocks whose parent the node does not know, through `handle_message` and
//! the real block processor thread.
//!
//! Core keeps none of them: `AcceptBlockHeader` refuses such a block as
//! `prev-blk-not-found` (`validation.cpp:4216`). satd keeps one only if it
//! asked for it, within the bounds in [`crate::net::orphan_blocks`], so it
//! can connect without being fetched again once its parent does.

use super::*;
use crate::chain::state::tests::{build_test_block, make_chain_state};
use crate::net::flow::{InFlight, PeerFlow};

fn peer_manager_over(chain_state: Arc<ChainState>) -> Arc<PeerManager> {
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // Leak the sender so the channel stays open for the manager's life.
    std::mem::forget(shutdown_tx);
    PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx)
}

fn tip_reaches(cs: &ChainState, hash: bitcoin::BlockHash, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while cs.tip_hash() != hash && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    cs.tip_hash() == hash
}

fn idle_within(flow: &PeerFlow, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while !flow.is_idle() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    flow.is_idle()
}

/// A synced node at height 3, with blocks 4 and 5 built on it but unknown to
/// the node.
fn fixture() -> (Arc<ChainState>, std::path::PathBuf, bitcoin::Block, bitcoin::Block) {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut parent = genesis;
    for h in 1..=3 {
        let b = build_test_block(parent, h, 1_707_100_000 + h);
        parent = cs.accept_block(&b).expect("connect fixture block").hash();
    }
    let b4 = build_test_block(parent, 4, 1_707_100_004);
    let b5 = build_test_block(b4.block_hash(), 5, 1_707_100_005);
    (Arc::new(cs), dir, b4, b5)
}

/// A block the node never asked for, whose parent it does not know, is not
/// kept: when the parent then connects, the block does not follow it.
///
/// Fails without the fix: the block waited in the buffer, with no request
/// behind it, and connected as soon as block 4 did.
#[test]
fn an_unrequested_block_with_an_unknown_parent_is_not_kept() {
    let (cs, dir, b4, b5) = fixture();
    let pm = peer_manager_over(cs.clone());
    assert!(pm.ibd.read().is_none(), "fixture: a synced node, not IBD");

    pm.handle_message(7, NetworkMessage::Block(b5.clone()), InFlight::new(None));
    // Block 4's guard is counted out once the processor is done with it,
    // which includes connecting whatever was waiting for it.
    let flow = Arc::new(PeerFlow::new());
    pm.handle_message(7, NetworkMessage::Block(b4.clone()), InFlight::new(Some(flow.clone())));
    assert!(idle_within(&flow, Duration::from_secs(10)), "block 4 must be processed");
    assert_eq!(cs.tip_hash(), b4.block_hash(), "block 4 connects and block 5 was not kept");
    assert!(cs.get_block_index(&b5.block_hash()).is_none(), "block 5 is unknown to the node");

    // Sent again now that its parent is known, it connects.
    pm.handle_message(7, NetworkMessage::Block(b5.clone()), InFlight::new(None));
    assert!(tip_reaches(&cs, b5.block_hash(), Duration::from_secs(10)), "block 5 must connect");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A block the node asked for waits for its parent and connects right after
/// it. This is the counterpart to the test above: the buffer still does its
/// job for a block that was requested.
#[test]
fn a_requested_block_waits_for_its_parent_and_connects_after_it() {
    let (cs, dir, b4, b5) = fixture();
    let pm = peer_manager_over(cs.clone());

    // As `handle_inv` records a `getdata` for an announced block.
    pm.note_blocks_requested(7, &[b5.block_hash()]);
    pm.handle_message(7, NetworkMessage::Block(b5.clone()), InFlight::new(None));
    pm.handle_message(7, NetworkMessage::Block(b4.clone()), InFlight::new(None));
    assert!(
        tip_reaches(&cs, b5.block_hash(), Duration::from_secs(10)),
        "block 5 must connect from the buffer once block 4 does; tip is {}",
        cs.tip_hash()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A block waiting for its parent no longer counts as work in flight for the
/// peer that sent it, so a `ping` behind it is answered. Core is done with
/// such a block once it has refused it as `prev-blk-not-found`.
///
/// Fails without the fix: the waiting block held the sender's in-flight
/// guard until its parent connected, so every pong from that peer waited for
/// the 60-second bound in the meantime.
#[test]
fn a_block_waiting_for_its_parent_does_not_hold_the_senders_pong() {
    let (cs, dir, b4, b5) = fixture();
    let pm = peer_manager_over(cs.clone());

    pm.note_blocks_requested(7, &[b5.block_hash()]);
    let flow = Arc::new(PeerFlow::new());
    pm.handle_message(7, NetworkMessage::Block(b5.clone()), InFlight::new(Some(flow.clone())));
    assert!(
        idle_within(&flow, Duration::from_secs(10)),
        "the waiting block must not hold the peer's in-flight count ({} in flight)",
        flow.in_flight()
    );

    // It did wait rather than being dropped: it follows its parent in.
    pm.handle_message(7, NetworkMessage::Block(b4.clone()), InFlight::new(None));
    assert!(tip_reaches(&cs, b5.block_hash(), Duration::from_secs(10)), "block 5 must connect");

    let _ = std::fs::remove_dir_all(&dir);
}
