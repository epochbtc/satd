//! A block body that arrives before its parent is known skips the P2P
//! mutation gate (Core's `IsBlockMutated` needs the parent to decide the
//! witness rules) and waits in the unknown-parent buffer. When the parent
//! connects, the buffer hands it to `accept_block` with its header known by
//! then. A body the header does not commit to must not get the header marked
//! invalid on that route.

use super::*;
use crate::chain::state::tests::{build_test_block, make_chain_state};

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

/// An empty body for block 5, sent before block 4 is known, then the headers,
/// then block 4, then the real block 5: the real block connects.
///
/// Fails without the fix: the buffered empty body reached `accept_block`
/// after block 4 connected, failed `bad-blk-length` with block 5's header
/// known, and marked block 5 `Invalid`; the real block 5 was then refused as
/// a duplicate and the tip stayed at 4.
#[test]
fn an_empty_body_buffered_before_its_parent_does_not_bar_the_real_block() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut parent = genesis;
    for h in 1..=3 {
        let b = build_test_block(parent, h, 1_707_000_000 + h);
        parent = cs.accept_block(&b).expect("connect fixture block").hash();
    }
    let b4 = build_test_block(parent, 4, 1_707_000_004);
    let b5 = build_test_block(b4.block_hash(), 5, 1_707_000_005);
    let empty5 = bitcoin::Block { header: b5.header, txdata: Vec::new() };

    let cs = Arc::new(cs);
    let pm = peer_manager_over(cs.clone());
    assert!(pm.ibd.read().is_none(), "fixture: a synced node, not IBD");
    let in_flight = || crate::net::flow::InFlight::new(None);

    // Only a block the node asked for waits for an unknown parent, as one
    // fetched after an `inv` does.
    pm.note_blocks_requested(7, &[b5.block_hash()]);
    pm.handle_message(7, NetworkMessage::Block(empty5), in_flight());
    pm.handle_message(7, NetworkMessage::Headers(vec![b4.header, b5.header]), in_flight());
    pm.handle_message(7, NetworkMessage::Block(b4.clone()), in_flight());
    assert!(
        tip_reaches(&cs, b4.block_hash(), Duration::from_secs(10)),
        "block 4 must connect"
    );

    pm.handle_message(7, NetworkMessage::Block(b5.clone()), in_flight());
    assert!(
        tip_reaches(&cs, b5.block_hash(), Duration::from_secs(10)),
        "the real block 5 must connect; its status is {:?}",
        cs.get_block_index(&b5.block_hash()).map(|e| e.status)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
