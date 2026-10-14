//! The IBD connector and a stored block that fails a consensus rule.

use super::*;
use crate::chain::state::tests::{build_test_block, build_test_block_spending, make_chain_state};
use crate::storage::blockindex::BlockStatus;
use bitcoin::OutPoint;
use bitcoin::hashes::Hash;

const BASE: u32 = 1_707_200_000;

/// Run the IBD connector over `cs` with `ibd` until it returns, or until
/// `limit` passes, when it is told to shut down. Returns whether it returned
/// on its own.
fn run_connector(
    cs: &ChainState,
    ibd: &Arc<parking_lot::RwLock<Option<crate::net::ibd::IbdScheduler>>>,
    limit: Duration,
) -> bool {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let fee_estimator = FeeEstimator::new();
    let connect_signal = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));
    let eta = Arc::new(AtomicU64::new(0));
    let peer_manager = std::sync::Weak::<PeerManager>::new();
    std::thread::scope(|s| {
        s.spawn(|| {
            let (mut last_log, mut last_prune) = (0u32, 0u32);
            PeerManager::ibd_connect_loop(
                cs,
                &fee_estimator,
                &connect_signal,
                ibd,
                0,
                1,
                &mut last_log,
                &mut last_prune,
                64,
                0,
                Network::Regtest,
                &eta,
                &peer_manager,
                &shutdown_rx,
            );
            let _ = done_tx.send(());
        });
        let finished = done_rx.recv_timeout(limit).is_ok();
        if !finished {
            let _ = shutdown_tx.send(true);
            let (lock, cvar) = &*connect_signal;
            *lock.lock() = true;
            cvar.notify_all();
        }
        finished
    })
}

/// Block 4 is stored and spends a coin that does not exist. The connector
/// marks it, and leaves IBD for the steady-state path instead of waiting on
/// a block it has judged.
///
/// Fails without the fix: the connector, with the block marked, parked on it
/// as a block with no usable data and never returned; before the mark existed
/// it retried the block thirty times and restarted IBD onto it.
#[test]
fn the_ibd_connector_leaves_ibd_when_a_stored_block_is_invalid() {
    let (cs, dir) = make_chain_state();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for h in 1..=3 {
        let b = build_test_block(parent, h, BASE + 600 * h);
        parent = cs.accept_block(&b).expect("fixture block").hash();
    }
    let missing = OutPoint { txid: bitcoin::Txid::from_byte_array([0xd7; 32]), vout: 0 };
    let bad = build_test_block_spending(parent, 4, BASE + 600 * 4, missing);
    let child = build_test_block(bad.block_hash(), 5, BASE + 600 * 5);
    for b in [&bad, &child] {
        cs.accept_header(&b.header).expect("fixture header");
        cs.store_block(b).expect("fixture body");
    }
    let ibd = Arc::new(parking_lot::RwLock::new(Some(crate::net::ibd::IbdScheduler::new(
        5, 3, &cs, 64,
    ))));

    let returned = run_connector(&cs, &ibd, Duration::from_secs(20));
    assert!(returned, "the connector must not keep waiting on a block it judged");
    assert!(ibd.read().is_none(), "IBD handed off to the steady-state path");
    assert_eq!(
        cs.get_block_index(&bad.block_hash()).map(|e| e.status),
        Some(BlockStatus::Invalid)
    );
    assert_eq!(cs.tip_height(), 3);
    assert_eq!(cs.best_header_hash(), parent, "the header tip left the invalid branch");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The must-succeed half: the same connector, given a valid block 4 and 5,
/// connects both and finishes IBD.
#[test]
fn the_ibd_connector_connects_valid_stored_blocks() {
    let (cs, dir) = make_chain_state();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for h in 1..=3 {
        let b = build_test_block(parent, h, BASE + 600 * h);
        parent = cs.accept_block(&b).expect("fixture block").hash();
    }
    let b4 = build_test_block(parent, 4, BASE + 600 * 4);
    let b5 = build_test_block(b4.block_hash(), 5, BASE + 600 * 5);
    for b in [&b4, &b5] {
        cs.accept_header(&b.header).expect("fixture header");
        cs.store_block(b).expect("fixture body");
    }
    let ibd = Arc::new(parking_lot::RwLock::new(Some(crate::net::ibd::IbdScheduler::new(
        5, 3, &cs, 64,
    ))));

    assert!(run_connector(&cs, &ibd, Duration::from_secs(20)), "IBD completes");
    assert!(ibd.read().is_none());
    assert_eq!(cs.tip_hash(), b5.block_hash());

    let _ = std::fs::remove_dir_all(&dir);
}
