//! #1119: a long chain of low-work headers must not hold the node in IBD.
//!
//! Header acceptance stores any header with valid proof of work, so a peer
//! can fork from genesis at minimum difficulty and send a chain taller than
//! the real one for little cost. The header tip used to be a height
//! high-water mark, raised by such a chain, and every reader of the header
//! lag then took the node to be far behind: `is_ibd` turned true, and with
//! it the node stopped fetching and accepting relayed transactions. Core
//! reports the most-work header (`m_best_header`) instead, and so does satd.

use super::*;
use super::txrequest_tests::{MockClock, add_peer};

fn mk_pm() -> (Arc<PeerManager>, tempfile::TempDir) {
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    let dir = tempfile::TempDir::new().unwrap();
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(shutdown_tx);
    let pm = PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx);
    (pm, dir)
}

/// `n` regtest headers on top of genesis, timestamps from `time_base`.
fn header_chain(n: u32, time_base: u32) -> Vec<bitcoin::block::Header> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    (1..=n)
        .map(|h| {
            let b = crate::chain::state::tests::build_test_block(parent, h, time_base + h);
            parent = b.block_hash();
            b.header
        })
        .collect()
}

/// The node is synced on a 30-block chain whose blocks each carry a
/// thousand times the minimum work. A peer sends 130 minimum-work headers
/// forking at genesis: 100 more than the tip, so a height high-water mark
/// put the node 100 blocks behind and in IBD.
///
/// The node stays out of IBD, its header tip stays at 30, and a transaction
/// announced afterwards is still requested.
///
/// Fails with the high-water mark: `headers_tip_height` read 130 and
/// `is_ibd` was true.
#[test]
fn a_tall_low_work_header_chain_leaves_the_node_out_of_ibd() {
    let _clock = MockClock::install();
    let (pm, _dir) = mk_pm();
    let cs = Arc::clone(&pm.chain_state);
    let now = crate::time::now_secs() as u32;
    let mut parent = cs.tip_hash();
    for h in 1..=30 {
        let b = crate::chain::state::tests::build_test_block(parent, h, now - 3_000 + 60 * h);
        parent = cs.accept_block(&b).expect("connect fixture block").hash();
    }
    cs.scale_active_chain_work_for_test(1_000);
    cs.refresh_best_header_to_tip();
    assert_eq!(cs.best_header_hash(), parent);

    let mut rx = add_peer(&pm, 1, Direction::Outbound);
    let fork = header_chain(130, now - 100_000);
    pm.handle_headers(1, fork.clone());
    let fork_tip = fork.last().unwrap().block_hash();
    assert!(cs.get_block_index(&fork_tip).is_some(), "fixture: the fork headers were accepted");

    assert_eq!(cs.headers_tip_height(), 30, "the low-work chain raised the header tip");
    assert_eq!(cs.best_header_hash(), parent);
    assert_eq!(pm.headers_tip.load(Ordering::Relaxed), 30);
    assert!(!pm.is_ibd(), "the low-work chain put the node in IBD");

    // Transaction relay: an announced transaction is fetched. In IBD the
    // announcement is dropped and no `getdata` goes out.
    while rx.try_recv().is_ok() {}
    let mut h = [0x11u8; 32];
    h[31] = 0x77;
    let w = bitcoin::Wtxid::from_byte_array(h);
    pm.handle_inv(1, vec![Inventory::WTx(w)]);
    let asked: Vec<Inventory> = std::iter::from_fn(|| rx.try_recv().ok())
        .filter_map(|m| match m {
            NetworkMessage::GetData(inv) => Some(inv),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(asked, vec![Inventory::WTx(w)], "the announced transaction was not requested");
}

/// A heavier-but-shorter switch that arrives as a block, not as headers:
/// the chain state's header tip drops, and the manager's mirror must follow
/// it on the next maintenance pass, or the node stays in IBD until a peer
/// next sends headers.
///
/// Fails without `refresh_headers_tip`: the mirror stayed at 60.
#[test]
fn a_block_that_lowers_the_header_tip_takes_the_node_out_of_ibd() {
    let (pm, _dir) = mk_pm();
    let cs = Arc::clone(&pm.chain_state);
    let now = crate::time::now_secs() as u32;
    let mut parent = cs.tip_hash();
    for h in 1..=5 {
        let b = crate::chain::state::tests::build_test_block(parent, h, now - 3_000 + 60 * h);
        parent = cs.accept_block(&b).expect("connect fixture block").hash();
    }
    let tip = parent;
    // 55 light headers above the tip, sent as headers.
    let mut above = Vec::new();
    let mut p = tip;
    for h in 6..=60 {
        let b = crate::chain::state::tests::build_test_block(p, h, now - 2_000 + h);
        p = b.block_hash();
        above.push(b.header);
    }
    let _rx = add_peer(&pm, 1, Direction::Outbound);
    pm.handle_headers(1, above);
    assert_eq!(pm.headers_tip.load(Ordering::Relaxed), 60);
    assert!(pm.is_ibd(), "fixture: 55 headers ahead of the tip");

    // The connected chain turns out heavier, and a block on it out-works
    // the 55 headers: the best header is that block, at height 6.
    cs.scale_active_chain_work_for_test(1_000);
    let b6 = crate::chain::state::tests::build_test_block(tip, 6, now - 1_000);
    cs.accept_block(&b6).expect("the heavier block connects");
    assert_eq!(cs.headers_tip_height(), 6);

    pm.refresh_headers_tip();
    assert_eq!(pm.headers_tip.load(Ordering::Relaxed), 6);
    assert!(!pm.is_ibd());
}
