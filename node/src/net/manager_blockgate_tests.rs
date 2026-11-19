//! Core's `AcceptBlock` gates for blocks a peer sends (#1247): an
//! unrequested block is stored only when it could soon be the tip, and a
//! block whose header claims too little work stores nothing, not even the
//! header (`too-little-chainwork`). The same work threshold applies to a
//! `cmpctblock` header.

use super::*;
use crate::chain::state::PeerBlockGate;
use crate::chain::state::tests::{build_test_block, make_chain_state};
use crate::net::flow::{InFlight, PeerFlow};
use crate::storage::blockindex::BlockStatus;

const T0: u32 = 1_707_200_000;

/// A synced regtest chain of `n` blocks. Returns the chain state, its
/// datadir and the active chain's hashes, genesis first.
fn chain(n: u32) -> (Arc<ChainState>, std::path::PathBuf, Vec<bitcoin::BlockHash>) {
    let (cs, dir) = make_chain_state();
    let mut hashes = vec![bitcoin::constants::genesis_block(Network::Regtest).block_hash()];
    for h in 1..=n {
        let b = build_test_block(hashes[h as usize - 1], h, T0 + h);
        hashes.push(cs.accept_block(&b).expect("connect fixture block").hash());
    }
    (Arc::new(cs), dir, hashes)
}

/// `n` blocks on `hashes[from]`, a fork whose blocks carry `tag` in their
/// timestamps so they differ from the active chain's.
fn fork(hashes: &[bitcoin::BlockHash], from: u32, n: u32, tag: u32) -> Vec<bitcoin::Block> {
    let mut parent = hashes[from as usize];
    (1..=n)
        .map(|i| {
            let b = build_test_block(parent, from + i, T0 + from + i + tag);
            parent = b.block_hash();
            b
        })
        .collect()
}

fn peer_manager_over(chain_state: Arc<ChainState>) -> Arc<PeerManager> {
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    std::mem::forget(shutdown_tx);
    PeerManager::new(chain_state, mempool, fee_estimator, Network::Regtest, shutdown_rx)
}

/// Hand `block` to the manager as peer 7's and wait until the block
/// processor is done with it.
fn deliver(pm: &PeerManager, block: &bitcoin::Block) {
    let flow = Arc::new(PeerFlow::new());
    pm.handle_message(7, NetworkMessage::Block(block.clone()), InFlight::new(Some(flow.clone())));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !flow.is_idle() {
        assert!(Instant::now() < deadline, "the block was not processed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status(cs: &ChainState, b: &bitcoin::Block) -> Option<BlockStatus> {
    cs.get_block_index(&b.block_hash()).map(|e| e.status)
}

/// The gate itself, case by case, on a 300-block chain: the threshold is
/// the tip's work less 144 blocks' worth.
#[test]
fn the_gate_follows_cores_accept_block() {
    let (cs, dir, hashes) = chain(300);
    // A fork 200 blocks deep claims too little work: nothing is stored.
    let deep = fork(&hashes, 100, 1, 1_000_000);
    assert_eq!(cs.peer_block_gate(&deep[0].header, false), PeerBlockGate::TooLittleChainwork);
    assert_eq!(cs.peer_block_gate(&deep[0].header, true), PeerBlockGate::TooLittleChainwork, "asked for or not");
    // A fork 50 deep passes the threshold but has less work than the tip:
    // its header is indexed, its block only if it was asked for.
    let near = fork(&hashes, 250, 1, 1_000_000);
    assert_eq!(cs.peer_block_gate(&near[0].header, false), PeerBlockGate::HeaderOnly("less work than the tip"));
    assert_eq!(cs.peer_block_gate(&near[0].header, true), PeerBlockGate::Process);
    // As much work as the tip is enough (`fHasMoreOrSameWork`).
    let sibling = fork(&hashes, 299, 1, 1_000_000);
    assert_eq!(cs.peer_block_gate(&sibling[0].header, false), PeerBlockGate::Process);
    // The next block is processed.
    let next = build_test_block(hashes[300], 301, T0 + 301);
    assert_eq!(cs.peer_block_gate(&next.header, false), PeerBlockGate::Process);

    // `fTooFarAhead`: on a header chain running past the tip, a block more
    // than 288 above it is not stored unless asked for.
    let ahead = fork(&hashes, 300, 290, 0);
    let headers: Vec<_> = ahead.iter().map(|b| b.header).collect();
    assert_eq!(cs.accept_headers(&headers).0, 290);
    assert_eq!(cs.peer_block_gate(&ahead[287].header, false), PeerBlockGate::Process, "288 above the tip");
    assert_eq!(cs.peer_block_gate(&ahead[288].header, false), PeerBlockGate::HeaderOnly("too far ahead of the tip"));
    assert_eq!(cs.peer_block_gate(&ahead[288].header, true), PeerBlockGate::Process);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The last gate: an unrequested block on a chain below
/// `-minimumchainwork` is not stored.
#[test]
fn an_unrequested_block_below_the_minimum_chain_work_is_not_stored() {
    let (mut cs, dir) = make_chain_state();
    cs.set_minimum_chain_work(Some([0xff; 32]));
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let b1 = build_test_block(genesis, 1, T0 + 1);
    // The threshold itself is the minimum chain work here, so the header is
    // refused outright; once indexed by a requested path, only the block is.
    assert_eq!(cs.peer_block_gate(&b1.header, false), PeerBlockGate::TooLittleChainwork);
    cs.accept_header(&b1.header).unwrap();
    assert_eq!(cs.peer_block_gate(&b1.header, false), PeerBlockGate::HeaderOnly("below the minimum chain work"));
    assert_eq!(cs.peer_block_gate(&b1.header, true), PeerBlockGate::Process);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Through the block processor: an unrequested block on a deep low-work
/// fork leaves nothing behind (no `valid-headers` tip in `getchaintips`),
/// and one on a near fork with less work leaves only its header.
#[test]
fn unrequested_low_work_blocks_are_not_written() {
    let (cs, dir, hashes) = chain(300);
    let pm = peer_manager_over(cs.clone());
    assert!(pm.ibd.read().is_none(), "fixture: a synced node, not IBD");

    let deep = fork(&hashes, 100, 1, 1_000_000);
    deliver(&pm, &deep[0]);
    assert_eq!(status(&cs, &deep[0]), None, "the deep fork's block left an index entry");

    let near = fork(&hashes, 250, 1, 1_000_000);
    deliver(&pm, &near[0]);
    assert_eq!(status(&cs, &near[0]), Some(BlockStatus::HeaderOnly), "the near fork's block was stored");

    // The same block, asked for, is stored.
    pm.note_blocks_requested(7, &[near[0].block_hash()]);
    deliver(&pm, &near[0]);
    assert_eq!(status(&cs, &near[0]), Some(BlockStatus::DataStored));
    assert_eq!(cs.tip_hash(), hashes[300], "the tip did not move");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core's `cmpctblock` handler ignores a header on a chain below the work
/// threshold, known or not: nothing is indexed and nothing is asked for.
#[test]
fn a_low_work_compact_block_header_is_ignored() {
    let (cs, dir, hashes) = chain(300);
    let pm = peer_manager_over(cs.clone());
    let deep = fork(&hashes, 100, 1, 1_000_000);
    assert!(pm.accept_compact_header(7, &deep[0].header).is_none());
    assert!(cs.get_block_index(&deep[0].block_hash()).is_none());
    // A header near the tip still goes in.
    let near = fork(&hashes, 299, 1, 1_000_000);
    assert!(pm.accept_compact_header(7, &near[0].header).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block `getblockfrompeer` asked for counts as requested, as Core
/// processes an operator fetch with `force_processing`: a headers-only side
/// branch, the RPC's main use, is stored, not dropped by the gate.
#[test]
fn a_block_fetched_by_getblockfrompeer_passes_the_gate() {
    let (cs, dir, hashes) = chain(300);
    let pm = peer_manager_over(cs.clone());
    let near = fork(&hashes, 250, 1, 1_000_000);
    cs.accept_header(&near[0].header).unwrap();
    pm.block_refetch.write().insert((near[0].block_hash(), 7), Instant::now());
    deliver(&pm, &near[0]);
    assert_eq!(status(&cs, &near[0]), Some(BlockStatus::DataStored), "the fetched block was dropped");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same gates during IBD. The download window takes a late delivery of
/// any height in it, so without them an unrequested block on a fork inside
/// the window was stored: a deep low-work one is now refused outright, and
/// one with less work than the tip leaves only its header.
#[test]
fn unrequested_low_work_blocks_are_not_written_during_ibd() {
    let (cs, dir, hashes) = chain(300);
    let pm = peer_manager_over(cs.clone());
    // Headers well past the tip, and a scheduler over them.
    let ahead = fork(&hashes, 300, 100, 0);
    let headers: Vec<_> = ahead.iter().map(|b| b.header).collect();
    assert_eq!(cs.accept_headers(&headers).0, 100);
    *pm.ibd.write() = Some(IbdScheduler::new(400, 300, &cs, 1024));

    let deep = fork(&hashes, 100, 1, 1_000_000);
    let near = fork(&hashes, 250, 1, 1_000_000);
    pm.handle_block_ibd(7, deep[0].clone(), false, InFlight::new(None));
    pm.handle_block_ibd(7, near[0].clone(), false, InFlight::new(None));
    // A block on the best-header chain is still stored, unrequested.
    pm.handle_block_ibd(7, ahead[0].clone(), false, InFlight::new(None));
    pm.wait_for_ibd_stores();
    assert_eq!(status(&cs, &deep[0]), None, "the deep fork's block left an index entry");
    assert_eq!(status(&cs, &near[0]), Some(BlockStatus::HeaderOnly), "the near fork's block was stored");
    assert_ne!(status(&cs, &ahead[0]), Some(BlockStatus::HeaderOnly), "the best-header chain's block was not stored");
    let _ = std::fs::remove_dir_all(&dir);
}

/// "On the best-header chain" in the IBD gate is ancestry, not the height
/// row: when the best header is on a branch that leaves the active chain
/// below the tip, that branch's blocks at or below the tip's height count as
/// requested and are stored, where the height row (the active chain's
/// block) would have taken them for a side branch with less work.
#[test]
fn the_ibd_gate_follows_the_best_header_branch_below_the_tip() {
    let (cs, dir, hashes) = chain(300);
    let pm = peer_manager_over(cs.clone());
    let branch = fork(&hashes, 290, 110, 3);
    let headers: Vec<_> = branch.iter().map(|b| b.header).collect();
    assert_eq!(cs.accept_headers(&headers).0, 110);
    assert_eq!(cs.best_header_hash(), branch.last().unwrap().block_hash(), "fixture: the branch is the best header chain");
    *pm.ibd.write() = Some(IbdScheduler::new(400, 300, &cs, 1024));
    // Height 295: below the tip, on the best-header branch.
    pm.handle_block_ibd(7, branch[4].clone(), false, InFlight::new(None));
    pm.wait_for_ibd_stores();
    assert_eq!(status(&cs, &branch[4]), Some(BlockStatus::DataStored), "the best-header branch's block was not stored");
    let _ = std::fs::remove_dir_all(&dir);
}
