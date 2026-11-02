//! `is_initial_block_download` as Core's `UpdateIBDStatus` /
//! `CChain::IsTipRecent` (#1071): the tip needs the minimum chain work as
//! well as a recent timestamp, and once the node has left IBD it stays out.
//!
//! No test here moves the mock clock, which is process-global; a stale tip
//! comes from invalidating back to old blocks instead.

use super::tests::build_test_block;
use super::*;
use crate::storage::db::InMemoryStore;
use crate::validation::script::NoopVerifier;

/// Old enough to be stale under the default 24 h `-maxtipage`.
const OLD: u32 = 1_709_000_000;

fn chain_state() -> (ChainState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    (cs, dir)
}

/// Blocks 1 and 2 stamped long ago, then block 3 stamped now.
fn old_then_recent() -> Vec<Block> {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let b1 = build_test_block(genesis, 1, OLD);
    let b2 = build_test_block(b1.block_hash(), 2, OLD + 600);
    let b3 = build_test_block(b2.block_hash(), 3, crate::time::now_secs() as u32);
    vec![b1, b2, b3]
}

fn accept_all(cs: &ChainState, blocks: &[Block]) {
    for b in blocks {
        cs.accept_block(b).unwrap();
    }
    assert_eq!(cs.tip_hash(), blocks.last().unwrap().block_hash(), "premise: every block connected");
}

/// A recent tip with less than the minimum chain work is still in IBD: a
/// short, recent-looking chain must not take the node out. Regtest's minimum
/// is zero, so `-minimumchainwork` sets one. Perturbation: drop the
/// chain-work comparison and the first assertion fails.
#[test]
fn a_recent_tip_below_the_minimum_chain_work_stays_in_ibd() {
    let (mut cs, _dir) = chain_state();
    let mut floor = [0u8; 32];
    floor[0] = 1;
    cs.set_minimum_chain_work(Some(floor));
    accept_all(&cs, &old_then_recent());
    assert!(cs.is_initial_block_download(), "recent tip, too little work");

    cs.set_minimum_chain_work(None);
    assert!(!cs.is_initial_block_download(), "the same tip leaves IBD without the floor");
}

/// Once out of IBD the node stays out when its tip goes stale. Nothing reads
/// the predicate until the tip is already stale, so this also shows the
/// latch is judged at each tip write, as Core's `SetTip` does, not only on
/// read. Perturbations: drop the latch, or the judgement in `set_tip`, and
/// the last assertion fails.
#[test]
fn leaving_ibd_latches_even_when_the_tip_goes_stale() {
    let blocks = old_then_recent();

    // The must-be-true half: the old tip on its own is in IBD.
    let (cs, _dir) = chain_state();
    accept_all(&cs, &blocks[..2]);
    assert!(cs.is_initial_block_download(), "premise: a stale tip is in IBD");

    let (cs, _dir) = chain_state();
    accept_all(&cs, &blocks);
    cs.invalidate_block(blocks[2].block_hash()).unwrap();
    assert_eq!(cs.tip_hash(), blocks[1].block_hash(), "premise: back on the stale tip");
    assert!(!cs.is_initial_block_download(), "left IBD at block 3; a stale tip does not re-enter it");
}

/// The latch does not arm in `BulkLoad` write mode (Core's `LoadingBlocks`),
/// even on a tip that would pass. Perturbation: drop the `bulk_load` check
/// and the first assertion fails.
#[test]
fn the_latch_does_not_arm_during_a_bulk_load() {
    let (cs, _dir) = chain_state();
    cs.set_write_mode(crate::storage::WriteMode::BulkLoad);
    accept_all(&cs, &old_then_recent());
    assert!(cs.is_initial_block_download(), "in IBD while the load runs");

    cs.set_write_mode(crate::storage::WriteMode::Normal);
    assert!(!cs.is_initial_block_download(), "leaves IBD once the load ends");
}
