//! Core v29's `bad-fork-prior-to-checkpoint` (`ContextualCheckBlockHeader`,
//! "Don't accept any forks from the main chain prior to last checkpoint"):
//! a header the index does not know yet, at a height below the highest
//! checkpoint the index holds (`BlockManager::GetLastCheckpoint`), is
//! refused and never stored.
//!
//! The fixture is a regtest chain of six blocks with a checkpoint pinned at
//! height 4.

use super::tests::{build_test_block, make_chain_state};
use super::*;

const CHECKPOINT_HEIGHT: u32 = 4;

/// Six regtest blocks on genesis, not yet given to any chain state.
fn main_chain() -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks = Vec::new();
    for h in 1..=6 {
        let b = build_test_block(parent, h, 1_707_000_000 + h);
        parent = b.block_hash();
        blocks.push(b);
    }
    blocks
}

fn checkpoint_on(blocks: &[Block]) -> Vec<Checkpoint> {
    vec![Checkpoint {
        height: CHECKPOINT_HEIGHT,
        hash: blocks[CHECKPOINT_HEIGHT as usize - 1].block_hash(),
    }]
}

/// A chain state with `blocks` connected and the checkpoint at height 4.
fn pinned_chain_state() -> (ChainState, std::path::PathBuf, Vec<Block>) {
    let (mut cs, dir) = make_chain_state();
    let blocks = main_chain();
    cs.set_checkpoints_for_test(checkpoint_on(&blocks));
    for b in &blocks {
        cs.accept_block(b).expect("connect fixture block");
    }
    assert_eq!(cs.tip_height(), 6);
    (cs, dir, blocks)
}

/// A block at `height` on `parent`, distinct from the main chain's.
fn fork_block(parent: &Block, height: u32) -> Block {
    build_test_block(parent.block_hash(), height, 1_707_100_000 + height)
}

fn is_fork_refusal(e: &ChainError, height: u32) -> bool {
    matches!(e, ChainError::ForkBeforeCheckpoint(h) if *h == height)
}

#[test]
fn a_header_forking_below_the_last_checkpoint_is_refused_and_not_stored() {
    let (cs, _dir, blocks) = pinned_chain_state();
    // On block 2, so at height 3: below the checkpoint at 4.
    let fork = fork_block(&blocks[1], 3);
    let hash = fork.block_hash();

    let err = cs.accept_header(&fork.header).expect_err("accept_header refuses the fork");
    assert!(is_fork_refusal(&err, 3), "accept_header: {err:?}");
    assert_eq!(err.to_string(), "bad-fork-prior-to-checkpoint");

    let (accepted, err) = cs.accept_headers(&[fork.header]);
    assert_eq!(accepted, 0);
    assert!(err.as_ref().is_some_and(|e| is_fork_refusal(e, 3)), "accept_headers: {err:?}");

    assert!(cs.get_block_index(&hash).is_none(), "the refused header has no index row");
    assert_eq!(cs.best_header_hash(), blocks[5].block_hash(), "best header unchanged");
}

/// A block that arrives without its header announced first takes the same
/// rule, on both block doors: `accept_block` and `store_block`.
#[test]
fn a_block_forking_below_the_last_checkpoint_is_refused_and_not_stored() {
    let (cs, _dir, blocks) = pinned_chain_state();
    let fork = fork_block(&blocks[1], 3);
    let hash = fork.block_hash();

    let err = cs.accept_block(&fork).expect_err("accept_block refuses the fork");
    assert!(is_fork_refusal(&err, 3), "accept_block: {err:?}");
    let err = cs.store_block(&fork).expect_err("store_block refuses the fork");
    assert!(is_fork_refusal(&err, 3), "store_block: {err:?}");

    assert!(cs.get_block_index(&hash).is_none(), "the refused block has no index row");
    assert_eq!(cs.tip_hash(), blocks[5].block_hash(), "tip unchanged");
}

/// At and above the checkpoint a fork is not this rule's business: a fork
/// on the checkpoint block (height 5) inherits its difficulty.
#[test]
fn a_header_forking_above_the_last_checkpoint_is_accepted() {
    let (cs, _dir, blocks) = pinned_chain_state();
    let fork = fork_block(&blocks[3], 5);
    cs.accept_header(&fork.header).expect("a fork above the checkpoint is accepted");
    let entry = cs.get_block_index(&fork.block_hash()).expect("indexed");
    assert_eq!(entry.height, 5);

    let fork2 = build_test_block(blocks[3].block_hash(), 5, 1_707_200_005);
    let (accepted, err) = cs.accept_headers(&[fork2.header]);
    assert_eq!((accepted, err.map(|e| e.to_string())), (1, None));
}

/// The rule runs after the already-known check: main-chain headers below the
/// checkpoint, sent again, are skipped as before, not refused.
#[test]
fn known_main_chain_headers_below_the_checkpoint_stay_harmless() {
    let (cs, _dir, blocks) = pinned_chain_state();
    let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
    let (accepted, err) = cs.accept_headers(&headers);
    assert_eq!((accepted, err.map(|e| e.to_string())), (0, None));
    let err = cs.accept_header(&blocks[1].header).expect_err("known");
    assert!(matches!(err, ChainError::Duplicate), "accept_header: {err:?}");
}

/// A fresh node is unaffected until its headers reach a checkpoint: with no
/// checkpoint in the index, a header sync from genesis is accepted whole,
/// and so is a fork below the (still unseen) checkpoint.
#[test]
fn a_fresh_header_sync_from_genesis_is_unaffected() {
    let (mut cs, _dir) = make_chain_state();
    let blocks = main_chain();
    cs.set_checkpoints_for_test(checkpoint_on(&blocks));

    let early_fork = fork_block(&blocks[1], 3);
    let (accepted, err) = cs.accept_headers(&[blocks[0].header, blocks[1].header, early_fork.header]);
    assert_eq!(
        (accepted, err.map(|e| e.to_string())),
        (3, None),
        "no checkpoint in the index yet: nothing is refused"
    );

    let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
    let (accepted, err) = cs.accept_headers(&headers);
    assert_eq!((accepted, err.map(|e| e.to_string())), (4, None));
    assert_eq!(cs.best_header_hash(), blocks[5].block_hash());
}

/// Core accepts a headers message one header at a time, so a checkpoint
/// earlier in the same batch already counts for the headers after it.
#[test]
fn a_checkpoint_earlier_in_the_batch_counts() {
    let (mut cs, _dir) = make_chain_state();
    let blocks = main_chain();
    cs.set_checkpoints_for_test(checkpoint_on(&blocks));

    let fork = fork_block(&blocks[1], 3);
    let mut headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
    headers.push(fork.header);
    let (accepted, err) = cs.accept_headers(&headers);
    assert_eq!(accepted, 6, "the main chain before the fork is committed");
    assert!(err.as_ref().is_some_and(|e| is_fork_refusal(e, 3)), "accept_headers: {err:?}");
    assert!(cs.get_block_index(&fork.block_hash()).is_none());
}

/// `-checkpoints=0` turns the rule off with the rest of the checkpoint
/// checks.
#[test]
fn with_checkpoints_disabled_the_fork_is_accepted() {
    let (mut cs, _dir) = make_chain_state();
    let blocks = main_chain();
    cs.set_checkpoints_for_test(checkpoint_on(&blocks));
    cs.set_enforce_checkpoints(false);
    for b in &blocks {
        cs.accept_block(b).expect("connect fixture block");
    }
    let fork = fork_block(&blocks[1], 3);
    cs.accept_header(&fork.header).expect("no checkpoint enforcement: the fork is accepted");
    assert!(cs.get_block_index(&fork.block_hash()).is_some());
    let fork_block_2 = fork_block(&blocks[2], 4);
    cs.store_block(&fork_block_2).expect("and so is a fork block");
}
