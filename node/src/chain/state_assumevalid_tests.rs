//! `-assumevalid` skips a block's scripts only under Core's five conditions
//! (`ConnectBlock`, `validation.cpp`); see `crate::chain::assumevalid`. satd
//! used to skip any block at or below the assumevalid block's height.

use super::tests::build_test_block;
use super::*;
use crate::chain::assumevalid as av;
use crate::storage::db::InMemoryStore;
use crate::validation::script::NoopVerifier;

const BASE: u32 = 1_709_000_000;

fn chain_state(assumevalid: AssumeValid) -> (ChainState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(NoopVerifier),
        assumevalid,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    (cs, dir)
}

/// Blocks 1..=n on regtest genesis, 600 s apart, not connected.
fn build_chain(parent: BlockHash, from: u32, n: u32, time_base: u32) -> Vec<Block> {
    let mut parent = parent;
    (from..from + n)
        .map(|h| {
            let b = build_test_block(parent, h, time_base + 600 * h);
            parent = b.block_hash();
            b
        })
        .collect()
}

fn genesis() -> BlockHash {
    bitcoin::constants::genesis_block(Network::Regtest).block_hash()
}

fn reason(cs: &ChainState, b: &Block, height: u32) -> av::ScriptCheckReason {
    cs.script_check_reason_at(height, &b.block_hash(), crate::time::now_secs())
}

#[test]
fn disabled_always_verifies() {
    let (cs, _dir) = chain_state(AssumeValid::Disabled);
    let blocks = build_chain(genesis(), 1, 1, BASE);
    cs.accept_block(&blocks[0]).unwrap();
    assert_eq!(reason(&cs, &blocks[0], 1), Some(av::ALWAYS_VERIFY));
}

#[test]
fn an_assumevalid_hash_not_in_the_headers_verifies() {
    let blocks = build_chain(genesis(), 1, 2, BASE);
    let (cs, _dir) = chain_state(AssumeValid::Hash(blocks[1].block_hash()));
    cs.accept_block(&blocks[0]).unwrap();
    assert_eq!(reason(&cs, &blocks[0], 1), Some(av::NOT_IN_HEADERS));
}

/// The chain is 2030 blocks with the assumevalid block at height 20.
/// Regtest proof is 2 per block, so two weeks on top is 2016 blocks.
///
/// - Block 13 has 2017 blocks above it: skipped.
/// - Block 14 has exactly 2016, which is two weeks; Core's bound is
///   inclusive, so it is verified.
/// - Blocks 20 and 21: verified, as too recent and as above the AV height.
/// - A side block at height 10: verified, as not in the AV chain.
///
/// The old height rule skipped every one of these except block 21.
/// Perturbation: replace the five-way decision with `height <= av_height`
/// and the side-block and too-recent assertions fail.
#[test]
fn only_buried_ancestors_of_the_assumevalid_block_skip_scripts() {
    const N: u32 = 2030;
    let blocks = build_chain(genesis(), 1, N, BASE);
    let av_block = &blocks[19];
    let (cs, _dir) = chain_state(AssumeValid::Hash(av_block.block_hash()));
    for b in &blocks {
        cs.accept_block(b).unwrap();
    }
    assert_eq!(cs.tip_height(), N);

    assert_eq!(reason(&cs, &blocks[12], 13), None, "2017 blocks on top: skipped");
    assert_eq!(reason(&cs, &blocks[13], 14), Some(av::TOO_RECENT), "exactly two weeks on top");
    assert_eq!(reason(&cs, av_block, 20), Some(av::TOO_RECENT));
    assert_eq!(reason(&cs, &blocks[20], 21), Some(av::ABOVE_AV_HEIGHT));

    // A competitor at height 10, below the assumevalid block, on another branch.
    let side = build_test_block(blocks[8].block_hash(), 10, BASE + 600 * 10 + 1);
    assert!(matches!(cs.accept_block(&side), Ok(BlockAcceptance::Stored(_))));
    assert_eq!(reason(&cs, &side, 10), Some(av::NOT_IN_AV_CHAIN));
    // Its height-10 sibling on the assumevalid chain still skips.
    assert_eq!(reason(&cs, &blocks[9], 10), None);
}

/// When the best header is on a branch that doesn't carry the assumevalid
/// block, scripts are verified. Core would still skip blocks below the fork
/// point, which are ancestors of both; satd verifies them too. That is
/// stricter than Core, never looser; see the `assumevalid` module doc.
#[test]
fn a_best_header_off_the_assumevalid_chain_verifies() {
    let blocks = build_chain(genesis(), 1, 30, BASE);
    let (cs, _dir) = chain_state(AssumeValid::Hash(blocks[19].block_hash()));
    for b in &blocks {
        cs.accept_block(b).unwrap();
    }
    // A heavier header chain forking at height 5.
    let fork = build_chain(blocks[4].block_hash(), 6, 40, BASE + 7);
    let headers: Vec<_> = fork.iter().map(|b| b.header).collect();
    let (accepted, err) = cs.accept_headers(&headers);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(accepted, 40);
    assert_eq!(cs.best_header_hash(), fork.last().unwrap().block_hash());

    assert_eq!(reason(&cs, &blocks[2], 3), Some(av::NOT_IN_BEST_HEADER_CHAIN));
}

/// `-assumevalid=all` (satd's) skips by the block's age, read from its own
/// index entry rather than through the height index.
#[test]
fn assumevalid_all_compares_the_blocks_age_with_the_node_clock() {
    const MAX_AGE: u64 = 86_400;
    let (cs, _dir) = chain_state(AssumeValid::All { max_age_secs: MAX_AGE });
    let b = build_test_block(genesis(), 1, 1_300_000_001);
    cs.accept_block(&b).unwrap();
    let t = 1_300_000_001u64;
    let at = |now| cs.script_check_reason_at(1, &b.block_hash(), now);
    assert_eq!(at(t), Some(av::NEWER_THAN_AGE), "a block mined now is not old");
    assert_eq!(at(t + MAX_AGE), Some(av::NEWER_THAN_AGE), "the cutoff is exclusive");
    assert_eq!(at(t + MAX_AGE + 1), None);
    assert_eq!(at(t - 1), Some(av::NEWER_THAN_AGE), "a clock behind the block saturates to age 0");
}

/// `should_skip_scripts`, which the connect paths call, answers from the
/// same decision.
#[test]
fn should_skip_scripts_follows_the_reason() {
    let blocks = build_chain(genesis(), 1, 3, BASE);
    let (cs, _dir) = chain_state(AssumeValid::Hash(blocks[1].block_hash()));
    for b in &blocks {
        cs.accept_block(b).unwrap();
    }
    // Two blocks on top of block 1 are nowhere near two weeks.
    assert!(!cs.should_skip_scripts(1, &blocks[0].block_hash()));
    assert!(!cs.should_skip_scripts(3, &blocks[2].block_hash()));
}

/// A best header below the minimum chain work verifies, whatever else holds:
/// Core's guard against a node denied access to the real chain. Regtest's
/// minimum is zero, so `-minimumchainwork` sets one here. Perturbation: drop
/// the comparison and the block is skipped.
#[test]
fn a_best_header_below_the_minimum_chain_work_verifies() {
    let blocks = build_chain(genesis(), 1, 2030, BASE);
    let (mut cs, _dir) = chain_state(AssumeValid::Hash(blocks[19].block_hash()));
    let mut floor = [0u8; 32];
    floor[0] = 1;
    cs.set_minimum_chain_work(Some(floor));
    for b in &blocks {
        cs.accept_block(b).unwrap();
    }
    assert_eq!(reason(&cs, &blocks[4], 5), Some(av::BELOW_MIN_CHAINWORK));
    cs.set_minimum_chain_work(None);
    assert_eq!(reason(&cs, &blocks[4], 5), None, "the same block skips without the floor");
}
