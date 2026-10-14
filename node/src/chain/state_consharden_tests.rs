//! The connect paths take a block's median time past whole, or not at all.
//!
//! `median_time_past_for_connect` is Core's `pindexPrev->GetMedianTimePast()`
//! (`chain.h`): the parent and up to ten of its ancestors. It answers from the
//! MTP cache when that holds the whole window and from the index otherwise,
//! and a window with a missing block is an error that is not a verdict on the
//! block, so it never marks one invalid.

use super::tests::{build_test_block, make_chain_state};
use super::*;
use crate::storage::StoreBatch;

const BASE: u32 = 1_707_000_000;

/// Connect `n` blocks on regtest genesis, 600 s apart.
fn connect_chain(cs: &ChainState, n: u32) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    (1..=n)
        .map(|h| {
            let b = build_test_block(parent, h, BASE + 600 * h);
            parent = cs.accept_block(&b).expect("connect fixture block").hash();
            b
        })
        .collect()
}

/// Core's `GetMedianTimePast` for the active block at `height - 1`, walking
/// parent links: its time and up to ten ancestors', sorted, element n/2.
fn core_median_time_past(cs: &ChainState, height: u32) -> u32 {
    let mut hash = cs.active_chain_hash_at_height(height - 1).expect("active block");
    let mut times = Vec::new();
    for _ in 0..11 {
        let entry = cs.get_block_index(&hash).expect("index entry");
        times.push(entry.header.time);
        if entry.height == 0 {
            break;
        }
        hash = entry.header.prev_blockhash;
    }
    times.sort_unstable();
    times[times.len() / 2]
}

#[test]
fn the_connect_median_is_cores_from_the_cache_and_from_the_index() {
    let (cs, _dir) = make_chain_state();
    connect_chain(&cs, 15);
    for height in 1..=16 {
        assert_eq!(
            cs.median_time_past_for_connect(height).unwrap(),
            core_median_time_past(&cs, height),
            "height {height}, cache"
        );
    }
    cs.mtp_cache.lock().clear();
    for height in 1..=16 {
        assert_eq!(
            cs.median_time_past_for_connect(height).unwrap(),
            core_median_time_past(&cs, height),
            "height {height}, index"
        );
    }
}

/// Block 7's height row is lost. The next block's window (blocks 2..=12)
/// cannot be read whole, so it is not connected, and it is not marked: once
/// the row is back, the same block connects.
#[test]
fn a_hole_in_the_mtp_window_stops_the_connect_without_marking_the_block() {
    let (cs, _dir) = make_chain_state();
    let blocks = connect_chain(&cs, 12);
    let next = build_test_block(blocks[11].block_hash(), 13, BASE + 600 * 13);

    cs.store
        .write_batch(StoreBatch { height_hash_removes: vec![7], ..Default::default() })
        .unwrap();
    cs.mtp_cache.lock().clear();

    let err = cs.accept_block(&next).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::Connect(connect::ConnectError::MedianTimeWindowGap { height: 13, missing: 7 })
        ),
        "got {err:?}"
    );
    assert_ne!(
        cs.get_block_index(&next.block_hash()).map(|e| e.status),
        Some(BlockStatus::Invalid),
        "a window this node cannot read is not a verdict on the block"
    );
    assert_eq!(cs.tip_height(), 12);

    cs.store
        .write_batch(StoreBatch { height_hash_puts: vec![(7, blocks[6].block_hash())], ..Default::default() })
        .unwrap();
    cs.accept_block(&next).expect("the block connects once the window is whole");
    assert_eq!(cs.tip_hash(), next.block_hash());
}
