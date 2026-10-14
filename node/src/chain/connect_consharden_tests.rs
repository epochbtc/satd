//! The median time past is Core's `GetMedianTimePast`, over a whole window.
//!
//! Core walks a block and up to ten of its ancestors through `pprev`
//! (`chain.h`); fewer than eleven only when the walk reaches genesis. satd
//! reads the window through the height index (or a replay plan), where a row
//! can be missing. A median over the rows that are left gates BIP 113 and BIP
//! 68 on a value Core never computes, and an empty window gave 0, which meets
//! every time lock. A window with a missing block is now an error that says
//! nothing about the block being connected.

use super::tests::{default_pos, make_block_spending, make_test_store_with_coin, test_store};
use super::*;
use crate::storage::db::InMemoryStore;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash;

const BASE: u32 = 1_700_000_000;

fn hash_for(height: u32) -> BlockHash {
    let mut arr = [0u8; 32];
    arr[..4].copy_from_slice(&height.to_le_bytes());
    arr[4] = 0xC6;
    BlockHash::from_byte_array(arr)
}

fn entry_at(height: u32, time: u32) -> BlockIndexEntry {
    let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
    header.time = time;
    BlockIndexEntry {
        header,
        height,
        status: BlockStatus::Valid,
        num_tx: 1,
        file_number: 0,
        data_pos: 0,
        chainwork: [0u8; 32],
    }
}

/// Index a block at each height in `heights`, stamped `time_of(height)`, with
/// its height row.
fn index_blocks(store: &InMemoryStore, heights: impl IntoIterator<Item = u32>, time_of: impl Fn(u32) -> u32) {
    let mut batch = StoreBatch::default();
    for h in heights {
        batch.block_index_puts.push((hash_for(h), entry_at(h, time_of(h))));
        batch.height_hash_puts.push((h, hash_for(h)));
    }
    store.write_batch(batch).unwrap();
}

/// Core's `GetMedianTimePast` for the block at `height - 1`, from the times
/// directly: up to eleven of them ending at that block, sorted, element n/2.
fn core_median(time_of: impl Fn(u32) -> u32, height: u32) -> u32 {
    let mut times: Vec<u32> = (height.saturating_sub(11)..height).map(time_of).collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// Out-of-order times, so the median is not simply the middle height's.
fn scrambled(h: u32) -> u32 {
    BASE + (h * 7919) % 1000
}

#[test]
fn the_median_is_cores_over_a_full_window_and_near_genesis() {
    let store = test_store();
    index_blocks(&store, 0..30, scrambled);
    for height in 1..30 {
        assert_eq!(
            get_median_time_past(&store, height).unwrap(),
            core_median(scrambled, height),
            "height {height}"
        );
    }
    // Nothing precedes genesis.
    assert_eq!(get_median_time_past(&store, 0).unwrap(), 0);
}

#[test]
fn a_missing_height_row_is_an_error_not_a_shorter_median() {
    let store = test_store();
    index_blocks(&store, (0..30).filter(|&h| h != 14), scrambled);
    let err = get_median_time_past(&store, 20).unwrap_err();
    assert!(
        matches!(err, ConnectError::MedianTimeWindowGap { height: 20, missing: 14 }),
        "got {err:?}"
    );
    assert!(!err.is_verdict_on_block(), "damage to the index is not a verdict on the block");
    // Windows that do not reach the hole are unaffected.
    assert_eq!(get_median_time_past(&store, 14).unwrap(), core_median(scrambled, 14));
    assert_eq!(get_median_time_past(&store, 26).unwrap(), core_median(scrambled, 26));
}

#[test]
fn a_height_row_without_its_index_entry_is_an_error() {
    let store = test_store();
    index_blocks(&store, 0..30, scrambled);
    let mut batch = StoreBatch::default();
    batch.height_hash_puts.push((17, BlockHash::from_byte_array([0xEE; 32])));
    store.write_batch(batch).unwrap();
    assert!(matches!(
        get_median_time_past(&store, 20),
        Err(ConnectError::MedianTimeWindowGap { height: 20, missing: 17 })
    ));
}

#[test]
fn a_replay_plan_that_does_not_reach_the_window_is_an_error() {
    let store = test_store();
    index_blocks(&store, 0..30, scrambled);
    let plan = crate::chain::replay_plan::ReplayPlan::from_hashes((0..15).map(hash_for).collect());
    assert_eq!(
        median_time_past_with_plan(&store, Some(&plan), 15).unwrap(),
        core_median(scrambled, 15)
    );
    assert!(matches!(
        median_time_past_with_plan(&store, Some(&plan), 20),
        Err(ConnectError::MedianTimeWindowGap { height: 20, missing: 15 })
    ));
}

/// Connect a block at `BLOCK_HEIGHT` spending a coin from `COIN_HEIGHT` with a
/// one-unit (512 s) BIP 68 time lock, against `store`.
fn connect_time_locked_spend(store: &InMemoryStore, outpoint: OutPoint, block_mtp: u32) -> Result<StoreBatch, ConnectError> {
    const BLOCK_HEIGHT: u32 = 40;
    let block = make_block_spending(outpoint, BLOCK_HEIGHT, 2, (1 << 22) | 1, 0);
    let address_index = Default::default();
    let sp_index = Default::default();
    #[cfg(feature = "block-filter-index")]
    let filter_index = Default::default();
    connect_block(&ConnectParams {
        replay_plan: None,
        store,
        block: &block,
        height: BLOCK_HEIGHT,
        parent_chainwork: &[0u8; 32],
        flat_pos: default_pos(),
        script_verifier: &NoopVerifier,
        median_time_past: block_mtp,
        network: Network::Regtest,
        pre_verified_txs: None,
        num_threads: 1,
        precomputed_txids: None,
        address_index: &address_index,
        sp_index: &sp_index,
        #[cfg(feature = "block-filter-index")]
        filter_index: &filter_index,
        phase_tracker: None,
        interrupt: None,
    })
}

const COIN_HEIGHT: u32 = 30;

/// Block times 100 s apart, so the coin's MTP (the window for height 30,
/// blocks 19..=29) is the time of block 24: `BASE + 2400`.
fn spaced(h: u32) -> u32 {
    BASE + 100 * h
}

#[test]
fn bip68_takes_the_coins_median_over_its_whole_window() {
    let (store, outpoint, _) = make_test_store_with_coin(COIN_HEIGHT, false);
    index_blocks(&store, 0..40, spaced);
    let coin_mtp = core_median(spaced, COIN_HEIGHT);
    assert_eq!(coin_mtp, BASE + 2400);

    // Exactly 512 s past the coin's MTP: the lock is met.
    assert!(connect_time_locked_spend(&store, outpoint, coin_mtp + 512).is_ok());
    // One second short: not met, a verdict on the block.
    let err = connect_time_locked_spend(&store, outpoint, coin_mtp + 511).err().expect("lock not met");
    assert!(matches!(err, ConnectError::SequenceLockNotMet), "got {err:?}");
    assert!(err.is_verdict_on_block());
}

/// With block 21's row gone, the median over the other ten is block 25's
/// time, 100 s later than Core's. A block that meets the lock by Core's
/// median would be refused with a verdict and marked invalid.
#[test]
fn bip68_with_a_hole_in_the_coins_window_is_not_a_verdict() {
    let (store, outpoint, _) = make_test_store_with_coin(COIN_HEIGHT, false);
    index_blocks(&store, (0..40).filter(|&h| h != 21), spaced);
    let err = connect_time_locked_spend(&store, outpoint, core_median(spaced, COIN_HEIGHT) + 512)
        .err()
        .expect("the window has a hole");
    assert!(
        matches!(err, ConnectError::MedianTimeWindowGap { height: COIN_HEIGHT, missing: 21 }),
        "got {err:?}"
    );
    assert!(!err.is_verdict_on_block());
}

/// With no rows at all in the coin's window, the median was 0 and every time
/// lock passed.
#[test]
fn an_empty_coin_window_no_longer_meets_every_time_lock() {
    let (store, outpoint, _) = make_test_store_with_coin(COIN_HEIGHT, false);
    index_blocks(&store, 0..19, spaced);
    let err = connect_time_locked_spend(&store, outpoint, BASE).err().expect("the window is empty");
    assert!(
        matches!(err, ConnectError::MedianTimeWindowGap { height: COIN_HEIGHT, missing: 19 }),
        "got {err:?}"
    );
    assert!(!err.is_verdict_on_block());
}
