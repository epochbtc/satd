//! What a block that fails to connect leaves behind, on every connect path.
//!
//! Core's `InvalidBlockFound` marks the block `BLOCK_FAILED_VALID` whichever
//! way it reached `ConnectTip`, and its `InvalidChainFound`
//! (`validation.cpp`) recalculates the header tip when that tip descends from
//! the failed block. `ActivateBestChain` then goes on to the next candidate.

use super::tests::{build_test_block, build_test_block_spending, make_chain_state};
use super::*;
use crate::storage::StoreBatch;
use bitcoin::hashes::Hash;

const BASE: u32 = 1_707_100_000;

/// Connect `n` blocks on regtest genesis through `accept_block`.
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

fn status(cs: &ChainState, hash: &BlockHash) -> Option<BlockStatus> {
    cs.get_block_index(hash).map(|e| e.status)
}

/// A block on `parent` that spends a coin that does not exist: well formed,
/// with valid proof of work, and invalid at connect (`bad-txns-inputs-missingorspent`).
fn spends_missing_coin(parent: BlockHash, height: u32, time: u32) -> Block {
    let missing = OutPoint { txid: bitcoin::Txid::from_byte_array([0xc5; 32]), vout: 0 };
    build_test_block_spending(parent, height, time, missing)
}

/// Announce the header and store the body, as the IBD download path does.
fn announce_and_store(cs: &ChainState, b: &Block) {
    cs.accept_header(&b.header).expect("fixture header");
    cs.store_block(b).expect("fixture body stored");
}

/// A branch fails at its last block during an activation attempt. The blocks
/// below it still out-work the tip, so the next attempt takes them, without
/// waiting for another block or header to arrive.
///
/// A1 - A2 - A3            (active, height 3)
///  \
///   B2 - B3 - B4 - B5     (stored; B5 spends a coin that does not exist)
///
/// Fails without the fix: the second attempt returned `None`. Its key (tip,
/// header tip, blocks indexed) was unchanged by the failed reorg, so the
/// attempt was skipped and the node stayed on A3 until something arrived.
#[test]
fn a_failed_activation_retries_the_valid_prefix_at_once() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let a3 = a[2].block_hash();

    let b2 = build_test_block(a[0].block_hash(), 2, BASE + 7_000);
    let b3 = build_test_block(b2.block_hash(), 3, BASE + 7_600);
    let b4 = build_test_block(b3.block_hash(), 4, BASE + 8_200);
    let b5 = spends_missing_coin(b4.block_hash(), 5, BASE + 8_800);
    for b in [&b2, &b3, &b4, &b5] {
        announce_and_store(&cs, b);
    }
    assert_eq!(cs.best_header_hash(), b5.block_hash());
    assert_eq!(cs.tip_hash(), a3, "store_block never activates");

    let first = cs.activate_best_stored_chain();
    assert!(first.is_err(), "B5 cannot connect: {first:?}");
    assert_eq!(cs.tip_hash(), a3, "the failed reorg rolled back");
    assert_eq!(status(&cs, &b5.block_hash()), Some(BlockStatus::Invalid));

    let second = cs.activate_best_stored_chain().expect("second attempt");
    assert_eq!(second, Some(b4.block_hash()), "the valid prefix is taken");
    assert_eq!(cs.tip_hash(), b4.block_hash());
    assert_eq!(cs.reorg_abort_count(), 1, "one failed reorg, then one that succeeded");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A mark clears the attempt key, whether or not the header tip is in the
/// marked subtree, and leaves the header tip alone when it is not.
///
/// Fails without the fix: the key survived the mark.
#[test]
fn marking_a_branch_clears_the_activation_attempt_key() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let side = build_test_block(a[0].block_hash(), 2, BASE + 9_000);
    announce_and_store(&cs, &side);
    assert_eq!(cs.best_header_hash(), a[2].block_hash(), "fixture: the side block is lighter");

    let headers_before = cs.headers_tip_height();
    let key = (cs.tip_hash(), cs.best_header_hash(), 7);
    *cs.last_activation_attempt.lock() = Some(key);
    {
        let _accept_guard = cs.accept_lock.lock();
        cs.mark_subtree_invalid(side.block_hash()).unwrap();
    }
    assert_eq!(status(&cs, &side.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(*cs.last_activation_attempt.lock(), None);
    assert_eq!(cs.best_header_hash(), a[2].block_hash(), "header tip not in the subtree");
    assert_eq!(cs.headers_tip_height(), headers_before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `accept_block`: a block whose header was the header tip fails to connect.
/// The header tip moves back to the active tip.
///
/// Fails without the fix: the header tip stayed on the invalid block, and
/// `headers` read 4 against a chain that cannot reach it.
#[test]
fn a_block_that_fails_to_connect_moves_the_header_tip_off_it() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let tip = a[2].block_hash();
    let bad = spends_missing_coin(tip, 4, BASE + 600 * 4);
    cs.accept_header(&bad.header).unwrap();
    assert_eq!(cs.best_header_hash(), bad.block_hash());
    assert_eq!(cs.headers_tip_height(), 4);

    let err = cs.accept_block(&bad).expect_err("a block spending a missing coin");
    assert_eq!(err.to_string(), "bad-txns-inputs-missingorspent");
    assert_eq!(status(&cs, &bad.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(cs.best_header_hash(), tip);
    assert_eq!(cs.headers_tip_height(), 3);

    // A valid sibling still connects and becomes the header tip.
    let good = build_test_block(tip, 4, BASE + 600 * 4 + 1);
    cs.accept_block(&good).expect("a valid sibling connects");
    assert_eq!(cs.tip_hash(), good.block_hash());
    assert_eq!(cs.best_header_hash(), good.block_hash());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The connector's `connect_stored_block`: a stored block that fails a
/// consensus rule is marked, with its descendants, and the header tip moves
/// off it. Offering it again is answered from the index.
///
/// Fails without the fix: the block stayed `DataStored`, and every retry
/// validated it again.
#[test]
fn the_connector_marks_a_stored_block_that_fails_to_connect() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let tip = a[2].block_hash();
    let bad = spends_missing_coin(tip, 4, BASE + 600 * 4);
    let child = build_test_block(bad.block_hash(), 5, BASE + 600 * 5);
    announce_and_store(&cs, &bad);
    announce_and_store(&cs, &child);
    assert_eq!(cs.best_header_hash(), child.block_hash());

    let err = cs.connect_stored_block(&bad.block_hash()).expect_err("cannot connect");
    assert_eq!(err.to_string(), "bad-txns-inputs-missingorspent");
    assert_eq!(status(&cs, &bad.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(status(&cs, &child.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(cs.best_header_hash(), tip);
    assert_eq!(cs.headers_tip_height(), 3);
    assert_eq!(cs.tip_hash(), tip);

    let again = cs.connect_stored_block(&bad.block_hash()).expect_err("judged");
    assert!(matches!(again, ChainError::Duplicate), "got {again:?}");

    let good = build_test_block(tip, 4, BASE + 600 * 4 + 1);
    announce_and_store(&cs, &good);
    cs.connect_stored_block(&good.block_hash()).expect("a valid sibling connects");
    assert_eq!(cs.tip_hash(), good.block_hash());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The connector's prefetch path, `connect_preprocessed_block`, marks the
/// same way.
///
/// Fails without the fix: the block stayed `DataStored`.
#[test]
fn the_prefetch_connect_marks_a_stored_block_that_fails_to_connect() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let tip = a[2].block_hash();
    let bad = spends_missing_coin(tip, 4, BASE + 600 * 4);
    announce_and_store(&cs, &bad);

    let entry = cs.get_block_index(&bad.block_hash()).unwrap();
    let parent = cs.get_block_index(&tip).unwrap();
    let pre = crate::chain::prefetch::PreprocessedBlock {
        height: 4,
        hash: bad.block_hash(),
        block: bad.clone(),
        flat_pos: FlatFilePos { file_number: entry.file_number, data_pos: entry.data_pos },
        mtp: 0,
        txids: bad.txdata.iter().map(|t| t.compute_txid()).collect(),
        script_verified_txs: Default::default(),
        context_free_checked: true,
        entry,
        parent,
    };
    let err = cs.connect_preprocessed_block(pre).expect_err("cannot connect");
    assert_eq!(err.to_string(), "bad-txns-inputs-missingorspent");
    assert_eq!(status(&cs, &bad.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(cs.best_header_hash(), tip);
    assert_eq!(cs.tip_hash(), tip);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A connector failure that reports this node's storage is not a verdict:
/// with a hole in the median-time-past window the stored block stays
/// `DataStored`, the header tip stays on it, and it connects once the hole is
/// repaired. (The window is read before `connect_block` runs, so this pins
/// the connect paths' order; the filter is pinned by
/// `only_a_verdict_from_connect_marks_a_stored_block`.)
#[test]
fn a_storage_gap_in_the_connector_does_not_mark_the_block() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 12);
    let next = build_test_block(a[11].block_hash(), 13, BASE + 600 * 13);
    announce_and_store(&cs, &next);

    cs.store
        .write_batch(StoreBatch { height_hash_removes: vec![7], ..Default::default() })
        .unwrap();
    cs.mtp_cache.lock().clear();

    let err = cs.connect_stored_block(&next.block_hash()).expect_err("window has a hole");
    assert!(
        matches!(
            err,
            ChainError::Connect(connect::ConnectError::MedianTimeWindowGap { height: 13, missing: 7 })
        ),
        "got {err:?}"
    );
    assert_eq!(status(&cs, &next.block_hash()), Some(BlockStatus::DataStored));
    assert_eq!(cs.best_header_hash(), next.block_hash());

    cs.store
        .write_batch(StoreBatch { height_hash_puts: vec![(7, a[6].block_hash())], ..Default::default() })
        .unwrap();
    cs.connect_stored_block(&next.block_hash()).expect("connects once the window is whole");
    assert_eq!(cs.tip_hash(), next.block_hash());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The filter itself: of the two errors `connect_block` can return for a
/// stored block, only the verdict is written down. A missing `chain_tx` row
/// for the parent reports this node's storage and leaves the block
/// `DataStored`; a missing input marks it.
///
/// Fails if the filter is dropped: the storage error marked the block.
#[test]
fn only_a_verdict_from_connect_marks_a_stored_block() {
    let (cs, dir) = make_chain_state();
    let a = connect_chain(&cs, 3);
    let tip = a[2].block_hash();
    let next = build_test_block(tip, 4, BASE + 600 * 4);
    announce_and_store(&cs, &next);
    let guard = cs.accept_lock.lock();

    cs.mark_stored_block_failure(&next.block_hash(), &connect::ConnectError::ChainTxGap { parent: tip });
    assert_eq!(status(&cs, &next.block_hash()), Some(BlockStatus::DataStored));
    assert_eq!(cs.best_header_hash(), next.block_hash());

    cs.mark_stored_block_failure(
        &next.block_hash(),
        &connect::ConnectError::MissingOrSpentInput {
            outpoint: OutPoint { txid: bitcoin::Txid::from_byte_array([0xc6; 32]), vout: 0 },
        },
    );
    assert_eq!(status(&cs, &next.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(cs.best_header_hash(), tip);

    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}
