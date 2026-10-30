//! A block stored before its parent's data arrived is indexed as a header:
//! it can become the best header, and once its parent connects the
//! stored-tail drain connects it (#922).
//!
//! Core's `AcceptBlock` runs `AcceptBlockHeader` (`validation.cpp:4307`)
//! for every block, and `BlockManager::AddToBlockIndex` raises
//! `m_best_header` to any entry with more work
//! (`node/blockstorage.cpp:249`). `ReceivedBlockTransactions` parks the
//! block in `m_blocks_unlinked` until its parent has data, then makes it a
//! candidate, and `ActivateBestChain` connects it.

use super::tests::{build_test_block, build_test_block_spending, make_chain_state};
use super::*;
use bitcoin::hashes::Hash;

const BASE: u32 = 1_707_200_000;

fn genesis() -> BlockHash {
    bitcoin::constants::genesis_block(Network::Regtest).block_hash()
}

/// One step of the connector's stored-tail drain: the next block on the
/// best-header chain, connected if its data is stored.
fn drain_one(cs: &ChainState) -> Option<Result<BlockHash, ChainError>> {
    let hash = cs.next_block_to_connect(cs.tip_height() + 1)?;
    if !cs.has_block_data(&hash) {
        return None;
    }
    Some(cs.connect_stored_block(&hash))
}

/// The steps from #922: the parent's header, then the child's block, then
/// the parent's block.
///
/// Fails without the fix: the best header stays on the parent after the
/// child is stored (`best_header_hash` is the parent), and once the parent
/// connects the drain finds no row at height 2, so the child is never
/// connected.
#[test]
fn a_block_stored_before_its_parent_becomes_the_best_header_and_connects_after_it() {
    let (cs, dir) = make_chain_state();
    let parent = build_test_block(genesis(), 1, BASE + 600);
    let child = build_test_block(parent.block_hash(), 2, BASE + 1200);

    cs.accept_header(&parent.header).unwrap();
    assert_eq!(cs.best_header_hash(), parent.block_hash());

    let r = cs.accept_block(&child);
    assert!(
        matches!(r, Ok(BlockAcceptance::Stored(h)) if h == child.block_hash()),
        "the child waits for its parent's data, got {r:?}"
    );
    assert_eq!(
        cs.best_header_hash(),
        child.block_hash(),
        "the stored child's header has the most work"
    );
    assert_eq!(cs.headers_tip_height(), 2);
    assert_eq!(
        cs.get_block_hash_by_height(2),
        Some(child.block_hash()),
        "the height row above the tip follows the best header"
    );
    assert_eq!(cs.tip_height(), 0);

    let r = cs.accept_block(&parent);
    assert!(
        matches!(r, Ok(BlockAcceptance::Connected(h)) if h == parent.block_hash()),
        "the parent extends the tip, got {r:?}"
    );
    assert_eq!(cs.best_header_hash(), child.block_hash(), "the parent does not lower it");

    let drained = drain_one(&cs);
    assert!(
        matches!(drained, Some(Ok(h)) if h == child.block_hash()),
        "the drain connects the stored child, got {drained:?}"
    );
    assert_eq!(cs.tip_hash(), child.block_hash());
    assert_eq!(cs.tip_height(), 2);
    assert!(drain_one(&cs).is_none(), "nothing left to drain");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-succeed pair for the change: blocks submitted in order connect as
/// before, and the best header follows the tip.
#[test]
fn blocks_submitted_in_order_still_connect_and_lead_the_best_header() {
    let (cs, dir) = make_chain_state();
    let mut prev = genesis();
    for h in 1..=3 {
        let b = build_test_block(prev, h, BASE + 600 * h);
        let r = cs.accept_block(&b);
        assert!(
            matches!(r, Ok(BlockAcceptance::Connected(x)) if x == b.block_hash()),
            "block {h}: {r:?}"
        );
        prev = b.block_hash();
        assert_eq!(cs.best_header_hash(), prev);
    }
    assert_eq!(cs.tip_height(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A stored block with no more work than the best header does not move it,
/// nor the height rows of the best-header chain: first seen wins a tie, as
/// for a header.
///
/// A1 - A2 - A3 - [A4 - A5]          (A1-A3 active, A4-A5 headers only)
///   \
///    [B2 - B3 - B4] - B5             (B5 stored, the same work as A5)
///
/// Perturbation: let `commit_accepted_headers_locked` take a best header of
/// equal work (`>= 0`) and the best header moves to B5.
#[test]
fn a_stored_block_without_more_work_leaves_the_best_header_alone() {
    let (cs, dir) = make_chain_state();
    let mut prev = genesis();
    for h in 1..=3 {
        let b = build_test_block(prev, h, BASE + 600 * h);
        prev = cs.accept_block(&b).unwrap().hash();
    }
    let a3 = prev;
    let a4 = build_test_block(a3, 4, BASE + 2400);
    let a5 = build_test_block(a4.block_hash(), 5, BASE + 3000);
    cs.accept_header(&a4.header).unwrap();
    cs.accept_header(&a5.header).unwrap();
    assert_eq!(cs.best_header_hash(), a5.block_hash());

    let a1 = cs.get_block_hash_by_height(1).unwrap();
    let b2 = build_test_block(a1, 2, BASE + 1260);
    let b3 = build_test_block(b2.block_hash(), 3, BASE + 1860);
    let b4 = build_test_block(b3.block_hash(), 4, BASE + 2460);
    let b5 = build_test_block(b4.block_hash(), 5, BASE + 3060);
    for b in [&b2, &b3, &b4] {
        cs.accept_header(&b.header).unwrap();
    }
    let r = cs.accept_block(&b5);
    assert!(matches!(r, Ok(BlockAcceptance::Stored(_))), "B5: {r:?}");

    assert_eq!(cs.best_header_hash(), a5.block_hash(), "A5 was seen first");
    assert_eq!(cs.get_block_hash_by_height(4), Some(a4.block_hash()));
    assert_eq!(cs.get_block_hash_by_height(5), Some(a5.block_hash()));
    assert_eq!(cs.tip_hash(), a3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A1 - A2 - A3 - A4                (A4 submitted as a block, connects)
///             \
///              [B4]                (header first, the same work as A4)
///
/// The tip moves to A4, which has data, but the best header stays on B4:
/// Core raises `m_best_header` only to an entry with more work
/// (`node/blockstorage.cpp`, `AddToBlockIndex`), so the first seen of two
/// equal-work headers keeps it.
#[test]
fn connecting_a_block_of_equal_work_leaves_the_best_header_alone() {
    let (cs, dir) = make_chain_state();
    let mut prev = genesis();
    for h in 1..=3 {
        let b = build_test_block(prev, h, BASE + 600 * h);
        prev = cs.accept_block(&b).unwrap().hash();
    }
    let b4 = build_test_block(prev, 4, BASE + 2460);
    cs.accept_header(&b4.header).unwrap();
    assert_eq!(cs.best_header_hash(), b4.block_hash());

    let a4 = build_test_block(prev, 4, BASE + 2400);
    cs.accept_block(&a4).unwrap();
    assert_eq!(cs.tip_hash(), a4.block_hash());
    assert_eq!(cs.best_header_hash(), b4.block_hash(), "B4 was seen first");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A stored child that fails to connect is not connected: the drain's
/// connect marks it invalid and the header tip moves back to the parent.
///
/// Must-succeed partner: the first test, where the same sequence with a
/// valid child reaches height 2.
#[test]
fn a_stored_child_that_fails_to_connect_is_marked_and_leaves_the_header_tip() {
    let (cs, dir) = make_chain_state();
    let parent = build_test_block(genesis(), 1, BASE + 600);
    let missing = OutPoint { txid: bitcoin::Txid::from_byte_array([0xa7; 32]), vout: 0 };
    let child = build_test_block_spending(parent.block_hash(), 2, BASE + 1200, missing);

    cs.accept_header(&parent.header).unwrap();
    let r = cs.accept_block(&child);
    assert!(matches!(r, Ok(BlockAcceptance::Stored(_))), "child: {r:?}");
    assert!(cs.accept_block(&parent).unwrap().connected());

    let drained = drain_one(&cs);
    assert!(matches!(drained, Some(Err(_))), "the child must fail to connect, got {drained:?}");
    assert_eq!(cs.tip_hash(), parent.block_hash());
    assert_eq!(
        cs.get_block_index(&child.block_hash()).map(|e| e.status),
        Some(BlockStatus::Invalid)
    );
    assert_eq!(cs.best_header_hash(), parent.block_hash(), "the header tip leaves the failed block");
    assert_eq!(cs.headers_tip_height(), 1);
    assert!(drain_one(&cs).is_none(), "the drain does not retry it");

    let _ = std::fs::remove_dir_all(&dir);
}
