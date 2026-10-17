//! Core's contextual header and block rules apply before a block is indexed
//! or written, on every path, not only when a block is connected.
//!
//! Core checks a header's `time-too-old`, `time-too-new` and `bad-version` in
//! `ContextualCheckBlockHeader`, called from `AcceptBlockHeader`, so no header
//! that breaks them enters the block index. It checks every transaction
//! (`CheckTransaction`), finality (`bad-txns-nonfinal`) and the BIP 34
//! coinbase height (`bad-cb-height`) in `CheckBlock` / `ContextualCheckBlock`,
//! both called from `AcceptBlock` before `WriteBlock`, so no block that breaks
//! them is stored. satd applied the header rules only in `accept_block`, and
//! the transaction rules only at connect time.

use super::tests::{build_test_block, grind_test_pow, make_chain_state};
use super::*;
use bitcoin::blockdata::locktime::absolute::LockTime;

const BASE: u32 = 1_708_000_000;

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

/// The median time past of the active block at `height`: its time and its
/// ten ancestors', sorted, element n/2.
fn mtp_at(cs: &ChainState, height: u32) -> u32 {
    let mut times: Vec<u32> = (height.saturating_sub(10)..=height)
        .map(|h| {
            let hash = cs.active_chain_hash_at_height(h).expect("active block");
            cs.get_block_index(&hash).expect("index entry").header.time
        })
        .collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// `build_test_block` with its header rewritten by `edit`, then re-solved.
fn block_with_header(parent: BlockHash, height: u32, time: u32, edit: impl FnOnce(&mut bitcoin::block::Header)) -> Block {
    let mut b = build_test_block(parent, height, time);
    edit(&mut b.header);
    grind_test_pow(&mut b);
    b
}

/// `build_test_block` whose coinbase is not final at `height`: a height
/// locktime equal to the block's own height, with a non-final sequence.
fn nonfinal_block(parent: BlockHash, height: u32, time: u32) -> Block {
    let mut b = build_test_block(parent, height, time);
    let cb = &mut b.txdata[0];
    cb.lock_time = LockTime::from_consensus(height);
    cb.input[0].sequence = bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF;
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    grind_test_pow(&mut b);
    b
}

/// `build_test_block` whose coinbase commits to the wrong height.
fn bad_cb_height_block(parent: BlockHash, height: u32, time: u32) -> Block {
    let mut b = build_test_block(parent, height, time);
    b.txdata[0].input[0].script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64 + 1)
        .push_int(time as i64)
        .into_script();
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    grind_test_pow(&mut b);
    b
}

/// `ValidationError` has no `PartialEq`; its reason strings are Core's, so
/// compare those.
fn is_validation(e: &ChainError, want: validation::ValidationError) -> bool {
    matches!(e, ChainError::Validation(v) if v.to_string() == want.to_string())
}

// ---- Headers ---------------------------------------------------------------

/// A header at the parent's median time past is `time-too-old`, and is not
/// indexed. Perturbation: drop `check_header_context` from `accept_header`
/// and this fails at the `expect_err`.
#[test]
fn accept_header_refuses_a_header_at_the_parents_mtp() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 11);
    let tip = blocks.last().unwrap().block_hash();
    let mtp = mtp_at(&cs, 11);

    let stale = block_with_header(tip, 12, mtp, |_| {});
    let err = cs.accept_header(&stale.header).expect_err("time-too-old");
    assert!(is_validation(&err, validation::ValidationError::TimeTooOld), "got {err:?}");
    assert!(cs.get_block_index(&stale.block_hash()).is_none(), "refused header was indexed");

    // One second later is fine: the refusal is the rule, not the fixture.
    let ok = block_with_header(tip, 12, mtp + 1, |_| {});
    cs.accept_header(&ok.header).expect("a header above the MTP is accepted");

    let _ = std::fs::remove_dir_all(&dir);
}

/// In a batch, the MTP is the header's own branch's, made of the batch's
/// earlier headers as well as stored ones. The window for height 3 is
/// {genesis, h1, h2}, whose median is h1's time.
#[test]
fn accept_headers_judges_time_against_the_batchs_own_ancestors() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let h1 = build_test_block(genesis, 1, BASE + 600);
    let h2 = build_test_block(h1.block_hash(), 2, BASE + 1200);
    let h3 = build_test_block(h2.block_hash(), 3, BASE + 600);

    let (accepted, err) = cs.accept_headers(&[h1.header, h2.header, h3.header]);
    assert_eq!(accepted, 2, "the first two headers are fine");
    let err = err.expect("the third is time-too-old");
    assert!(is_validation(&err, validation::ValidationError::TimeTooOld), "got {err:?}");
    assert!(cs.get_block_index(&h3.block_hash()).is_none());
    // The two accepted before it are committed, not dropped with the batch.
    // Perturbation: return on the refusal without committing, and this fails.
    for h in [&h1, &h2] {
        assert_eq!(
            cs.get_block_index(&h.block_hash()).map(|e| e.status),
            Some(BlockStatus::HeaderOnly),
            "a header accepted before the refused one must be indexed"
        );
    }
    assert_eq!(cs.best_header_hash(), h2.block_hash());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A batch whose last header is ahead of the clock keeps the rest: an honest
/// peer whose clock runs fast must not stop header sync at its last batch.
#[test]
fn accept_headers_keeps_the_prefix_of_a_batch_ending_ahead_of_the_clock() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let h1 = build_test_block(genesis, 1, BASE + 600);
    let ahead = crate::time::now_secs() as u32 + 2 * 60 * 60 + 60;
    let h2 = build_test_block(h1.block_hash(), 2, ahead);
    let (accepted, err) = cs.accept_headers(&[h1.header, h2.header]);
    assert_eq!(accepted, 1);
    assert!(err.is_some_and(|e| is_validation(&e, validation::ValidationError::TimeTooNew)));
    assert!(cs.get_block_index(&h1.block_hash()).is_some(), "h1 must be committed");
    assert!(cs.get_block_index(&h2.block_hash()).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other direction: a header earlier than its parent but above the
/// window's median is valid. A walk that stopped where the store ends would
/// see only the parent, take its time as the median and refuse the header.
/// Perturbation: resolve the MTP walk through the store only, and this fails.
#[test]
fn accept_headers_accepts_a_header_below_its_parent_but_above_the_median() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let h1 = build_test_block(genesis, 1, BASE + 600);
    let h2 = build_test_block(h1.block_hash(), 2, BASE + 1200);
    let h3 = build_test_block(h2.block_hash(), 3, BASE + 900);

    let (accepted, err) = cs.accept_headers(&[h1.header, h2.header, h3.header]);
    assert!(err.is_none(), "got {err:?}");
    assert_eq!(accepted, 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A header more than two hours ahead of the clock is `time-too-new`.
#[test]
fn accept_header_refuses_a_header_two_hours_ahead() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 1);
    let ahead = crate::time::now_secs() as u32 + 2 * 60 * 60 + 60;
    let b = block_with_header(blocks[0].block_hash(), 2, ahead, |_| {});
    let err = cs.accept_header(&b.header).expect_err("time-too-new");
    assert!(is_validation(&err, validation::ValidationError::TimeTooNew), "got {err:?}");

    let (accepted, err) = cs.accept_headers(&[b.header]);
    assert_eq!(accepted, 0);
    assert!(err.is_some_and(|e| is_validation(&e, validation::ValidationError::TimeTooNew)));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A version-1 header where BIP 34 is active (height 1 on regtest) is
/// `bad-version(0x00000001)`, on both header paths.
#[test]
fn header_paths_refuse_a_version_below_the_buried_minimum() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let v1 = block_with_header(genesis, 1, BASE + 600, |h| {
        h.version = bitcoin::block::Version::from_consensus(1);
    });
    let err = cs.accept_header(&v1.header).expect_err("bad-version");
    assert!(is_validation(&err, validation::ValidationError::BadVersion(1)), "got {err:?}");
    assert_eq!(err.to_string(), "bad-version(0x00000001)");

    let (accepted, err) = cs.accept_headers(&[v1.header]);
    assert_eq!(accepted, 0);
    assert!(err.is_some_and(|e| is_validation(&e, validation::ValidationError::BadVersion(1))));
    assert!(cs.get_block_index(&v1.block_hash()).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Block store (IBD) ----------------------------------------------------

/// `store_block` applies the header rules to a block whose header it has not
/// seen, so the block is neither written nor indexed.
#[test]
fn store_block_refuses_a_time_too_old_block_with_no_header() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 11);
    let b = block_with_header(blocks[10].block_hash(), 12, mtp_at(&cs, 11), |_| {});
    let err = cs.store_block(&b).expect_err("time-too-old");
    assert!(is_validation(&err, validation::ValidationError::TimeTooOld), "got {err:?}");
    assert!(cs.get_block_index(&b.block_hash()).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A non-final block is refused before it is written, and the header row an
/// announcement left is marked invalid (Core's `BLOCK_FAILED_VALID` for a
/// `ContextualCheckBlock` failure in `AcceptBlock`), so the scheduler stops
/// asking for it. Perturbation: drop the mark and the status stays
/// `HeaderOnly`; drop `check_block_context_before_write` and `store_block`
/// succeeds.
#[test]
fn store_block_refuses_a_nonfinal_block_and_marks_its_header() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 3);
    let b = nonfinal_block(blocks[2].block_hash(), 4, BASE + 600 * 4);

    cs.accept_header(&b.header).expect("the header itself is fine");
    let err = cs.store_block(&b).expect_err("bad-txns-nonfinal");
    assert!(
        matches!(err, ChainError::Connect(connect::ConnectError::LocktimeNotFinal)),
        "got {err:?}"
    );
    assert_eq!(err.to_string(), "bad-txns-nonfinal");
    assert_eq!(
        cs.get_block_index(&b.block_hash()).map(|e| e.status),
        Some(BlockStatus::Invalid),
        "the announced header must be marked invalid"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A block whose coinbase commits to the wrong height is refused before the
/// write. With no header row there is nothing to mark, and nothing is indexed.
#[test]
fn store_block_refuses_a_bad_coinbase_height_with_no_header() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 3);
    let b = bad_cb_height_block(blocks[2].block_hash(), 4, BASE + 600 * 4);
    let err = cs.store_block(&b).expect_err("bad-cb-height");
    assert_eq!(err.to_string(), "bad-cb-height");
    assert!(cs.get_block_index(&b.block_hash()).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- accept_block ----------------------------------------------------------

/// A side-chain block that breaks a transaction rule used to be written and
/// stored (`submitblock` answered `inconclusive`); it is refused with Core's
/// reason now, before anything is written.
#[test]
fn accept_block_refuses_a_nonfinal_side_block_before_storing_it() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 4);
    // A competitor at height 3, below the tip of 4: a side block.
    let side = nonfinal_block(blocks[1].block_hash(), 3, BASE + 600 * 3 + 7);
    let err = cs.accept_block(&side).expect_err("bad-txns-nonfinal");
    assert_eq!(err.to_string(), "bad-txns-nonfinal");
    assert!(cs.get_block_index(&side.block_hash()).is_none(), "refused side block was indexed");
    assert_eq!(cs.tip_height(), 4);

    // The same block without the locktime is stored as a side block: the
    // refusal is the rule, not the fixture.
    let ok = build_test_block(blocks[1].block_hash(), 3, BASE + 600 * 3 + 7);
    assert!(matches!(cs.accept_block(&ok), Ok(BlockAcceptance::Stored(_))));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The coinbase-height rule on a block that extends the tip, with its header
/// announced first: refused before the write, the header row marked.
#[test]
fn accept_block_marks_an_announced_header_whose_block_has_a_bad_coinbase_height() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 2);
    let b = bad_cb_height_block(blocks[1].block_hash(), 3, BASE + 600 * 3);
    cs.accept_header(&b.header).expect("header is fine");
    let err = cs.accept_block(&b).expect_err("bad-cb-height");
    assert_eq!(err.to_string(), "bad-cb-height");
    assert_eq!(cs.get_block_index(&b.block_hash()).map(|e| e.status), Some(BlockStatus::Invalid));
    assert_eq!(cs.tip_height(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Connect -----------------------------------------------------------------

/// A block already in the index (put there by a reindex scan, or by a satd
/// from before header acceptance applied the rules) is still judged at
/// connect: `connect_block` repeats `time-too-old` and `bad-version`, and the
/// failure is a verdict that marks the block. Perturbation: drop
/// `check_header_time_and_version` from `connect_block` and the block
/// connects.
#[test]
fn connect_refuses_a_stored_block_that_is_time_too_old() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 11);
    let b = block_with_header(blocks[10].block_hash(), 12, mtp_at(&cs, 11), |_| {});
    super::tests::store_block_without_connecting(&cs, &b, 12);

    let err = cs.connect_stored_block(&b.block_hash()).expect_err("time-too-old at connect");
    assert_eq!(err.to_string(), "time-too-old");
    assert_eq!(cs.tip_height(), 11);
    assert_eq!(cs.get_block_index(&b.block_hash()).map(|e| e.status), Some(BlockStatus::Invalid));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same for `bad-version`.
#[test]
fn connect_refuses_a_stored_block_with_a_stale_version() {
    let (cs, dir) = make_chain_state();
    let blocks = connect_chain(&cs, 2);
    let b = block_with_header(blocks[1].block_hash(), 3, BASE + 600 * 3, |h| {
        h.version = bitcoin::block::Version::from_consensus(3);
    });
    super::tests::store_block_without_connecting(&cs, &b, 3);

    let err = cs.connect_stored_block(&b.block_hash()).expect_err("bad-version at connect");
    assert_eq!(err.to_string(), "bad-version(0x00000003)");
    assert_eq!(cs.tip_height(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}
