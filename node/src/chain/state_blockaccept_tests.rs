//! Which `accept_block` failures are written down against the block hash.
//!
//! Bitcoin Core marks a block `BLOCK_FAILED_VALID` only for a verdict the
//! block hash commits to, and only on an index entry that exists:
//!
//! - `ProcessNewBlock` runs `CheckBlock` first and, on failure, returns
//!   without reaching `AcceptBlock`, so nothing is marked.
//! - `AcceptBlock` makes the index entry (`AcceptBlockHeader`) before
//!   `ContextualCheckBlock` and `ConnectTip` can fail, and `InvalidBlockFound`
//!   marks that entry unless the result is `BLOCK_MUTATED`.

use super::tests::{build_test_block, build_test_block_spending, grind_test_pow, make_chain_state};
use super::*;
use bitcoin::{ScriptBuf, Transaction, TxIn, TxOut};

/// Connect `n` blocks on regtest genesis through `accept_block`.
fn connect_chain(cs: &ChainState, n: u32) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks = Vec::new();
    for h in 1..=n {
        let b = build_test_block(parent, h, 1_707_000_000 + h);
        parent = cs.accept_block(&b).expect("connect fixture block").hash();
        blocks.push(b);
    }
    blocks
}

fn status(cs: &ChainState, hash: &BlockHash) -> Option<BlockStatus> {
    cs.get_block_index(hash).map(|e| e.status)
}

/// A regtest block on `parent` whose header commits to exactly `txdata`, with
/// its proof of work solved and its header accepted: the `HeaderOnly` row a
/// header announcement leaves.
fn announced_block(cs: &ChainState, parent: BlockHash, time: u32, txdata: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: parent,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(bitcoin::TxMerkleNode::all_zeros);
    grind_test_pow(&mut block);
    cs.accept_header(&block.header).expect("fixture header");
    assert_eq!(status(cs, &block.block_hash()), Some(BlockStatus::HeaderOnly));
    block
}

fn coinbase(script_sig: Vec<u8>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(script_sig),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: outputs,
    }
}

fn pay(sats: u64, script: Vec<u8>) -> TxOut {
    TxOut { value: bitcoin::Amount::from_sat(sats), script_pubkey: ScriptBuf::from(script) }
}

/// A non-coinbase transaction whose serialization without witness is exactly
/// 64 bytes: the shape that can be read as an inner merkle node.
fn sixty_four_byte_tx() -> Transaction {
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0x11; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![pay(1_000, vec![0x51; 4])],
    };
    assert_eq!(tx.base_size(), 64, "fixture: a 64-byte transaction");
    tx
}

/// An empty body sent for an announced header is a merkle mismatch, not a
/// verdict on the block. The honest body connects afterwards.
///
/// This is the order the P2P path produces when the empty body arrives before
/// its parent is known: it waits in the unknown-parent buffer, the headers
/// arrive, the parent connects, and the buffer hands the empty body to
/// `accept_block` with the header now known.
///
/// Fails without the fix: the empty body answered `bad-blk-length`
/// (`EmptyBlock`, tested before the merkle root), was marked `Invalid`, and
/// the honest block 5 then answered `duplicate`.
#[test]
fn an_empty_body_for_a_known_header_does_not_bar_the_real_block() {
    let (cs, dir) = make_chain_state();
    let chain = connect_chain(&cs, 3);
    let b4 = build_test_block(chain[2].block_hash(), 4, 1_707_000_004);
    let b5 = build_test_block(b4.block_hash(), 5, 1_707_000_005);
    let (accepted, err) = cs.accept_headers(&[b4.header, b5.header]);
    assert_eq!(accepted, 2, "fixture: headers accepted ({err:?})");

    let empty = Block { header: b5.header, txdata: Vec::new() };
    let err = cs.accept_block(&empty).expect_err("an empty body must be refused");
    assert_eq!(err.to_string(), "bad-txnmrklroot", "Core's CheckMerkleRoot runs first");
    assert_eq!(
        status(&cs, &b5.block_hash()),
        Some(BlockStatus::HeaderOnly),
        "a body the header does not commit to must not mark the header invalid"
    );

    cs.accept_block(&b4).expect("block 4 connects");
    cs.accept_block(&b5).expect("the real block 5 connects");
    assert_eq!(cs.tip_hash(), b5.block_hash());
    assert_eq!(status(&cs, &b5.block_hash()), Some(BlockStatus::Valid));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `CheckBlock` failures are never marked, as in Core's `ProcessNewBlock`,
/// even when the header does commit to the failing body. Each case here is a
/// body whose merkle root matches its header.
///
/// Fails without the fix: every one of these was marked `Invalid` on the
/// `HeaderOnly` row (only mutation-class reasons were exempt).
#[test]
fn a_check_block_failure_is_not_marked_on_a_known_header() {
    let (cs, dir) = make_chain_state();
    let chain = connect_chain(&cs, 3);
    let tip = chain[2].block_hash();
    let subsidy = crate::chain::connect::block_subsidy(Network::Regtest, 4);

    // `bad-cb-missing`, in the shape Core's `IsBlockMutated` singles out: no
    // coinbase and one 64-byte transaction, which a header for a two-
    // transaction block can be made to commit to.
    let coinbase_less = announced_block(&cs, tip, 1_707_000_100, vec![sixty_four_byte_tx()]);
    assert!(
        crate::validation::block::is_block_mutated(&coinbase_less, true),
        "fixture: the P2P gate would call this body mutated"
    );
    // `bad-cb-multiple`.
    let two_coinbases = announced_block(
        &cs,
        tip,
        1_707_000_101,
        vec![
            coinbase(vec![0x54, 0x01], vec![pay(subsidy, vec![])]),
            coinbase(vec![0x54, 0x02], vec![pay(1, vec![])]),
        ],
    );
    // `bad-blk-sigops`: Core's legacy-count ceiling in `CheckBlock`.
    let sigops = announced_block(
        &cs,
        tip,
        1_707_000_102,
        vec![coinbase(vec![0x54, 0x03], vec![pay(subsidy, vec![0xac; 20_001])])],
    );

    for (block, reason) in [
        (&coinbase_less, "bad-cb-missing"),
        (&two_coinbases, "bad-cb-multiple"),
        (&sigops, "bad-blk-sigops"),
    ] {
        let err = cs.accept_block(block).expect_err(reason);
        assert_eq!(err.to_string(), reason);
        assert_eq!(
            status(&cs, &block.block_hash()),
            Some(BlockStatus::HeaderOnly),
            "{reason}: a CheckBlock failure must leave the header unmarked"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `bad-blk-weight` is the one `check_block` rule Core marks: it comes from
/// `ContextualCheckBlock`, after the witness commitment has pinned every byte
/// that was weighed. The counterpart to the test above: marking still happens
/// where Core marks.
///
/// Perturbation: drop the `OverweightBlock` arm from `accept_block`'s marking
/// and the status stays `HeaderOnly`.
#[test]
fn an_overweight_block_is_still_marked_invalid() {
    let (cs, dir) = make_chain_state();
    let chain = connect_chain(&cs, 3);
    let tip = chain[2].block_hash();

    // A spend whose witness alone pushes the block past 4M weight units, under
    // a valid BIP 141 commitment.
    let mut witness = bitcoin::Witness::new();
    witness.push(vec![0u8; 4_000_000]);
    let heavy = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0x22; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness,
        }],
        output: vec![pay(1_000, vec![])],
    };
    // BIP 141: the witness root over [0 (coinbase), wtxid(heavy)], then
    // SHA256d(witness root || reserved value).
    let sha256d = |a: &[u8; 32], b: &[u8; 32]| {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(a);
        preimage[32..].copy_from_slice(b);
        bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array()
    };
    let nonce = [0u8; 32];
    let witness_root = sha256d(&[0u8; 32], &heavy.compute_wtxid().to_raw_hash().to_byte_array());
    let commitment = sha256d(&witness_root, &nonce);
    let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment_script.extend_from_slice(&commitment);
    let mut cb = coinbase(
        vec![0x54, 0x04],
        vec![pay(crate::chain::connect::block_subsidy(Network::Regtest, 4), vec![]), pay(0, commitment_script)],
    );
    cb.input[0].witness.push(nonce);

    let block = announced_block(&cs, tip, 1_707_000_200, vec![cb, heavy]);
    let err = cs.accept_block(&block).expect_err("an overweight block must be refused");
    assert_eq!(err.to_string(), "bad-blk-weight");
    assert_eq!(
        status(&cs, &block.block_hash()),
        Some(BlockStatus::Invalid),
        "Core's AcceptBlock marks bad-blk-weight BLOCK_FAILED_VALID"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A block that extends the tip, arrives without its header first and fails
/// to connect is remembered as invalid. A copy sent again is answered from
/// the index: not validated again, and not written to disk again.
///
/// Fails without the fix: no index entry existed for the mark to land on, so
/// the second copy was validated in full, answered
/// `bad-txns-inputs-missingorspent` again, and grew the block files.
#[test]
fn a_tip_extending_block_that_fails_to_connect_is_remembered() {
    let (cs, dir) = make_chain_state();
    let chain = connect_chain(&cs, 3);
    let tip = chain[2].block_hash();

    let missing = OutPoint { txid: bitcoin::Txid::from_byte_array([0x9e; 32]), vout: 0 };
    let bad = build_test_block_spending(tip, 4, 1_707_000_004, missing);
    assert!(cs.get_block_index(&bad.block_hash()).is_none(), "fixture: no header announced");

    let err = cs.accept_block(&bad).expect_err("a block spending a missing coin");
    assert_eq!(err.to_string(), "bad-txns-inputs-missingorspent");
    assert_eq!(status(&cs, &bad.block_hash()), Some(BlockStatus::Invalid));
    assert_eq!(cs.tip_hash(), tip, "the tip must not move");

    let on_disk = cs.flat_files.lock().size_on_disk();
    let again = cs.accept_block(&bad).expect_err("the same block again");
    assert!(matches!(again, ChainError::Duplicate), "answered from the index, got: {again}");
    assert_eq!(
        cs.flat_files.lock().size_on_disk(),
        on_disk,
        "a copy of a block already judged must not be written again"
    );

    // The tip's other children are untouched by the mark.
    let good = build_test_block(tip, 4, 1_707_000_005);
    cs.accept_block(&good).expect("a valid sibling connects");
    assert_eq!(cs.tip_hash(), good.block_hash());
    assert_eq!(status(&cs, &bad.block_hash()), Some(BlockStatus::Invalid));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The index entry made for an unannounced block is the one a header
/// announcement makes, so a block that connects ends exactly as it did before:
/// `Valid`, the tip, and the best header.
#[test]
fn an_unannounced_block_that_connects_ends_valid_and_best() {
    let (cs, dir) = make_chain_state();
    let chain = connect_chain(&cs, 3);
    let b4 = build_test_block(chain[2].block_hash(), 4, 1_707_000_004);
    assert!(cs.get_block_index(&b4.block_hash()).is_none(), "fixture: no header announced");

    cs.accept_block(&b4).expect("block 4 connects");
    let entry = cs.get_block_index(&b4.block_hash()).expect("indexed");
    assert_eq!(entry.status, BlockStatus::Valid);
    assert_eq!(entry.num_tx, 1);
    assert_eq!(cs.tip_hash(), b4.block_hash());
    assert_eq!(cs.best_header_hash(), b4.block_hash());
    assert_eq!(cs.check_block_index(None), Ok(4));

    let _ = std::fs::remove_dir_all(&dir);
}
