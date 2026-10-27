//! Reading OP_RETURN-stripped blocks, and the writes that retire a strip
//! record: prune, and every path that points a block's entry at a fresh full
//! copy.
//!
//! Nothing here strips through the strip worker, which does not exist yet.
//! [`strip`] does what it will do, in its order: commit the record, then
//! overwrite the payload on disk.

use std::os::unix::fs::FileExt;

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::{Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, transaction};

use super::tests::{build_test_block, grind_test_pow, make_chain_state, make_chain_state_with_store};
use super::*;
use crate::storage::StoreBatch;
use crate::storage::db::InMemoryStore;
use crate::storage::opreturn_strip::StripRecord;
use crate::storage::test_store::ControllableStore;

/// The plan's default threshold; the test payload is above it.
const THRESHOLD: u64 = 4096;
const PAYLOAD: usize = 5000;

fn time(h: u32) -> u32 {
    1_300_000_000 + h * 600
}

fn big_op_return() -> ScriptBuf {
    let mut v = vec![0x6a];
    v.extend((1..PAYLOAD).map(|i| (i % 251) as u8 + 1));
    ScriptBuf::from_bytes(v)
}

/// A block on `parent` whose second transaction spends `spend` into a plain
/// output and a `PAYLOAD`-byte OP_RETURN.
fn block_with_big_op_return(parent: BlockHash, height: u32, spend: OutPoint) -> Block {
    let mut block = build_test_block(parent, height, time(height));
    block.txdata.push(Transaction {
        version: transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spend,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: big_op_return(),
            },
        ],
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    grind_test_pow(&mut block);
    block
}

/// Blocks 1 to 101, coinbase only.
fn mature_chain(cs: &ChainState) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks = Vec::new();
    for h in 1..=101 {
        let b = build_test_block(parent, h, time(h));
        assert!(cs.accept_block(&b).expect("accept").connected());
        parent = b.block_hash();
        blocks.push(b);
    }
    blocks
}

fn coinbase_of(b: &Block) -> OutPoint {
    OutPoint {
        txid: b.txdata[0].compute_txid(),
        vout: 0,
    }
}

/// `mature_chain`, then block 102 carrying the big OP_RETURN, connected.
fn chain_with_a_big_op_return(cs: &ChainState) -> Vec<Block> {
    let mut blocks = mature_chain(cs);
    let b = block_with_big_op_return(blocks[100].block_hash(), 102, coinbase_of(&blocks[0]));
    assert!(cs.accept_block(&b).expect("accept").connected());
    blocks.push(b);
    blocks
}

fn record_for(block: &Block) -> (StripRecord, Vec<u8>) {
    StripRecord::build(&serialize(block), block, THRESHOLD)
        .expect("the bytes are the block")
        .expect("the OP_RETURN is eligible")
}

fn put_record(store: &dyn crate::storage::Store, hash: BlockHash, record: &StripRecord) {
    store
        .write_batch(StoreBatch {
            opreturn_strip_puts: vec![(hash, record.encode())],
            ..Default::default()
        })
        .unwrap();
}

/// Where a block's payload starts in its block file: after the 8-byte
/// magic and length that `data_pos` points at.
fn payload_location(cs: &ChainState, hash: &BlockHash) -> (std::path::PathBuf, u64) {
    let entry = cs.store.get_block_index(hash).expect("indexed");
    (
        cs.blocks_dir().join(format!("blk{:05}.dat", entry.file_number)),
        u64::from(entry.data_pos) + 8,
    )
}

fn overwrite_payload(path: &std::path::Path, offset: u64, bytes: &[u8]) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.write_all_at(bytes, offset).unwrap();
}

/// Strip `block` as the strip worker will: the record first, then the
/// bytes. Returns the filled form.
fn strip(cs: &ChainState, block: &Block) -> Vec<u8> {
    let hash = block.block_hash();
    let (record, filled) = record_for(block);
    put_record(&*cs.store, hash, &record);
    let (path, offset) = payload_location(cs, &hash);
    overwrite_payload(&path, offset, &filled);
    filled
}

fn corrupt_warning(cs: &ChainState, hash: &BlockHash) -> Option<String> {
    let id = format!("blockdata.corrupt.{hash}");
    cs.warnings().list().into_iter().find(|w| w.id == id).map(|w| w.message)
}

fn assert_filled(cs: &ChainState, original: &Block, filled: &[u8]) {
    let hash = original.block_hash();
    let stored = cs.get_stored_block(&hash).expect("a stripped block reads in its filled form");
    assert!(stored.is_stripped());
    assert_eq!(serialize(&stored.block), filled);
    assert_eq!(stored.txids(), original.txdata.iter().map(|t| t.compute_txid()).collect::<Vec<_>>());
    assert_eq!(stored.wtxids(), original.txdata.iter().map(|t| t.compute_wtxid()).collect::<Vec<_>>());
    let script = stored.block.txdata[1].output[1].script_pubkey.as_bytes();
    assert_eq!(script.len(), PAYLOAD, "the filled form keeps the original size");
    assert_eq!(script[0], 0x6a);
    assert!(script[1..].iter().all(|b| *b == 0));
}

/// `get_block` answers "unavailable" for a stripped block and raises no
/// warning, since stripping is not corruption; `get_stored_block` answers
/// the filled form with the original txids.
#[test]
fn a_stripped_block_is_unavailable_to_get_block_and_filled_from_get_stored_block() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();

    assert_eq!(cs.get_block(&hash).as_ref(), Some(b), "intact before the strip");
    assert!(!cs.get_stored_block(&hash).unwrap().is_stripped());

    let filled = strip(&cs, b);
    let (path, offset) = payload_location(&cs, &hash);
    let mut on_disk = vec![0u8; filled.len()];
    std::fs::File::open(&path).unwrap().read_exact_at(&mut on_disk, offset).unwrap();
    assert_eq!(on_disk, filled, "premise: the payload on disk is zeroed");

    assert_eq!(cs.get_block(&hash), None);
    assert!(!cs.block_data_readable(&hash));
    assert_eq!(corrupt_warning(&cs, &hash), None, "a stripped block is not corrupt");
    assert_filled(&cs, b, &filled);
    // Its neighbours are untouched.
    assert_eq!(cs.get_block(&blocks[100].block_hash()).as_ref(), Some(&blocks[100]));
    let _ = std::fs::remove_dir_all(dir);
}

/// A record that does not fit the bytes it is found with is corruption,
/// reported as such, and never served.
#[test]
fn a_record_that_does_not_fit_the_bytes_is_reported_as_corruption() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    let filled = strip(&cs, b);
    assert_filled(&cs, b, &filled);

    let (mut record, _) = record_for(b);
    record.filled_sha256[0] ^= 1;
    put_record(&*cs.store, hash, &record);
    assert!(cs.get_stored_block(&hash).is_none());
    assert!(cs.get_block(&hash).is_none());
    let warning = corrupt_warning(&cs, &hash).expect("a mismatched record is reported");
    assert!(warning.contains("strip record does not match"), "{warning}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_record_that_does_not_decode_is_reported_as_corruption() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    let filled = strip(&cs, b);
    assert_filled(&cs, b, &filled);

    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_puts: vec![(hash, vec![0xff])],
            ..Default::default()
        })
        .unwrap();
    assert!(cs.get_stored_block(&hash).is_none());
    let warning = corrupt_warning(&cs, &hash).expect("an undecodable record is reported");
    assert!(warning.contains("strip record does not decode"), "{warning}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A record that cannot be read is not "no record": reading on would serve
/// the zeroed bytes as the block.
#[test]
fn an_unreadable_record_is_corruption_not_an_intact_block() {
    let store = ControllableStore::new();
    let controls = store.controls();
    let (cs, dir) = make_chain_state_with_store(Box::new(store));
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    let filled = strip(&cs, b);
    assert_filled(&cs, b, &filled);

    controls.set_strip_unreadable(true);
    assert!(cs.get_stored_block(&hash).is_none());
    assert!(cs.get_block(&hash).is_none());
    let warning = corrupt_warning(&cs, &hash).expect("an unreadable record is reported");
    assert!(warning.contains("strip record could not be read"), "{warning}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The reader race. A strip commits its record and punches between a
/// reader's byte read and its record lookup. The reader read the bytes
/// before the record existed, so they were intact, and it must answer the
/// intact block. Looking the record up first would see no record and then
/// read the punched bytes as the block.
#[test]
fn a_strip_between_the_byte_read_and_the_record_lookup_reads_consistently() {
    let store = ControllableStore::new();
    let controls = store.controls();
    let (cs, dir) = make_chain_state_with_store(Box::new(store));
    let blocks = chain_with_a_big_op_return(&cs);
    let b = blocks[101].clone();
    let hash = b.block_hash();
    let (record, filled) = record_for(&b);
    let (path, offset) = payload_location(&cs, &hash);

    // The worker flushes before every pass (plan §2.4), so the connect's
    // buffered rows are on disk and the hook's direct write is not shadowed.
    cs.flush_durable().unwrap();
    let punched = filled.clone();
    controls.after_next_strip_lookup(move |inner: &InMemoryStore| {
        put_record(inner, hash, &record);
        overwrite_payload(&path, offset, &punched);
    });
    assert_eq!(
        cs.get_block(&hash).as_ref(),
        Some(&b),
        "a reader that found no record must have read intact bytes"
    );
    assert_eq!(corrupt_warning(&cs, &hash), None);

    // The next reader finds the record.
    assert_eq!(cs.get_block(&hash), None);
    assert_filled(&cs, &b, &filled);
    let _ = std::fs::remove_dir_all(dir);
}

/// Deleting a block file deletes the bytes its blocks' records describe, so
/// the records go with it.
#[test]
fn prune_drops_the_strip_records_of_the_blocks_it_deletes() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    strip(&cs, b);

    // Rotate the append file so file 0 becomes deletable (see
    // `prune_keeps_a_file_holding_blocks_stored_above_the_tip`).
    std::fs::write(cs.blocks_dir().join("blk00001.dat"), b"").unwrap();
    *cs.flat_files.lock() = FlatFileManager::new(cs.blocks_dir()).unwrap();
    let mut parent = hash;
    for h in 103..=110 {
        let next = build_test_block(parent, h, time(h));
        assert!(cs.accept_block(&next).expect("accept").connected());
        parent = next.block_hash();
    }

    assert!(cs.store.get_opreturn_strip(&hash).unwrap().is_some(), "premise: stripped");
    assert_eq!(cs.prune_up_to(102), 1, "file 0 goes");
    assert!(cs.is_pruned(&hash));
    assert_eq!(cs.store.get_opreturn_strip(&hash).unwrap(), None);
    let _ = std::fs::remove_dir_all(dir);
}

/// `getblockfrompeer`'s repair appends a full copy and points the entry at
/// it; the record of the old copy goes in the same batch.
#[test]
fn repairing_a_stripped_block_with_a_full_copy_drops_the_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    strip(&cs, b);
    assert_eq!(cs.get_block(&hash), None, "premise: stripped");

    assert!(matches!(cs.repair_block_data(b), Ok(BlockDataRepair::Repaired { .. })));
    assert_eq!(cs.store.get_opreturn_strip(&hash).unwrap(), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(b));
    let _ = std::fs::remove_dir_all(dir);
}

/// A header-only entry left with a record: what a `-reindex` that could not
/// find a stripped block's copy leaves behind.
fn header_only_with_a_record(cs: &ChainState) -> Block {
    let blocks = mature_chain(cs);
    let b = block_with_big_op_return(blocks[100].block_hash(), 102, coinbase_of(&blocks[0]));
    cs.accept_header(&b.header).expect("header");
    let (record, _) = record_for(&b);
    put_record(&*cs.store, b.block_hash(), &record);
    b
}

#[test]
fn storing_a_full_copy_over_a_stale_record_drops_the_record() {
    let (cs, dir) = make_chain_state();
    let b = header_only_with_a_record(&cs);
    let hash = b.block_hash();

    cs.store_block(&b).expect("store");
    assert_eq!(cs.store.get_opreturn_strip(&hash).unwrap(), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&b));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn connecting_a_full_copy_over_a_stale_record_drops_the_record() {
    let (cs, dir) = make_chain_state();
    let b = header_only_with_a_record(&cs);
    let hash = b.block_hash();

    assert!(cs.accept_block(&b).expect("accept").connected());
    assert_eq!(cs.store.get_opreturn_strip(&hash).unwrap(), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&b));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn storing_a_side_chain_copy_over_a_stale_record_drops_the_record() {
    let (cs, dir) = make_chain_state();
    let blocks = mature_chain(&cs);
    // A competitor for height 101, on block 100: no more work than the tip,
    // so it is stored and not connected.
    let fork = block_with_big_op_return(blocks[99].block_hash(), 101, coinbase_of(&blocks[0]));
    let hash = fork.block_hash();
    let (record, _) = record_for(&fork);
    put_record(&*cs.store, hash, &record);

    assert!(!cs.accept_block(&fork).expect("accept").connected());
    assert_eq!(cs.store.get_opreturn_strip(&hash).unwrap(), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&fork));
    let _ = std::fs::remove_dir_all(dir);
}

/// A record lost some other way than the writes above, as store corruption
/// loses a row, leaves the punched bytes looking like an intact block whose
/// header hash still matches. The zeroed payload calls for a merkle check,
/// and the check refuses it.
#[test]
fn a_lost_strip_record_is_caught_by_the_merkle_check() {
    let (cs, dir) = make_chain_state();
    let blocks = chain_with_a_big_op_return(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    strip(&cs, b);
    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_removes: vec![hash],
            ..Default::default()
        })
        .unwrap();

    assert!(cs.get_stored_block(&hash).is_none(), "punched bytes must not read as the block");
    let warning = corrupt_warning(&cs, &hash).expect("a lost record is reported");
    assert!(warning.contains("lost strip record"), "{warning}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The must-succeed pair: a genuine OP_RETURN payload of zeros, never
/// stripped, reproduces its merkle root and reads as the block.
#[test]
fn a_genuine_zero_payload_reads_as_the_block() {
    let (cs, dir) = make_chain_state();
    let blocks = mature_chain(&cs);
    let mut b = block_with_big_op_return(blocks[100].block_hash(), 102, coinbase_of(&blocks[0]));
    let mut zeros = vec![0x6a];
    zeros.resize(PAYLOAD, 0);
    b.txdata[1].output[1].script_pubkey = ScriptBuf::from_bytes(zeros);
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    grind_test_pow(&mut b);
    assert!(crate::storage::opreturn_strip::has_zeroed_op_return(&b), "premise");
    assert!(cs.accept_block(&b).expect("accept").connected());

    let hash = b.block_hash();
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&b));
    assert_eq!(corrupt_warning(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}
