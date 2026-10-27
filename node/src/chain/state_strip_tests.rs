//! `ChainState::strip_block`: what it strips, what it refuses, and what it
//! does when the block moves under it.

use std::os::unix::fs::FileExt;

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::{Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, transaction};

use super::super::tests::{build_test_block, grind_test_pow, make_chain_state};
use super::*;
use crate::storage::opreturn_strip::{StripRecord, tx_spans};

const THRESHOLD: u64 = 4096;
/// tx 1 carries a large OP_RETURN (vout 1) and a small one (vout 2); tx 2 a
/// small one (vout 1).
const BIG: usize = 5000;
const SMALL: usize = 300;

/// Recent enough that a tip near height 105 is out of IBD, and not in the
/// future. Fixed once per run, so every chain this file builds is the same.
fn time(h: u32) -> u32 {
    static BASE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *BASE.get_or_init(|| crate::time::now_secs() as u32 - 120 * 600) + h * 600
}

fn op_return(len: usize, seed: u8) -> ScriptBuf {
    let mut v = vec![0x6a];
    v.extend((1..len).map(|i| (i % 251) as u8 ^ seed | 1));
    ScriptBuf::from_bytes(v)
}

fn spend(prev: OutPoint, scripts: Vec<ScriptBuf>) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: scripts
            .into_iter()
            .enumerate()
            .map(|(i, s)| TxOut {
                value: Amount::from_sat(if i == 0 { 1_000 } else { 0 }),
                script_pubkey: s,
            })
            .collect(),
    }
}

fn block_on(parent: BlockHash, height: u32, txs: Vec<Transaction>) -> Block {
    let mut block = build_test_block(parent, height, time(height));
    block.txdata.extend(txs);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    grind_test_pow(&mut block);
    block
}

fn coinbase_of(b: &Block) -> OutPoint {
    OutPoint {
        txid: b.txdata[0].compute_txid(),
        vout: 0,
    }
}

fn connect(cs: &ChainState, b: &Block) {
    assert!(cs.accept_block(b).expect("accept").connected());
}

/// Blocks 1 to 101, then block 102 with the OP_RETURNs, then 103 to 105.
/// Returns every block; `blocks[101]` is the one with the OP_RETURNs.
fn chain(cs: &ChainState) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks = Vec::new();
    for h in 1..=101 {
        let b = build_test_block(parent, h, time(h));
        connect(cs, &b);
        parent = b.block_hash();
        blocks.push(b);
    }
    let b = block_on(
        parent,
        102,
        vec![
            spend(
                coinbase_of(&blocks[0]),
                vec![ScriptBuf::new(), op_return(BIG, 1), op_return(SMALL, 2)],
            ),
            spend(coinbase_of(&blocks[1]), vec![ScriptBuf::new(), op_return(SMALL, 3)]),
        ],
    );
    connect(cs, &b);
    blocks.push(b);
    for h in 103..=105 {
        let b = build_test_block(blocks.last().unwrap().block_hash(), h, time(h));
        connect(cs, &b);
        blocks.push(b);
    }
    assert!(!cs.is_initial_block_download(), "premise: the fixture is out of IBD");
    blocks
}

/// The block's bytes as they sit in its block file, decoded.
fn on_disk(cs: &ChainState, hash: &BlockHash) -> Vec<u8> {
    let entry = cs.store.get_block_index(hash).expect("indexed");
    let path = cs.blocks_dir().join(format!("blk{:05}.dat", entry.file_number));
    let f = std::fs::File::open(path).unwrap();
    let mut len = [0u8; 8];
    f.read_exact_at(&mut len, u64::from(entry.data_pos)).unwrap();
    let key = cs.flat_files.lock().xor_key();
    crate::storage::flatfile::xor_in_place(&mut len, &key, u64::from(entry.data_pos));
    let size = u32::from_le_bytes(len[4..8].try_into().unwrap()) as usize;
    let mut data = vec![0u8; size];
    f.read_exact_at(&mut data, u64::from(entry.data_pos) + 8).unwrap();
    crate::storage::flatfile::xor_in_place(&mut data, &key, u64::from(entry.data_pos) + 8);
    data
}

fn write_on_disk(cs: &ChainState, hash: &BlockHash, offset: usize, bytes: &[u8]) {
    let entry = cs.store.get_block_index(hash).expect("indexed");
    let path = cs.blocks_dir().join(format!("blk{:05}.dat", entry.file_number));
    let at = u64::from(entry.data_pos) + 8 + offset as u64;
    let mut enc = bytes.to_vec();
    let key = cs.flat_files.lock().xor_key();
    crate::storage::flatfile::xor_in_place(&mut enc, &key, at);
    std::fs::OpenOptions::new().write(true).open(path).unwrap().write_all_at(&enc, at).unwrap();
}

/// The bytes of output `vout` of tx `tx` after its opcode, as stored.
fn payload_on_disk(cs: &ChainState, hash: &BlockHash, tx: usize, vout: usize) -> Vec<u8> {
    let bytes = on_disk(cs, hash);
    let span = tx_spans(&bytes).unwrap()[tx].outputs[vout];
    bytes[span.strip_range()].to_vec()
}

fn record(cs: &ChainState, hash: &BlockHash) -> Option<StripRecord> {
    cs.store.get_opreturn_strip(hash).unwrap().map(|b| StripRecord::decode(&b).unwrap())
}

fn corrupt_warning(cs: &ChainState, hash: &BlockHash) -> Option<String> {
    let id = format!("blockdata.corrupt.{hash}");
    cs.warnings().list().into_iter().find(|w| w.id == id).map(|w| w.message)
}

fn stats(outcome: StripOutcome) -> StripStats {
    match outcome {
        StripOutcome::Stripped(s) | StripOutcome::Redone(s) | StripOutcome::Extended(s) => s,
        other => panic!("expected a strip, got {other:?}"),
    }
}

/// `get_stored_block` reads the stripped block with its original identity.
fn assert_reads_as(cs: &ChainState, original: &Block) {
    let stored = cs.get_stored_block(&original.block_hash()).expect("the stripped block reads");
    assert!(stored.is_stripped());
    assert_eq!(stored.txids(), original.txdata.iter().map(|t| t.compute_txid()).collect::<Vec<_>>());
    assert_eq!(stored.wtxids(), original.txdata.iter().map(|t| t.compute_wtxid()).collect::<Vec<_>>());
}

#[test]
fn strip_block_records_then_zeroes_the_eligible_payloads() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    let before = on_disk(&cs, &hash);

    let s = stats(cs.strip_block(&hash, THRESHOLD).unwrap());
    assert_eq!((s.txs, s.outputs, s.span_bytes), (1, 1, BIG as u64 - 1));

    let rec = record(&cs, &hash).expect("a record");
    assert_eq!(rec.txs.len(), 1);
    assert_eq!(rec.txs[0].tx_index, 1);
    assert_eq!(rec.txs[0].txid, b.txdata[1].compute_txid());
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().all(|x| *x == 0), "the big payload is zeroed");
    assert_eq!(
        payload_on_disk(&cs, &hash, 1, 2),
        op_return(SMALL, 2).as_bytes()[1..],
        "below the threshold stays"
    );
    // Nothing else on disk changed.
    let after = on_disk(&cs, &hash);
    let span = tx_spans(&before).unwrap()[1].outputs[1].strip_range();
    assert_eq!(before[..span.start], after[..span.start]);
    assert_eq!(before[span.end..], after[span.end..]);

    assert_eq!(cs.get_block(&hash), None);
    assert_reads_as(&cs, b);
    assert_eq!(corrupt_warning(&cs, &hash), None);
    assert_eq!(cs.get_block(&blocks[100].block_hash()).as_ref(), Some(&blocks[100]));
    let _ = std::fs::remove_dir_all(dir);
}

/// A strip a crash interrupted after its record is finished by the next
/// call: it punches the spans again, and writes no new record.
#[test]
fn a_repeat_strip_re_punches_the_recorded_spans() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let original = on_disk(&cs, &hash);
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let rec = record(&cs, &hash);

    // As if the punch never landed.
    write_on_disk(&cs, &hash, 0, &original);
    assert!(cs.get_stored_block(&hash).is_some(), "a record over intact bytes reads");
    let s = match cs.strip_block(&hash, THRESHOLD).unwrap() {
        StripOutcome::Redone(s) => s,
        other => panic!("expected a redo, got {other:?}"),
    };
    assert_eq!((s.outputs, s.span_bytes), (1, BIG as u64 - 1));
    assert_eq!(record(&cs, &hash), rec);
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().all(|x| *x == 0));
    assert_reads_as(&cs, &blocks[101]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn nothing_eligible_writes_nothing() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let before = on_disk(&cs, &hash);
    assert_eq!(cs.strip_block(&hash, BIG as u64 + 1).unwrap(), StripOutcome::NothingEligible);
    assert_eq!(
        cs.strip_block(&blocks[50].block_hash(), 0).unwrap(),
        StripOutcome::NothingEligible,
        "a coinbase-only block"
    );
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(on_disk(&cs, &hash), before);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&blocks[101]));
    let _ = std::fs::remove_dir_all(dir);
}

/// Lowering the threshold adds the newly eligible outputs to the record:
/// a stripped transaction keeps its recorded txid, a new one takes its
/// txid from its bytes, and only the new spans are punched.
#[test]
fn a_lower_threshold_extends_the_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();

    let s = match cs.strip_block(&hash, SMALL as u64).unwrap() {
        StripOutcome::Extended(s) => s,
        other => panic!("expected an extension, got {other:?}"),
    };
    assert_eq!((s.txs, s.outputs, s.span_bytes), (2, 2, 2 * (SMALL as u64 - 1)));
    let rec = record(&cs, &hash).unwrap();
    let shape: Vec<(u32, Vec<u32>)> =
        rec.txs.iter().map(|t| (t.tx_index, t.outputs.iter().map(|o| o.vout).collect())).collect();
    assert_eq!(shape, vec![(1, vec![1, 2]), (2, vec![1])]);
    for (tx, vout) in [(1, 1), (1, 2), (2, 1)] {
        assert!(payload_on_disk(&cs, &hash, tx, vout).iter().all(|x| *x == 0), "{tx}:{vout}");
    }
    assert_reads_as(&cs, b);
    assert!(matches!(cs.strip_block(&hash, SMALL as u64).unwrap(), StripOutcome::Redone(_)));
    let _ = std::fs::remove_dir_all(dir);
}

/// Bytes that do not hash to the header's merkle root are never stripped:
/// the record's txids would be wrong for good once the payload is gone.
#[test]
fn a_stored_copy_that_fails_check_block_is_refused_and_reported() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let spans = tx_spans(&on_disk(&cs, &hash)).unwrap();
    // A byte of tx 1's prevout: it still deserializes, with the same header.
    write_on_disk(&cs, &hash, spans[1].offset + 6, &[0xee]);
    let before = on_disk(&cs, &hash);

    match cs.strip_block(&hash, THRESHOLD) {
        Err(StripError::Corrupt { detail, .. }) => assert!(detail.contains("check_block"), "{detail}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let warning = corrupt_warning(&cs, &hash).expect("the corrupt copy is reported");
    assert!(warning.contains("check_block"), "{warning}");
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(on_disk(&cs, &hash), before, "nothing punched");
    let _ = std::fs::remove_dir_all(dir);
}

/// Punched bytes whose record was lost are not a block: re-stripping them
/// would record txids computed from zeros.
#[test]
fn punched_bytes_with_a_lost_record_are_refused() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_removes: vec![hash],
            ..Default::default()
        })
        .unwrap();
    assert!(matches!(cs.strip_block(&hash, THRESHOLD), Err(StripError::Corrupt { .. })));
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_node_in_ibd_strips_nothing() {
    let (cs, dir) = make_chain_state();
    let genesis = cs.tip_hash();
    assert!(cs.is_initial_block_download(), "premise: a genesis-only node is in IBD");
    assert!(matches!(
        cs.strip_block(&genesis, 0),
        Err(StripError::NotQuiet("initial block download"))
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bulk_load_write_mode_strips_nothing() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.set_write_mode(crate::storage::WriteMode::BulkLoad);
    assert!(matches!(cs.strip_block(&hash, THRESHOLD), Err(StripError::NotQuiet(_))));
    assert_eq!(record(&cs, &hash), None);
    cs.set_write_mode(crate::storage::WriteMode::Normal);
    assert!(matches!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Stripped(_)));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_background_chainstate_strips_nothing() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let snap = blocks[104].block_hash();
    cs.attach_background(dir.join("chainstate_background"), 105, snap, [0u8; 32], 64, -1)
        .unwrap();
    assert!(matches!(cs.strip_block(&hash, THRESHOLD), Err(StripError::NotQuiet(_))));
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn only_a_valid_block_on_the_active_chain_is_stripped() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();

    let unknown = BlockHash::from_byte_array([9; 32]);
    assert!(matches!(cs.strip_block(&unknown, THRESHOLD), Err(StripError::UnknownBlock(_))));

    cs.invalidate_block(hash).unwrap();
    assert!(matches!(
        cs.strip_block(&hash, THRESHOLD),
        Err(StripError::NotValid { status: BlockStatus::Invalid, .. })
    ));
    cs.reconsider_block(hash).unwrap();
    assert_eq!(cs.tip_hash(), blocks[104].block_hash());

    // A longer fork from block 101 takes over; 102 to 105 leave the active
    // chain still Valid.
    let mut parent = blocks[100].block_hash();
    for h in 102..=107 {
        let b = build_test_block(parent, h, time(h) + 1);
        cs.accept_block(&b).expect("accept fork block");
        parent = b.block_hash();
    }
    assert_eq!(cs.tip_hash(), parent, "premise: the fork is active");
    let entry = cs.store.get_block_index(&hash).unwrap();
    assert_eq!(entry.status, BlockStatus::Valid, "premise: a disconnected block stays Valid");
    assert!(matches!(cs.strip_block(&hash, THRESHOLD), Err(StripError::NotActive(_))));
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

/// A repair that points the entry at a fresh copy between the record and
/// the punch leaves the fresh copy intact and drops the record, which
/// describes the old copy. Nothing is punched.
#[test]
fn a_repoint_before_the_punch_leaves_no_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = blocks[101].clone();
    let hash = b.block_hash();
    let old = cs.store.get_block_index(&hash).unwrap();
    let original = on_disk(&cs, &hash);
    *cs.strip.after_record_hook.lock() = Some(Box::new(move |cs: &ChainState| {
        assert!(record(cs, &b.block_hash()).is_some(), "the hook runs after the record");
        // `get_block` sees the record and answers None, so the repair
        // appends a full copy.
        assert!(matches!(
            cs.repair_block_data(&b).unwrap(),
            crate::chain::state::BlockDataRepair::Repaired { .. }
        ));
    }));

    assert_eq!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Raced);
    let now = cs.store.get_block_index(&hash).unwrap();
    assert_ne!((now.file_number, now.data_pos), (old.file_number, old.data_pos), "premise: moved");
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&blocks[101]));
    assert_eq!(on_disk(&cs, &hash), original);
    let _ = std::fs::remove_dir_all(dir);
}

/// A block whose entry changes in place between the record and the punch
/// keeps the record it had before the call: nothing new is punched, and
/// what an earlier strip punched still has its record.
///
/// The change here is `invalidateblock`. With a record in place the block
/// reads as stripped, so the disconnect fails closed (plan §2.10), but the
/// block is marked `Invalid` all the same.
#[test]
fn a_block_invalidated_before_the_punch_keeps_its_prior_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let invalidate = move |cs: &ChainState| {
        let _ = cs.invalidate_block(hash);
        assert_eq!(cs.store.get_block_index(&hash).unwrap().status, BlockStatus::Invalid);
    };

    // No prior record: none is left.
    *cs.strip.after_record_hook.lock() = Some(Box::new(invalidate));
    assert_eq!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Raced);
    assert_eq!(record(&cs, &hash), None);
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().any(|x| *x != 0), "not punched");
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&blocks[101]));
    let _ = std::fs::remove_dir_all(dir);

    // A prior record: it is put back, so its punched span still reads.
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    assert_eq!(blocks[101].block_hash(), hash);
    assert!(matches!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Stripped(_)));
    let prior = record(&cs, &hash);
    *cs.strip.after_record_hook.lock() = Some(Box::new(invalidate));
    assert_eq!(cs.strip_block(&hash, SMALL as u64).unwrap(), StripOutcome::Raced);
    assert_eq!(record(&cs, &hash), prior);
    assert_eq!(payload_on_disk(&cs, &hash, 2, 1), op_return(SMALL, 3).as_bytes()[1..], "not punched");
    // Invalid, but its data is still served, through the record.
    assert_reads_as(&cs, &blocks[101]);
    assert_eq!(corrupt_warning(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_test_rpc_is_allowed_only_on_regtest() {
    let (cs, dir) = make_chain_state();
    assert!(!cs.test_strip_allowed());
    cs.allow_test_strip();
    assert!(cs.test_strip_allowed());
    let _ = std::fs::remove_dir_all(dir);

    let tmp = tempfile::TempDir::new().unwrap();
    let cs = ChainState::new(
        Box::new(crate::storage::db::InMemoryStore::new()),
        crate::storage::flatfile::FlatFileManager::new(&tmp.path().join("blocks")).unwrap(),
        Network::Signet,
        Box::new(crate::validation::script::NoopVerifier),
        crate::chain::state::AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    cs.allow_test_strip();
    assert!(!cs.test_strip_allowed());
}
