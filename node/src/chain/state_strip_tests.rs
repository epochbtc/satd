//! `ChainState::strip_block`: what it strips, what it refuses, and what it
//! does when the block moves under it.

use std::os::unix::fs::FileExt;

use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::{Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, transaction};

use super::super::tests::{build_test_block, grind_test_pow, make_chain_state};
use super::super::ChainError;
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

/// A repair that points the entry at a fresh copy between the plan and the
/// punch drops the record in its own batch. The strip's record lands after
/// it and describes the old copy, so it is removed again, and nothing is
/// punched. The repair needs a record to act (it leaves a readable intact
/// block alone), so this is an extension of a block stripped once. The hook
/// drives the append half directly: a full repair would restore this block
/// in place, which waits for the strip lock the strip holds.
#[test]
fn a_repoint_before_the_punch_leaves_no_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = blocks[101].clone();
    let hash = b.block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let old = cs.store.get_block_index(&hash).unwrap();
    let before = on_disk(&cs, &hash);
    *cs.strip.after_plan_hook.lock() = Some(Box::new(move |cs: &ChainState| {
        assert!(matches!(
            cs.repair_block_data_by_append(&b, 102).unwrap(),
            crate::chain::state::BlockDataRepair::Repaired { .. }
        ));
        assert!(record(cs, &b.block_hash()).is_none(), "the repair dropped the record");
    }));

    assert_eq!(cs.strip_block(&hash, SMALL as u64).unwrap(), StripOutcome::Raced);
    let now = cs.store.get_block_index(&hash).unwrap();
    assert_ne!((now.file_number, now.data_pos), (old.file_number, old.data_pos), "premise: moved");
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&blocks[101]));
    // Neither copy was punched by the extension.
    let at_old = {
        let path = cs.blocks_dir().join(format!("blk{:05}.dat", old.file_number));
        let mut data = vec![0u8; before.len()];
        std::fs::File::open(path).unwrap().read_exact_at(&mut data, u64::from(old.data_pos) + 8).unwrap();
        let key = cs.flat_files.lock().xor_key();
        crate::storage::flatfile::xor_in_place(&mut data, &key, u64::from(old.data_pos) + 8);
        data
    };
    assert_eq!(at_old, before);
    let _ = std::fs::remove_dir_all(dir);
}

/// A block whose entry changes in place between the plan and the punch
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
    // Mark it the way invalidateblock does. Not through invalidateblock: it
    // refuses to disconnect a block that already has a strip record (plan
    // §2.10), which the second case below needs.
    let invalidate = move |cs: &ChainState| {
        let _accept = cs.accept_lock.lock();
        cs.mark_subtree_invalid(hash).unwrap();
        assert_eq!(cs.store.get_block_index(&hash).unwrap().status, BlockStatus::Invalid);
    };

    // No prior record: none is left.
    *cs.strip.after_plan_hook.lock() = Some(Box::new(invalidate));
    let changes = cs.strip.changes.load(Ordering::Acquire);
    assert_eq!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Raced);
    assert_eq!(record(&cs, &hash), None);
    // The raced write counts as a change, as every record write does, so an
    // option-off pass counts again after it.
    assert_ne!(cs.strip.changes.load(Ordering::Acquire), changes, "the raced write was not counted as a change");
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().any(|x| *x != 0), "not punched");
    assert_eq!(cs.get_block(&hash).as_ref(), Some(&blocks[101]));
    let _ = std::fs::remove_dir_all(dir);

    // A prior record: it is put back, so its punched span still reads.
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    assert_eq!(blocks[101].block_hash(), hash);
    assert!(matches!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Stripped(_)));
    let prior = record(&cs, &hash);
    *cs.strip.after_plan_hook.lock() = Some(Box::new(invalidate));
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

/// An entry pointing at the wrong record is not stripped: the bytes there
/// are another block, which passes `check_block` on its own terms, so the
/// record would describe the wrong transactions.
#[test]
fn an_entry_pointing_at_another_block_is_refused() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let other = cs.store.get_block_index(&blocks[100].block_hash()).unwrap();
    let mut entry = cs.store.get_block_index(&hash).unwrap();
    entry.file_number = other.file_number;
    entry.data_pos = other.data_pos;
    cs.store
        .write_batch(StoreBatch {
            block_index_puts: vec![(hash, entry)],
            ..Default::default()
        })
        .unwrap();
    match cs.strip_block(&hash, 0) {
        Err(StripError::Corrupt { detail, .. }) => assert!(detail.contains("different block"), "{detail}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

/// A prune between the plan and the punch drops the record in its own
/// batch. The entry did not move, but its data is gone, so the record it
/// had before the call is not put back.
#[test]
fn a_prune_before_the_punch_leaves_no_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    assert!(record(&cs, &hash).is_some());
    *cs.strip.after_plan_hook.lock() = Some(Box::new(move |cs: &ChainState| {
        // What `prune_up_to` writes for the block.
        let mut entry = cs.store.get_block_index(&hash).unwrap();
        entry.status = BlockStatus::Pruned;
        cs.store
            .write_batch(StoreBatch {
                block_index_puts: vec![(hash, entry)],
                opreturn_strip_removes: vec![hash],
                ..Default::default()
            })
            .unwrap();
    }));
    assert_eq!(cs.strip_block(&hash, SMALL as u64).unwrap(), StripOutcome::Raced);
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

/// An extension takes the new transactions' txids and wtxids from their
/// bytes. The merkle root does not cover witnesses, but the old record's
/// filled hash covers every byte, so a witness gone bad on disk since the
/// first strip is refused.
#[test]
fn an_extension_refuses_bytes_changed_since_the_first_strip() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let mut witness_tx = spend(coinbase_of(&blocks[2]), vec![ScriptBuf::new(), op_return(SMALL, 4)]);
    witness_tx.input[0].witness = Witness::from_slice(&[vec![0xab; 40]]);
    let mut b = build_test_block(blocks[104].block_hash(), 106, time(106));
    b.txdata.push(spend(coinbase_of(&blocks[3]), vec![ScriptBuf::new(), op_return(BIG, 5)]));
    b.txdata.push(witness_tx);
    b.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    let root = b.witness_root().unwrap();
    let commitment = Block::compute_witness_commitment(&root, &[0u8; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    b.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    grind_test_pow(&mut b);
    connect(&cs, &b);
    let hash = b.block_hash();
    assert!(matches!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Stripped(_)));

    // A witness byte of tx 2, which the extension would record.
    let bytes = on_disk(&cs, &hash);
    let spans = tx_spans(&bytes).unwrap();
    let tx2 = &spans[2];
    let at = (tx2.offset..tx2.offset + tx2.len)
        .rev()
        .find(|i| bytes[*i] == 0xab)
        .expect("the witness item");
    write_on_disk(&cs, &hash, at, &[0xac]);
    match cs.strip_block(&hash, SMALL as u64) {
        Err(StripError::Corrupt { detail, .. }) => assert!(detail.contains("recorded hash"), "{detail}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(record(&cs, &hash).unwrap().txs.len(), 1, "the record is unchanged");
    let _ = std::fs::remove_dir_all(dir);
}

/// A reorg between the plan and the punch takes the block off the active
/// chain, still `Valid` and in place. It must not be stripped: a reorg back
/// would need its bytes.
#[test]
fn a_block_reorged_out_before_the_punch_is_not_stripped() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let fork_from = blocks[100].block_hash();
    *cs.strip.after_plan_hook.lock() = Some(Box::new(move |cs: &ChainState| {
        let mut parent = fork_from;
        for h in 102..=107 {
            let b = build_test_block(parent, h, time(h) + 1);
            cs.accept_block(&b).expect("accept fork block");
            parent = b.block_hash();
        }
        assert_eq!(cs.tip_hash(), parent, "premise: the fork is active");
        assert_eq!(cs.store.get_block_index(&hash).unwrap().status, BlockStatus::Valid);
    }));
    assert_eq!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Raced);
    assert_eq!(record(&cs, &hash), None);
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().any(|x| *x != 0), "not punched");
    let _ = std::fs::remove_dir_all(dir);
}

/// A chainstate whose blocks dir is obfuscated with a random `xor.dat` key,
/// as `-blocksxor=1` makes it.
fn make_xor_chain_state() -> (ChainState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "satd-strip-xor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let flat_files = crate::storage::flatfile::FlatFileManager::with_xor_mode(
        &dir.join("blocks"),
        crate::storage::flatfile::XorMode::Enabled,
    )
    .unwrap();
    assert_ne!(flat_files.xor_key(), [0; 8], "premise: a nonzero key");
    let cs = ChainState::new(
        Box::new(crate::storage::db::InMemoryStore::new()),
        flat_files,
        Network::Regtest,
        Box::new(crate::validation::script::NoopVerifier),
        crate::chain::state::AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    (cs, dir)
}

/// Under a blocks-dir xor key a punched span reads back as the key, not as
/// zeros. The strip still reads through its record, and a lost record is
/// still caught: the payload is recognised as punched and the merkle check
/// fails, rather than the block being served with txids computed from the
/// key bytes.
#[test]
fn under_a_blocks_xor_key_a_lost_record_is_still_caught() {
    let (cs, dir) = make_xor_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let key = cs.flat_files.lock().xor_key();
    let payload = payload_on_disk(&cs, &hash, 1, 1);
    assert!(payload.iter().any(|b| *b != 0), "premise: the punch decodes to the key, not zeros");
    assert!(
        (0..8).any(|p| payload.iter().enumerate().all(|(j, b)| *b == key[(p + j) % 8])),
        "premise: the punch decodes to the key"
    );
    assert_reads_as(&cs, &blocks[101]);

    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_removes: vec![hash],
            ..Default::default()
        })
        .unwrap();
    assert!(cs.get_stored_block(&hash).is_none(), "never served with wrong txids");
    assert!(cs.get_block(&hash).is_none());
    let warning = corrupt_warning(&cs, &hash).expect("the lost record is reported");
    assert!(warning.contains("lost strip record"), "{warning}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A prune that lands between the plan's index read and its read of the
/// bytes makes the read fail. That is a race, not corruption: no warning.
#[test]
fn a_prune_during_the_plan_is_a_race_not_corruption() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    *cs.strip.before_read_hook.lock() = Some(Box::new(move |cs: &ChainState| {
        // As a prune leaves it: the entry Pruned and the bytes gone. The
        // file is cut at this block rather than deleted, since an open read
        // handle would still see a deleted file.
        let mut entry = cs.store.get_block_index(&hash).unwrap();
        let path = cs.blocks_dir().join(format!("blk{:05}.dat", entry.file_number));
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(u64::from(entry.data_pos))
            .unwrap();
        entry.status = BlockStatus::Pruned;
        cs.store
            .write_batch(StoreBatch {
                block_index_puts: vec![(hash, entry)],
                ..Default::default()
            })
            .unwrap();
    }));
    assert_eq!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Raced);
    assert_eq!(corrupt_warning(&cs, &hash), None);
    assert_eq!(record(&cs, &hash), None);
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Replaying a stripped block (-reindex, -reindex-chainstate)
// ---------------------------------------------------------------------------

/// Clear the chainstate back to genesis, keeping the block index, as
/// `-reindex-chainstate` does, and plan the replay.
fn rewind(cs: &ChainState) -> crate::chain::replay_plan::ReplayPlan {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    cs.flush_coin_cache().unwrap();
    cs.store.flush().unwrap();
    cs.store.clear_chainstate().unwrap();
    cs.seed_genesis_chain_rows().unwrap();
    {
        let mut tip = cs.tip.write();
        tip.hash = genesis;
        tip.height = 0;
    }
    cs.mtp_cache.lock().clear();
    crate::chain::replay_plan::plan_replay_from_block_index(&*cs.store, genesis, None).unwrap()
}

fn prefetch(cs: &ChainState, plan: &crate::chain::replay_plan::ReplayPlan, height: u32) -> Option<crate::chain::prefetch::PreprocessedBlock> {
    crate::chain::prefetch::prefetch_block(
        &*cs.store,
        cs.blocks_dir(),
        &cs.blocks_xor_key,
        Some(plan),
        height,
        false,
        cs.primary_engine(),
        Network::Regtest,
        &std::sync::atomic::AtomicBool::new(false),
    )
}

/// Replace the record's txid for its first transaction, keeping its filled
/// hash: the record still fits the bytes, but names the wrong transaction.
fn misname_first_stripped_tx(cs: &ChainState, hash: &BlockHash) {
    let mut rec = record(cs, hash).unwrap();
    rec.txs[0].txid = bitcoin::Txid::from_byte_array([0x42; 32]);
    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_puts: vec![(*hash, rec.encode())],
            ..Default::default()
        })
        .unwrap();
}

/// A stripped block replays on both paths of `-reindex-chainstate`, the
/// direct read and the prefetched one, and its outputs land under the txids
/// its record holds. Each path is driven by hand: the prefetcher races the
/// connect cursor, so a whole replay cannot pick the path.
#[test]
fn both_replay_paths_connect_a_stripped_block_under_its_recorded_txids() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    let stripped = blocks[101].txdata[1].compute_txid();
    assert!(matches!(cs.strip_block(&hash, THRESHOLD).unwrap(), StripOutcome::Stripped(_)));
    assert_ne!(on_disk(&cs, &hash), bitcoin::consensus::serialize(&blocks[101]), "premise: punched");

    for prefetched in [false, true] {
        let plan = rewind(&cs);
        for height in 1..=105u32 {
            let planned = plan.hash_at(height).unwrap();
            if prefetched && height == 102 {
                let pre = prefetch(&cs, &plan, height).expect("the prefetcher reads a stripped block");
                assert_eq!(pre.txids[1], stripped, "the recorded txid");
                assert_eq!(pre.script_skip_txs, [1usize].into_iter().collect());
                assert!(!pre.script_verified_txs.contains(&1), "never pre-verified");
                cs.reindex_connect_prefetched(&plan, pre).unwrap();
            } else {
                cs.reindex_connect_direct(&plan, height, planned).unwrap();
            }
        }
        assert_eq!(cs.tip_hash(), blocks[104].block_hash(), "prefetched: {prefetched}");
        cs.flush_coin_cache().unwrap();
        assert!(
            cs.get_coin(&OutPoint { txid: stripped, vout: 0 }).is_some(),
            "the stripped tx's output, under its real txid (prefetched: {prefetched})"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A record that fits the bytes but names the wrong txid is never replayed:
/// the direct path stops with an error naming the remedy, and the
/// prefetcher hands the block to it.
#[test]
fn a_replay_stops_at_a_stripped_block_whose_record_misnames_a_tx() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    misname_first_stripped_tx(&cs, &hash);

    let plan = rewind(&cs);
    for height in 1..=101u32 {
        cs.reindex_connect_direct(&plan, height, plan.hash_at(height).unwrap()).unwrap();
    }
    assert!(prefetch(&cs, &plan, 102).is_none(), "deferred to the direct read");
    match cs.reindex_connect_direct(&plan, 102, hash) {
        Err(ChainError::FlatFile(msg)) => {
            assert!(msg.contains("strip record") && msg.contains("getblockfrompeer"), "{msg}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(cs.tip_hash(), blocks[100].block_hash(), "nothing connected");
    let _ = std::fs::remove_dir_all(dir);
}

/// The MTP window a replay starts from is read through the records too: a
/// stripped block there reads, and one with a bad record stops the replay.
#[test]
fn the_replay_mtp_window_reads_a_stripped_block_through_its_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let plan = crate::chain::replay_plan::plan_replay_from_block_index(
        &*cs.store,
        bitcoin::constants::genesis_block(Network::Regtest).block_hash(),
        None,
    )
    .unwrap();
    cs.verify_replay_mtp_window(&plan, 105).expect("the window reads");
    misname_first_stripped_tx(&cs, &hash);
    match cs.verify_replay_mtp_window(&plan, 105) {
        Err(ChainError::FlatFile(msg)) => assert!(msg.contains("strip record"), "{msg}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// `-reindex` indexes a stripped side-chain block through its record rather
/// than skipping it as a block that fails `check_block`.
#[test]
fn a_reindex_indexes_a_stripped_side_chain_block() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let entry = cs.store.get_block_index(&hash).unwrap();
    let pos = FlatFilePos { file_number: entry.file_number, data_pos: entry.data_pos };
    let headers = std::collections::HashMap::from([(
        hash,
        super::super::ReindexHeaderRef { header: entry.header, pos },
    )]);
    cs.index_reindex_side_chain(&[(hash, 102, [0u8; 32])], &headers).unwrap();
    let indexed = cs.store.get_block_index(&hash).unwrap();
    assert_eq!(indexed.status, BlockStatus::DataStored, "indexed, not skipped");
    assert_eq!(indexed.num_tx, 3);

    misname_first_stripped_tx(&cs, &hash);
    let mut valid = indexed;
    valid.status = BlockStatus::Valid;
    cs.store
        .write_batch(StoreBatch { block_index_puts: vec![(hash, valid)], ..Default::default() })
        .unwrap();
    cs.index_reindex_side_chain(&[(hash, 102, [0u8; 32])], &headers).unwrap();
    assert_eq!(
        cs.store.get_block_index(&hash).unwrap().status,
        BlockStatus::Valid,
        "a bad record is skipped, not indexed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A stripped block whose record was lost is a strip-record error on
/// replay, not a block that fails validation.
#[test]
fn a_replay_names_a_lost_strip_record() {
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
    let plan = rewind(&cs);
    for height in 1..=101u32 {
        cs.reindex_connect_direct(&plan, height, plan.hash_at(height).unwrap()).unwrap();
    }
    match cs.reindex_connect_direct(&plan, 102, hash) {
        Err(ChainError::FlatFile(msg)) => {
            assert!(msg.contains("strip record is missing") && msg.contains("-reindex"), "{msg}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The live chainstate audit reads a stripped block through its record: the
/// block is neither unreadable nor short of txindex rows, so a healthy chain
/// with a stripped block in the window is consistent (plan §2.8, PR 5e).
#[test]
fn the_chainstate_audit_reads_a_stripped_block_through_its_record() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    assert!(cs.verify_chainstate_default().is_consistent(), "premise: consistent before");
    cs.strip_block(&hash, THRESHOLD).unwrap();
    assert_eq!(cs.get_block(&hash), None, "premise: stripped");
    let report = cs.verify_chainstate_default();
    assert!(report.is_consistent(), "{}", report.describe());
    assert!(report.unreadable.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

/// `invalidate_block` waits for a strip in progress: a strip commits its
/// record before `accept_lock`, so only the strip lock keeps a record from
/// landing between invalidate's stripped-block check and its marks.
#[test]
fn invalidate_block_waits_for_a_strip_in_progress() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let cs = std::sync::Arc::new(cs);
    let tip = blocks.last().unwrap().block_hash();
    let held = cs.strip.lock.lock();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = {
        let cs = cs.clone();
        std::thread::spawn(move || {
            let r = cs.invalidate_block(tip);
            done_tx.send(()).unwrap();
            r
        })
    };
    assert!(
        done_rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
        "invalidate_block ran while a strip held the lock"
    );
    drop(held);
    done_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("it runs once the strip is done");
    worker.join().unwrap().expect("invalidate");
    assert_eq!(cs.store.get_block_index(&tip).unwrap().status, BlockStatus::Invalid);
    let _ = std::fs::remove_dir_all(dir);
}

/// `getblockfrompeer`'s repair of a stripped block restores it in place
/// (plan §2.12): the entry keeps its position, nothing is appended, the
/// payload is back on disk, the record is gone, and the block reads intact.
#[test]
fn a_repair_restores_a_stripped_block_in_place() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    assert!(payload_on_disk(&cs, &hash, 1, 1).iter().all(|x| *x == 0), "premise: punched");
    let entry = cs.store.get_block_index(&hash).unwrap();
    let file = cs.blocks_dir().join(format!("blk{:05}.dat", entry.file_number));
    let len = std::fs::metadata(&file).unwrap().len();

    assert!(matches!(cs.repair_block_data(b).unwrap(), crate::chain::state::BlockDataRepair::Repaired { .. }));
    let now = cs.store.get_block_index(&hash).unwrap();
    assert_eq!((now.file_number, now.data_pos), (entry.file_number, entry.data_pos), "in place");
    assert_eq!(std::fs::metadata(&file).unwrap().len(), len, "nothing appended");
    assert_eq!(payload_on_disk(&cs, &hash, 1, 1), op_return(BIG, 1).as_bytes()[1..], "the payload is back");
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(b));
    assert_eq!(corrupt_warning(&cs, &hash), None);
    // A repeat finds the block readable and writes nothing.
    assert!(matches!(
        cs.repair_block_data(b).unwrap(),
        crate::chain::state::BlockDataRepair::AlreadyPresent { .. }
    ));
    let _ = std::fs::remove_dir_all(dir);
}

/// A record that does not describe the peer's copy is never trusted to place
/// it: the repair appends a copy as for any damaged block, and the record goes
/// with the old one.
#[test]
fn a_repair_appends_when_the_record_does_not_describe_the_block() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    let entry = cs.store.get_block_index(&hash).unwrap();
    // A record that decodes but whose filled hash is not this block's.
    let mut wrong = record(&cs, &hash).unwrap();
    wrong.filled_sha256[0] ^= 1;
    cs.store
        .write_batch(StoreBatch { opreturn_strip_puts: vec![(hash, wrong.encode())], ..Default::default() })
        .unwrap();

    assert!(matches!(cs.repair_block_data(b).unwrap(), crate::chain::state::BlockDataRepair::Repaired { .. }));
    let now = cs.store.get_block_index(&hash).unwrap();
    assert_ne!((now.file_number, now.data_pos), (entry.file_number, entry.data_pos), "appended");
    assert_eq!(record(&cs, &hash), None);
    assert_eq!(cs.get_block(&hash).as_ref(), Some(b));
    let _ = std::fs::remove_dir_all(dir);
}

/// The in-place restore waits for a strip in progress: a redo, which writes no
/// record, would otherwise punch bytes whose record the restore had removed.
#[test]
fn an_in_place_restore_waits_for_a_strip_in_progress() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = blocks[101].clone();
    cs.strip_block(&b.block_hash(), THRESHOLD).unwrap();
    let cs = std::sync::Arc::new(cs);
    let held = cs.strip.lock.lock();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = {
        let cs = cs.clone();
        std::thread::spawn(move || {
            let r = cs.repair_block_data(&b).map(|_| ());
            done_tx.send(()).unwrap();
            r
        })
    };
    assert!(
        done_rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
        "the restore ran while a strip held the lock"
    );
    drop(held);
    done_rx.recv_timeout(std::time::Duration::from_secs(10)).expect("it runs once the strip is done");
    worker.join().unwrap().expect("restore");
    assert_eq!(record(&cs, &blocks[101].block_hash()), None);
    let _ = std::fs::remove_dir_all(dir);
}

fn pass(cs: &ChainState, max_blocks: u32) -> PassReport {
    cs.strip_pass(max_blocks, &std::sync::atomic::AtomicBool::new(false)).unwrap()
}

/// The worker strips only below `tip - depth - 2`: a block a limited peer
/// may still ask for keeps its bytes.
#[test]
fn a_pass_strips_only_below_tip_minus_depth_minus_two() {
    let (cs, dir) = make_chain_state();
    let mut blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.configure_opreturn_prune(StripConfig {
        depth: 1,
        size_threshold: THRESHOLD,
    });

    // Tip 105, depth 1: heights up to 101 only.
    let r = pass(&cs, 1000);
    assert_eq!((r.examined, r.stripped, r.more), (102, 0, false));
    assert_eq!(record(&cs, &hash), None, "102 is not yet deep enough");
    assert_eq!(cs.opreturn_strip_meta().unwrap().next_height, 102);

    let b = build_test_block(blocks.last().unwrap().block_hash(), 106, time(106));
    connect(&cs, &b);
    blocks.push(b);
    let r = pass(&cs, 1000);
    assert_eq!((r.examined, r.stripped), (1, 1));
    assert!(record(&cs, &hash).is_some());
    // The pass added the totals up for `getblockchaininfo`, which never
    // reads the store itself.
    assert_eq!(cs.opreturn_strip_summary_last().blocks, 1);
    assert_reads_as(&cs, &blocks[101]);
    let s = cs.opreturn_strip_summary().unwrap();
    assert_eq!((s.blocks, s.transactions, s.outputs), (1, 1, 1));
    assert!(cs.opreturn_prune_active());
    let _ = std::fs::remove_dir_all(dir);
}

/// The cursor carries a pass on where the last one stopped, and a lower
/// threshold than the one it was reached under starts the scan over.
#[test]
fn a_lowered_threshold_rescans_from_the_bottom() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.configure_opreturn_prune(StripConfig {
        depth: 0,
        size_threshold: THRESHOLD,
    });
    let at = |next_height: u32, size_threshold| opreturn_strip::StripMeta {
        next_height,
        size_threshold,
        depth: 0,
        last_hash: cs.active_chain_hash_at_height_indexed(next_height - 1),
    };

    // A pass at most 10 blocks long stops with more to do.
    let r = pass(&cs, 10);
    assert_eq!((r.examined, r.more), (10, true));
    assert_eq!(cs.opreturn_strip_meta(), Some(at(10, THRESHOLD)));

    // Past 102 under the same threshold: nothing to do there again.
    cs.write_strip_meta(&at(103, THRESHOLD)).unwrap();
    assert_eq!(pass(&cs, 1000).stripped, 0);
    assert_eq!(record(&cs, &hash), None);

    // Past 102 under a higher one: 102 was never examined at 4096.
    cs.write_strip_meta(&at(103, 2 * THRESHOLD)).unwrap();
    let r = pass(&cs, 1000);
    assert_eq!((r.examined, r.stripped), (103, 1));
    assert!(record(&cs, &hash).is_some());
    assert_eq!(cs.opreturn_strip_meta(), Some(at(103, THRESHOLD)));
    let _ = std::fs::remove_dir_all(dir);
}

/// Off, the worker does nothing and says so.
#[test]
fn a_pass_without_the_option_does_nothing() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    assert_eq!(pass(&cs, 1000), PassReport::default());
    assert_eq!(cs.opreturn_strip_worker_status(), WorkerStatus::Off);
    assert_eq!(record(&cs, &blocks[101].block_hash()), None);
    assert!(!cs.opreturn_prune_active());
    let _ = std::fs::remove_dir_all(dir);
}

/// A record that does not read back still marks the node as holding
/// stripped blocks: its block is stripped on disk either way.
#[test]
fn an_unreadable_record_still_counts_as_stripped() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_puts: vec![(blocks[101].block_hash(), vec![0xff, 0x00])],
            ..Default::default()
        })
        .unwrap();
    cs.load_opreturn_strip_state().unwrap();
    assert!(cs.opreturn_prune_active());
    assert_eq!(cs.opreturn_strip_summary().unwrap().blocks, 0, "not counted in the totals");
    let _ = std::fs::remove_dir_all(dir);
}

/// A reorg that replaces blocks below the cursor, none of them stripped,
/// moves the cursor back to the fork: the blocks now at those heights are
/// examined, and a large OP_RETURN in one of them is stripped.
#[test]
fn a_reorg_below_the_cursor_rescans_from_the_fork() {
    let (cs, dir) = make_chain_state();
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut a = Vec::new();
    for h in 1..=104 {
        let b = build_test_block(a.last().map_or(genesis, Block::block_hash), h, time(h));
        connect(&cs, &b);
        a.push(b);
    }
    cs.configure_opreturn_prune(StripConfig {
        depth: 0,
        size_threshold: THRESHOLD,
    });
    // Tip 104: heights up to 101 examined, nothing to strip.
    assert_eq!(pass(&cs, 1000).examined, 102);
    assert_eq!(cs.opreturn_strip_meta().unwrap().last_hash, Some(a[100].block_hash()));

    // A heavier branch from 100 replaces 101 to 104; its 101 carries a large
    // OP_RETURN.
    let mut b = vec![block_on(
        a[99].block_hash(),
        101,
        vec![spend(coinbase_of(&a[0]), vec![ScriptBuf::new(), op_return(BIG, 1)])],
    )];
    for h in 102..=106 {
        b.push(build_test_block(b.last().unwrap().block_hash(), h, time(h) + 1));
    }
    for blk in &b {
        cs.accept_block(blk).expect("accept");
    }
    assert_eq!(cs.tip_hash(), b[5].block_hash(), "premise: the branch is active");

    // Tip 106: the pass goes back to 101, examines 101 to 103, strips 101.
    let r = pass(&cs, 1000);
    assert_eq!((r.examined, r.stripped), (3, 1));
    assert!(record(&cs, &b[0].block_hash()).is_some());
    assert_eq!(cs.opreturn_strip_meta().unwrap().last_hash, Some(b[2].block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// A record removed by another write (here the append repair; `-prune` and a
/// fresh full copy go the same way) drops the cached totals, and the
/// worker's pass adds them up again even with the option off, so
/// `getblockchaininfo` and `/metrics` stop counting it.
#[test]
fn a_record_removed_elsewhere_leaves_the_totals_after_the_next_pass() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    let hash = b.block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    assert_eq!(cs.opreturn_strip_summary_last().blocks, 1);
    // A record that does not describe the block, so the repair appends.
    let mut wrong = record(&cs, &hash).unwrap();
    wrong.filled_sha256[0] ^= 1;
    cs.store
        .write_batch(StoreBatch { opreturn_strip_puts: vec![(hash, wrong.encode())], ..Default::default() })
        .unwrap();
    cs.repair_block_data(b).unwrap();
    assert_eq!(record(&cs, &hash), None, "premise: the append removed the record");

    assert_eq!(pass(&cs, 1000), PassReport::default(), "the option is off");
    assert_eq!(cs.opreturn_strip_summary_last().blocks, 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// With the option off, restoring the last stripped block finishes the job
/// (plan §11.5) at the worker's next pass: the node is no longer stripping,
/// so it advertises `NODE_NETWORK` again, and the strip family is gone.
#[test]
fn restoring_the_last_stripped_block_with_the_option_off_finishes() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    cs.strip_block(&b.block_hash(), THRESHOLD).unwrap();
    // A cursor left from when the option was on.
    let meta = opreturn_strip::StripMeta {
        next_height: 103,
        size_threshold: THRESHOLD,
        depth: 0,
        last_hash: None,
    };
    cs.write_strip_meta(&meta).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    assert!(cs.opreturn_prune_active(), "premise: a stripped block keeps the node limited");
    assert_eq!(cs.opreturn_strip_meta(), Some(meta), "premise: a record keeps the family");

    cs.repair_block_data(b).unwrap();
    assert_eq!(record(&cs, &b.block_hash()), None, "premise: restored");
    assert!(cs.opreturn_prune_active(), "until the worker's pass");
    assert_eq!(pass(&cs, 1000), PassReport::default());
    assert!(!cs.opreturn_prune_active());
    assert_eq!(cs.opreturn_strip_summary_last().blocks, 0);
    assert!(!cs.holds_strip_record(&b.block_hash()));
    assert_eq!(cs.opreturn_strip_meta(), None, "the strip family is dropped, cursor and all");
    let _ = std::fs::remove_dir_all(dir);
}

/// A record left, or the option on, and the pass finishes nothing.
#[test]
fn a_record_left_or_the_option_on_keeps_the_node_stripping() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = &blocks[101];
    cs.strip_block(&b.block_hash(), THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    cs.forget_strip_summary();
    assert_eq!(pass(&cs, 1000), PassReport::default());
    assert!(cs.opreturn_prune_active(), "a record is left");
    assert!(record(&cs, &b.block_hash()).is_some());
    // The finish rechecks under the strip lock: a record written between the
    // pass's count and the lock keeps the family.
    assert!(!cs.finish_opreturn_unstrip().unwrap());
    assert!(record(&cs, &b.block_hash()).is_some());
    assert!(cs.opreturn_prune_active());

    cs.configure_opreturn_prune(StripConfig {
        depth: 0,
        size_threshold: THRESHOLD,
    });
    cs.repair_block_data(b).unwrap();
    pass(&cs, 1000);
    assert!(cs.opreturn_prune_active(), "the option is on");
    assert!(cs.opreturn_strip_meta().is_some(), "and its cursor is kept");
    let _ = std::fs::remove_dir_all(dir);
}

/// At startup with the option off and no record, the family goes: a drop a
/// crash interrupted, or a datadir that only ever held the worker's cursor.
/// With the option on, the cursor stays.
#[test]
fn startup_drops_an_empty_strip_family_only_with_the_option_off() {
    let meta = opreturn_strip::StripMeta {
        next_height: 50,
        size_threshold: THRESHOLD,
        depth: 288,
        last_hash: None,
    };
    let (cs, dir) = make_chain_state();
    chain(&cs);
    cs.write_strip_meta(&meta).unwrap();
    cs.configure_opreturn_prune(StripConfig {
        depth: 288,
        size_threshold: THRESHOLD,
    });
    cs.load_opreturn_strip_state().unwrap();
    assert_eq!(cs.opreturn_strip_meta(), Some(meta), "the option is on");
    let _ = std::fs::remove_dir_all(dir);

    let (cs, dir) = make_chain_state();
    chain(&cs);
    cs.write_strip_meta(&meta).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    assert_eq!(cs.opreturn_strip_meta(), None);
    assert!(!cs.opreturn_prune_active());
    let _ = std::fs::remove_dir_all(dir);
}

/// The worker stops once nothing is stripped and the option is off, rather
/// than idling for the life of the node.
#[test]
fn the_worker_stops_when_nothing_is_left_to_count() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    let b = blocks[101].clone();
    cs.strip_block(&b.block_hash(), THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    cs.repair_block_data(&b).unwrap();
    let cs = std::sync::Arc::new(cs);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = {
        let (cs, stop) = (cs.clone(), stop.clone());
        std::thread::spawn(move || {
            run_strip_worker(cs, stop);
            done_tx.send(()).unwrap();
        })
    };
    let finished = done_rx.recv_timeout(std::time::Duration::from_secs(10));
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(finished.is_ok(), "the worker kept running with nothing to do");
    assert!(!cs.opreturn_prune_active());
    let _ = std::fs::remove_dir_all(dir);
}

/// The last record's remove can ride a coin batch, and wait in the coin cache
/// for a flush. The pass after it must flush before it counts: a count of the
/// store behind the cache would still find the record, and nothing would
/// make a later pass count again.
#[test]
fn a_remove_waiting_in_the_coin_cache_still_finishes() {
    let store = crate::storage::coin_cache::CoinCache::new(Box::new(crate::storage::db::InMemoryStore::new()), 10);
    let (cs, dir) = super::super::tests::make_chain_state_with_store(Box::new(store));
    let blocks = chain(&cs);
    let hash = blocks[101].block_hash();
    cs.strip_block(&hash, THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    pass(&cs, 1000);
    assert!(cs.opreturn_prune_active(), "premise: a record is left");

    // As a connect removes it: in a batch with coins, then the totals dropped.
    cs.store
        .write_batch(StoreBatch {
            coin_puts: vec![(
                OutPoint { txid: <bitcoin::Txid as bitcoin::hashes::Hash>::from_byte_array([7; 32]), vout: 0 },
                crate::storage::coinview::Coin {
                    amount: 1,
                    script_pubkey: ScriptBuf::new(),
                    height: 1,
                    coinbase: false,
                    txseq: node_index::TXSEQ_UNKNOWN,
                },
            )],
            opreturn_strip_removes: vec![hash],
            ..Default::default()
        })
        .unwrap();
    cs.forget_strip_summary();
    let mut seen = 0;
    cs.store.for_each_opreturn_strip(&mut |_, _| seen += 1).unwrap();
    assert_eq!(seen, 1, "premise: the remove waits in the cache");

    pass(&cs, 1000);
    assert!(!cs.opreturn_prune_active(), "the pass counted the store behind the cache");
    let _ = std::fs::remove_dir_all(dir);
}

/// With nothing changed since its last count, a pass neither flushes nor
/// counts again: on a node with stripped blocks left and the option off, that
/// would be a durability flush and a full read of the records every minute.
#[test]
fn an_idle_pass_does_not_count_again() {
    let (cs, dir) = make_chain_state();
    let blocks = chain(&cs);
    cs.strip_block(&blocks[101].block_hash(), THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    pass(&cs, 1000);
    let counted_at = cs.strip.summary.lock().unwrap().0;
    pass(&cs, 1000);
    assert_eq!(cs.strip.summary.lock().unwrap().0, counted_at, "an idle pass counted again");
    cs.forget_strip_summary();
    pass(&cs, 1000);
    assert!(cs.strip.summary.lock().is_some(), "a change is counted on the next pass");
    let _ = std::fs::remove_dir_all(dir);
}

/// A finish that fails (here the family drop) is retried by the next pass,
/// though nothing has changed since: no later change would come to prompt
/// one, and the node would stay limited until a restart.
#[test]
fn a_failed_finish_is_retried_by_the_next_pass() {
    let store = crate::storage::test_store::ControllableStore::new();
    let controls = store.controls();
    let (cs, dir) = super::super::tests::make_chain_state_with_store(Box::new(store));
    let blocks = chain(&cs);
    let b = &blocks[101];
    cs.strip_block(&b.block_hash(), THRESHOLD).unwrap();
    cs.load_opreturn_strip_state().unwrap();
    cs.repair_block_data(b).unwrap();
    controls.fail_next_strip_drop();
    assert!(cs.strip_pass(1000, &std::sync::atomic::AtomicBool::new(false)).is_err(), "premise: the finish failed");
    assert!(cs.opreturn_prune_active());
    pass(&cs, 1000);
    assert!(!cs.opreturn_prune_active(), "the failed finish was never retried");
    let _ = std::fs::remove_dir_all(dir);
}

/// The restore's work list (plan §11.4): every record whose block is still
/// stored, by height, newest first on a pruning node (R-6), each with the
/// stored block's length. A record whose block is gone is left out.
#[test]
fn the_restore_work_list_is_the_stored_records_in_height_order() {
    let (cs, _dir) = make_chain_state();
    let blocks = chain(&cs);
    let pick = [blocks[40].block_hash(), blocks[5].block_hash(), blocks[90].block_hash()];
    let unknown = BlockHash::from_byte_array([7; 32]);
    let mut puts: Vec<(BlockHash, Vec<u8>)> = pick.iter().map(|h| (*h, vec![1])).collect();
    puts.push((unknown, vec![1]));
    cs.store
        .write_batch(StoreBatch {
            opreturn_strip_puts: puts,
            ..Default::default()
        })
        .unwrap();

    let heights = |work: &[RestoreItem]| work.iter().map(|i| i.height).collect::<Vec<_>>();
    let ascending = cs.opreturn_restore_work(false).unwrap();
    assert_eq!(heights(&ascending), vec![6, 41, 91], "the unknown block is left out");
    assert_eq!(heights(&cs.opreturn_restore_work(true).unwrap()), vec![91, 41, 6]);
    for item in &ascending {
        let block = blocks.iter().find(|b| b.block_hash() == item.hash).unwrap();
        assert_eq!(item.len, serialize(block).len() as u64, "the stored length");
    }
}

/// The restore waits for the tip (plan §11.4, R-3): during IBD, and while
/// the best header is ahead of the tip; not on a node at its best header.
#[test]
fn the_restore_waits_while_the_tip_is_behind() {
    let (cs, dir) = make_chain_state();
    assert_eq!(cs.opreturn_restore_held_by_tip(), Some("initial block download"));
    let blocks = chain(&cs);
    assert_eq!(cs.opreturn_restore_held_by_tip(), None, "caught up");
    let tip = blocks.last().unwrap();
    let next = block_on(tip.block_hash(), 106, Vec::new());
    cs.accept_header(&next.header).expect("header");
    assert_eq!(cs.opreturn_restore_held_by_tip(), Some("the tip is behind the best header"));
    connect(&cs, &next);
    assert_eq!(cs.opreturn_restore_held_by_tip(), None);
    let _ = std::fs::remove_dir_all(dir);
}
