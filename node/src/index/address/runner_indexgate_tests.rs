//! The address backfill's reorg cleanup and the live connect path share
//! keys. A replacement block on the same parent numbers its transactions
//! from the same ordinal, so a transaction re-mined at the same position, or
//! any output paying the same script at the same position, produces exactly
//! the key the displaced block's row had. By the time the cleanup runs the
//! live path has removed the displaced block's rows and written the
//! replacement's, so removing every key the displaced block could have
//! produced deletes live rows: a history entry disappears and an output that
//! is spent reads as unspent.
//!
//! The cleanup now removes only keys the active chain does not own.

use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::hashes::Hash as _;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, Block, Network, OutPoint, ScriptBuf, TxOut};

use crate::chain::state::tests::{build_test_block, build_test_block_spending};
use crate::chain::state::{AssumeValid, ChainState};
use crate::index::address::backfill::{BackfillError, BackfillHandle};
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::cursor::{BackfillCursor, BackfillState};
use crate::index::address::keys::{AddrFundingRowV3, scripthash_of};
use crate::index::address::runner::BackfillRunner;
use crate::storage::flatfile::FlatFileManager;
use crate::storage::rocksdb_store::RocksDbStore;
use crate::storage::{Store, StoreBatch};
use crate::validation::script::NoopVerifier;

const BASE: u32 = 1_707_200_000;

fn chain_with_address_index(dir: &std::path::Path) -> ChainState {
    chain(dir, true)
}

fn chain(dir: &std::path::Path, live_address_index: bool) -> ChainState {
    let store = RocksDbStore::open(dir, false, 16, false, -1).unwrap();
    ChainState::new(
        Box::new(store),
        FlatFileManager::new(&dir.join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        16,
        2,
        AddressIndexConfig {
            enabled: live_address_index,
            ..Default::default()
        },
        Default::default(),
        Default::default(),
    )
    .unwrap()
}

/// Recompute the merkle root and find a nonce for regtest's target.
fn remine(block: &mut Block) {
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = block.header.target();
    for nonce in 0u32.. {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            return;
        }
    }
}

fn op_return_script() -> ScriptBuf {
    ScriptBuf::builder()
        .push_opcode(OP_RETURN)
        .push_slice([0xde, 0xad])
        .into_script()
}

/// Connect `n` coinbase-only blocks on genesis.
fn connect_chain(cs: &ChainState, n: u32) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    (1..=n)
        .map(|h| {
            let b = build_test_block(parent, h, BASE + 600 * h);
            cs.accept_block(&b).expect("fixture block connects");
            parent = b.block_hash();
            b
        })
        .collect()
}

fn funding_heights(cs: &ChainState, sh: &[u8; 32]) -> Vec<(u32, bitcoin::Txid, u32)> {
    cs.store_ref()
        .iter_addr_funding(sh)
        .into_iter()
        .map(|(k, _)| (k.height, k.txid, k.vout))
        .collect()
}

/// ```text
///   1 .. 101 - A102            (A102: coinbase + OP_RETURN, and tx S)
///          \
///           B102 - B103        (B102: another coinbase, and the same tx S)
/// ```
/// S spends block 1's coinbase. A backfill finished pass 2 with A102 as its
/// anchor, and the reorg to B103 then invalidated it.
///
/// Fails without the fix: the cleanup removed B102's coinbase funding row,
/// S's funding row, S's spending row and S's spend-index row, all of which
/// B102 owns under the same keys.
#[test]
fn reorg_cleanup_keeps_the_rows_the_active_chain_owns() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain_with_address_index(dir.path());
    let chain = connect_chain(&cs, 101);
    let parent = chain[100].block_hash();
    let coinbase_1 = OutPoint {
        txid: chain[0].txdata[0].compute_txid(),
        vout: 0,
    };

    let mut a102 = build_test_block_spending(parent, 102, BASE + 100_000, coinbase_1);
    a102.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script(),
    });
    remine(&mut a102);
    let b102 = build_test_block_spending(parent, 102, BASE + 200_000, coinbase_1);
    let b103 = build_test_block(b102.block_hash(), 103, BASE + 200_600);
    let spend_tx = a102.txdata[1].compute_txid();
    assert_eq!(spend_tx, b102.txdata[1].compute_txid(), "S is re-mined unchanged");
    assert_ne!(a102.block_hash(), b102.block_hash());

    cs.accept_block(&a102).expect("A102 connects");
    assert_eq!(cs.tip_hash(), a102.block_hash());

    // What a backfill run over this chain wrote beyond the live rows: the
    // funding row for A102's OP_RETURN output (which a pass 1 from before
    // it skipped unspendable outputs wrote, and a reorg must still clear),
    // and the pass-1 lookup row pass 2 used for S.
    let store = cs.store_ref();
    // The live rows are on disk before the backfill's, as they would be
    // for any block older than one flush window.
    store.flush().unwrap();
    let sh_empty = scripthash_of(&ScriptBuf::new());
    let sh_op_return = scripthash_of(&op_return_script());
    let a102_first_txseq = store
        .get_cumulative_tx_count(&parent)
        .expect("ordinal base of A102");
    store.create_backfill_temp_cf().unwrap();
    let mut planted = StoreBatch::default();
    planted.addr_funding_puts.push(AddrFundingRowV3 {
        scripthash: sh_op_return,
        txseq: a102_first_txseq,
        vout: 1,
        amount_sat: 0,
    });
    planted.addr_backfill_temp_puts.push((coinbase_1, sh_empty, 1));
    store.write_batch(planted).unwrap();
    assert_eq!(funding_heights(&cs, &sh_op_return).len(), 1);

    let handle = BackfillHandle::new(BackfillCursor {
        state: BackfillState::Running,
        pass: 2,
        cursor_height: 102,
        snapshot_height: 102,
        started_at_unix: 1,
        snapshot_tip_hash: a102.block_hash().to_byte_array(),
    });

    // The reorg. B102 alone ties A102 on work; B103 wins.
    cs.accept_block(&b102).expect("B102 stored");
    cs.accept_block(&b103).expect("B103 reorgs");
    assert_eq!(cs.tip_hash(), b103.block_hash());
    store.flush().unwrap();

    let b102_coinbase = b102.txdata[0].compute_txid();
    let before = funding_heights(&cs, &sh_empty);
    assert!(before.contains(&(102, b102_coinbase, 0)));
    assert!(before.contains(&(102, spend_tx, 0)));

    BackfillRunner::cleanup_stale_rows_after_reorg(&cs, &handle).expect("cleanup runs");

    let after = funding_heights(&cs, &sh_empty);
    assert!(
        after.contains(&(102, b102_coinbase, 0)),
        "the cleanup removed B102's coinbase funding row: {after:?}"
    );
    assert!(
        after.contains(&(102, spend_tx, 0)),
        "the cleanup removed the funding row of S, which B102 re-mined: {after:?}"
    );
    let spending: Vec<(u32, bitcoin::Txid)> = store
        .iter_addr_spending(&sh_empty)
        .into_iter()
        .map(|(k, _)| (k.height, k.txid))
        .collect();
    assert!(
        spending.contains(&(102, spend_tx)),
        "the cleanup removed S's spending row: {spending:?}"
    );
    let spend = store.lookup_spend(&coinbase_1).unwrap();
    assert_eq!(
        spend.map(|s| (s.spending_txid, s.height)),
        Some((spend_tx, 102)),
        "the cleanup removed S's spend-index row, so block 1's coinbase reads as unspent"
    );

    // What only the displaced block owned is still removed.
    assert!(
        funding_heights(&cs, &sh_op_return).is_empty(),
        "the displaced block's OP_RETURN row must be removed"
    );
    drop(dir);
}

/// No reorg: the anchor is still active, so the cleanup touches nothing.
#[test]
fn reorg_cleanup_with_nothing_divergent_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain_with_address_index(dir.path());
    let chain = connect_chain(&cs, 3);
    let tip = chain[2].block_hash();
    cs.store_ref().flush().unwrap();
    let sh_empty = scripthash_of(&ScriptBuf::new());
    let before = funding_heights(&cs, &sh_empty);
    assert_eq!(before.len(), 3);

    let handle = BackfillHandle::new(BackfillCursor {
        state: BackfillState::Running,
        pass: 2,
        cursor_height: 3,
        snapshot_height: 3,
        started_at_unix: 1,
        snapshot_tip_hash: tip.to_byte_array(),
    });
    let r: Result<(), BackfillError> = BackfillRunner::cleanup_stale_rows_after_reorg(&cs, &handle);
    r.unwrap();
    assert_eq!(funding_heights(&cs, &sh_empty), before);
}

/// The backfill writes rows only under `accept_lock`: while another thread
/// holds the lock (as every reorg does for its whole length), no row lands.
///
/// Fails without the fix: the runner wrote rows while the lock was held.
#[test]
fn the_backfill_writes_rows_only_under_accept_lock() {
    let dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(chain(dir.path(), false));
    let blocks = connect_chain(&cs, 5);
    cs.store_ref().flush().unwrap();
    let sh_empty = scripthash_of(&ScriptBuf::new());
    assert!(funding_heights(&cs, &sh_empty).is_empty(), "the live path writes no rows here");

    cs.store_ref().create_backfill_temp_cf().unwrap();
    let handle = Arc::new(BackfillHandle::new(BackfillCursor {
        state: BackfillState::Running,
        pass: 1,
        cursor_height: 0,
        snapshot_height: 5,
        started_at_unix: 1,
        snapshot_tip_hash: blocks[4].block_hash().to_byte_array(),
    }));
    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let runner = BackfillRunner {
        handle: handle.clone(),
        chain: cs.clone(),
        cfg: AddressIndexConfig {
            enabled: true,
            ..Default::default()
        },
        shutdown,
    };

    let held = cs.hold_accept_lock_for_test();
    let walk = std::thread::spawn(move || runner.run());
    std::thread::sleep(Duration::from_millis(300));
    let written_while_held = funding_heights(&cs, &sh_empty);
    drop(held);
    walk.join().unwrap().expect("the backfill completes");
    cs.store_ref().flush().unwrap();

    assert!(
        written_while_held.is_empty(),
        "rows written while accept_lock was held: {written_while_held:?}"
    );
    assert_eq!(funding_heights(&cs, &sh_empty).len(), 5, "every row written afterwards");
    assert_eq!(handle.cursor().state, BackfillState::Completed);
}

/// Run a backfill over `cs` from genesis to `tip` (at `height`) and wait
/// for it to complete.
fn run_backfill(cs: &Arc<ChainState>, tip: &Block, height: u32) {
    cs.store_ref().create_backfill_temp_cf().unwrap();
    let handle = Arc::new(BackfillHandle::new(BackfillCursor {
        state: BackfillState::Running,
        pass: 1,
        cursor_height: 0,
        snapshot_height: height,
        started_at_unix: 1,
        snapshot_tip_hash: tip.block_hash().to_byte_array(),
    }));
    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let runner = BackfillRunner {
        handle: handle.clone(),
        chain: cs.clone(),
        cfg: AddressIndexConfig {
            enabled: true,
            ..Default::default()
        },
        shutdown,
    };
    runner.run().expect("the backfill completes");
    cs.store_ref().flush().unwrap();
    assert_eq!(handle.cursor().state, BackfillState::Completed);
}

/// A backfill indexes what the live path indexes. Block 102 carries both
/// kinds of unspendable output: an OP_RETURN on a spending transaction and
/// a script over Core's `MAX_SCRIPT_SIZE` (10,000 bytes) on the coinbase. The live path writes no
/// row for either, so the backfill must not.
///
/// Fails without the fix: pass 1 wrote funding rows for both, so a
/// scripthash query on either script found an unspent output that a node
/// indexed live does not have.
#[test]
fn the_backfill_skips_unspendable_outputs_as_the_live_path_does() {
    let live_dir = tempfile::tempdir().unwrap();
    let backfill_dir = tempfile::tempdir().unwrap();
    let live = chain_with_address_index(live_dir.path());
    let backfilled = Arc::new(chain(backfill_dir.path(), false));

    let mut blocks = connect_chain(&live, 101);
    for b in &blocks {
        backfilled.accept_block(b).expect("fixture block connects");
    }
    let coinbase_1 = OutPoint {
        txid: blocks[0].txdata[0].compute_txid(),
        vout: 0,
    };
    let oversized = ScriptBuf::from_bytes(vec![0x51; 10_001]);
    let mut b102 = build_test_block_spending(blocks[100].block_hash(), 102, BASE + 100_000, coinbase_1);
    b102.txdata[1].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script(),
    });
    b102.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: oversized.clone(),
    });
    remine(&mut b102);
    live.accept_block(&b102).expect("B102 connects");
    backfilled.accept_block(&b102).expect("B102 connects");
    blocks.push(b102);
    live.store_ref().flush().unwrap();

    run_backfill(&backfilled, &blocks[101], 102);

    let sh_empty = scripthash_of(&ScriptBuf::new());
    let sh_op_return = scripthash_of(&op_return_script());
    let sh_oversized = scripthash_of(&oversized);
    assert!(
        funding_heights(&backfilled, &sh_op_return).is_empty(),
        "the backfill indexed an OP_RETURN output"
    );
    assert!(
        funding_heights(&backfilled, &sh_oversized).is_empty(),
        "the backfill indexed an output over MAX_SCRIPT_SIZE"
    );
    assert!(funding_heights(&live, &sh_op_return).is_empty());
    assert!(funding_heights(&live, &sh_oversized).is_empty());

    // Everything spendable is indexed the same both ways.
    assert_eq!(funding_heights(&backfilled, &sh_empty), funding_heights(&live, &sh_empty));
    assert_eq!(funding_heights(&live, &sh_empty).len(), 103, "102 coinbases and S's output");
    let spending = |cs: &ChainState| -> Vec<(u32, bitcoin::Txid, u32)> {
        cs.store_ref()
            .iter_addr_spending(&sh_empty)
            .into_iter()
            .map(|(k, _)| (k.height, k.txid, k.vin))
            .collect()
    };
    assert_eq!(spending(&backfilled), spending(&live));
    assert_eq!(spending(&live).len(), 1);
}
