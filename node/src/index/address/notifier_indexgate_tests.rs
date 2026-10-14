//! Status pushes refused while an address backfill runs are made up when it
//! finishes.
//!
//! While the backfill cursor is not Idle or Completed the address index
//! refuses reads, so a status recompute triggered by a block or a mempool
//! transaction in that time cannot run. Without a retry, a subscriber whose
//! history changed then would see nothing until some later event touched
//! the same script.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Txid;
use bitcoin::hashes::Hash as _;

use super::{notifier_task, recompute_all_active};
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::cursor::BackfillState;
use crate::index::address::keys::{AddrFundingRowV3, Scripthash};
use crate::index::address::lookups::RocksAddressIndex;
use crate::mempool::pool::Mempool;
use crate::storage::rocksdb_store::RocksDbStore;
use crate::storage::{BackfillCursorWrite, Store, StoreBatch};

const SH: Scripthash = [0x6b; 32];

fn set_cursor(store: &dyn Store, state: BackfillState) {
    let batch = StoreBatch {
        backfill_cursor_advance: Some(BackfillCursorWrite {
            state,
            pass: 2,
            cursor_height: 1,
            snapshot_height: 5,
            started_at_unix: 1,
            snapshot_tip_hash: [4u8; 32],
        }),
        ..Default::default()
    };
    store.write_batch(batch).unwrap();
}

/// One confirmed transaction paying `SH`, with the rows its history
/// resolves through, and the address backfill cursor Running.
fn index_mid_backfill() -> (Arc<RocksAddressIndex>, Arc<dyn Store>, tempfile::TempDir) {
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap())
        as Arc<dyn Store>;
    let txid = Txid::from_byte_array([0x31; 32]);
    let hash = bitcoin::BlockHash::from_byte_array([5u8; 32]);
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let mut batch = StoreBatch::default();
    batch.tx_loc_puts.push((txid, 1));
    batch.txseq_txid_puts.push((1, txid));
    batch.txseq_block_puts.push((1, 5));
    batch.height_hash_puts.push((5, hash));
    batch.block_index_puts.push((
        hash,
        BlockIndexEntry {
            header: genesis.header,
            height: 5,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        },
    ));
    batch.addr_funding_puts.push(AddrFundingRowV3 {
        scripthash: SH,
        txseq: 1,
        vout: 0,
        amount_sat: 1_000,
    });
    store.write_batch(batch).unwrap();
    set_cursor(store.as_ref(), BackfillState::Running);
    let index = Arc::new(RocksAddressIndex::new(
        store.clone(),
        AddressIndexConfig {
            enabled: true,
            ..Default::default()
        },
    ));
    (index, store, dir)
}

/// A refused recompute is owed until serving resumes, and paid once.
#[test]
fn a_recompute_refused_during_a_backfill_is_owed_until_it_completes() {
    let (index, store, _dir) = index_mid_backfill();
    let registry = index.subscription_registry();
    let mut rx = registry.subscribe(SH).unwrap();
    let mempool = Mempool::new(8 * 1024 * 1024, 1);

    recompute_all_active(&index, &registry, &mempool);
    assert!(rx.try_recv().is_err(), "nothing is pushed while the index refuses reads");
    assert!(!index.take_status_recompute_owed(), "not payable while the backfill runs");

    set_cursor(store.as_ref(), BackfillState::Completed);
    assert!(index.take_status_recompute_owed(), "payable once it completes");
    assert!(!index.take_status_recompute_owed(), "and paid only once");
    recompute_all_active(&index, &registry, &mempool);
    assert!(rx.try_recv().is_ok(), "the recompute pushes the status");
}

/// The notifier task pays the debt by itself, with no further block or
/// mempool event.
///
/// Fails without the fix: no status was ever pushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_notifier_pushes_the_status_once_the_backfill_completes() {
    let (index, store, _dir) = index_mid_backfill();
    let registry = index.subscription_registry();
    let mut rx = registry.subscribe(SH).unwrap();
    let mempool = Arc::new(Mempool::new(8 * 1024 * 1024, 1));
    let (chain, _chain_dir) = crate::chain::state::tests::make_chain_state();
    let (chain_tx, chain_rx) = tokio::sync::broadcast::channel(16);
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(notifier_task(
        index.clone(),
        registry.clone(),
        Arc::new(chain),
        mempool,
        chain_rx,
        shutdown,
    ));

    // A block arrives while the backfill runs: its recompute is refused.
    chain_tx
        .send(crate::chain::events::ChainEvent::BlockConnected {
            hash: bitcoin::BlockHash::all_zeros(),
            height: 6,
        })
        .ok();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(rx.try_recv().is_err(), "nothing is pushed while the index refuses reads");

    set_cursor(store.as_ref(), BackfillState::Completed);
    let pushed = tokio::time::timeout(Duration::from_secs(20), rx.recv()).await;
    shutdown_tx.send(true).unwrap();
    let _ = task.await;
    assert!(
        matches!(pushed, Ok(Ok(_))),
        "the status was not pushed after the backfill completed: {pushed:?}"
    );
}
