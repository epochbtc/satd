//! The address and spend indexes serve only while no address backfill is
//! mid-run.
//!
//! Electrum and Esplora check the address index's "complete" marker once,
//! when they bind. A `backfillindex address` started afterwards runs while
//! they keep serving, and a run that stops part-way (a reorg, a cancel, an
//! error) leaves the marker set. The silent-payment index already requires
//! its backfill cursor to be Idle or Completed before it serves; the address
//! and spend indexes now do the same.

use std::sync::Arc;

use bitcoin::OutPoint;
use bitcoin::hashes::Hash as _;
use node_index::{AddressIndex, IndexError, SpendIndex};

use crate::index::address::config::AddressIndexConfig;
use crate::index::address::cursor::BackfillState;
use crate::index::address::lookups::RocksAddressIndex;
use crate::index::outpoint_spend::lookups::RocksSpendIndex;
use crate::storage::rocksdb_store::RocksDbStore;
use crate::storage::{BackfillCursorWrite, Store, StoreBatch};

const SH: [u8; 32] = [0x5a; 32];

fn indexes_with_cursor(
    state: BackfillState,
) -> (RocksAddressIndex, RocksSpendIndex, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap())
        as Arc<dyn Store>;
    let batch = StoreBatch {
        backfill_cursor_advance: Some(BackfillCursorWrite {
            state,
            pass: 2,
            cursor_height: 50,
            snapshot_height: 100,
            started_at_unix: 1,
            snapshot_tip_hash: [9u8; 32],
        }),
        ..Default::default()
    };
    store.write_batch(batch).unwrap();
    assert_eq!(store.read_backfill_cursor().state, state);
    assert!(store.address_index_complete());
    assert!(store.spent_complete());
    let cfg = AddressIndexConfig {
        enabled: true,
        ..Default::default()
    };
    (
        RocksAddressIndex::new(store.clone(), cfg.clone()),
        RocksSpendIndex::new(store, Arc::new(cfg)),
        dir,
    )
}

fn outpoint() -> OutPoint {
    OutPoint {
        txid: bitcoin::Txid::from_byte_array([0x77; 32]),
        vout: 0,
    }
}

/// `Ok` for every read when serving, `Err(Incomplete)` for every read when
/// not. Mixed answers fail the test.
fn serves(addr: &RocksAddressIndex, spend: &RocksSpendIndex) -> bool {
    let results: Vec<Result<(), IndexError>> = vec![
        addr.confirmed_history(&SH).map(|_| ()),
        addr.confirmed_history_limited(&SH, 10).map(|_| ()),
        addr.balance(&SH).map(|_| ()),
        addr.confirmed_distinct_history_limited(&SH, 10).map(|_| ()),
        addr.confirmed_txs_in_chain_order(&SH, 10).map(|_| ()),
        addr.confirmed_txs_newest_first(&SH, None, 10).map(|_| ()),
        addr.utxos(&SH).map(|_| ()),
        addr.utxos_limited(&SH, 10).map(|_| ()),
        spend.spend_of(&outpoint()).map(|_| ()),
        spend.spends_of_tx(&outpoint().txid).map(|_| ()),
    ];
    let ok: Vec<bool> = results.iter().map(|r| r.is_ok()).collect();
    if ok.iter().all(|o| *o) {
        return true;
    }
    for r in &results {
        assert!(
            matches!(r, Err(IndexError::Incomplete)),
            "every read must refuse the same way: {results:?}"
        );
    }
    false
}

/// Fails without the fix: every state served.
#[test]
fn the_address_and_spend_indexes_do_not_serve_while_a_backfill_is_not_quiescent() {
    for state in [
        BackfillState::Running,
        BackfillState::Paused,
        BackfillState::Failed,
        BackfillState::Cancelled,
    ] {
        let (addr, spend, _dir) = indexes_with_cursor(state);
        assert!(
            !serves(&addr, &spend),
            "served with the address backfill cursor {}",
            state.label()
        );
    }
}

#[test]
fn the_address_and_spend_indexes_serve_when_the_backfill_is_idle_or_completed() {
    for state in [BackfillState::Idle, BackfillState::Completed] {
        let (addr, spend, _dir) = indexes_with_cursor(state);
        assert!(
            serves(&addr, &spend),
            "refused with the address backfill cursor {}",
            state.label()
        );
        // An unknown outpoint on a quiescent, complete index is unspent.
        assert_eq!(spend.spend_of(&outpoint()).unwrap(), None);
    }
}
