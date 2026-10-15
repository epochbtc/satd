//! A pass-through write of filter rows supersedes the pending rows for the
//! same keys, and only once it has been written: a failed write leaves the
//! pending rows as they were.

use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, OutPoint, Txid};

use node_filter_index::{FILTER_TYPE_BASIC, FilterHeaderRow, FilterKey, FilterRow};

use super::CoinCache;
use crate::storage::coinview::Coin;
use crate::storage::test_store::ControllableStore;
use crate::storage::{Store, StoreBatch};

const HEIGHT: u32 = 5;
const LIVE: [u8; 32] = [0xAA; 32];
const BACKFILL: [u8; 32] = [0xBB; 32];

fn key() -> FilterKey {
    FilterKey {
        filter_type: FILTER_TYPE_BASIC,
        height: HEIGHT,
    }
}

/// A connect-shaped batch (a coin and the tip) carrying a filter row, so it
/// stays pending.
fn live_row(cache: &CoinCache) {
    let coin = Coin {
        amount: 1_000,
        script_pubkey: bitcoin::ScriptBuf::new(),
        height: HEIGHT,
        coinbase: false,
        txseq: 0,
    };
    let mut batch = StoreBatch::default();
    batch.coin_puts.push((OutPoint::new(Txid::from_byte_array([1; 32]), 0), coin));
    batch.tip = Some(BlockHash::from_byte_array([5; 32]));
    batch.filter_puts.push(FilterRow { key: key(), filter: vec![1] });
    batch.filter_header_puts.push(FilterHeaderRow { key: key(), header: LIVE });
    cache.write_batch(batch).unwrap();
}

/// A backfill-shaped batch: filter rows only, so it passes through.
fn backfill_row() -> StoreBatch {
    let mut batch = StoreBatch::default();
    batch.filter_puts.push(FilterRow { key: key(), filter: vec![2] });
    batch.filter_header_puts.push(FilterHeaderRow { key: key(), header: BACKFILL });
    batch
}

/// Fails without the fix: the flush wrote the pending live header back over
/// the backfill's.
#[test]
fn a_pass_through_filter_row_survives_the_flush_of_the_pending_one() {
    let cache = CoinCache::new(Box::new(ControllableStore::new()), 10);
    live_row(&cache);
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), Some(LIVE));

    cache.write_batch(backfill_row()).unwrap();
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), Some(BACKFILL));
    assert_eq!(cache.get_filter(FILTER_TYPE_BASIC, HEIGHT), Some(vec![2]));
    cache.flush().unwrap();
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), Some(BACKFILL));
    assert_eq!(cache.get_filter(FILTER_TYPE_BASIC, HEIGHT), Some(vec![2]));
}

/// Fails if the pending rows are dropped before the write: the failed
/// pass-through took the live row out of pending, and the flush stored the
/// block without a filter header.
#[test]
fn a_failed_pass_through_write_keeps_the_pending_filter_row() {
    let store = ControllableStore::new();
    let controls = store.controls();
    let cache = CoinCache::new(Box::new(store), 10);
    live_row(&cache);

    controls.fail_next_write();
    cache
        .write_batch(backfill_row())
        .expect_err("the injected fault must surface");
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), Some(LIVE));
    cache.flush().unwrap();
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), Some(LIVE));
    assert_eq!(cache.get_filter(FILTER_TYPE_BASIC, HEIGHT), Some(vec![1]));
}

/// A pass-through remove drops the pending rows for its key.
#[test]
fn a_pass_through_filter_remove_drops_the_pending_rows() {
    let cache = CoinCache::new(Box::new(ControllableStore::new()), 10);
    live_row(&cache);
    let remove = StoreBatch {
        filter_removes: vec![key()],
        ..Default::default()
    };
    cache.write_batch(remove).unwrap();
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), None);
    cache.flush().unwrap();
    assert_eq!(cache.get_filter_header(FILTER_TYPE_BASIC, HEIGHT), None);
    assert_eq!(cache.get_filter(FILTER_TYPE_BASIC, HEIGHT), None);
}
