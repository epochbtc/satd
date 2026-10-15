//! The one-time header chain check repairs a datadir whose stored filter
//! headers stopped chaining from the stored filters, and leaves a
//! consistent one alone.

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin::{Block, Network};

use node_filter_index::cursor::BackfillState;
use node_filter_index::{FILTER_TYPE_BASIC, FilterHeaderRow, FilterIndexConfig, FilterKey};

use super::{HeaderChainCheck, check_filter_header_chain};
use crate::chain::state::tests::build_test_block;
use crate::chain::state::{AssumeValid, ChainState};
use crate::index::filter::emit::GENESIS_PREV_FILTER_HEADER;
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;
use crate::storage::{FilterBackfillCursorWrite, Store, StoreBatch};
use crate::validation::script::NoopVerifier;

const BASE: u32 = 1_707_300_000;
const TIP: u32 = 6;

fn enabled() -> FilterIndexConfig {
    FilterIndexConfig {
        enabled: true,
        peer_serve: false,
    }
}

/// A chain of `TIP` blocks connected with the index on, flushed.
fn chain(dir: &std::path::Path) -> ChainState {
    let cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        16,
        2,
        Default::default(),
        enabled(),
        Default::default(),
    )
    .unwrap();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for h in 1..=TIP {
        let b: Block = build_test_block(parent, h, BASE + 600 * h);
        cs.accept_block(&b).expect("fixture block accepted");
        parent = b.block_hash();
    }
    cs.store_ref().flush().unwrap();
    cs
}

fn headers(cs: &ChainState) -> Vec<Option<[u8; 32]>> {
    (0..=TIP)
        .map(|h| cs.store_ref().get_filter_header(FILTER_TYPE_BASIC, h))
        .collect()
}

fn set_cursor(cs: &ChainState, state: BackfillState) {
    let mut batch = StoreBatch::default();
    batch.filter_backfill_cursor_advance = Some(FilterBackfillCursorWrite {
        state,
        cursor_height: 3,
        snapshot_height: 3,
        started_at_unix: 1,
        snapshot_tip_hash: [7u8; 32],
    });
    cs.store_ref().write_batch(batch).unwrap();
}

/// Rewrite the headers from `from` up as a pre-0.6.1 backfill left them:
/// chained off zeros at `from` instead of off the header below.
fn break_chain_from(cs: &ChainState, from: u32) {
    let mut prev = FilterHeader::from_byte_array(GENESIS_PREV_FILTER_HEADER);
    let mut batch = StoreBatch::default();
    for h in from..=TIP {
        let filter = cs.store_ref().get_filter(FILTER_TYPE_BASIC, h).unwrap();
        prev = BlockFilter::new(&filter).filter_header(&prev);
        batch.filter_header_puts.push(FilterHeaderRow {
            key: FilterKey {
                filter_type: FILTER_TYPE_BASIC,
                height: h,
            },
            header: prev.to_byte_array(),
        });
    }
    cs.store_ref().write_batch(batch).unwrap();
}

fn not_shut_down() -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(tx);
    rx
}

/// Fails without the repair: the headers at 4..=6 stay chained off zeros.
#[test]
fn the_check_rewrites_headers_that_do_not_chain() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    let good = headers(&cs);
    set_cursor(&cs, BackfillState::Completed);
    break_chain_from(&cs, 4);
    assert_ne!(headers(&cs), good);

    let out = check_filter_header_chain(&cs, &enabled(), &not_shut_down()).unwrap();
    assert_eq!(
        out,
        HeaderChainCheck::Walked {
            checked_to: Some(TIP),
            rewritten: 3,
            first_rewritten: Some(4),
        }
    );
    assert_eq!(headers(&cs), good, "repaired chain equals the in-order one");
    assert!(cs.store_ref().filter_header_chain_checked());

    // Once only.
    break_chain_from(&cs, 5);
    assert_eq!(
        check_filter_header_chain(&cs, &enabled(), &not_shut_down()).unwrap(),
        HeaderChainCheck::Skipped("already checked")
    );
}

/// Must-succeed partner: a consistent chain is walked and left unchanged.
#[test]
fn the_check_leaves_a_consistent_chain() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    let good = headers(&cs);
    set_cursor(&cs, BackfillState::Completed);

    let out = check_filter_header_chain(&cs, &enabled(), &not_shut_down()).unwrap();
    assert_eq!(
        out,
        HeaderChainCheck::Walked {
            checked_to: Some(TIP),
            rewritten: 0,
            first_rewritten: None,
        }
    );
    assert_eq!(headers(&cs), good);
    assert!(cs.store_ref().filter_header_chain_checked());
}

/// Without a backfill ever run, every row came from in-order live connects:
/// nothing to walk, and the marker is set.
#[test]
fn the_check_skips_a_datadir_no_backfill_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    assert_eq!(
        check_filter_header_chain(&cs, &enabled(), &not_shut_down()).unwrap(),
        HeaderChainCheck::Skipped("no filter backfill has run")
    );
    assert!(cs.store_ref().filter_header_chain_checked());
}

/// With the index off nothing is walked and the marker stays unset, so the
/// check runs once the index is back on.
#[test]
fn the_check_waits_while_the_index_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    set_cursor(&cs, BackfillState::Completed);
    let out = check_filter_header_chain(&cs, &FilterIndexConfig::default(), &not_shut_down()).unwrap();
    assert_eq!(out, HeaderChainCheck::Skipped("block filter index disabled"));
    assert!(!cs.store_ref().filter_header_chain_checked());
}

/// The walk stops at the first missing row and leaves the rows above it to
/// the backfill that will rewrite them.
#[test]
fn the_check_stops_at_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    set_cursor(&cs, BackfillState::Running);
    break_chain_from(&cs, 2);
    let mut gap = StoreBatch::default();
    gap.filter_removes.push(FilterKey {
        filter_type: FILTER_TYPE_BASIC,
        height: 4,
    });
    cs.store_ref().write_batch(gap).unwrap();
    let above = headers(&cs)[5..].to_vec();

    let out = check_filter_header_chain(&cs, &enabled(), &not_shut_down()).unwrap();
    assert_eq!(
        out,
        HeaderChainCheck::Walked {
            checked_to: Some(3),
            rewritten: 2,
            first_rewritten: Some(2),
        }
    );
    assert_eq!(headers(&cs)[5..].to_vec(), above, "rows above the gap untouched");
}

/// A shutdown before the walk finishes leaves the marker unset.
#[test]
fn the_check_is_retried_after_a_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path());
    set_cursor(&cs, BackfillState::Completed);
    let (tx, rx) = tokio::sync::watch::channel(true);
    assert_eq!(
        check_filter_header_chain(&cs, &enabled(), &rx).unwrap(),
        HeaderChainCheck::Interrupted
    );
    drop(tx);
    assert!(!cs.store_ref().filter_header_chain_checked());
}

/// The RocksDB marker starts unset and survives a reopen once set.
#[test]
fn the_rocksdb_marker_persists() {
    use crate::storage::rocksdb_store::RocksDbStore;
    let dir = tempfile::tempdir().unwrap();
    {
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.filter_header_chain_checked());
        store.mark_filter_header_chain_checked().unwrap();
        assert!(store.filter_header_chain_checked());
    }
    let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
    assert!(store.filter_header_chain_checked());
}
