//! The filter backfill and the live connect path both write filter rows,
//! keyed by height.
//!
//! - A backfill row is written only for a block that is on the active chain
//!   at the moment of the write. The anchor check and the write happen under
//!   the chain's `accept_lock`, so a reorg cannot land between them and leave
//!   a row for a block it just disconnected.
//! - After a reorg invalidates a run, the cleanup must not remove the rows
//!   the live path wrote for the replacement blocks at the same heights.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use bitcoin::{Block, Network};

use node_filter_index::cursor::BackfillState;
use node_filter_index::{FILTER_TYPE_BASIC, FilterHeaderRow, FilterIndexConfig, FilterKey, FilterRow};

use crate::chain::state::tests::build_test_block;
use crate::chain::state::{AssumeValid, ChainState};
use crate::index::filter::backfill::BackfillHandle;
use crate::index::filter::cursor::BackfillCursor;
use crate::index::filter::runner::BackfillRunner;
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;
use crate::storage::{Store, StoreBatch};
use crate::validation::script::NoopVerifier;

const BASE: u32 = 1_707_300_000;

fn enabled() -> FilterIndexConfig {
    FilterIndexConfig {
        enabled: true,
        peer_serve: false,
    }
}

fn chain(dir: &std::path::Path, live_filters: bool) -> ChainState {
    ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.join("blocks")).unwrap(),
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        16,
        2,
        Default::default(),
        if live_filters { enabled() } else { Default::default() },
        Default::default(),
    )
    .unwrap()
}

/// Build and connect a branch of `n` blocks on `parent` at `parent_height`.
fn extend(cs: &ChainState, parent: bitcoin::BlockHash, parent_height: u32, n: u32, salt: u32) -> Vec<Block> {
    let mut parent = parent;
    (1..=n)
        .map(|i| {
            let h = parent_height + i;
            let b = build_test_block(parent, h, BASE + salt + 600 * h);
            cs.accept_block(&b).expect("fixture block accepted");
            parent = b.block_hash();
            b
        })
        .collect()
}

fn header(cs: &ChainState, height: u32) -> Option<[u8; 32]> {
    cs.store_ref().get_filter_header(FILTER_TYPE_BASIC, height)
}

fn running_cursor(snapshot_height: u32, cursor_height: u32, anchor: bitcoin::BlockHash) -> BackfillCursor {
    BackfillCursor {
        state: BackfillState::Running,
        cursor_height,
        snapshot_height,
        started_at_unix: 1,
        snapshot_tip_hash: anchor.to_byte_array(),
    }
}

/// ```text
///   A1 - A2 - A3              (backfill anchor A3, walked to 3)
///     \
///      B2 - B3 - B4           (active after the reorg)
/// ```
/// Fails without the fix: the cleanup removed the filter rows at heights 2
/// and 3, which the live path had just written for B2 and B3.
#[test]
fn reorg_cleanup_keeps_the_rows_the_live_path_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path(), true);
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let a = extend(&cs, genesis, 0, 3, 0);
    let handle = BackfillHandle::new(running_cursor(3, 3, a[2].block_hash()));

    let b = extend(&cs, a[0].block_hash(), 1, 3, 50_000);
    assert_eq!(cs.tip_hash(), b[2].block_hash(), "the B branch is active");
    cs.store_ref().flush().unwrap();
    let live: Vec<Option<[u8; 32]>> = (0..=4).map(|h| header(&cs, h)).collect();
    assert!(live.iter().all(|h| h.is_some()), "live rows at 0..=4: {live:?}");

    BackfillRunner::cleanup_stale_rows_after_reorg(&cs, &handle).expect("cleanup runs");

    for h in 0..=4u32 {
        assert_eq!(
            header(&cs, h),
            live[h as usize],
            "the cleanup changed the live filter row at height {h}"
        );
    }
}

/// A row above the live tip belongs to no active block, so the cleanup still
/// removes it.
#[test]
fn reorg_cleanup_removes_a_row_above_the_live_tip() {
    let dir = tempfile::tempdir().unwrap();
    let cs = chain(dir.path(), true);
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let a = extend(&cs, genesis, 0, 3, 0);
    let handle = BackfillHandle::new(running_cursor(3, 3, a[2].block_hash()));

    cs.invalidate_block(a[2].block_hash()).expect("invalidate A3");
    assert_eq!(cs.tip_height(), 2);
    // A row for A3 that a backfill write left behind.
    let key = FilterKey {
        filter_type: FILTER_TYPE_BASIC,
        height: 3,
    };
    let mut stale = StoreBatch::default();
    stale.filter_puts.push(FilterRow { key, filter: vec![1] });
    stale.filter_header_puts.push(FilterHeaderRow { key, header: [3u8; 32] });
    cs.store_ref().write_batch(stale).unwrap();
    cs.store_ref().flush().unwrap();
    let kept = header(&cs, 2);
    assert!(kept.is_some());

    BackfillRunner::cleanup_stale_rows_after_reorg(&cs, &handle).expect("cleanup runs");

    assert_eq!(header(&cs, 3), None, "the row above the live tip is removed");
    assert_eq!(header(&cs, 2), kept, "the live row below it is kept");
}

/// The backfill writes a row only under `accept_lock`: while another thread
/// holds the lock (as every reorg does for its whole length), no row lands.
///
/// Fails without the fix: the runner wrote rows while the lock was held.
#[test]
fn the_backfill_writes_rows_only_under_accept_lock() {
    let dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(chain(dir.path(), false));
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let blocks = extend(&cs, genesis, 0, 5, 0);
    assert_eq!(header(&cs, 0), None, "the live path writes no filter rows here");

    let handle = Arc::new(BackfillHandle::new(running_cursor(5, 0, blocks[4].block_hash())));
    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let runner = BackfillRunner {
        handle: handle.clone(),
        chain: cs.clone(),
        cfg: enabled(),
        shutdown,
    };

    let held = cs.hold_accept_lock_for_test();
    let walk = std::thread::spawn(move || runner.run());
    std::thread::sleep(Duration::from_millis(300));
    let written_while_held: Vec<u32> = (0..=5).filter(|h| header(&cs, *h).is_some()).collect();
    drop(held);
    walk.join().unwrap().expect("the backfill completes");

    assert!(
        written_while_held.is_empty(),
        "rows written while accept_lock was held: {written_while_held:?}"
    );
    assert!((0..=5).all(|h| header(&cs, h).is_some()), "every row written afterwards");
    assert_eq!(handle.cursor().state, BackfillState::Completed);
}
