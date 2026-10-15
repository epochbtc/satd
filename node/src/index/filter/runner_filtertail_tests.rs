//! The backfill writes its rows straight to the backing store, while the
//! live connect path's rows for recent blocks sit in the `CoinCache`'s
//! pending batch until the next flush. Where both hold a row for the same
//! height, the backfill's row is the newer one and must be what reads see
//! and what the flush leaves on disk.
//!
//! The case that matters is the filter header chain. A block connected
//! before the rows below it exist chains its live header off the all-zero
//! fallback; the backfill (and its tail catch-up) rewrites that header from
//! the correct previous one. If the pending live row survived, a read would
//! serve it, the flush would write it back over the corrected row, and every
//! later live header would chain off it.

use std::sync::Arc;

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin::{Block, Network};

use node_filter_index::cursor::BackfillState;
use node_filter_index::{FILTER_TYPE_BASIC, FilterIndexConfig, FilterKey};

use crate::chain::state::tests::build_test_block;
use crate::chain::state::{AssumeValid, ChainState};
use crate::index::filter::backfill::BackfillHandle;
use crate::index::filter::cursor::BackfillCursor;
use crate::index::filter::emit::GENESIS_PREV_FILTER_HEADER;
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

fn chain(dir: &std::path::Path) -> ChainState {
    ChainState::new(
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
    .unwrap()
}

fn extend(cs: &ChainState, parent: bitcoin::BlockHash, parent_height: u32, n: u32) -> Vec<Block> {
    let mut parent = parent;
    (1..=n)
        .map(|i| {
            let h = parent_height + i;
            let b = build_test_block(parent, h, BASE + 600 * h);
            cs.accept_block(&b).expect("fixture block accepted");
            parent = b.block_hash();
            b
        })
        .collect()
}

fn header(cs: &ChainState, height: u32) -> Option<[u8; 32]> {
    cs.store_ref().get_filter_header(FILTER_TYPE_BASIC, height)
}

/// Remove the filter rows at `0..=top`, as on a node that connected those
/// blocks before the index was enabled, and leave nothing pending.
fn drop_rows_up_to(cs: &ChainState, top: u32) {
    cs.store_ref().flush().unwrap();
    let mut batch = StoreBatch::default();
    for height in 0..=top {
        batch.filter_removes.push(FilterKey {
            filter_type: FILTER_TYPE_BASIC,
            height,
        });
    }
    cs.store_ref().write_batch(batch).unwrap();
    cs.store_ref().flush().unwrap();
    assert!((0..=top).all(|h| header(cs, h).is_none()));
}

/// The first height `0..=tip` whose stored header is not
/// `sha256d(sha256d(filter) || header[h-1])`, starting from the all-zero
/// genesis previous header, or `None` when the whole chain holds.
fn first_broken_link(cs: &ChainState, tip: u32) -> Option<u32> {
    let mut prev = FilterHeader::from_byte_array(GENESIS_PREV_FILTER_HEADER);
    for h in 0..=tip {
        let filter = cs
            .store_ref()
            .get_filter(FILTER_TYPE_BASIC, h)
            .unwrap_or_else(|| panic!("no filter row at height {h}"));
        let stored = header(cs, h).unwrap_or_else(|| panic!("no filter header at height {h}"));
        let expected = BlockFilter::new(&filter).filter_header(&prev);
        if expected.to_byte_array() != stored {
            return Some(h);
        }
        prev = expected;
    }
    None
}

fn run_backfill(cs: &Arc<ChainState>, snapshot_height: u32, anchor: bitcoin::BlockHash) {
    let handle = Arc::new(BackfillHandle::new(BackfillCursor {
        state: BackfillState::Running,
        cursor_height: 0,
        snapshot_height,
        started_at_unix: 1,
        snapshot_tip_hash: anchor.to_byte_array(),
    }));
    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    BackfillRunner {
        handle: handle.clone(),
        chain: cs.clone(),
        cfg: enabled(),
        shutdown,
    }
    .run()
    .expect("the backfill completes");
    assert_eq!(handle.cursor().state, BackfillState::Completed);
}

/// Blocks 4..=6 connect after the rows below them are gone, so their live
/// headers chain off zeros and stay pending. The backfill walks 0..=3 and
/// its tail catch-up rewrites 4..=6.
///
/// Fails without the fix: the pending live rows at 4..=6 shadowed the
/// catch-up's rows and the flush wrote them back, so the chain broke at 4.
#[test]
fn tail_catchup_rows_survive_the_flush_of_pending_live_rows() {
    let dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(chain(dir.path()));
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let a = extend(&cs, genesis, 0, 3);
    drop_rows_up_to(&cs, 3);
    let b = extend(&cs, a[2].block_hash(), 3, 3);
    assert_eq!(cs.tip_hash(), b[2].block_hash());

    run_backfill(&cs, 3, a[2].block_hash());
    assert_eq!(first_broken_link(&cs, 6), None, "chain as read before the flush");
    cs.store_ref().flush().unwrap();
    assert_eq!(first_broken_link(&cs, 6), None, "chain as stored after the flush");

    // The next live block chains off the corrected header.
    extend(&cs, b[2].block_hash(), 6, 1);
    cs.store_ref().flush().unwrap();
    assert_eq!(first_broken_link(&cs, 7), None, "chain after the next live block");
}

/// The snapshot itself covers blocks whose live rows are still pending: the
/// main walk, not only the tail catch-up, must win over them.
///
/// Fails without the fix: the walk read the pending zero-chained header at
/// height 4 as its previous header, and the flush wrote the live rows back.
#[test]
fn snapshot_walk_rows_survive_the_flush_of_pending_live_rows() {
    let dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(chain(dir.path()));
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let a = extend(&cs, genesis, 0, 3);
    drop_rows_up_to(&cs, 3);
    let b = extend(&cs, a[2].block_hash(), 3, 3);

    run_backfill(&cs, 6, b[2].block_hash());
    assert_eq!(first_broken_link(&cs, 6), None, "chain as read before the flush");
    cs.store_ref().flush().unwrap();
    assert_eq!(first_broken_link(&cs, 6), None, "chain as stored after the flush");
}

/// Must-succeed partner: with the index on from genesis, in-order live
/// connects alone build a correct chain, pending and flushed, and a later
/// backfill over it leaves every header unchanged.
#[test]
fn in_order_live_connects_keep_the_chain_and_a_backfill_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let cs = Arc::new(chain(dir.path()));
    let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let a = extend(&cs, genesis, 0, 6);
    assert_eq!(first_broken_link(&cs, 6), None, "pending live chain");
    let live: Vec<Option<[u8; 32]>> = (0..=6).map(|h| header(&cs, h)).collect();

    run_backfill(&cs, 3, a[2].block_hash());
    cs.store_ref().flush().unwrap();
    assert_eq!(first_broken_link(&cs, 6), None, "flushed chain");
    let after: Vec<Option<[u8; 32]>> = (0..=6).map(|h| header(&cs, h)).collect();
    assert_eq!(after, live, "the backfill changed a correct header");
}
