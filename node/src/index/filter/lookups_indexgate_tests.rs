//! The filter index serves only while no backfill is mid-run.
//!
//! The "complete" marker alone is not enough. It is set once and stays set
//! while a later `backfillindex blockfilter` runs over the same index, and a
//! run that stops part-way (a reorg, a cancel, an error) leaves it set too.
//! The silent-payment index already requires its backfill cursor to be Idle
//! or Completed as well; the filter index now does the same.

use std::sync::Arc;

use node_filter_index::cursor::BackfillState;
use node_filter_index::{
    FILTER_TYPE_BASIC, FilterHeaderRow, FilterIndex, FilterIndexConfig, FilterKey, FilterRow,
    IndexError,
};

use super::RocksFilterIndex;
use crate::storage::db::InMemoryStore;
use crate::storage::{FilterBackfillCursorWrite, Store, StoreBatch};

fn enabled() -> FilterIndexConfig {
    FilterIndexConfig {
        enabled: true,
        peer_serve: false,
    }
}

/// A complete index with rows at heights 0..=1000 and the backfill cursor in
/// `state`.
fn index_with_cursor(state: BackfillState) -> RocksFilterIndex {
    let store = Arc::new(InMemoryStore::new());
    let mut batch = StoreBatch::default();
    for height in 0..=1000u32 {
        let key = FilterKey {
            filter_type: FILTER_TYPE_BASIC,
            height,
        };
        batch.filter_puts.push(FilterRow {
            key,
            filter: vec![height as u8],
        });
        batch.filter_header_puts.push(FilterHeaderRow {
            key,
            header: [height as u8; 32],
        });
    }
    batch.filter_backfill_cursor_advance = Some(FilterBackfillCursorWrite {
        state,
        cursor_height: 500,
        snapshot_height: 1000,
        started_at_unix: 1,
        snapshot_tip_hash: [7u8; 32],
    });
    store.write_batch(batch).unwrap();
    assert!(store.block_filter_index_complete());
    assert_eq!(store.read_filter_backfill_cursor().state, state);
    RocksFilterIndex::new(store, enabled())
}

fn serves(idx: &RocksFilterIndex) -> bool {
    let served = [
        idx.filter_at(FILTER_TYPE_BASIC, 1).is_ok(),
        idx.header_at(FILTER_TYPE_BASIC, 1).is_ok(),
        idx.headers_range(FILTER_TYPE_BASIC, 0, 3).is_ok(),
        idx.checkpoints_to(FILTER_TYPE_BASIC, 1000).is_ok(),
        idx.is_complete(),
    ];
    assert!(
        served.iter().all(|s| *s) || served.iter().all(|s| !*s),
        "every serving path must agree: {served:?}"
    );
    served[0]
}

/// Fails without the fix: every state served off the marker alone.
#[test]
fn the_filter_index_does_not_serve_while_a_backfill_is_not_quiescent() {
    for state in [
        BackfillState::Running,
        BackfillState::Paused,
        BackfillState::Failed,
        BackfillState::Cancelled,
    ] {
        let idx = index_with_cursor(state);
        assert!(!serves(&idx), "served with the backfill cursor {}", state.label());
        assert!(matches!(
            idx.filter_at(FILTER_TYPE_BASIC, 1),
            Err(IndexError::Incomplete)
        ));
    }
}

#[test]
fn the_filter_index_serves_when_the_backfill_is_idle_or_completed() {
    for state in [BackfillState::Idle, BackfillState::Completed] {
        let idx = index_with_cursor(state);
        assert!(serves(&idx), "refused with the backfill cursor {}", state.label());
        assert_eq!(idx.filter_at(FILTER_TYPE_BASIC, 1).unwrap(), vec![1u8]);
    }
}
