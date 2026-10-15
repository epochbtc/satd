//! One-time check of the stored BIP 157 filter header chain.
//!
//! Before 0.6.1, a filter backfill's rows could lose to the live connect
//! path's still-pending rows for the same heights (see
//! `CoinCache::drop_pending_filter_rows_superseded_by`). Those live rows
//! chained their header off the all-zero fallback, so from the first such
//! height on, every stored filter header differed from the BIP 157 chain,
//! even though every stored *filter* was correct: a filter depends only on
//! its block, a header also on the header before it.
//!
//! That makes the repair exact and cheap: walk the stored rows from
//! genesis, recompute `header[h] = sha256d(sha256d(filter[h]) ||
//! header[h-1])`, and rewrite each header that differs. No block or undo
//! data is read. The pass runs once per datadir (the
//! `block_filter_index.header_chain_checked` marker) and only where a filter
//! backfill has ever run: without one, every row came from the live path in
//! height order, which chains correctly.

use bitcoin::bip158::{BlockFilter, FilterHeader};
use bitcoin::hashes::Hash as _;

use node_filter_index::cursor::BackfillState;
use node_filter_index::{FILTER_TYPE_BASIC, FilterHeaderRow, FilterIndexConfig, FilterKey};

use crate::chain::state::ChainState;
use crate::index::filter::backfill::BackfillError;
use crate::index::filter::emit::GENESIS_PREV_FILTER_HEADER;
use crate::storage::{Store, StoreBatch, WriteMode};

/// Heights checked per `accept_lock` hold.
const CHUNK: u32 = 1000;

/// What `check_filter_header_chain` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderChainCheck {
    /// Nothing walked: the index is off, the check already ran, or no
    /// backfill has ever written rows on this datadir.
    Skipped(&'static str),
    /// Walked `0..=checked_to`; `rewritten` headers differed and were
    /// rewritten, the first of them at `first_rewritten`.
    Walked {
        checked_to: Option<u32>,
        rewritten: u64,
        first_rewritten: Option<u32>,
    },
    /// Shutdown arrived mid-walk; the marker is not set, so the next start
    /// walks again.
    Interrupted,
}

/// Run the one-time header chain check if this datadir still needs it.
///
/// The walk goes up from genesis while each height has both a filter and a
/// header row, up to the active tip, and stops at the first missing row:
/// rows above a gap belong to a backfill that has not finished, and that
/// backfill rewrites them. Each chunk is checked and written under
/// `accept_lock`, so live connects and reorgs interleave between chunks but
/// never inside one, and each chunk starts from the stored header below it.
pub fn check_filter_header_chain(
    chain: &ChainState,
    cfg: &FilterIndexConfig,
    shutdown: &tokio::sync::watch::Receiver<bool>,
) -> Result<HeaderChainCheck, BackfillError> {
    let store = chain.store_ref();
    if !cfg.enabled {
        return Ok(HeaderChainCheck::Skipped("block filter index disabled"));
    }
    if store.filter_header_chain_checked() {
        return Ok(HeaderChainCheck::Skipped("already checked"));
    }
    if store.read_filter_backfill_cursor().state == BackfillState::Idle {
        store.mark_filter_header_chain_checked()?;
        return Ok(HeaderChainCheck::Skipped("no filter backfill has run"));
    }

    tracing::info!("filter index: checking the stored filter header chain (one-time)");
    let mut next: u32 = 0;
    let mut checked_to: Option<u32> = None;
    let mut rewritten: u64 = 0;
    let mut first_rewritten: Option<u32> = None;
    loop {
        if *shutdown.borrow() {
            return Ok(HeaderChainCheck::Interrupted);
        }
        let done = chain.with_accept_lock(|| -> Result<bool, BackfillError> {
            let (_, tip) = chain.tip_snapshot();
            if next > tip {
                return Ok(true);
            }
            let mut prev = if next == 0 {
                GENESIS_PREV_FILTER_HEADER
            } else {
                match store.get_filter_header(FILTER_TYPE_BASIC, next - 1) {
                    Some(h) => h,
                    None => return Ok(true),
                }
            };
            let end = tip.min(next.saturating_add(CHUNK - 1));
            let mut batch = StoreBatch::default();
            let mut stop = false;
            let mut h = next;
            while h <= end {
                let (Some(filter), Some(stored)) = (
                    store.get_filter(FILTER_TYPE_BASIC, h),
                    store.get_filter_header(FILTER_TYPE_BASIC, h),
                ) else {
                    stop = true;
                    break;
                };
                let expected = BlockFilter::new(&filter)
                    .filter_header(&FilterHeader::from_byte_array(prev))
                    .to_byte_array();
                if expected != stored {
                    first_rewritten.get_or_insert(h);
                    rewritten += 1;
                    batch.filter_header_puts.push(FilterHeaderRow {
                        key: FilterKey {
                            filter_type: FILTER_TYPE_BASIC,
                            height: h,
                        },
                        header: expected,
                    });
                }
                prev = expected;
                checked_to = Some(h);
                h += 1;
            }
            if !batch.filter_header_puts.is_empty() {
                store.write_batch_mode(batch, WriteMode::Normal)?;
            }
            next = h;
            Ok(stop || next > tip)
        })?;
        if done {
            break;
        }
        if next.is_multiple_of(100_000) {
            tracing::info!(height = next, rewritten, "filter index: header chain check progress");
        }
    }
    if rewritten > 0 {
        store.flush_durable()?;
    }
    store.mark_filter_header_chain_checked()?;
    match first_rewritten {
        Some(first) => tracing::warn!(
            first_rewritten = first,
            rewritten,
            checked_to = ?checked_to,
            "filter index: rewrote filter headers that did not chain from the stored filters"
        ),
        None => tracing::info!(
            checked_to = ?checked_to,
            "filter index: stored filter header chain is consistent"
        ),
    }
    Ok(HeaderChainCheck::Walked {
        checked_to,
        rewritten,
        first_rewritten,
    })
}

#[cfg(test)]
#[path = "header_chain_filtertail_tests.rs"]
mod filtertail_tests;
