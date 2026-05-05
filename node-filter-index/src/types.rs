//! Read-side types for the BIP 158 filter index.

use crate::keys::FilterKey;

/// Disabled / not-found surface error for the filter index. Callers
/// (the `getblockfilter` RPC handler and the BIP 157 P2P arms) use the
/// distinction to decide whether to error vs. silent-drop:
///
/// - `Disabled`: index turned off via runtime config; RPC errors with
///   the disabled-message, P2P silent-drops.
/// - `Incomplete`: index enabled but `block_filter_index.complete` is
///   false (backfill in progress or never finished); RPC errors with
///   the not-synced-message, P2P silent-drops and the
///   `NODE_COMPACT_FILTERS` advertisement is suppressed.
/// - `NotFound`: row doesn't exist for this `(type, height)` (e.g.
///   stop-hash not on the active chain or above tip).
/// - `InvalidRange`: BIP 157 caps violated (`stop < start` or
///   `stop - start >= 1000`).
/// - `Storage`: surfaced storage failure.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("block filter index is disabled — restart with --blockfilterindex=basic to enable")]
    Disabled,
    #[error(
        "block filter index is not synced — wait for backfill to complete or run reindex-chainstate"
    )]
    Incomplete,
    #[error("filter not found at height {0}")]
    NotFound(u32),
    #[error("invalid filter range: start={start_height}, stop={stop_height}")]
    InvalidRange { start_height: u32, stop_height: u32 },
    #[error("storage error: {0}")]
    Storage(String),
}

/// One filter blob row.
#[derive(Clone, Debug)]
pub struct FilterRow {
    pub key: FilterKey,
    pub filter: Vec<u8>,
}

/// One filter-header row (32 bytes; computed via
/// `BlockFilter::filter_header(prev)`).
#[derive(Clone, Debug)]
pub struct FilterHeaderRow {
    pub key: FilterKey,
    pub header: [u8; 32],
}
