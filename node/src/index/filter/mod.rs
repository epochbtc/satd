//! BIP 158 compact block filter index — runtime implementation.
//!
//! The trait surface (`FilterIndex`), key codec, error types, and
//! runtime config live in the sibling `node-filter-index` crate so
//! protocol-side consumers can depend on those without pulling in
//! `Store` / `ChainState`. This module owns the emit helpers (called
//! from `connect_block` / `disconnect_block`) and, in PR-2 onwards, the
//! `RocksFilterIndex` impl that binds the trait to the `Store`-backed
//! storage layout.

#[cfg(feature = "block-filter-index")]
pub mod backfill;
#[cfg(feature = "block-filter-index")]
pub mod emit;
#[cfg(feature = "block-filter-index")]
pub mod lookups;
#[cfg(feature = "block-filter-index")]
pub mod runner;

#[cfg(feature = "block-filter-index")]
pub use backfill::{
    BackfillError, BackfillHandle, PREFLIGHT_REQUIRED_FREE_BYTES, StatusReport, render_status,
};
#[cfg(feature = "block-filter-index")]
pub use emit::{build_filter_row_pair, filter_remove_key};
#[cfg(feature = "block-filter-index")]
pub use lookups::{MAX_FILTER_RANGE, RocksFilterIndex, filter_hash};
#[cfg(feature = "block-filter-index")]
pub use runner::{BackfillCommand, BackfillRunner, preflight_disk};

pub use node_filter_index::cursor;
pub use node_filter_index::{
    BackfillCursor, BackfillState, FILTER_KEY_LEN, FILTER_TYPE_BASIC, FilterHeaderRow, FilterIndex,
    FilterIndexConfig, FilterKey, FilterRow, IndexError, decode_filter_key, encode_filter_key,
};
