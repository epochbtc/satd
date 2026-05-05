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
pub mod emit;
#[cfg(feature = "block-filter-index")]
pub mod lookups;

#[cfg(feature = "block-filter-index")]
pub use emit::{build_filter_row_pair, filter_remove_key};
#[cfg(feature = "block-filter-index")]
pub use lookups::{MAX_FILTER_RANGE, RocksFilterIndex, filter_hash};

pub use node_filter_index::{
    decode_filter_key, encode_filter_key, FilterHeaderRow, FilterIndex, FilterIndexConfig,
    FilterKey, FilterRow, IndexError, FILTER_KEY_LEN, FILTER_TYPE_BASIC,
};
