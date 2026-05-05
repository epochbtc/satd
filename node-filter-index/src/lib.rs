//! BIP 158 compact block filter index — trait, schema types, cursor, config.
//!
//! This crate is the boundary between the filter-index implementation
//! (which lives in `node` because it needs `Store` / `ChainState`) and
//! consumers that only want the read surface (the `FilterIndex` trait,
//! key codec, `FilterIndexConfig`).
//!
//! Mirrors the workspace pattern set by `node-index`: the runtime impl
//! `RocksFilterIndex` lives in `node/src/index/filter/`, the trait and
//! types live here so future protocol crates (e.g. an Esplora REST or
//! Electrum-extras shim that exposes filters) can depend on this crate
//! alone.

pub mod config;
pub mod cursor;
pub mod keys;
pub mod trait_def;
pub mod types;

pub use config::FilterIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use keys::{
    decode_filter_key, encode_filter_key, FilterKey, FILTER_KEY_LEN, FILTER_TYPE_BASIC,
};
pub use trait_def::FilterIndex;
pub use types::{FilterHeaderRow, FilterRow, IndexError};
