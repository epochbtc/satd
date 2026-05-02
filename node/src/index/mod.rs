//! Auxiliary indexes layered on top of the chainstate.
//!
//! Each submodule is a logically-distinct index; they share the same
//! RocksDB instance and ride atomic-with-chainstate writes via `StoreBatch`.

pub mod address;
pub mod outpoint_spend;
