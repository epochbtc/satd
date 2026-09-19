//! Confirmed-side spend index — which input consumed a given output.
//!
//! Maintained atomically with `connect_block` / `disconnect_block` and
//! the address-history index, gated on the same `--addressindex=N`
//! flag (the spend index is a strict superset of the addr-spending
//! lookup; turning off the address index turns this off too).
//!
//! Both ends of a row are named by transaction ordinal rather than
//! txid — 16 bytes a row instead of 76 — and the storage layer resolves
//! them back to the txid and height consumers expect before a row
//! leaves it. The module name is fossilised from the `outpoint_spend`
//! column family the ordinal-keyed `spent` family replaced.
//!
//! Consumers:
//! - Esplora `/tx/:txid/outspend/:vout` and `/tx/:txid/outspends`
//! - Future Electrum `blockchain.outpoint.subscribe` (post-M5)
//!
//! satd does not implement Core's `gettxspendingprevout`; when it does,
//! this is what would back its confirmed side (mempool inputs stay in
//! the mempool's existing tracker).
//!
//! Schema and codec live in `node-index::spend_keys`. This module
//! contains only the integration surface (emit helpers, lookup
//! adapter).

pub mod emit;
pub mod lookups;

pub use node_index::{SpendIndex, SpendingRef};
