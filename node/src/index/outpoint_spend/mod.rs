//! Confirmed-side spend index — `prev_outpoint -> SpendingRef`.
//!
//! Maintained atomically with `connect_block` / `disconnect_block` and
//! the address-history index, gated on the same `--addressindex=N`
//! flag (the spend index is a strict superset of the addr-spending
//! lookup; turning off the address index turns this off too).
//!
//! Consumers:
//! - Esplora `/tx/:txid/outspend/:vout` and `/tx/:txid/outspends`
//! - `gettxspendingprevout` RPC for confirmed inputs (mempool inputs
//!   stay in the mempool's existing tracker)
//! - Future Electrum `blockchain.outpoint.subscribe` (post-M5)
//!
//! Schema and codec live in `node-index::spend_keys`. This module
//! contains only the integration surface (emit helpers, lookup
//! adapter).

pub mod emit;
pub mod lookups;

pub use node_index::{SpendIndex, SpendingRef};
