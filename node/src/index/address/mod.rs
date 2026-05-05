//! Address-history index — funding and spending rows keyed by
//! `sha256(scriptPubKey)`. Backs the operator-facing RPCs and the
//! native Electrum / Esplora subsystems described in `ECOSYSTEM.md`.
//!
//! Pure types (the `AddressIndex` trait, key/row codec, `BackfillCursor`,
//! `AddressIndexConfig`, error types, `SubscriptionRegistry`) live in
//! the sibling `node-index` crate so future Electrum / Esplora protocol
//! crates can depend on those without pulling in `Store` / `Mempool` /
//! `ChainState`. This module re-exports them under the historical
//! `crate::index::address` path so internal call sites stay stable, and
//! owns the runtime implementation files (`emit`, `lookups`, `mempool`,
//! `notifier`, `backfill`, `runner`, `stats`) that bind the trait to
//! `Store`-backed concrete types.

pub mod backfill;
pub mod emit;
pub mod lookups;
pub mod mempool;
pub mod notifier;
pub mod runner;
pub mod stats;

pub use node_index::{config, cursor, keys, subscribe, trait_def, types};

pub use backfill::{BackfillError, BackfillHandle, StatusReport, render_status};
pub use runner::{BackfillCommand, BackfillRunner, PREFLIGHT_REQUIRED_FREE_BYTES, preflight_disk};
pub use node_index::AddressIndexConfig;
pub use node_index::{BackfillCursor, BackfillState};
pub use emit::{emit_funding, emit_spending, funding_remove_key, spending_remove_key};
pub use node_index::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, Scripthash,
    decode_funding_key, decode_funding_value, decode_spending_key, decode_spending_value,
    encode_funding_key, encode_funding_value, encode_spending_key, encode_spending_value,
    scripthash_of,
};
pub use lookups::RocksAddressIndex;
pub use mempool::{MempoolAddrIndex, NotifyBundle, mempool_index_task};
pub use notifier::notifier_task;
pub use node_index::{SubscribeError, SubscriptionRegistry, status_hash};
pub use node_index::AddressIndex;
pub use node_index::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
