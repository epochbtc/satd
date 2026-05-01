//! Address-history index — funding and spending rows keyed by
//! `sha256(scriptPubKey)`. Backs the operator-facing RPCs and the
//! native Electrum / Esplora subsystems described in `ECOSYSTEM.md`
//! and `ADDRESS_INDEX.md`.
//!
//! This module owns the on-disk schema (CFs, key/row codec) and the
//! runtime-config struct. Higher-level functionality — connect/
//! disconnect emission, lookup trait impls, mempool variant, the
//! subscription registry, and the deferred backfill — lands in
//! follow-up PRs (M2-M7).

pub mod backfill;
pub mod config;
pub mod cursor;
pub mod emit;
pub mod keys;
pub mod lookups;
pub mod mempool;
pub mod notifier;
pub mod runner;
pub mod stats;
pub mod subscribe;
pub mod trait_def;
pub mod types;

pub use backfill::{BackfillError, BackfillHandle, StatusReport, render_status};
pub use runner::{BackfillCommand, BackfillRunner, PREFLIGHT_REQUIRED_FREE_BYTES, preflight_disk};
pub use config::AddressIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use emit::{emit_funding, emit_spending, funding_remove_key, spending_remove_key};
pub use keys::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, Scripthash,
    decode_funding_key, decode_funding_value, decode_spending_key, decode_spending_value,
    encode_funding_key, encode_funding_value, encode_spending_key, encode_spending_value,
    scripthash_of,
};
pub use lookups::RocksAddressIndex;
pub use mempool::{MempoolAddrIndex, NotifyBundle, mempool_index_task};
pub use notifier::notifier_task;
pub use subscribe::{SubscribeError, SubscriptionRegistry, status_hash};
pub use trait_def::AddressIndex;
pub use types::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
