//! Address-history index — trait, schema types, cursor, config.
//!
//! This crate is the boundary between the address-index implementation
//! (which lives in `node` because it needs `Store` / `Mempool` /
//! `ChainState`) and consumers that only want the read surface (the
//! `AddressIndex` trait, key/row codec, `BackfillCursor`, etc.).
//!
//! Future Electrum and Esplora protocol crates depend on this crate
//! alone; they receive an `Arc<dyn AddressIndex>` at runtime that the
//! `node` crate constructs.

pub mod config;
pub mod cursor;
pub mod keys;
pub mod subscribe;
pub mod trait_def;
pub mod types;

pub use config::AddressIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use keys::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, Scripthash,
    decode_funding_key, decode_funding_value, decode_spending_key, decode_spending_value,
    encode_funding_key, encode_funding_value, encode_spending_key, encode_spending_value,
    scripthash_of,
};
pub use subscribe::{SubscribeError, SubscriptionRegistry, status_hash};
pub use trait_def::AddressIndex;
pub use types::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
