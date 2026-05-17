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
pub mod spend_keys;
pub mod spend_trait;
pub mod subscribe;
pub mod trait_def;
pub mod types;

pub use config::AddressIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use keys::{
    AddrFundingKey, AddrFundingKeyV2Payload, AddrFundingRow, AddrSpendingKey,
    AddrSpendingKeyV2Payload, AddrSpendingRow, KEY_LEN_V2, SCRIPTHASH_PREFIX_LEN, Scripthash,
    decode_funding_key_v2, decode_funding_value, decode_spending_key_v2, decode_spending_value,
    encode_funding_key_v2, encode_funding_value, encode_spending_key_v2, encode_spending_value,
    reconstruct_funding_key, reconstruct_spending_key, scripthash_of,
};
pub use spend_keys::{
    OUTPOINT_KEY_LEN, SPEND_VALUE_LEN, SpendingRef, decode_outpoint_key, decode_spend_value,
    encode_outpoint_key, encode_spend_value,
};
pub use spend_trait::SpendIndex;
pub use subscribe::{SubscribeError, SubscriptionRegistry, status_hash};
pub use trait_def::AddressIndex;
pub use types::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
