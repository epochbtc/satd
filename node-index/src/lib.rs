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
pub mod txseq;
pub mod types;

pub use config::AddressIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use keys::{
    AddrFundingKey, AddrFundingKeyV3, AddrFundingKeyV3Payload, AddrFundingRow, AddrFundingRowV3,
    AddrSpendingKey, AddrSpendingKeyV2Payload, AddrSpendingRow, KEY_LEN_V2, KEY_LEN_V3,
    SCRIPTHASH_PREFIX_LEN, Scripthash, decode_funding_key_v3, decode_funding_value,
    decode_spending_key_v2, decode_spending_value, encode_funding_key_v3, encode_funding_value,
    encode_spending_key_v2, encode_spending_value, reconstruct_funding_key_v3,
    reconstruct_spending_key, scripthash_of,
};
pub use spend_keys::{
    SPENT_KEY_LEN, SPENT_VALUE_LEN, SpendingRef, SpentRow, decode_spent_key, decode_spent_value,
    encode_spent_key, encode_spent_value,
};
pub use spend_trait::SpendIndex;
pub use subscribe::{SubscribeError, SubscriptionRegistry, status_hash};
pub use trait_def::AddressIndex;
pub use txseq::{
    TXSEQ_LEN, TXSEQ_MAX, TXSEQ_UNKNOWN, TxSeq, VOUT_LEN, VOUT_MAX, decode_txseq, decode_u24,
    encode_txseq, encode_u24,
};
pub use types::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
