//! BIP 352 silent-payment tweak index — kernel, schema types, cursor, config.
//!
//! This crate is the boundary between the silent-payment-index
//! implementation (which lives in `node` because it needs `Store` /
//! `ChainState`) and consumers that only want the pure pieces: the
//! BIP 352 crypto kernel (`compute`), the row/key codec (`keys`), the
//! read trait (`SpIndex`), the backfill cursor, and the config.
//!
//! Mirrors the workspace pattern set by `node-filter-index`: the runtime
//! impl lives in `node/src/index/silent_payments/`, the trait, types,
//! codec, and — uniquely here — the shared BIP 352 kernel live in this
//! crate so both the index writer and the scan-key matcher (Tier 2) run
//! the *same* extraction and derivation code. The SDK's client-side
//! scanner (`sp_light_scan`) links the same kernel, so "the node computed
//! this tweak" and "the wallet scanned this tweak" can never diverge.
//!
//! The only cryptographic dependency is `bitcoin::secp256k1`, already in
//! the workspace tree (design decision D5): BIP 352 uses the full
//! compressed ECDH point, not a hashed x-coordinate, so no new "ecdh"
//! feature is needed.

pub mod compute;
pub mod config;
pub mod cursor;
pub mod keys;
pub mod trait_def;
pub mod types;

pub use compute::{
    K_MAX, SpMatch, TaprootOutput, TweakEntry, compute_tweak, eligible_inputs, scan_outputs,
    taproot_outputs,
};
pub use config::SpIndexConfig;
pub use cursor::{BackfillCursor, BackfillState};
pub use keys::{
    CF_SP_TWEAKS, SP_KEY_LEN, SP_TWEAKS_VERSION, SpBlockRow, decode_sp_key, encode_sp_key,
};
pub use trait_def::SpIndex;
pub use types::{SpCodecError, SpIndexError};
