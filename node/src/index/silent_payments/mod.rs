//! BIP 352 silent-payment tweak index — runtime implementation.
//!
//! The BIP 352 kernel, row/key codec, backfill cursor, read trait, and
//! config live in the sibling `node-sp-index` crate so protocol-side
//! consumers can depend on those without pulling in `Store` /
//! `ChainState`. This module owns the emit helper (`build_sp_row`,
//! called from `connect_block` / `disconnect_block`). The backfill
//! runner and the `RocksSpIndex` read impl arrive in later PRs.
//!
//! Unlike the filter index, the SP index is **always compiled** and
//! gated purely at runtime (`silentpaymentindex=1`), following the
//! address-index model — the only new dependency surface is
//! `bitcoin::secp256k1`, already in the tree (design decision D5).

pub mod backfill;
pub mod emit;
pub mod runner;
pub mod stats;

pub use backfill::{
    BackfillError, BackfillHandle, PREFLIGHT_REQUIRED_FREE_BYTES, StatusReport, render_status,
};
pub use emit::{EmitError, build_sp_row};
pub use runner::{BackfillCommand, BackfillRunner, preflight_disk};

pub use node_sp_index::cursor::{self, BackfillCursor, BackfillState};
pub use node_sp_index::{
    CF_SP_TWEAKS, SP_TWEAKS_VERSION, SpBlockRow, SpIndex, SpIndexConfig, SpIndexError, TweakEntry,
    compute_tweak, eligible_inputs, scan_outputs,
};
