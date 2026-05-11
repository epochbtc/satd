//! Electrum protocol server for satd.
//!
//! Architecturally this crate is the Electrum analogue of
//! [`esplora-handlers`]: a thin protocol layer that calls into satd's
//! shared chainstate via the `node-index` trait surface
//! ([`AddressIndex`](node_index::AddressIndex),
//! [`SpendIndex`](node_index::SpendIndex)) plus the
//! [`extras::ElectrumExtras`] shim defined here for the surface that
//! lives outside the index proper (raw tx bytes, block headers by
//! height, merkle proofs, txid-by-position).
//!
//! See `ECOSYSTEM.md` §4 / §4a for the architectural rationale (single
//! binary, native, shared chainstate). The `node-index` crate's
//! module-level docs describe the trait surface this protocol crate
//! consumes.
//!
//! Design lineage: the wire protocol shape (method names, JSON
//! payloads, status-hash construction, merkle-proof encoding) follows
//! `romanz/electrs`. See `vendor/electrs.MIT` for attribution and the
//! upstream MIT LICENSE.
//!
//! Scope by milestone (per the Electrum plan):
//! - **PR-1 (this PR)**: crate scaffold, leaf modules
//!   ([`types`], [`status`], [`merkle`]), and the
//!   [`extras::ElectrumExtras`] trait. No transport, no method
//!   dispatch yet.
//! - PR-2: method handlers + dispatch.
//! - PR-3: TCP transport + JSON-RPC line protocol.
//! - PR-4: per-connection subscriptions.
//! - PR-5: TLS support (`tokio-rustls`).
//! - PR-6: wiring in `satd/main.rs` + ops docs.

pub mod config;
pub mod dispatch;
pub mod error;
pub mod extras;
pub mod handlers;
pub mod merkle;
pub mod rpc;
pub mod server;
pub mod state;
pub mod status;
pub mod subscribe;
pub mod types;

pub use config::ElectrumConfig;
pub use dispatch::{
    Notification, Request, Requests, Response, dispatch, dispatch_with_subscriptions,
};
pub use error::JsonRpcError;
pub use extras::{ElectrumExtras, RocksElectrumExtras, TxConfirmation, TxMerkleProof};
pub use merkle::{compute_merkle_branch, merkle_root};
pub use server::{
    BoxedDispatch, ConnectionFactory, ElectrumServer, ElectrumServerError, state_connection_factory,
};
pub use state::ElectrumState;
pub use status::compute_status_hash;
pub use subscribe::{HeadersSource, NOTIFY_CHANNEL_CAP, Subscriptions};
pub use types::{
    BalanceResponse, FeeHistogramEntry, GetMerkleResponse, HeadersResponse, HistoryEntry,
    ListUnspentEntry, ScripthashHex, TxidHex,
};

/// Electrum protocol version this server reports via `server.version`.
/// Matches `romanz/electrs` v0.11.1
/// (commit `35216c6d30148be8e6763d913d437330f431fc03`,
/// `src/electrum.rs::PROTOCOL_VERSION`). The single-string form means
/// `server.version` negotiation expects an exact match — the client's
/// stated version must be `1.4` to be acceptable, just like electrs.
pub const PROTOCOL_VERSION: &str = "1.4";
