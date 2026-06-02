//! `satd-auth` — unified authentication + authorization for satd's API surfaces.
//!
//! A single, transport-agnostic credential model and policy engine that every
//! satd surface (JSON-RPC, Esplora, Electrum, MCP, gRPC streaming) shares,
//! without breaking Bitcoin Core compatibility. See `SATD_AUTH_PLAN.md` for the
//! full design.
//!
//! # Shape
//!
//! - A surface's carrier adapter extracts a [`Credential`] from its native
//!   transport (HTTP `Authorization` header, gRPC metadata, mTLS leaf).
//! - [`Verifier::resolve`] turns it into a [`Principal`] — an identity plus a
//!   [`CapabilitySet`] and quota/rate ceilings — or an [`AuthError`].
//! - The surface enforces the required [`Capability`] with [`Principal::require`].
//!
//! Default behavior is unchanged: with no `authfile` configured, only the
//! Core-compatible operator path (cookie / `-rpcuser` / `-rpcauth`) is live, and
//! it resolves to a full-capability operator [`Principal`].
//!
//! # mTLS ↔ token precedence
//!
//! Transport mTLS (the `tls-config` crate) composes *underneath* this layer and
//! gates the connection. When a bearer token is also presented, the **token
//! refines the principal/capabilities**; absent a token, the mTLS leaf subject
//! is the principal (Electrum phase). This crate never does transport TLS.
//!
//! This PR ships the foundation (credential model, token store, verifier,
//! operator mapping, quota traits). Per-surface wiring and the local quota/rate
//! enforcement backends land in subsequent PRs.

mod capability;
mod credential;
mod error;
mod operator;
mod principal;
mod quota;
mod store;
mod verify;

pub use capability::{Capability, CapabilitySet};
pub use credential::Credential;
pub use error::{AuthError, DenyReason, StoreError};
pub use operator::{CookieCredential, OperatorCreds, RpcAuthCredential, UserPassCredential};
pub use principal::{Principal, PrincipalKind};
pub use quota::{
    Accounting, QuotaExceeded, QuotaStore, RateDecision, RateLimiter, RatePolicy,
    UnlimitedAccounting, WatchLease,
};
pub use store::{ReloadDelta, TokenEntry, TokenStore, TokenTable};
pub use verify::Verifier;
