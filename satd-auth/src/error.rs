//! Error types for the auth crate.

use thiserror::Error;

/// An authentication failure: the presented credential could not be resolved to
/// a [`Principal`](crate::Principal).
///
/// These map to transport-level rejections at each surface (HTTP 401, gRPC
/// `UNAUTHENTICATED`). They deliberately carry no detail about *why* a token
/// failed — a verifier must not leak whether a token id exists.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AuthError {
    /// No credential was presented (no `Authorization` header / metadata).
    #[error("no credential presented")]
    Missing,
    /// A credential was presented but did not match any known principal
    /// (bad token, wrong password, expired token, revoked token).
    #[error("credential not recognized")]
    Unauthenticated,
    /// The credential *kind* is not supported on this surface yet (e.g. an
    /// mTLS client-cert principal before the Electrum phase lands).
    #[error("credential type not supported")]
    Unsupported,
}

/// Errors raised while *loading* or *reloading* the TOML token store. Distinct
/// from [`AuthError`]: these are operator-facing configuration faults surfaced
/// at startup (fatal) or on SIGHUP (logged; the last-good table is retained).
#[derive(Debug, Error)]
pub enum StoreError {
    /// The file could not be read.
    #[error("cannot read auth file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The file is group/world-accessible or has an execute bit — i.e. not a
    /// strictly owner-readable secret (`0600` / `0400`).
    #[error(
        "auth file {path} has unsafe permissions (mode {mode:#o}): it must be \
         readable only by its owner with no execute bit; set it to 0600 \
         (or 0400 for a read-only secret)"
    )]
    Permissions { path: String, mode: u32 },
    /// The TOML failed to parse, or a `[[token]]` entry was malformed.
    #[error("auth file {path}: {detail}")]
    Malformed { path: String, detail: String },
}

/// Why an authenticated principal was denied an operation: the capability it
/// lacked.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("principal lacks required capability `{0}`")]
pub struct DenyReason(pub &'static str);
