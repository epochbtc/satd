//! JSON-RPC surfaces: the server, its middleware layers, and the
//! per-method handler modules.

/// Maximum JSON-RPC request/response body size, in bytes.
///
/// Every RPC surface is bound by this one number: the jsonrpsee
/// `ServerConfig` (`max_request_body_size` / `max_response_body_size`,
/// shared by the full and read-only listeners), the JSON-RPC 1.0 compat
/// shim that buffers a request body to rewrite its `jsonrpc` member, and
/// the batch-response builders in [`readonly`] and [`capability`] that
/// must not emit a batch the inner service would then refuse.
///
/// It is 20 MiB rather than jsonrpsee's 10 MiB default because Core's
/// functional suite exercises `echo` with two 8 MiB arguments
/// (`ARG_SZ_LARGE` in `rpc_misc.py`), which a 10 MiB cap rejects.
pub(crate) const RPC_MAX_BODY_SIZE: usize = 20 * 1024 * 1024;

pub mod access;
pub mod address;
pub mod admission;
pub mod allowip;
pub mod amounts;
pub mod auth;
pub mod blockchain;
pub mod capability;
pub mod compat;
pub mod descriptor;
pub mod error;
pub mod indexes;
pub mod mining;
pub mod named_params;
pub mod network;
pub mod params;
pub mod policy;
pub mod psbt;
pub mod rawtx;
pub mod readonly;
pub mod warmup;
pub mod server;
pub mod util;
