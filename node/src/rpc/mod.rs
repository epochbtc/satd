//! JSON-RPC surfaces: the server, its middleware layers, and the
//! per-method handler modules.

/// Maximum JSON-RPC **request** body size, in bytes.
///
/// This is the DoS guard: it bounds what an authenticated caller can make
/// the node buffer before it has decided anything. It binds the jsonrpsee
/// `ServerConfig`'s `max_request_body_size` (shared by the full and
/// read-only listeners) and the JSON-RPC 1.0 compat shim that buffers a
/// request body to rewrite its `jsonrpc` member.
///
/// It is 20 MiB rather than jsonrpsee's 10 MiB default because Core's
/// functional suite exercises `echo` with two 8 MiB arguments
/// (`ARG_SZ_LARGE` in `rpc_misc.py`), which a 10 MiB cap rejects.
pub(crate) const RPC_MAX_BODY_SIZE: usize = 20 * 1024 * 1024;

/// Maximum JSON-RPC **response** body size, in bytes.
///
/// Bitcoin Core has no response cap at all: `evhttp_set_max_body_size`
/// (src/httpserver.cpp) bounds the request body, and `WriteReply` writes
/// whatever the method produced. satd used to bind both directions to
/// [`RPC_MAX_BODY_SIZE`], which meant a request-shaped budget was policing
/// replies whose size is set by the chain and the mempool, not by the
/// caller. `getrawmempool verbose` crosses 20 MiB at roughly 17,000
/// mempool transactions — an ordinary mainnet mempool — and satd answered
/// `-32008 Response is too big` where Core answers the call (#723).
///
/// The figure is derived rather than round. Verbose mempool JSON measures
/// about 0.76x the mempool's own serialised bytes, so the default
/// `-maxmempool=300` (286 MiB) tops out near 217 MiB of reply. 256 MiB
/// covers that with headroom, which makes the guarantee "a node at its
/// default mempool ceiling can still answer `getrawmempool verbose`".
///
/// A node configured with a larger `-maxmempool` can still outgrow this.
/// That is a deliberate stopping point: the alternative is an unbounded
/// reply, and jsonrpsee buffers the whole thing, so this number is also
/// the per-in-flight-request memory ceiling. Making it configurable is the
/// follow-up, not this constant's job.
pub(crate) const RPC_MAX_RESPONSE_SIZE: usize = 256 * 1024 * 1024;

pub mod active_commands;
pub mod access;
pub mod address;
pub mod admission;
pub mod allowip;
pub mod address_decode;
pub mod amounts;
pub mod auth;
pub mod blockchain;
pub mod capability;
pub mod compat;
pub mod descriptor;
pub mod error;
pub mod indexes;
pub mod logging;
pub mod mining;
pub mod named_params;
pub mod network;
pub mod params;
pub mod policy;
pub mod psbt;
pub mod psbt_v2;
pub mod rawtx;
pub mod readonly;
pub mod warmup;
pub mod server;
pub mod util;
