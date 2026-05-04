//! Method handlers for the Electrum JSON-RPC surface.
//!
//! Split by namespace:
//! - [`server_methods`] — `server.*`
//! - [`blockchain`] — `blockchain.*`
//! - [`mempool`] — `mempool.*`
//!
//! Each handler is `fn(state, params) -> Result<Value, JsonRpcError>`,
//! synchronous, no transport coupling. The dispatch layer
//! ([`crate::dispatch::dispatch`]) wraps the result into a JSON-RPC
//! [`Response`](crate::dispatch::Response).

pub mod blockchain;
pub mod mempool;
pub mod server_methods;
