//! Native Esplora REST handlers, sharing satd's chainstate.
//!
//! Compatible with the `blockstream.info` / `mempool.space` HTTP API.
//! See `ECOSYSTEM.md` §4 / §4a for the architectural rationale (one
//! RocksDB instance, atomic reorg consistency, sub-millisecond index
//! lookups). This crate ships the handlers; `satd` mounts them on a
//! configurable port behind optional cookie / userpass auth.
//!
//! Scope by milestone (per the Esplora plan):
//! - PR 2 (this PR): scaffolding + `/blocks/tip/hash`, `/blocks/tip/height`,
//!   `/blocks[/:start_height]`, `/block-height/:h`. Auth, CORS, timeout,
//!   concurrency-limit middleware.
//! - PR 3-7: block / tx / address / outspend / mempool / fee endpoints.
//! - PR 9: WebSocket + SSE.

pub mod auth;
pub mod config;
pub mod encode;
pub mod error;
pub mod handlers;
pub mod router;
pub mod state;

pub use config::{EsploraAuth, EsploraConfig};
pub use error::EsploraError;
pub use router::{RouterBuildError, build_router};
pub use state::EsploraState;
