pub mod adaptive_cache;
pub mod chain;
pub mod ibd_eta;
pub mod memstat;
pub mod mempool;
pub mod metrics;
pub mod mining;
pub mod net;
pub mod perf;
pub mod rpc;
pub mod shutdown;
pub mod storage;
pub mod validation;
pub mod warnings;

/// BIP 14 user agent string, derived from Cargo.toml version at compile time.
pub const USER_AGENT: &str = concat!("/satd:", env!("CARGO_PKG_VERSION"), "/");
