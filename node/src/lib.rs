pub mod chain;
pub mod mempool;
pub mod mining;
pub mod net;
pub mod perf;
pub mod rpc;
pub mod storage;
pub mod validation;

/// BIP 14 user agent string, derived from Cargo.toml version at compile time.
pub const USER_AGENT: &str = concat!("/satd:", env!("CARGO_PKG_VERSION"), "/");
