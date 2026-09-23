//! A solo-mining Stratum server.
//!
//! A miner connects to the node directly, receives work built from the
//! node's own block template, and has the blocks it finds accepted and
//! relayed by the same process. There is no pool: no share accounting, no
//! payout splitting. The username a miner presents is the address its
//! coinbase pays.
//!
//! The protocol-agnostic core — [`template`], [`job`], [`share`] and
//! [`vardiff`] — turns a [`BlockTemplate`](crate::mining::template::BlockTemplate)
//! into hashable work and judges what comes back. [`v1`] speaks Stratum V1
//! (line-delimited JSON-RPC) on top of it, and `v2` speaks Stratum V2 (behind
//! the `stratum-v2` feature); [`server`] owns the listeners and the template
//! refresh loop.

pub mod config;
pub mod found;
pub mod job;
pub mod miner;
pub mod server;
pub mod share;
pub mod template;
pub mod tls;
pub mod v1;
#[cfg(feature = "stratum-v2")]
pub mod v2;
pub mod vardiff;

#[cfg(test)]
mod winning_block_tests;

pub use config::{StratumConfig, V2Config, default_initial_difficulty, resolve_payout, should_issue_work};
pub use server::{StratumHandle, StratumServer, StratumServerError, StratumStats};
