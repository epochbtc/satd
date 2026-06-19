//! Async Rust client SDK for the satd Streaming Consumption API
//! (`satd.events.v1`).
//!
//! It wraps the generated tonic client with a typed event model, auth metadata
//! injection, and cursor capture, so a consumer writes against [`StreamClient`]
//! instead of hand-rolling channels, metadata, and protobuf unwrapping.
//!
//! ```no_run
//! use satd_events_client::{StreamClient, SubscribeOptions, Categories, Event};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = StreamClient::builder("http://127.0.0.1:50051")
//!     .bearer_token("…")
//!     .keepalive_default()
//!     .connect()
//!     .await?;
//!
//! let mut events = client.subscribe(SubscribeOptions {
//!     categories: Categories::MEMPOOL | Categories::CHAIN,
//!     ..Default::default()
//! }).await?;
//!
//! while let Some(event) = events.message().await? {
//!     match event {
//!         Event::BlockConnected { height, .. } => println!("block {height}"),
//!         Event::MempoolEnter { fee, vsize, .. } => println!("tx {fee}/{vsize}"),
//!         Event::Lagged { resume_cursor, .. } => {
//!             // reconnect with `resume_cursor` to recover the gap
//!             let _ = resume_cursor;
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Scope (this revision)
//!
//! - [`StreamClient::subscribe`] — the full firehose with `from_cursor` replay
//!   and cursor capture.
//! - [`StreamClient::watch`] — opens the bidirectional stream and returns a
//!   [`WatchHandle`] with typed helpers for every watch kind: `add_scripts`
//!   (with per-script `min_value` floors), `add_outpoints`, `add_tx_lifecycle` /
//!   `add_depth_alarms`, `add_descriptor`, and `add_script_prefixes` (the
//!   privacy-preserving prefix watch), plus `set_categories` / `set_cursor` and
//!   the matching `remove_*`. [`send_control`](WatchHandle::send_control) remains
//!   for raw access.
//!
//! - [`StreamClient::resilient_subscribe`] — the firehose wrapped in a
//!   [`ResilientSubscription`] that reconnects with backoff, persists and
//!   replays the durable cursor (via a [`CursorStore`]), recovers from `Lagged`
//!   per a [`LagPolicy`], and surfaces replay-truncation gaps.
//! - [`PrefixWatcher`] (default-on `bitcoin` feature) — the privacy-preserving
//!   prefix-watch local re-filter: decodes a [`PrefixMatch`]'s `raw_tx` and
//!   recomputes `sha256(scriptPubKey)` to keep only true matches.
//!
//! TLS is layered on next. The raw wire types are re-exported under [`proto`]
//! for low-level use.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod event;
#[cfg(feature = "bitcoin")]
mod prefix;
mod resilience;

pub use client::{
    AutoClose, Categories, EventStream, StreamClient, StreamClientBuilder, SubscribeOptions,
    WatchHandle,
};
pub use error::StreamError;
pub use event::{
    Cursor, Event, EvictReason, Outpoint, PrefixMatch, ScriptPrefix, SpentPrevout,
};
pub use resilience::{
    Backoff, CursorStore, FileCursorStore, LagPolicy, NoopCursorStore, ResilientConfig,
    ResilientSubscription,
};

#[cfg(feature = "bitcoin")]
pub use prefix::{
    prefix_of, scripthash_of, FundingHit, PrefixHits, PrefixWatcher, SpendingHit,
};

/// The generated `satd.events.v1` wire types, for low-level control-message
/// construction until typed helpers cover every case.
pub use satd_events_proto::v1 as proto;
