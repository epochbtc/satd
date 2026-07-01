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
//! - [`StreamClient::resilient_watch`] — the bidirectional `Watch` stream
//!   wrapped in a [`ResilientWatch`] that mirrors the watch-set and
//!   re-registers it on reconnect (watch-sets are per-connection), then
//!   re-anchors off the deterministic [`Event::CursorAccepted`] /
//!   [`Event::CursorRejected`] results, retrying transient rejects in place and
//!   surfacing the rest for a resnapshot. Integrators with a durable watch-set
//!   source-of-truth can install a
//!   [`watch_set_loader`](ResilientWatchConfig::watch_set_loader) to rebuild the
//!   canonical set from that truth on every (re)connect.
//! - [`PrefixWatcher`] (default-on `bitcoin` feature) — the privacy-preserving
//!   prefix-watch local re-filter: decodes a [`PrefixMatch`]'s `raw_tx` and
//!   recomputes `sha256(scriptPubKey)` to keep only true matches.
//!
//! ## TLS / mTLS (default-on `tls` feature)
//!
//! Builder methods encrypt the gRPC transport so a bearer token (and the event
//! stream) never travels in cleartext:
//!
//! - [`tls`](StreamClientBuilder::tls) — TLS with the bundled Mozilla roots
//!   (public-CA servers).
//! - [`tls_ca_pem`](StreamClientBuilder::tls_ca_pem) — pin a private / self-signed
//!   CA, the usual case for a satd node serving its own certificate.
//! - [`tls_client_identity`](StreamClientBuilder::tls_client_identity) — present a
//!   client certificate for mutual TLS (`-eventsgrpcmtls`).
//! - [`tls_domain`](StreamClientBuilder::tls_domain) — override the verified
//!   certificate name (SNI) when connecting by IP or through a proxy.
//!
//! ```no_run
//! # use satd_events_client::StreamClient;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let ca = std::fs::read("node-ca.pem")?;
//! let client = StreamClient::builder("https://node.example:50051")
//!     .tls_ca_pem(ca)
//!     .bearer_token("…")
//!     .connect()
//!     .await?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```
//!
//! TLS uses the `ring` rustls provider. Opt out with `default-features = false`
//! for a plaintext-only build. The raw wire types are re-exported under
//! [`proto`] for low-level use.
//!
//! ## Stability & versioning
//!
//! The SDK tracks the **additive `satd.events.v1` wire schema**, not the node's
//! release cadence: new optional fields and event / watch kinds are added
//! without breaking existing consumers, and the crate follows [semver]
//! independently of the satd node version — a node and SDK do **not** need
//! matching versions. The generated wire types are re-exported under [`proto`]
//! so you can pin to the schema directly when a typed helper does not yet cover
//! your case. Minimum supported Rust version (**MSRV**) is **1.93**; an MSRV
//! bump is treated as a minor-version change.
//!
//! See the [wire/streaming spec][spec] for the underlying gRPC contract and the
//! [`satd-events-proto`][proto-crate] crate for the generated types.
//!
//! [semver]: https://semver.org/
//! [spec]: https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md
//! [proto-crate]: https://docs.rs/satd-events-proto

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod event;
#[cfg(feature = "bitcoin")]
mod prefix;
mod resilience;
mod resilient_watch;

pub use client::{
    AutoClose, Categories, EventStream, StreamClient, StreamClientBuilder, SubscribeOptions,
    WatchHandle,
};
pub use error::StreamError;
pub use event::{
    Cursor, CursorRejectReason, Event, EvictReason, Outpoint, PrefixMatch, ScriptPrefix,
    SpentPrevout,
};
pub use resilience::{
    Backoff, CursorStore, FileCursorStore, LagPolicy, NoopCursorStore, ResilientConfig,
    ResilientSubscription,
};
pub use resilient_watch::{ResilientWatch, ResilientWatchConfig, WatchSetBuilder};

#[cfg(feature = "bitcoin")]
#[cfg_attr(docsrs, doc(cfg(feature = "bitcoin")))]
pub use prefix::{
    prefix_of, scripthash_of, FundingHit, PrefixHits, PrefixWatcher, SpendingHit,
};

/// The generated `satd.events.v1` wire types, for low-level control-message
/// construction until typed helpers cover every case.
pub use satd_events_proto::v1 as proto;
