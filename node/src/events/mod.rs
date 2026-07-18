//! Pluggable transport bus for satd.
//!
//! Wraps the existing [`crate::mempool::events::MempoolEvent`] and
//! [`crate::chain::events::ChainEvent`] broadcasts in a versioned,
//! edge-stamped [`NodeEvent`] envelope. External transports (gRPC, ZMQ,
//! NATS, …) attach via the [`EventSink`] trait without touching the
//! consensus / mempool hot paths.
//!
//! The internal Rust consumers (Esplora SSE, address-index notifier,
//! `subscribemempool` JSON-RPC, reorg-webhook dispatcher) keep using the
//! raw broadcasts directly — this module is purely additive.
//!
//! Module layout:
//! - [`envelope`] — `NodeEvent`, `NodeEventBody`, `EdgeStamp`, `EdgeIdentity`.
//! - [`publisher`] — `EventPublisher` daemon-level service that bridges
//!   the internal broadcasts into envelopes, drives a 1 Hz heartbeat,
//!   and supervises sink tasks.
//! - [`sink`] — `EventSink` trait, runtime helpers.
//! - [`schema`] — schema-version constant and evolution rules.

pub mod envelope;
pub mod publisher;
pub mod replay;
pub mod schema;
pub mod sink;
pub mod watch;

pub use envelope::{
    BlockTweaks, Cursor, CursorRejectReason, EdgeIdentity, EdgeStamp, NodeEvent, NodeEventBody,
    SetCursorOutcome, SpTweakEntry, ALL_CATEGORIES_DEFAULT, CATEGORY_CHAIN, CATEGORY_HEARTBEAT,
    CATEGORY_MEMPOOL, CATEGORY_TWEAKS, EXPLICIT_ONLY_CATEGORIES,
};
pub use publisher::{EventPublisher, TweakSubscriberGuard, ENVELOPE_BROADCAST_CAPACITY};
pub use replay::{
    build_cursor_replay, cursor_accepted_event, cursor_rejected_event, lagged_event, plan_rescan,
    BlockCursorSource, BlockScanSource, CursorReplay, RescanPlan, RescanRejectReason,
    MAX_REPLAY_BLOCKS, MAX_RESCAN_BLOCKS,
};
pub use schema::SCHEMA_VERSION;
pub use sink::EventSink;
pub use watch::{
    prefix_bucket_key, run_watch_matcher, PrefixMatch, SpentPrevoutMeta, WatchHandle, WatchMatch,
    WatchRegistry, WATCH_CHANNEL_CAPACITY,
};
