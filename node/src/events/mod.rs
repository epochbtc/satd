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
pub mod schema;
pub mod sink;

pub use envelope::{EdgeIdentity, EdgeStamp, NodeEvent, NodeEventBody};
pub use publisher::{EventPublisher, ENVELOPE_BROADCAST_CAPACITY};
pub use schema::SCHEMA_VERSION;
pub use sink::EventSink;
