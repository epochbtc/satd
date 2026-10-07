//! External event-streaming adapters for the satd pluggable transport
//! bus. Each adapter is feature-gated so consumers of this crate pull in
//! only the dependencies they need:
//!
//! - `grpc` — `tonic`-based server-streaming gRPC adapter.
//! - `zmq`  — ZMQ PUB sockets: the satd-native `-eventszmqbind` sink and
//!   Bitcoin Core's `-zmqpub*` notifications.
//!
//! The bus core lives in `node::events`; this crate only contains the
//! adapter-side glue.

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "grpc")]
pub mod proto {
    //! Generated protobuf types, re-exported from the `satd-events-proto`
    //! codegen crate so the wire schema has a single source of truth. Paths are
    //! unchanged for downstream consumers: `satd_events::proto::satd::events::v1`
    //! and the short alias `satd_events::proto::v1`.
    pub use satd_events_proto::{satd, v1};
}

#[cfg(feature = "grpc")]
pub use grpc::{GrpcEventSink, GrpcEventSinkError, GrpcLimits, GrpcTlsParams};

#[cfg(feature = "zmq")]
pub mod zmq;

// In-tree ZMTP 3.0 PUB server for the Core-compatible `-zmqpub*` topics.
#[cfg(feature = "zmq")]
pub mod zmtp;

// Bitcoin Core's `-zmqpub*` notifications, published from the event bus.
#[cfg(feature = "zmq")]
pub mod core_zmq;

#[cfg(feature = "zmq")]
pub use core_zmq::{CoreZmqBindError, CoreZmqChain, CoreZmqMempool, CoreZmqSink};

#[cfg(feature = "zmq")]
pub use zmq::{ZmqEventSink, ZmqEventSinkError, ZmqTopicConfig};

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "ws")]
pub use ws::{WsLimits, WsStreamError, WsStreamServer};

// Descriptor convenience layer — shared by the gRPC and WS watch surfaces.
#[cfg(any(feature = "grpc", feature = "ws"))]
pub mod descriptor;

// Per-subscription watch-set with per-item quota leases (cross-message dedup +
// per-remove release) — shared by the gRPC and WS watch surfaces.
#[cfg(any(feature = "grpc", feature = "ws"))]
pub(crate) mod watchset;

// Category-level authorization, shared by the gRPC and WS/SSE carriers.
#[cfg(any(feature = "grpc", feature = "ws"))]
pub(crate) mod catauth;
