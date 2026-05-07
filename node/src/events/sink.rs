//! [`EventSink`] — the trait every external transport adapter implements.
//!
//! Each adapter owns its own subscribe-and-deliver loop, so transports
//! can have wildly different lifecycles (gRPC: one short-lived task per
//! client; ZMQ: one long-lived PUB socket; NATS: one long-lived
//! publisher). The trait exists to standardize how the
//! [`super::EventPublisher`] hands a sink its event stream and shutdown
//! signal — not to enforce per-event delivery semantics.
//!
//! Lag handling is the sink's responsibility. Mirror the existing
//! Esplora SSE pattern (`tokio_stream::wrappers::BroadcastStream` →
//! `BroadcastStreamRecvError::Lagged` is logged + counted, never
//! propagated). Sinks must NOT panic on transport errors — log, count,
//! and continue.

use async_trait::async_trait;
use tokio::sync::{broadcast, watch};

use super::envelope::NodeEvent;

/// External-transport adapter contract.
///
/// Sinks are constructed by the operator-facing wiring code in
/// `satd/main.rs`, then handed to
/// [`super::EventPublisher::attach_sinks`]. Each `attach_sinks` call
/// spawns one tokio task per sink running [`EventSink::run`].
///
/// Implementors must:
/// - Drain `events` until the `shutdown` watch flips to `true` OR the
///   broadcast sender is dropped.
/// - Handle `broadcast::error::RecvError::Lagged(n)` by logging and
///   counting; never panic.
/// - Bound their own internal queues so a slow downstream client cannot
///   wedge the publisher.
/// - Consume `self` (boxed) to drop transport handles cleanly on
///   shutdown.
#[async_trait]
pub trait EventSink: Send + Sync + 'static {
    /// Stable, lowercase, hyphen-separated tag used in log lines and
    /// metrics labels (e.g. `"grpc"`, `"zmq"`, `"ws"`).
    fn name(&self) -> &'static str;

    /// Lifecycle entrypoint. Owns its own subscribe loop.
    async fn run(
        self: Box<Self>,
        events: broadcast::Receiver<NodeEvent>,
        shutdown: watch::Receiver<bool>,
    );
}

/// Test-only sink that records every received envelope into a shared
/// [`std::sync::Mutex<Vec<NodeEvent>>`]. Used by the publisher unit tests
/// and as a reference for new sink implementors.
#[cfg(test)]
pub mod testing {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    /// Records every envelope it receives. Lag is reported via
    /// `lag_total` (cumulative dropped count).
    #[derive(Clone, Default)]
    pub struct CaptureSink {
        pub received: Arc<Mutex<Vec<NodeEvent>>>,
        pub lag_total: Arc<std::sync::atomic::AtomicU64>,
    }

    impl CaptureSink {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn snapshot(&self) -> Vec<NodeEvent> {
            self.received.lock().clone()
        }
    }

    #[async_trait]
    impl EventSink for CaptureSink {
        fn name(&self) -> &'static str {
            "capture"
        }

        async fn run(
            self: Box<Self>,
            mut events: broadcast::Receiver<NodeEvent>,
            mut shutdown: watch::Receiver<bool>,
        ) {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => return,
                    res = events.recv() => match res {
                        Ok(env) => self.received.lock().push(env),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            self.lag_total
                                .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                }
            }
        }
    }
}
