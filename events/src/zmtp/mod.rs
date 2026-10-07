//! A small ZMTP 3.0 PUB server: the transport for satd's Bitcoin
//! Core-compatible `-zmqpub*` notifications.
//!
//! It speaks ZMTP 3.0 with the NULL mechanism (RFC 23) and the PUB-SUB
//! pattern (RFC 29), in the server role only, and also understands the
//! subscription and heartbeat commands a ZMTP 3.1 peer may send (RFC 37).
//! `contrib/zmq/interop.sh` checks it against libzmq (through pyzmq) and
//! LND's `gozmq`.
//!
//! Why not the `zeromq` crate the `-eventszmqbind` sink uses:
//! - its PUB send flushes a subscriber's buffer once, with a no-op waker,
//!   and nothing drains the rest until the *next* send to that subscriber.
//!   The tail of a multi-MB `rawblock` would wait for the next block;
//! - it has no high-water mark, so `-zmqpub<topic>hwm` could not be
//!   honoured;
//! - unexpected send errors and some endpoints (`ipc://*`) reach `todo!()`;
//! - it cannot bind `tcp://*:<port>`, and a stale ipc socket file fails the
//!   bind.
//!
//! Each subscriber gets a queue of up to `hwm` messages (unbounded for 0,
//! as in libzmq) and a writer that writes every message completely, so
//! delivery never depends on a later publish. [`ZmtpPub::publish`] never
//! blocks: a message that does not fit a subscriber's queue is dropped for
//! that subscriber and counted, which is what a libzmq PUB socket does at
//! its high-water mark. On top of the HWM, a subscriber whose unwritten
//! bytes would pass [`SUBSCRIBER_BYTE_CAP`] also drops: a thousand queued
//! multi-MB blocks is gigabytes, more than a slow reader should cost.

mod codec;
mod endpoint;
mod peer;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use endpoint::{IpcFile, Listener};
use peer::{Msg, Subscriber};

/// The most unwritten bytes one subscriber may have queued before further
/// messages to it are dropped, whatever the high-water mark.
pub const SUBSCRIBER_BYTE_CAP: usize = 256 << 20;

/// Pause after a failed `accept` (for example, out of file descriptors)
/// before trying again, so the loop does not spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// A bound PUB socket. Dropping it closes the listener, disconnects every
/// subscriber and removes an `ipc://` socket file.
pub struct ZmtpPub {
    shared: Arc<Shared>,
    local_endpoint: String,
    accept: JoinHandle<()>,
    /// Dropped with the socket; every connection task watches it.
    _shutdown: watch::Sender<()>,
    _ipc_file: Option<IpcFile>,
}

pub(crate) struct Shared {
    hwm: usize,
    byte_cap: usize,
    subscribers: Mutex<Vec<(u64, Arc<Subscriber>)>>,
    next_id: AtomicU64,
    dropped: AtomicU64,
    /// Accepted TCP connections whose SO_KEEPALIVE read back as set.
    #[cfg(test)]
    keepalive_set: AtomicU64,
}

impl Shared {
    fn subscribers(&self) -> MutexGuard<'_, Vec<(u64, Arc<Subscriber>)>> {
        self.subscribers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add a subscriber; it is removed when the returned guard drops.
    pub(crate) fn register(self: &Arc<Self>, sub: Arc<Subscriber>) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.subscribers().push((id, sub));
        Registration { shared: self.clone(), id }
    }
}

pub(crate) struct Registration {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.shared.subscribers().retain(|(id, _)| *id != self.id);
    }
}

impl ZmtpPub {
    /// Bind `endpoint` (see the module docs for the forms) and start
    /// accepting subscribers. `hwm` is each subscriber's queue length in
    /// messages; 0 means unbounded. Must be called inside a tokio runtime,
    /// which then runs the connection tasks.
    pub async fn bind(endpoint: &str, hwm: usize) -> io::Result<Self> {
        Self::bind_with_cap(endpoint, hwm, SUBSCRIBER_BYTE_CAP).await
    }

    pub(crate) async fn bind_with_cap(
        endpoint: &str,
        hwm: usize,
        byte_cap: usize,
    ) -> io::Result<Self> {
        let bound = endpoint::bind(endpoint)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {endpoint}: {e}")))?;
        let shared = Arc::new(Shared {
            hwm,
            byte_cap,
            subscribers: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            #[cfg(test)]
            keepalive_set: AtomicU64::new(0),
        });
        let (shutdown, shutdown_rx) = watch::channel(());
        let accept = tokio::spawn(accept_loop(bound.listener, shared.clone(), shutdown_rx));
        Ok(Self {
            shared,
            local_endpoint: bound.local_endpoint,
            accept,
            _shutdown: shutdown,
            _ipc_file: bound.ipc_file,
        })
    }

    /// The endpoint actually bound: an ephemeral port is filled in, and
    /// `tcp://*` reads `tcp://0.0.0.0`.
    pub fn local_endpoint(&self) -> String {
        self.local_endpoint.clone()
    }

    /// Queue `frames` (topic, body, sequence) for every subscriber whose
    /// subscription prefix matches the topic, once per subscriber. Never
    /// blocks; a subscriber whose queue is full, or whose unwritten bytes
    /// are at the cap, misses this message and the drop is counted.
    pub fn publish(&self, frames: [Bytes; 3]) {
        let subs = self.shared.subscribers();
        if subs.is_empty() {
            return;
        }
        let size = frames.iter().map(Bytes::len).sum();
        let msg: Msg = Arc::new(frames);
        for (_, sub) in subs.iter() {
            if sub.matches(&msg[0]) && !sub.offer(&msg, size, self.shared.byte_cap) {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether any connected subscriber would receive a message on `topic`.
    pub fn has_subscriber(&self, topic: &[u8]) -> bool {
        self.shared.subscribers().iter().any(|(_, s)| s.matches(topic))
    }

    /// Connected subscribers that have completed the handshake.
    pub fn subscriber_count(&self) -> usize {
        self.shared.subscribers().len()
    }

    /// Messages dropped for a subscriber because its queue was full or its
    /// unwritten bytes were at the cap, since the socket was bound.
    pub fn dropped_total(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// `(queued messages, unwritten bytes)` per subscriber.
    #[cfg(test)]
    pub(crate) fn queue_depths(&self) -> Vec<(usize, usize)> {
        self.shared
            .subscribers()
            .iter()
            .map(|(_, s)| (s.queue.depth(), s.queued_bytes.load(Ordering::Relaxed)))
            .collect()
    }

    /// Subscribers that would receive a message on `topic`.
    #[cfg(test)]
    pub(crate) fn subscribers_matching(&self, topic: &[u8]) -> usize {
        self.shared.subscribers().iter().filter(|(_, s)| s.matches(topic)).count()
    }

    #[cfg(test)]
    pub(crate) fn keepalive_set_count(&self) -> u64 {
        self.shared.keepalive_set.load(Ordering::Relaxed)
    }
}

impl Drop for ZmtpPub {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl std::fmt::Debug for ZmtpPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZmtpPub")
            .field("local_endpoint", &self.local_endpoint)
            .field("subscribers", &self.subscriber_count())
            .field("dropped", &self.dropped_total())
            .finish()
    }
}

async fn accept_loop(listener: Listener, shared: Arc<Shared>, shutdown: watch::Receiver<()>) {
    loop {
        let accepted = match &listener {
            Listener::Tcp(l) => l.accept().await.map(|(stream, peer)| {
                configure_tcp(&stream, &shared);
                debug!(target: "events::zmq::zmtp", %peer, "ZMTP subscriber connected");
                tokio::spawn(peer::serve(stream, shared.clone(), shutdown.clone()));
            }),
            Listener::Ipc(l) => l.accept().await.map(|(stream, _)| {
                debug!(target: "events::zmq::zmtp", "ZMTP subscriber connected (ipc)");
                tokio::spawn(peer::serve(stream, shared.clone(), shutdown.clone()));
            }),
        };
        if let Err(e) = accepted {
            warn!(target: "events::zmq::zmtp", error = %e, "ZMTP accept failed");
            tokio::time::sleep(ACCEPT_RETRY).await;
        }
    }
}

/// TCP keepalive (Core sets `ZMQ_TCP_KEEPALIVE=1`) so a subscriber that
/// vanished without a FIN is eventually noticed, and no Nagle delay on the
/// last segment of a message.
fn configure_tcp(stream: &tokio::net::TcpStream, shared: &Shared) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(target: "events::zmq::zmtp", error = %e, "TCP_NODELAY not set");
    }
    let sock = socket2::SockRef::from(stream);
    if let Err(e) = sock.set_keepalive(true) {
        debug!(target: "events::zmq::zmtp", error = %e, "SO_KEEPALIVE not set");
    }
    #[cfg(test)]
    if sock.keepalive().unwrap_or(false) {
        shared.keepalive_set.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(not(test))]
    let _ = shared;
}
