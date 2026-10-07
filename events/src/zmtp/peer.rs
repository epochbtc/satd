//! One subscriber connection: handshake, then a reader half (subscriptions
//! and commands) and a writer half (queued messages) run until either ends.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::Shared;
use super::codec::{
    FLAG_MORE, GREETING, check_peer_ready, frame_header, pong_frame, protocol, read_frame,
    read_peer_greeting, ready_frame,
};

/// How long a connecting peer has to complete the greeting and READY
/// exchange. libzmq's default `ZMQ_HANDSHAKE_IVL` is 30 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Distinct subscription prefixes one peer may hold. A real subscriber
/// holds a handful (Core's topics are five); a peer past this is closed so
/// it cannot grow memory or the per-publish match cost without bound.
const MAX_SUBSCRIPTIONS: usize = 1024;

/// Writer buffer. Small messages are coalesced into one write; a frame
/// larger than this goes to the socket directly.
const WRITE_BUFFER: usize = 64 * 1024;

/// Messages the writer takes from its queue before it flushes and checks
/// for a pending PONG again.
const WRITE_BATCH: usize = 64;

/// Pending PONG replies. A peer that PINGs faster than they drain loses
/// the extra replies, not the connection.
const CONTROL_QUEUE: usize = 4;

/// A published message: topic, body, sequence.
pub(crate) type Msg = Arc<[Bytes; 3]>;

/// The prefixes one peer subscribes to, each with a count: subscribing to
/// the same prefix twice needs two cancels to remove it, as with libzmq's
/// subscription trie.
#[derive(Default)]
pub(crate) struct Subscriptions {
    prefixes: Vec<(Box<[u8]>, u32)>,
}

impl Subscriptions {
    fn add(&mut self, prefix: &[u8]) -> io::Result<()> {
        if let Some((_, n)) = self.prefixes.iter_mut().find(|(p, _)| &**p == prefix) {
            *n = n.saturating_add(1);
            return Ok(());
        }
        if self.prefixes.len() >= MAX_SUBSCRIPTIONS {
            return Err(protocol(format!(
                "peer subscribed to more than {MAX_SUBSCRIPTIONS} prefixes"
            )));
        }
        self.prefixes.push((prefix.into(), 1));
        Ok(())
    }

    fn cancel(&mut self, prefix: &[u8]) {
        if let Some(i) = self.prefixes.iter().position(|(p, _)| &**p == prefix) {
            self.prefixes[i].1 -= 1;
            if self.prefixes[i].1 == 0 {
                self.prefixes.swap_remove(i);
            }
        }
    }

    /// Whether any prefix matches `topic`. One answer per message however
    /// many prefixes match, so a message is delivered once.
    pub(crate) fn matches(&self, topic: &[u8]) -> bool {
        self.prefixes.iter().any(|(p, _)| topic.starts_with(p))
    }
}

pub(crate) enum QueueTx {
    Bounded(mpsc::Sender<Msg>),
    Unbounded(mpsc::UnboundedSender<Msg>),
}

pub(crate) enum QueueRx {
    Bounded(mpsc::Receiver<Msg>),
    Unbounded(mpsc::UnboundedReceiver<Msg>),
}

pub(crate) enum Enqueued {
    Yes,
    Full,
    Closed,
}

/// A queue of `hwm` messages, or an unbounded one for `hwm == 0`, which is
/// what a high-water mark of 0 means in libzmq.
pub(crate) fn queue(hwm: usize) -> (QueueTx, QueueRx) {
    if hwm == 0 {
        let (tx, rx) = mpsc::unbounded_channel();
        (QueueTx::Unbounded(tx), QueueRx::Unbounded(rx))
    } else {
        let (tx, rx) = mpsc::channel(hwm);
        (QueueTx::Bounded(tx), QueueRx::Bounded(rx))
    }
}

impl QueueTx {
    fn try_send(&self, msg: Msg) -> Enqueued {
        match self {
            QueueTx::Bounded(tx) => match tx.try_send(msg) {
                Ok(()) => Enqueued::Yes,
                Err(mpsc::error::TrySendError::Full(_)) => Enqueued::Full,
                Err(mpsc::error::TrySendError::Closed(_)) => Enqueued::Closed,
            },
            QueueTx::Unbounded(tx) => match tx.send(msg) {
                Ok(()) => Enqueued::Yes,
                Err(_) => Enqueued::Closed,
            },
        }
    }

    /// Messages waiting in a bounded queue. Unbounded queues report 0.
    #[cfg(test)]
    pub(crate) fn depth(&self) -> usize {
        match self {
            QueueTx::Bounded(tx) => tx.max_capacity() - tx.capacity(),
            QueueTx::Unbounded(_) => 0,
        }
    }
}

impl QueueRx {
    async fn recv(&mut self) -> Option<Msg> {
        match self {
            QueueRx::Bounded(rx) => rx.recv().await,
            QueueRx::Unbounded(rx) => rx.recv().await,
        }
    }

    fn try_recv(&mut self) -> Option<Msg> {
        match self {
            QueueRx::Bounded(rx) => rx.try_recv().ok(),
            QueueRx::Unbounded(rx) => rx.try_recv().ok(),
        }
    }
}

/// A registered subscriber, shared between its connection task and
/// [`super::ZmtpPub::publish`].
pub(crate) struct Subscriber {
    subs: Mutex<Subscriptions>,
    pub(crate) queue: QueueTx,
    /// Bytes queued and not yet written to the socket.
    pub(crate) queued_bytes: AtomicUsize,
}

impl Subscriber {
    pub(crate) fn matches(&self, topic: &[u8]) -> bool {
        self.subs.lock().unwrap_or_else(PoisonError::into_inner).matches(topic)
    }

    /// Queue `msg` (of `size` bytes), unless the queue is at its high-water
    /// mark or the subscriber already has unwritten bytes and this message
    /// would take them past `byte_cap`. An idle subscriber always takes a
    /// message, so the cap can never make one undeliverable. Returns `false`
    /// when the message was dropped for this subscriber.
    pub(crate) fn offer(&self, msg: &Msg, size: usize, byte_cap: usize) -> bool {
        let before = self.queued_bytes.fetch_add(size, Ordering::Relaxed);
        if before > 0 && before.saturating_add(size) > byte_cap {
            self.queued_bytes.fetch_sub(size, Ordering::Relaxed);
            return false;
        }
        match self.queue.try_send(msg.clone()) {
            Enqueued::Yes => true,
            Enqueued::Full => {
                self.queued_bytes.fetch_sub(size, Ordering::Relaxed);
                false
            }
            // The connection is ending and will unregister; not a drop.
            Enqueued::Closed => {
                self.queued_bytes.fetch_sub(size, Ordering::Relaxed);
                true
            }
        }
    }

    fn subscribe(&self, prefix: &[u8]) -> io::Result<()> {
        self.subs.lock().unwrap_or_else(PoisonError::into_inner).add(prefix)
    }

    fn cancel(&self, prefix: &[u8]) {
        self.subs.lock().unwrap_or_else(PoisonError::into_inner).cancel(prefix)
    }
}

/// Serve one accepted connection until it closes, fails, or the PUB
/// socket is dropped.
pub(crate) async fn serve<S>(stream: S, shared: Arc<Shared>, mut shutdown: watch::Receiver<()>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let result = tokio::select! {
        _ = shutdown.changed() => Ok(()),
        r = run(stream, &shared) => r,
    };
    if let Err(e) = result {
        debug!(target: "events::zmq::zmtp", error = %e, "ZMTP subscriber closed");
    }
}

async fn run<S>(stream: S, shared: &Arc<Shared>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        wr.write_all(&GREETING).await?;
        read_peer_greeting(&mut rd).await?;
        wr.write_all(&ready_frame()).await?;
        let ready = read_frame(&mut rd).await?;
        check_peer_ready(&ready)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ZMTP handshake timed out"))??;

    let (tx, rx) = queue(shared.hwm);
    let sub = Arc::new(Subscriber {
        subs: Mutex::new(Subscriptions::default()),
        queue: tx,
        queued_bytes: AtomicUsize::new(0),
    });
    let _registration = shared.register(sub.clone());
    let (ctl_tx, ctl_rx) = mpsc::channel(CONTROL_QUEUE);
    tokio::select! {
        r = read_loop(&mut rd, &sub, &ctl_tx) => r,
        r = write_loop(&mut wr, rx, ctl_rx, &sub) => r,
    }
}

/// Apply the peer's subscriptions and answer its PINGs. Returns `Ok` when
/// the peer closes the connection.
async fn read_loop<R: AsyncRead + Unpin>(
    r: &mut R,
    sub: &Subscriber,
    ctl: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let mut in_multipart = false;
    loop {
        let frame = match read_frame(r).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if frame.is_command() {
            let Some((name, data)) = frame.command() else {
                return Err(protocol("malformed command from peer"));
            };
            match name {
                // ZMTP 3.1 (RFC 37) subscription commands.
                b"SUBSCRIBE" => sub.subscribe(data)?,
                b"CANCEL" => sub.cancel(data),
                b"PING" => {
                    // A 2-byte TTL, then up to 16 bytes of context to echo.
                    if data.len() < 2 || data.len() > 18 {
                        return Err(protocol("malformed PING from peer"));
                    }
                    let _ = ctl.try_send(pong_frame(&data[2..]));
                }
                b"ERROR" => {
                    return Err(protocol(format!(
                        "peer sent ERROR: {}",
                        String::from_utf8_lossy(data.get(1..).unwrap_or_default())
                    )));
                }
                // PONG and commands this server has no use for.
                _ => {}
            }
            continue;
        }
        // ZMTP 3.0 subscriptions are single-frame messages whose first byte
        // is 1 (subscribe) or 0 (cancel). Any part of a multipart message,
        // and any other single frame, is not a subscription.
        let first_part = !in_multipart;
        in_multipart = frame.more();
        if !first_part || frame.more() {
            continue;
        }
        match frame.body.split_first() {
            Some((1, prefix)) => sub.subscribe(prefix)?,
            Some((0, prefix)) => sub.cancel(prefix),
            _ => {}
        }
    }
}

/// Write queued messages, each one completely. After taking a message the
/// writer drains whatever else is already queued and then flushes, so no
/// message ever waits in the buffer for a later publish.
async fn write_loop<W: AsyncWrite + Unpin>(
    w: W,
    mut rx: QueueRx,
    mut ctl: mpsc::Receiver<Vec<u8>>,
    sub: &Subscriber,
) -> io::Result<()> {
    let mut w = BufWriter::with_capacity(WRITE_BUFFER, w);
    loop {
        tokio::select! {
            biased;
            Some(frame) = ctl.recv() => w.write_all(&frame).await?,
            msg = rx.recv() => {
                let Some(msg) = msg else { return Ok(()) };
                write_message(&mut w, &msg, sub).await?;
                for _ in 1..WRITE_BATCH {
                    let Some(msg) = rx.try_recv() else { break };
                    write_message(&mut w, &msg, sub).await?;
                }
            }
        }
        w.flush().await?;
    }
}

async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &Msg,
    sub: &Subscriber,
) -> io::Result<()> {
    let mut size = 0;
    for (i, part) in msg.iter().enumerate() {
        let flags = if i + 1 < msg.len() { FLAG_MORE } else { 0 };
        w.write_all(&frame_header(flags, part.len())).await?;
        w.write_all(part).await?;
        size += part.len();
    }
    sub.queued_bytes.fetch_sub(size, Ordering::Relaxed);
    Ok(())
}
