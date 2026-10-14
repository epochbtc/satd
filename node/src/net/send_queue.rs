//! Per-peer outbound queue accounting, behind Bitcoin Core's send-buffer
//! limit.
//!
//! Core stops working for a peer once the bytes queued to it pass
//! `-maxsendbuffer` (1,000,000 by default). `fPauseSend` is set
//! (`net.cpp` `SocketSendData` and `PushMessage`), `ProcessGetData` stops
//! serving (`net_processing.cpp` `ProcessGetData`), and `ProcessMessages`
//! takes no further message from that peer until the buffer drains. The
//! unserved rest of a `getdata` stays in `m_getdata_requests` and is served
//! as the buffer empties; until it has all been served, nothing else the peer
//! sent is processed either ("this maintains the order of responses and
//! prevents m_getdata_requests to grow unbounded").
//!
//! satd's queue to a peer is a bounded channel that the peer's write loop
//! drains. [`PeerSender`] is the sending end: it counts the bytes each
//! message adds. [`SendQueue`] is the state the manager and the write loop
//! share: those bytes, the unserved `getdata` entries, and whether the write
//! loop may hand the manager the peer's next message.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bitcoin::consensus::Encodable;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use tokio::sync::{Notify, mpsc};

/// Core's default `-maxsendbuffer`, `DEFAULT_MAXSENDBUFFER` (1000 kB,
/// `net.h`), in bytes. Past it a peer is not served and not read.
pub const MAX_SEND_BUFFER_BYTES: usize = 1_000_000;

/// Core's `TIMEOUT_INTERVAL` (`net.h`). A peer whose socket has taken no
/// bytes for this long while a message waits to go out is dropped (Core's
/// `InactivityCheck`, "socket sending timeout").
pub const SEND_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Size of a v1 message header: magic, command, length and checksum.
const MESSAGE_HEADER_SIZE: usize = 24;

/// What a message counts for while it waits in a peer's queue: its v1 wire
/// size, header and payload.
///
/// The sender adds it and the write loop takes it off again, both from the
/// message itself, so the two always agree. A v2 packet is a few bytes
/// longer or shorter on the wire; the budget does not need to know.
pub fn queued_size(msg: &NetworkMessage) -> usize {
    // Encoding into a sink cannot fail.
    MESSAGE_HEADER_SIZE + msg.consensus_encode(&mut bitcoin::io::sink()).unwrap_or(0)
}

/// State shared by the manager and one peer's write loop.
#[derive(Debug, Default)]
pub struct SendQueue {
    /// Bytes queued to the peer and not yet written to its socket.
    queued_bytes: AtomicUsize,
    /// `getdata` entries not yet served, oldest first: Core's
    /// `m_getdata_requests`.
    getdata: parking_lot::Mutex<VecDeque<Inventory>>,
    /// `getdata.len()`, readable without the lock.
    getdata_len: AtomicUsize,
    /// `getdata` messages the write loop has handed the manager that the
    /// manager has not yet taken in.
    getdata_unhandled: AtomicUsize,
    /// A [`crate::net::manager::NetEvent::GetDataResume`] for this peer is
    /// waiting in the manager's queue.
    resume_queued: AtomicBool,
    /// Wakes the write loop when the peer's messages may be read again.
    reader_wake: Notify,
}

impl SendQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes queued and not yet written.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Acquire)
    }

    /// Core's `fPauseSend`: more than [`MAX_SEND_BUFFER_BYTES`] is queued.
    pub fn over_limit(&self) -> bool {
        self.queued_bytes() > MAX_SEND_BUFFER_BYTES
    }

    fn add(&self, n: usize) {
        self.queued_bytes.fetch_add(n, Ordering::AcqRel);
    }

    /// The write loop has written (or given up on) a message counted at `n`.
    pub fn sent(&self, n: usize) {
        let _ = self
            .queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(n)));
    }

    /// Append a `getdata` request's entries to the unserved ones.
    pub fn push_getdata(&self, entries: Vec<Inventory>) {
        let mut q = self.getdata.lock();
        q.extend(entries);
        self.getdata_len.store(q.len(), Ordering::Release);
    }

    /// The oldest unserved `getdata` entry, left in place. It stays counted
    /// as unserved while the manager works on it, so the write loop never
    /// sees an empty backlog and resumes reading before the entry is done.
    pub fn front_getdata(&self) -> Option<Inventory> {
        self.getdata.lock().front().copied()
    }

    /// Drop the oldest unserved `getdata` entry: it has been answered.
    pub fn pop_getdata(&self) {
        let mut q = self.getdata.lock();
        q.pop_front();
        self.getdata_len.store(q.len(), Ordering::Release);
    }

    /// How many `getdata` entries are waiting to be served.
    pub fn getdata_backlog(&self) -> usize {
        self.getdata_len.load(Ordering::Acquire)
    }

    /// The write loop has handed the manager a `getdata`. Until the manager
    /// has taken it in and served it, the loop reads nothing more.
    pub fn note_getdata_forwarded(&self) {
        self.getdata_unhandled.fetch_add(1, Ordering::AcqRel);
    }

    /// The manager has taken in a `getdata` (whatever it made of it).
    pub fn note_getdata_handled(&self) {
        let _ = self
            .getdata_unhandled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(1)));
        self.wake_reader();
    }

    /// Whether the write loop must leave the peer's next message unread:
    /// a `getdata` is still being served, or the queue is over
    /// [`MAX_SEND_BUFFER_BYTES`] (Core's `ProcessMessages`).
    pub fn reading_paused(&self) -> bool {
        self.getdata_unhandled.load(Ordering::Acquire) > 0
            || self.getdata_backlog() > 0
            || self.over_limit()
    }

    /// Called by the write loop after a write. True when the manager should
    /// be asked to serve more of the backlog: there is some, the queue has
    /// room, and no request to serve is already waiting.
    pub fn take_resume(&self) -> bool {
        self.getdata_backlog() > 0 && !self.over_limit() && !self.resume_queued.swap(true, Ordering::AcqRel)
    }

    /// Called by the manager as it starts on a resume request, before it
    /// looks at the queue, so a write that drains the queue after that look
    /// asks again rather than being lost.
    pub fn resume_taken(&self) {
        self.resume_queued.store(false, Ordering::Release);
    }

    /// Tell the write loop the peer's messages may be readable again.
    pub fn wake_reader(&self) {
        // `notify_one` stores a permit when the loop is not waiting, so a
        // wake sent between its check and its wait is not lost.
        self.reader_wake.notify_one();
    }

    /// Resolves after [`Self::wake_reader`].
    pub async fn reader_woken(&self) {
        self.reader_wake.notified().await;
    }
}

/// The sending end of a peer's queue. Counts what it queues in the shared
/// [`SendQueue`].
///
/// Holds the channel's sender: the write loop learns that the manager has
/// dropped the peer when the last one goes. The write loop itself holds only
/// the [`SendQueue`].
#[derive(Debug, Clone)]
pub struct PeerSender {
    tx: mpsc::Sender<NetworkMessage>,
    queue: Arc<SendQueue>,
}

impl From<mpsc::Sender<NetworkMessage>> for PeerSender {
    fn from(tx: mpsc::Sender<NetworkMessage>) -> Self {
        Self { tx, queue: Arc::new(SendQueue::new()) }
    }
}

impl PeerSender {
    /// The state this sender shares with the peer's write loop.
    pub fn queue(&self) -> &Arc<SendQueue> {
        &self.queue
    }

    /// Queue a message if there is room, counting its bytes. The signature
    /// is the tokio sender's, which this replaces at every call site.
    #[allow(clippy::result_large_err)]
    pub fn try_send(&self, msg: NetworkMessage) -> Result<(), mpsc::error::TrySendError<NetworkMessage>> {
        let n = queued_size(&msg);
        // Counted before the message is visible to the write loop, so the
        // loop can never take it off before it was put on.
        self.queue.add(n);
        self.tx.try_send(msg).inspect_err(|_| self.queue.sent(n))
    }

    /// Queue a message, waiting for room, counting its bytes.
    #[allow(clippy::result_large_err)]
    pub async fn send(&self, msg: NetworkMessage) -> Result<(), mpsc::error::SendError<NetworkMessage>> {
        let n = queued_size(&msg);
        self.queue.add(n);
        self.tx.send(msg).await.inspect_err(|_| self.queue.sent(n))
    }

    /// Whether `getdata` serving must stop for now: the queue is over
    /// [`MAX_SEND_BUFFER_BYTES`], or the channel has no free slot.
    pub fn paused(&self) -> bool {
        self.queue.over_limit() || self.tx.capacity() == 0
    }
}

#[cfg(test)]
#[path = "send_queue_tests.rs"]
mod tests;
