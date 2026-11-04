//! The queue between the P2P task and header acceptance (#1187).
//!
//! Accepting a `headers` message commits its index rows under `accept_lock`
//! (`ChainState::commit_accepted_headers`), and a block connect holds that
//! lock from start to finish, script verification included. Handled inline, a
//! `headers` message that arrived during a long connect parked the P2P task
//! on the lock, the way a stored block did before #875: no other peer's
//! messages, no block requests, no ping replies until the connect let go.
//! The proof-of-work checks on up to 2,000 headers ran inline as well.
//!
//! The P2P task now hands each `headers` message to the headers thread
//! through this queue and goes on. One thread takes the jobs in the order
//! they arrived, so the header-sync state sees each batch's result in order,
//! as it did inline.
//!
//! Core handles one connection's messages one at a time, in order, and a
//! peer relies on it: the `block` it sends after a `headers` message finds
//! the header indexed, and an `inv` finds the header known. So while the
//! queue holds work, the block-relay messages that arrive behind it (`inv`,
//! `cmpctblock`, `blocktxn`, and `block` outside initial block download) are
//! queued too, from every peer, and handled on the headers thread in arrival
//! order. When the queue is idle they are handled on the P2P task as before.
//! Only the P2P task pushes, so a relay message it handles inline never runs
//! alongside one on the headers thread.
//!
//! The queue is bounded in bytes. A push past the bound waits for room,
//! which costs the P2P task what an inline `headers` message used to, and
//! only then. An empty queue takes any message.

use std::collections::VecDeque;
use std::time::Duration;

use bitcoin::p2p::message::NetworkMessage;
use parking_lot::{Condvar, Mutex};

use crate::net::flow::InFlight;
use crate::net::peer::PeerId;

/// The most message bytes the queue holds before a push waits for room.
/// A full `headers` message is about 160 KB, so this is some 200 of them.
pub const HEADERS_QUEUE_MAX_BYTES: usize = 32 * 1024 * 1024;

/// How long a push waits for room before it looks again at whether the
/// headers thread has gone.
const PUSH_RECHECK: Duration = Duration::from_millis(100);

/// One message waiting for the headers thread.
pub struct HeadersJob {
    pub peer: PeerId,
    pub msg: NetworkMessage,
    /// Counts the message out once it is handled, so a pong the peer sent
    /// behind it comes back after it, as it did inline.
    pub in_flight: InFlight,
    /// The message's size, as counted against the bound.
    pub size: usize,
}

impl HeadersJob {
    pub fn new(peer: PeerId, msg: NetworkMessage, in_flight: InFlight) -> Self {
        let size = approx_size(&msg);
        Self { peer, msg, in_flight, size }
    }
}

/// A message's size for the bound: what it carries, near enough.
fn approx_size(msg: &NetworkMessage) -> usize {
    match msg {
        // 80 bytes and a zero transaction count each.
        NetworkMessage::Headers(h) => h.len() * 81,
        NetworkMessage::Block(b) => b.total_size(),
        NetworkMessage::Inv(inv) => inv.len() * 36,
        NetworkMessage::CmpctBlock(c) => {
            80 + c.compact_block.short_ids.len() * 6
                + c.compact_block.prefilled_txs.iter().map(|p| p.tx.total_size()).sum::<usize>()
        }
        NetworkMessage::BlockTxn(b) => b.transactions.transactions.iter().map(|t| t.total_size()).sum(),
        _ => 1024,
    }
}

#[derive(Default)]
struct State {
    jobs: VecDeque<HeadersJob>,
    bytes: usize,
    /// A job has been taken and is being handled.
    busy: bool,
    /// The headers thread has gone. Jobs it left stay queued until the next
    /// push hands them back, so they are still handled, in order.
    closed: bool,
}

/// See the module docs.
pub struct HeadersQueue {
    state: Mutex<State>,
    cvar: Condvar,
    max_bytes: usize,
}

impl Default for HeadersQueue {
    fn default() -> Self {
        Self::new(HEADERS_QUEUE_MAX_BYTES)
    }
}

impl HeadersQueue {
    pub fn new(max_bytes: usize) -> Self {
        Self { state: Mutex::new(State::default()), cvar: Condvar::new(), max_bytes }
    }

    /// Queue `job` for the headers thread, waiting for room while the queue
    /// is at its bound. Once the thread has gone, hands back every job still
    /// queued, then `job`, for the caller to handle inline in that order.
    pub fn push(&self, job: HeadersJob) -> Result<(), Vec<HeadersJob>> {
        let mut state = self.state.lock();
        loop {
            if state.closed {
                state.bytes = 0;
                let mut jobs: Vec<HeadersJob> = std::mem::take(&mut state.jobs).into();
                jobs.push(job);
                return Err(jobs);
            }
            if state.jobs.is_empty() || state.bytes.saturating_add(job.size) <= self.max_bytes {
                break;
            }
            let _ = self.cvar.wait_for(&mut state, PUSH_RECHECK);
        }
        state.bytes += job.size;
        state.jobs.push_back(job);
        drop(state);
        self.cvar.notify_all();
        Ok(())
    }

    /// The next job, waiting up to `wait` for one. Marks the queue busy
    /// until [`Self::done`].
    pub fn pop(&self, wait: Duration) -> Option<HeadersJob> {
        let mut state = self.state.lock();
        if state.jobs.is_empty() && !state.closed {
            let _ = self.cvar.wait_for(&mut state, wait);
        }
        if state.closed {
            return None;
        }
        let job = state.jobs.pop_front()?;
        state.bytes -= job.size;
        state.busy = true;
        Some(job)
    }

    /// The job [`Self::pop`] returned has been handled.
    pub fn done(&self) {
        self.state.lock().busy = false;
        self.cvar.notify_all();
    }

    /// The headers thread is going: later pushes are handed back, with
    /// whatever is still queued ahead of them, and [`Self::take_stranded`]
    /// hands back the rest.
    pub fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.busy = false;
        drop(state);
        self.cvar.notify_all();
    }

    /// Once the thread has gone, the jobs it left, in order, for the caller
    /// to handle inline. Nothing while it is running.
    pub fn take_stranded(&self) -> Vec<HeadersJob> {
        let mut state = self.state.lock();
        if !state.closed {
            return Vec::new();
        }
        state.bytes = 0;
        std::mem::take(&mut state.jobs).into()
    }

    /// Wake a headers thread waiting in [`Self::pop`].
    pub fn wake(&self) {
        self.cvar.notify_all();
    }

    /// The headers thread has gone.
    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    /// Nothing queued and nothing being handled.
    pub fn is_idle(&self) -> bool {
        let state = self.state.lock();
        state.jobs.is_empty() && !state.busy
    }

    /// Bytes queued.
    #[cfg(test)]
    pub fn queued_bytes(&self) -> usize {
        self.state.lock().bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(peer: PeerId, size: usize) -> HeadersJob {
        HeadersJob { peer, msg: NetworkMessage::Headers(Vec::new()), in_flight: InFlight::adopt(None), size }
    }

    /// Jobs come out in the order they went in, which is what keeps the
    /// header-sync state seeing each batch's result in order.
    #[test]
    fn jobs_come_out_in_arrival_order() {
        let q = HeadersQueue::new(1000);
        for peer in [3, 1, 2] {
            assert!(q.push(job(peer, 10)).is_ok());
        }
        let order: Vec<PeerId> = std::iter::from_fn(|| {
            let j = q.pop(Duration::ZERO)?;
            q.done();
            Some(j.peer)
        })
        .collect();
        assert_eq!(order, vec![3, 1, 2]);
        assert!(q.is_idle());
    }

    /// A job being handled keeps the queue from reading idle, so a relay
    /// message that arrives meanwhile queues behind it.
    #[test]
    fn a_job_in_hand_keeps_the_queue_busy() {
        let q = HeadersQueue::new(1000);
        assert!(q.is_idle());
        assert!(q.push(job(1, 10)).is_ok());
        assert!(!q.is_idle());
        let _taken = q.pop(Duration::ZERO).unwrap();
        assert!(!q.is_idle(), "busy until done");
        q.done();
        assert!(q.is_idle());
    }

    /// An empty queue takes a message larger than the bound; a full one makes
    /// the push wait until the thread takes something.
    #[test]
    fn a_push_past_the_bound_waits_for_room() {
        let q = std::sync::Arc::new(HeadersQueue::new(100));
        assert!(q.push(job(1, 150)).is_ok(), "an empty queue takes an oversized message");
        let pusher = {
            let q = q.clone();
            std::thread::spawn(move || q.push(job(2, 10)).is_ok())
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!pusher.is_finished(), "the push waits while the queue is past its bound");
        assert_eq!(q.queued_bytes(), 150);
        let first = q.pop(Duration::ZERO).unwrap();
        assert_eq!(first.peer, 1);
        q.done();
        assert!(pusher.join().unwrap(), "the push goes in once there is room");
        assert_eq!(q.queued_bytes(), 10);
    }

    /// Once the thread has gone, a push hands back what was still queued and
    /// then its own job, in order, so nothing is dropped and nothing jumps
    /// ahead.
    #[test]
    fn a_closed_queue_hands_back_its_jobs_in_order() {
        let q = HeadersQueue::new(1000);
        assert!(q.push(job(1, 10)).is_ok());
        assert!(q.push(job(2, 10)).is_ok());
        q.close();
        assert!(q.pop(Duration::ZERO).is_none(), "a closed queue gives the thread nothing");
        let back = q.push(job(3, 10)).expect_err("a closed queue hands jobs back");
        assert_eq!(back.iter().map(|j| j.peer).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert!(q.is_idle());
        assert_eq!(q.queued_bytes(), 0);
    }

    /// A running queue strands nothing; a closed one hands back what it held,
    /// in order, once.
    #[test]
    fn a_closed_queue_gives_up_its_stranded_jobs_once() {
        let q = HeadersQueue::new(1000);
        assert!(q.push(job(1, 10)).is_ok());
        assert!(q.take_stranded().is_empty(), "the thread still owns them");
        assert!(q.push(job(2, 10)).is_ok());
        q.close();
        assert_eq!(q.take_stranded().iter().map(|j| j.peer).collect::<Vec<_>>(), vec![1, 2]);
        assert!(q.take_stranded().is_empty());
        assert!(q.is_idle());
        assert_eq!(q.queued_bytes(), 0);
    }

    /// A push waiting for room gives up waiting when the thread goes, and
    /// hands its job back rather than waiting for a pop that never comes.
    #[test]
    fn a_waiting_push_is_handed_back_when_the_queue_closes() {
        let q = std::sync::Arc::new(HeadersQueue::new(100));
        assert!(q.push(job(1, 150)).is_ok());
        let pusher = {
            let q = q.clone();
            std::thread::spawn(move || q.push(job(2, 10)).err().map(|v| v.len()))
        };
        std::thread::sleep(Duration::from_millis(50));
        q.close();
        assert_eq!(pusher.join().unwrap(), Some(2), "the queued job and its own");
    }
}
