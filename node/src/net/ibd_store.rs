//! The queue between the P2P task and the IBD block store (#875).
//!
//! During IBD every arriving block is stored as it comes in, and the store
//! takes `accept_lock` to index it. The IBD connector holds that lock for a
//! whole connect, script verification included, which on a block of large
//! transactions is tens of seconds. Stored inline, a block that arrived
//! during such a connect parked the P2P task on the lock: no other peer's
//! messages, no new block requests, no ping replies, and once the connect
//! let go the stall check dropped peers whose deliveries were still queued
//! behind it.
//!
//! The P2P task now hands each block to a store thread through this queue
//! and goes on. The queue is bounded in bytes. A block that would take it
//! past the bound is stored inline, as before, so a store that cannot keep
//! up costs what it did, never memory without limit; the scheduler bounds
//! what is in flight anyway (16 blocks a peer, inside the download window),
//! and the queue never holds more than that.

use std::collections::VecDeque;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

use crate::net::flow::InFlight;
use crate::net::peer::PeerId;

/// The most block bytes the queue holds before a block is stored inline.
/// Room for the in-flight window at mainnet's usual block sizes, without
/// adding much to what a small host keeps in memory during IBD.
pub const IBD_STORE_QUEUE_MAX_BYTES: usize = 128 * 1024 * 1024;

/// One block waiting to be stored.
pub struct IbdStoreJob {
    pub peer: PeerId,
    /// Boxed: the job travels by value through `try_push`'s error.
    pub block: Box<bitcoin::Block>,
    /// The height the scheduler credited the block's arrival at, if it did:
    /// the store's outcome settles that height.
    pub arrived_at: Option<u32>,
    /// Counts the `block` message out once it is stored, so a pong the peer
    /// sent behind it still comes back after the block is stored.
    pub in_flight: InFlight,
    /// The block's serialized size, as counted against the bound.
    pub size: usize,
}

#[derive(Default)]
struct State {
    jobs: VecDeque<IbdStoreJob>,
    bytes: usize,
    /// A job has been taken and is being stored.
    busy: bool,
}

/// See the module docs.
pub struct IbdStoreQueue {
    state: Mutex<State>,
    cvar: Condvar,
    max_bytes: usize,
}

impl Default for IbdStoreQueue {
    fn default() -> Self {
        Self::new(IBD_STORE_QUEUE_MAX_BYTES)
    }
}

impl IbdStoreQueue {
    pub fn new(max_bytes: usize) -> Self {
        Self { state: Mutex::new(State::default()), cvar: Condvar::new(), max_bytes }
    }

    /// Queue `job` for the store thread, or hand it back when it would take
    /// the queue past its bound. An empty queue takes any block, so one
    /// larger than the bound is not stored inline for that alone.
    pub fn try_push(&self, job: IbdStoreJob) -> Result<(), IbdStoreJob> {
        let mut state = self.state.lock();
        if !state.jobs.is_empty() && state.bytes.saturating_add(job.size) > self.max_bytes {
            return Err(job);
        }
        state.bytes += job.size;
        state.jobs.push_back(job);
        drop(state);
        self.cvar.notify_one();
        Ok(())
    }

    /// The next job, waiting up to `wait` for one. Marks the queue busy
    /// until [`Self::done`].
    pub fn pop(&self, wait: Duration) -> Option<IbdStoreJob> {
        let mut state = self.state.lock();
        if state.jobs.is_empty() {
            let _ = self.cvar.wait_for(&mut state, wait);
        }
        let job = state.jobs.pop_front()?;
        state.bytes -= job.size;
        state.busy = true;
        Some(job)
    }

    /// The job [`Self::pop`] returned has been stored.
    pub fn done(&self) {
        self.state.lock().busy = false;
        self.cvar.notify_all();
    }

    /// Drop every queued job, for shutdown. Their `in_flight` guards count
    /// the messages out as they drop.
    pub fn clear(&self) {
        let jobs = {
            let mut state = self.state.lock();
            state.bytes = 0;
            std::mem::take(&mut state.jobs)
        };
        drop(jobs);
    }

    /// Wake a store thread waiting in [`Self::pop`].
    pub fn wake(&self) {
        self.cvar.notify_all();
    }

    /// Nothing queued and nothing being stored.
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

    fn job(size: usize) -> IbdStoreJob {
        IbdStoreJob {
            peer: 1,
            block: Box::new(bitcoin::constants::genesis_block(bitcoin::Network::Regtest)),
            arrived_at: None,
            in_flight: InFlight::adopt(None),
            size,
        }
    }

    /// The bound refuses a block that would take the queue past it, but an
    /// empty queue takes any block.
    #[test]
    fn the_byte_bound_refuses_overflow_but_never_an_empty_queue() {
        let q = IbdStoreQueue::new(100);
        assert!(q.try_push(job(150)).is_ok(), "an empty queue takes an oversized block");
        assert!(q.try_push(job(1)).is_err(), "a full queue refuses the next block");
        let first = q.pop(Duration::ZERO).unwrap();
        assert_eq!(first.size, 150);
        assert_eq!(q.queued_bytes(), 0);
        assert!(!q.is_idle(), "busy until done");
        q.done();
        assert!(q.is_idle());
        assert!(q.try_push(job(60)).is_ok());
        assert!(q.try_push(job(40)).is_ok(), "exactly at the bound fits");
        assert!(q.try_push(job(1)).is_err());
        q.clear();
        assert!(q.is_idle());
        assert_eq!(q.queued_bytes(), 0);
    }
}
