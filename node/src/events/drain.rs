//! Drain tracking for the asynchronous event bridges, behind
//! `syncwithvalidationinterfacequeue`.
//!
//! ## What Core's RPC promises, and what it means here
//!
//! Core's validation callbacks run on one serialized background queue, so
//! `syncwithvalidationinterfacequeue` enqueues a no-op behind everything
//! already queued and blocks until it runs. When it returns, every callback
//! that was pending on entry has completed. Core's test framework calls it
//! from `sync_all()` for exactly that: to stop asserting against state a
//! callback has not caught up with yet.
//!
//! satd has no equivalent single queue, and for most of what tests assert it
//! does not need one: block connection writes its indexes **inline** and the
//! mempool is updated under its own lock, both before the originating RPC
//! returns. State reachable over RPC is therefore already settled when the RPC
//! that changed it answers.
//!
//! What *is* asynchronous is outbound event delivery: `ChainEvent` and
//! `MempoolEvent` go onto broadcast channels, and the bridges in
//! [`super::publisher`] turn them into the `NodeEvent`s that gRPC/WebSocket/ZMQ
//! subscribers see. That is the queue satd actually has, so that is what this
//! module drains — making the RPC mean something real here rather than
//! returning immediately and hoping.
//!
//! ## Shape
//!
//! Per stream, two monotonic counters: one incremented when an event is handed
//! to the channel, one when a bridge has finished publishing it. A waiter
//! snapshots `emitted` and waits for `processed` to reach it. Because both only
//! ever increase, a snapshot cannot be overtaken by later events — the wait
//! finishes when the events that existed *at entry* are done, which is Core's
//! guarantee.
//!
//! Three cases have to be right or the RPC hangs forever instead of failing:
//!
//! * **No bridge running.** Events are emitted whether or not anyone bridges
//!   them, so a lane only counts if a bridge registered itself. An idle lane is
//!   already drained.
//! * **A lagged consumer.** A bridge that falls behind is told how many events
//!   it skipped, and those count as processed — they will never be delivered,
//!   so waiting for them would never end.
//! * **A stuck bridge.** The wait is bounded. Core blocks forever because its
//!   queue is guaranteed to drain; satd would rather answer with an error than
//!   pin an RPC worker indefinitely.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// How often the wait re-checks progress independently of notifications, so a
/// lost wakeup can only add latency, never hang the call.
const RECHECK_INTERVAL: Duration = Duration::from_millis(25);

/// How long [`wait_for_drain`] will wait before reporting the queue stuck.
/// Generous: this only has to exceed the time a healthy bridge takes to
/// publish a backlog, and it exists to convert a hang into a diagnosis.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// One event stream's progress.
struct Lane {
    emitted: AtomicU64,
    processed: AtomicU64,
    /// Set once a bridge is consuming this stream. Until then nothing will
    /// advance `processed`, so the lane must not be waited on.
    bridged: AtomicBool,
    progress: Notify,
}

impl Lane {
    const fn new() -> Self {
        Self {
            emitted: AtomicU64::new(0),
            processed: AtomicU64::new(0),
            bridged: AtomicBool::new(false),
            progress: Notify::const_new(),
        }
    }

    fn emitted(&self) {
        self.emitted.fetch_add(1, Ordering::AcqRel);
    }

    fn processed(&self, n: u64) {
        self.processed.fetch_add(n, Ordering::AcqRel);
        self.progress.notify_waiters();
    }

    /// The count to wait for, or `None` when this lane cannot make progress
    /// and so must not be waited on.
    fn target(&self) -> Option<u64> {
        self.bridged
            .load(Ordering::Acquire)
            .then(|| self.emitted.load(Ordering::Acquire))
    }

    fn drained(&self, target: u64) -> bool {
        self.processed.load(Ordering::Acquire) >= target
    }

    /// Mark this lane consumable, discounting everything emitted earlier.
    ///
    /// A bridge only receives what is broadcast after it subscribes, so events
    /// emitted before that can never reach it. Counting them would leave a
    /// permanent deficit and make every later wait burn the full timeout, so
    /// the baseline moves to the current emitted count.
    fn bridge_started(&self) {
        self.processed
            .store(self.emitted.load(Ordering::Acquire), Ordering::Release);
        self.bridged.store(true, Ordering::Release);
    }
}

static CHAIN: Lane = Lane::new();
static MEMPOOL: Lane = Lane::new();

/// A chain event was handed to the broadcast channel.
pub fn chain_emitted() {
    CHAIN.emitted();
}

/// A mempool event was handed to the broadcast channel.
pub fn mempool_emitted() {
    MEMPOOL.emitted();
}

/// `n` chain events have been fully published (or provably skipped by a lagged
/// receiver, which amounts to the same thing for a waiter).
pub fn chain_processed(n: u64) {
    CHAIN.processed(n);
}

/// As [`chain_processed`], for the mempool stream.
pub fn mempool_processed(n: u64) {
    MEMPOOL.processed(n);
}

/// Mark the chain bridge live. Called once, by the bridge, before its loop.
pub fn chain_bridge_started() {
    CHAIN.bridge_started();
}

/// As [`chain_bridge_started`], for the mempool bridge.
pub fn mempool_bridge_started() {
    MEMPOOL.bridge_started();
}

/// Wait until every event emitted before this call has been published.
///
/// Returns `false` if [`DRAIN_TIMEOUT`] elapsed first, which means a bridge is
/// wedged — the caller should report that rather than pretend it drained.
pub async fn wait_for_drain() -> bool {
    let targets = [(&CHAIN, CHAIN.target()), (&MEMPOOL, MEMPOOL.target())];
    let wait = async {
        for (lane, target) in targets {
            let Some(target) = target else { continue };
            while !lane.drained(target) {
                // Two guards, because the failure mode of getting this wrong is
                // an RPC that never answers.
                //
                // `notified()` only registers the waiter when the future is
                // first *polled*, so creating it is not enough; `enable()`
                // registers now, closing the window between the re-check below
                // and the `await`.
                let notified = lane.progress.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if lane.drained(target) {
                    break;
                }
                // And the wait is re-checked periodically regardless, so even
                // if a wakeup were lost the barrier costs latency rather than
                // hanging. Belt and braces is worth it here: a lost wakeup is
                // precisely the bug that unit tests do not reliably reproduce.
                let _ = tokio::time::timeout(RECHECK_INTERVAL, notified).await;
            }
        }
    };
    tokio::time::timeout(DRAIN_TIMEOUT, wait).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lanes are process-global, so these cases share state and must run
    /// in one test, in order — the unbridged case in particular only holds
    /// before any bridge has registered.
    #[tokio::test]
    async fn drain_waits_only_on_lanes_that_can_progress() {
        // (a) Events are emitted whether or not a bridge exists. Without the
        // `bridged` guard, every node running without the events surface would
        // block here forever.
        chain_emitted();
        mempool_emitted();
        assert!(
            wait_for_drain().await,
            "an unbridged lane has nothing to wait for"
        );

        // (b) Once a bridge is live the wait is real: it must not return until
        // `processed` reaches the count emitted at entry.
        // Starting the bridge discounts (a)'s event, which it never saw.
        chain_bridge_started();
        chain_emitted();
        let waiter = tokio::spawn(wait_for_drain());
        tokio::task::yield_now().await;
        chain_processed(1);
        assert!(
            waiter.await.unwrap(),
            "should finish once processed catches up"
        );

        // (c) A lagged receiver never delivers what it skipped, so those count
        // as processed; insisting on them would never return.
        mempool_bridge_started();
        for _ in 0..5 {
            mempool_emitted();
        }
        mempool_processed(5);
        assert!(wait_for_drain().await, "skipped events must count as done");
    }

    /// A bridge that starts after events were already broadcast must not
    /// inherit a debt it can never pay: it never received those events, so
    /// every later wait would burn the full timeout.
    #[tokio::test]
    async fn a_late_bridge_does_not_inherit_undeliverable_events() {
        let lane = Lane::new();
        lane.emitted();
        lane.emitted();
        lane.bridge_started();
        assert_eq!(
            lane.target(),
            Some(2),
            "the lane is now consumable and its target is the current count"
        );
        assert!(lane.drained(2), "pre-bridge events must not be waited on");
    }
}
