//! Per-peer work-in-flight accounting, behind Bitcoin Core's message
//! ordering guarantee.
//!
//! Core processes one connection's messages one at a time, in the order they
//! arrived, on a single thread. A test — and a peer — can therefore rely on
//! `send_and_ping(block)`: when the pong comes back, the block has been
//! connected, because the pong could not have been produced until the block
//! message ahead of it was done. Core's own functional tests lean on this
//! constantly (`feature_dersig`, `feature_cltv`, `p2p_segwit`,
//! `feature_block`, …), and so do real peers.
//!
//! satd does not process a connection on one thread. A `block` travels
//! `event_tx` → the manager's drain → `block_tx` → the block processor,
//! while `ping` is answered on the peer's own socket task — deliberately, so
//! the manager's 500 ms drain cadence does not land in the round-trip time
//! the *peer* measures. The result is that satd's pong guarantees nothing
//! about what came before it.
//!
//! This is the accounting that restores the guarantee without giving up the
//! fast path. The socket task counts a message as in flight the moment it
//! hands it to the manager, and whatever finally disposes of it — the drain
//! for a message handled inline, the block processor for a block — counts it
//! out. A ping arriving while the peer has nothing in flight (the ordinary
//! keepalive case) is still answered immediately; one arriving behind work
//! waits for that work, and only that work, to finish.

use std::sync::Arc;

use tokio::sync::watch;

/// One peer's count of messages received and not yet disposed of.
#[derive(Debug)]
pub struct PeerFlow {
    /// The count itself. A `watch` rather than an atomic so a parked pong can
    /// wait on it without polling.
    in_flight: watch::Sender<u64>,
}

impl Default for PeerFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerFlow {
    pub fn new() -> Self {
        Self { in_flight: watch::Sender::new(0) }
    }

    /// Count a message as in flight. Called by the socket task as it hands
    /// the message to the manager, so the count covers messages still
    /// sitting in the event queue as well as ones being worked on.
    pub fn queued(&self) {
        self.in_flight.send_modify(|n| *n += 1);
    }

    /// Count a message as disposed of — processed, rejected, or dropped.
    ///
    /// Saturating: a double completion would otherwise wrap the count to
    /// `u64::MAX` and park every future pong until the peer timed out, which
    /// is a far worse failure than answering one ping early.
    pub fn completed(&self) {
        self.in_flight.send_modify(|n| *n = n.saturating_sub(1));
    }

    /// Count `n` messages as disposed of at once.
    pub fn completed_n(&self, n: u64) {
        self.in_flight.send_modify(|v| *v = v.saturating_sub(n));
    }

    /// Nothing from this peer is outstanding.
    pub fn is_idle(&self) -> bool {
        *self.in_flight.borrow() == 0
    }

    /// The current count, for logging.
    pub fn in_flight(&self) -> u64 {
        *self.in_flight.borrow()
    }

    /// Wait until nothing from this peer is outstanding.
    ///
    /// The caller is responsible for bounding the wait: a message that is
    /// never completed — a bug anywhere in the pipeline — must not hold a
    /// pong forever, because the peer would drop us for not answering.
    pub async fn wait_idle(&self) {
        let mut rx = self.in_flight.subscribe();
        // `wait_for` checks the current value first, so an already-idle peer
        // returns without awaiting.
        let _ = rx.wait_for(|n| *n == 0).await;
    }
}

/// A message counted in on construction and out on drop.
///
/// The drop is what makes this safe to use along the block pipeline, where a
/// block can leave by a dozen different paths — connected, rejected as
/// mutated, buffered and later dropped, discarded because the peer went
/// away. Every one of those is a completion, and forgetting one would park
/// the peer's next pong until its ping timeout.
#[derive(Debug)]
pub struct InFlight(Option<Arc<PeerFlow>>);

impl InFlight {
    /// Counts one message in against `flow`, if the peer is still known.
    pub fn new(flow: Option<Arc<PeerFlow>>) -> Self {
        if let Some(f) = &flow {
            f.queued();
        }
        Self(flow)
    }

    /// An already-counted message: takes over responsibility for counting it
    /// out without counting it in again.
    pub fn adopt(flow: Option<Arc<PeerFlow>>) -> Self {
        Self(flow)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f.completed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_with_nothing_outstanding_is_idle() {
        let flow = PeerFlow::new();
        assert!(flow.is_idle());
        flow.queued();
        assert!(!flow.is_idle());
        flow.completed();
        assert!(flow.is_idle());
    }

    /// The count covers every message in flight, not just the newest: a pong
    /// behind two blocks must wait for both.
    #[test]
    fn the_count_tracks_every_message_in_flight() {
        let flow = PeerFlow::new();
        flow.queued();
        flow.queued();
        assert_eq!(flow.in_flight(), 2);
        flow.completed();
        assert!(!flow.is_idle(), "one is still outstanding");
        flow.completed();
        assert!(flow.is_idle());
    }

    /// A double completion must not wrap the count. Parking every future
    /// pong until the ping timeout is a worse failure than answering one
    /// early, so the count floors at zero.
    #[test]
    fn an_extra_completion_cannot_wrap_the_count() {
        let flow = PeerFlow::new();
        flow.completed();
        flow.completed();
        assert_eq!(flow.in_flight(), 0);
        assert!(flow.is_idle());
    }

    /// The guard counts out on every exit path, which is the whole reason it
    /// exists: a block leaves the pipeline a dozen ways.
    #[test]
    fn the_guard_counts_out_when_it_is_dropped() {
        let flow = Arc::new(PeerFlow::new());
        {
            let _g = InFlight::new(Some(flow.clone()));
            assert_eq!(flow.in_flight(), 1);
        }
        assert!(flow.is_idle(), "the guard's drop completed the message");
    }

    #[tokio::test]
    async fn waiting_returns_at_once_when_the_peer_is_already_idle() {
        let flow = PeerFlow::new();
        // Would hang if `wait_for` did not check the current value first.
        tokio::time::timeout(std::time::Duration::from_secs(5), flow.wait_idle())
            .await
            .expect("an idle peer does not wait");
    }

    #[tokio::test]
    async fn waiting_returns_once_the_last_message_completes() {
        let flow = Arc::new(PeerFlow::new());
        let guard = InFlight::new(Some(flow.clone()));
        let waiter = {
            let flow = flow.clone();
            tokio::spawn(async move { flow.wait_idle().await })
        };
        // Still outstanding, so the waiter is parked.
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "the pong must wait for the block");
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the wait ends when the message completes")
            .unwrap();
    }
}
