//! AssumeUTXO background catch-up download tracking.
//!
//! After `loadtxoutset`, the primary chainstate serves the tip from the
//! snapshot at `snapshot_height`, while a
//! [`BackgroundChainState`](crate::chain::background::BackgroundChainState)
//! re-validates the history genesis→`snapshot_height`. The *headers* for
//! that historical range are already present (a precondition of
//! `loadtxoutset`), but the block *data* below the snapshot was never
//! downloaded — forward IBD only ever requests blocks above the primary
//! tip. This tracker drives downloading that historical block data.
//!
//! It is intentionally much simpler than the forward [`IbdScheduler`]
//! (`crate::net::ibd`): the background connects strictly in-order and the
//! historical chain is checkpoint-protected, so a small sliding window of
//! sequential requests above the background connect cursor is sufficient.
//! Robustness against a peer that accepts a `getdata` but never delivers
//! comes from a stale-request timeout that returns the height to the
//! request pool on the next pass.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::net::peer::PeerId;

/// Tracks which historical block heights have an outstanding `getdata`
/// to a peer, so the background download window neither re-requests a
/// height already in flight nor leaves a silently-dropped request stuck
/// forever.
pub struct BgDownloader {
    /// Heights requested but not yet stored: `height -> (peer, requested_at)`.
    in_flight: HashMap<u32, (PeerId, Instant)>,
    /// How far above the background connect cursor we keep blocks
    /// requested/downloaded. Bounds outstanding requests and on-disk
    /// read-ahead so a slow connector cannot make the downloader run the
    /// node out of disk.
    window: u32,
    /// A request older than this is assumed lost and becomes eligible for
    /// re-request (to a possibly different peer) on the next pass.
    stale_after: Duration,
}

impl BgDownloader {
    pub fn new(window: u32, stale_after: Duration) -> Self {
        Self {
            in_flight: HashMap::new(),
            window: window.max(1),
            stale_after,
        }
    }

    /// A height's data was stored — it no longer needs requesting.
    pub fn note_stored(&mut self, height: u32) {
        self.in_flight.remove(&height);
    }

    /// Drop every in-flight request assigned to a departed peer so the
    /// heights are re-requested promptly rather than waiting out the
    /// stale timeout.
    pub fn note_peer_gone(&mut self, peer: PeerId) {
        self.in_flight.retain(|_, (p, _)| *p != peer);
    }

    /// Forget all outstanding requests (handoff completed / background
    /// detached — the tracker is about to go idle).
    pub fn reset(&mut self) {
        self.in_flight.clear();
    }

    /// Drop requests older than `stale_after` so they re-enter the pool.
    pub fn release_stale(&mut self, now: Instant) {
        let stale = self.stale_after;
        self.in_flight
            .retain(|_, (_, at)| now.duration_since(*at) < stale);
    }

    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    pub fn is_in_flight(&self, height: u32) -> bool {
        self.in_flight.contains_key(&height)
    }

    pub fn window(&self) -> u32 {
        self.window
    }

    /// The contiguous height range we want downloaded for the current
    /// connect `cursor`: `(cursor, min(cursor + window, snapshot)]`.
    /// Returns an empty range when the cursor has reached the snapshot.
    /// The caller maps each height to its (already-known) block hash,
    /// skips heights whose data is already on disk, skips
    /// [`is_in_flight`](Self::is_in_flight) heights, issues `getdata`, and
    /// records each via [`mark_in_flight`](Self::mark_in_flight).
    pub fn wanted_range(&self, cursor: u32, snapshot: u32) -> std::ops::RangeInclusive<u32> {
        // When `cursor >= snapshot`, `start > end`, which is an empty
        // `RangeInclusive` (iterates nothing, `is_empty()` is true).
        let start = cursor.saturating_add(1);
        let end = snapshot.min(cursor.saturating_add(self.window));
        start..=end
    }

    /// Record that `height` was just requested from `peer`.
    pub fn mark_in_flight(&mut self, height: u32, peer: PeerId, now: Instant) {
        self.in_flight.insert(height, (peer, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> PeerId {
        n
    }

    #[test]
    fn wanted_range_is_window_bounded_above_cursor() {
        let d = BgDownloader::new(100, Duration::from_secs(30));
        let r = d.wanted_range(0, 1000);
        assert_eq!(*r.start(), 1);
        assert_eq!(*r.end(), 100);
    }

    #[test]
    fn wanted_range_clamps_to_snapshot() {
        let d = BgDownloader::new(100, Duration::from_secs(30));
        let r = d.wanted_range(950, 1000);
        assert_eq!(*r.start(), 951);
        assert_eq!(*r.end(), 1000);
    }

    #[test]
    fn wanted_range_empty_at_or_past_snapshot() {
        let d = BgDownloader::new(100, Duration::from_secs(30));
        assert!(d.wanted_range(1000, 1000).is_empty());
        assert!(d.wanted_range(1001, 1000).is_empty());
    }

    #[test]
    fn note_stored_clears_in_flight() {
        let mut d = BgDownloader::new(100, Duration::from_secs(30));
        let now = Instant::now();
        d.mark_in_flight(5, pid(1), now);
        assert!(d.is_in_flight(5));
        d.note_stored(5);
        assert!(!d.is_in_flight(5));
        assert_eq!(d.in_flight_len(), 0);
    }

    #[test]
    fn release_stale_drops_only_expired() {
        let mut d = BgDownloader::new(100, Duration::from_secs(30));
        let t0 = Instant::now();
        d.mark_in_flight(5, pid(1), t0);
        d.mark_in_flight(6, pid(1), t0 + Duration::from_secs(25));
        // 31s after t0: height 5 (age 31s) is stale, height 6 (age 6s) is not.
        d.release_stale(t0 + Duration::from_secs(31));
        assert!(!d.is_in_flight(5));
        assert!(d.is_in_flight(6));
    }

    #[test]
    fn note_peer_gone_drops_that_peers_requests() {
        let mut d = BgDownloader::new(100, Duration::from_secs(30));
        let now = Instant::now();
        d.mark_in_flight(5, pid(1), now);
        d.mark_in_flight(6, pid(2), now);
        d.note_peer_gone(pid(1));
        assert!(!d.is_in_flight(5));
        assert!(d.is_in_flight(6));
    }

    #[test]
    fn reset_clears_everything() {
        let mut d = BgDownloader::new(100, Duration::from_secs(30));
        let now = Instant::now();
        d.mark_in_flight(5, pid(1), now);
        d.mark_in_flight(6, pid(2), now);
        d.reset();
        assert_eq!(d.in_flight_len(), 0);
    }
}
