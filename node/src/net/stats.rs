//! Per-peer and process-global P2P wire activity counters.
//!
//! These feed `getpeerinfo` (`bytessent`/`bytesrecv`/`lastsend`/`lastrecv`),
//! `getnettotals`, and the Prometheus `satd_net_bytes_*_total` counters.
//! They are updated from the connection read/write halves
//! ([`crate::net::connection`] / [`crate::net::v2transport`]) at the exact
//! point bytes cross the wire, so the count is the actual on-wire size for
//! both the v1 plaintext and v2 (BIP 324) encrypted transports — for v2 that
//! includes the framing / authentication overhead, matching Core's
//! "bytes on the wire" semantics.
//!
//! Scope note: counting starts once the connection is split into read/write
//! halves (i.e. post-handshake steady state). The handshake itself
//! (version/verack, and the v2 key/garbage exchange) is a small, one-time
//! per-peer cost that is not included — `getnettotals` is therefore a slight
//! undercount of absolute socket bytes, but exact for all ongoing traffic.
//! For monitoring, prefer the native Prometheus listener (`-metricsport`)
//! over polling these RPCs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Current wall-clock time as unix seconds (0 on a pre-epoch clock).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Process-global byte totals across all peers, past and present. Like
/// Bitcoin Core's `CConnman` totals, these persist after a peer disconnects
/// (a peer's bytes are not subtracted when it goes away).
#[derive(Debug, Default)]
pub struct NetTotals {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
}

impl NetTotals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }
}

/// Per-peer wire activity. Shared (`Arc`) between a peer's I/O tasks (which
/// record) and its `PeerHandle` (which `getpeerinfo` reads). Every record
/// also bumps the shared [`NetTotals`], so the global counters are always
/// the sum of all per-peer activity.
#[derive(Debug)]
pub struct PeerStats {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    /// Unix seconds of the last send / recv; 0 = never.
    last_send: AtomicU64,
    last_recv: AtomicU64,
    totals: Arc<NetTotals>,
}

impl PeerStats {
    /// Create a per-peer counter set tied to the process-global `totals`.
    pub fn new(totals: Arc<NetTotals>) -> Arc<Self> {
        Arc::new(Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            last_send: AtomicU64::new(0),
            last_recv: AtomicU64::new(0),
            totals,
        })
    }

    /// Record `n` bytes written to this peer (updates per-peer + global +
    /// `lastsend`).
    pub fn record_sent(&self, n: usize) {
        let n = n as u64;
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
        self.last_send.store(now_secs(), Ordering::Relaxed);
        self.totals.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` bytes read from this peer (updates per-peer + global +
    /// `lastrecv`).
    pub fn record_recv(&self, n: usize) {
        let n = n as u64;
        self.bytes_recv.fetch_add(n, Ordering::Relaxed);
        self.last_recv.store(now_secs(), Ordering::Relaxed);
        self.totals.bytes_recv.fetch_add(n, Ordering::Relaxed);
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    pub fn last_send(&self) -> u64 {
        self.last_send.load(Ordering::Relaxed)
    }

    pub fn last_recv(&self) -> u64 {
        self.last_recv.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_peer_records_roll_up_into_global_totals() {
        let totals = NetTotals::new();
        let a = PeerStats::new(totals.clone());
        let b = PeerStats::new(totals.clone());

        a.record_sent(100);
        a.record_recv(40);
        b.record_sent(25);

        assert_eq!(a.bytes_sent(), 100);
        assert_eq!(a.bytes_recv(), 40);
        assert_eq!(b.bytes_sent(), 25);

        // Global is the sum across peers, past and present.
        assert_eq!(totals.bytes_sent(), 125);
        assert_eq!(totals.bytes_recv(), 40);
    }

    #[test]
    fn records_stamp_last_activity() {
        let a = PeerStats::new(NetTotals::new());
        assert_eq!(a.last_send(), 0);
        assert_eq!(a.last_recv(), 0);
        a.record_sent(1);
        a.record_recv(1);
        assert!(a.last_send() > 0);
        assert!(a.last_recv() > 0);
    }
}
