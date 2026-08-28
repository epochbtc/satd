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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Bitcoin Core's key for message types it does not count individually
/// (`NET_MESSAGE_TYPE_OTHER` in `net.cpp`). satd also folds decoy packets and
/// undecodable frames in here, since neither carries a message type.
pub const MSG_TYPE_OTHER: &str = "*other*";

/// Normalise a `NetworkMessage::cmd()` into a per-message-counter key.
///
/// rust-bitcoin returns `"unknown"` for a command it has no variant for, and
/// every other value is a `&'static str` from a closed set -- so a peer can
/// never make satd allocate a new map key, which is the memory-DoS Core
/// guards against by only counting message types it knows.
fn msg_key(cmd: &'static str) -> &'static str {
    if cmd == "unknown" { MSG_TYPE_OTHER } else { cmd }
}

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
    /// Per-message-type byte tallies behind `getpeerinfo`'s
    /// `bytessent_per_msg` / `bytesrecv_per_msg`. Bounded by the message-type
    /// enum plus `*other*`, so these maps cannot grow with peer traffic.
    /// Locked only for the duration of one `+=`; never held across an await.
    per_msg_sent: Mutex<BTreeMap<&'static str, u64>>,
    per_msg_recv: Mutex<BTreeMap<&'static str, u64>>,
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
            per_msg_sent: Mutex::new(BTreeMap::new()),
            per_msg_recv: Mutex::new(BTreeMap::new()),
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

    /// Attribute `n` already-counted sent bytes to a message type.
    ///
    /// Separate from [`Self::record_sent`] because the two are recorded at
    /// different points on the read path: bytes are counted as soon as a frame
    /// comes off the wire, but its message type is only known once the frame
    /// has been decrypted and decoded. Calling both keeps
    /// `sum(per_msg) == total`.
    pub fn attribute_sent(&self, cmd: &'static str, n: usize) {
        if let Ok(mut m) = self.per_msg_sent.lock() {
            *m.entry(msg_key(cmd)).or_insert(0) += n as u64;
        }
    }

    /// Attribute `n` already-counted received bytes to a message type.
    pub fn attribute_recv(&self, cmd: &'static str, n: usize) {
        if let Ok(mut m) = self.per_msg_recv.lock() {
            *m.entry(msg_key(cmd)).or_insert(0) += n as u64;
        }
    }

    /// Snapshot of `bytessent_per_msg`.
    pub fn bytes_sent_per_msg(&self) -> BTreeMap<&'static str, u64> {
        self.per_msg_sent.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Snapshot of `bytesrecv_per_msg`.
    pub fn bytes_recv_per_msg(&self) -> BTreeMap<&'static str, u64> {
        self.per_msg_recv.lock().map(|m| m.clone()).unwrap_or_default()
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

    /// The per-type tallies must add up to the peer's byte total: they are the
    /// same bytes, attributed. A site that counts one without the other would
    /// make `getpeerinfo` self-contradictory.
    #[test]
    fn per_message_tallies_sum_to_the_totals() {
        let a = PeerStats::new(NetTotals::new());
        for (cmd, n) in [("ping", 32usize), ("pong", 32), ("inv", 61), ("ping", 32)] {
            a.record_sent(n);
            a.attribute_sent(cmd, n);
            a.record_recv(n);
            a.attribute_recv(cmd, n);
        }
        let sent = a.bytes_sent_per_msg();
        assert_eq!(sent.get("ping"), Some(&64), "repeat sends accumulate");
        assert_eq!(sent.get("pong"), Some(&32));
        assert_eq!(sent.get("inv"), Some(&61));
        assert_eq!(sent.values().sum::<u64>(), a.bytes_sent());
        assert_eq!(a.bytes_recv_per_msg().values().sum::<u64>(), a.bytes_recv());
    }

    /// A message type satd has no variant for must not become a map key of its
    /// own: the key set has to stay bounded no matter what a peer sends.
    #[test]
    fn unknown_message_types_fold_into_other() {
        let a = PeerStats::new(NetTotals::new());
        a.attribute_recv("unknown", 100);
        a.attribute_recv(MSG_TYPE_OTHER, 5);
        a.attribute_recv("ping", 32);
        let recv = a.bytes_recv_per_msg();
        assert_eq!(recv.get(MSG_TYPE_OTHER), Some(&105), "both fold into one key");
        assert_eq!(recv.get("unknown"), None, "\"unknown\" is not a key Core emits");
        assert_eq!(recv.len(), 2);
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
