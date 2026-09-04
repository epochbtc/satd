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

/// Monotonic microseconds for round-trip timing.
///
/// Deliberately not wall-clock: `setmocktime` and NTP steps both move
/// `SystemTime`, and either would otherwise show up as a nonsense ping time
/// (or a negative one, clamped to zero).
fn now_micros() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_micros() as u64
}

/// Process-global byte totals across all peers, past and present. Like
/// Bitcoin Core's `CConnman` totals, these persist after a peer disconnects
/// (a peer's bytes are not subtracted when it goes away).
#[derive(Debug, Default)]
pub struct NetTotals {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    /// Peers dropped for not answering a ping. Its own counter because this
    /// is the one disconnect satd initiates on its own judgement of a peer:
    /// if it ever misfires the symptom is a falling peer count with no
    /// external cause, and a log line is not something you can alert on.
    ping_timeouts: AtomicU64,
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

    pub fn ping_timeouts(&self) -> u64 {
        self.ping_timeouts.load(Ordering::Relaxed)
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
    /// Nonce of the ping awaiting a pong, or 0 when none is outstanding.
    /// satd never sends nonce 0, so 0 is unambiguous as "nothing pending".
    ping_nonce: AtomicU64,
    /// [`now_micros`] at which the outstanding ping was sent.
    ping_sent_us: AtomicU64,
    /// Last measured round trip, in microseconds; 0 = never measured.
    ping_time_us: AtomicU64,
    /// Best round trip seen, in microseconds; `u64::MAX` = never measured.
    min_ping_us: AtomicU64,
    /// Unix seconds when we last received a block from this peer (0 = never).
    last_block: AtomicU64,
    /// Unix seconds when we last received a transaction from this peer (0 = never).
    last_transaction: AtomicU64,
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
            ping_nonce: AtomicU64::new(0),
            ping_sent_us: AtomicU64::new(0),
            ping_time_us: AtomicU64::new(0),
            min_ping_us: AtomicU64::new(u64::MAX),
            last_block: AtomicU64::new(0),
            last_transaction: AtomicU64::new(0),
            totals,
        })
    }

    /// Record that this peer is being dropped for an unanswered ping.
    pub fn note_ping_timeout(&self) {
        self.totals.ping_timeouts.fetch_add(1, Ordering::Relaxed);
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

    /// Unix seconds when a block was last received from this peer (0 = never).
    pub fn last_block(&self) -> u64 {
        self.last_block.load(Ordering::Relaxed)
    }

    /// Unix seconds when a transaction was last received from this peer (0 = never).
    pub fn last_transaction(&self) -> u64 {
        self.last_transaction.load(Ordering::Relaxed)
    }

    /// Record that a block was received from this peer now.
    pub fn record_block(&self) {
        self.last_block.store(now_secs(), Ordering::Relaxed);
    }

    /// Record that a transaction was received from this peer now.
    pub fn record_transaction(&self) {
        self.last_transaction.store(now_secs(), Ordering::Relaxed);
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

    /// Note that a keepalive ping carrying `nonce` has just gone out.
    ///
    /// Overwrites any previous outstanding ping, which cannot happen on the
    /// send path (it only pings when nothing is pending) but keeps this
    /// honest if a caller ever pings unconditionally: the newest ping is the
    /// one a pong will be matched against.
    pub fn ping_sent(&self, nonce: u64) {
        self.ping_nonce.store(nonce, Ordering::Relaxed);
        self.ping_sent_us.store(now_micros(), Ordering::Relaxed);
    }

    /// Match a received pong against the outstanding ping, recording the
    /// round trip. Returns whether it matched.
    ///
    /// A peer that echoes a stale or invented nonce is ignored rather than
    /// allowed to write a bogus round-trip time, and a peer that sends the
    /// same valid pong twice is counted once.
    ///
    /// A pong carrying nonce zero clears the outstanding ping without
    /// recording a time. That is Bitcoin Core's "Nonce zero" case
    /// (`net_processing.cpp`): the peer is plainly answering, it just cannot
    /// be timed, so the ping is finished rather than left pending. Without
    /// this the ping would stay outstanding forever -- no further ping would
    /// ever be sent, and the peer would be dropped at `PING_TIMEOUT` for
    /// answering.
    ///
    /// The send timestamp is read *before* the nonce is cleared. Both halves
    /// run on the peer's own task today, but the read-then-clear order is
    /// what makes that an optimisation rather than a correctness
    /// requirement: clearing first would let a concurrent `ping_sent`
    /// overwrite the timestamp between the two, yielding a ~0 round trip
    /// that `min_ping_us` would then keep forever.
    pub fn pong_received(&self, nonce: u64) -> bool {
        let outstanding = self.ping_nonce.load(Ordering::Relaxed);
        if outstanding == 0 {
            return false;
        }
        if nonce == 0 {
            self.ping_nonce.store(0, Ordering::Relaxed);
            return true;
        }
        if nonce != outstanding {
            return false;
        }
        let sent_us = self.ping_sent_us.load(Ordering::Relaxed);
        self.ping_nonce.store(0, Ordering::Relaxed);
        // A sub-microsecond round trip (loopback) would otherwise store 0,
        // which is this field's "never measured" sentinel.
        let rtt = now_micros().saturating_sub(sent_us).max(1);
        self.ping_time_us.store(rtt, Ordering::Relaxed);
        self.min_ping_us.fetch_min(rtt, Ordering::Relaxed);
        true
    }

    /// Whether a ping is still awaiting its pong.
    pub fn ping_outstanding(&self) -> bool {
        self.ping_nonce.load(Ordering::Relaxed) != 0
    }

    /// Last measured round trip in seconds, or `None` if never measured.
    pub fn ping_time_secs(&self) -> Option<f64> {
        match self.ping_time_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(us as f64 / 1_000_000.0),
        }
    }

    /// Best round trip seen in seconds, or `None` if never measured.
    pub fn min_ping_secs(&self) -> Option<f64> {
        match self.min_ping_us.load(Ordering::Relaxed) {
            u64::MAX => None,
            us => Some(us as f64 / 1_000_000.0),
        }
    }

    /// Whether the outstanding ping has gone unanswered for longer than
    /// `timeout`.
    ///
    /// False when no ping is pending, which is the important half: an idle
    /// but healthy peer -- one that answered its last ping and has had
    /// nothing to say since -- must never be judged timed out.
    pub fn ping_timed_out(&self, timeout: std::time::Duration) -> bool {
        self.ping_wait_secs()
            .is_some_and(|waited| waited > timeout.as_secs_f64())
    }

    /// Seconds the outstanding ping has been waiting, or `None` if no ping
    /// is pending.
    pub fn ping_wait_secs(&self) -> Option<f64> {
        if !self.ping_outstanding() {
            return None;
        }
        let waited = now_micros().saturating_sub(self.ping_sent_us.load(Ordering::Relaxed));
        // Core gates on `m_ping_wait > 0s`, so a getpeerinfo issued in the
        // same microsecond as the ping omits the field rather than reporting
        // a zero-length wait.
        if waited == 0 {
            return None;
        }
        Some(waited as f64 / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_pong_records_a_round_trip() {
        let s = PeerStats::new(NetTotals::new());
        assert_eq!(s.ping_time_secs(), None, "nothing measured yet");
        assert_eq!(s.min_ping_secs(), None);
        assert_eq!(s.ping_wait_secs(), None, "no ping outstanding");

        s.ping_sent(42);
        assert!(s.ping_outstanding());
        // Core omits `pingwait` until the wait is measurably non-zero, so the
        // field only appears once time has actually passed.
        assert_eq!(s.ping_wait_secs(), None, "no measurable wait yet");
        std::thread::sleep(std::time::Duration::from_micros(1500));
        assert!(s.ping_wait_secs().is_some_and(|w| w > 0.0));

        assert!(s.pong_received(42));
        assert!(!s.ping_outstanding());
        // Loopback round trips can be sub-microsecond; the recorded time must
        // still be non-zero so it is distinguishable from "never measured".
        assert!(s.ping_time_secs().unwrap() > 0.0);
        assert_eq!(s.ping_time_secs(), s.min_ping_secs());
        assert_eq!(s.ping_wait_secs(), None);
    }

    #[test]
    fn a_wrong_or_repeated_nonce_cannot_write_a_ping_time() {
        let s = PeerStats::new(NetTotals::new());
        // Unsolicited pong, before any ping went out.
        assert!(!s.pong_received(7));
        assert_eq!(s.ping_time_secs(), None);

        s.ping_sent(1234);
        // A peer echoing some other nonce leaves the ping outstanding.
        assert!(!s.pong_received(9999));
        assert!(s.ping_outstanding());
        assert_eq!(s.ping_time_secs(), None);

        assert!(s.pong_received(1234));
        let measured = s.ping_time_secs();
        // The same valid pong replayed is counted once, not twice.
        assert!(!s.pong_received(1234));
        assert_eq!(s.ping_time_secs(), measured);
    }

    #[test]
    fn a_pong_carrying_nonce_zero_finishes_the_ping_without_timing_it() {
        use std::time::Duration;
        let s = PeerStats::new(NetTotals::new());

        // Nothing outstanding: a nonce-zero pong is still just an
        // unsolicited pong.
        assert!(!s.pong_received(0));

        s.ping_sent(77);
        // Core treats a nonce-zero pong as finishing the ping ("Nonce zero")
        // rather than as a mismatch. Left outstanding, this peer would never
        // be pinged again and would be dropped at PING_TIMEOUT -- for
        // answering.
        assert!(s.pong_received(0));
        assert!(!s.ping_outstanding());
        assert!(!s.ping_timed_out(Duration::ZERO));
        // It cannot be timed, so it must not write a round trip.
        assert_eq!(s.ping_time_secs(), None);
        assert_eq!(s.min_ping_secs(), None);
    }

    #[test]
    fn only_an_unanswered_ping_can_time_out() {
        use std::time::Duration;
        let s = PeerStats::new(NetTotals::new());

        // A peer that has never been pinged is not timed out, however small
        // the timeout -- there is nothing outstanding to be late.
        assert!(!s.ping_timed_out(Duration::ZERO));

        s.ping_sent(1);
        assert!(
            !s.ping_timed_out(Duration::from_secs(1200)),
            "a ping sent just now is not overdue"
        );

        // The clock here is monotonic from process start, so a 20-minute wait
        // cannot be faked by backdating -- the subtraction just clamps to
        // zero. Compare a real elapsed wait against a small deadline instead;
        // the predicate is the same one PING_TIMEOUT drives.
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            s.ping_timed_out(Duration::from_millis(1)),
            "a ping unanswered past its deadline has timed out"
        );

        // Answering it clears the timeout: an idle peer that pongs is healthy
        // and must not be dropped no matter how long it then stays quiet.
        assert!(s.pong_received(1));
        assert!(!s.ping_timed_out(Duration::ZERO));
    }

    #[test]
    fn minping_keeps_the_best_round_trip_not_the_last() {
        let s = PeerStats::new(NetTotals::new());
        s.ping_sent(1);
        assert!(s.pong_received(1));
        let first = s.ping_time_us.load(Ordering::Relaxed);

        // Force a deliberately slow second round trip by sleeping through it.
        // Backdating `ping_sent_us` instead is not sound: `now_micros` counts
        // from its first call, so early in the process the subtraction
        // saturates to zero and the "slow" round trip collapses to the raw
        // clock reading, which can tie with `first`. Sleeping past `first`
        // guarantees the strict ordering the assertions need.
        s.ping_sent(2);
        std::thread::sleep(std::time::Duration::from_micros(first + 1500));
        assert!(s.pong_received(2));

        assert!(
            s.ping_time_us.load(Ordering::Relaxed) > first,
            "pingtime tracks the latest round trip"
        );
        assert_eq!(
            s.min_ping_us.load(Ordering::Relaxed),
            first,
            "minping keeps the best round trip seen"
        );
    }

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
