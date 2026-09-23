//! What one miner has been doing: the tally behind its log lines, and the
//! registry of connected miners behind `getstratuminfo`.
//!
//! Every figure here is derived from shares the server judged, so it
//! describes the device as the node sees it — a miner whose own dashboard
//! reports a hashrate this tally does not is hashing work the node never
//! receives.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, MutexGuard};

use super::server::ShareOutcome;

/// Accepted shares older than this no longer count toward the hashrate
/// estimate. At vardiff's one share per 30 seconds that is about twenty
/// shares, which puts the estimate within roughly a quarter of the truth.
pub const HASHRATE_WINDOW: Duration = Duration::from_secs(600);

/// How often a connected miner's status is logged under `-debug=stratum`.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(300);

/// Longest miner-supplied string (user agent, device name) kept.
pub const MAX_LABEL_CHARS: usize = 64;

/// A connection that has not authorized (Stratum V1) or opened a channel
/// (Stratum V2) is dropped after sending nothing for this long.
pub const UNAUTHORIZED_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The shortest silence that drops a miner, however fast it submits.
pub const MIN_MINER_IDLE_TIMEOUT: Duration = UNAUTHORIZED_IDLE_TIMEOUT;

/// The silence that drops a miner before its share rate is known.
pub const UNESTIMATED_MINER_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// The longest silence a miner is allowed, however slowly it submits.
pub const MAX_MINER_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

/// How many expected share intervals of silence drop a miner.
///
/// Shares arrive as a Poisson process, so a gap of `k` expected intervals
/// happens with probability `e^-k`. At vardiff's one share per 30 seconds a
/// miner has about 2,900 gaps a day; at `k = 20` (`e^-20` ≈ 2·10⁻⁹) a
/// hashing miner is dropped by chance about once in four centuries, and
/// about once a week if the rate estimate were twice the truth (`e^-10`). A dead miner is found after about ten minutes.
pub const IDLE_SHARE_INTERVALS: f64 = 20.0;

/// Shares an estimate needs before it is trusted for the idle limit.
const MIN_ESTIMATE_SHARES: usize = 4;

/// How long a miner may send nothing before its connection is dropped.
///
/// `share_rate` is the shares per second the miner is expected to submit at
/// its current difficulty ([`MinerTally::share_rate`]), summed over a
/// connection's channels. A miner submits nothing but shares, so silence
/// only means something relative to how often it should find one: a fixed
/// limit either drops a healthy miner whose difficulty makes shares rare or
/// waits needlessly long for a dead one.
pub fn miner_idle_timeout(share_rate: Option<f64>) -> Duration {
    match share_rate {
        Some(rate) if rate > 0.0 && rate.is_finite() => {
            let secs = IDLE_SHARE_INTERVALS / rate;
            if secs >= MAX_MINER_IDLE_TIMEOUT.as_secs_f64() {
                MAX_MINER_IDLE_TIMEOUT
            } else {
                Duration::from_secs_f64(secs).max(MIN_MINER_IDLE_TIMEOUT)
            }
        }
        _ => UNESTIMATED_MINER_IDLE_TIMEOUT,
    }
}

/// Bound on the shares the estimate remembers. Only a miner far below its
/// vardiff target (regtest, or a `suggest_difficulty` floor set too low)
/// reaches it; the estimate then covers the shares it kept.
const MAX_WINDOW_SHARES: usize = 4096;

/// Shares judged, by outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShareCounts {
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
}

impl ShareCounts {
    fn add(&mut self, outcome: ShareOutcome) {
        match outcome {
            ShareOutcome::Accepted => self.accepted += 1,
            ShareOutcome::Rejected => self.rejected += 1,
            ShareOutcome::Stale => self.stale += 1,
        }
    }
}

/// One miner's shares: a Stratum V1 connection or a Stratum V2 channel.
#[derive(Debug)]
pub struct MinerTally {
    connected: Instant,
    total: ShareCounts,
    since_status: ShareCounts,
    last_status: Instant,
    /// Accepted shares inside [`HASHRATE_WINDOW`]: when, and the difficulty
    /// they were judged at.
    window: VecDeque<(Instant, u64)>,
    best_share: f64,
    last_share: Option<Instant>,
    /// Every accepted share since the miner connected: how many, and the
    /// sum of the difficulties they were judged at.
    lifetime_shares: usize,
    lifetime_work: f64,
    /// The window's hashrate as of the last accepted share, once the window
    /// held enough shares to say. Fixed at the share, so readings taken
    /// during a later silence (which empty the window) do not change it.
    window_rate_at_last_share: Option<f64>,
    /// The difficulty the last accepted share was judged at.
    last_share_difficulty: u64,
}

/// A periodic status reading, covering the shares since the last one.
#[derive(Debug, Clone, Copy)]
pub struct StatusReport {
    pub shares: ShareCounts,
    pub hashrate: f64,
    /// Seconds since the last accepted share, if there was one.
    pub last_share_secs: Option<u64>,
}

impl MinerTally {
    pub fn new(now: Instant) -> Self {
        Self {
            connected: now,
            total: ShareCounts::default(),
            since_status: ShareCounts::default(),
            last_status: now,
            window: VecDeque::new(),
            best_share: 0.0,
            last_share: None,
            lifetime_shares: 0,
            lifetime_work: 0.0,
            window_rate_at_last_share: None,
            last_share_difficulty: 0,
        }
    }

    /// Count an accepted share judged at `difficulty` whose header achieved
    /// `hash_difficulty`.
    pub fn accept(&mut self, now: Instant, difficulty: u64, hash_difficulty: f64) {
        self.total.add(ShareOutcome::Accepted);
        self.since_status.add(ShareOutcome::Accepted);
        if self.window.len() == MAX_WINDOW_SHARES {
            self.window.pop_front();
        }
        self.window.push_back((now, difficulty));
        if hash_difficulty > self.best_share {
            self.best_share = hash_difficulty;
        }
        self.last_share = Some(now);
        self.last_share_difficulty = difficulty;
        self.lifetime_shares += 1;
        self.lifetime_work += difficulty as f64;
        let rate = self.hashrate(now);
        self.window_rate_at_last_share = (self.window.len() >= MIN_ESTIMATE_SHARES).then_some(rate);
    }

    /// Count a share that was not accepted.
    pub(crate) fn refuse(&mut self, outcome: ShareOutcome) {
        self.total.add(outcome);
        self.since_status.add(outcome);
    }

    pub fn total(&self) -> ShareCounts {
        self.total
    }

    /// The highest difficulty any accepted share achieved.
    pub fn best_share(&self) -> f64 {
        self.best_share
    }

    pub fn connected_secs(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.connected).as_secs()
    }

    pub fn last_share_secs(&self, now: Instant) -> Option<u64> {
        self.last_share.map(|t| now.saturating_duration_since(t).as_secs())
    }

    /// Estimated hashes per second: the work the accepted shares in the
    /// window prove, over the time the window spans.
    ///
    /// A share at difficulty `d` takes `d · 2^32` hashes on average. The span
    /// is the window, or the time since the miner connected if that is
    /// shorter, so a new miner is not diluted by time before it existed.
    pub fn hashrate(&mut self, now: Instant) -> f64 {
        while self.window.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) > HASHRATE_WINDOW) {
            self.window.pop_front();
        }
        let window_start = now.checked_sub(HASHRATE_WINDOW).unwrap_or(self.connected);
        let mut start = window_start.max(self.connected);
        if self.window.len() == MAX_WINDOW_SHARES
            && let Some((oldest, _)) = self.window.front()
        {
            start = start.max(*oldest);
        }
        let span = now.saturating_duration_since(start).as_secs_f64();
        if span < 1.0 {
            return 0.0;
        }
        let work: f64 = self.window.iter().map(|(_, d)| *d as f64).sum();
        work * 4_294_967_296.0 / span
    }

    /// Shares per second this miner is expected to submit at `difficulty`,
    /// or `None` until there are enough shares to say.
    ///
    /// Two estimates, and the lower is taken: the recent window, which
    /// follows a miner that slowed down, and the whole connection, which
    /// still has an answer for a miner whose shares are too rare to fill the
    /// window. The lower rate is the longer expected silence, so neither
    /// estimate's noise can make a hashing miner look dead.
    ///
    /// Both are measured up to the last accepted share, not up to now. The
    /// idle limit is asked about a silence in progress; measured up to now,
    /// that silence would lower the rate it is judged by, and the limit would
    /// grow as fast as the silence did — for a miner with a few shares behind
    /// it, faster, so it could never be reached.
    ///
    /// For the same reason the rate is taken at the higher of `difficulty`
    /// and the difficulty the last share was judged at. Vardiff lowers the
    /// difficulty of a miner that has gone quiet; judged at the lowered
    /// difficulty, the silence already endured could exceed the new limit at
    /// once, and a miner that was only unlucky would be dropped just as it
    /// was given easier shares to find.
    pub fn share_rate(&self, difficulty: u64) -> Option<f64> {
        let at = self.last_share?;
        let per_share = difficulty.max(self.last_share_difficulty).max(1) as f64 * 4_294_967_296.0;
        let window = self.window_rate_at_last_share;
        let span = at.saturating_duration_since(self.connected).as_secs_f64();
        let lifetime = (self.lifetime_shares >= MIN_ESTIMATE_SHARES && span >= 1.0)
            .then(|| self.lifetime_work * 4_294_967_296.0 / span);
        let hashrate = match (window, lifetime) {
            (Some(w), Some(l)) => w.min(l),
            (w, l) => w.or(l)?,
        };
        Some(hashrate / per_share)
    }

    /// A status reading once [`STATUS_INTERVAL`] has passed since the last.
    pub fn status_due(&mut self, now: Instant) -> Option<StatusReport> {
        if now.saturating_duration_since(self.last_status) < STATUS_INTERVAL {
            return None;
        }
        self.last_status = now;
        let shares = std::mem::take(&mut self.since_status);
        Some(StatusReport { shares, hashrate: self.hashrate(now), last_share_secs: self.last_share_secs(now) })
    }
}

/// One connected miner, as `getstratuminfo` reports it: a Stratum V1
/// connection once it authorized, or a Stratum V2 channel.
#[derive(Debug)]
pub struct MinerRecord {
    /// `"v1"` or `"v2"`.
    pub protocol: &'static str,
    pub peer: SocketAddr,
    /// The Stratum V2 channel; `None` for Stratum V1.
    pub channel_id: Option<u32>,
    /// The payout address, or `None` when the node's `--stratumaddress` pays.
    pub address: Option<String>,
    pub worker: Option<String>,
    /// The Stratum V1 user agent or the Stratum V2 vendor, hardware and
    /// firmware, already made safe by [`label`].
    pub device: Option<String>,
    /// The share difficulty the miner is currently set to.
    pub difficulty: u64,
    /// Unix time the miner connected (V1) or opened the channel (V2).
    pub connected_time: u64,
    pub tally: MinerTally,
}

impl MinerRecord {
    pub fn new(protocol: &'static str, peer: SocketAddr, channel_id: Option<u32>, difficulty: u64) -> Self {
        Self {
            protocol,
            peer,
            channel_id,
            address: None,
            worker: None,
            device: None,
            difficulty,
            connected_time: crate::time::now_secs(),
            tally: MinerTally::new(Instant::now()),
        }
    }

    fn info(&mut self, now: Instant, now_secs: u64) -> serde_json::Value {
        let total = self.tally.total();
        let last_share_time = self.tally.last_share_secs(now).map(|ago| now_secs.saturating_sub(ago));
        let best = self.tally.best_share();
        serde_json::json!({
            "protocol": self.protocol,
            "peer": self.peer.to_string(),
            "channel_id": self.channel_id,
            "address": self.address,
            "worker": self.worker,
            "device": self.device,
            "difficulty": self.difficulty,
            "connected_time": self.connected_time,
            "shares": { "accepted": total.accepted, "rejected": total.rejected, "stale": total.stale },
            // JSON has no infinity; an all-zero hash is not a share anyone finds.
            "best_share_difficulty": if best.is_finite() { best } else { f64::MAX },
            "last_share_time": last_share_time,
            "hashrate": self.tally.hashrate(now),
        })
    }
}

/// The miners connected now.
#[derive(Debug, Default)]
pub struct MinerRegistry {
    next_id: AtomicU64,
    miners: Mutex<BTreeMap<u64, Arc<Mutex<MinerRecord>>>>,
}

impl MinerRegistry {
    /// List `record` until the returned slot drops.
    pub fn register(self: &Arc<Self>, record: MinerRecord) -> MinerSlot {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let record = Arc::new(Mutex::new(record));
        self.miners.lock().insert(id, record.clone());
        MinerSlot { registry: self.clone(), id, record }
    }

    pub(crate) fn records(&self) -> Vec<Arc<Mutex<MinerRecord>>> {
        // Copied out, so a session's lock is never taken under the registry's.
        self.miners.lock().values().cloned().collect()
    }

    /// Every connected miner, oldest first.
    pub fn info(&self) -> Vec<serde_json::Value> {
        let (now, now_secs) = (Instant::now(), crate::time::now_secs());
        self.records().iter().map(|r| r.lock().info(now, now_secs)).collect()
    }

    /// How many miners are connected.
    pub fn len(&self) -> usize {
        self.miners.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The estimated hashrate of every connected miner, summed.
    pub fn hashrate(&self) -> f64 {
        let now = Instant::now();
        self.records().iter().map(|r| r.lock().tally.hashrate(now)).sum()
    }
}

/// A miner's entry in the [`MinerRegistry`], removed when this drops.
#[derive(Debug)]
pub struct MinerSlot {
    registry: Arc<MinerRegistry>,
    id: u64,
    record: Arc<Mutex<MinerRecord>>,
}

impl MinerSlot {
    /// The record. Take it once per statement: the lock is not reentrant.
    pub fn lock(&self) -> MutexGuard<'_, MinerRecord> {
        self.record.lock()
    }
}

impl Drop for MinerSlot {
    fn drop(&mut self) {
        self.registry.miners.lock().remove(&self.id);
    }
}

/// A miner-supplied string made safe to log: printable ASCII only, at most
/// [`MAX_LABEL_CHARS`]. A miner is a remote peer, and its user agent must not
/// be able to write a line break into the node's log.
pub fn label(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A hashrate with an SI unit, e.g. `1.21 TH/s`.
pub fn format_hashrate(hashes_per_sec: f64) -> String {
    const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
    let mut value = hashes_per_sec.max(0.0);
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// An achieved share difficulty for a log line: whole units from 100 up,
/// three decimals below, and scientific notation under 0.001 (regtest, where
/// a miss is far below difficulty 1), where a floor would read every miss as
/// zero.
pub fn format_difficulty(difficulty: f64) -> String {
    if !difficulty.is_finite() {
        "inf".to_string()
    } else if difficulty >= 100.0 {
        format!("{difficulty:.0}")
    } else if difficulty >= 0.001 || difficulty == 0.0 {
        format!("{difficulty:.3}")
    } else {
        format!("{difficulty:.2e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrate_is_proven_work_over_the_span() {
        let t0 = Instant::now();
        let mut tally = MinerTally::new(t0);
        assert_eq!(tally.hashrate(t0), 0.0, "no time, no estimate");
        // Ten shares at difficulty 10,000 over 300 s: 10 · 10^4 · 2^32 / 300.
        for i in 1..=10 {
            tally.accept(t0 + Duration::from_secs(30 * i), 10_000, 12_000.0);
        }
        let expected = 10.0 * 10_000.0 * 4_294_967_296.0 / 300.0;
        let got = tally.hashrate(t0 + Duration::from_secs(300));
        assert!((got - expected).abs() / expected < 1e-9, "{got} vs {expected}");
        assert_eq!(format_hashrate(got), "1.43 TH/s");

        // Past the window, early shares stop counting and the span stops growing.
        let later = t0 + HASHRATE_WINDOW + Duration::from_secs(150);
        let got = tally.hashrate(later);
        let kept = 6.0; // the shares at 150..=300 s are within 600 s of 750 s
        let expected = kept * 10_000.0 * 4_294_967_296.0 / HASHRATE_WINDOW.as_secs_f64();
        assert!((got - expected).abs() / expected < 1e-9, "{got} vs {expected}");
    }

    /// The idle limit is twenty expected share intervals, within bounds.
    /// The first case is the one seen live: a BM1370 at about 1.2 TH/s that
    /// vardiff had set to 20,160 expects a share every ~72 s, and the old
    /// fixed 120 s dropped it after a gap one in five gaps exceeds.
    #[test]
    fn idle_timeout_scales_with_the_expected_share_interval() {
        let rate = |hashrate: f64, difficulty: f64| hashrate / (difficulty * 4_294_967_296.0);

        let observed = miner_idle_timeout(Some(rate(1.2e12, 20_160.0)));
        let interval = 20_160.0 * 4_294_967_296.0 / 1.2e12;
        assert!((observed.as_secs_f64() - IDLE_SHARE_INTERVALS * interval).abs() < 1.0, "{observed:?}");
        assert!(observed > Duration::from_secs(1_400), "{observed:?}");

        // A fast miner still gets the floor; a very slow one the ceiling.
        assert_eq!(miner_idle_timeout(Some(rate(1.2e12, 10.0))), MIN_MINER_IDLE_TIMEOUT);
        assert_eq!(miner_idle_timeout(Some(rate(1.0e9, 1.0e6))), MAX_MINER_IDLE_TIMEOUT);
        // No estimate, or a useless one: the fixed allowance.
        for unknown in [None, Some(0.0), Some(f64::NAN), Some(f64::INFINITY)] {
            assert_eq!(miner_idle_timeout(unknown), UNESTIMATED_MINER_IDLE_TIMEOUT, "{unknown:?}");
        }
    }

    /// The share rate needs a few shares, and takes the slower of the recent
    /// window and the whole connection.
    #[test]
    fn share_rate_is_the_lower_of_window_and_lifetime() {
        let t0 = Instant::now();
        let secs = |s: u64| t0 + Duration::from_secs(s);
        let mut tally = MinerTally::new(t0);
        for i in 1..MIN_ESTIMATE_SHARES as u64 {
            tally.accept(secs(30 * i), 1_000, 1_000.0);
        }
        assert_eq!(tally.share_rate(1_000), None, "too few shares to say");

        // One share every 30 s at the current difficulty: a rate of 1/30.
        let mut tally = MinerTally::new(t0);
        for i in 1..=20 {
            tally.accept(secs(30 * i), 1_000, 1_000.0);
        }
        let rate = tally.share_rate(1_000).unwrap();
        assert!((rate - 1.0 / 30.0).abs() < 1e-9, "{rate}");
        // The same hashrate at four times the difficulty: a quarter the rate.
        let rate = tally.share_rate(4_000).unwrap();
        assert!((rate - 1.0 / 120.0).abs() < 1e-9, "{rate}");

        // Shares too rare to fill the window: the whole connection answers.
        let mut tally = MinerTally::new(t0);
        for i in 1..=10 {
            tally.accept(secs(300 * i), 1_000, 1_000.0);
        }
        let rate = tally.share_rate(1_000).unwrap();
        assert!((rate - 1.0 / 300.0).abs() < 1e-9, "{rate}");

        // A miner that slowed down: the recent window is slower, and wins.
        let mut tally = MinerTally::new(t0);
        for i in 1..=99 {
            tally.accept(secs(10 * i), 1_000, 1_000.0);
        }
        for i in 1..=10 {
            tally.accept(secs(1_000 + 60 * i), 1_000, 1_000.0);
        }
        // The window ends at the last share (1,600 s) and so starts after the
        // fast run's last share (990 s).
        let rate = tally.share_rate(1_000).unwrap();
        assert!((rate - 1.0 / 60.0).abs() < 1e-9, "{rate}");
    }

    /// The limit for a silence in progress must not grow with that silence:
    /// the estimate stops at the last share. A miner with ten shares at one
    /// every 30 s is allowed twenty intervals, 600 s, whether asked at its
    /// last share or 700 s into the silence. Measured up to now, the window
    /// would be empty by then and the whole connection's rate would have
    /// fallen to ten shares in 1,000 s, a limit of 2,000 s still growing.
    #[test]
    fn the_permitted_silence_does_not_grow_with_the_silence() {
        let t0 = Instant::now();
        let secs = |s: u64| t0 + Duration::from_secs(s);
        let mut tally = MinerTally::new(t0);
        for i in 1..=10 {
            tally.accept(secs(30 * i), 1_000, 1_000.0);
        }
        let at_last_share = miner_idle_timeout(tally.share_rate(1_000));
        assert_eq!(at_last_share, Duration::from_secs(600));
        // Status readings during the silence evict the window; the limit
        // must not move.
        let _ = tally.hashrate(secs(1_000));
        assert_eq!(miner_idle_timeout(tally.share_rate(1_000)), at_last_share);

        // A miner that slowed before going quiet: the window (one share a
        // minute) is slower than the whole connection, so it sets the limit,
        // and still does after the silence has emptied it.
        let mut tally = MinerTally::new(t0);
        for i in 1..=99 {
            tally.accept(secs(10 * i), 1_000, 1_000.0);
        }
        for i in 1..=10 {
            tally.accept(secs(1_000 + 60 * i), 1_000, 1_000.0);
        }
        let at_last_share = miner_idle_timeout(tally.share_rate(1_000));
        assert_eq!(at_last_share, Duration::from_secs(1_200));
        let _ = tally.hashrate(secs(1_600 + 900));
        assert_eq!(miner_idle_timeout(tally.share_rate(1_000)), at_last_share);
    }

    /// Vardiff lowering the difficulty during a silence does not shorten the
    /// limit that silence is judged by.
    #[test]
    fn a_lowered_difficulty_does_not_shorten_the_idle_limit() {
        let t0 = Instant::now();
        let secs = |s: u64| t0 + Duration::from_secs(s);
        let mut tally = MinerTally::new(t0);
        for i in 1..=10 {
            tally.accept(secs(30 * i), 8_000, 8_000.0);
        }
        let before = miner_idle_timeout(tally.share_rate(8_000));
        assert_eq!(before, Duration::from_secs(600));
        // Vardiff divides the difficulty by eight after a long silence.
        assert_eq!(miner_idle_timeout(tally.share_rate(1_000)), before);
        // Raised, the limit grows: shares at the new difficulty are rarer.
        assert_eq!(miner_idle_timeout(tally.share_rate(16_000)), Duration::from_secs(1_200));
    }

    #[test]
    fn counts_best_share_and_status() {
        let t0 = Instant::now();
        let mut tally = MinerTally::new(t0);
        tally.accept(t0, 1_000, 1_500.0);
        tally.accept(t0, 1_000, 90_000.0);
        tally.refuse(ShareOutcome::Rejected);
        tally.refuse(ShareOutcome::Stale);
        assert_eq!(tally.total(), ShareCounts { accepted: 2, rejected: 1, stale: 1 });
        assert_eq!(tally.best_share(), 90_000.0);

        assert!(tally.status_due(t0 + STATUS_INTERVAL - Duration::from_secs(1)).is_none());
        let report = tally.status_due(t0 + STATUS_INTERVAL).expect("due");
        assert_eq!(report.shares, ShareCounts { accepted: 2, rejected: 1, stale: 1 });
        assert_eq!(report.last_share_secs, Some(STATUS_INTERVAL.as_secs()));
        // The interval restarts; the totals do not.
        tally.refuse(ShareOutcome::Rejected);
        let report = tally.status_due(t0 + STATUS_INTERVAL * 2).expect("due");
        assert_eq!(report.shares, ShareCounts { accepted: 0, rejected: 1, stale: 0 });
        assert_eq!(tally.total().rejected, 2);
    }

    #[test]
    fn registry_lists_miners_until_their_slot_drops() {
        let registry = Arc::new(MinerRegistry::default());
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let first = registry.register(MinerRecord::new("v1", peer, None, 1_000));
        let second = registry.register(MinerRecord::new("v2", peer, Some(3), 2_000));
        {
            let mut r = first.lock();
            r.worker = Some("rig1".into());
            r.tally.accept(Instant::now(), 1_000, 5_000.0);
        }
        let info = registry.info();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0]["protocol"], "v1");
        assert_eq!(info[0]["worker"], "rig1");
        assert_eq!(info[0]["shares"]["accepted"], 1);
        assert_eq!(info[0]["best_share_difficulty"], 5_000.0);
        assert!(info[0]["last_share_time"].is_u64());
        assert_eq!(info[1]["channel_id"], 3);
        assert!(info[1]["last_share_time"].is_null());
        drop(first);
        let info = registry.info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0]["difficulty"], 2_000);
        drop(second);
        assert!(registry.info().is_empty());
        assert_eq!(registry.hashrate(), 0.0);
    }

    #[test]
    fn labels_cannot_break_a_log_line() {
        assert_eq!(label("bitaxe/BM1370/v2.9.0"), "bitaxe/BM1370/v2.9.0");
        assert_eq!(label("evil\n2026-01-01 ERROR forged\r"), "evil2026-01-01 ERROR forged");
        assert_eq!(label(&"x".repeat(500)).len(), MAX_LABEL_CHARS);
        assert_eq!(label("  \u{1b}[31m  "), "[31m");
        assert_eq!(format_hashrate(0.0), "0.00 H/s");
        assert_eq!(format_hashrate(1_210_000_000_000.0), "1.21 TH/s");
        assert_eq!(format_difficulty(f64::INFINITY), "inf");
        assert_eq!(format_difficulty(123_456.7), "123457");
        assert_eq!(format_difficulty(0.0421), "0.042");
        assert_eq!(format_difficulty(0.0), "0.000");
        assert_eq!(format_difficulty(4.66e-10), "4.66e-10");
    }
}
