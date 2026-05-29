use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Shared startup-progress signal used by the lightweight pre-init RPC and
/// by long-running startup phases (RocksDB open, reindex, chainstate replay)
/// to surface progress to operators while the full node is still loading.
///
/// Hot fields (`current` / `total`) are atomic so the reindex inner loop can
/// update them without locking. The phase + free-form message live behind a
/// short critical section because they change rarely.
///
/// This type also owns the **timing** for the active phase — elapsed wall
/// clock, a throughput rate, and an ETA — so those are computed daemon-side
/// once and survive a TUI restart, rather than being re-derived by each
/// client from scratch. Elapsed and rate are tracked here for every counting
/// phase; the ETA is either a generic linear estimate from the rate (good for
/// the fast-start byte download) or a weight-aware value pushed by the reindex
/// driver via [`set_eta`](Self::set_eta).
pub struct StartupProgress {
    inner: parking_lot::RwLock<Inner>,
    current: AtomicU64,
    total: AtomicU64,
    // u64 sentinel for `Option<u64>`: `u64::MAX` means "no stop target".
    // Real `-stopatheight` values are u32, so the sentinel can never
    // collide with a legitimate setting.
    stop_height: AtomicU64,

    /// Wall-clock anchor for the whole startup, set once at construction.
    /// Owned daemon-side so elapsed time is stable across TUI restarts.
    started_at: Instant,
    /// Milliseconds since `started_at` at which the current phase began.
    /// Reset by [`set_phase`](Self::set_phase). Phase elapsed is
    /// `started_at.elapsed() - phase_started_ms`.
    phase_started_ms: AtomicU64,

    /// Rolling `(timestamp, current)` samples for rate estimation, fed from
    /// the `set_current` hot path but throttled to one sample per second so
    /// the lock is taken rarely. Cleared on phase change.
    samples: parking_lot::Mutex<VecDeque<(Instant, u64)>>,
    /// Milliseconds since `started_at` of the last recorded sample, used to
    /// throttle sampling without locking `samples` on every update.
    last_sample_ms: AtomicU64,

    /// ETA override slot, in seconds. See [`NO_OVERRIDE`] / [`OVERRIDE_NONE`]:
    /// when unset the snapshot derives a linear ETA from the rate; when a
    /// driver calls [`set_eta`](Self::set_eta) it takes precedence.
    eta_secs: AtomicU64,
}

#[derive(Default, Clone)]
struct Inner {
    phase: String,
    message: String,
}

const NO_STOP_HEIGHT: u64 = u64::MAX;

/// Number of `(timestamp, current)` samples kept for rate estimation.
const RATE_WINDOW: usize = 30;
/// Minimum spacing between rate samples.
const SAMPLE_INTERVAL_MS: u64 = 1000;
/// `last_sample_ms` sentinel meaning "no sample taken yet this phase" — the
/// next `set_current` records an anchor sample immediately rather than
/// waiting out the throttle interval.
const NEVER_SAMPLED: u64 = u64::MAX;

/// ETA slot is unset: the snapshot derives a linear ETA from the rate.
const NO_OVERRIDE: u64 = u64::MAX;
/// ETA slot is driver-controlled but no estimate is available yet — surface
/// `None` and do NOT fall back to the linear estimate (which would be wildly
/// wrong for the cost-skewed reindex phases).
const OVERRIDE_NONE: u64 = u64::MAX - 1;
/// Largest ETA a driver can store; keeps real values clear of the sentinels.
const MAX_ETA: u64 = u64::MAX - 2;

/// Snapshot of startup progress at one point in time.
#[derive(Debug, Clone, Default)]
pub struct StartupSnapshot {
    /// Stable machine-readable phase identifier
    /// (e.g. `"opening_db"`, `"reindex_scan"`, `"reindex_connect"`).
    pub phase: String,
    /// Human-readable status message.
    pub message: String,
    /// Items processed so far in the current phase. `0` if not applicable.
    pub current: u64,
    /// Items expected in the current phase. `0` means unknown.
    pub total: u64,
    /// Configured `-stopatheight` target, if the active phase honors one.
    /// `Some(h)` means the phase will exit cleanly when `current >= h`,
    /// even if `total` is larger (e.g. reindex against block files that
    /// extend past the stop height).
    pub stop_height: Option<u64>,
    /// Wall-clock seconds elapsed in the current phase.
    pub elapsed_secs: u64,
    /// Wall-clock seconds elapsed since startup began (across all phases).
    pub total_elapsed_secs: u64,
    /// Items processed per second over the recent sample window, if known.
    /// Units match `current` (blocks for reindex, bytes for the download).
    pub rate: Option<f64>,
    /// Estimated seconds remaining in the current phase, if known.
    pub eta_secs: Option<u64>,
}

impl StartupProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: parking_lot::RwLock::new(Inner {
                phase: "opening_db".to_string(),
                message: "Opening database...".to_string(),
            }),
            current: AtomicU64::new(0),
            total: AtomicU64::new(0),
            stop_height: AtomicU64::new(NO_STOP_HEIGHT),
            started_at: Instant::now(),
            phase_started_ms: AtomicU64::new(0),
            samples: parking_lot::Mutex::new(VecDeque::with_capacity(RATE_WINDOW)),
            last_sample_ms: AtomicU64::new(NEVER_SAMPLED),
            eta_secs: AtomicU64::new(NO_OVERRIDE),
        })
    }

    /// Set the current phase and clear the per-phase counters and timing.
    pub fn set_phase(&self, phase: &str, message: &str) {
        {
            let mut g = self.inner.write();
            g.phase.clear();
            g.phase.push_str(phase);
            g.message.clear();
            g.message.push_str(message);
        }
        self.current.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        // The stop height is a per-phase concern: cleared on phase change
        // so a later phase that doesn't honor stopatheight (e.g.
        // "chain_init") doesn't inherit the previous phase's target.
        self.stop_height.store(NO_STOP_HEIGHT, Ordering::Relaxed);
        // Reset timing so elapsed / rate / ETA reflect the new phase only.
        self.phase_started_ms
            .store(self.started_at.elapsed().as_millis() as u64, Ordering::Relaxed);
        self.last_sample_ms.store(NEVER_SAMPLED, Ordering::Relaxed);
        self.eta_secs.store(NO_OVERRIDE, Ordering::Relaxed);
        self.samples.lock().clear();
    }

    /// Update only the human-readable message, leaving phase + counters intact.
    pub fn set_message(&self, message: &str) {
        let mut g = self.inner.write();
        g.message.clear();
        g.message.push_str(message);
    }

    /// Record the expected work item count for the current phase.
    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    /// Hot path: bump current item count and feed the rate sampler.
    pub fn set_current(&self, current: u64) {
        self.current.store(current, Ordering::Relaxed);

        // Throttled rate sampling: take a sample at most once per second so
        // the `samples` lock stays cold even when this is called thousands of
        // times per second on the early (trivial) blocks of a reindex.
        let now_ms = self.started_at.elapsed().as_millis() as u64;
        let last = self.last_sample_ms.load(Ordering::Relaxed);
        // Take an anchor sample immediately on the first update of a phase
        // (`last == NEVER_SAMPLED`), then throttle to one per second.
        let due = last == NEVER_SAMPLED || now_ms.saturating_sub(last) >= SAMPLE_INTERVAL_MS;
        if due
            && self
                .last_sample_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let mut w = self.samples.lock();
            w.push_back((Instant::now(), current));
            while w.len() > RATE_WINDOW {
                w.pop_front();
            }
        }
    }

    /// Record the `-stopatheight` target for the current phase so the TUI
    /// can show that reindex will halt at height H even when the on-disk
    /// block files extend past it. Pass `None` to clear.
    pub fn set_stop_height(&self, stop_height: Option<u64>) {
        self.stop_height
            .store(stop_height.unwrap_or(NO_STOP_HEIGHT), Ordering::Relaxed);
    }

    /// Push a driver-computed ETA (in seconds) for the current phase. Used by
    /// the reindex loops to supply a weight-aware estimate that the linear
    /// rate-based fallback can't produce. Calling this — even with `None` —
    /// switches the phase into driver-controlled ETA mode for the remainder
    /// of the phase, suppressing the linear fallback until the next
    /// [`set_phase`](Self::set_phase).
    pub fn set_eta(&self, eta: Option<u64>) {
        let v = match eta {
            Some(s) => s.min(MAX_ETA),
            None => OVERRIDE_NONE,
        };
        self.eta_secs.store(v, Ordering::Relaxed);
    }

    /// Items/sec over the rolling window, or `None` if the window is too
    /// short or hasn't advanced.
    fn rate(&self) -> Option<f64> {
        let w = self.samples.lock();
        if w.len() < 2 {
            return None;
        }
        let (t0, c0) = *w.front()?;
        let (t1, c1) = *w.back()?;
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt < 1.0 || c1 <= c0 {
            return None;
        }
        Some((c1 - c0) as f64 / dt)
    }

    pub fn snapshot(&self) -> StartupSnapshot {
        let (phase, message) = {
            let g = self.inner.read();
            (g.phase.clone(), g.message.clone())
        };
        let current = self.current.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let raw_stop = self.stop_height.load(Ordering::Relaxed);
        let stop_height = (raw_stop != NO_STOP_HEIGHT).then_some(raw_stop);

        let total_elapsed_ms = self.started_at.elapsed().as_millis() as u64;
        let phase_ms = self.phase_started_ms.load(Ordering::Relaxed);
        let total_elapsed_secs = total_elapsed_ms / 1000;
        let elapsed_secs = total_elapsed_ms.saturating_sub(phase_ms) / 1000;

        let rate = self.rate();

        let eta_secs = match self.eta_secs.load(Ordering::Relaxed) {
            // No driver override: derive a linear ETA from the rate. The
            // operator's target is `stop_height` when set, else `total`.
            NO_OVERRIDE => {
                let denom = stop_height.unwrap_or(total);
                match rate {
                    Some(r) if r > 0.0 && denom > current => {
                        Some(((denom - current) as f64 / r) as u64)
                    }
                    _ => None,
                }
            }
            OVERRIDE_NONE => None,
            v => Some(v),
        };

        StartupSnapshot {
            phase,
            message,
            current,
            total,
            stop_height,
            elapsed_secs,
            total_elapsed_secs,
            rate,
            eta_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reflects_current_state() {
        let p = StartupProgress::new();
        let s = p.snapshot();
        assert_eq!(s.phase, "opening_db");
        assert_eq!(s.current, 0);
        assert_eq!(s.total, 0);
        assert_eq!(s.stop_height, None);

        p.set_phase("reindex_connect", "Replaying blocks");
        p.set_total(10_000);
        p.set_current(2_500);
        let s = p.snapshot();
        assert_eq!(s.phase, "reindex_connect");
        assert_eq!(s.message, "Replaying blocks");
        assert_eq!(s.current, 2_500);
        assert_eq!(s.total, 10_000);
        assert_eq!(s.stop_height, None);

        // set_phase clears counters
        p.set_phase("ready", "All set");
        let s = p.snapshot();
        assert_eq!(s.current, 0);
        assert_eq!(s.total, 0);
        assert_eq!(s.stop_height, None);
    }

    #[test]
    fn stop_height_is_per_phase() {
        let p = StartupProgress::new();
        p.set_phase("reindex_chainstate", "Replaying UTXO set");
        p.set_total(945_000);
        p.set_stop_height(Some(840_000));

        let s = p.snapshot();
        assert_eq!(s.total, 945_000);
        assert_eq!(s.stop_height, Some(840_000));

        // Switching phase clears the stop target so it can't leak into
        // phases that don't honor it.
        p.set_phase("chain_init", "Initializing chain state...");
        let s = p.snapshot();
        assert_eq!(s.stop_height, None);
    }

    #[test]
    fn stop_height_can_be_cleared() {
        let p = StartupProgress::new();
        p.set_phase("reindex_chainstate", "Replaying UTXO set");
        p.set_stop_height(Some(123));
        assert_eq!(p.snapshot().stop_height, Some(123));
        p.set_stop_height(None);
        assert_eq!(p.snapshot().stop_height, None);
    }

    #[test]
    fn elapsed_is_nonzero_immediately_and_monotonic() {
        let p = StartupProgress::new();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let s = p.snapshot();
        // The daemon owns the clock, so elapsed is meaningful on the very
        // first snapshot — no client-side warmup.
        assert!(s.total_elapsed_secs >= 1, "total_elapsed={}", s.total_elapsed_secs);
        assert!(s.elapsed_secs >= 1, "elapsed={}", s.elapsed_secs);
    }

    #[test]
    fn phase_elapsed_resets_but_total_does_not() {
        let p = StartupProgress::new();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        p.set_phase("reindex_connect", "Replaying blocks");
        let s = p.snapshot();
        // Phase clock restarts at the transition; the overall clock keeps
        // running.
        assert!(s.total_elapsed_secs >= 1, "total_elapsed={}", s.total_elapsed_secs);
        assert_eq!(s.elapsed_secs, 0, "phase elapsed should reset on set_phase");
    }

    #[test]
    fn rate_populates_after_two_samples() {
        let p = StartupProgress::new();
        p.set_phase("reindex_connect", "Replaying blocks");
        p.set_total(1_000_000);
        // First sample.
        p.set_current(0);
        assert!(p.snapshot().rate.is_none(), "one sample is not enough");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // Second sample, one second later, with progress.
        p.set_current(2_000);
        let r = p.snapshot().rate.expect("rate should be known after 2 samples");
        // ~2000 items over ~1.1s.
        assert!(r > 500.0 && r < 4000.0, "rate={r}");
    }

    #[test]
    fn linear_eta_from_rate_when_no_override() {
        let p = StartupProgress::new();
        p.set_phase("fast_start_download", "Downloading snapshot");
        p.set_total(10_000);
        p.set_current(0);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        p.set_current(1_000);
        let s = p.snapshot();
        // ~1000/s, 9000 remaining → ~9s. Allow a wide band for timing jitter.
        let eta = s.eta_secs.expect("linear ETA should be derived from rate");
        assert!((2..=30).contains(&eta), "eta={eta}");
    }

    #[test]
    fn set_eta_some_overrides_linear() {
        let p = StartupProgress::new();
        p.set_phase("reindex_connect", "Replaying blocks");
        p.set_total(10_000);
        p.set_current(0);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        p.set_current(1_000);
        // Driver pushes a weight-aware estimate that bears no relation to the
        // naive linear one — it must win.
        p.set_eta(Some(123_456));
        assert_eq!(p.snapshot().eta_secs, Some(123_456));
    }

    #[test]
    fn set_eta_none_suppresses_linear_fallback() {
        let p = StartupProgress::new();
        p.set_phase("reindex_connect", "Replaying blocks");
        p.set_total(10_000);
        p.set_current(0);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        p.set_current(1_000);
        // Activate driver mode with no estimate yet: ETA is None, and we do
        // NOT leak the (bogus for reindex) linear value.
        p.set_eta(None);
        assert_eq!(p.snapshot().eta_secs, None);
    }

    #[test]
    fn set_phase_clears_eta_override() {
        let p = StartupProgress::new();
        p.set_phase("reindex_connect", "Replaying blocks");
        p.set_eta(Some(999));
        assert_eq!(p.snapshot().eta_secs, Some(999));
        // New phase falls back to linear mode (no samples yet → None).
        p.set_phase("chain_init", "Initializing chain state...");
        assert_eq!(p.snapshot().eta_secs, None);
    }
}
