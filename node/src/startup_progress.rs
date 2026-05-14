use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Shared startup-progress signal used by the lightweight pre-init RPC and
/// by long-running startup phases (RocksDB open, reindex, chainstate replay)
/// to surface progress to operators while the full node is still loading.
///
/// Hot fields (`current` / `total`) are atomic so the reindex inner loop can
/// update them without locking. The phase + free-form message live behind a
/// short critical section because they change rarely.
#[derive(Default)]
pub struct StartupProgress {
    inner: parking_lot::RwLock<Inner>,
    current: AtomicU64,
    total: AtomicU64,
    // u64 sentinel for `Option<u64>`: `u64::MAX` means "no stop target".
    // Real `-stopatheight` values are u32, so the sentinel can never
    // collide with a legitimate setting.
    stop_height: AtomicU64,
}

#[derive(Default, Clone)]
struct Inner {
    phase: String,
    message: String,
}

const NO_STOP_HEIGHT: u64 = u64::MAX;

/// Snapshot of startup progress at one point in time.
#[derive(Debug, Clone)]
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
        })
    }

    /// Set the current phase and clear the per-phase counters.
    pub fn set_phase(&self, phase: &str, message: &str) {
        let mut g = self.inner.write();
        g.phase.clear();
        g.phase.push_str(phase);
        g.message.clear();
        g.message.push_str(message);
        self.current.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        // The stop height is a per-phase concern: cleared on phase change
        // so a later phase that doesn't honor stopatheight (e.g.
        // "chain_init") doesn't inherit the previous phase's target.
        self.stop_height.store(NO_STOP_HEIGHT, Ordering::Relaxed);
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

    /// Hot path: bump current item count.
    pub fn set_current(&self, current: u64) {
        self.current.store(current, Ordering::Relaxed);
    }

    /// Record the `-stopatheight` target for the current phase so the TUI
    /// can show that reindex will halt at height H even when the on-disk
    /// block files extend past it. Pass `None` to clear.
    pub fn set_stop_height(&self, stop_height: Option<u64>) {
        self.stop_height
            .store(stop_height.unwrap_or(NO_STOP_HEIGHT), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StartupSnapshot {
        let g = self.inner.read();
        let raw_stop = self.stop_height.load(Ordering::Relaxed);
        StartupSnapshot {
            phase: g.phase.clone(),
            message: g.message.clone(),
            current: self.current.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            stop_height: if raw_stop == NO_STOP_HEIGHT {
                None
            } else {
                Some(raw_stop)
            },
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
}
