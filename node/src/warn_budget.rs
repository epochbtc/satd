//! A per-site budget for warnings that a flood can emit at line rate.
//!
//! An accept loop that refuses a connection at capacity logs one line per
//! refusal. Under a connection flood that is thousands of formatted lines a
//! second, each carrying a peer address, and the loop backs off only on
//! accept *errors*, never on refusals — so the flood's cheapest effect is
//! filling the operator's disk with the report of itself. Every listener
//! that sheds at accept routes its warning through a [`WarnBudget`]: the
//! first `burst` events in each window are logged, the rest are counted,
//! and the first line of the next window carries the count it swallowed.
//!
//! A budget belongs to one listener. A `static` in the accept function is
//! only that when the function serves a single listener: one that serves
//! several binds (the JSON-RPC accept loops) must own an instance per bind,
//! or a flood on one silences the others' reports.
//!
//! ```ignore
//! let at_capacity = WarnBudget::new(5, Duration::from_secs(60));
//! // ... in the accept loop:
//! if let Some(suppressed) = at_capacity.tick() {
//!     tracing::warn!(peer = %peer, suppressed, "at-capacity rejection");
//! }
//! ```

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A fixed-window log budget. Cheap enough to sit on an accept path: one
/// uncontended mutex per event.
pub struct WarnBudget {
    burst: u32,
    window: Duration,
    state: Mutex<State>,
}

struct State {
    window_start: Option<Instant>,
    logged: u32,
    suppressed: u64,
}

impl WarnBudget {
    /// Log the first `burst` events of every `window`; count the rest.
    pub const fn new(burst: u32, window: Duration) -> Self {
        Self {
            burst,
            window,
            state: Mutex::new(State {
                window_start: None,
                logged: 0,
                suppressed: 0,
            }),
        }
    }

    /// Record one event. `Some(suppressed)` means the caller should log it,
    /// and `suppressed` is how many events the previous window swallowed
    /// (zero within a window); `None` means stay quiet.
    pub fn tick(&self) -> Option<u64> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&self, now: Instant) -> Option<u64> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = match s.window_start {
            None => true,
            Some(start) => now.duration_since(start) >= self.window,
        };
        if fresh {
            let carried = s.suppressed;
            s.window_start = Some(now);
            s.logged = 1;
            s.suppressed = 0;
            return Some(carried);
        }
        if s.logged < self.burst {
            s.logged += 1;
            return Some(0);
        }
        s.suppressed += 1;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_the_burst_then_counts_until_the_window_turns() {
        let b = WarnBudget::new(2, Duration::from_secs(1));
        let t0 = Instant::now();
        assert_eq!(b.tick_at(t0), Some(0));
        assert_eq!(b.tick_at(t0 + Duration::from_millis(1)), Some(0));
        for i in 0..3 {
            assert_eq!(b.tick_at(t0 + Duration::from_millis(2 + i)), None);
        }
        // The next window's first line reports what the last one swallowed.
        assert_eq!(b.tick_at(t0 + Duration::from_secs(1)), Some(3));
        assert_eq!(b.tick_at(t0 + Duration::from_millis(1001)), Some(0));
        assert_eq!(b.tick_at(t0 + Duration::from_millis(1002)), None);
    }

    #[test]
    fn a_quiet_window_carries_nothing() {
        let b = WarnBudget::new(1, Duration::from_secs(1));
        let t0 = Instant::now();
        assert_eq!(b.tick_at(t0), Some(0));
        assert_eq!(b.tick_at(t0 + Duration::from_secs(5)), Some(0));
    }

    #[test]
    fn a_zero_burst_still_reports_once_per_window() {
        // burst 0 degenerates to one line per window (the window opener),
        // which is the floor: an operator always learns the surface is
        // shedding, and how much.
        let b = WarnBudget::new(0, Duration::from_secs(1));
        let t0 = Instant::now();
        assert_eq!(b.tick_at(t0), Some(0));
        assert_eq!(b.tick_at(t0 + Duration::from_millis(1)), None);
        assert_eq!(b.tick_at(t0 + Duration::from_secs(1)), Some(1));
    }
}
