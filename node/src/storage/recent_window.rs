//! Exact per-height UTXO counts for the most recent block heights.
//!
//! `gettxoutsetinfo`'s age distribution is built from the chainstate's
//! creation-height histogram, which counts coins per 1000-block chunk. That is
//! too coarse for the young end of the distribution: the `<1h` bucket is six
//! blocks wide and `<1d` is 144, so a chunk-sized answer cannot place a coin
//! in either. This window keeps an exact count per height for the most recent
//! [`RECENT_WINDOW`] heights, so the four youngest buckets are exact and only
//! the older ones fall back to the chunk estimate.
//!
//! The window is maintained by the same batch deltas as the coarse histogram,
//! in the same atomic write, so it cannot drift from the coins it describes.
//! It lives under its own metadata key and is additive: a datadir written by
//! a binary that did not maintain it simply has no key (or a stale one) and
//! is rebuilt with a single scan of the coins.

use std::collections::HashMap;

/// Heights the four youngest age buckets span: the `<1mo` edge (4320 blocks
/// = 30 days at ten minutes a block).
pub const RECENT_WINDOW: u32 = 4320;

/// Heights kept below the recent range.
///
/// The window slides forward when a coin is created above it and never slides
/// back, because sliding back would need counts it no longer holds. A reorg or
/// `invalidateblock` lowers the tip without lowering the window, which moves
/// the oldest recent heights below it. The margin keeps a reorg up to this
/// many blocks deep fully covered. A deeper one leaves the oldest heights to
/// the chunk estimate until the chain regrows past its old tip.
pub const RECENT_WINDOW_REORG_MARGIN: u32 = 144;

/// Number of heights a [`RecentHeightWindow`] holds.
pub const RECENT_WINDOW_LEN: u32 = RECENT_WINDOW + RECENT_WINDOW_REORG_MARGIN;

/// Exact count of unspent coins by creation height for the most recent
/// [`RECENT_WINDOW_LEN`] heights. `counts[i]` is the count at height
/// `base + i`.
///
/// No coin exists above [`top`](Self::top): the window slides up as soon as a
/// coin is created above it. Heights below `base` are not tracked.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecentHeightWindow {
    /// Chain tip the window was last written at, as raw hash bytes. All
    /// zeroes when the store had no tip. A window whose `tip_hash` does not
    /// match the store's tip on open was left behind by a binary that did
    /// not maintain it, and is discarded and rebuilt.
    pub tip_hash: [u8; 32],
    /// Height of `counts[0]`.
    pub base: u32,
    /// Always [`RECENT_WINDOW_LEN`] long.
    pub counts: Vec<u64>,
}

impl RecentHeightWindow {
    /// An all-zero window at heights `0..RECENT_WINDOW_LEN`: the exact
    /// answer for an empty UTXO set.
    pub fn empty(tip_hash: [u8; 32]) -> Self {
        Self {
            tip_hash,
            base: 0,
            counts: vec![0; RECENT_WINDOW_LEN as usize],
        }
    }

    /// Highest height the window holds.
    pub fn top(&self) -> u32 {
        self.base + (RECENT_WINDOW_LEN - 1)
    }

    /// Whether the window has the shape this binary writes. A persisted
    /// value that fails this was written with a different length and is
    /// rebuilt rather than trusted.
    pub fn is_well_formed(&self) -> bool {
        self.counts.len() == RECENT_WINDOW_LEN as usize
            && self.base.checked_add(RECENT_WINDOW_LEN - 1).is_some()
    }

    /// Exact count of unspent coins created at `height`, or `None` when the
    /// window does not track it (below `base`). Heights above
    /// [`top`](Self::top) hold no coins and read as `Some(0)`.
    pub fn count_at(&self, height: u32) -> Option<u64> {
        if height < self.base {
            return None;
        }
        Some(
            self.counts
                .get((height - self.base) as usize)
                .copied()
                .unwrap_or(0),
        )
    }

    /// Whether every height of the recent range ending at `tip` is tracked:
    /// `tip - RECENT_WINDOW + 1 ..= tip`, clipped at genesis.
    pub fn covers_recent_range(&self, tip: u32) -> bool {
        self.base <= tip.saturating_sub(RECENT_WINDOW - 1)
    }

    /// Slide forward so `height` is the top, zeroing the heights that enter
    /// and discarding the ones that leave. No-op when `height` is already
    /// inside the window.
    fn slide_to(&mut self, height: u32) {
        if height <= self.top() {
            return;
        }
        let new_base = height - (RECENT_WINDOW_LEN - 1);
        let shift = (new_base - self.base) as usize;
        if shift >= self.counts.len() {
            self.counts.iter_mut().for_each(|c| *c = 0);
        } else {
            self.counts.rotate_left(shift);
            let len = self.counts.len();
            self.counts[len - shift..].iter_mut().for_each(|c| *c = 0);
        }
        self.base = new_base;
    }

    /// Count one coin created at `height`. Used by the build scan, which
    /// sees each coin once, in key order rather than height order.
    pub(crate) fn add_one(&mut self, height: u32) {
        self.slide_to(height);
        if let Some(slot) = height
            .checked_sub(self.base)
            .and_then(|i| self.counts.get_mut(i as usize))
        {
            *slot += 1;
        }
    }

    /// Apply per-height net deltas. The window first slides up to the
    /// highest height with a non-zero delta, then every delta inside it is
    /// applied; deltas below `base` are dropped (the coarse histogram still
    /// counts those coins).
    ///
    /// Returns the heights whose count would have gone negative. Those are
    /// clamped to zero. A consistent chainstate never produces one: it means
    /// a coin was removed that the window never counted.
    pub(crate) fn apply(&mut self, deltas: &HashMap<u32, i64>) -> Vec<u32> {
        if let Some(max) = deltas
            .iter()
            .filter(|(_, d)| **d != 0)
            .map(|(h, _)| *h)
            .max()
        {
            self.slide_to(max);
        }
        let mut clamped = Vec::new();
        for (&height, &delta) in deltas {
            if delta == 0 || height < self.base {
                continue;
            }
            let Some(slot) = self.counts.get_mut((height - self.base) as usize) else {
                continue;
            };
            let next = *slot as i64 + delta;
            if next < 0 {
                clamped.push(height);
                *slot = 0;
            } else {
                *slot = next as u64;
            }
        }
        clamped.sort_unstable();
        clamped
    }
}

/// What [`Store::build_recent_window`](crate::storage::Store::build_recent_window)
/// did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecentWindowBuild {
    /// The window was already live; nothing was scanned.
    AlreadyLive,
    /// The coins were scanned and the window is now live.
    Built {
        coins_scanned: u64,
        elapsed_ms: u64,
        /// Distinct heights written while the scan ran, folded in at the end.
        pending_heights: usize,
    },
    /// Another build is already scanning; this call did nothing.
    InProgress,
    /// The caller's cancel flag was set. Nothing was persisted; the next
    /// start builds again.
    Cancelled,
    /// The chainstate was cleared while the scan ran. The clear left an
    /// exact (empty) window in place, so this scan's result was discarded.
    Superseded,
    /// This store does not keep a window.
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deltas(pairs: &[(u32, i64)]) -> HashMap<u32, i64> {
        let mut m = HashMap::new();
        for &(h, d) in pairs {
            *m.entry(h).or_default() += d;
        }
        m
    }

    #[test]
    fn empty_window_spans_from_genesis() {
        let w = RecentHeightWindow::empty([0; 32]);
        assert_eq!(w.base, 0);
        assert_eq!(w.top(), RECENT_WINDOW_LEN - 1);
        assert!(w.is_well_formed());
        assert!(w.covers_recent_range(0));
        assert!(w.covers_recent_range(RECENT_WINDOW_LEN - 1));
        assert_eq!(w.count_at(0), Some(0));
        assert_eq!(w.count_at(u32::MAX), Some(0));
    }

    #[test]
    fn apply_slides_to_the_highest_nonzero_delta_only() {
        let mut w = RecentHeightWindow::empty([0; 32]);
        w.apply(&deltas(&[(3, 2), (10, 1)]));
        assert_eq!(w.count_at(3), Some(2));
        // A put+remove pair nets to zero and must not move the window.
        w.apply(&deltas(&[(RECENT_WINDOW_LEN + 50, 1), (RECENT_WINDOW_LEN + 50, -1)]));
        assert_eq!(w.base, 0);
        // A real coin above the top slides the window so it is the top.
        w.apply(&deltas(&[(RECENT_WINDOW_LEN + 5, 1)]));
        assert_eq!(w.top(), RECENT_WINDOW_LEN + 5);
        assert_eq!(w.base, 6);
        assert_eq!(w.count_at(3), None, "slid below the window");
        assert_eq!(w.count_at(10), Some(1), "survived the slide");
        assert_eq!(w.count_at(RECENT_WINDOW_LEN + 5), Some(1));
    }

    #[test]
    fn slide_past_the_whole_window_zeroes_it() {
        let mut w = RecentHeightWindow::empty([0; 32]);
        w.apply(&deltas(&[(7, 4)]));
        w.apply(&deltas(&[(10 * RECENT_WINDOW_LEN, 1)]));
        assert_eq!(w.counts.iter().sum::<u64>(), 1);
        assert_eq!(w.count_at(10 * RECENT_WINDOW_LEN), Some(1));
    }

    #[test]
    fn negative_delta_clamps_and_is_reported() {
        let mut w = RecentHeightWindow::empty([0; 32]);
        w.apply(&deltas(&[(5, 1)]));
        let clamped = w.apply(&deltas(&[(5, -3), (6, -1), (7, 2)]));
        assert_eq!(clamped, vec![5, 6]);
        assert_eq!(w.count_at(5), Some(0));
        assert_eq!(w.count_at(6), Some(0));
        assert_eq!(w.count_at(7), Some(2));
    }

    #[test]
    fn add_one_matches_apply_in_any_order() {
        let heights = [9000u32, 12, 4400, 8999, 4700, 9000, 100];
        let mut scanned = RecentHeightWindow::empty([0; 32]);
        for h in heights {
            scanned.add_one(h);
        }
        let mut applied = RecentHeightWindow::empty([0; 32]);
        applied.apply(&deltas(&heights.iter().map(|h| (*h, 1)).collect::<Vec<_>>()));
        assert_eq!(scanned, applied);
        assert_eq!(scanned.top(), 9000);
        assert_eq!(scanned.count_at(9000), Some(2));
        assert_eq!(scanned.count_at(4700), Some(1));
        assert_eq!(scanned.count_at(4400), None);
    }

    #[test]
    fn a_reorg_inside_the_margin_keeps_the_recent_range_covered() {
        let mut w = RecentHeightWindow::empty([0; 32]);
        w.apply(&deltas(&[(20_000, 1)]));
        assert!(w.covers_recent_range(20_000));
        assert!(w.covers_recent_range(20_000 - RECENT_WINDOW_REORG_MARGIN));
        assert!(!w.covers_recent_range(20_000 - RECENT_WINDOW_REORG_MARGIN - 1));
    }
}
