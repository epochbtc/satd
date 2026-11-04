//! Arrivals: how much weight is entering the mempool, per feerate band.
//!
//! The mempool simulator prices the queue that exists now, but transactions
//! that arrive before the next block compete for it too. This keeps a
//! moving average of incoming weight in each of the simulator's histogram
//! bands, so the simulator can add the weight expected to arrive before
//! blocks 1 and 2 (see `estimate::arrival_injection`).
//!
//! Guards against a flood that inflates the estimate:
//! - A transaction counts only once it has been in the mempool for
//!   [`MIN_RESIDENCE_SECS`] and is still there, in the template class
//!   (a transaction quarantined from templates never counts).
//! - The injection is capped at one block of weight per band per simulated
//!   block.
//!
//! Not persisted: a restart starts cold, and a cold tracker injects nothing.

use std::collections::{HashSet, VecDeque};

use bitcoin::Txid;

/// A transaction counts as an arrival only after this long in the pool.
pub const MIN_RESIDENCE_SECS: u64 = 10;
/// Half-life of the per-band moving average.
pub const RATE_HALF_LIFE_SECS: f64 = 150.0;
/// The tracker is warm once it has run this long...
pub const WARM_AFTER_SECS: u64 = 60;
/// ...and counted this many arrivals.
pub const WARM_AFTER_ARRIVALS: u64 = 32;
/// Most transactions waiting out their residence at once; the oldest go
/// first past it.
const MAX_PENDING: usize = 200_000;

/// Per-band moving averages of arriving weight.
#[derive(Debug, Clone)]
pub struct ArrivalTracker {
    /// Lower bound of each band, sat/kvB, ascending.
    bands: Vec<u64>,
    /// Moving average of arriving weight per band, weight units per second,
    /// as of `updated`.
    level: Vec<f64>,
    updated: u64,
    started: Option<u64>,
    counted: u64,
    pending: VecDeque<(Txid, u64)>,
    /// The txids in `pending`, so a transaction evicted and re-admitted
    /// while it waits is noted once.
    pending_ids: HashSet<Txid>,
}

/// A snapshot of the tracker's rates.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrivalRates {
    /// `(band lower bound sat/kvB, weight units per second)`, ascending.
    pub bands: Vec<(u64, f64)>,
    pub warm: bool,
}

impl ArrivalTracker {
    pub fn new(bands_sat_per_kvb: Vec<u64>) -> Self {
        let n = bands_sat_per_kvb.len();
        Self {
            bands: bands_sat_per_kvb,
            level: vec![0.0; n],
            updated: 0,
            started: None,
            counted: 0,
            pending: VecDeque::new(),
            pending_ids: HashSet::new(),
        }
    }

    /// A transaction entered the pool at `now`. It is counted later, by
    /// [`Self::promote`], if it is still there after its residence.
    pub fn note(&mut self, txid: Txid, now: u64) {
        // Keep `pending` in time order even if the clock steps back, so
        // promotion can stop at the first entry still waiting.
        let now = self.pending.back().map_or(now, |&(_, last)| now.max(last));
        self.started.get_or_insert(now);
        if !self.pending_ids.insert(txid) {
            return;
        }
        if self.pending.len() >= MAX_PENDING
            && let Some((old, _)) = self.pending.pop_front()
        {
            self.pending_ids.remove(&old);
        }
        self.pending.push_back((txid, now));
    }

    /// Count every noted transaction whose residence is over. `lookup`
    /// answers, for a txid, `Some((feerate sat/kvB, weight))` if it is still
    /// in the pool in the template class, else `None` (it is then dropped).
    pub fn promote(&mut self, now: u64, mut lookup: impl FnMut(&Txid) -> Option<(u64, u64)>) {
        // The clock stepped back past the newest entry: restart the residence
        // of everything waiting from now, rather than holding the queue until
        // the clock catches up with entries stamped in its future.
        if self.pending.back().is_some_and(|&(_, entered)| entered > now) {
            for p in &mut self.pending {
                p.1 = p.1.min(now);
            }
            self.updated = self.updated.min(now);
        }
        while let Some(&(txid, entered)) = self.pending.front() {
            if now < entered + MIN_RESIDENCE_SECS {
                break;
            }
            self.pending.pop_front();
            self.pending_ids.remove(&txid);
            if let Some((rate, weight)) = lookup(&txid) {
                self.add(entered, rate, weight);
            }
        }
    }

    fn band_of(&self, rate: u64) -> Option<usize> {
        self.bands.iter().rposition(|b| rate >= *b)
    }

    fn decay_to(&mut self, now: u64) {
        if now > self.updated {
            let f = 0.5f64.powf((now - self.updated) as f64 / RATE_HALF_LIFE_SECS);
            for l in &mut self.level {
                *l *= f;
            }
            self.updated = now;
        }
    }

    /// Add one arrival of `weight` at time `at` to its band. An impulse of
    /// `w * ln2 / H` makes a steady flow of `r` weight per second settle at a
    /// level of `r`.
    fn add(&mut self, at: u64, rate: u64, weight: u64) {
        self.counted += 1;
        let Some(band) = self.band_of(rate) else {
            return;
        };
        self.decay_to(at);
        let age = self.updated.saturating_sub(at) as f64;
        let impulse = weight as f64 * std::f64::consts::LN_2 / RATE_HALF_LIFE_SECS;
        self.level[band] += impulse * 0.5f64.powf(age / RATE_HALF_LIFE_SECS);
    }

    pub fn rates(&mut self, now: u64) -> ArrivalRates {
        self.decay_to(now);
        let warm = self.counted >= WARM_AFTER_ARRIVALS
            && self.started.is_some_and(|s| now >= s + WARM_AFTER_SECS);
        ArrivalRates {
            bands: self.bands.iter().copied().zip(self.level.iter().copied()).collect(),
            warm,
        }
    }

    /// Forget every rate and pending arrival (the pool was replaced).
    pub fn reset(&mut self) {
        let bands = std::mem::take(&mut self.bands);
        *self = Self::new(bands);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn txid(n: u32) -> Txid {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        Txid::from_byte_array(b)
    }

    fn tracker() -> ArrivalTracker {
        ArrivalTracker::new(vec![1_000, 10_000, 100_000])
    }

    #[test]
    fn young_transactions_do_not_count() {
        let mut t = tracker();
        t.note(txid(1), 1_000);
        t.promote(1_000 + MIN_RESIDENCE_SECS - 1, |_| Some((20_000, 4_000)));
        assert!(t.rates(1_009).bands.iter().all(|(_, r)| *r == 0.0));
        t.promote(1_000 + MIN_RESIDENCE_SECS, |_| Some((20_000, 4_000)));
        assert!(t.rates(1_010).bands[1].1 > 0.0, "counted once resident for 10 s");
    }

    #[test]
    fn transactions_gone_or_outside_the_template_class_do_not_count() {
        let mut t = tracker();
        t.note(txid(1), 1_000);
        t.note(txid(2), 1_000);
        // Neither is still in the pool in the template class.
        t.promote(2_000, |_| None);
        assert!(t.rates(2_000).bands.iter().all(|(_, r)| *r == 0.0));
    }

    #[test]
    fn a_steady_flow_settles_at_its_rate_in_its_band() {
        let mut t = tracker();
        // 400 WU every second into the 10 sat/vB band, for 30 minutes.
        for s in 0..1_800u64 {
            t.note(txid(s as u32), s);
            t.promote(s, |_| Some((20_000, 400)));
        }
        let r = t.rates(1_800);
        assert!(r.warm);
        let level = r.bands[1].1;
        assert!((level - 400.0).abs() < 25.0, "settles near 400 WU/s, got {level}");
        assert_eq!(r.bands[0].1, 0.0);
        assert_eq!(r.bands[2].1, 0.0);
    }

    /// A clock step back does not stall counting behind entries stamped in
    /// the clock's future.
    #[test]
    fn a_clock_step_back_does_not_stall_promotion() {
        let mut t = tracker();
        t.note(txid(1), 10_000);
        // The clock steps back an hour; later admissions are stamped then.
        t.note(txid(2), 6_400);
        t.promote(6_400, |_| Some((20_000, 400)));
        assert_eq!(t.pending.len(), 2, "neither resident yet on the new clock");
        t.promote(6_400 + MIN_RESIDENCE_SECS, |_| Some((20_000, 400)));
        assert!(t.pending.is_empty(), "both counted after ten seconds of the new clock");
        assert!(t.rates(6_400 + MIN_RESIDENCE_SECS).bands[1].1 > 0.0);
    }

    /// A transaction evicted and re-admitted while it waits out its
    /// residence counts once.
    #[test]
    fn a_readmitted_transaction_counts_once() {
        let mut t = tracker();
        t.note(txid(1), 1_000);
        t.note(txid(1), 1_003);
        let mut looked_up = 0;
        t.promote(1_000 + MIN_RESIDENCE_SECS + 5, |_| {
            looked_up += 1;
            Some((20_000, 400))
        });
        assert_eq!(looked_up, 1);
    }

    #[test]
    fn warm_needs_both_time_and_count() {
        let mut t = tracker();
        for i in 0..(WARM_AFTER_ARRIVALS as u32) {
            t.note(txid(i), 0);
        }
        t.promote(MIN_RESIDENCE_SECS, |_| Some((20_000, 400)));
        assert!(!t.rates(MIN_RESIDENCE_SECS).warm, "count reached, not the time");
        assert!(t.rates(WARM_AFTER_SECS).warm);
        let mut few = tracker();
        few.note(txid(1), 0);
        few.promote(MIN_RESIDENCE_SECS, |_| Some((20_000, 400)));
        assert!(!few.rates(10 * WARM_AFTER_SECS).warm, "time reached, not the count");
    }
}
