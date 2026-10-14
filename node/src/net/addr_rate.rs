//! Bitcoin Core's rate limit on the addresses a peer announces
//! (`net_processing.cpp` `ProcessAddrs`).
//!
//! Every peer has a token bucket. It starts with one token and gains
//! [`MAX_ADDR_RATE_PER_SECOND`] tokens a second, up to
//! [`MAX_ADDR_PROCESSING_TOKEN_BUCKET`]. Each address taken from the peer's
//! `addr` and `addrv2` messages spends one token; an address that finds the
//! bucket empty is dropped, unless the peer has the `addr` permission.
//! Sending the peer a `getaddr` adds [`MAX_ADDR_TO_SEND`] tokens on top,
//! past that limit, so its answer is taken whole.

use crate::net::limits::MAX_ADDR_TO_SEND;

/// Core's `MAX_ADDR_RATE_PER_SECOND`: tokens gained per second.
pub const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;

/// Core's `MAX_ADDR_PROCESSING_TOKEN_BUCKET`: the bucket refills no
/// further than this.
pub const MAX_ADDR_PROCESSING_TOKEN_BUCKET: f64 = MAX_ADDR_TO_SEND as f64;

/// One peer's address token bucket and its counters: Core's
/// `Peer::m_addr_token_bucket`, `m_addr_token_timestamp`,
/// `m_addr_processed` and `m_addr_rate_limited`.
#[derive(Debug, Clone)]
pub struct AddrTokenBucket {
    tokens: f64,
    /// Node time of the last refill, in microseconds
    /// (`crate::time::now_micros`).
    refilled_at_micros: u64,
    /// Addresses from this peer that passed the limit and were looked at
    /// (`getpeerinfo.addr_processed`).
    pub processed: u64,
    /// Addresses from this peer dropped by the limit
    /// (`getpeerinfo.addr_rate_limited`).
    pub rate_limited: u64,
}

impl AddrTokenBucket {
    /// A new peer's bucket: one token, as in Core.
    pub fn new(now_micros: u64) -> Self {
        Self {
            tokens: 1.0,
            refilled_at_micros: now_micros,
            processed: 0,
            rate_limited: 0,
        }
    }

    /// Add the tokens earned since the last refill, unless the bucket is
    /// already at [`MAX_ADDR_PROCESSING_TOKEN_BUCKET`], and restart the clock
    /// either way. Core does this once per message, before taking any of it.
    /// A clock that went backwards earns nothing.
    pub fn refill(&mut self, now_micros: u64) {
        if self.tokens < MAX_ADDR_PROCESSING_TOKEN_BUCKET {
            let elapsed_secs = now_micros.saturating_sub(self.refilled_at_micros) as f64 / 1_000_000.0;
            self.tokens = (self.tokens + elapsed_secs * MAX_ADDR_RATE_PER_SECOND)
                .min(MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        self.refilled_at_micros = now_micros;
    }

    /// Spend a token on one address. Without one the address is dropped
    /// and counted as rate limited, unless `exempt` (the `addr`
    /// permission), in which case it is taken for free.
    pub fn admit(&mut self, exempt: bool) -> bool {
        if self.tokens < 1.0 {
            if !exempt {
                self.rate_limited += 1;
                return false;
            }
        } else {
            self.tokens -= 1.0;
        }
        true
    }

    /// A `getaddr` was sent to the peer: room for its answer, past the
    /// refill limit.
    pub fn getaddr_sent(&mut self) {
        self.tokens += MAX_ADDR_TO_SEND as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000;

    fn take(bucket: &mut AddrTokenBucket, n: usize, exempt: bool) -> usize {
        (0..n).filter(|_| bucket.admit(exempt)).count()
    }

    #[test]
    fn a_new_peer_gets_one_address_then_one_every_ten_seconds() {
        let mut b = AddrTokenBucket::new(0);
        b.refill(0);
        assert_eq!(take(&mut b, 1000, false), 1);
        assert_eq!(b.rate_limited, 999);

        b.refill(100 * SEC);
        assert_eq!(take(&mut b, 1000, false), 10, "0.1 a second");

        b.refill(105 * SEC);
        assert_eq!(take(&mut b, 1, false), 0, "half a token is not one");
        b.refill(110 * SEC);
        assert_eq!(take(&mut b, 1, false), 1, "the half carried over");
    }

    #[test]
    fn the_bucket_refills_to_a_thousand_and_no_further() {
        let mut b = AddrTokenBucket::new(0);
        b.refill(1_000_000 * SEC);
        assert_eq!(take(&mut b, 2000, false), 1000);
    }

    #[test]
    fn a_getaddr_makes_room_for_its_answer_past_the_limit() {
        let mut b = AddrTokenBucket::new(0);
        b.refill(1_000_000 * SEC);
        b.getaddr_sent();
        assert_eq!(take(&mut b, 3000, false), 2000);
    }

    #[test]
    fn the_addr_permission_takes_every_address() {
        let mut b = AddrTokenBucket::new(0);
        b.refill(0);
        assert_eq!(take(&mut b, 1000, true), 1000);
        assert_eq!(b.rate_limited, 0);
    }

    #[test]
    fn a_clock_that_goes_backwards_earns_nothing() {
        let mut b = AddrTokenBucket::new(100 * SEC);
        b.refill(0);
        assert_eq!(take(&mut b, 10, false), 1, "only the first token");
        // And the clock restarted from the earlier time, as Core's does.
        b.refill(10 * SEC);
        assert_eq!(take(&mut b, 10, false), 1);
    }
}
