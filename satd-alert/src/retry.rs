//! Response classification and the retry curve.
//!
//! The governing constraint is that a webhook endpoint is *outside* the
//! operator's node and can behave arbitrarily badly. Nothing here may be able
//! to block, unbound, or spin: delivery is serial per hook, a hook's queue is
//! bounded, and a failing endpoint degrades that hook's delivery and nothing
//! else.

use std::time::Duration;

/// What to do with an attempt's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// 2xx — the receiver acked. Advance the cursor.
    Delivered,
    /// Transient: retry this same event after a backoff.
    Retry,
    /// Permanent for this event: count it and move on.
    ///
    /// A misconfigured receiver (wrong path → 404, bad auth → 401, a body it
    /// rejects → 400) would otherwise pin the head of the queue forever and
    /// convert every subsequent event into a queue-overflow drop. Skipping the
    /// event loses one delivery; retrying it forever loses all of them.
    Drop,
}

/// Longest backoff between attempts. Matches the peer-reconnect curve's cap:
/// an endpoint that has been down for five minutes is being restarted or
/// redeployed, and probing it faster than that helps nobody.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Base delay before attempt `n` (1-based): 1s · 2^(n-1), capped at
/// [`MAX_BACKOFF`]. Jitter is applied separately by [`jitter`] so this stays a
/// pure function of the attempt number and can be asserted exactly.
pub fn retry_delay(attempt: u32) -> Duration {
    // `attempt` is 1-based, so the first retry waits 1s. Saturating shift keeps
    // a long-dead endpoint from overflowing into a zero delay.
    let secs = 1u64.checked_shl(attempt.saturating_sub(1)).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

/// Spread a delay by up to ±25 %, given a caller-supplied random value.
///
/// Randomness is a parameter rather than a call to a global RNG so the curve is
/// deterministic under test. The purpose is the usual one: a node with several
/// hooks pointed at the same receiver must not retry them all in lockstep.
pub fn jitter(base: Duration, rand: u64) -> Duration {
    let base_ms = base.as_millis() as u64;
    if base_ms == 0 {
        return base;
    }
    let span = base_ms / 2; // ±25 % of base
    let offset = rand % span.max(1);
    Duration::from_millis(base_ms.saturating_sub(span / 2).saturating_add(offset))
}

/// Classify a delivery attempt.
///
/// `status` is the HTTP status if one was received; `None` means the request
/// never produced a response (connect error, TLS failure, timeout) — always
/// retryable, since it says nothing about whether the receiver would accept the
/// event.
pub fn classify_response(status: Option<u16>) -> Disposition {
    match status {
        None => Disposition::Retry,
        Some(s) if (200..300).contains(&s) => Disposition::Delivered,
        // 408 Request Timeout and 429 Too Many Requests are explicitly
        // "try again" despite being 4xx; 5xx is the server admitting fault.
        Some(408) | Some(429) => Disposition::Retry,
        Some(s) if (500..600).contains(&s) => Disposition::Retry,
        // Every other 4xx is the receiver saying this request is wrong, and it
        // will be just as wrong next time. 3xx lands here too: the delivery
        // client does not follow redirects (a followed redirect would carry the
        // signed body to a host the alertfile never named), so a redirecting
        // endpoint is a misconfiguration to fix in the alertfile, not something
        // to retry into.
        Some(_) => Disposition::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_delivered() {
        for s in [200, 201, 202, 204, 299] {
            assert_eq!(classify_response(Some(s)), Disposition::Delivered, "{s}");
        }
    }

    #[test]
    fn server_errors_and_transport_failures_retry() {
        for s in [500, 502, 503, 504, 599] {
            assert_eq!(classify_response(Some(s)), Disposition::Retry, "{s}");
        }
        assert_eq!(classify_response(None), Disposition::Retry, "no response");
    }

    #[test]
    fn the_two_retryable_4xx_are_retried() {
        assert_eq!(classify_response(Some(408)), Disposition::Retry);
        assert_eq!(classify_response(Some(429)), Disposition::Retry);
    }

    #[test]
    fn client_errors_are_dropped_not_retried_forever() {
        // A misconfigured receiver must not pin the head of the queue and
        // convert every later event into an overflow drop.
        for s in [400, 401, 403, 404, 410, 422] {
            assert_eq!(classify_response(Some(s)), Disposition::Drop, "{s}");
        }
    }

    #[test]
    fn redirects_are_dropped_because_they_are_never_followed() {
        // The delivery client sets `Policy::none()`, so a 3xx arrives here
        // rather than being chased to a host the alertfile never named.
        for s in [301, 302, 303, 307, 308] {
            assert_eq!(classify_response(Some(s)), Disposition::Drop, "{s}");
        }
    }

    #[test]
    fn backoff_doubles_then_caps() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(9), Duration::from_secs(256));
        assert_eq!(retry_delay(10), MAX_BACKOFF, "capped");
        // A hook that has been failing for days must stay at the cap, not
        // overflow back to something small.
        assert_eq!(retry_delay(64), MAX_BACKOFF);
        assert_eq!(retry_delay(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn jitter_stays_within_a_quarter_of_the_base() {
        let base = Duration::from_secs(8);
        for r in [0u64, 1, 999, u64::MAX / 2, u64::MAX] {
            let j = jitter(base, r);
            assert!(
                j >= Duration::from_secs(6) && j <= Duration::from_secs(10),
                "jitter({base:?}, {r}) = {j:?} escaped ±25%",
            );
        }
    }

    #[test]
    fn jitter_actually_varies() {
        let base = Duration::from_secs(8);
        assert_ne!(jitter(base, 0), jitter(base, 1_234_567));
    }
}
