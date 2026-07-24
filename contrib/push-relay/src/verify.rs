//! Request authentication and replay suppression.

use std::collections::VecDeque;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Recommended freshness window, in seconds (docs/api/webhooks.md §3).
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 600;

/// Verify `X-Satd-Signature` (contract version 2).
///
/// The HMAC covers a canonical string, not the body alone:
///
/// ```text
/// "2" LF <timestamp> LF <delivery-id> LF <hook-id> LF <raw_body>
/// ```
///
/// Three things matter here and are easy to get wrong:
///
/// - The HMAC is over the **raw body bytes**, before any JSON parsing.
///   Verifying a re-serialized body fails, because key order and whitespace
///   change.
/// - The comparison is **constant time**. A `==` on the hex string leaks, byte
///   by byte, how much of a forged signature was correct.
/// - The delivery id is inside the signed material. That is what makes it safe
///   to deduplicate on: if it were not signed, anyone holding one captured
///   delivery could replay it under the ids of alerts that have not arrived
///   yet, and this relay would then discard the real ones as duplicates.
pub fn signature_valid(
    secret: &str,
    timestamp: &str,
    delivery_id: &str,
    hook_id: &str,
    raw_body: &[u8],
    header: &str,
) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(b"2\n");
    mac.update(timestamp.as_bytes());
    mac.update(b"\n");
    mac.update(delivery_id.as_bytes());
    mac.update(b"\n");
    mac.update(hook_id.as_bytes());
    mac.update(b"\n");
    mac.update(raw_body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    expected.len() == header.len() && expected.as_bytes().ct_eq(header.as_bytes()).into()
}

/// Whether `X-Satd-Timestamp` is present, numeric, and within the freshness
/// window of `now`.
///
/// Without this the signature alone makes a captured delivery a permanent
/// bearer token: it would verify forever, so anyone who obtained one could
/// replay a stale "all clear" during a real incident, or buzz the operator's
/// phone at will.
pub fn timestamp_fresh(header: &str, now: u64, window: u64) -> bool {
    let Ok(ts) = header.parse::<u64>() else {
        return false;
    };
    ts.abs_diff(now) <= window
}

/// Bounded set of recently-seen `X-Satd-Delivery` ids.
///
/// satd delivers at-least-once and retries, so the same id arrives more than
/// once whenever a response is lost after the relay acted on it. Without this,
/// every such retry becomes a duplicate buzz on the operator's phone.
///
/// A ring rather than a growing set: this is a reference relay, deduplication
/// only needs to cover the retry window, and unbounded memory in a
/// long-running daemon is a bug waiting to happen.
pub struct DeliveryDedup {
    seen: VecDeque<String>,
    capacity: usize,
}

impl DeliveryDedup {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record an id. Returns `true` if it is new (act on it), `false` if it is
    /// a duplicate (acknowledge and drop).
    pub fn insert(&mut self, id: &str) -> bool {
        if id.is_empty() {
            // No idempotency key: act on it. Better a duplicate notification
            // than a silently dropped alert.
            return true;
        }
        if self.seen.iter().any(|s| s == id) {
            return false;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(id.to_string());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "1753400000";
    const DID: &str = "abababababababababababababababab-7-42";
    const HOOK: &str = "pager";

    // The vectors published in docs/api/webhooks.md, asserted independently
    // here so this relay and satd are verified against the same values by two
    // separate implementations.
    #[test]
    fn spec_signature_vectors() {
        assert!(signature_valid(
            "hunter2",
            TS,
            DID,
            HOOK,
            br#"{"hello":"world"}"#,
            "sha256=0dcd7bcc563327beab8a0ec4464a261288b43825415ae4c1ebdc91e79c83e031",
        ));
        assert!(signature_valid(
            "hunter2",
            TS,
            DID,
            HOOK,
            b"",
            "sha256=abb61065799427bc98456c493fe12ac9adec92fd10bebbc1bd00720becb69b6c",
        ));
    }

    #[test]
    fn a_wrong_secret_or_tampered_body_fails() {
        let good = "sha256=0dcd7bcc563327beab8a0ec4464a261288b43825415ae4c1ebdc91e79c83e031";
        let body = br#"{"hello":"world"}"#;
        assert!(!signature_valid("hunter3", TS, DID, HOOK, body, good));
        assert!(!signature_valid("hunter2", TS, DID, HOOK, br#"{"hello":"worlD"}"#, good));
        // Whitespace is part of the signed bytes — this is why the raw body
        // must be verified before parsing.
        assert!(!signature_valid("hunter2", TS, DID, HOOK, br#"{"hello": "world"}"#, good));
    }

    #[test]
    fn tampered_delivery_metadata_fails() {
        // The whole point of v2. Each of these is a header an attacker can set
        // freely on a replayed request; none may verify against a signature
        // minted for different values.
        let good = "sha256=0dcd7bcc563327beab8a0ec4464a261288b43825415ae4c1ebdc91e79c83e031";
        let body = br#"{"hello":"world"}"#;
        assert!(
            !signature_valid("hunter2", TS, "abababababababababababababababab-7-43", HOOK, body, good),
            "a forged delivery id must not verify — it is the dedup key",
        );
        assert!(!signature_valid("hunter2", "1753400001", DID, HOOK, body, good), "timestamp");
        assert!(!signature_valid("hunter2", TS, DID, "other", body, good), "hook id");
    }

    #[test]
    fn a_stale_or_unparseable_timestamp_is_rejected() {
        let now = 1_753_400_000;
        assert!(timestamp_fresh("1753400000", now, MAX_TIMESTAMP_SKEW_SECS));
        assert!(timestamp_fresh("1753399500", now, MAX_TIMESTAMP_SKEW_SECS), "within window");
        // A capture replayed an hour later must not be actionable.
        assert!(!timestamp_fresh("1753396400", now, MAX_TIMESTAMP_SKEW_SECS));
        // Clock skew in the other direction is bounded too.
        assert!(!timestamp_fresh("1753403600", now, MAX_TIMESTAMP_SKEW_SECS));
        for bad in ["", "abc", "-1", "99999999999999999999"] {
            assert!(!timestamp_fresh(bad, now, MAX_TIMESTAMP_SKEW_SECS), "{bad:?}");
        }
    }

    #[test]
    fn a_missing_or_malformed_header_fails() {
        for header in ["", "sha256=", "deadbeef", "sha1=abc"] {
            assert!(
                !signature_valid("hunter2", TS, DID, HOOK, br#"{"hello":"world"}"#, header),
                "{header:?} should not verify"
            );
        }
    }

    #[test]
    fn duplicate_deliveries_are_suppressed() {
        let mut d = DeliveryDedup::new(4);
        assert!(d.insert("node-1-42"), "first sighting acts");
        assert!(!d.insert("node-1-42"), "a retry does not");
        assert!(d.insert("node-1-43"));
    }

    #[test]
    fn the_dedup_window_is_bounded() {
        let mut d = DeliveryDedup::new(2);
        d.insert("a");
        d.insert("b");
        d.insert("c"); // evicts "a"
        assert!(d.insert("a"), "an id older than the window is acted on again");
    }

    #[test]
    fn a_delivery_without_an_id_is_acted_on() {
        // A duplicate notification beats a dropped alert.
        let mut d = DeliveryDedup::new(4);
        assert!(d.insert(""));
        assert!(d.insert(""));
    }
}
