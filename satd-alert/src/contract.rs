//! The webhook delivery contract: header names, the idempotency key, and the
//! body signature.
//!
//! Normatively specified in `docs/api/webhooks.md`. The rules that matter:
//!
//! - The **body is the event**, byte-for-byte identical to the JSON a
//!   WebSocket subscriber would receive for the same event. One documented
//!   wire schema, not two — a receiver written against the streaming spec
//!   parses webhook bodies with the same code.
//! - Delivery metadata rides in **headers**, never in the body. Putting the
//!   attempt counter or hook id inside the JSON would change the bytes between
//!   retries of the same event, which breaks both signature caching and
//!   receiver-side deduplication.
//! - The signature is computed over the **raw request body**, so a receiver
//!   verifies before parsing — the standard order, and the only one that is
//!   safe against a parser that normalizes.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// `sha256=<hex>` over the raw body, keyed by the hook's secret. Retained
/// unchanged from the shipped `reorgwebhook` so existing receivers keep working
/// when that hook is served by this dispatcher.
pub const SIGNATURE_HEADER: &str = "X-Satd-Signature";
/// Idempotency key: `<node_id>-<instance_id>-<seq>`. Stable across retries of
/// one event, unique across restarts (the instance id is a per-process nonce).
pub const DELIVERY_HEADER: &str = "X-Satd-Delivery";
/// Which configured hook this delivery belongs to.
pub const HOOK_HEADER: &str = "X-Satd-Hook";
/// 1-based attempt counter. Present so a receiver can tell a retry from a
/// genuine duplicate event without keeping state.
pub const ATTEMPT_HEADER: &str = "X-Satd-Attempt";
/// Contract version. Bumped only for a breaking change to the header set or
/// signature scheme — the *body* schema is versioned independently by the
/// event envelope's `schema_version`.
pub const WEBHOOK_VERSION_HEADER: &str = "X-Satd-Webhook-Version";
/// Contract version for alertfile hooks: signature covers the delivery
/// metadata, not just the body, and `X-Satd-Timestamp` is present.
pub const WEBHOOK_VERSION: &str = "2";
/// Contract version the legacy `-reorgwebhook` alias keeps emitting.
///
/// That surface shipped before this crate existed: body-only signature, no
/// delivery id, `ReorgRecord` rather than the event envelope. Deployed
/// receivers verify it as-is, so it is frozen — the version header is how a
/// receiver tells the two apart.
pub const LEGACY_WEBHOOK_VERSION: &str = "1";

/// Unix seconds at which a delivery was signed. Covered by the v2 signature;
/// a receiver rejects a delivery outside [`MAX_TIMESTAMP_SKEW_SECS`].
pub const TIMESTAMP_HEADER: &str = "X-Satd-Timestamp";

/// Sign a raw body with a hook secret, rendering the `X-Satd-Signature` value.
///
/// HMAC-SHA256 over the exact bytes that go on the wire. The `sha256=` prefix
/// is part of the value (GitHub-webhook convention) so the algorithm can be
/// migrated later without a header rename.
pub fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Build the idempotency key for an event.
///
/// All three components already exist on every envelope (`EdgeStamp.node_id`,
/// `EdgeStamp.seq`, and the publisher's per-process `instance_id`), so this
/// adds no state: it is stable across retries of one event because the stamp is
/// fixed at publish time, and unique across restarts because `instance_id` is.
pub fn delivery_id(node_id_hex: &str, instance_id: u64, seq: u64) -> String {
    format!("{node_id_hex}-{instance_id}-{seq}")
}

/// Maximum age a receiver should accept for a v2 delivery, in seconds.
///
/// Normative for receivers, and now enforced on the sending side too: a
/// delivery older than this is refused by a conforming receiver, so continuing
/// to retry it is guaranteed-futile work that pins the head of a serial queue.
/// The dispatcher abandons an event once it crosses this age.
///
/// Note the bound that matters is the *total* retry span, not the 300 s cap on
/// any one backoff interval — a doubling curve reaches 600 s of cumulative age
/// around the tenth attempt.
///
/// Wide enough to tolerate ordinary clock skew, tight enough that a captured
/// delivery is not a permanent replay token.
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 600;

/// Build the canonical string a v2 signature covers.
///
/// ```text
/// "2" LF <timestamp> LF <delivery-id> LF <hook-id> LF <body>
/// ```
///
/// Unambiguous without escaping because every field before the body is
/// constrained to a character set that excludes LF: the version is a literal,
/// the timestamp is decimal digits, the delivery id is hex and `-`, and the
/// hook id is restricted to `[A-Za-z0-9_-]` at
/// parse time. The body is last, so its content cannot be confused with a
/// preceding field however it is shaped.
pub fn v2_signing_string(timestamp: u64, delivery_id: &str, hook_id: &str, body: &[u8]) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(body.len() + delivery_id.len() + hook_id.len() + 32);
    buf.extend_from_slice(b"2\n");
    buf.extend_from_slice(timestamp.to_string().as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(delivery_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(hook_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(body);
    buf
}

/// Sign a v2 delivery: HMAC-SHA256 over [`v2_signing_string`].
///
/// v1 (see [`sign_body`]) covers the body and nothing else, which leaves the
/// delivery id — the value the contract instructs receivers to deduplicate
/// on — unauthenticated *and* predictable, since `seq` is dense and every
/// component of the id is visible in any single captured delivery. Anyone
/// holding one valid `(body, signature)` pair could therefore replay it under
/// forged future ids, filling a receiver's dedup cache so that the genuine
/// alerts bearing those ids are discarded on arrival — while satd counts them
/// delivered and moves on. Nothing is retained to notice the loss with, so the
/// alerts are simply gone. Signing the id closes that, and signing a timestamp
/// bounds replay of the capture itself.
pub fn sign_v2(
    secret: &str,
    timestamp: u64,
    delivery_id: &str,
    hook_id: &str,
    body: &[u8],
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(&v2_signing_string(timestamp, delivery_id, hook_id, body));
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors. These are the contract: they are reproduced verbatim in
    // `docs/api/webhooks.md` and in the reference push relay's tests, so an
    // independent receiver implementation can verify its HMAC without running
    // a node. Changing any expected value here is a breaking protocol change
    // and must come with a `WEBHOOK_VERSION` bump.
    /// v2 golden vectors. Computed independently (Python `hmac`) against the
    /// canonical string, not captured from this implementation's own output —
    /// a vector derived from the code under test only proves the code agrees
    /// with itself. Reproduced verbatim in `docs/api/webhooks.md` and in the
    /// reference relay's tests.
    #[test]
    fn v2_signature_golden_vectors() {
        let node = "ab".repeat(16);
        let did = delivery_id(&node, 7, 42);
        assert_eq!(did, "abababababababababababababababab-7-42");
        assert_eq!(
            sign_v2("hunter2", 1_753_400_000, &did, "pager", br#"{"hello":"world"}"#),
            "sha256=0dcd7bcc563327beab8a0ec4464a261288b43825415ae4c1ebdc91e79c83e031",
        );
        assert_eq!(
            sign_v2("hunter2", 1_753_400_000, &did, "pager", b""),
            "sha256=abb61065799427bc98456c493fe12ac9adec92fd10bebbc1bd00720becb69b6c",
        );
    }

    #[test]
    fn v2_signature_covers_every_metadata_field() {
        let node = "ab".repeat(16);
        let did = delivery_id(&node, 7, 42);
        let base = sign_v2("s", 1_000, &did, "pager", b"body");
        // Each of these is a field v1 left unauthenticated. Changing any one
        // must change the signature, or the field is not really covered.
        assert_ne!(base, sign_v2("s", 1_001, &did, "pager", b"body"), "timestamp");
        assert_ne!(
            base,
            sign_v2("s", 1_000, &delivery_id(&node, 7, 43), "pager", b"body"),
            "delivery id — the dedup key an attacker would forge"
        );
        assert_ne!(base, sign_v2("s", 1_000, &did, "other", b"body"), "hook id");
        assert_ne!(base, sign_v2("s", 1_000, &did, "pager", b"body2"), "body");
        assert_ne!(base, sign_v2("t", 1_000, &did, "pager", b"body"), "secret");
    }

    #[test]
    fn v2_canonical_string_is_unambiguous() {
        // The delimiter is LF and no field before the body may contain one, so
        // no reshuffling of field contents can produce the same signing string.
        // Concatenation without a delimiter would let ("ab","c") collide with
        // ("a","bc"); this asserts it does not.
        assert_ne!(
            v2_signing_string(1, "ab", "c", b"x"),
            v2_signing_string(1, "a", "bc", b"x"),
        );
    }

    #[test]
    fn signature_golden_vectors() {
        for (secret, body, expected) in [
            (
                "hunter2",
                r#"{"hello":"world"}"#,
                "sha256=12f1ef94c239895aafefa2a6804ec6136d8c23fff17c08064cfc75b33e3fbaf5",
            ),
            (
                "",
                "",
                "sha256=b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
            ),
        ] {
            assert_eq!(sign_body(secret, body.as_bytes()), expected, "secret={secret:?}");
        }
    }

    #[test]
    fn signature_covers_the_exact_bytes() {
        // A single-byte change must change the signature — the point of signing
        // the raw body rather than a parsed/normalized form.
        let a = sign_body("k", br#"{"a":1}"#);
        let b = sign_body("k", br#"{"a":2}"#);
        assert_ne!(a, b);
        // And whitespace is not normalized away.
        assert_ne!(sign_body("k", br#"{"a":1}"#), sign_body("k", br#"{"a": 1}"#));
    }

    #[test]
    fn signature_is_keyed() {
        assert_ne!(sign_body("k1", b"body"), sign_body("k2", b"body"));
    }

    #[test]
    fn delivery_ids_are_stable_and_unique() {
        let node = "ab".repeat(16);
        // Same event, any attempt ⇒ same id (the caller does not vary it).
        assert_eq!(delivery_id(&node, 7, 42), delivery_id(&node, 7, 42));
        // Different event ⇒ different id.
        assert_ne!(delivery_id(&node, 7, 42), delivery_id(&node, 7, 43));
        // Same seq after a restart ⇒ different id, because the instance nonce
        // changed. Without this a receiver would dedupe away real events.
        assert_ne!(delivery_id(&node, 7, 42), delivery_id(&node, 8, 42));
    }

    /// Ids are unique per event within a process, across every field that
    /// varies: node, instance, and counter.
    #[test]
    fn a_delivery_id_varies_with_every_component() {
        let node = "ab".repeat(16);
        let other = "cd".repeat(16);
        assert_ne!(delivery_id(&node, 7, 1), delivery_id(&other, 7, 1));
        assert_ne!(delivery_id(&node, 7, 1), delivery_id(&node, 8, 1));
        assert_ne!(delivery_id(&node, 7, 1), delivery_id(&node, 7, 2));
    }
}
