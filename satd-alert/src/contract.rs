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
pub const WEBHOOK_VERSION: &str = "1";

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

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors. These are the contract: they are reproduced verbatim in
    // `docs/api/webhooks.md` and in the reference push relay's tests, so an
    // independent receiver implementation can verify its HMAC without running
    // a node. Changing any expected value here is a breaking protocol change
    // and must come with a `WEBHOOK_VERSION` bump.
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
}
