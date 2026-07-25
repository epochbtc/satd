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

/// Build the idempotency key for a **synthesized** envelope — a catch-up replay
/// event or a gap notice.
///
/// These do not come off the live bus. They are stamped by the replay builder,
/// which has no sequence to assign and writes `seq: 0` into every one of them;
/// live bus events start at 1. So `seq` is not merely a weak discriminator
/// here — it is one constant shared by every replayed event and every lag
/// notice for the life of the process.
///
/// That matters more than it looks. Catch-up exists precisely so a hook that
/// was down does not miss what happened, and the contract tells receivers to
/// deduplicate on this header. Minting these from `seq` would mean a node down
/// for 100 blocks replays 100 events that a conforming receiver collapses into
/// one — the durability feature delivering 1% of what it advertises, silently.
/// The same collision would swallow every gap notice after the first, breaking
/// "a gap is never silent" from the second gap onward.
///
/// The `r` prefix keeps this space disjoint from the bus (`<seq>`) and watch
/// (`w<seq>`) spaces.
pub fn replay_delivery_id(node_id_hex: &str, instance_id: u64, seq: u64) -> String {
    format!("{node_id_hex}-{instance_id}-r{seq}")
}

/// Delivery id for a replayed **confirmed block**, derived from its height.
///
/// Deterministic on purpose, and the only id in the scheme that is. Every other
/// form embeds this process's random `instance_id` and a running counter, which
/// is right for an event that happens once — but a replayed block is precisely
/// the event this design can deliver twice: a restart replays from the durable
/// cursor, and a reload can leave two generations briefly overlapping. Under a
/// counter-minted id those duplicates arrive with *different* headers, which
/// makes "deduplicate on `X-Satd-Delivery`" unimplementable for the only
/// duplicate that actually occurs. Keyed on height, both copies carry the same
/// id and a conforming receiver collapses them, which is the contract.
///
/// The instance component is fixed at `0` — a real `instance_id` is a random
/// `u64` and would reintroduce the per-process variation this exists to remove.
/// The `b` prefix keeps the space disjoint from the bus (`<seq>`), watch
/// (`w<seq>`), and synthesized (`r<seq>`) spaces.
pub fn block_delivery_id(node_id_hex: &str, height: u32) -> String {
    format!("{node_id_hex}-0-b{height}")
}

/// Maximum age a receiver should accept for a v2 delivery, in seconds.
///
/// Normative for receivers, advisory here: satd stamps `X-Satd-Timestamp` and
/// signs it, but only the receiver can enforce freshness. Wide enough to
/// tolerate ordinary clock skew and a retry backoff (which caps at 300 s), tight
/// enough that a captured delivery is not a permanent replay token.
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 600;

/// Build the canonical string a v2 signature covers.
///
/// ```text
/// "2" LF <timestamp> LF <delivery-id> LF <hook-id> LF <body>
/// ```
///
/// Unambiguous without escaping because every field before the body is
/// constrained to a character set that excludes LF: the version is a literal,
/// the timestamp is decimal digits, the delivery id is hex plus `-` and an
/// optional `w`/`r` tag, and the hook id is restricted to `[A-Za-z0-9_-]` at
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
/// delivered and advances its cursor. Signing the id closes that, and signing a
/// timestamp bounds replay of the capture itself.
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

    /// The id spaces must not overlap. They are minted from independent
    /// counters — the bus `seq`, a synth counter, and a block height — so
    /// without the prefixes a replayed block at height 500 and a bus event with
    /// `seq` 500 would collide, and a conforming receiver would silently
    /// discard the second. (The watch space, `w<seq>`, is added with the
    /// watch-hook feature and is covered alongside it.)
    #[test]
    fn the_delivery_id_spaces_are_disjoint() {
        let node = "ab".repeat(16);
        let n = 500u64;
        let ids = [
            delivery_id(&node, 7, n),
            replay_delivery_id(&node, 7, n),
            block_delivery_id(&node, n as u32),
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a, b, "delivery id spaces collide at the same counter value");
            }
        }
    }

    /// A replayed block's id is derived from its height alone, so the same
    /// block delivered twice — a restart replaying from the durable cursor, or
    /// a reload whose generations briefly overlap — carries the same
    /// idempotency key. Every other id embeds a random per-process
    /// `instance_id`, which would make those duplicates undedupable.
    #[test]
    fn a_replayed_block_id_is_stable_across_restarts() {
        let node = "ab".repeat(16);
        assert_eq!(block_delivery_id(&node, 840_000), block_delivery_id(&node, 840_000));
        assert_ne!(block_delivery_id(&node, 840_000), block_delivery_id(&node, 840_001));
        // No instance component to vary: this is the whole point.
        assert!(block_delivery_id(&node, 840_000).ends_with("-0-b840000"));
    }
}
