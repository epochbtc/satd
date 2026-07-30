# satd push relay (reference)

Receives satd's [alert webhooks](../../docs/api/webhooks.md) and forwards the
ones worth waking someone for as **APNs / FCM push notifications**, using *your*
Apple and Google credentials.

It is a separate process, outside the satd workspace, on purpose: a Bitcoin node
has no business holding a push-provider credential, and the JWT/OAuth stack that
comes with one has no business in its dependency tree.

## Status: reference-grade

Fork it. A wallet vendor needs device registration, per-user routing, and their
own retry policy — none of which belong in an example, and all of which are
specific to how you run things. Roughly an afternoon's work from here.

What *is* worth copying verbatim is the receive path in `src/main.rs`:

1. Verify `X-Satd-Signature` over the **raw body**, in constant time, **before
   parsing**. A re-serialized body does not verify (key order and whitespace are
   part of the signed bytes), and parsing unauthenticated input is the thing to
   avoid.
2. Deduplicate on `X-Satd-Delivery`. satd retries, so the same id arrives again
   whenever a response is lost after you acted on it — and a `SIGHUP` reload on
   the node can deliver one event twice, both stamped `X-Satd-Attempt: 1`. Dedup
   is required, not advisory.

   Note what this relay's ordering costs you: the delivery is recorded in the
   dedup ring *before* the push is attempted, so if the push then fails, satd's
   retry is suppressed as a duplicate. Moving the insert after a successful push
   is the fix, and it is not the same fix as moving the ACK (see below).
3. **Acknowledge before pushing.** satd delivers serially per hook; holding the
   response open across two provider round-trips puts the node's queue behind
   Apple's and Google's latency.

   Know what that costs: once this relay answers `200`, satd considers the
   event delivered and will not send it again. A push that then fails at APNs
   or FCM is gone — end to end, the chain is at-most-once even though satd's
   half is at-least-once. That is the right trade for a reference (a missed
   banner is not a missed payment; the wallet still reconciles against the
   node), but if you need better, do not simply move the ACK after the push —
   that trades the loss for head-of-line blocking on the whole hook. Persist an
   outbox before acknowledging and retry from it.

## Run it

```sh
cargo build --release
cp relay.example.toml /etc/satd-push-relay/relay.toml   # then edit
chmod 600 /etc/satd-push-relay/relay.toml               # holds the signing secret
chmod 600 /etc/satd-push-relay/AuthKey_*.p8             # and the credentials it points at
chmod 600 /etc/satd-push-relay/service-account.json
./target/release/satd-push-relay /etc/satd-push-relay/relay.toml
```

The relay enforces all three: it refuses to start on a group- or
world-accessible `relay.toml`, APNs key, or FCM service-account file.

It listens on loopback by default and does not terminate TLS. Bind it anywhere
else and the alert bodies — node identity, tip heights, disk state, peer counts
— cross the network in cleartext; the HMAC gives you authenticity, not
confidentiality. Put a TLS-terminating proxy in front if it is not loopback.

Point a satd hook at it (in the node's `alertfile`):

```toml
[[webhook]]
id = "push"
url = "http://127.0.0.1:9099/hook"
secret = "the same value as satd_secret in relay.toml"
categories = ["status", "chain"]
min_severity = "warning"
```

## What gets pushed

| Delivery | Notification |
|---|---|
| `status`, at or above `min_severity` | `CRITICAL: disk_low` / `Recovered: tip_stall`, with the most actionable `details` field folded into the body |

| `chain` / `reorg` | "Chain reorganization" with the fork's from/to heights |
| anything else (blocks, mempool) | nothing — a relay that buzzed on every block would be uninstalled within a day |

`min_severity` is a **status** floor only; reorg notifications are not status
events and are always pushed.

There is no "you missed some alerts" notification, because satd does not send
one. Webhooks are best-effort and report drops on the node's
`satd_alertwebhook_dropped_total` counter — alert on that from your metrics
stack, not from the relay, which cannot know what it was never sent.

Raise and clear share a collapse id (`apns-collapse-id` / `collapse_key`), so a
condition that recovers **replaces** its own alert on the lock screen instead of
stacking a second banner.

## Credentials

- **APNs**: token auth. You need the `.p8` key, its key id, your team id, and
  the app's bundle id. Set `production = false` to use the sandbox gateway.
- **FCM**: HTTP v1. You need the service-account JSON from the Firebase console.

Both are read from disk at push time and never leave this process.

## Tests

```sh
cargo test
```

The HMAC vectors in `src/verify.rs` are the ones published in
[`docs/api/webhooks.md`](../../docs/api/webhooks.md), asserted here by an
implementation independent of satd's — if both pass, the spec is unambiguous.
