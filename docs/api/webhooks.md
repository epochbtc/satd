# satd Alert Webhooks — Delivery Contract

**Status:** normative for `X-Satd-Webhook-Version: 1`.
**Audience:** anyone writing a receiver — an alerting relay, a wallet backend,
a push-notification bridge, a `curl | jq` script in a systemd unit.

This document specifies what satd sends and what a receiver must do. It is the
wire-level companion to the operator-facing
[Alerting chapter](https://epochbtc.github.io/satd/observability.html) (how to
configure hooks) and to [`streaming.md`](streaming.md) (the event schema the
bodies use).

Everything here is verifiable without a running node: §6 gives signature test
vectors, and the same vectors are asserted by satd's own unit tests, so an
independent implementation can be checked for agreement offline.

---

## 1. Request

```http
POST <hook url> HTTP/1.1
Content-Type: application/json
X-Satd-Signature: sha256=<hex>
X-Satd-Delivery: <node_id>-<instance_id>-<seq>
X-Satd-Hook: <hook id>
X-Satd-Attempt: <n>
X-Satd-Webhook-Version: 1

<body>
```

| Header | Meaning |
|---|---|
| `X-Satd-Signature` | `sha256=` followed by the lowercase hex HMAC-SHA256 of the **raw request body**, keyed by the hook's configured `secret`. See §3. |
| `X-Satd-Delivery` | Idempotency key. Stable across retries of one event; unique across daemon restarts. See §4. |
| `X-Satd-Hook` | The `id` of the hook this delivery belongs to, as written in the alertfile. |
| `X-Satd-Attempt` | 1-based attempt counter for *this* event. `1` on first delivery; `>1` means an earlier attempt failed. |
| `X-Satd-Webhook-Version` | This contract's version. Bumped only for a breaking change to the header set or signature scheme — **not** for changes to the body schema, which is versioned independently by `schema_version` inside the body. |

Exactly one event per request. Batching is not part of version 1.

## 2. Body

The body is **byte-identical to the JSON a WebSocket subscriber receives for the
same event**. There is one schema, specified in
[`streaming.md`](streaming.md#5-event-envelope), not a separate webhook schema:

```json
{
  "schema_version": 1,
  "stamp": {
    "node_id": "…", "region": "…",
    "edge_seen_at_ns": 123, "edge_wall_ns": 1700000000000000000, "seq": 42
  },
  "cursor": { "height": 812345, "tx_index": 0, "mempool_seq": "17", "instance_id": "88…" },
  "body": { "category": "status", "kind": "tip_stall", "state": "raised", … }
}
```

`cursor` is absent on events that do not advance a durable position (status
events, heartbeats, mempool transitions, watch matches).

Delivery metadata is **never** in the body. That is deliberate: if the attempt
counter or hook id were inside the JSON, the bytes would differ between retries
of the same event, which would break both signature reuse and receiver-side
deduplication.

Bodies you may receive, by the hook's configured `categories`:

| Category | `body.category` values |
|---|---|
| `status` | `status` (see [streaming.md §7.8](streaming.md#78-node-health-status-events)) |
| `chain` | `chain` (`block_connected`, `block_disconnected`, `reorg`) |
| `mempool` | `mempool` (`enter`, `leave_confirmed`, `leave_evicted`, `leave_replaced`) |
| `heartbeat` | `heartbeat` (downsampled per hook — see §5.4) |
| any hook with a watch-set | `script_matched`, `outpoint_spent`, `txid_matched`, `txid_replaced`, `txid_evicted`, `txid_unconfirmed`, `txid_depth_reached`, `txid_finalized`, `silent_payment_matched` |
| any hook | `lagged` — an in-band gap notice (§5.3) |

A receiver **must** tolerate an unrecognized `body.category` or `kind`: new ones
are added additively and do not bump `schema_version`.

Hashes (`txid`, `block_hash`, `scripthash`, `output_key`, `tweak`) are hex in
**internal (consensus) byte order, unreversed** — the streaming API's
convention, *not* the reversed display order JSON-RPC uses. A `scripthash` is
`sha256(scriptPubKey)`.

## 3. Signature

```
X-Satd-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>
```

- Computed over the **exact request body bytes**, before any parsing.
- The key is the hook's `secret` from the alertfile, as UTF-8 bytes.
- Every delivery is signed; a hook without a secret cannot be configured.

A receiver **must**:

1. Read the raw body without parsing or re-serializing it. A JSON round-trip
   changes whitespace and key order and will not verify.
2. Recompute the HMAC and compare in **constant time**.
3. Reject the request if the header is absent or does not match — before doing
   anything else with the content.

The scheme is unchanged from satd's original `reorgwebhook`, so receivers
written against that keep working.

## 4. Idempotency

```
X-Satd-Delivery: <node_id>-<instance_id>-<seq>
```

- `node_id` — the node's stable 32-hex-character identity.
- `instance_id` — a per-process nonce, regenerated on every restart.
- `seq` — the event's monotonic sequence within that process.

Deduplicate on the whole string. It is **stable across retries** (the components
are fixed when the event is published) and **unique across restarts** (the
instance nonce changes), so a retry and a genuinely repeated condition are
distinguishable — which a bare `seq` could not do, since `seq` restarts at zero.

Delivery is **at-least-once**, never exactly-once. Design your receiver so a
duplicate is harmless.

## 5. Delivery behavior

### 5.1 Acknowledgement

Any `2xx` acknowledges. The response body is ignored.

### 5.2 Retries

| Response | Behavior |
|---|---|
| `2xx` | Delivered. |
| `5xx`, `408`, `429` | Retried. |
| No response (timeout, connection failure, TLS error) | Retried. |
| Any other `4xx` | **Not** retried: counted, logged, and skipped. |

Retries are 1 s doubling to a 300 s ceiling, jittered, and continue
indefinitely. Delivery is **serial and in-order per hook** — one request in
flight at a time — so a receiver observes events in the order the node produced
them, and a retry is never overtaken by the event behind it.

Non-retryable `4xx` is a deliberate asymmetry: a receiver answering `404`
forever would otherwise pin the head of the queue and convert every later event
into an overflow drop. Losing one delivery beats losing all of them.

Per-attempt timeout: 10 s.

### 5.3 Gaps

A hook's outbound queue is bounded (1024 events). If a receiver falls far enough
behind, events are dropped — and the next successful delivery is **preceded by a
`lagged` body**:

```json
{"schema_version":1,"stamp":{…},"body":{
  "category":"lagged","dropped_count":37,
  "resume_cursor":{"height":812345,"tx_index":0,"mempool_seq":"0","instance_id":"88…"}}}
```

A gap is never silent. To recover the missed span, reconnect a streaming client
with `from_cursor = resume_cursor` (see
[streaming.md §6](streaming.md#6-cursors--replay)).

### 5.4 Durability across a node restart

| Event class | Guarantee |
|---|---|
| `chain` (confirmed) | **At-least-once.** The hook's resume position is persisted, and on startup it replays what it missed — bounded by the same 10 000-block window the streaming API uses. Beyond that you get a `lagged` notice and must resync the older span yourself. |
| `status` | **At-least-once by re-evaluation.** Standing conditions are re-detected and re-raised after a restart. A condition that raised *and* cleared while the node was down is stale by definition and is not reconstructed. |
| `mempool`, unconfirmed watch matches | **Best-effort.** Mempool state is ephemeral; anything that matters is re-emitted when it confirms. |
| watch matches | **Live-only.** A match that occurred while the daemon was down is not re-delivered. |
| `heartbeat` | Sampled at the hook's `heartbeat_interval_secs`; no durability by construction. |

## 6. Test vectors

Signature vectors, asserted by satd's `satd-alert` unit tests. An independent
receiver can verify its HMAC implementation against these without a node:

| secret | body | `X-Satd-Signature` |
|---|---|---|
| `hunter2` | `{"hello":"world"}` | `sha256=12f1ef94c239895aafefa2a6804ec6136d8c23fff17c08064cfc75b33e3fbaf5` |
| *(empty)* | *(empty)* | `sha256=b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad` |

Note the second vector is the well-known HMAC-SHA256 of an empty message under
an empty key — useful as a smoke test that your HMAC wiring is correct at all.

Reference verification:

```python
import hmac, hashlib
def verify(secret: str, raw_body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)   # constant time
```

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify(secret: &str, raw_body: &[u8], header: &str) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(raw_body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    // `Mac::verify_slice` is the constant-time comparison in this crate.
    expected.len() == header.len()
        && subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), header.as_bytes()).into()
}
```

## 7. Transport

HTTPS is expected. Plaintext `http://` is accepted without ceremony only for
loopback and RFC1918 targets — a relay on the same host, a receiver inside a
private network. For a public host it requires an explicit
`allow_insecure_http = true` on the hook: bodies carry chain data rather than
secrets, but signed-then-cleartext is still a footgun.

satd verifies server certificates using the platform trust store via rustls. No
client certificate is presented in version 1.

## 8. Non-goals

Stated so nobody waits for them:

- **Exactly-once delivery.** Deduplicate on `X-Satd-Delivery`.
- **Batching.** One event per request.
- **Ordering across hooks.** Ordering is per hook only.
- **A hosted relay.** satd delivers to endpoints you run. The reference push
  relay in `contrib/` is a starting point you operate yourself, with your own
  APNs/FCM credentials.
