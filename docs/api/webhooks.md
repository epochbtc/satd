# satd Alert Webhooks — Delivery Contract

**Status:** normative for `X-Satd-Webhook-Version: 2`.
**Audience:** anyone writing a receiver — an alerting relay, a wallet backend,
a push-notification bridge, a `curl | jq` script in a systemd unit.

This document specifies what satd sends and what a receiver must do. It is the
wire-level companion to the operator-facing
[Alerting chapter](https://epochbtc.github.io/satd/observability.html) (how to
configure hooks) and to [`streaming.md`](streaming.md) (the event schema the
bodies use).

**Scope.** Webhooks are a basic, **best-effort** way to automate off chain and
mempool events. They deliver live and retry a while; they do not persist, do not
resume, and do not match on your addresses. If you need guaranteed delivery,
resumability across downtime, history, backpressure, or per-address matching,
the [Streaming Consumption API](streaming.md) is the canonical way to integrate
with satd and does all of it properly. Choosing webhooks for an integration that
needs those things is choosing the wrong surface.

Everything here is verifiable without a running node: §6 gives signature test
vectors, and the same vectors are asserted by satd's own unit tests, so an
independent implementation can be checked for agreement offline.

---

## 1. Request

```http
POST <hook url> HTTP/1.1
Content-Type: application/json
X-Satd-Signature: sha256=<hex>
X-Satd-Timestamp: <unix seconds>
X-Satd-Delivery: <node_id>-<instance_id>-<seq>
X-Satd-Hook: <hook id>
X-Satd-Attempt: <n>
X-Satd-Webhook-Version: 2

<body>
```

| Header | Meaning |
|---|---|
| `X-Satd-Signature` | `sha256=` followed by the lowercase hex HMAC-SHA256 of the **canonical signing string** (§3), keyed by the hook's configured `secret`. |
| `X-Satd-Timestamp` | Unix seconds at which satd signed this delivery. Covered by the signature; a receiver **must** reject a delivery whose timestamp is outside its freshness window. See §3. |
| `X-Satd-Delivery` | Idempotency key. Stable across retries of one event; unique across daemon restarts. See §4. |
| `X-Satd-Hook` | The `id` of the hook this delivery belongs to, as written in the alertfile. The id `reorg-legacy` is **reserved** for the legacy `reorgwebhook=` alias — do not use it for a hook of your own, or your deliveries and its will be indistinguishable here and its metric series will collide with yours. |
| `X-Satd-Attempt` | 1-based attempt counter for *this* event. `1` on first delivery; `>1` means an earlier attempt failed. |
| `X-Satd-Webhook-Version` | This contract's version. Bumped only for a breaking change to the header set or signature scheme — **not** for changes to the body schema, which is versioned independently by `schema_version` inside the body. |

Exactly one event per request. Batching is not part of version 2.

> **The legacy `reorgwebhook=` alias is out of scope for this document.** It
> predates the alertfile, and it is frozen so that already-deployed receivers
> keep working: it reports `X-Satd-Webhook-Version: 1`, signs the **body alone**
> (and only when `reorgwebhooksecret` is set), sends a `ReorgRecord` rather than
> an event envelope, carries no `X-Satd-Delivery` and no `X-Satd-Timestamp`, and
> retries three times with a 200 ms base rather than the schedule in §5.2. Check
> the version header before applying anything below. Everything in this document
> describes version 2 — alertfile hooks.

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
  "body": { "category": "chain", "kind": "block_connected", "height": 812345, … }
}
```

`cursor` is present on `block_connected` and absent on everything else — status
events, heartbeats, mempool transitions, `block_disconnected` and `reorg` carry
no position. It is carried because the envelope is shared with the streaming
API, where it is load-bearing; **satd does not use it for webhook delivery and
neither should you rely on it here.** Webhooks do not resume (§5.4). If you want
to act on a position, take it to the streaming API.

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

A receiver **must** tolerate an unrecognized `body.category` or `kind`: new ones
are added additively and do not bump `schema_version`.

**`categories` is the entire filter surface.** A hook cannot subscribe to
specific addresses, outpoints, transactions or silent-payment scan keys. That is
what the streaming API's `Watch` stream is for, and it does it properly —
per-connection watch-sets, depth alarms, `RescanBlocks` for history,
backpressure. A `[webhook.watch]` table in an alertfile is rejected at load as
an unknown key — the alertfile parser accepts no key it does not implement.

In particular, do not reach for `"mempool"` to learn about *your* transactions
before they confirm: it is every transaction on the network, thousands per
minute on mainnet, and it is the wrong tool. Use `Watch`.

### Hash byte order — read this before writing a lookup

Byte order is **not uniform across bodies**, because the two families are
serialized by different code. Getting it wrong is silent: you compute a
valid-looking 32-byte hex string that simply never matches anything.

| Body family | `txid` / `block_hash` byte order |
|---|---|
| **`chain` bodies** (`block_connected`, `block_disconnected`, `reorg`) | **Reversed — RPC display order**, the same string `getblockhash` returns |
| **`mempool` bodies** (`enter`, `leave_*`) | **Reversed — RPC display order** |

Every hash a webhook delivers is in RPC display order, so a `txid` from a
`mempool.enter` body can be handed straight to `getrawtransaction`. (The
streaming API's watch matches use internal, unreversed order — if you consume
both surfaces, that is the seam to watch.)

## 3. Signature

```
X-Satd-Signature: sha256=<hex(HMAC-SHA256(secret, signing_string))>
```

The signature covers the delivery **metadata as well as the body**:

```
signing_string = "2" LF <X-Satd-Timestamp> LF <X-Satd-Delivery> LF <X-Satd-Hook> LF <raw_body>
```

where `LF` is a single `0x0A` and `raw_body` is the exact request body bytes.
No escaping is needed: every field before the body is restricted to a character
set that excludes LF (the version is a literal, the timestamp is decimal digits,
the delivery id is hex plus `-`, and hook ids are `[A-Za-z0-9_-]`), and the body
is last.

- The key is the hook's `secret` from the alertfile, as UTF-8 bytes.
- Every delivery is signed; a hook without a secret cannot be configured.

**Why the metadata is signed.** §4 tells you to deduplicate on
`X-Satd-Delivery`. If that header were outside the signature it would also be
*forgeable*, and its values are predictable from any single delivery you have
seen. An attacker holding one valid `(body, signature)` pair could then replay
it under the delivery ids of alerts you have not received yet, so that when the
real "disk is filling" alert arrives your receiver discards it as a duplicate —
while satd counts it delivered. Signing the id closes that; signing the
timestamp bounds how long a captured delivery stays replayable.

A receiver **must**:

1. Read the raw body without parsing or re-serializing it. A JSON round-trip
   changes whitespace and key order and will not verify.
2. Reconstruct the signing string from the headers and the raw body, recompute
   the HMAC, and compare in **constant time**.
3. Reject the request if the signature header is absent or does not match —
   before doing anything else with the content.
4. Reject the request if `X-Satd-Timestamp` is missing, unparseable, or further
   from your clock than your freshness window. **600 seconds** is the
   recommended window: wide enough for ordinary clock skew and for satd's retry
   backoff (which caps at 300 s), tight enough that a captured delivery is not a
   permanent bearer token.

Note that the timestamp is stamped once per *event*, not once per attempt — it
does not move across retries, so a delivery still being retried after your
window will age out. That is intended: a 20-minute-stale alert is not worth
acting on.

Worked vectors and reference receiver code are in §6.

## 4. Idempotency

```
X-Satd-Delivery: <node_id>-<instance_id>-<seq>
```

- `node_id` — the node's stable 32-hex-character identity.
- `instance_id` — a per-process nonce, regenerated on every restart.
- `seq` — the event's own monotonic sequence within that process.

Treat the whole value as an opaque string; do not parse its parts. Deduplicate
on it. It is **stable across retries** (the components are fixed when the event
is published) and **unique across restarts** (the instance nonce changes) — so a
retry and a genuinely repeated condition are distinguishable, which a bare `seq`
could not do since `seq` restarts at zero.

Delivery is **at-most-once**, never exactly-once, and **deduplicating on this
header is required** — not merely advisable.

Two situations produce a repeat, and both carry the id unchanged, so the same
event never arrives under two different ids:

1. A **retry** of a delivery whose response was lost. `X-Satd-Attempt`
   increments.
2. A **config reload** (`SIGHUP`). The dispatcher subscribes the incoming
   generation to the event bus before retiring the outgoing one, so that no
   event falls between them; the cost is that an event in flight across the
   handover can be enqueued by both. Both copies carry `X-Satd-Attempt: 1`.
   This is the deliberate trade — losing an alert is worse than repeating one —
   and it is why a receiver must dedupe rather than lean on the attempt counter
   alone.

## 5. Delivery behavior

### 5.1 Acknowledgement

Any `2xx` acknowledges. The response body is ignored.

### 5.2 Retries

| Response | Behavior |
|---|---|
| `2xx` | Delivered. |
| `5xx`, `408`, `429` | Retried. |
| No response (timeout, connection failure, TLS error) | Retried. |
| `3xx` | **Not** retried and **not followed**: counted, logged, and skipped. |
| Any other `4xx` | **Not** retried: counted, logged, and skipped. |

Retries are 1 s doubling to a 300 s ceiling, jittered, and are **abandoned once
the delivery ages past the freshness window it was signed with**
(`MAX_TIMESTAMP_SKEW_SECS`, 600 s) — in practice around the tenth or eleventh
attempt. Retrying past that point is pointless: §4 requires the receiver to
reject anything outside the window, so a delivery that can no longer pass that
check cannot be accepted however many times it is sent.

The operational consequence is worth stating plainly: **a receiver unreachable
for more than ~10 minutes loses the events raised during the outage.** A relay
redeploy or a slow restart is long enough. Standing health conditions recover on
their own, because the detectors re-evaluate and re-raise them (§6), but chain
and mempool events do not — they are gone. Alert on
`satd_alertwebhook_dropped_total` if that matters, and use the Streaming
Consumption API if you need a guarantee rather than best effort.

Delivery is **serial and in-order per hook** — one request in flight at a time —
so a receiver observes events in the order the node produced them, and a retry is
never overtaken by the event behind it.

Non-retryable `4xx` is a deliberate asymmetry: a receiver answering `404`
forever would otherwise pin the head of the queue and convert every later event
into an overflow drop. Losing one delivery beats losing all of them. A skipped
event is counted in `satd_alertwebhook_dropped_total` and logged, like any
other loss.

**Redirects are never followed.** satd sends to the URL in the alertfile and
nowhere else. Following a `3xx` would move the signed body, and the hook's
identity with it, to a host the operator never named — and the useful targets
for that are the ones they cannot see from outside: a cloud metadata endpoint,
an RFC1918 admin port, the node's own RPC. Publish a stable final URL; if it
changes, the operator updates the alertfile.

Per-attempt timeout: 10 s.

### 5.3 What happens when a hook falls behind

A hook's outbound queue is bounded (1024 events). If your receiver cannot keep
up, or the dispatcher itself lags the event bus, events are **dropped**. There is
no in-band notice: nothing is inserted into the stream to tell you, and nothing
is held for later.

What you get instead is the operator-side signal —
`satd_alertwebhook_dropped_total{hook="..."}` moves and the node logs it. Alert
on that counter if a gap matters to you.

This is the deliberate shape of the surface. A webhook is a fire-and-forget HTTP
callback; making it tell you reliably what it failed to tell you is a strictly
harder problem than the one it exists to solve, and it is already solved one
surface over. If you need to know you have every event, consume the
[Streaming Consumption API](streaming.md) — real cursors, backpressure, and a
bounded `RescanBlocks` for history.

### 5.4 Durability across a node restart

None, by design.

| Event class | Guarantee |
|---|---|
| `chain` | **Best-effort.** Delivered live or not at all. A node that was down did not deliver those blocks and does not go back for them; its hooks resume at the live head. |
| `mempool` | **Best-effort.** Mempool state is ephemeral; anything that matters is re-emitted when it confirms. |
| `status` | **Re-raised by re-evaluation.** Standing conditions are re-detected at startup and raised again, so a live problem still reaches you across a restart. This is a property of the detectors, not of delivery. A condition that raised *and* cleared while the node was down is stale by definition and is not reconstructed. |
| `heartbeat` | Sampled at the hook's `heartbeat_interval_secs`; no durability by construction. |

Nothing is persisted per hook. Retries are the only recovery mechanism, and they
cover the only failure this surface promises to survive: a receiver that is
briefly unreachable.

**`chain` alerts are suppressed while the node is in initial block download.**
Syncing from genesis would otherwise POST one delivery per historical block for
as long as the sync takes. `status`, `heartbeat` **and `mempool`** keep flowing:
health events because "this node is unhealthy" is exactly as true mid-sync, and
the heartbeat so an external dead-man's switch does not declare a syncing node
dead. Size a `mempool` receiver accordingly — a multi-day sync does not quiet
it, and mainnet mempool volume is thousands of deliveries a minute. What was suppressed is counted in `satd_alertwebhook_dropped_total`. The
suppression latches on first leaving IBD, so a node whose tip later goes stale
keeps alerting — the IBD predicate is the tip header's *age*, which reads
"syncing" on any node that has stalled or been restored from a backup, and
that is exactly when you most want the alert.

## 6. Test vectors

Signature vectors, asserted by satd's `satd-alert` unit tests and independently
recomputed (they are not captured from satd's own output). An independent
receiver can verify its HMAC implementation against these without a node.

```
secret       = "hunter2"
timestamp    = 1753400000
delivery id  = "abababababababababababababababab-7-42"
hook id      = "pager"

body = {"hello":"world"}
  → sha256=0dcd7bcc563327beab8a0ec4464a261288b43825415ae4c1ebdc91e79c83e031

body = (empty)
  → sha256=abb61065799427bc98456c493fe12ac9adec92fd10bebbc1bd00720becb69b6c
```

Reproduce from a shell:

```sh
printf '2\n1753400000\nabababababababababababababababab-7-42\npager\n{"hello":"world"}' \
  | openssl dgst -sha256 -hmac "hunter2"
```

Reference verification:

```python
import hmac, hashlib, time

def verify(headers, raw_body: bytes, secret: str, window: int = 600) -> bool:
    ts = headers["X-Satd-Timestamp"]
    if abs(time.time() - int(ts)) > window:      # bound replay of a capture
        return False
    msg = (b"2\n" + ts.encode()
           + b"\n" + headers["X-Satd-Delivery"].encode()
           + b"\n" + headers["X-Satd-Hook"].encode()
           + b"\n" + raw_body)
    want = "sha256=" + hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-Satd-Signature"])   # constant time
```

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify(secret: &str, ts: &str, delivery: &str, hook: &str, raw_body: &[u8], header: &str) -> bool {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"2\n");
    msg.extend_from_slice(ts.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(delivery.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(hook.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(raw_body);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&msg);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    expected.len() == header.len()
        && subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), header.as_bytes()).into()
}
```

The caller must still check the timestamp window; the Rust snippet above covers
only the HMAC half.

## 7. Transport

HTTPS is expected. Plaintext `http://` is accepted without ceremony only for
loopback and RFC1918 targets — a relay on the same host, a receiver inside a
private network. For a public host it requires an explicit
`allow_insecure_http = true` on the hook: bodies carry chain data rather than
secrets, but signed-then-cleartext is still a footgun.

satd verifies server certificates with rustls against the **bundled Mozilla root
set** (webpki-roots), *not* the operating system trust store. A receiver whose
certificate chains to a private or corporate CA installed system-wide will
therefore fail verification, and every delivery to it will be retried until it
ages out of the freshness window and is dropped — so the hook is effectively
dark, not merely delayed. Terminate such a receiver behind a publicly-trusted
certificate, or put a local reverse proxy in front of it and point the hook at
loopback. No client certificate is presented.

## 8. Non-goals

Stated so nobody waits for them:

- **Exactly-once delivery.** Deduplicate on `X-Satd-Delivery`.
- **Guaranteed delivery, or any notice of what was missed.** Drops are visible
  to the operator as a counter, not to the receiver in-band. Use the streaming
  API if you need to know you have everything.
- **Resuming after downtime.** A hook that was not running resumes at the live
  head. There is no cursor, no replay, and no catch-up.
- **Watching addresses, coins, transactions, or silent-payment scan keys.** A
  hook filters on `categories`, `kinds` and `min_severity` only. Per-address
  matching is the streaming API's `Watch` stream.
- **Batching.** One event per request.
- **Ordering across hooks.** Ordering is per hook only.
- **A hosted relay.** satd delivers to endpoints you run. Where an alert goes
  after that — a pager, a chat channel, a push service — is your receiver's
  business, not the node's.
