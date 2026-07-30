# satd Alert Webhooks — Delivery Contract

**Status:** normative for `X-Satd-Webhook-Version: 2`.
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

`cursor` is absent on events that do not advance a durable position: status
events, heartbeats, and mempool transitions. Within the `chain` category it is
carried by `block_connected` only — `block_disconnected` and `reorg` have no
resume position of their own, so a receiver that persists `event.cursor`
unconditionally on any `chain` body will stall or crash on the first reorg,
which is the moment it most needs to be right.

**Watch matches have a different envelope shape.** A `script_matched`,
`outpoint_spent`, `txid_*`, or `silent_payment_matched` body is
`{schema_version, cursor, body}` — there is **no `stamp`** — and its `cursor` is
always *present*, though it is `null` while the match is unconfirmed and an
object once confirmed. That cursor also omits `instance_id`. If you write one
deserializer for both shapes, make `stamp` optional and treat `cursor` as
nullable rather than absent.

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

**A watch-set is not filtered by `categories`.** They are independent
subscriptions on one hook: `categories` selects from the node's firehose (what
the node and the chain are doing), while the watch-set selects your own
addresses, coins, and transactions. A hook with `categories = ["chain"]` and a
watch-set receives block events and *both phases* of its own matches — the
mempool sighting (`confirmed: false`) and the confirmed re-emit — while
receiving no mempool transitions for anything else. Adding `"mempool"` to see
unconfirmed matches is therefore unnecessary and expensive: you already have
them, and what you would add is every transaction on the network.

### Hash byte order — read this before writing a lookup

Byte order is **not uniform across bodies**, because the two families are
serialized by different code. Getting it wrong is silent: you compute a
valid-looking 32-byte hex string that simply never matches anything.

| Body family | `txid` / `block_hash` byte order |
|---|---|
| **Watch matches** (`script_matched`, `outpoint_spent`, `txid_*`, `silent_payment_matched`) | **Internal (consensus) order, unreversed** |
| **`chain` bodies** (`block_connected`, `block_disconnected`, `reorg`) | **Reversed — RPC display order**, the same string `getblockhash` returns |
| **`mempool` bodies** (`enter`, `leave_*`) | **Reversed — RPC display order** |

So a `txid` from a `mempool.enter` body can be handed straight to
`getrawtransaction`, while a `txid` from a `script_matched` body must be
byte-reversed first (or compared against other internal-order values).

`scripthash`, `output_pubkey`, and `tweak` appear only on watch matches and are
always internal order, unreversed. A `scripthash` is `sha256(scriptPubKey)`.

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
the delivery id is hex plus `-` and an optional `w`/`r` tag, and hook ids are
`[A-Za-z0-9_-]`), and the body is last.

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
X-Satd-Delivery: <node_id>-<instance_id>-<seq>       # live firehose event
X-Satd-Delivery: <node_id>-<instance_id>-w<seq>      # watch match
X-Satd-Delivery: <node_id>-<instance_id>-r<seq>      # synthesized: gap notice
```

- `node_id` — the node's stable 32-hex-character identity.
- `instance_id` — a per-process nonce, regenerated on every restart.
- `seq` — a monotonic sequence within that process.

There are three disjoint sequence spaces, distinguished by the prefix, because
only live bus events have a bus sequence to name them. Watch matches (`w`)
arrive on a per-subscriber channel; gap notices (`r`) are synthesized rather
than published, and every synthesized envelope carries the same internal stamp —
so without a separate space, every gap notice after the first would collapse to
one idempotency key at your end.

Treat the whole value as an opaque string; do not parse its parts. Deduplicate
on it. It is **stable across retries** (the components are fixed when the event
is published) and **unique across restarts** (the instance nonce changes) — so a
retry and a genuinely repeated condition are distinguishable, which a bare `seq`
could not do since `seq` restarts at zero.

Delivery is **at-most-once**, never exactly-once. A duplicate is possible only
as a retry of one delivery, which carries the id unchanged, so deduplicating on
`X-Satd-Delivery` is sufficient — you will not receive the same event under two
different ids. The node never re-sends an event it has already delivered: what
it does instead is *tell* you when something was missed (§5.3).

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

Retries are 1 s doubling to a 300 s ceiling, jittered, and continue
indefinitely. Delivery is **serial and in-order per hook** — one request in
flight at a time — so a receiver observes events in the order the node produced
them, and a retry is never overtaken by the event behind it.

Non-retryable `4xx` is a deliberate asymmetry: a receiver answering `404`
forever would otherwise pin the head of the queue and convert every later event
into an overflow drop. Losing one delivery beats losing all of them. A skipped
event still advances the hook's resume position, so a hard-rejecting endpoint
makes progress rather than announcing the same refused span as a gap after
every restart.

**Redirects are never followed.** satd sends to the URL in the alertfile and
nowhere else. Following a `3xx` would move the signed body, and the hook's
identity with it, to a host the operator never named — and the useful targets
for that are the ones they cannot see from outside: a cloud metadata endpoint,
an RFC1918 admin port, the node's own RPC. Publish a stable final URL; if it
changes, the operator updates the alertfile.

Per-attempt timeout: 10 s.

### 5.3 Gaps

A hook's outbound queue is bounded (1024 events). If a receiver falls far enough
behind, events are dropped — and the next successful delivery is **preceded by a
`lagged` body**:

```json
{"schema_version":1,"stamp":{…},
 "cursor":{"height":812345,"tx_index":0,"mempool_seq":"0","instance_id":"88…"},
 "body":{
  "category":"lagged","dropped_count":37,
  "resume_cursor":{"height":812345,"tx_index":0,"mempool_seq":"0","instance_id":"88…"}}}
```

A gap caused by satd dropping events is never silent. Two qualifications:

- An event **you** refused with a non-retryable status is still reported. It
  advances the hook's resume position (§5.4), so unlike a queue overflow you
  cannot go back for it — being told is all you get.
- `resume_cursor` is a *chain* position. It names where to go looking; it does
  not name what was lost. Watch matches in particular are forward-only, so if
  the dropped span contained matches you must reconcile those separately
  (`getaddresshistory`) — a `lagged` notice does not tell you whether any of the
  dropped events were matches.

satd will not re-send the span. To recover it, go and fetch it: reconnect a
streaming client with `from_cursor = resume_cursor` (see
[streaming.md §6](streaming.md#6-cursors--replay)), or use the JSON-RPC history
calls. This is the whole shape of the contract — the webhook tells you *that*
you have a hole and *where* it starts, and a surface built for bulk history
gives you the contents.

### 5.4 Durability across a node restart

| Event class | Guarantee |
|---|---|
| `chain` (confirmed) | **At-most-once, gap-announced.** The hook's resume position is persisted, but it is a marker rather than a replay cursor: on startup the hook emits one `lagged` body naming what it missed while the node was down, and then goes live. It does not re-send the span — recover it yourself from `resume_cursor` (§5.3). An event you answer with a non-retryable status (§5.2) is skipped permanently and the cursor advances past it, and that skip also produces a `lagged` body rather than relying on you having noticed at the time. |
| `status` | **At-least-once by re-evaluation.** Standing conditions are re-detected and re-raised after a restart. A condition that raised *and* cleared while the node was down is stale by definition and is not reconstructed. |
| `mempool`, unconfirmed watch matches | **Best-effort.** Mempool state is ephemeral; anything that matters is re-emitted when it confirms. |
| confirmed watch matches | **Forward-only from registration.** Adding a watch entry does not replay history for it, and a restart is not a gap: the watch-set is re-registered before P2P starts, so blocks arriving during catch-up are matched normally. The one loss window is a crash between a block connecting and this delivery being acknowledged — the restart announces the span, but the matches are not reconstructed, because the blocks are already connected and are not rescanned. Reconcile with `getaddresshistory` after an unclean shutdown if that matters. |
| `heartbeat` | Sampled at the hook's `heartbeat_interval_secs`; no durability by construction. |

**Alerts are suppressed while the node is in initial block download**, except
`status` and `heartbeat`. Syncing from genesis would otherwise POST one delivery
per historical block, and one per historical transaction touching a watched
entry, for as long as the sync takes. Health events keep flowing because "this
node is unhealthy" is exactly as true mid-sync, and the heartbeat keeps flowing
so an external dead-man's switch does not declare a syncing node dead.
Everything suppressed is counted and reported in the next `lagged` body — this
is not an exception to §5.3.

Suppression applies to *confirmed* events only. An unconfirmed watch match comes
from the mempool, which is live by construction and can never be historical, so
there is no firehose to prevent — and because a watch match has no replay behind
it, suppressing a live one destroys it rather than deferring it. The IBD
predicate is the tip header's *age*, which reads "syncing" on any node whose
chain has stalled or which was restored from a backup, so the narrow scope is
what keeps an anti-firehose measure from silencing a node that has a genuine
problem. Within a process the suppression also latches on first leaving IBD, so
a tip that later goes stale does not re-arm it at the 24-hour mark.

**Watch-match bodies delivered over a webhook always carry `raw_tx: null` and
`descriptor_matches: []`.** The opt-in raw-transaction and descriptor-attribution
features are per-subscription knobs on the streaming API and have no alertfile
equivalent; `streaming.md` documents those fields as populated because there they
can be. Fetch the transaction with `getrawtransaction` if you need its bytes.

**Reorgs re-emit confirmed watch matches.** There is no retraction event for a
script, outpoint, or silent-payment match: if a transaction confirms at height
H, the chain reorgs, and it reconfirms at H′, you receive a second
`confirmed: true` match for the same transaction with a **new** delivery id —
idempotency will not collapse them for you. If you credit on `confirmed: true`,
either wait for enough depth or key your ledger on `(txid, vout)` rather than on
delivery. Note this bites hardest on a hook configured with a watch-set but
*without* `categories = ["chain"]`, which is a supported shape: such a hook
receives no `reorg` or `block_disconnected` event and so has no way to learn the
rollback happened at all.

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
therefore fail verification and be retried forever. Terminate such a receiver
behind a publicly-trusted certificate, or put a local reverse proxy in front of
it and point the hook at loopback. No client certificate is presented.

## 8. Non-goals

Stated so nobody waits for them:

- **Exactly-once delivery.** Deduplicate on `X-Satd-Delivery`.
- **Batching.** One event per request.
- **Ordering across hooks.** Ordering is per hook only.
- **A hosted relay.** satd delivers to endpoints you run. The reference push
  relay in `contrib/` is a starting point you operate yourself, with your own
  APNs/FCM credentials.
