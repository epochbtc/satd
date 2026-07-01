# Rust SDK (`satd-events-client`)

`satd-events-client` is the async Rust client for the [Streaming Consumption
API](streaming.md). The gRPC contract is fully specified and a generated tonic
client already exists — but it is raw: every consumer otherwise hand-writes the
same channel wiring, `authorization` metadata injection, cursor capture and
persistence, lag recovery, reconnect-with-backoff, and (for prefix watches)
local re-filtering. The SDK absorbs all of that behind a small typed surface, so
a consumer watches outpoints in ten lines instead of a hundred.

It is the recommended way to consume the streaming API from Rust. Non-Rust
consumers use the gRPC/WebSocket surface directly against the
[`.proto`](https://github.com/epochbtc/satd/blob/master/satd-events-proto/proto/satd/events/v1/events.proto)
contract.

## Crate layout

The wire types are codegen'd once in `satd-events-proto` (a thin tonic/prost
crate shared by the node's server and this client), so the SDK pulls no server
glue — no `node`, no RocksDB. `satd-events-client` adds only a lean ergonomic
layer (`tonic`, `prost`, `tokio`, `tokio-stream`, `thiserror`, and an optional
`bitcoin`).

```toml
[dependencies]
satd-events-client = "0.4"
```

> **Pre-publish:** the crate is not yet on crates.io. Until the published
> release lands, depend on it via git and read its API docs locally:
>
> ```toml
> satd-events-client = { git = "https://github.com/epochbtc/satd", branch = "master" }
> ```
>
> ```sh
> cargo doc -p satd-events-client --no-deps --all-features --open
> ```

The default build includes the `bitcoin` feature (the prefix-watch re-filter and
scripthash helpers). For a minimal dependency tree that hands you raw bytes to
filter yourself:

```toml
satd-events-client = { version = "0.4", default-features = false }
```

## Connecting

```rust,ignore
use satd_events_client::{StreamClient, SubscribeOptions, Categories, Event};

let mut client = StreamClient::builder("http://node:50051")
    .bearer_token(token)     // sent as `authorization: Bearer …` on every call
    .keepalive_default()     // http2 keepalive matching the server (30s/20s)
    .connect()
    .await?;
```

The bearer token is honored only when the server enforces auth
(`-eventsgrpcauth`). Over a plaintext `http://` endpoint the token travels in
cleartext — enable TLS (below), restrict bearer auth to loopback, or front the
node with a TLS-terminating proxy. The client's `Debug` impl redacts the token
(and never prints TLS key material).

## TLS / mTLS

With the default `tls` feature, encrypt the transport so neither the token nor
the event stream is sent in the clear. The node terminates TLS natively
(`eventsgrpctlscert`/`eventsgrpctlskey`; see the [Streaming chapter](streaming.md)).

```rust,ignore
// Public-CA server: trust the bundled Mozilla roots.
let client = StreamClient::builder("https://node.example:50051")
    .tls()
    .bearer_token(token)
    .connect()
    .await?;

// satd node with its own (self-signed) CA: pin it.
let ca = std::fs::read("node-ca.pem")?;
let client = StreamClient::builder("https://10.0.0.5:50051")
    .tls_ca_pem(ca)
    .tls_domain("node.example")          // when connecting by IP / through a proxy
    .bearer_token(token)
    .connect()
    .await?;

// Mutual TLS (server set with `eventsgrpcmtls=1`): present a client certificate.
let client = StreamClient::builder("https://node.example:50051")
    .tls_ca_pem(std::fs::read("node-ca.pem")?)
    .tls_client_identity(std::fs::read("client-cert.pem")?, std::fs::read("client-key.pem")?)
    .connect()
    .await?;
```

`tls_ca_pem` pins exactly that authority (the bundled public roots are not used);
plain `tls()` uses the public roots. TLS uses the `ring` rustls provider. For a
plaintext-only minimal build, depend with `default-features = false`.

## Firehose — `subscribe`

```rust,ignore
let mut events = client.subscribe(SubscribeOptions {
    categories: Categories::MEMPOOL | Categories::CHAIN,
    from_cursor: persisted_cursor, // durable replay anchor; None = forward-only
    since_seq:   None,             // forward-only dedup within the broadcast window
}).await?;

while let Some(event) = events.message().await? {
    match event {
        Event::BlockConnected { height, .. } => println!("block {height}"),
        Event::MempoolEnter { txid, fee, vsize, .. } => { /* … */ }
        Event::Lagged { resume_cursor, .. } => { /* reconnect from resume_cursor */ }
        _ => {}
    }
}
```

`Event` is a flat enum mirroring the proto `oneof body`, so you `match` instead
of unwrapping nested `Option`s. As confirmed events flow, the stream captures
their durable `Cursor`; `events.cursor()` returns the latest. Persist it and
present it again as `from_cursor` to resume exactly where you left off.

## Durable firehose — `resilient_subscribe`

For a long-lived consumer, `resilient_subscribe` wraps the firehose in a
`ResilientSubscription` that handles the failure modes for you:

```rust,ignore
use std::sync::Arc;
use satd_events_client::{ResilientConfig, FileCursorStore, Event};

let config = ResilientConfig::new()
    .cursor_store(Arc::new(FileCursorStore::new("/var/lib/app/satd.cursor")));

let mut sub = client.resilient_subscribe(opts, config);
loop {
    match sub.next().await? {
        Event::ReplayGap { resume_height, first_height } => {
            // replay was clamped: blocks (resume_height, first_height) were
            // skipped — full-resync them from another source
        }
        event => handle(event),
    }
}
```

What it absorbs:

- **Reconnect with backoff** — transport errors and clean server closes trigger
  an exponential-backoff reconnect (`Backoff`, capped, optionally bounded by
  `max_retries`). `next()` returns `Err` only on a permanent failure or
  exhausted retries.
- **Cursor persistence** — confirmed cursors are written to a `CursorStore`
  (`NoopCursorStore` default; `FileCursorStore` for restart-durable resume, or
  your own impl over a database). A reconnect *and* a process restart both
  resume from the stored anchor.
- **Lag recovery** — a `Lagged` notice is, by default (`LagPolicy::AutoResume`),
  transparently turned into a reconnect from its `resume_cursor`;
  `LagPolicy::Surface` hands it to you instead.
- **Replay-truncation detection** — the server clamps a far-behind cursor's
  replay to the most recent `MAX_REPLAY_BLOCKS` (10,000) blocks. When that
  happens the SDK emits a synthetic `Event::ReplayGap` *before* the first
  replayed block, naming the skipped range, so you can full-resync it rather
  than silently delivering a gap.
- **`instance_id` handling** — the full cursor replays verbatim; the server
  discards a stale `mempool_seq` on a restart mismatch while confirmed (height)
  replay is unaffected.

## Watches — `watch`

`watch` opens the bidirectional stream and returns a `WatchHandle` plus the
event stream. The handle has a typed helper for every watch kind; empty inputs
are no-ops, and dropping the handle tears the stream down.

```rust,ignore
let (watch, mut events) = client.watch().await?;

watch.add_scripts([(scripthash, Some(100_000))]).await?;  // per-script min_value floor (sat)
watch.add_outpoints([(txid, vout)]).await?;
watch.add_tx_lifecycle([txid], AutoClose::AtDepth(6)).await?;
watch.add_depth_alarms([txid], [1, 3]).await?;            // cross product txids × depths
watch.add_descriptor(descriptor, /*gap*/ 20, /*start*/ 0).await?;  // multipath <0;1> ⇒ 2×gap scripts
watch.add_script_prefixes([(prefix_bytes, 16)]).await?;   // privacy-preserving prefix
watch.set_categories(mask).await?;
watch.set_cursor(cursor).await?;                          // mid-stream re-anchor (best-effort)
watch.remove_scripts([scripthash]).await?;                // releases quota immediately
```

A few sharp edges the helpers handle for you:

- **Depth alarms vs lifecycle.** `add_tx_lifecycle` sends an empty `min_depths`
  (the server reads that as a lifecycle add); `add_depth_alarms` sends the
  depths and filters out `depth < 1` client-side, so an all-invalid call is a
  true no-op rather than an accidental lifecycle add.
- **`min_value` floors.** Parallel to the scripthashes; a `None` floor delivers
  everything, a floor of 0 is deliver-all, and a non-zero floor suppresses
  matches below it server-side (symmetric across funding and spend sides).
- **`set_cursor` reports its outcome in-band.** `Ok(())` means the re-anchor was
  *sent*, not that it ran. The server answers on the event stream with exactly
  one `Event::CursorAccepted { clamped, earliest_replayed, .. }` (admitted,
  replaying — `clamped` flags an authoritative replay-window gap) or
  `Event::CursorRejected { reason, .. }` (`RateLimited`, `ConcurrentReanchor`,
  `EmptyCursor`, `NoSource`). Drive your catch-up off those rather than treating
  `Ok(())` as success — or use `resilient_watch` (below), which does it for you.

## Durable watch — `resilient_watch`

`watch` gives you the raw bidirectional stream; `resilient_watch` wraps it the
way `resilient_subscribe` wraps the firehose — but with the extra work the
`Watch` stream needs, because **the watch-set is per-connection**: when the
stream drops, the server discards your watch-set and quota leases, so a bare
reconnect comes back blind.

`ResilientWatch` closes that gap:

- **Watch-set mirror.** It records every `add_*` / `remove_*` / `set_categories`
  you make and **re-registers the whole set** on each reconnect — you keep
  calling the same typed helpers, now on `ResilientWatch`.
- **Re-anchor off the deterministic result.** After re-registering it
  `set_cursor`s to the persisted high-water and drives catch-up off the in-band
  ack: a transient `CursorRejected` (`RateLimited` / `ConcurrentReanchor`) is
  backed off and retried in place; a `CursorAccepted { clamped: true, .. }` or a
  terminal reject (`NoSource`) is surfaced so you can resnapshot — the
  exception, not the everyday fallback.
- **Cursor persistence + backoff.** It reuses the same `CursorStore` and
  `Backoff` as `resilient_subscribe`, committing confirmed cursors on-poll.

```rust,ignore
use satd_events_client::{ResilientWatchConfig, FileCursorStore, Event, AutoClose};
use std::sync::Arc;

let config = ResilientWatchConfig::new()
    .cursor_store(Arc::new(FileCursorStore::new("/var/lib/app/watch.cursor")));
let mut watch = client.resilient_watch(config);

// Register interest once; it is replayed automatically across reconnects.
watch.add_scripts([(scripthash, None)]).await?;
watch.add_tx_lifecycle([txid], AutoClose::AtDepth(6)).await?;

loop {
    match watch.next().await? {
        Event::ScriptMatched { txid, .. } => { /* ... */ }
        Event::CursorAccepted { clamped: true, earliest_replayed, .. } => {
            // Authoritative gap: full-resync confirmed history below
            // `earliest_replayed` from another source.
        }
        Event::CursorRejected { reason, .. } => { /* escalate to a resnapshot */ }
        _ => {}
    }
}
```

It is single-task, like `ResilientSubscription`: interleave watch-set edits with
`next()` calls from one task (react to a match, then adjust the watch-set). A
descriptor replays from its latest `(gap_limit, start)`, so advance `start` to
slide the window across reconnects (the server reconciles the slid window), or
`remove_descriptor(descriptor)` to drop it — which releases every scripthash its
window contributed whose last owner that drops (a script shared with a direct add
or another descriptor stays).

### Watch-set loader — when truth lives outside the wrapper

The mirror above is authoritative only when you build the watch-set once at
startup and never change it during the process lifetime. The moment the
watch-set has a durable **source-of-truth** outside the wrapper — a DB table, a
config file, an upstream service — the mirror is really a *cache* of that truth,
and two gaps open: a process restart starts with an empty mirror (nothing to
replay), and a change to the truth while the stream is down (an entity added,
removed, or rekeyed through your own API) leaves the mirror stale until the next
in-process edit happens to touch it.

`watch_set_loader` closes both. It runs once after **every** (re)connect,
**before** the event stream resumes, and rebuilds the canonical set from your
truth into a fresh `WatchSetBuilder` — so the first events after a reconnect
already land on a fully-populated subscription, and a restart rehydrates from
truth instead of from an empty mirror:

```rust,ignore
use satd_events_client::{ResilientWatchConfig, FileCursorStore, WatchSetBuilder};
use std::sync::Arc;

let db = Arc::new(my_watch_db());
let config = ResilientWatchConfig::new()
    .cursor_store(Arc::new(FileCursorStore::new("/var/lib/app/watch.cursor")))
    .watch_set_loader({
        let db = db.clone();
        move |builder: WatchSetBuilder| {
            let db = db.clone();
            async move {
                // Query the source-of-truth and declare the canonical set.
                for row in db.load_watched_scripts().await? {
                    builder.add_scripts([(row.scripthash, row.min_value)]);
                }
                Ok(())
            }
        }
    });
let mut watch = client.resilient_watch(config);
```

Semantics:

- **Canonical on every connect.** The loaded set *replaces* the mirror. You can
  still call `add_*` / `remove_*` for live edits within the current connection,
  but the next reconnect re-derives the set from the loader — so your truth, not
  the accumulated in-process edits, is the record across reconnects. Persist a
  hot-add to your truth and the loader picks it up on the next connect.
- **The cursor is independent.** Resume still comes from the `CursorStore` /
  `from_cursor`; the re-anchor runs after the loaded set is registered, exactly
  as without a loader.
- **Loader errors are transient.** A failure maps to `StreamError::WatchSetLoader`
  and is backed off and retried on the next connect — a momentary outage of your
  source-of-truth must not crash an at-least-once consumer.

`WatchSetBuilder` exposes the declarative `add_*` / `set_categories` surface (no
`remove_*` — you are building a complete set into an empty mirror). Omit the
loader and behavior is exactly the mirror-replay described above.

#### Pushing a truth change mid-stream — `reload()`

The loader fires on every *reconnect*. When the durable truth changes **while the
stream is up** — a bulk import that wrote rows outside your hot-add path, an admin
rotation, an operator "make the wire match truth now" reconciliation — `reload()`
re-runs the loader and pushes the freshly-loaded set as a **single atomic
`SetWatchSet`**:

```rust,ignore
let summary = watch.reload().await?;   // ReloadSummary { added, removed, unchanged, applied }
tracing::info!(?summary, "watch-set realigned with truth");
```

- **One atomic replace, server-reconciled** — `reload()` sends the *whole* desired
  set in one `SetWatchSet` message; the server reconciles it under its watch-set
  lock, by **effective scripthash coverage** (descriptors expanded). It never
  sends a client-computed `Add*`/`Remove*` delta, so there is no message ordering
  that can strand coverage or over-charge at quota. An item watched in both the
  old and new set — even if its *mechanism* changes (a direct script becoming
  descriptor-covered, or vice versa) — is kept without a re-registration, so the
  matcher sees no gap. Quota is all-or-nothing on the whole target.
- **Deterministic result** — the outcome arrives in-band on `next()` as
  `Event::WatchSetReplaced { added, removed, unchanged }` (the server's
  authoritative counts) or `Event::WatchSetRejected { reason, required, quota }`.
  `reason` is `QuotaExceeded` (the target does not fit quota — shed and retry) or
  `Malformed` (the server could not parse an element of the snapshot — a client
  bug; retrying the same set will not help). Either way the live set is left
  unchanged. The `ReloadSummary` returned by `reload()` carries advisory
  client-side counts; the `Event` is the source of truth.
- **Atomic w.r.t. your task** — `&mut self` serializes `reload()` against your
  `add_*` / `next()` on the single task.
- **Disconnected defers, never errors** — with the stream down there's nothing to
  apply now; the mirror is still updated and the next reconnect's loader
  re-registers it. `ReloadSummary::applied` tells you which happened.
- Returns `ReloadError::NoLoader` if no loader is configured, or
  `ReloadError::Loader` if the loader itself fails (surfaced, not retried — you
  decide whether to call again).

This reuses the backoff / cursor re-anchor / loader plumbing — the reason to use
`ResilientWatch` at all — instead of dropping and rebuilding the wrapper to force
a full re-push.

## Prefix watches (privacy-preserving)

A prefix watch registers a coarse `bits`-bit prefix of `sha256(scriptPubKey)`.
The server delivers **every** transaction in that `2^-bits` bucket — so it
learns only the bucket, never your exact script — and you filter the decoys out
locally. `PrefixWatcher` (the `bitcoin` feature) is that filter:

```rust,ignore
use satd_events_client::{PrefixWatcher, Event};

let mut watcher = PrefixWatcher::new();
watcher.watch_script(&my_script_pubkey);

let (watch, mut events) = client.watch().await?;
watch.add_script_prefixes(watcher.prefixes(16)).await?;   // dedup'd bucket set

while let Some(event) = events.message().await? {
    if let Event::PrefixMatched(m) = event {
        let hits = watcher.filter(&m)?;     // decodes raw_tx, recomputes sha256(spk)
        for f in &hits.funding { /* true output match */ }
        for s in &hits.spending { /* true spend match */ }
        if hits.has_unresolved() {
            // spend-side prevout the server didn't retain (mempool below the
            // `full` tier): resolve the outpoint yourself before concluding
            // non-match — never treat absent as zero
        }
    }
}
```

`prefixes(bits)` derives the deduplicated bucket set to register (scripts sharing
a bucket collapse to one). `filter` returns only genuine matches plus the
outpoints it could not resolve locally — it never issues a precise follow-up
fetch that would re-leak the interest the bucket exists to hide. See the
[Streaming API chapter](streaming.md) for `streamprevoutmeta` retention tiers,
which govern what the spend side carries.

## Errors

`StreamError` classifies the conditions that stop forward progress; the
`Lagged` notice is **not** among them — it is a normal, recoverable `Event`. Use
`StreamError::is_retryable()` to decide whether to back off and retry
(`Connect`, transient transport codes, `QuotaExhausted`) versus give up
(`PermissionDenied`, a bad endpoint/token, client-side argument errors).
`Unauthenticated` is reported non-retryable — re-auth and reconnect
deliberately rather than blind-retrying the same token. `QuotaExhausted` is
treated as retryable because its common causes (subscription cap, per-principal
rate limit) are transient; a genuinely full *watch quota* is not, so inspect the
boxed status message before retrying a watch-add forever.

## Stability & versioning

The SDK tracks the **additive `satd.events.v1` wire schema**, not the node's
release cadence: new optional fields and event/watch kinds are added without
breaking existing consumers, and the crate follows [semver](https://semver.org/)
independently of the satd node version — a node and SDK do **not** need matching
versions. The generated wire types are re-exported under `proto` so you can pin
to the schema directly when a typed helper does not yet cover your case. The
minimum supported Rust version (**MSRV**) is **1.93**; an MSRV bump is treated as
a minor-version change. The underlying gRPC contract is the
[streaming spec](streaming.md).

## Examples

Runnable examples live in
[`satd-events-client/examples/`](https://github.com/epochbtc/satd/tree/master/satd-events-client/examples):
`firehose_tail`, `resilient_tail`, `watch_outpoints`, `descriptor_wallet`,
`lifecycle_alarms`, `prefix_privacy`, and — over an encrypted transport —
`tls_tail` and `mtls_tail`.

```sh
cargo run -p satd-events-client --example resilient_tail -- http://127.0.0.1:50051 /tmp/satd.cursor
cargo run -p satd-events-client --example tls_tail -- https://node.example:50051 ./node-ca.pem
```
