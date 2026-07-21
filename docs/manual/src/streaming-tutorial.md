# Getting Started: Consuming Events

This chapter takes you from nothing to a durable, reconnect-surviving consumer
of satd's Streaming Consumption API, one runnable step at a time. Each step
names the concept, then links to the two reference chapters that own the
detail:

- the [Streaming Consumption API](streaming.md) chapter: the wire protocol,
  transports, watch-sets, cursors, quotas, and operator limits;
- the [Rust SDK (`satd-events-client`)](rust-sdk.md) chapter: every type and
  method, in isolation.

Read those when you need a full signature or an edge case.

The tutorial uses the Rust SDK throughout. Nothing here is Rust-specific at the
protocol level: WebSocket and SSE consumers follow the same sequence over the
JSON rendering (see the [Transports](streaming.md) section).

## Prerequisites

You need a running node with the events gRPC listener enabled
(`eventsgrpcbind = 127.0.0.1:50051`) and a project that depends on
`satd-events-client`. A loopback node needs no token. A remote node needs
bearer auth or mTLS; [Step 8](#step-8-go-remote-safely) covers that.

## Step 1: Choose a transport

The API has one schema and three transports: gRPC (the primary programmatic
surface), JSON over WebSocket (`GET /ws`, with a control channel), and SSE
(`GET /sse`, a read-only firehose for browsers and `curl`).

If you are writing a service, use gRPC. It is the only transport with the full
bidirectional watch-set control channel. The transport details and the port
model are in the [Transports](streaming.md) section. The rest of this tutorial
uses gRPC.

## Step 2: Connect

```rust,ignore
use satd_events_client::{StreamClient, SubscribeOptions, Categories, Event};

let mut client = StreamClient::builder("http://127.0.0.1:50051")
    .keepalive_default()
    .connect()
    .await?;
```

This opens a plaintext loopback connection, which is fine for a node on the
same host. TLS, mTLS, and bearer tokens are one builder call each; see
[Connecting](rust-sdk.md) and [Step 8](#step-8-go-remote-safely).

## Step 3: Tail the firehose

Before you watch anything specific, prove the pipe works. Tail the raw event
firehose, every block and mempool transition the node sees:

```rust,ignore
let mut events = client.subscribe(SubscribeOptions {
    categories: Categories::MEMPOOL | Categories::CHAIN,
    from_cursor: None,   // forward-only for now; Step 5 makes it durable
    since_seq:   None,
}).await?;

while let Some(event) = events.message().await? {
    match event {
        Event::BlockConnected { height, .. } => println!("block {height}"),
        Event::MempoolEnter { txid, .. }      => println!("mempool {txid}"),
        _ => {}
    }
}
```

`Event` is a flat enum, so you `match` on it instead of unwrapping nested
options. The full firehose semantics (categories, the captured `Cursor`, lag
notices) are under [the `subscribe` reference](rust-sdk.md).

## Step 4: Watch something and react

The firehose is the wrong tool for tracking your own scripts; that is a
watch-set. Open the bidirectional `watch` stream, register interest, and react
to matches:

```rust,ignore
let (watch, mut events) = client.watch().await?;

// A direct script watch, with an optional per-script value floor (sat).
watch.add_scripts([(scripthash, Some(100_000))]).await?;

// Or a whole wallet from its exported descriptor: the server expands the
// gap-limit window and derives the scripts for you (keyless: public-key-only).
watch.add_descriptor(descriptor, /*gap*/ 20, /*start*/ 0).await?;

while let Some(event) = events.message().await? {
    if let Event::ScriptMatched { txid, descriptors, .. } = event {
        // `descriptors` maps a descriptor-derived hit back to its descriptor
        // and exact (branch, derivation_index); it is empty for a direct
        // watch. A multi-wallet consumer routes the hit with no reverse index.
        println!("hit {txid} ({} descriptor attributions)", descriptors.len());
    }
}
```

Outpoint, txid-lifecycle, and confirmation-depth watches all take the same
shape. Every watch kind, and the edge cases the typed helpers handle, are under
[the `watch` reference](rust-sdk.md).

## Step 5: Make it survive a reconnect

The `watch` stream above loses its watch-set and its place in the stream the
moment the connection drops. `resilient_watch` fixes both. It re-registers the
watch-set on every reconnect and resumes from a persisted cursor, so a network
blip or a process restart is invisible to your logic.

```rust,ignore
use satd_events_client::{ResilientWatchConfig, FileCursorStore, Event, AutoClose};
use std::sync::Arc;

let config = ResilientWatchConfig::new()
    .cursor_store(Arc::new(FileCursorStore::new("/var/lib/app/watch.cursor")));
let mut watch = client.resilient_watch(config);

// Registered once; replayed automatically across every reconnect.
watch.add_scripts([(scripthash, None)]).await?;
watch.add_tx_lifecycle([txid], AutoClose::AtDepth(6)).await?;

loop {
    match watch.next().await? {
        Event::ScriptMatched { txid, .. } => { /* your logic */ }
        _ => {}
    }
}
```

Kill the node's listener and bring it back: the wrapper reconnects with
backoff, re-registers the set, and re-anchors the cursor. Re-anchoring is
deterministic, driven by the in-band `CursorAccepted`/`CursorRejected` result.
Use this wrapper as the default for any long-lived consumer. See
[the `resilient_watch` reference](rust-sdk.md).

## Step 6: Bind the watch-set to your source of truth

The mirror `resilient_watch` keeps is authoritative only if you build the set
once and never change it. Real consumers have a durable source of truth, such
as a database table of watched addresses, and it changes while the process
runs.

Give the wrapper a `watch_set_loader`. The wrapper then rebuilds the canonical
set from that truth on every reconnect, and on a fresh start it rehydrates from
truth, not from an empty mirror:

```rust,ignore
let config = ResilientWatchConfig::new()
    .cursor_store(Arc::new(FileCursorStore::new("/var/lib/app/watch.cursor")))
    .watch_set_loader({
        let db = db.clone();
        move |builder| {
            let db = db.clone();
            async move {
                for row in db.load_watched_scripts().await? {
                    builder.add_scripts([(row.scripthash, row.min_value)]);
                }
                Ok(())
            }
        }
    });
```

When the truth changes while the stream is up, after a bulk import for
example, call `watch.reload().await?`. It re-runs the loader and pushes the
whole desired set as a single atomic `SetWatchSet`. The server reconciles the
set by effective coverage under its lock and answers deterministically:
`WatchSetReplaced`, or `WatchSetRejected { reason, .. }` with `QuotaExceeded`,
`CapExceeded`, or `Malformed`. No client-computed delta can strand coverage.
The full semantics are in the loader and `reload()` subsections of
[the `resilient_watch` reference](rust-sdk.md).

## Step 7: Watch privately with a script prefix

Every step so far tells the node exactly which scripts you care about. For a
custodian, an exchange, or a privacy-sensitive wallet, that interest set is
itself sensitive: the node operator learns exactly whom you watch. A **prefix
watch** breaks that link.

You register only a coarse `bits`-bit prefix of `sha256(scriptPubKey)`. The
server delivers every transaction that falls in that `2^-bits` bucket, so it
learns only the bucket, never your exact script. You filter the decoys out
locally. `PrefixWatcher` (behind the `bitcoin` feature) computes the buckets to
register and does the local filtering:

```rust,ignore
use satd_events_client::{PrefixWatcher, Event};

let mut watcher = PrefixWatcher::new();
watcher.watch_script(&my_script_pubkey);          // add each real script locally

let (watch, mut events) = client.watch().await?;
watch.add_script_prefixes(watcher.prefixes(16)).await?;   // register 16-bit buckets

while let Some(event) = events.message().await? {
    if let Event::PrefixMatched(m) = event {
        let hits = watcher.filter(&m)?;           // recomputes sha256(spk), drops decoys
        for f in &hits.funding  { /* a genuine funding match */ }
        for s in &hits.spending { /* a genuine spend match  */ }
        if hits.has_unresolved() {
            // A spend-side prevout the server did not retain (mempool below
            // the `full` tier). Resolve the outpoint yourself before you
            // conclude non-match; do not treat "absent" as "not mine".
        }
    }
}
```

`bits` sets the privacy/bandwidth trade-off. Fewer bits means a larger bucket,
more decoy traffic, and a weaker link between you and any one script. `filter`
never issues a precise follow-up fetch, because that would re-leak the interest
the bucket exists to hide. The `streamprevoutmeta` option governs spend-side
retention; the retention tiers and the full mechanism are in
[Prefix watches](rust-sdk.md) and the [Streaming API](streaming.md) chapter.

## Step 8: Go remote safely

Every step above assumed a loopback node. A remote bind must be encrypted and
authenticated: over plaintext `http://`, the bearer token and the entire event
stream travel in the clear. Add TLS (a public CA or a pinned self-signed CA)
and a token, or mutual TLS, with one builder call each:

```rust,ignore
let mut client = StreamClient::builder("https://node.example:50051")
    .tls()                       // or .tls_ca_pem(std::fs::read("node-ca.pem")?)
    .bearer_token(token)
    .keepalive_default()
    .connect()
    .await?;
```

The node-side options (`eventsgrpctlscert`, `eventsgrpcmtls`,
`eventsgrpcallowremote`) are in the [Transport encryption](streaming.md)
section. The client-side builder options, including the mTLS client identity,
are under [TLS / mTLS](rust-sdk.md).

## Where to next

The tutorial covered the full sequence: connect, tail the firehose, register a
watch-set, make it durable, bind it to your source of truth, watch privately,
and go remote. The reference chapters cover what this tutorial deferred:

- **Quotas and error handling.** The watch quota, the rate limits, and which
  `StreamError`s are retryable: [Errors](rust-sdk.md) and the
  [Authentication & quotas](streaming.md) section.
- **Cursors and replay.** Exact confirmed-side replay, best-effort mempool
  replay, and the replay-truncation `ReplayGap`:
  [Cursors & replay](streaming.md).
- **Runnable examples.** `firehose_tail`, `resilient_tail`, `watch_outpoints`,
  `descriptor_wallet`, `lifecycle_alarms`, `prefix_privacy`, `tls_tail`, and
  `mtls_tail`, in
  [`satd-events-client/examples/`](https://github.com/epochbtc/satd/tree/master/satd-events-client/examples).
