# satd-events-client

Async Rust client SDK for the satd **Streaming Consumption API** (`satd.events.v1`).

It wraps the generated [tonic](https://github.com/hyperium/tonic) client with a
typed event model, per-call auth metadata, cursor capture/persistence,
reconnect-with-backoff, `Lagged` auto-resume, replay-truncation detection, and a
privacy-preserving prefix-watch local re-filter — so a consumer writes against
`StreamClient` instead of hand-rolling channels, metadata, and protobuf
unwrapping.

- **Typed events & watches** — `Event` is a flat enum over the proto `oneof`;
  `WatchHandle` has a typed helper for every watch kind (scripts with
  `min_value` floors, outpoints, txid lifecycle, depth alarms, descriptors,
  prefixes).
- **Durable firehose** — `resilient_subscribe` reconnects with backoff and
  persists the resume cursor through a `CursorStore`, so a process restart
  resumes from the stored height; `Lagged` recovers automatically and a
  server-side replay clamp surfaces as a synthetic `Event::ReplayGap`.
- **Native TLS / mTLS** — `tls()` / `tls_ca_pem()` / `tls_client_identity()` /
  `tls_domain()` encrypt the transport (ring rustls provider) so a bearer token
  is never sent in cleartext.
- **No server-dependency leak** — wire types live in the thin
  [`satd-events-proto`](https://docs.rs/satd-events-proto) crate, so this SDK
  pulls none of the `node`/RocksDB server stack.

## Install

> **Pre-publish:** this crate is not yet on crates.io. Depend on it via git
> until the published release lands:

```toml
[dependencies]
satd-events-client = { git = "https://github.com/epochbtc/satd", branch = "master" }
```

Once published, `cargo add satd-events-client`.

To read the API docs before publication, generate them locally:

```sh
cargo doc -p satd-events-client --no-deps --all-features --open
```

## Quickstart

```rust,no_run
use satd_events_client::{StreamClient, SubscribeOptions, Categories, Event};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StreamClient::builder("http://127.0.0.1:50051")
        .keepalive_default()
        .connect()
        .await?;

    let mut events = client
        .subscribe(SubscribeOptions {
            categories: Categories::MEMPOOL | Categories::CHAIN,
            ..Default::default()
        })
        .await?;

    while let Some(event) = events.message().await? {
        if let Event::BlockConnected { height, .. } = event {
            println!("block {height}");
        }
    }
    Ok(())
}
```

Over a plaintext `http://` endpoint a bearer token travels in cleartext — enable
TLS (below), restrict bearer auth to loopback, or front the node with a
TLS-terminating proxy.

```rust,no_run
# use satd_events_client::StreamClient;
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
// Pin a satd node's own (self-signed) CA and authenticate with a token.
let client = StreamClient::builder("https://node.example:50051")
    .tls_ca_pem(std::fs::read("node-ca.pem")?)
    .bearer_token("…")
    .connect()
    .await?;
# let _ = client; Ok(())
# }
```

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `bitcoin` | on | Typed bitcoin helpers + the `PrefixWatcher` prefix-watch re-filter (pulls `bitcoin`/secp256k1). |
| `tls` | on | Native TLS / mTLS via tonic's rustls integration (ring provider; no aws-lc-rs / C toolchain). |

For a minimal, plaintext-only build: `default-features = false`.

## Examples

Runnable examples live in [`examples/`](examples/) — `firehose_tail`,
`resilient_tail`, `watch_outpoints`, `descriptor_wallet`, `lifecycle_alarms`,
`prefix_privacy`, `tls_tail`, `mtls_tail`:

```sh
cargo run -p satd-events-client --example firehose_tail -- http://127.0.0.1:50051
```

## Stability & versioning

The SDK tracks the **additive `satd.events.v1` wire schema**, not the node's
release cadence, and follows [semver](https://semver.org/) independently of the
satd node version — a node and SDK do **not** need matching versions. MSRV is
**1.93** (an MSRV bump is a minor-version change).

## More

- **Operator Manual — Rust SDK chapter:** <https://epochbtc.github.io/satd/rust-sdk.html>
- **Wire / streaming spec:** [`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md)

## License

MIT — see [LICENSE](https://github.com/epochbtc/satd/blob/master/LICENSE).
