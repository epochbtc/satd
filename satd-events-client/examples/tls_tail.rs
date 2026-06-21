//! Tail the firehose over **TLS**, so the bearer token and event stream are
//! never sent in cleartext. Pin the node's own (self-signed) CA with the second
//! argument; omit it to trust the bundled public Mozilla roots instead.
//!
//! ```sh
//! # Pin a satd node's CA (the usual case) + authenticate with a token:
//! cargo run -p satd-events-client --example tls_tail -- \
//!     https://node.example:50051 ./node-ca.pem [token]
//!
//! # Public-CA server (no CA pin): pass "-" for the CA path:
//! cargo run -p satd-events-client --example tls_tail -- https://node.example:50051 -
//! ```

use satd_events_client::{Categories, Event, StreamClient, SubscribeOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args
        .next()
        .unwrap_or_else(|| "https://127.0.0.1:50051".into());
    let ca_path = args.next(); // a path, or "-"/absent for the bundled roots
    let token = args.next();

    // NOTE: the endpoint must be `https://` — the SDK refuses to connect with
    // TLS requested over a plaintext `http://` scheme rather than silently
    // downgrading.
    let mut builder = StreamClient::builder(endpoint).keepalive_default();
    builder = match ca_path.as_deref() {
        Some(p) if p != "-" => builder.tls_ca_pem(std::fs::read(p)?),
        _ => builder.tls(), // bundled public roots
    };
    if let Some(token) = token {
        builder = builder.bearer_token(token);
    }
    let mut client = builder.connect().await?;

    let mut events = client
        .subscribe(SubscribeOptions {
            categories: Categories::MEMPOOL | Categories::CHAIN,
            ..Default::default()
        })
        .await?;

    while let Some(event) = events.message().await? {
        match event {
            Event::BlockConnected { height, .. } => println!("block {height}"),
            other => println!("event {other:?}"),
        }
    }
    Ok(())
}
