//! Tail the firehose over **mutual TLS** — present a client certificate to a
//! satd node configured with `eventsgrpcmtls=1`. The node verifies the client
//! cert against its configured CA (and optional CN/DNS-SAN allowlist); the
//! client pins the node's CA with `tls_ca_pem`.
//!
//! ```sh
//! cargo run -p satd-events-client --example mtls_tail -- \
//!     https://node.example:50051 ./node-ca.pem ./client-cert.pem ./client-key.pem
//! ```
//!
//! Pinning the server CA (`tls_ca_pem`) is required for the usual self-signed
//! satd node: without it the *server* cert is verified against the bundled
//! public roots and the handshake fails.

use satd_events_client::{Categories, Event, StreamClient, SubscribeOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args
        .next()
        .unwrap_or_else(|| "https://127.0.0.1:50051".into());
    let ca = args.next().expect("arg 2: server CA PEM path");
    let cert = args.next().expect("arg 3: client cert PEM path");
    let key = args.next().expect("arg 4: client key PEM path");

    let mut client = StreamClient::builder(endpoint)
        .keepalive_default()
        .tls_ca_pem(std::fs::read(ca)?)
        .tls_client_identity(std::fs::read(cert)?, std::fs::read(key)?)
        .connect()
        .await?;

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
