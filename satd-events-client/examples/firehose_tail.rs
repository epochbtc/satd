//! Tail the firehose: connect, subscribe to mempool + chain, print each event.
//!
//! ```sh
//! cargo run -p satd-events-client --example firehose_tail -- http://127.0.0.1:50051 [token]
//! ```

use satd_events_client::{Categories, Event, StreamClient, SubscribeOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "http://127.0.0.1:50051".into());

    let mut builder = StreamClient::builder(endpoint).keepalive_default();
    if let Some(token) = args.next() {
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
            Event::MempoolEnter { txid, fee, vsize, .. } => {
                println!("mempool enter {} fee={} vsize={}", hex(&txid), fee, vsize);
            }
            Event::BlockConnected { hash, height } => {
                println!("block {height} {}", hex(&hash));
            }
            Event::Reorg { from_height, to_height, .. } => {
                println!("reorg {from_height} -> {to_height}");
            }
            // The cursor advances on confirmed events — persist it to resume.
            other => {
                if let Some(c) = events.cursor() {
                    println!("event {other:?} (cursor height={})", c.height);
                } else {
                    println!("event {other:?}");
                }
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
