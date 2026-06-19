//! Watch specific outpoints (`txid:vout`) for their spend, on a bidirectional
//! `Watch` stream. Prints `OutpointSpent` as each lands in mempool / a block.
//!
//! ```sh
//! cargo run -p satd-events-client --example watch_outpoints -- http://127.0.0.1:50051
//! ```

use satd_events_client::{Event, StreamClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    let (watch, mut events) = client.watch().await?;

    // Replace with real outpoints (txid bytes in internal order, vout). The
    // handle stays alive for the life of the stream; dropping it tears down.
    let txid = [0u8; 32];
    watch.add_outpoints([(txid, 0), (txid, 1)]).await?;

    while let Some(event) = events.message().await? {
        if let Event::OutpointSpent { outpoint, spending_txid, confirmed, .. } = event {
            println!(
                "outpoint {}:{} spent by {} ({})",
                hex(&outpoint.txid),
                outpoint.vout,
                hex(&spending_txid),
                if confirmed { "confirmed" } else { "mempool" },
            );
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
