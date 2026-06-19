//! Watch a wallet by output descriptor: expand `[start, start+gap)` into a
//! script watch-set server-side, and advance the gap-limit window as funding
//! approaches the high end (the client owns advancement).
//!
//! ```sh
//! cargo run -p satd-events-client --example descriptor_wallet -- http://127.0.0.1:50051
//! ```

use satd_events_client::{Event, StreamClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    let (watch, mut events) = client.watch().await?;

    // A ranged descriptor; the node expands it to scripts [0, 20).
    let descriptor = "wpkh([deadbeef/84h/0h/0h]xpub6.../0/*)";
    let gap_limit = 20u32;
    let mut start = 0u32;
    watch.add_descriptor(descriptor, gap_limit, start).await?;

    while let Some(event) = events.message().await? {
        if let Event::ScriptMatched { txid, is_output, index, confirmed, .. } = event {
            println!(
                "descriptor hit tx={} {} idx={} ({})",
                hex(&txid),
                if is_output { "funding" } else { "spending" },
                index,
                if confirmed { "confirmed" } else { "mempool" },
            );
            // A real wallet tracks which child index funded and advances the
            // window so it never runs past the gap limit.
            start += gap_limit;
            watch.add_descriptor(descriptor, gap_limit, start).await?;
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
