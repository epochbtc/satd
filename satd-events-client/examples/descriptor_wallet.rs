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
        match event {
            Event::ScriptMatched { txid, is_output, index, confirmed, .. } => {
                println!(
                    "descriptor hit tx={} {} idx={} ({})",
                    hex(&txid),
                    if is_output { "funding" } else { "spending" },
                    index,
                    if confirmed { "confirmed" } else { "mempool" },
                );
                // Gap-limit advancement is the wallet's job, and only *funding*
                // (output-side) hits consume new addresses. This stand-in is
                // deliberately simple: it nudges the window forward on each
                // funding hit. A real wallet maps the matched `scripthash` back
                // to the derived child index it registered, and only advances
                // when funding lands near the top of the current
                // `[start, start+gap_limit)` window — never on a spend
                // (`is_output == false`), and never past the gap limit. (Note
                // `index` here is the tx vout/vin, not the descriptor child
                // index, so it can't drive advancement on its own.)
                if is_output {
                    start += 1;
                    watch.add_descriptor(descriptor, gap_limit, start).await?;
                }
            }
            // If the node can't expand the descriptor it emits
            // `DescriptorNeedsAddresses`, which this SDK maps to `Event::Unknown`
            // (a typed accessor is future work) — a real client would surface it
            // rather than silently ignoring an unexpandable descriptor.
            Event::Unknown => {}
            _ => {}
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
