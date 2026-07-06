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
            Event::ScriptMatched { txid, is_output, index, confirmed, descriptors, .. } => {
                // Attribution gives the exact (branch, derivation_index) the
                // server derived the matched script at — no need to re-expand
                // the descriptor or maintain a reverse scripthash index.
                for d in &descriptors {
                    println!(
                        "descriptor hit tx={} {} idx={} branch={} derivation={} ({})",
                        hex(&txid),
                        if is_output { "funding" } else { "spending" },
                        index,
                        d.branch,
                        d.derivation_index,
                        if confirmed { "confirmed" } else { "mempool" },
                    );
                }
                // Gap-limit advancement is still the wallet's job, and only
                // *funding* (output-side) hits consume new addresses: only
                // advance once a funding match's derivation_index lands near
                // the top of the current [start, start+gap_limit) window,
                // never on a spend. This stand-in nudges the window forward on
                // every funding hit instead.
                if is_output {
                    start += 1;
                    watch.add_descriptor(descriptor, gap_limit, start).await?;
                }
            }
            // Forward-compat: an event arm this SDK build doesn't recognize
            // (a newer server) decodes to `Event::Unknown`. The server never
            // pushes a gap-limit nudge — advancing the window is this client's
            // job, done above on each funding match.
            Event::Unknown => {}
            _ => {}
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
