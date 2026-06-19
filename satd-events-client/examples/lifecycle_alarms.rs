//! Track a transaction's lifecycle (seen → confirmed → replaced/evicted) and
//! arm depth alarms that fire once at given confirmation depths.
//!
//! ```sh
//! cargo run -p satd-events-client --example lifecycle_alarms -- http://127.0.0.1:50051
//! ```

use satd_events_client::{AutoClose, Event, StreamClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    let (watch, mut events) = client.watch().await?;

    let txid = [0u8; 32]; // replace with the txid to track

    // Lifecycle watch that self-evicts (emitting TxidFinalized) at 6 confs.
    watch.add_tx_lifecycle([txid], AutoClose::AtDepth(6)).await?;
    // Single-shot alarms at 1 and 3 confs (cross product of txids × depths).
    watch.add_depth_alarms([txid], [1, 3]).await?;

    while let Some(event) = events.message().await? {
        match event {
            Event::TxidMatched { confirmed, height, .. } => {
                println!("seen ({}) at height {height}", if confirmed { "confirmed" } else { "mempool" });
            }
            Event::TxidDepthReached { depth, height, .. } => {
                println!("depth alarm: {depth} confs at height {height}");
            }
            Event::TxidReplaced { replacing_txid, .. } => {
                println!("replaced by {}", hex(&replacing_txid));
            }
            Event::TxidEvicted { reason, .. } => println!("evicted: {reason}"),
            Event::TxidFinalized { depth, .. } => {
                println!("finalized at {depth} confs — watch auto-closed");
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
