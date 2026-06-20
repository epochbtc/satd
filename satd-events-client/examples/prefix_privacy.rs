//! Privacy-preserving prefix watch: register a coarse `bits`-bit bucket of
//! `sha256(scriptPubKey)` (the server learns only the bucket), then re-filter
//! the decoy-laden deliveries down to true matches locally with a
//! [`PrefixWatcher`].
//!
//! Requires the default `bitcoin` feature.
//!
//! ```sh
//! cargo run -p satd-events-client --example prefix_privacy -- http://127.0.0.1:50051
//! ```

use satd_events_client::{Event, PrefixWatcher, StreamClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".into());

    // Our real scripts stay client-side; the server never sees them.
    let mut watcher = PrefixWatcher::new();
    watcher.watch_script_bytes(&[0x6a, 0x01, 0x2a]); // replace with real scriptPubKeys

    // Register a 16-bit bucket per script (coarse enough to hide which exact
    // script we hold; the watcher dedups scripts that share a bucket).
    let bits = 16;
    let prefixes = watcher.prefixes(bits);

    let mut client = StreamClient::builder(endpoint).keepalive_default().connect().await?;
    let (watch, mut events) = client.watch().await?;
    watch.add_script_prefixes(prefixes).await?;

    while let Some(event) = events.message().await? {
        if let Event::PrefixMatched(m) = event {
            // The bucket fired; decode and re-filter against our real scripts.
            let hits = watcher.filter(&m)?;
            for f in &hits.funding {
                println!("funding hit tx={} vout={} value={}", hits.txid, f.vout, f.value);
            }
            for s in &hits.spending {
                println!("spend hit tx={} outpoint={}:{}", hits.txid, hex(&s.outpoint.txid), s.outpoint.vout);
            }
            if hits.has_unresolved() {
                // Server didn't retain the prevout script (mempool below the
                // `full` tier); resolve these outpoints yourself before deciding
                // they're non-matches.
                println!("{} prevout(s) need local resolution", hits.unresolved.len());
            }
            if !hits.is_match() && !hits.has_unresolved() {
                // A decoy from the bucket — silently ignore (the privacy cost).
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
