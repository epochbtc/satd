//! Durable firehose: reconnect with backoff, persist the resume cursor to a
//! file, and recover from lag automatically. Survives both transient
//! disconnects and a full process restart (the cursor file replays on launch).
//!
//! ```sh
//! cargo run -p satd-events-client --example resilient_tail -- http://127.0.0.1:50051 /tmp/satd.cursor
//! ```

use std::sync::Arc;

use satd_events_client::{
    Categories, Event, FileCursorStore, ResilientConfig, StreamClient, SubscribeOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let cursor_path = args.next().unwrap_or_else(|| "/tmp/satd.cursor".into());

    let client = StreamClient::builder(endpoint).keepalive_default().connect().await?;

    // AutoResume lag policy + file-backed cursor are the defaults worth setting:
    // a restart resumes from the persisted height instead of forward-only.
    let config = ResilientConfig::new()
        .cursor_store(Arc::new(FileCursorStore::new(cursor_path)));

    let mut sub = client.resilient_subscribe(
        SubscribeOptions {
            categories: Categories::MEMPOOL | Categories::CHAIN,
            ..Default::default()
        },
        config,
    );

    // `next()` reconnects and replays underneath; it returns Err only on a
    // permanent failure (bad endpoint/token) or exhausted retries.
    loop {
        match sub.next().await {
            Ok(Event::ReplayGap { resume_height, first_height }) => {
                eprintln!(
                    "WARNING: replay clamped — blocks ({resume_height}, {first_height}) \
                     skipped; full-resync them from another source"
                );
            }
            Ok(Event::BlockConnected { height, .. }) => println!("block {height}"),
            Ok(other) => println!("{other:?}"),
            Err(e) => {
                eprintln!("fatal: {e}");
                return Err(e.into());
            }
        }
    }
}
