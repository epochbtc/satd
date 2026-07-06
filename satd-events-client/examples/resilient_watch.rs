//! Reconnect-and-replay-aware `Watch`: a durable-truth watch-set loader
//! rebuilds the canonical set from an external store on every (re)connect,
//! `reload()` realigns a live stream with that truth on demand, and the
//! resume cursor survives both transient disconnects and a full process
//! restart (commit-on-poll, persisted to a file).
//!
//! ```sh
//! cargo run -p satd-events-client --example resilient_watch -- http://127.0.0.1:50051 /tmp/satd-watch.cursor
//! ```

use std::sync::{Arc, Mutex};

use satd_events_client::{
    Event, FileCursorStore, ResilientWatchConfig, StreamClient, WatchSetBuilder,
};

/// Stand-in for a durable source-of-truth (a DB, a config file, an upstream
/// service) that the loader rebuilds the watch-set from on every reconnect.
/// A real integrator would query it with real `await`s between calls.
#[derive(Clone, Default)]
struct WatchedAddresses(Arc<Mutex<Vec<[u8; 32]>>>);

impl WatchedAddresses {
    fn snapshot(&self) -> Vec<[u8; 32]> {
        self.0.lock().unwrap().clone()
    }

    fn insert(&self, scripthash: [u8; 32]) {
        self.0.lock().unwrap().push(scripthash);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let cursor_path = args.next().unwrap_or_else(|| "/tmp/satd-watch.cursor".into());

    // Seed the truth with one address; a real integrator's truth already has
    // whatever it persisted before this process started.
    let truth = WatchedAddresses::default();
    truth.insert([0x11; 32]);

    let client = StreamClient::builder(endpoint).keepalive_default().connect().await?;

    let loader_truth = truth.clone();
    let config = ResilientWatchConfig::new()
        .cursor_store(Arc::new(FileCursorStore::new(cursor_path)))
        .watch_set_loader(move |builder: WatchSetBuilder| {
            let truth = loader_truth.clone();
            async move {
                // Runs on every (re)connect, before the event stream resumes,
                // so the mirror can never go stale after a restart or an
                // outage — the loader's truth is canonical, not the
                // in-process add_scripts/remove_scripts history.
                let scripts = truth.snapshot().into_iter().map(|s| (s, None));
                builder.add_scripts(scripts);
                Ok(())
            }
        });

    let mut watch = client.resilient_watch(config);

    // Drive the stream; new addresses (e.g. from a wallet's own key-derivation
    // flow) are added to the truth and picked up via reload() rather than a
    // live add_scripts, so a later reconnect's loader agrees with this call.
    let mut inserted_second = false;
    loop {
        match watch.next().await? {
            Event::ScriptMatched { txid, is_output, confirmed, .. } => {
                println!(
                    "watch hit tx={} {} ({})",
                    hex(&txid),
                    if is_output { "funding" } else { "spending" },
                    if confirmed { "confirmed" } else { "mempool" },
                );
                if !inserted_second {
                    inserted_second = true;
                    truth.insert([0x22; 32]);
                    let summary = watch.reload().await?;
                    println!(
                        "reload: +{} -{} ={} applied={}",
                        summary.added, summary.removed, summary.unchanged, summary.applied
                    );
                }
            }
            Event::CursorRejected { reason, .. } => {
                // A terminal reject (e.g. NoSource): the persisted cursor is
                // stale for this node's retention window. A real integrator
                // would clear the store and resnapshot from scratch here.
                eprintln!("re-anchor rejected: {reason:?}");
            }
            _ => {}
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
