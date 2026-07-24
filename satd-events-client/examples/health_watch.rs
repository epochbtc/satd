//! Watch a node's own health and react to it — the shape of a real alerting
//! integration, in about fifty lines.
//!
//! ```sh
//! cargo run -p satd-events-client --example health_watch -- http://127.0.0.1:50051 [token]
//! ```
//!
//! Three things worth copying from this example:
//!
//! 1. **Ask for the category explicitly.** `Categories::STATUS` is not part of
//!    the `0` ("all") default, so a client that does not request it receives
//!    nothing — which is the point: an older client never starts receiving a
//!    body it cannot parse after the node is upgraded.
//! 2. **Track raise/clear pairs, don't count events.** A standing condition
//!    fires once when entered and once when it recovers. Holding the active set
//!    (as below) gives you "what is wrong right now" for free; counting alerts
//!    gives you a number that only ever grows.
//! 3. **Tolerate unknown kinds.** New conditions ship additively, so a kind this
//!    build predates arrives as `StatusKind::Unknown`. Its `severity` and
//!    `message` are still meaningful — handle it generically rather than
//!    treating it as an error.
//!
//! Note that status events are **not replayable**: connecting after a condition
//! was raised will not re-deliver it. The node re-raises standing conditions
//! when it restarts, and `getwarnings` over JSON-RPC answers "what is wrong
//! right now" at any moment — use that to seed state on connect if you need a
//! complete picture immediately.

use std::collections::BTreeSet;

use satd_events_client::{
    Categories, Event, StatusKind, StatusSeverity, StatusState, StreamClient, SubscribeOptions,
};

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
            // HEARTBEAT as well as STATUS, deliberately.
            //
            // Unknown category bits are ignored by design, so `STATUS` alone
            // against a pre-0.5.0 node is accepted and then matches nothing —
            // an open connection that stays silent forever, indistinguishable
            // from a healthy node. That is failing open in the one direction
            // alerting must not. Subscribing to heartbeats too means silence is
            // itself a signal: if the pings stop, either the node or the
            // connection is gone.
            categories: Categories::STATUS | Categories::HEARTBEAT,
            ..Default::default()
        })
        .await?;

    println!("watching node health (heartbeats confirm the stream is live)");

    // The set of conditions currently standing. This — not a count of events —
    // is what an operator actually wants to know.
    let mut active: BTreeSet<String> = BTreeSet::new();

    while let Some(event) = events.message().await? {
        // Heartbeats are the liveness half of this subscription: a node that
        // has gone quiet looks exactly like a healthy one unless something is
        // expected to keep arriving. Everything else (a lag notice, a body this
        // build does not know) is ignored — tolerating what you did not ask for
        // is the forward-compatible default.
        if matches!(event, Event::Heartbeat { .. }) {
            continue;
        }
        let Event::Status {
            kind,
            state,
            severity,
            message,
            details,
        } = event
        else {
            continue;
        };

        let name = kind_name(kind);
        match state {
            StatusState::Raised => {
                active.insert(name.clone());
            }
            StatusState::Cleared => {
                active.remove(&name);
            }
            // A one-shot observation: it happened, there is nothing to clear.
            StatusState::Edge | StatusState::Unknown(_) => {}
        }

        // Route by severity rather than by kind, so a condition this build does
        // not recognize still reaches the right place.
        let route = match severity {
            StatusSeverity::Info => "info",
            StatusSeverity::Warning => "warn",
            // An unrecognized severity sorts above Critical deliberately: a
            // condition we cannot name is not one to quietly downgrade.
            StatusSeverity::Critical | StatusSeverity::Unknown(_) => "PAGE",
        };

        let detail = details
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("[{route}] {name} {state:?}: {message}  {detail}");

        if active.is_empty() {
            println!("       → all clear");
        } else {
            println!("       → standing: {}", active.iter().cloned().collect::<Vec<_>>().join(", "));
        }
    }
    Ok(())
}

fn kind_name(kind: StatusKind) -> String {
    match kind {
        StatusKind::IbdComplete => "ibd_complete".into(),
        StatusKind::TipStall => "tip_stall".into(),
        StatusKind::DiskLow => "disk_low".into(),
        StatusKind::MempoolCongested => "mempool_congested".into(),
        StatusKind::PeerFloor => "peer_floor".into(),
        StatusKind::DeepReorg => "deep_reorg".into(),
        // A newer node reporting a condition this build predates.
        StatusKind::Unknown(v) => format!("unknown({v})"),
    }
}
