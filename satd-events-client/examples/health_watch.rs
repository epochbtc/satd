//! Watch a node's own health and react to it — the shape of a real alerting
//! integration.
//!
//! ```sh
//! cargo run -p satd-events-client --example health_watch -- http://127.0.0.1:50051 [token]
//! ```
//!
//! Five things worth copying:
//!
//! 1. **Ask for the category explicitly.** `Categories::STATUS` is not part of
//!    the `0` ("all") default, so a client that does not request it receives
//!    nothing — which is the point: an older client never starts receiving a
//!    body it cannot parse after the node is upgraded. Note the node also
//!    requires the token to hold `rpc:read` for this category, since the bodies
//!    carry host telemetry that capability gates elsewhere.
//! 2. **Reconnect.** This uses `resilient_subscribe`, not `subscribe`. A plain
//!    subscription surfaces any transient stream error to the caller, and the
//!    obvious `?` on it ends the process — precisely when the node restarting is
//!    what produced the error, which is also when it re-raises every standing
//!    condition. An unsupervised copy of that shape is silently off from its
//!    first blip onward.
//! 3. **Put a deadline on silence.** Heartbeats are subscribed *and enforced*
//!    with a timeout. Subscribing to them and then ignoring them proves nothing:
//!    if the node process is alive but its publisher is wedged, gRPC keepalive
//!    still answers, `next()` blocks forever, and "no output" reads as "nothing
//!    is wrong".
//! 4. **Track raise/clear pairs, don't count events.** A standing condition
//!    fires once when entered and once when it recovers. Holding the active set
//!    gives you "what is wrong right now"; counting alerts gives you a number
//!    that only ever grows.
//! 5. **Tolerate unknown kinds.** New conditions ship additively, so a kind this
//!    build predates arrives as `StatusKind::Unknown` — and the enums are
//!    `#[non_exhaustive]`, so the compiler makes you handle that. `severity` and
//!    `message` stay meaningful.
//!
//! # What this client cannot know
//!
//! Status events are **not replayable**. There is no cursor for them, so a
//! client that connects after a condition was raised never learns about it, and
//! `ResilientSubscription` hides reconnects — meaning a drop during which
//! `tip_stall` raised and `disk_low` cleared leaves the set below silently
//! wrong, with no synthetic notice to key off (`ReplayGap` is cursor-anchored,
//! and status carries no cursor).
//!
//! So the set below is honestly labelled: it is what *this connection has
//! observed*, not the node's true state. **`getwarnings` over JSON-RPC is the
//! authoritative answer** to "what is wrong right now". A production integration
//! should poll it on a slow timer (say once a minute) and treat this stream as
//! the low-latency edge signal on top — which is also what makes a missed
//! transition self-correcting rather than permanent. This example prints the
//! observed set rather than pretending to be complete; it does not poll, because
//! that would need an RPC client and this file is about the stream.

use std::collections::BTreeSet;
use std::time::Duration;

use satd_events_client::{
    Categories, Event, ResilientConfig, StatusKind, StatusSeverity, StatusState, StreamClient,
    SubscribeOptions,
};

/// How long the stream may stay silent before we treat it as broken.
///
/// The node's heartbeat interval is well under this, so several missed pings in
/// a row are needed to trip it — a deadline tight enough to catch a wedged
/// publisher, loose enough not to fire on ordinary scheduling jitter.
const SILENCE_DEADLINE: Duration = Duration::from_secs(90);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "http://127.0.0.1:50051".into());

    let mut builder = StreamClient::builder(endpoint).keepalive_default();
    if let Some(token) = args.next() {
        builder = builder.bearer_token(token);
    }
    let client = builder.connect().await?;

    let mut events = client.resilient_subscribe(
        SubscribeOptions {
            // HEARTBEAT as well as STATUS, deliberately.
            //
            // Unknown category bits are ignored by design, so `STATUS` alone
            // against a pre-0.5.0 node is accepted and then matches nothing —
            // an open connection that stays silent forever, indistinguishable
            // from a healthy node. That is failing open in the one direction
            // alerting must not. Subscribing to heartbeats makes silence a
            // signal, and the deadline below is what actually reads it.
            categories: Categories::STATUS | Categories::HEARTBEAT,
            ..Default::default()
        },
        ResilientConfig::default(),
    );

    println!("watching node health (heartbeats confirm the stream is live)");

    // Conditions this connection has seen raised and not yet seen cleared.
    // Deliberately NOT called "the node's active conditions" — see the module
    // docs: without replay, this can only ever be a partial view.
    let mut observed: BTreeSet<String> = BTreeSet::new();

    loop {
        let event = match tokio::time::timeout(SILENCE_DEADLINE, events.next()).await {
            Ok(Ok(ev)) => ev,
            // The stream itself failed in a way even the resilient layer would
            // not retry. Surface it; do not treat it as end-of-stream.
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // No event of any kind — not even a heartbeat — for the whole
                // window. Something between the node's publisher and this
                // process is stuck. Exiting non-zero is the honest move for an
                // example: a supervisor restarts it, and a monitored process
                // that dies is far louder than one that sits quiet.
                eprintln!(
                    "no events for {}s — the stream is silent, which is not the \
                     same as the node being healthy",
                    SILENCE_DEADLINE.as_secs()
                );
                std::process::exit(1);
            }
        };

        // Everything not a status body (heartbeats, a lag notice, a body this
        // build does not know) is ignored — tolerating what you did not ask for
        // is the forward-compatible default. The heartbeat's job is done by
        // arriving at all.
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
                observed.insert(name.clone());
            }
            StatusState::Cleared => {
                observed.remove(&name);
            }
            // A one-shot observation: it happened, there is nothing to clear.
            StatusState::Edge => {}
            // The producer did not set a state. This is the dangerous one to
            // swallow: if the event that arrived unset was a *clear*, dropping
            // it silently leaves the condition standing in `observed` for the
            // life of the process, long after it recovered. We cannot infer
            // which it was, so say so loudly and let the operator reconcile
            // against `getwarnings` rather than trusting the set below.
            StatusState::Unspecified => {
                eprintln!(
                    "  !! {name} arrived with no state — cannot tell raise from clear; \
                     the standing set below may now be wrong"
                );
            }
            // The enum is non-exhaustive, so a state this build predates lands
            // here. Do not guess at its lifecycle — report it and move on.
            _ => {}
        }

        // Route by severity rather than by kind, so a condition this build does
        // not recognize still reaches the right place.
        let route = match severity {
            // The producer never set a severity. Log it — the kind and message
            // are still meaningful — but do not page: an absent field is not a
            // critical condition, and treating it as one pages on every partial
            // or buggy producer.
            StatusSeverity::Unspecified => "info",
            StatusSeverity::Info => "info",
            StatusSeverity::Warning => "warn",
            StatusSeverity::Critical => "PAGE",
            // An unrecognized severity pages deliberately: a condition we cannot
            // name is not one to quietly downgrade.
            _ => "PAGE",
        };

        let detail = details
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("[{route}] {name} {state:?}: {message}  {detail}");

        if observed.is_empty() {
            // NOT "all clear": this client may simply never have been told.
            // `getwarnings` is the surface that can answer that.
            println!("       → nothing standing that this client has observed");
        } else {
            println!(
                "       → standing (observed): {}",
                observed.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
}

fn kind_name(kind: StatusKind) -> String {
    match kind {
        // Distinct from `Unknown`: the field was never set, rather than set to
        // something this build predates. Worth telling apart when you are
        // deciding whether to upgrade the client or go fix the producer.
        StatusKind::Unspecified => "unspecified".into(),
        StatusKind::IbdComplete => "ibd_complete".into(),
        StatusKind::TipStall => "tip_stall".into(),
        StatusKind::DiskLow => "disk_low".into(),
        StatusKind::MempoolCongested => "mempool_congested".into(),
        StatusKind::PeerFloor => "peer_floor".into(),
        StatusKind::DeepReorg => "deep_reorg".into(),
        // A newer node reporting a condition this build predates. The enum is
        // non-exhaustive, so this arm also absorbs variants added later.
        StatusKind::Unknown(v) => format!("unknown({v})"),
        _ => "unknown".into(),
    }
}
