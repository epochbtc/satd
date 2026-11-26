//! The network survey's probes against a live Bitcoin Core (#1353).
//!
//! A probe joins the set the survey sends only if Core neither raises a
//! misbehaviour against the sender nor drops the connection over it. Each
//! probe here is the exact message the survey builds
//! (`node::net::survey::probe_message`), sent over v1 and over v2 on a
//! connection of its own to a regtest `bitcoind` that does not whitelist the
//! harness, so any punishment would show. After each, a `ping` round trip
//! proves Core handled it, and Core must still list the connection, have
//! logged no `Misbehaving` or disconnect line for it, and have banned
//! nothing.
//!
//! The oracle is `$BITCOIND` if set (the Core version pinned by CORE_IMAGE
//! in scripts/canary/PINS, v32.1), else the `bitcoind` copied out of that
//! image with Docker:
//!
//! ```text
//! cargo test -p satd --test core_survey_probes --features core-p2p-differential
//! ```

#[path = "../../fuzz/src/p2p_diff.rs"]
mod p2p_diff;

use node::net::survey::{Probe, ProbeContext, probe_message};
use p2p_diff::{CoreOracle, ProbeVerdict};
use rand::SeedableRng as _;

fn context(oracle: &CoreOracle, wtxid_relay: bool) -> ProbeContext {
    let (genesis, first) = oracle.first_blocks().expect("Core's first blocks");
    let mut rng = rand::rngs::StdRng::seed_from_u64(1353);
    ProbeContext::new(&mut rng, genesis, first, wtxid_relay)
}

/// Send one probe over v1 and over v2 and hold Core to no punishment.
/// Returns the verdicts, v1 first.
fn unpunished(oracle: &mut CoreOracle, probe: Probe, ctx: &ProbeContext) -> [ProbeVerdict; 2] {
    [false, true].map(|v2| {
        let msg = probe_message(probe, ctx);
        let verdict = oracle
            .probe(v2, msg)
            .unwrap_or_else(|e| panic!("{} over v{}: {e}", probe.name(), 1 + u8::from(v2)));
        let transport = if v2 { "v2" } else { "v1" };
        assert!(
            verdict.still_connected,
            "{} over {transport}: Core dropped the connection: {:#?}",
            probe.name(),
            verdict.log
        );
        assert!(
            verdict.punishment().is_empty(),
            "{} over {transport}: Core punished it: {:#?}",
            probe.name(),
            verdict.punishment()
        );
        assert_eq!(
            verdict.banned,
            0,
            "{} over {transport}: Core banned something",
            probe.name()
        );
        verdict
    })
}

/// Every probe the survey sends, against one `bitcoind` (one at a time:
/// the harness starts one oracle per process). Each must be handled
/// without a misbehaviour or a disconnect, with the answer the survey
/// records; then the harness must see a disconnect where Core gives one.
#[test]
fn every_probe_is_handled_by_core_without_punishment() {
    let mut oracle = CoreOracle::start_without_whitelist().expect("start Bitcoin Core");

    // ping: its own pong comes back.
    let ctx = context(&oracle, true);
    for v in unpunished(&mut oracle, Probe::Ping, &ctx) {
        assert!(
            v.replies.iter().any(|r| r == "pong"),
            "ping: the probe's own pong: {:?}",
            v.replies
        );
    }

    // getheaders with a one-hash locator: answered, from the block after it.
    for v in unpunished(&mut oracle, Probe::GetHeaders, &ctx) {
        assert!(
            v.replies.iter().any(|r| r == "headers"),
            "getheaders: {:?}",
            v.replies
        );
        let line = format!("getheaders 1 to {} from peer={}", ctx.stop, v.core_id);
        assert!(
            v.log.iter().any(|l| l.contains(&line)),
            "getheaders: {:#?}",
            v.log
        );
    }

    // getdata for a transaction nobody has, by wtxid and by txid: notfound.
    for wtxid_relay in [true, false] {
        let ctx = context(&oracle, wtxid_relay);
        for v in unpunished(&mut oracle, Probe::GetData, &ctx) {
            assert!(
                v.replies.iter().any(|r| r == "notfound"),
                "getdata by wtxid {wtxid_relay}: {:?}",
                v.replies
            );
        }
    }

    // An unknown message type: read, logged and ignored.
    let command: &str = ctx.unknown_command.as_ref();
    for v in unpunished(&mut oracle, Probe::Unknown, &ctx) {
        let line = format!("Unknown message type \"{command}\" from peer={}", v.core_id);
        assert!(
            v.log.iter().any(|l| l.contains(&line)),
            "unknown: Core read and ignored it: {:#?}",
            v.log
        );
    }

    // The harness can see a punishment: a `getheaders` locator over Core's
    // `MAX_LOCATOR_SZ` (101) costs the connection. Without this, a harness
    // that never noticed a disconnect would pass every probe above.
    let msg = bitcoin::p2p::message::NetworkMessage::GetHeaders(
        bitcoin::p2p::message_blockdata::GetHeadersMessage::new(vec![ctx.locator; 102], ctx.stop),
    );
    if let Ok(v) = oracle.probe(false, msg) {
        assert!(
            !v.still_connected || !v.punishment().is_empty(),
            "an oversized locator went unpunished: {v:#?}"
        );
    } // Err: the pong never came, as Core closed the connection.
}
