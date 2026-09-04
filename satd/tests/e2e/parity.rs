//! Differential parity harness: the Rust SDK and the Go SDK, driven through the
//! same watch spec against the same live node, must produce the same events.
//!
//! "The Go SDK is at parity with the Rust SDK" is otherwise a claim nobody
//! checks. This test makes it falsifiable. One node boots; two clients connect —
//! `satd-events-client` in-process here, and `clients/go/cmd/paritydump` as a
//! subprocess — register byte-identical watch specs, and write every event they
//! receive as canonical JSON lines. A scenario then drives the node through
//! mempool admission, a confirmation, and four blocks. At the end the two dumps
//! are sorted by content and diffed line by line.
//!
//! SCOPE, stated plainly so nobody reads more into a green run than is there.
//! Four scenarios are compared today:
//!
//!   S1  funding + spend match, mempool then confirmed  (mempool_enter,
//!       script_matched, outpoint_spent, mempool_leave_confirmed)
//!   S2  reorg via invalidateblock                      (reorg,
//!       block_disconnected)
//!   S3  tx lifecycle + depth alarms                    (txid_depth_reached,
//!       txid_finalized)
//!   S5  prefix watch, decoys included                  (prefix_matched)
//!
//! Still NOT differentially compared: replacement (txid_replaced), rescan
//! output, silent-payment matches, descriptor attribution, and the cursor
//! control acks. Those render arms are compiled and unit-tested on both sides
//! but no scenario drives them here. Adding a scenario is the way to widen the
//! guarantee - each is a `parity_begin` -> drive -> `finish` triple, and the
//! non-vacuity floor passed to `finish` is what stops a broken one going green.
//!
//! Any divergence fails: a variant one SDK cannot decode, a field typed
//! differently, an off-by-one height, an enum mapped to the wrong constant.
//!
//! The canonical form is defined in `canonical` below and mirrored exactly by
//! `clients/go/cmd/paritydump/render.go`. Read the two together — they are one
//! contract implemented twice, which is the only way a differential test can
//! mean anything.
//!
//! Folded into the `e2e` target via `mod parity;` in `tests/e2e.rs`, so the
//! shared harness is reached through `crate::common`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use satd_events_client::{Cursor, Event, StreamClient};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::common::{
    script_prefix_hex,
    build_signed_p2wpkh_spend_seq, block1_coinbase_txid, display_to_internal_hex,
    e2e_test_timeout, DeterministicWallet, StreamingNode,
};

// ---- the shared watch spec --------------------------------------------------

/// The watch spec both dumpers read.
///
/// Serialized once and handed to both sides, so the two clients cannot differ in
/// what they asked for — only in what they made of the answer. Field names and
/// types mirror `clients/go/cmd/paritydump/spec.go` exactly; the Go reader is
/// configured to reject unknown fields, so a field added here without adding it
/// there fails loudly rather than silently narrowing the Go watch set.
#[derive(Default, Serialize, Deserialize)]
struct Spec {
    categories: u32,
    include_raw_tx: bool,
    scripts: Vec<SpecScript>,
    outpoints: Vec<SpecOutpoint>,
    lifecycles: Vec<SpecLifecycle>,
    depth_alarms: Vec<SpecDepth>,
    descriptors: Vec<SpecDesc>,
    prefixes: Vec<SpecPrefix>,
    silent_payments: Vec<SpecSp>,
}

#[derive(Serialize, Deserialize)]
struct SpecScript {
    scripthash: String,
    min_value: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct SpecOutpoint {
    txid: String,
    vout: u32,
}

#[derive(Serialize, Deserialize)]
struct SpecLifecycle {
    txid: String,
    /// Auto-close depth: 0 never closes, N closes at N confirmations. Carried
    /// as a depth because that is the one shape both SDKs can express - Go
    /// models `AutoClose` as a `uint32` depth, Rust as `Never | AtDepth(u32)`.
    auto_close_depth: u32,
}

#[derive(Serialize, Deserialize)]
struct SpecDepth {
    txid: String,
    depth: u32,
}

#[derive(Serialize, Deserialize)]
struct SpecDesc {
    descriptor: String,
    gap_limit: u32,
    start: u32,
}

#[derive(Serialize, Deserialize)]
struct SpecPrefix {
    prefix: String,
    bits: u32,
}

#[derive(Serialize, Deserialize)]
struct SpecSp {
    scan_secret: String,
    spend_pubkey: String,
    labels: Vec<u32>,
}

impl Spec {
    /// Register the whole spec on a live watch handle, in the same order as the
    /// Go dumper's `apply` — the node acks each control separately, so a
    /// different order would sequence the acks differently.
    async fn apply(&self, h: &satd_events_client::WatchHandle) {
        if self.categories != 0 {
            h.set_categories(self.categories).await.expect("set_categories");
        }
        if self.include_raw_tx {
            h.set_watch_options(true).await.expect("set_watch_options");
        }
        if !self.scripts.is_empty() {
            let items: Vec<_> = self
                .scripts
                .iter()
                .map(|s| (hash32(&s.scripthash), s.min_value))
                .collect();
            h.add_scripts(items).await.expect("add_scripts");
        }
        if !self.outpoints.is_empty() {
            let items: Vec<_> =
                self.outpoints.iter().map(|o| (hash32(&o.txid), o.vout)).collect();
            h.add_outpoints(items).await.expect("add_outpoints");
        }

        let mut by_policy: Vec<(u32, Vec<[u8; 32]>)> = Vec::new();
        for lc in &self.lifecycles {
            let txid = hash32(&lc.txid);
            match by_policy.iter_mut().find(|(p, _)| *p == lc.auto_close_depth) {
                Some((_, v)) => v.push(txid),
                None => by_policy.push((lc.auto_close_depth, vec![txid])),
            }
        }
        for (policy, txids) in by_policy {
            h.add_tx_lifecycle(txids, auto_close_from_depth(policy))
                .await
                .expect("add_tx_lifecycle");
        }

        if !self.depth_alarms.is_empty() {
            let txids: Vec<[u8; 32]> =
                self.depth_alarms.iter().map(|d| hash32(&d.txid)).collect();
            let depths: Vec<u32> = self.depth_alarms.iter().map(|d| d.depth).collect();
            h.add_depth_alarms(txids, depths).await.expect("add_depth_alarms");
        }
        for d in &self.descriptors {
            h.add_descriptor(&d.descriptor, d.gap_limit, d.start)
                .await
                .expect("add_descriptor");
        }
        if !self.prefixes.is_empty() {
            let items: Vec<(Vec<u8>, u32)> = self
                .prefixes
                .iter()
                .map(|p| (hex_bytes(&p.prefix), p.bits))
                .collect();
            h.add_script_prefixes(items).await.expect("add_script_prefixes");
        }
        if !self.silent_payments.is_empty() {
            let items: Vec<_> = self
                .silent_payments
                .iter()
                .map(|sp| satd_events_client::SilentPaymentTarget {
                    scan_secret: hash32(&sp.scan_secret),
                    spend_pubkey: hash33(&sp.spend_pubkey),
                    labels: sp.labels.clone(),
                })
                .collect();
            h.add_silent_payments(items).await.expect("add_silent_payments");
        }
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hash32(s: &str) -> [u8; 32] {
    let v = hex_bytes(s);
    assert_eq!(v.len(), 32, "want 32 bytes, got {}", v.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hash33(s: &str) -> [u8; 33] {
    let v = hex_bytes(s);
    assert_eq!(v.len(), 33, "want 33 bytes, got {}", v.len());
    let mut out = [0u8; 33];
    out.copy_from_slice(&v);
    out
}

fn auto_close_from_depth(depth: u32) -> satd_events_client::AutoClose {
    use satd_events_client::AutoClose;
    if depth == 0 { AutoClose::Never } else { AutoClose::AtDepth(depth) }
}

// ---- canonical rendering ----------------------------------------------------

/// Canonical rendering, mirroring `clients/go/cmd/paritydump/render.go`.
///
/// `serde_json::Map` is a `BTreeMap` by default, so keys sort — matching Go's
/// `encoding/json`, which sorts map keys. Neither side may use a struct, whose
/// field order is declaration order.
mod canonical {
    use super::*;

    pub fn render(ev: &Event) -> Value {
        match ev {
            // `time` is the node's wall clock at admission: identical in both
            // dumps only by luck. Dropped.
            Event::MempoolEnter { txid, fee, vsize, fee_rate_sat_per_kvb, .. } => obj(
                "mempool_enter",
                [
                    ("txid", json!(hexs(txid))),
                    ("fee", json!(fee)),
                    ("vsize", json!(vsize)),
                    ("fee_rate_sat_per_kvb", json!(fee_rate_sat_per_kvb)),
                ],
            ),
            Event::MempoolLeaveConfirmed { txid, block_hash, height } => obj(
                "mempool_leave_confirmed",
                [
                    ("txid", json!(hexs(txid))),
                    ("block_hash", json!(hexs(block_hash))),
                    ("height", json!(height)),
                ],
            ),
            Event::MempoolLeaveEvicted { txid, reason } => obj(
                "mempool_leave_evicted",
                [("txid", json!(hexs(txid))), ("reason", json!(evict_name(*reason)))],
            ),
            Event::MempoolLeaveReplaced { txid, replacing_txid } => obj(
                "mempool_leave_replaced",
                [
                    ("txid", json!(hexs(txid))),
                    ("replacing_txid", json!(hexs(replacing_txid))),
                ],
            ),

            Event::BlockConnected { hash, height } => obj(
                "block_connected",
                [("hash", json!(hexs(hash))), ("height", json!(height))],
            ),
            Event::BlockDisconnected { hash, height } => obj(
                "block_disconnected",
                [("hash", json!(hexs(hash))), ("height", json!(height))],
            ),
            Event::Reorg { from_height, old_tip, to_height, new_tip } => obj(
                "reorg",
                [
                    ("from_height", json!(from_height)),
                    ("old_tip", json!(hexs(old_tip))),
                    ("to_height", json!(to_height)),
                    ("new_tip", json!(hexs(new_tip))),
                ],
            ),
            // Timer-driven; filtered before the diff. uptime_ns dropped for the
            // same reason as `time`.
            Event::Heartbeat { .. } => obj("heartbeat", []),
            Event::Status { kind, state, severity, message, details } => obj(
                "status",
                [
                    ("kind", json!(status_kind_name(*kind))),
                    ("state", json!(status_state_name(*state))),
                    ("severity", json!(status_severity_name(*severity))),
                    ("message", json!(message)),
                    ("details", json!(details.iter().collect::<BTreeMap<_, _>>())),
                ],
            ),

            Event::OutpointSpent { outpoint, spending_txid, spending_vin, confirmed } => obj(
                "outpoint_spent",
                [
                    ("outpoint", outpoint_val(&outpoint.txid, outpoint.vout)),
                    ("spending_txid", json!(hexs(spending_txid))),
                    ("spending_vin", json!(spending_vin)),
                    ("confirmed", json!(confirmed)),
                ],
            ),
            Event::ScriptMatched {
                scripthash,
                txid,
                is_output,
                index,
                confirmed,
                amount,
                raw_tx,
                descriptors,
            } => obj(
                "script_matched",
                [
                    ("scripthash", json!(hexs(scripthash))),
                    ("txid", json!(hexs(txid))),
                    ("is_output", json!(is_output)),
                    ("index", json!(index)),
                    ("confirmed", json!(confirmed)),
                    ("amount", json!(amount)),
                    ("raw_tx", json!(hexs(raw_tx.as_deref().unwrap_or(&[])))),
                    (
                        "descriptors",
                        Value::Array(
                            descriptors
                                .iter()
                                .map(|d| {
                                    map([
                                        ("descriptor", json!(d.descriptor)),
                                        ("branch", json!(d.branch)),
                                        ("derivation_index", json!(d.derivation_index)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Event::TxidMatched { txid, confirmed, height } => obj(
                "txid_matched",
                [
                    ("txid", json!(hexs(txid))),
                    ("confirmed", json!(confirmed)),
                    ("height", json!(height)),
                ],
            ),
            Event::TxidReplaced { txid, replacing_txid } => obj(
                "txid_replaced",
                [
                    ("txid", json!(hexs(txid))),
                    ("replacing_txid", json!(hexs(replacing_txid))),
                ],
            ),
            Event::TxidEvicted { txid, reason } => obj(
                "txid_evicted",
                [("txid", json!(hexs(txid))), ("reason", json!(reason))],
            ),
            Event::TxidUnconfirmed { txid, prev_height } => obj(
                "txid_unconfirmed",
                [("txid", json!(hexs(txid))), ("prev_height", json!(prev_height))],
            ),
            Event::TxidDepthReached { txid, depth, height } => obj(
                "txid_depth_reached",
                [
                    ("txid", json!(hexs(txid))),
                    ("depth", json!(depth)),
                    ("height", json!(height)),
                ],
            ),
            Event::TxidFinalized { txid, depth, height } => obj(
                "txid_finalized",
                [
                    ("txid", json!(hexs(txid))),
                    ("depth", json!(depth)),
                    ("height", json!(height)),
                ],
            ),

            Event::PrefixMatched(m) => obj(
                "prefix_matched",
                [
                    (
                        "prefix",
                        map([
                            ("prefix", json!(hexs(&m.prefix.prefix))),
                            ("bits", json!(m.prefix.bits)),
                        ]),
                    ),
                    ("raw_tx", json!(hexs(&m.raw_tx))),
                    ("confirmed", json!(m.confirmed)),
                    ("height", json!(m.height)),
                    (
                        "matched_prevouts",
                        Value::Array(
                            m.matched_prevouts
                                .iter()
                                .map(|p| {
                                    map([
                                        (
                                            "outpoint",
                                            outpoint_val(&p.outpoint.txid, p.outpoint.vout),
                                        ),
                                        ("script_pubkey", json!(hexs(&p.script_pubkey))),
                                        ("amount", json!(p.amount)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ],
            ),
            Event::SilentPaymentMatched {
                scan_pubkey,
                txid,
                vout,
                output_pubkey,
                amount,
                tweak,
                k,
                label,
                confirmed,
                height,
                raw_tx,
            } => obj(
                "silent_payment_matched",
                [
                    ("scan_pubkey", json!(hexs(scan_pubkey))),
                    ("txid", json!(hexs(txid))),
                    ("vout", json!(vout)),
                    ("output_pubkey", json!(hexs(output_pubkey))),
                    ("amount", json!(amount)),
                    ("tweak", json!(hexs(tweak))),
                    ("k", json!(k)),
                    ("label", json!(label)),
                    ("confirmed", json!(confirmed)),
                    ("height", json!(height)),
                    ("raw_tx", json!(hexs(raw_tx.as_deref().unwrap_or(&[])))),
                ],
            ),
            Event::BlockTweaks { block_hash, height, entries, filtered } => obj(
                "block_tweaks",
                [
                    ("block_hash", json!(hexs(block_hash))),
                    ("height", json!(height)),
                    (
                        "entries",
                        Value::Array(entries.iter().map(tweak_entry).collect()),
                    ),
                    ("filtered", json!(filtered)),
                ],
            ),
            Event::MempoolTweak { entry } => obj("mempool_tweak", [("entry", tweak_entry(entry))]),

            Event::Lagged { dropped_count, resume_cursor } => obj(
                "lagged",
                [
                    ("dropped_count", json!(dropped_count)),
                    ("resume_cursor", cursor_val(resume_cursor.as_ref())),
                ],
            ),
            Event::ReplayGap { resume_height, first_height } => obj(
                "replay_gap",
                [
                    ("resume_height", json!(resume_height)),
                    ("first_height", json!(first_height)),
                ],
            ),
            Event::CursorAccepted { from, clamped, earliest_replayed } => obj(
                "cursor_accepted",
                [
                    ("from", cursor_val(from.as_ref())),
                    ("clamped", json!(clamped)),
                    ("earliest_replayed", json!(earliest_replayed)),
                ],
            ),
            Event::CursorRejected { reason, current_head } => obj(
                "cursor_rejected",
                [
                    ("reason", json!(cursor_reject_name(*reason))),
                    ("current_head", cursor_val(current_head.as_ref())),
                ],
            ),
            Event::WatchSetReplaced { added, removed, unchanged } => obj(
                "watch_set_replaced",
                [
                    ("added", json!(added)),
                    ("removed", json!(removed)),
                    ("unchanged", json!(unchanged)),
                ],
            ),
            Event::WatchSetRejected { reason, required, quota } => obj(
                "watch_set_rejected",
                [
                    ("reason", json!(watch_set_reject_name(*reason))),
                    ("required", json!(required)),
                    ("quota", json!(quota)),
                ],
            ),
            Event::RescanAccepted { from_height, to_height, clamped } => obj(
                "rescan_accepted",
                [
                    ("from_height", json!(from_height)),
                    ("to_height", json!(to_height)),
                    ("clamped", json!(clamped)),
                ],
            ),
            Event::RescanRejected { reason, tip_height } => obj(
                "rescan_rejected",
                [
                    ("reason", json!(rescan_reject_name(*reason))),
                    ("tip_height", json!(tip_height)),
                ],
            ),
            Event::RescanComplete { from_height, to_height, matches } => obj(
                "rescan_complete",
                [
                    ("from_height", json!(from_height)),
                    ("to_height", json!(to_height)),
                    ("matches", json!(matches)),
                ],
            ),
            // A variant an SDK cannot decode is itself parity-relevant: one side
            // decoding and the other filing it here is the missing-variant case.
            Event::Unknown => obj("unknown", []),
            // `Event` is #[non_exhaustive]. A variant added to the SDK without a
            // rendering here would otherwise diff as silence against whatever Go
            // renders - so name it loudly instead.
            other => obj("UNRENDERED", [("debug", json!(format!("{other:?}")))]),
        }
    }

    fn tweak_entry(e: &satd_events_client::TweakEntry) -> Value {
        map([
            ("tweak", json!(hexs(&e.tweak))),
            ("txid", json!(hexs(&e.txid))),
            ("max_value", json!(e.max_value)),
            (
                "taproot_outputs",
                Value::Array(
                    e.taproot_outputs
                        .iter()
                        .map(|t| {
                            map([
                                ("vout", json!(t.vout)),
                                ("output_pubkey", json!(hexs(&t.output_pubkey))),
                                ("value", json!(t.value)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    fn outpoint_val(txid: &[u8], vout: u32) -> Value {
        map([("txid", json!(hexs(txid))), ("vout", json!(vout))])
    }

    /// `instance_id` is deliberately absent: it is the publisher's incarnation
    /// id, changes on every node restart, and differs between two clients only
    /// if one reconnected across one. No parity signal, plenty of noise.
    fn cursor_val(c: Option<&Cursor>) -> Value {
        match c {
            None => Value::Null,
            Some(c) => map([
                ("height", json!(c.height)),
                ("tx_index", json!(c.tx_index)),
                ("mempool_seq", json!(c.mempool_seq)),
            ]),
        }
    }

    fn map<const N: usize>(fields: [(&str, Value); N]) -> Value {
        let mut m = Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), v);
        }
        Value::Object(m)
    }

    fn obj<const N: usize>(kind: &str, fields: [(&str, Value); N]) -> Value {
        let mut m = Map::new();
        for (k, v) in fields {
            m.insert(k.to_string(), v);
        }
        m.insert("type".to_string(), json!(kind));
        Value::Object(m)
    }

    pub fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

use canonical::render;

// Enum spellings come from the generated proto descriptor on both sides —
// prost's `as_str_name` here, Go's `<Enum>_name` table there — so neither
// dumper hand-writes a string that could drift from the other's.
//
// The Rust SDK's enums are nominal (with an `Unknown` arm), so getting to the
// descriptor needs an explicit variant-to-variant map. That map is the inverse
// of the SDK's own decode, which is the point: if the SDK decoded a wire value
// to the wrong constant, the name rendered here differs from the one Go's
// generated table produces for the value ITS SDK decoded, and the diff fires.
use satd_events_proto::v1 as pb;

macro_rules! enum_namer {
    ($fn_name:ident, $sdk:path, $pb:path, { $($variant:ident => $pb_variant:ident),* $(,)? }) => {
        fn $fn_name(v: $sdk) -> String {
            use $pb as P;
            use $sdk as S;
            #[allow(unreachable_patterns)]
            match v {
                $(S::$variant => P::$pb_variant.as_str_name().to_string(),)*
                other => format!("UNKNOWN({other:?})"),
            }
        }
    };
}

enum_namer!(evict_name, satd_events_client::EvictReason, pb::EvictReason, {
    Unspecified => Unspecified,
    FullPool => FullPool,
    Expiry => Expiry,
    BlockConflict => BlockConflict,
    Policy => Policy,
});

enum_namer!(status_kind_name, satd_events_client::StatusKind, pb::StatusKind, {
    Unspecified => Unspecified,
    IbdComplete => IbdComplete,
    TipStall => TipStall,
    DiskLow => DiskLow,
    MempoolCongested => MempoolCongested,
    PeerFloor => PeerFloor,
    DeepReorg => DeepReorg,
});

enum_namer!(status_state_name, satd_events_client::StatusState, pb::StatusState, {
    Unspecified => Unspecified,
    Raised => Raised,
    Cleared => Cleared,
    Edge => Edge,
});

enum_namer!(status_severity_name, satd_events_client::StatusSeverity, pb::StatusSeverity, {
    Unspecified => Unspecified,
    Info => Info,
    Warning => Warning,
    Critical => Critical,
});

enum_namer!(
    cursor_reject_name,
    satd_events_client::CursorRejectReason,
    pb::cursor_rejected::Reason,
    {
        RateLimited => RateLimited,
        ConcurrentReanchor => ConcurrentReanchor,
        EmptyCursor => EmptyCursor,
        NoSource => NoSource,
    }
);

enum_namer!(
    watch_set_reject_name,
    satd_events_client::WatchSetRejectReason,
    pb::watch_set_rejected::Reason,
    {
        QuotaExceeded => QuotaExceeded,
        CapExceeded => CapExceeded,
        Malformed => Malformed,
    }
);

enum_namer!(
    rescan_reject_name,
    satd_events_client::RescanRejectReason,
    pb::rescan_rejected::Reason,
    {
        RateLimited => RateLimited,
        ConcurrentRescan => ConcurrentRescan,
        InvalidRange => InvalidRange,
        RangeTooLarge => RangeTooLarge,
        NoSource => NoSource,
        EmptyWatchSet => EmptyWatchSet,
    }
);

// ---- the Rust dumper --------------------------------------------------------

/// Drive the Rust SDK through `spec` and collect canonical JSON lines, stopping
/// on the same sentinel as the Go dumper.
async fn rust_dump(
    port: u16,
    spec: &Spec,
    until_height: u32,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Vec<String> {
    let mut client = StreamClient::builder(format!("http://127.0.0.1:{port}"))
        .connect()
        .await
        .expect("rust dumper connect");
    let (handle, mut stream) = client.watch().await.expect("rust dumper watch");
    spec.apply(&handle).await;

    // Same readiness barrier as the Go dumper: one deliberately invalid rescan,
    // answered with exactly one RescanRejected and no side effects. See the
    // comment there for why counting registration acks does not work.
    handle.rescan(1, 0).await.expect("readiness probe");
    let mut is_ready = false;
    let mut ready = Some(ready);
    let mut out: Vec<String> = Vec::new();

    while let Some(ev) = stream.message().await.expect("rust dumper recv") {
        if !is_ready {
            if matches!(ev, Event::RescanRejected { .. } | Event::RescanAccepted { .. }) {
                is_ready = true;
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
            }
            // Everything before the barrier is registration handshake.
            continue;
        }
        if matches!(ev, Event::Heartbeat { .. }) {
            continue;
        }

        // Sorted by rendered CONTENT, matching the Go dumper's flush. Keying on
        // the cursor was wrong: only confirmed events carry one, so every
        // mempool-side event inherited whichever block cursor arrived before it
        // on that connection, and identical events landed in different buckets
        // on the two streams. See the note on flush() in the Go dumper.
        out.push(serde_json::to_string(&render(&ev)).expect("render"));

        if let Event::BlockConnected { height, .. } = ev
            && height >= until_height
        {
            break;
        }
    }
    out.sort();
    out
}

// ---- the Go dumper ----------------------------------------------------------

/// Locate (building if needed) the Go `paritydump` binary.
///
/// CI sets `PARITYDUMP_BIN`. Locally the binary is built on demand, and if the
/// Go toolchain is absent the test skips with a reason rather than failing —
/// a missing local toolchain is not a parity finding.
fn paritydump_binary(tmp: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PARITYDUMP_BIN") {
        let p = PathBuf::from(p);
        assert!(p.exists(), "PARITYDUMP_BIN={} does not exist", p.display());
        return Some(p);
    }

    let go = which_go()?;
    let out = tmp.join("paritydump");
    let module = repo_root().join("clients/go");
    let status = std::process::Command::new(&go)
        .args(["build", "-o"])
        .arg(&out)
        .arg("./cmd/paritydump")
        .current_dir(&module)
        .status()
        .ok()?;
    assert!(status.success(), "go build ./cmd/paritydump failed");
    Some(out)
}

fn which_go() -> Option<PathBuf> {
    for cand in ["go", "/usr/local/go/bin/go"] {
        if std::process::Command::new(cand)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(PathBuf::from(cand));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".local/go/bin/go");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/satd for this crate.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

// ---- the harness --------------------------------------------------------------

const WALLET_SEED: u8 = 0x41;
/// Blocks mined to this address produce no watch match, so the sentinel block
/// that ends every run carries nothing that could race it. See `finish`.
const UNWATCHED_SEED: u8 = 0x7c;

/// What a scenario's spec is built from, pre-fetched so the builder stays
/// synchronous (every RPC here is blocking and would otherwise need its own
/// `spawn_blocking` inside each scenario).
struct SpecInputs<'a> {
    wallet: &'a DeterministicWallet,
    /// Block 1's coinbase txid in **internal** byte order — the form the watch
    /// API takes.
    coinbase_internal: &'a str,
}

/// One parity run in progress: both dumpers are connected and registered, and
/// the caller is expected to drive the node before calling [`finish`].
///
/// Split into begin/finish rather than taking a scenario closure because the
/// scenario needs `&StreamingNode` across an await, and expressing that as an
/// `AsyncFnOnce` bound buys nothing a plain struct does not.
struct ParityRun {
    sn: StreamingNode,
    wallet: DeterministicWallet,
    addr: String,
    _tmp: tempfile::TempDir,
    go_out: PathBuf,
    go_proc: KillOnDrop,
    go_stderr: std::sync::Arc<std::sync::Mutex<String>>,
    rust_task: tokio::task::JoinHandle<Vec<String>>,
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boot a node, connect both SDKs, and register `spec` on each.
///
/// `blocks` is how many blocks the scenario itself will mine, EXCLUDING the
/// sentinel [`finish`] adds. Both dumpers stop on a `block_connected` at or
/// above `tip + blocks + 1`, so the count has to be right or the run either
/// ends early or hangs to its timeout.
///
/// Returns `None` — a skip, not a failure — when there is no Go toolchain and
/// `PARITYDUMP_BIN` is unset.
async fn parity_begin(
    node_args: &[&'static str],
    build_spec: impl FnOnce(SpecInputs<'_>) -> Spec,
    blocks: u32,
) -> Option<ParityRun> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let go_bin = paritydump_binary(tmp.path())?;

    let args = node_args.to_vec();
    let sn = tokio::task::spawn_blocking(move || StreamingNode::start(&args)).await.unwrap();
    let wallet = DeterministicWallet::from_secret([WALLET_SEED; 32]);
    let addr = wallet.address.to_string();
    let rpc = sn.node.rpc_handle();
    tokio::task::spawn_blocking({
        let addr = addr.clone();
        move || rpc.mine(101, &addr)
    })
    .await
    .unwrap();

    let coinbase_display = tokio::task::spawn_blocking({
        let rpc = sn.node.rpc_handle();
        move || block1_coinbase_txid(&rpc)
    })
    .await
    .unwrap();
    let coinbase_internal = display_to_internal_hex(&coinbase_display);

    let spec = build_spec(SpecInputs {
        wallet: &wallet,
        coinbase_internal: &coinbase_internal,
    });
    let spec_path = tmp.path().join("watch.json");
    std::fs::write(&spec_path, serde_json::to_vec_pretty(&spec).unwrap()).unwrap();

    let tip = tokio::task::spawn_blocking({
        let rpc = sn.node.rpc_handle();
        move || rpc.block_count()
    })
    .await
    .unwrap();
    let until_height = tip as u32 + blocks + 1;

    // Both dumpers connect and register BEFORE the scenario starts. A client
    // that subscribes mid-scenario sees a different prefix of the event stream,
    // and every resulting diff is a race rather than a finding.
    let go_out = tmp.path().join("go.jsonl");
    let go_ready = tmp.path().join("go.ready");
    let mut go_proc = std::process::Command::new(&go_bin)
        .arg("-endpoint")
        .arg(format!("127.0.0.1:{}", sn.grpc_port()))
        .arg("-spec")
        .arg(&spec_path)
        .arg("-out")
        .arg(&go_out)
        .arg("-ready-file")
        .arg(&go_ready)
        .arg("-until-height")
        .arg(until_height.to_string())
        .arg("-timeout")
        .arg(format!("{}s", e2e_test_timeout(300).as_secs()))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn paritydump");

    // Drain the child's stderr on a thread. Piping it and never reading it lost
    // every Go-side diagnostic ("dial refused", "recv after N events: ...") and
    // would eventually block the child on a full pipe; the buffer is printed
    // with any failure below.
    let go_stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        use std::io::Read;
        let mut pipe = go_proc.stderr.take().expect("stderr piped");
        let sink = std::sync::Arc::clone(&go_stderr);
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = pipe.read_to_string(&mut buf);
            *sink.lock().unwrap() = buf;
        });
    }
    // A killer guard makes sure the child cannot outlive this test as an orphan
    // writing into a deleted TempDir, on any panic path.
    let go_proc = KillOnDrop(go_proc);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let port = sn.grpc_port();
    let rust_task = {
        let spec = serde_json::from_slice::<Spec>(&std::fs::read(&spec_path).unwrap()).unwrap();
        tokio::spawn(async move { rust_dump(port, &spec, until_height, ready_tx).await })
    };

    tokio::time::timeout(e2e_test_timeout(120), ready_rx)
        .await
        .expect("rust dumper never became ready (timed out)")
        .expect("rust dumper never became ready");
    wait_for_file(&go_ready, e2e_test_timeout(120)).await;

    Some(ParityRun {
        sn,
        wallet,
        addr,
        _tmp: tmp,
        go_out,
        go_proc,
        go_stderr,
        rust_task,
    })
}

impl ParityRun {
    /// Make a JSON-RPC call against the node, returning the whole response.
    async fn rpc_call(&self, method: &'static str, params: Vec<Value>) -> Value {
        let rpc = self.sn.node.rpc_handle();
        tokio::task::spawn_blocking(move || rpc.call(method, params))
            .await
            .unwrap()
            .expect("rpc call")
    }

    /// A JSON-RPC call whose `result` is a bare string (a block hash, say).
    async fn rpc_string(&self, method: &'static str, params: Vec<Value>) -> String {
        self.rpc_call(method, params).await["result"]
            .as_str()
            .expect("string result")
            .to_string()
    }

    /// Mine `n` blocks to the watched address, pausing so both streams see them.
    async fn mine_watched(&self, n: u32) {
        for _ in 0..n {
            let rpc = self.sn.node.rpc_handle();
            let target = self.addr.clone();
            tokio::task::spawn_blocking(move || rpc.mine(1, &target)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Mine `n` blocks to an address neither dumper watches.
    async fn mine_unwatched(&self, n: u32) {
        let unwatched = DeterministicWallet::from_secret([UNWATCHED_SEED; 32]).address.to_string();
        for _ in 0..n {
            let rpc = self.sn.node.rpc_handle();
            let target = unwatched.clone();
            tokio::task::spawn_blocking(move || rpc.mine(1, &target)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Build, sign, and BROADCAST a spend of block 1's coinbase to `dest`.
    ///
    /// `build_signed_p2wpkh_spend_seq` only builds and signs — it never touches
    /// the node. A scenario that discards the returned pair broadcasts nothing,
    /// which is how the original harness silently compared only block events
    /// while claiming to cover mempool admission.
    async fn broadcast_spend(&self, dest: bitcoin::ScriptBuf, fee_sat: u64, sequence: u32) -> String {
        let rpc = self.sn.node.rpc_handle();
        let w = self.wallet.clone();
        let (raw, txid) = tokio::task::spawn_blocking(move || {
            build_signed_p2wpkh_spend_seq(&rpc, &w, dest, fee_sat, sequence)
        })
        .await
        .unwrap();
        let rpc = self.sn.node.rpc_handle();
        let sent = tokio::task::spawn_blocking(move || rpc.send_raw_tx(&raw)).await.unwrap();
        assert_eq!(sent, txid, "sendrawtransaction returns the computed txid");
        // Let the mempool events reach both streams before anything confirms.
        tokio::time::sleep(Duration::from_millis(500)).await;
        txid
    }

    /// Mine the sentinel block, collect both dumps, and diff them.
    ///
    /// `expect_kinds` is the non-vacuity floor: every one must appear, or the
    /// run proved nothing. `!is_empty()` alone could never fail — the dumpers
    /// push the sentinel block BEFORE breaking, so the block_connected lines
    /// always satisfy it even if every watch registration had been REJECTED and
    /// not a single watch event was compared. (Registration rejections land
    /// before the readiness barrier and are dropped by both sides, so that
    /// failure is invisible here by construction.)
    async fn finish(mut self, expect_kinds: &[&str]) {
        // The sentinel is mined to an UNWATCHED address on purpose: a match for
        // the sentinel block travels on the watch-matcher channel while the
        // block event travels on the live channel, so whether it arrives before
        // or after the sentinel is a per-connection race — and each dumper stops
        // ON the sentinel. Mining it elsewhere leaves no such match to race, so
        // both dumps end on exactly the same event set.
        self.mine_unwatched(1).await;

        let rust_lines = tokio::time::timeout(e2e_test_timeout(300), &mut self.rust_task)
            .await
            .expect("rust dumper timed out")
            .expect("rust dumper panicked");

        let status = wait_for_exit(&mut self.go_proc.0, e2e_test_timeout(120));
        assert!(
            status,
            "go paritydump did not exit cleanly. stderr:\n{}",
            self.go_stderr.lock().unwrap()
        );

        let go_lines: Vec<String> = std::fs::read_to_string(&self.go_out)
            .expect("go dump")
            .lines()
            .map(normalize_line)
            .collect();
        let rust_lines: Vec<String> = rust_lines.iter().map(|l| normalize_line(l)).collect();

        for kind in expect_kinds {
            let needle = format!("\"type\":\"{kind}\"");
            assert!(
                rust_lines.iter().any(|l| l.contains(&needle)),
                "no {kind} event was compared. The scenario or the watch registration is \
                 broken, and a green run would prove nothing about the watch surface.\n\
                 kinds actually present: {:?}",
                observed_kinds(&rust_lines)
            );
        }

        if go_lines != rust_lines {
            // The dumps live in a TempDir deleted as this unwind runs, so print
            // the finding itself rather than a path that no longer exists.
            let first_diff = go_lines
                .iter()
                .zip(rust_lines.iter())
                .find(|(g, r)| g != r)
                .map(|(g, r)| format!("go:   {g}\nrust: {r}"))
                .unwrap_or_else(|| {
                    format!(
                        "no differing line; the dumps differ in LENGTH: go={} rust={}",
                        go_lines.len(),
                        rust_lines.len()
                    )
                });
            let stderr = self.go_stderr.lock().unwrap().clone();
            panic!(
                "\nGo and Rust SDKs disagree ({} vs {} events).\n\
                 Each line is one event in canonical form.\n\n{}\n\n\
                 go paritydump stderr:\n{}\n",
                go_lines.len(),
                rust_lines.len(),
                first_diff,
                if stderr.is_empty() { "(empty)" } else { stderr.as_str() }
            );
        }
    }
}

// ---- the scenarios --------------------------------------------------------

/// S1: a funding match and a spend match, mempool then confirmed.
#[tokio::test(flavor = "multi_thread")]
async fn parity_script_and_outpoint_mempool_then_confirmed() {
    let Some(run) = parity_begin(
        &[],
        |i| Spec {
            include_raw_tx: true,
            scripts: vec![SpecScript {
                scripthash: canonical::hexs(&sha256(i.wallet.address.script_pubkey().as_bytes())),
                min_value: None,
            }],
            outpoints: vec![SpecOutpoint { txid: i.coinbase_internal.to_string(), vout: 0 }],
            ..Default::default()
        },
        3,
    )
    .await
    else {
        eprintln!("skipping parity test: no Go toolchain and PARITYDUMP_BIN unset");
        return;
    };

    let dest = DeterministicWallet::from_secret([0x42; 32]).address.script_pubkey();
    run.broadcast_spend(dest, 1_000, 0xffff_ffff).await;
    // Three blocks to the watched address: each yields a coinbase script match.
    run.mine_watched(3).await;

    run.finish(&[
        "mempool_enter",
        "script_matched",
        "outpoint_spent",
        "mempool_leave_confirmed",
        "block_connected",
    ])
    .await;
}

/// Re-encode a line through serde_json so both sides' number formatting and key
/// order are normalized. Without this a difference in how one encoder renders a
/// large integer would read as a protocol divergence.
/// The distinct `type` values present in a dump, for a failure message that says
/// what DID arrive rather than only what did not.
fn observed_kinds(lines: &[String]) -> Vec<String> {
    let mut kinds: Vec<String> = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v.get("type").and_then(Value::as_str).map(str::to_owned))
        .collect();
    kinds.sort();
    kinds.dedup();
    kinds
}

fn normalize_line(line: &str) -> String {
    let v: Value = serde_json::from_str(line).expect("dump line is not JSON");
    serde_json::to_string(&v).unwrap()
}

async fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {}", path.display());
}

fn wait_for_exit(proc: &mut std::process::Child, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match proc.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return false,
        }
    }
    let _ = proc.kill();
    false
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(b).to_byte_array()
}

/// S2: a reorg. `invalidateblock` rolls the tip back, and both SDKs must
/// narrate it identically — the `reorg` marker and the per-block
/// `block_disconnected`, neither of which any earlier scenario produced.
#[tokio::test(flavor = "multi_thread")]
async fn parity_reorg_disconnects_and_renarrates() {
    let Some(run) = parity_begin(
        &[],
        |i| Spec {
            scripts: vec![SpecScript {
                scripthash: canonical::hexs(&sha256(i.wallet.address.script_pubkey().as_bytes())),
                min_value: None,
            }],
            ..Default::default()
        },
        // net +3: mine 2, invalidate 1, mine 2.
        3,
    )
    .await
    else {
        eprintln!("skipping parity test: no Go toolchain and PARITYDUMP_BIN unset");
        return;
    };

    run.mine_watched(2).await;
    // Invalidating the tip is the one way to make a SINGLE node reorg
    // deterministically; a two-node race would make the diff a scheduling
    // artifact rather than a finding.
    let tip_hash = run.rpc_string("getbestblockhash", vec![]).await;
    let resp = run.rpc_call("invalidateblock", vec![serde_json::json!(tip_hash)]).await;
    assert!(resp["error"].is_null(), "invalidateblock errored: {resp:?}");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Mine past the invalidated height so the sentinel is reachable: the tip
    // went backwards, and `-until-height` counts forwards only.
    //
    // These go to the UNWATCHED address, and that is load-bearing rather than
    // incidental. Re-mining to the same address at the same height reproduces
    // the same coinbase and therefore the same block hash — which the node
    // rejects, since it just marked that hash invalid. The chain then never
    // advances, the sentinel height is never reached, and the run dies at its
    // timeout with nothing to point at. A different coinbase makes the
    // replacement block genuinely new.
    run.mine_unwatched(2).await;

    // Fail loudly if the chain did not actually advance, rather than letting
    // `finish` block until the dumper timeout and report only "timed out".
    let height = run.rpc_call("getblockcount", vec![]).await["result"]
        .as_u64()
        .expect("block count");
    assert_eq!(
        height, 104,
        "the chain must be back above the invalidated height before the sentinel; \
         a stuck tip here means the replacement blocks were rejected"
    );

    run.finish(&["reorg", "block_disconnected", "block_connected", "script_matched"]).await;
}

/// S3: transaction lifecycle and depth alarms.
///
/// Both are registered against block 1's coinbase, whose txid is knowable at
/// spec-build time — the alternative (a txid the scenario creates) cannot be
/// named in a spec that has to be written before the node is driven.
#[tokio::test(flavor = "multi_thread")]
async fn parity_lifecycle_and_depth_alarms() {
    // `-txindex` is load-bearing here, not incidental. Both watches name a txid
    // that confirmed BEFORE registration, so arming them depends on the
    // one-shot txindex probe resolving the anchor; with the index off the
    // probe finds nothing and the entry waits for a live observation that
    // never comes (see `no_txindex_waits_for_live_observation`).
    let Some(run) = parity_begin(
        &["--txindex=1"],
        |i| Spec {
            // The chain is at 101, so block 1's coinbase sits at depth 101.
            // Both thresholds are ahead of that and fire as the scenario mines.
            lifecycles: vec![SpecLifecycle {
                txid: i.coinbase_internal.to_string(),
                auto_close_depth: 104,
            }],
            depth_alarms: vec![SpecDepth { txid: i.coinbase_internal.to_string(), depth: 103 }],
            ..Default::default()
        },
        3,
    )
    .await
    else {
        eprintln!("skipping parity test: no Go toolchain and PARITYDUMP_BIN unset");
        return;
    };

    run.mine_unwatched(3).await;

    run.finish(&["txid_depth_reached", "txid_finalized", "block_connected"]).await;
}

/// S5: a privacy prefix watch, decoys and all.
///
/// The bucket is deliberately wide (8 bits), so the deliveries include
/// transactions the consumer never asked for. Both SDKs must receive the SAME
/// decoy set — a prefix watch whose decoys differed between clients would leak
/// differently on each, which no per-SDK test can see.
#[tokio::test(flavor = "multi_thread")]
async fn parity_prefix_watch_including_decoys() {
    let Some(run) = parity_begin(
        &[],
        |i| Spec {
            prefixes: vec![SpecPrefix {
                prefix: script_prefix_hex(&i.wallet.address.script_pubkey(), 8),
                bits: 8,
            }],
            ..Default::default()
        },
        3,
    )
    .await
    else {
        eprintln!("skipping parity test: no Go toolchain and PARITYDUMP_BIN unset");
        return;
    };

    let dest = DeterministicWallet::from_secret([0x43; 32]).address.script_pubkey();
    run.broadcast_spend(dest, 1_000, 0xffff_ffff).await;
    run.mine_watched(3).await;

    run.finish(&["prefix_matched", "block_connected"]).await;
}
