//! Behaviour flags: shapes of conduct in a peer's
//! [`crate::net::behavior::PeerBehavior`] record that an honest peer does
//! not show, each carried with the numbers that raised it.
//!
//! [`evaluate`] is a pure function of a peer's record and a few facts the
//! manager holds about it (session length, how often its network group has
//! connected, its address token bucket, its fingerprint). The manager runs
//! it on every connected peer every [`EVALUATE_INTERVAL_SECS`], not per
//! message, and once more when a peer leaves. Flags are recomputed each
//! time, so one can clear. Nothing here changes how a peer is treated.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::net::behavior::PeerBehavior;
use crate::net::fingerprint::{Family, Fingerprint};

/// How often the manager re-evaluates every connected peer.
pub const EVALUATE_INTERVAL_SECS: u64 = 5;

/// A behaviour flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Crawler,
    Spy,
    FingerprintMismatch,
    AddrAbuse,
    HeightLie,
    NotfoundPattern,
    Stalling,
}

impl Flag {
    /// Every flag, in code order.
    pub const ALL: [Flag; 7] = [
        Flag::Crawler,
        Flag::Spy,
        Flag::FingerprintMismatch,
        Flag::AddrAbuse,
        Flag::HeightLie,
        Flag::NotfoundPattern,
        Flag::Stalling,
    ];

    /// The one-letter code.
    pub fn code(self) -> char {
        match self {
            Flag::Crawler => 'C',
            Flag::Spy => 'S',
            Flag::FingerprintMismatch => 'F',
            Flag::AddrAbuse => 'A',
            Flag::HeightLie => 'H',
            Flag::NotfoundPattern => 'N',
            Flag::Stalling => 'T',
        }
    }

    /// The name used in RPC output and the manual.
    pub fn name(self) -> &'static str {
        match self {
            Flag::Crawler => "crawler",
            Flag::Spy => "spy",
            Flag::FingerprintMismatch => "fingerprint-mismatch",
            Flag::AddrAbuse => "addr-abuse",
            Flag::HeightLie => "height-lie",
            Flag::NotfoundPattern => "notfound-pattern",
            Flag::Stalling => "stalling",
        }
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlagSet(u8);

impl FlagSet {
    pub fn contains(self, flag: Flag) -> bool {
        self.0 & flag.bit() != 0
    }

    pub fn insert(&mut self, flag: Flag) {
        self.0 |= flag.bit();
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = Flag> {
        Flag::ALL.into_iter().filter(move |f| self.contains(*f))
    }
}

impl fmt::Display for FlagSet {
    /// The codes, in order: `CS`, or empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.iter().try_for_each(|flag| write!(f, "{}", flag.code()))
    }
}

/// The thresholds each flag is judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thresholds {
    /// `C`: the session is shorter than this.
    pub crawler_session_max_secs: u64,
    /// `C`: at least this many inbound connections from the peer's network
    /// group, this one included, within the window. A peer fingerprinted as
    /// bitnodes or bitcoin-seeder needs none.
    pub crawler_netgroup_min: u32,
    /// `C`: the window the network-group count covers.
    pub crawler_netgroup_window_secs: u64,
    /// `S`: at least this many transactions announced to the peer.
    pub spy_announced_min: u64,
    /// `S`: the peer asked for at least this share of them, per mille.
    pub spy_getdata_permille_min: u64,
    /// `S`: the 10th percentile of its `getdata` delay is at most this, in
    /// milliseconds (a bucket bound of the latency histogram).
    pub spy_p10_max_ms: u64,
    /// `S`: connected at least this long.
    pub spy_session_min_secs: u64,
    /// `A`: more `getaddr` than this in one connection. Core answers one.
    pub addr_getaddr_max: u64,
    /// `A`: more addresses than this dropped by the address token bucket.
    pub addr_rate_limited_max: u64,
    /// `H`: `height_claim_gap` at least this.
    pub height_gap_min: u32,
    /// `N`: at least this many `notfound` for transactions it announced.
    pub notfound_min: u64,
    /// `N`: and at least this share of the transactions it announced, per
    /// mille.
    pub notfound_permille_min: u64,
    /// `T`: at least this many block-download stalls.
    pub stalls_min: u32,
}

/// The thresholds in use.
///
/// PLACEHOLDERS, pending calibration: every value here is to be replaced
/// by the distribution measured on a synced mainnet node over 48 hours
/// before this ships. Until then they are deliberately loose, so that a
/// flag says more about the threshold than about the peer only rarely.
pub const THRESHOLDS: Thresholds = Thresholds {
    crawler_session_max_secs: 300,
    crawler_netgroup_min: 3,
    crawler_netgroup_window_secs: 3_600,
    spy_announced_min: 500,
    spy_getdata_permille_min: 900,
    spy_p10_max_ms: 5,
    spy_session_min_secs: 2 * 3_600,
    addr_getaddr_max: 1,
    addr_rate_limited_max: 1_000,
    height_gap_min: 6,
    notfound_min: 10,
    notfound_permille_min: 100,
    stalls_min: 3,
};

/// One number or name of a flag's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Num(u64),
    Name(&'static str),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Num(n) => write!(f, "{n}"),
            Value::Name(s) => f.write_str(s),
        }
    }
}

impl From<&Value> for serde_json::Value {
    fn from(v: &Value) -> Self {
        match v {
            Value::Num(n) => serde_json::json!(n),
            Value::Name(s) => serde_json::json!(s),
        }
    }
}

/// What raised a flag: named values.
pub type Evidence = Vec<(&'static str, Value)>;

/// Writes evidence as `key=value key=value`.
pub struct EvidenceDisplay<'a>(pub &'a Evidence);

impl fmt::Display for EvidenceDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

/// What [`evaluate`] judges a peer by.
pub struct Inputs<'a> {
    pub behavior: &'a PeerBehavior,
    /// The peer dialed us.
    pub inbound: bool,
    /// Seconds since it connected (in total, when it has left).
    pub session_secs: u64,
    /// Inbound connections from its network group within the `C` window,
    /// this one included. 0 when its group is not measured: an outbound,
    /// onion or unroutable peer.
    pub netgroup_seen: u32,
    /// Addresses from it the address token bucket dropped.
    pub addr_rate_limited: u64,
    pub fingerprint: Fingerprint,
}

/// The flags a peer carries now, each with its evidence, in code order.
pub fn evaluate(i: &Inputs, t: &Thresholds) -> Vec<(Flag, Evidence)> {
    let b = i.behavior;
    let num = Value::Num;
    let mut out = Vec::new();

    // A peer whose handshake is a known crawler's needs no busy network
    // group: crawlers that return only every hour or two never make one.
    let crawler_family = i.fingerprint.observed().filter(|f| matches!(f, Family::Bitnodes | Family::BitcoinSeeder));
    let busy_netgroup = i.netgroup_seen >= t.crawler_netgroup_min;
    if i.inbound
        && i.session_secs < t.crawler_session_max_secs
        && b.getaddr_in > 0
        && b.headers_req == 0
        && b.blocks_req == 0
        && (busy_netgroup || crawler_family.is_some())
    {
        let mut evidence = vec![
            ("session_secs", num(i.session_secs)),
            ("getaddr_in", num(b.getaddr_in)),
            ("headers_req", num(b.headers_req)),
            ("blocks_req", num(b.blocks_req)),
            ("netgroup_seen", num(u64::from(i.netgroup_seen))),
        ];
        if let (false, Some(f)) = (busy_netgroup, crawler_family) {
            evidence.push(("fingerprint", Value::Name(f.name())));
        }
        out.push((Flag::Crawler, evidence));
    }

    let relay = b.version.as_ref().is_some_and(|v| v.relay);
    let getdata_permille = permille(b.getdata_tx_in, b.inv_tx_announced_to);
    let p10 = b.getdata_latency.p10_ms();
    if relay
        && b.inv_tx_announced_to >= t.spy_announced_min
        && getdata_permille >= t.spy_getdata_permille_min
        && p10.is_some_and(|ms| ms <= t.spy_p10_max_ms)
        && b.inv_tx_in == 0
        && b.blocks_req == 0
        && i.session_secs >= t.spy_session_min_secs
    {
        out.push((
            Flag::Spy,
            vec![
                ("inv_tx_announced_to", num(b.inv_tx_announced_to)),
                ("getdata_tx_in", num(b.getdata_tx_in)),
                ("getdata_permille", num(getdata_permille)),
                ("getdata_p10_ms", num(p10.unwrap_or(0))),
                ("inv_tx_in", num(b.inv_tx_in)),
                ("blocks_req", num(b.blocks_req)),
                ("session_secs", num(i.session_secs)),
            ],
        ));
    }

    if let Fingerprint::Mismatch { claimed, observed } = i.fingerprint {
        out.push((
            Flag::FingerprintMismatch,
            vec![("claimed", Value::Name(claimed.name())), ("observed", Value::Name(observed.name()))],
        ));
    }

    if b.getaddr_in > t.addr_getaddr_max || i.addr_rate_limited > t.addr_rate_limited_max {
        out.push((
            Flag::AddrAbuse,
            vec![
                ("getaddr_in", num(b.getaddr_in)),
                ("addr_in", num(b.addr_in)),
                ("addr_rate_limited", num(i.addr_rate_limited)),
            ],
        ));
    }

    if b.height_claim_gap >= t.height_gap_min {
        let start_height = b.version.as_ref().map_or(0, |v| u64::try_from(v.start_height).unwrap_or(0));
        out.push((
            Flag::HeightLie,
            vec![("height_claim_gap", num(u64::from(b.height_claim_gap))), ("start_height", num(start_height))],
        ));
    }

    let notfound_permille = permille(b.notfound_after_inv, b.inv_tx_in);
    if b.notfound_after_inv >= t.notfound_min && notfound_permille >= t.notfound_permille_min {
        out.push((
            Flag::NotfoundPattern,
            vec![
                ("notfound_after_inv", num(b.notfound_after_inv)),
                ("inv_tx_in", num(b.inv_tx_in)),
                ("notfound_permille", num(notfound_permille)),
            ],
        ));
    }

    if b.stalls >= t.stalls_min {
        out.push((Flag::Stalling, vec![("stalls", num(u64::from(b.stalls)))]));
    }

    out
}

/// `part / whole` in thousandths, capped at 1000; 0 for an empty whole.
fn permille(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    (u128::from(part) * 1_000 / u128::from(whole)).min(1_000) as u64
}

/// The last judgement of one peer, kept on its `PeerInfo`.
#[derive(Debug, Clone, Default)]
pub struct PeerFlags {
    /// Whether it has been evaluated at all.
    pub evaluated: bool,
    pub fingerprint: Fingerprint,
    /// Whether the transcript counted as final when last evaluated.
    pub settled: bool,
    /// The flags it carries, with their evidence, in code order.
    pub flags: Vec<(Flag, Evidence)>,
    /// Every flag it has carried this connection: a flag is logged the
    /// first time only.
    pub ever: FlagSet,
    /// Its network group, keyed, for an inbound routable peer.
    pub netgroup: Option<u64>,
}

impl PeerFlags {
    /// The flags it carries now.
    pub fn set(&self) -> FlagSet {
        let mut s = FlagSet::default();
        for (f, _) in &self.flags {
            s.insert(*f);
        }
        s
    }

    /// Take a new evaluation; returns the flags carried for the first time
    /// this connection, with their evidence.
    pub fn update(&mut self, fingerprint: Fingerprint, settled: bool, flags: Vec<(Flag, Evidence)>) -> Vec<(Flag, Evidence)> {
        let gained: Vec<(Flag, Evidence)> = flags.iter().filter(|(f, _)| !self.ever.contains(*f)).cloned().collect();
        for (f, _) in &gained {
            self.ever.insert(*f);
        }
        self.evaluated = true;
        self.fingerprint = fingerprint;
        self.settled = settled;
        self.flags = flags;
        gained
    }
}

/// The most inbound connections the network-group window remembers. Past
/// it the oldest is forgotten first, so a flood of connections costs a
/// fixed amount of memory and only makes the count lower.
pub const NETGROUP_WINDOW_MAX: usize = 4_096;

/// Recent inbound connections by keyed network group, for `C`. Holds a
/// salted hash of the group only, never an address.
#[derive(Debug, Default)]
pub struct NetgroupWindow {
    seen: VecDeque<(u64, Instant)>,
}

impl NetgroupWindow {
    /// An inbound connection from group `key` at `now`.
    pub fn record(&mut self, key: u64, now: Instant) {
        if self.seen.len() >= NETGROUP_WINDOW_MAX {
            self.seen.pop_front();
        }
        self.seen.push_back((key, now));
    }

    /// Forget connections older than `window`, then count by group.
    pub fn counts(&mut self, now: Instant, window: Duration) -> std::collections::HashMap<u64, u32> {
        while let Some((_, at)) = self.seen.front() {
            if now.saturating_duration_since(*at) > window {
                self.seen.pop_front();
            } else {
                break;
            }
        }
        let mut counts = std::collections::HashMap::new();
        for (key, _) in &self.seen {
            *counts.entry(*key).or_insert(0u32) += 1;
        }
        counts
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Connected peers per flag and per observed family, for metrics and the
/// status page. No addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagCounts {
    /// Peers carrying each flag, in [`Flag::ALL`] order.
    pub flagged: [usize; Flag::ALL.len()],
    /// Peers whose transcript matched each family, in [`Family::ALL`]
    /// order, mismatches counted under the family observed.
    pub families: [usize; Family::ALL.len()],
    /// Peers with no match (or none yet).
    pub unknown: usize,
}

impl FlagCounts {
    pub fn add(&mut self, p: &PeerFlags) {
        for (f, _) in &p.flags {
            self.flagged[*f as usize] += 1;
        }
        match p.fingerprint.observed() {
            Some(family) => {
                let i = Family::ALL.iter().position(|f| *f == family).unwrap_or(0);
                self.families[i] += 1;
            }
            None => self.unknown += 1,
        }
    }
}

/// Seconds since the peer connected, by the node clock: `conn_time` is set
/// from it, so `setmocktime` moves both ends alike.
pub fn session_secs(info: &crate::net::peer::PeerInfo) -> u64 {
    let start = info.conn_time.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    crate::time::now_secs().saturating_sub(start)
}

/// One peer as `getpeerbehavior` reports it: its id, fingerprint, flags
/// with their evidence, and the raw counters. No address. The user agent is
/// the sanitized one `getpeerinfo.subver` shows, escaped by JSON.
pub fn peer_json(info: &crate::net::peer::PeerInfo) -> serde_json::Value {
    use serde_json::json;
    let b = &info.behavior;
    let p = &info.flags;
    let fingerprint = match p.fingerprint {
        Fingerprint::Known(family, confidence) => {
            json!({"result": "known", "family": family.name(), "confidence": confidence.name()})
        }
        Fingerprint::Unknown => json!({"result": "unknown"}),
        Fingerprint::Mismatch { claimed, observed } => {
            json!({"result": "mismatch", "claimed": claimed.name(), "observed": observed.name()})
        }
    };
    let mut fingerprint = fingerprint;
    fingerprint["settled"] = json!(p.settled);
    fingerprint["handshake"] = json!(b.handshake.commands().collect::<Vec<_>>());
    let flags: Vec<serde_json::Value> = p
        .flags
        .iter()
        .map(|(flag, evidence)| {
            let ev: serde_json::Map<String, serde_json::Value> =
                evidence.iter().map(|(k, v)| (k.to_string(), serde_json::Value::from(v))).collect();
            json!({"code": flag.code().to_string(), "name": flag.name(), "evidence": ev})
        })
        .collect();
    let lat = &b.getdata_latency;
    let mut counters = json!({
        "inv_tx_in": b.inv_tx_in,
        "getdata_tx_in": b.getdata_tx_in,
        "getdata_latency": {
            "count": lat.count(),
            "p10_ms": lat.p10_ms(),
            "median_ms": lat.median_ms(),
            "bucket_bounds_ms": crate::net::behavior::LATENCY_BOUNDS_MS,
            "buckets": lat.buckets(),
        },
        "inv_tx_announced_to": b.inv_tx_announced_to,
        "headers_req": b.headers_req,
        "blocks_req": b.blocks_req,
        "getaddr_in": b.getaddr_in,
        "addr_in": b.addr_in,
        "addr_out": b.addr_out,
        "addr_rate_limited": info.addr_rate.rate_limited,
        "notfound_after_inv": b.notfound_after_inv,
        "height_claim_gap": b.height_claim_gap,
        "stalls": b.stalls,
    });
    if let Some(v) = &b.version {
        counters["version"] = json!({
            "protocol_version": v.protocol_version,
            "services": format!("{:016x}", v.services),
            "relay": v.relay,
            "start_height": v.start_height,
        });
    }
    let session_secs = session_secs(info);
    let mut out = json!({
        "id": info.id,
        "connection_type": info.conn_type.as_str(),
        "session_secs": session_secs,
        "subver": b.version.as_ref().map_or("", |v| v.user_agent.as_str()),
        "evaluated": p.evaluated,
        "fingerprint": fingerprint,
        "flag_codes": p.set().to_string(),
        "flags": flags,
        "counters": counters,
    });
    // An alt-slot peer (`-altslots`): the rule it matched and how far its
    // user agent was trusted, or a fallback holding an empty slot. A trial
    // still being judged has none yet.
    match &info.alt {
        Some(crate::net::altslots::AltRole::Matched { rule, trust }) => {
            out["alt_slot"] = json!({"rule": rule, "trust": trust.name(), "fallback": false});
        }
        Some(crate::net::altslots::AltRole::Fallback) => {
            out["alt_slot"] = json!({"rule": null, "trust": null, "fallback": true});
        }
        Some(crate::net::altslots::AltRole::Trial) | None => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_bits_are_distinct() {
        let codes: String = Flag::ALL.iter().map(|f| f.code()).collect();
        assert_eq!(codes, "CSFAHNT");
        let mut s = FlagSet::default();
        for f in Flag::ALL {
            assert!(!s.contains(f));
            s.insert(f);
        }
        assert_eq!(s.to_string(), "CSFAHNT");
        for (i, f) in Flag::ALL.iter().enumerate() {
            assert_eq!(*f as usize, i, "Flag::ALL is in discriminant order");
        }
    }

    #[test]
    fn a_flag_is_gained_once_per_connection() {
        let mut p = PeerFlags::default();
        let t = vec![(Flag::Stalling, vec![("stalls", Value::Num(3))])];
        assert_eq!(p.update(Fingerprint::Unknown, false, t.clone()).len(), 1);
        assert_eq!(p.update(Fingerprint::Unknown, false, Vec::new()).len(), 0);
        assert!(p.set().is_empty(), "a flag clears when its shape goes");
        assert_eq!(p.update(Fingerprint::Unknown, false, t).len(), 0, "and is not logged again");
        assert!(p.set().contains(Flag::Stalling));
    }

    /// The window forgets what is older than it, and holds at most
    /// `NETGROUP_WINDOW_MAX` connections however many arrive.
    #[test]
    fn the_netgroup_window_is_bounded() {
        let mut w = NetgroupWindow::default();
        let t0 = Instant::now();
        for _ in 0..3 {
            w.record(7, t0);
        }
        w.record(8, t0 + Duration::from_secs(100));
        let c = w.counts(t0 + Duration::from_secs(100), Duration::from_secs(3_600));
        assert_eq!((c[&7], c[&8]), (3, 1));
        let c = w.counts(t0 + Duration::from_secs(3_650), Duration::from_secs(3_600));
        assert_eq!((c.get(&7), c[&8]), (None, 1));
        for i in 0..10_000u64 {
            w.record(i, t0 + Duration::from_secs(3_650));
        }
        assert_eq!(w.len(), NETGROUP_WINDOW_MAX);
    }

    #[test]
    fn permille_is_capped_and_safe() {
        assert_eq!(permille(5, 0), 0);
        assert_eq!(permille(9, 10), 900);
        assert_eq!(permille(30, 10), 1_000);
        assert_eq!(permille(u64::MAX, u64::MAX), 1_000);
    }
}
