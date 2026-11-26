//! What the crawl (`-crawl`) reports: the aggregate `getcrawlinfo`, the
//! metrics and the status page read, and the per-address rows of
//! `getcrawlnodes`.
//!
//! The aggregate is counts only: no address, no user agent, nothing a
//! peer chose. It is taken over the reachable set, the addresses whose last
//! completed handshake is within the liveness window
//! ([`CrawlBook::snapshot`]), and over the whole book for the learned
//! counts. I2P and CJDNS addresses are counted as learned and never as
//! reachable: the crawl never dials them.
//!
//! The rows carry raw addresses. Only `getcrawlnodes` serves them, behind
//! the RPC's authentication and off the read-only listener.
//!
//! This module is the pure part: every function takes the book and `now`.

use crate::net::crawlbook::{
    ChainCheck, CrawlAddr, CrawlBook, CrawlEntry, GetaddrResult, Network, Observation,
};
use crate::net::fingerprint::{Confidence, Family, Fingerprint};
use crate::net::survey::{self, Verdict};

/// The networks the crawl dials, in [`Network::ALL`]'s order.
pub const DIALLED: [Network; 3] = [Network::Ipv4, Network::Ipv6, Network::Onion];

/// How a reachable address answered the two transports. Each reachable
/// address is in exactly one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// BIP 324 and v1 both completed a handshake.
    Both,
    /// v1 completed and the last BIP 324 attempt failed: a v1-only node.
    V1Only,
    /// v1 completed and BIP 324 was never tried: the node advertised no
    /// `NODE_P2P_V2`, so the crawl dialled it over v1 alone. Whether it
    /// speaks v2 is not known.
    V1V2Untried,
    /// BIP 324 completed and a v1 attempt within the liveness window failed.
    V2Only,
    /// BIP 324 completed and no v1 attempt has told yet whether v1 works.
    V2Unconfirmed,
}

impl Transport {
    pub const ALL: [Transport; 5] = [
        Transport::Both,
        Transport::V1Only,
        Transport::V1V2Untried,
        Transport::V2Only,
        Transport::V2Unconfirmed,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Transport::Both => "v2_and_v1",
            Transport::V1Only => "v1_only",
            Transport::V1V2Untried => "v1_v2_untried",
            Transport::V2Only => "v2_only",
            Transport::V2Unconfirmed => "v2_unconfirmed",
        }
    }

    /// The class of an entry that completed a handshake.
    pub fn of(e: &CrawlEntry) -> Transport {
        if e.v2_only {
            Transport::V2Only
        } else if e.v2_ok == Some(true) && e.v1_ok == Some(true) {
            Transport::Both
        } else if e.v2_ok == Some(true) {
            Transport::V2Unconfirmed
        } else if e.v2_ok == Some(false) {
            Transport::V1Only
        } else {
            Transport::V1V2Untried
        }
    }

    fn index(self) -> usize {
        Transport::ALL
            .iter()
            .position(|t| *t == self)
            .expect("every class is in ALL")
    }
}

/// The crawl's aggregate: counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aggregate {
    /// Entries in the book.
    pub entries: usize,
    /// Entries per network, [`Network::ALL`]'s order.
    pub learned: [usize; Network::ALL.len()],
    /// Entries that ever completed a handshake, per network.
    pub ever_reached: [usize; Network::ALL.len()],
    /// Reachable addresses (a handshake within the liveness window), per
    /// network, [`DIALLED`]'s order.
    pub reachable: [usize; DIALLED.len()],
    /// Reachable addresses per [`Transport`] class, [`Transport::ALL`]'s
    /// order.
    pub transport: [usize; Transport::ALL.len()],
    /// Reachable addresses whose address was last advertised (in a
    /// `getaddr` answer or the address-book sample) with `NODE_P2P_V2`. The
    /// node's own `version` services do not count here, though they decide
    /// the dial ([`CrawlEntry::dials_v2_first`](crate::net::crawlbook::CrawlEntry::dials_v2_first)).
    pub v2_advertised: usize,
    /// Reachable addresses per observed family (a row matched, at `high`
    /// or `low`), [`Family::ALL`]'s order.
    pub families: [usize; Family::ALL.len()],
    /// Reachable addresses whose handshake matched no family and whose user
    /// agent names none: neither claimed, fake nor closed early. An address
    /// with no observation yet (its entry was read from an older book) is
    /// one: nothing names a family for it.
    pub unknown: usize,
    /// Reachable addresses whose handshake matched no family but whose
    /// user agent names one (a [`Confidence::Claimed`] fingerprint), per
    /// family, [`Family::ALL`]'s order. Never counted in
    /// [`families`](Self::families) or [`unknown`](Self::unknown): a user
    /// agent is not an observation.
    pub claimed: [usize; Family::ALL.len()],
    /// Reachable addresses whose last session was fake
    /// ([`Verdict::Fake`]), per claimed family, [`Family::ALL`]'s order.
    /// Never counted in `families`, `claimed` or `unknown`.
    pub fake: [usize; Family::ALL.len()],
    /// Reachable addresses whose last session was closed early
    /// ([`Verdict::ClosedEarly`]): counted under no family, claim or
    /// unknown, and as reachable, by network and by transport like any
    /// other.
    pub closed_early: usize,
    /// Reachable addresses whose user agent names one family and handshake
    /// another.
    pub mismatches: usize,
    /// Addresses in the book, reachable or not, whose last observation is
    /// closed early and that have a retry scheduled.
    pub retries_pending: usize,
    /// Addresses in the book whose last observation is closed early and
    /// that have no retry left.
    pub retries_exhausted: usize,
}

impl Aggregate {
    /// Every reachable address.
    pub fn reachable_total(&self) -> usize {
        self.reachable.iter().sum()
    }
}

fn network_index(n: Network) -> usize {
    Network::ALL
        .iter()
        .position(|x| *x == n)
        .expect("every network is in ALL")
}

/// The aggregate of `book` as of `now`.
pub fn aggregate(book: &CrawlBook, now: u64) -> Aggregate {
    let mut agg = Aggregate {
        entries: book.len(),
        ..Aggregate::default()
    };
    for (addr, e) in book.rows() {
        let i = network_index(addr.network());
        agg.learned[i] += 1;
        if e.last_success.is_some() {
            agg.ever_reached[i] += 1;
        }
        if e.closed_early_retry.pending() {
            agg.retries_pending += 1;
        }
        if e.closed_early_retry.exhausted()
            && e.observation
                .as_ref()
                .is_some_and(|o| o.verdict == Verdict::ClosedEarly)
        {
            agg.retries_exhausted += 1;
        }
    }
    for (peer, e) in book.snapshot(now) {
        let net = crate::net::crawl::network_of(peer);
        let i = DIALLED
            .iter()
            .position(|n| *n == net)
            .expect("a reachable address is on a dialled network");
        agg.reachable[i] += 1;
        agg.transport[Transport::of(e).index()] += 1;
        if e.v2_advertised() {
            agg.v2_advertised += 1;
        }
        let index = |f: Family| {
            Family::ALL
                .iter()
                .position(|x| *x == f)
                .expect("every family is in ALL")
        };
        // Each reachable address in exactly one of the family, claimed,
        // fake, closed-early and unknown tallies.
        let (verdict, fp) = e
            .observation
            .as_ref()
            .map_or((Verdict::Classified, Fingerprint::Unknown), |o| {
                (o.verdict, o.fingerprint)
            });
        match verdict {
            Verdict::ClosedEarly => agg.closed_early += 1,
            Verdict::Fake(f) => agg.fake[index(f)] += 1,
            Verdict::Classified => match fp {
                Fingerprint::Known(f, Confidence::Claimed) => agg.claimed[index(f)] += 1,
                Fingerprint::Known(f, _) => agg.families[index(f)] += 1,
                Fingerprint::Mismatch { observed, .. } => {
                    agg.families[index(observed)] += 1;
                    agg.mismatches += 1;
                }
                Fingerprint::Unknown => agg.unknown += 1,
            },
        }
    }
    agg
}

/// The aggregate as `getcrawlinfo` reports it: `book`, `reachable`,
/// `transport`, `families`, `claimed`, `fake`, `closed_early`,
/// `mismatches` and `retries` (closed-early addresses in the whole book
/// with a retry scheduled, and with none left). Shares are of the
/// reachable addresses. Each reachable
/// address is counted once among `families` (observed families, and
/// `unknown`: no row matched and the user agent names no family),
/// `claimed` (no row matched; the user agent names the family), `fake`
/// (per claimed family) and `closed_early`, so a claim never adds to a
/// family's observed count.
pub fn aggregate_json(agg: &Aggregate, max_entries: usize) -> serde_json::Value {
    let total = agg.reachable_total();
    let share = |n: usize| {
        if total == 0 {
            0.0
        } else {
            n as f64 / total as f64
        }
    };
    let per_network = |counts: &[usize; Network::ALL.len()]| {
        let mut m = serde_json::Map::new();
        for (n, c) in Network::ALL.iter().zip(counts) {
            m.insert(n.name().to_string(), serde_json::json!(c));
        }
        serde_json::Value::Object(m)
    };
    let mut reachable = serde_json::Map::new();
    reachable.insert("total".to_string(), serde_json::json!(total));
    for (n, c) in DIALLED.iter().zip(agg.reachable) {
        reachable.insert(n.name().to_string(), serde_json::json!(c));
    }
    let mut transport = serde_json::Map::new();
    for (t, c) in Transport::ALL.iter().zip(agg.transport) {
        transport.insert(
            t.name().to_string(),
            serde_json::json!({ "count": c, "share": share(c) }),
        );
    }
    transport.insert(
        "v2_advertised".to_string(),
        serde_json::json!({ "count": agg.v2_advertised, "share": share(agg.v2_advertised) }),
    );
    let mut families = serde_json::Map::new();
    for (f, c) in Family::ALL.iter().zip(agg.families) {
        families.insert(
            f.name().to_string(),
            serde_json::json!({ "count": c, "share": share(c) }),
        );
    }
    families.insert(
        "unknown".to_string(),
        serde_json::json!({ "count": agg.unknown, "share": share(agg.unknown) }),
    );
    let per_family = |counts: &[usize; Family::ALL.len()]| {
        let mut out = serde_json::Map::new();
        for (f, c) in Family::ALL.iter().zip(counts) {
            out.insert(
                f.name().to_string(),
                serde_json::json!({ "count": c, "share": share(*c) }),
            );
        }
        serde_json::Value::Object(out)
    };
    serde_json::json!({
        "book": {
            "entries": agg.entries,
            "max_entries": max_entries,
            "learned": per_network(&agg.learned),
            "ever_reached": per_network(&agg.ever_reached),
        },
        "reachable": reachable,
        "transport": transport,
        "families": families,
        "claimed": per_family(&agg.claimed),
        "fake": per_family(&agg.fake),
        "closed_early": { "count": agg.closed_early, "share": share(agg.closed_early) },
        "mismatches": agg.mismatches,
        "retries": { "pending": agg.retries_pending, "exhausted": agg.retries_exhausted },
    })
}

/// An address as the rows print it: `ip:port`, `[ipv6]:port`,
/// `<host>.onion:port`, `<base32>.b32.i2p:port`.
pub fn addr_text(addr: &CrawlAddr) -> String {
    match addr {
        CrawlAddr::Peer(peer) => peer.to_string(),
        CrawlAddr::I2p { dest, port } => {
            format!(
                "{}.b32.i2p:{port}",
                data_encoding::BASE32_NOPAD
                    .encode(dest)
                    .to_ascii_lowercase()
            )
        }
        CrawlAddr::Cjdns { ip, port } => std::net::SocketAddr::from((*ip, *port)).to_string(),
    }
}

pub(crate) fn chain_check_name(c: ChainCheck) -> &'static str {
    match c {
        ChainCheck::OnChain => "on_chain",
        ChainCheck::Behind => "behind",
        ChainCheck::Fork => "fork",
        ChainCheck::OtherChain => "other_chain",
    }
}

fn observation_json(o: &Observation) -> serde_json::Value {
    let claimed = match o.fingerprint {
        Fingerprint::Mismatch { claimed, .. } => Some(claimed.name()),
        _ => None,
    };
    let getaddr = o.getaddr.map(|g| match g {
        GetaddrResult::Answered { entries, delay_ms } => {
            serde_json::json!({ "result": "answered", "entries": entries, "delay_ms": delay_ms })
        }
        GetaddrResult::NoAnswer => serde_json::json!({ "result": "no_answer" }),
    });
    serde_json::json!({
        "time": o.at,
        "fingerprint": o.fingerprint_text(),
        "family": o.observed_family().map(Family::name),
        "claimed": claimed.or_else(|| Family::claimed_by(&o.user_agent).map(Family::name)),
        "mismatch": o.mismatch(),
        "subver": o.user_agent,
        "version": o.protocol_version,
        "services": format!("{:016x}", o.services),
        "v2": o.v2,
        "asn": o.asn,
        "height": o.height,
        "height_gap": o.height_gap(),
        "chain_check": o.chain_check.map(chain_check_name),
        "clock_offset": o.clock_offset_secs,
        "handshake_rtt_ms": o.handshake_rtt_ms,
        "getaddr": getaddr,
        "probes": survey::probes_json(&o.probes),
    })
}

/// One `getcrawlnodes` row. Without `verbose`: the address, its network,
/// whether it is reachable now, its last handshake, transport class,
/// observed family and fingerprint (`core/claimed` when only the user
/// agent names the family, `fake/core` for a fake session, `closed-early`
/// when the peer closed before its transcript settled; `family` is then
/// null), and for a closed-early address its `retry` schedule (`count`,
/// `next_due`). With `verbose`: every field of the entry and of its last
/// observation.
pub fn row_json(
    addr: &CrawlAddr,
    e: &CrawlEntry,
    now: u64,
    liveness_secs: u64,
    verbose: bool,
) -> serde_json::Value {
    let reachable = addr.dialable()
        && e.last_success
            .is_some_and(|s| s >= now.saturating_sub(liveness_secs));
    let transport = e.last_success.map(|_| Transport::of(e).name());
    let o = e.observation.as_ref();
    let mut row = serde_json::json!({
        "addr": addr_text(addr),
        "network": addr.network().name(),
        "reachable": reachable,
        "last_success": e.last_success,
        "transport": transport,
        "family": o.and_then(Observation::observed_family).map(Family::name),
        "fingerprint": o.map(Observation::fingerprint_text),
    });
    if o.is_some_and(|o| o.verdict == Verdict::ClosedEarly) {
        row["retry"] = e.closed_early_retry.json();
    }
    if verbose {
        let extra = serde_json::json!({
            "dialable": addr.dialable(),
            "first_learned": e.first_learned,
            "last_named": e.last_named,
            "sources": e.source_count(),
            "advertised_services": format!("{:016x}", e.advertised_services),
            "v2_advertised": e.v2_advertised(),
            "best_time": e.best_time,
            "attempts": e.attempts,
            "last_attempt": e.last_attempt,
            "last_discovery": e.last_discovery,
            "last_v1_check": e.last_v1_check,
            "failures": e.failures,
            "failing_since": e.failing_since,
            "retry_at": e.retry_at,
            "in_flight": e.in_flight(now),
            "v2_ok": e.v2_ok,
            "v1_ok": e.v1_ok,
            "v2_only": e.v2_only,
            "reachable_count": e.reachable_count,
            "first_reachable": e.first_reachable,
            "observation": e.observation.as_ref().map(observation_json),
        });
        if let (Some(o), Some(x)) = (row.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                o.insert(k.clone(), v.clone());
            }
        }
    }
    row
}

/// `getcrawlnodes`: a row per address in the book, the most recently
/// reached first, then by address.
pub fn nodes_json(book: &CrawlBook, now: u64, verbose: bool) -> serde_json::Value {
    let liveness = book.params().liveness_secs;
    let mut rows: Vec<(&CrawlAddr, &CrawlEntry)> = book.rows().collect();
    rows.sort_unstable_by(|a, b| b.1.last_success.cmp(&a.1.last_success).then(a.0.cmp(b.0)));
    rows.into_iter()
        .map(|(addr, e)| row_json(addr, e, now, liveness, verbose))
        .collect()
}

#[cfg(test)]
#[path = "crawlreport_tests.rs"]
mod tests;
