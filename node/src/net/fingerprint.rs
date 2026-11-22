//! Which implementation a peer runs, judged from what it sent during and
//! just after its handshake.
//!
//! [`classify`] compares a peer's handshake transcript
//! ([`crate::net::behavior::HandshakeCapture`]) and `version` fields against
//! [`TABLE`], a list of the shapes each implementation was measured to send.
//! Every row comes from a capture committed under
//! `contrib/peer-fingerprint/fixtures` and is named after it; the fixture
//! replay test checks that each capture classifies as its own family and no
//! other. No row is written from documentation. A shape no capture shows
//! (an older release, a block-relay-only or feeler connection from Core) is
//! [`Fingerprint::Unknown`], never a guess.
//!
//! Knots and the other Core forks share Core's networking code and are the
//! [`Family::Core`] family.

use std::fmt;

use crate::net::behavior::{HandshakeCapture, VersionFields};
use crate::net::survey::{Probe, ProbeOutcome, ProbeResults};
use crate::net::v2transport::V2Greeting;

/// An implementation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// Bitcoin Core, and the forks that share its networking code (Knots).
    Core,
    Btcd,
    Bcoin,
    Libbitcoin,
    Floresta,
    Rbitcoin,
    Satd,
    /// The `bitcoin-seeder` DNS seed crawler.
    BitcoinSeeder,
    /// The bitnodes.io crawler.
    Bitnodes,
}

impl Family {
    /// Every family, in the order metrics and the manual list them.
    pub const ALL: [Family; 9] = [
        Family::Core,
        Family::Btcd,
        Family::Bcoin,
        Family::Libbitcoin,
        Family::Floresta,
        Family::Rbitcoin,
        Family::Satd,
        Family::BitcoinSeeder,
        Family::Bitnodes,
    ];

    /// The name used in RPC output and metric labels.
    pub fn name(self) -> &'static str {
        match self {
            Family::Core => "core",
            Family::Btcd => "btcd",
            Family::Bcoin => "bcoin",
            Family::Libbitcoin => "libbitcoin",
            Family::Floresta => "floresta",
            Family::Rbitcoin => "rbitcoin",
            Family::Satd => "satd",
            Family::BitcoinSeeder => "bitcoin-seeder",
            Family::Bitnodes => "bitnodes",
        }
    }

    /// A crawler rather than a node.
    pub fn is_crawler(self) -> bool {
        matches!(self, Family::BitcoinSeeder | Family::Bitnodes)
    }

    /// The family a user agent names, from the client names the captures
    /// carry: the first BIP 14 component whose name is one of them. Knots
    /// sends `/Satoshi:…/Knots:…/`, btcd `/btcwire:…/btcd:…/`.
    pub fn claimed_by(user_agent: &str) -> Option<Family> {
        user_agent.split('/').find_map(|component| {
            let name = component.split([':', '(']).next().unwrap_or("");
            match name {
                "Satoshi" | "Knots" => Some(Family::Core),
                "btcwire" | "btcd" => Some(Family::Btcd),
                "bcoin" => Some(Family::Bcoin),
                "libbitcoin" => Some(Family::Libbitcoin),
                "Floresta" => Some(Family::Floresta),
                "rbitcoin" => Some(Family::Rbitcoin),
                "satd" => Some(Family::Satd),
                "bitcoin-seeder" => Some(Family::BitcoinSeeder),
                "bitnodes.io" => Some(Family::Bitnodes),
                _ => None,
            }
        })
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How sure a [`Fingerprint::Known`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The commands alone match only this family's rows.
    High,
    /// Another family's row has the same commands; the `version` fields
    /// told them apart.
    Low,
}

impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Low => "low",
        }
    }
}

/// What [`classify`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fingerprint {
    /// The transcript matches this family's row, and the user agent names
    /// it or no family at all.
    Known(Family, Confidence),
    /// No row matches, or the transcript is not settled yet.
    #[default]
    Unknown,
    /// The user agent names one family and the transcript matches another.
    Mismatch { claimed: Family, observed: Family },
}

impl Fingerprint {
    /// The family the transcript matched, whatever the user agent says.
    pub fn observed(&self) -> Option<Family> {
        match *self {
            Fingerprint::Known(f, _) => Some(f),
            Fingerprint::Mismatch { observed, .. } => Some(observed),
            Fingerprint::Unknown => None,
        }
    }
}

impl fmt::Display for Fingerprint {
    /// `core/high`, `unknown`, or `mismatch(claimed=core,observed=btcd)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fingerprint::Known(family, confidence) => write!(f, "{family}/{}", confidence.name()),
            Fingerprint::Unknown => f.write_str("unknown"),
            Fingerprint::Mismatch { claimed, observed } => {
                write!(f, "mismatch(claimed={claimed},observed={observed})")
            }
        }
    }
}

/// Which direction a row was captured in, as satd sees the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowDirection {
    /// The peer dialed us (a fixture's `inbound`).
    Inbound,
    /// We dialed the peer (a fixture's `outbound`).
    Outbound,
    /// Both directions were captured with the same shape.
    Either,
}

impl RowDirection {
    fn admits(self, inbound: bool) -> bool {
        match self {
            RowDirection::Inbound => inbound,
            RowDirection::Outbound => !inbound,
            RowDirection::Either => true,
        }
    }
}

/// One measured shape.
///
/// A row pins the commands (replies to our own requests left out, as the
/// transcript leaves them out), the direction, `relay`, and whether any
/// service bit is set, all as captured. A shape with no feature negotiation
/// in it (no `wtxidrelay` or `sendaddrv2`) is what every client below
/// protocol 70016 sends, so those rows pin the protocol version too.
#[derive(Debug)]
pub struct Row {
    /// The captures it comes from, as fixture names without `.json`.
    pub captures: &'static [&'static str],
    pub family: Family,
    pub direction: RowDirection,
    pub commands: &'static [&'static str],
    pub relay: bool,
    pub services_zero: bool,
    pub protocol_version: Option<u32>,
}

impl Row {
    fn matches_version(&self, v: &VersionFields) -> bool {
        v.relay == self.relay
            && (v.services == 0) == self.services_zero
            && self.protocol_version.is_none_or(|p| p == v.protocol_version)
    }
}

/// The measured shapes. Captures with no row: those in which the
/// implementation sent no `version` (a v2 dial to a v1-only node, rbitcoin
/// refusing v1), and rbitcoin's first, catch-up connection, which ends at
/// `verack` as any client's feeler connection does.
#[rustfmt::skip]
pub const TABLE: &[Row] = &[
    Row {
        captures: &[
            "core-31.2-inbound", "core-31.2-inbound-s2", "core-31.2-inbound-v2", "core-31.2-inbound-v2-s2",
            "knots-29.4.3.knots20260508-inbound", "knots-29.4.3.knots20260508-inbound-s2",
            "knots-29.4.3.knots20260508-inbound-v2", "knots-29.4.3.knots20260508-inbound-v2-s2",
        ],
        family: Family::Core,
        direction: RowDirection::Inbound,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "getaddr"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &[
            "core-31.2-outbound", "core-31.2-outbound-v2",
            "knots-29.4.3.knots20260508-outbound", "knots-29.4.3.knots20260508-outbound-v2",
        ],
        family: Family::Core,
        direction: RowDirection::Outbound,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct", "ping"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["satd-0.7.0-inbound", "satd-0.7.0-inbound-s2", "satd-0.7.0-inbound-v2", "satd-0.7.0-inbound-v2-s2"],
        family: Family::Satd,
        direction: RowDirection::Inbound,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendheaders", "getheaders"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["satd-0.7.0-outbound", "satd-0.7.0-outbound-v2"],
        family: Family::Satd,
        direction: RowDirection::Outbound,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "getheaders"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["rbitcoin-0.8.0-inbound-v2-s2", "rbitcoin-0.8.0-outbound-v2"],
        family: Family::Rbitcoin,
        direction: RowDirection::Either,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendheaders", "sendcmpct", "ping"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["btcd-0.27.0-inbound", "btcd-0.27.0-inbound-v2"],
        family: Family::Btcd,
        direction: RowDirection::Inbound,
        commands: &["version", "sendaddrv2", "verack", "getaddr"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["btcd-0.27.0-outbound"],
        family: Family::Btcd,
        direction: RowDirection::Outbound,
        commands: &["version", "sendaddrv2", "verack"],
        relay: true, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["bcoin-2.2.0-inbound", "bcoin-2.2.0-inbound-v2", "bcoin-2.2.0-outbound"],
        family: Family::Bcoin,
        direction: RowDirection::Either,
        commands: &["version", "verack", "addr"],
        relay: true, services_zero: false, protocol_version: Some(70015),
    },
    Row {
        captures: &[
            "libbitcoin-3.8.0-inbound", "libbitcoin-3.8.0-inbound-s2", "libbitcoin-3.8.0-inbound-v2",
            "libbitcoin-3.8.0-inbound-v2-s2", "libbitcoin-3.8.0-outbound",
        ],
        family: Family::Libbitcoin,
        direction: RowDirection::Either,
        commands: &["version", "verack"],
        relay: false, services_zero: false, protocol_version: Some(70013),
    },
    Row {
        captures: &["floresta-0.9.1-inbound", "floresta-0.9.1-inbound-s2"],
        family: Family::Floresta,
        direction: RowDirection::Inbound,
        commands: &["version", "sendaddrv2", "verack", "getaddr"],
        relay: false, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["floresta-0.9.1-inbound-v2"],
        family: Family::Floresta,
        direction: RowDirection::Inbound,
        commands: &["version", "sendaddrv2", "verack", "feefilter", "getaddr"],
        relay: false, services_zero: false, protocol_version: None,
    },
    Row {
        captures: &["bitcoin-seeder-92d2b46-inbound", "bitcoin-seeder-92d2b46-inbound-v2"],
        family: Family::BitcoinSeeder,
        direction: RowDirection::Inbound,
        commands: &["version", "verack", "getaddr"],
        relay: false, services_zero: true, protocol_version: Some(60000),
    },
    Row {
        captures: &["bitnodes-036dc5c-inbound", "bitnodes-036dc5c-inbound-v2"],
        family: Family::Bitnodes,
        direction: RowDirection::Inbound,
        commands: &["version", "sendaddrv2", "verack", "getaddr"],
        relay: false, services_zero: true, protocol_version: None,
    },
];

/// How long after it connects a peer's transcript counts as settled though
/// still open: the capture's own wait before its first probe. A peer that
/// has sent nothing beyond `verack` by then (btcd when we dial it) has shown
/// its whole shape.
pub const SETTLE_SECS: u64 = 10;

/// The row a transcript matches, if any.
pub fn matching_row(inbound: bool, capture: &HandshakeCapture, version: &VersionFields) -> Option<&'static Row> {
    TABLE.iter().find(|row| {
        row.direction.admits(inbound)
            && capture.commands().eq(row.commands.iter().copied())
            && row.matches_version(version)
    })
}

/// Judge a peer. `settled` is whether its transcript is final though still
/// open: it has been connected [`SETTLE_SECS`], or the connection ended. An
/// open, unsettled transcript is [`Fingerprint::Unknown`] for now.
pub fn classify(
    inbound: bool,
    capture: &HandshakeCapture,
    version: Option<&VersionFields>,
    settled: bool,
) -> Fingerprint {
    let Some(version) = version else {
        return Fingerprint::Unknown;
    };
    if capture.is_open() && !settled {
        return Fingerprint::Unknown;
    }
    let Some(row) = matching_row(inbound, capture, version) else {
        return Fingerprint::Unknown;
    };
    let observed = row.family;
    match Family::claimed_by(&version.user_agent) {
        Some(claimed) if claimed != observed => Fingerprint::Mismatch { claimed, observed },
        _ => {
            let shared = TABLE.iter().any(|other| {
                other.family != observed && other.direction.admits(inbound) && other.commands == row.commands
            });
            Fingerprint::Known(observed, if shared { Confidence::Low } else { Confidence::High })
        }
    }
}

// ---- Crawl sessions ----
//
// A crawl session's `version` is not a node's (services 0, relay off, a
// crawler's user agent), and peers answer it differently: none sends
// `getheaders` to services 0, and Core leaves a `getdata` unanswered on a
// connection that set relay off. So crawl sessions are judged against rows
// of their own, from captures of each implementation greeted as a crawl
// greets it (`contrib/peer-fingerprint/fixtures/crawl`). A crawl session
// also sees more than the survey's transcript: the BIP 324 greeting, the
// probes' answers and the `getaddr` answer, and its rows pin what every
// capture showed of them.

/// The message a `getaddr` answer came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrKind {
    Addr,
    AddrV2,
}

impl AddrKind {
    pub fn name(self) -> &'static str {
        match self {
            AddrKind::Addr => "addr",
            AddrKind::AddrV2 => "addrv2",
        }
    }
}

/// What a crawl session saw beyond the transcript and the `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CrawlFeatures {
    /// What the peer sent inside BIP 324 before its first message; `None`
    /// over v1.
    pub v2: Option<V2Greeting>,
    /// The probes' outcomes; a probe not sent is `None`.
    pub probes: ProbeResults,
    /// The message the `getaddr` answer came in; `None` when no `getaddr`
    /// was sent or no answer came.
    pub getaddr: Option<AddrKind>,
}

/// The transports a crawl row's implementation completed the handshake on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transports {
    /// v1 and BIP 324, with the same shape.
    Both,
    /// BIP 324 only: it closed our v1 connection before its `version`.
    V2Only,
}

impl Transports {
    fn admits(self, v2: bool) -> bool {
        match self {
            Transports::Both => true,
            Transports::V2Only => v2,
        }
    }
}

/// How a probe was answered in a crawl row's captures. A disconnect
/// matches no row: no capture shows one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Answered,
    Silent,
    /// Not pinned: whether an answer comes depends on the peer's state or
    /// on timing (`getheaders` from a node in initial block download, a
    /// `pong` over a slow path), not on its implementation.
    Either,
}

impl Answer {
    fn admits(self, outcome: ProbeOutcome) -> bool {
        matches!(
            (self, outcome),
            (Answer::Answered, ProbeOutcome::Answered(_))
                | (Answer::Silent, ProbeOutcome::Silent)
                | (Answer::Either, ProbeOutcome::Answered(_) | ProbeOutcome::Silent)
        )
    }
}

/// One shape measured against the crawl's `version`. Every feature is as
/// its captures show it; a feature the session did not measure (no probes
/// on a liveness session, no BIP 324 greeting over v1, no `getaddr`
/// answer) is not held against a row.
#[derive(Debug)]
pub struct CrawlRow {
    /// The captures it comes from, as names under `fixtures/crawl` without
    /// `.json`.
    pub captures: &'static [&'static str],
    pub family: Family,
    pub commands: &'static [&'static str],
    pub relay: bool,
    pub services_zero: bool,
    pub protocol_version: Option<u32>,
    pub transports: Transports,
    /// Inside BIP 324: decoy packets before the version packet.
    pub v2_decoys: bool,
    /// Inside BIP 324: a version packet with contents.
    pub v2_version_contents: bool,
    /// The probes' answers, in [`Probe::ALL`]'s order.
    pub probes: [Answer; 4],
    /// The message the `getaddr` answer comes in.
    pub getaddr: AddrKind,
}

impl CrawlRow {
    fn matches_version(&self, v: &VersionFields) -> bool {
        v.relay == self.relay
            && (v.services == 0) == self.services_zero
            && self.protocol_version.is_none_or(|p| p == v.protocol_version)
    }

    /// Everything but the `version` fields agrees with this row.
    fn admits_session(&self, capture: &HandshakeCapture, f: &CrawlFeatures) -> bool {
        capture.commands().eq(self.commands.iter().copied()) && self.admits_features(f)
    }

    /// The BIP 324 greeting, the probes and the `getaddr` answer agree.
    fn admits_features(&self, f: &CrawlFeatures) -> bool {
        self.transports.admits(f.v2.is_some())
            && f.v2.is_none_or(|g| (g.decoys > 0) == self.v2_decoys && (g.version_len > 0) == self.v2_version_contents)
            && Probe::ALL
                .iter()
                .zip(self.probes)
                .all(|(p, answer)| f.probes.get(*p).is_none_or(|o| answer.admits(o)))
            && f.getaddr.is_none_or(|k| k == self.getaddr)
    }
}

/// The shapes measured against the crawl's `version`. Captures with no
/// row: those in which the implementation sent no `version` (rbitcoin
/// closing our v1 connection). Knots, btcd, bcoin and libbitcoin have no
/// crawl-shape capture yet, so no row: a crawl session to one is unknown.
#[rustfmt::skip]
pub const CRAWL_TABLE: &[CrawlRow] = &[
    CrawlRow {
        captures: &[
            "core-32.1-outbound-crawl", "core-32.1-outbound-crawl-v2",
            "core-24.0.1-outbound-crawl", "core-24.0.1-outbound-crawl-v2",
        ],
        family: Family::Core,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct", "ping"],
        relay: true, services_zero: false, protocol_version: None,
        transports: Transports::Both,
        v2_decoys: false, v2_version_contents: false,
        // Core leaves the unknown transaction unanswered when we set relay
        // off, as every capture shows, but not when its operator grants us
        // relay (`-whitelist` with the relay permission): live Core nodes
        // of 30.x to 32.1 answered it. So it is not pinned.
        probes: [Answer::Either, Answer::Either, Answer::Either, Answer::Silent],
        getaddr: AddrKind::AddrV2,
    },
    CrawlRow {
        captures: &["satd-0.8.0-pre-outbound-crawl", "satd-0.8.0-pre-outbound-crawl-v2"],
        family: Family::Satd,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct", "feefilter", "ping"],
        relay: true, services_zero: false, protocol_version: None,
        transports: Transports::Both,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: AddrKind::AddrV2,
    },
    CrawlRow {
        // The v1 capture shows rbitcoin closing the connection before its
        // `version`: hence v2 only.
        captures: &["rbitcoin-0.8.99-outbound-crawl-v2"],
        family: Family::Rbitcoin,
        commands: &["version", "wtxidrelay", "sendaddrv2", "verack", "sendheaders", "sendcmpct", "ping"],
        relay: true, services_zero: false, protocol_version: None,
        transports: Transports::V2Only,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: AddrKind::AddrV2,
    },
];

/// The crawl row a session matches, if any.
pub fn matching_crawl_row(
    capture: &HandshakeCapture,
    version: &VersionFields,
    features: &CrawlFeatures,
) -> Option<&'static CrawlRow> {
    matching_crawl_row_in(CRAWL_TABLE, capture, version, features)
}

fn matching_crawl_row_in<'t>(
    table: &'t [CrawlRow],
    capture: &HandshakeCapture,
    version: &VersionFields,
    features: &CrawlFeatures,
) -> Option<&'t CrawlRow> {
    table.iter().find(|row| row.admits_session(capture, features) && row.matches_version(version))
}

/// Judge a crawl session, once it has ended, against [`CRAWL_TABLE`]. The
/// result is read as [`classify`]'s is, except that `high` also covers a
/// shape another family's row shares the commands of when the session's
/// BIP 324 greeting, probes or `getaddr` answer ruled that row out; `low`
/// is left for the shapes only the `version` fields told apart.
pub fn classify_crawl(
    capture: &HandshakeCapture,
    version: Option<&VersionFields>,
    features: &CrawlFeatures,
) -> Fingerprint {
    classify_crawl_in(CRAWL_TABLE, capture, version, features)
}

fn classify_crawl_in(
    table: &[CrawlRow],
    capture: &HandshakeCapture,
    version: Option<&VersionFields>,
    features: &CrawlFeatures,
) -> Fingerprint {
    let Some(version) = version else {
        return Fingerprint::Unknown;
    };
    let Some(row) = matching_crawl_row_in(table, capture, version, features) else {
        return Fingerprint::Unknown;
    };
    let observed = row.family;
    match Family::claimed_by(&version.user_agent) {
        Some(claimed) if claimed != observed => Fingerprint::Mismatch { claimed, observed },
        _ => {
            let only_version_tells = table.iter().any(|other| {
                other.family != observed && other.commands == row.commands && other.admits_features(features)
            });
            Fingerprint::Known(observed, if only_version_tells { Confidence::Low } else { Confidence::High })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::behavior::replay_fixture;

    /// Fixture replay: every capture a row names classifies as that row's
    /// family, every capture under `contrib/peer-fingerprint/fixtures` that
    /// no row names classifies as unknown, and every name a row lists is a
    /// capture. Each capture is also tried against every other row: it
    /// matches its own and no other.
    #[test]
    fn every_capture_classifies_as_its_own_family_and_no_other() {
        let names = crate::net::behavior::fixture_names();
        for row in TABLE {
            for capture in row.captures {
                assert!(names.iter().any(|n| n == capture), "row names {capture}, which is not a capture");
            }
        }
        for name in &names {
            let r = replay_fixture(name);
            let got = classify(r.inbound, &r.capture, r.version.as_ref(), true);
            let own: Vec<&Row> = TABLE.iter().filter(|row| row.captures.contains(&name.as_str())).collect();
            assert!(own.len() <= 1, "{name} is named by {} rows", own.len());
            match own.first() {
                Some(row) => {
                    assert_eq!(got.observed(), Some(row.family), "{name}");
                    assert!(matches!(got, Fingerprint::Known(..)), "{name}: its own agent, so no mismatch: {got:?}");
                    let v = r.version.as_ref().unwrap();
                    let hits: Vec<&Row> = TABLE
                        .iter()
                        .filter(|other| {
                            other.direction.admits(r.inbound)
                                && r.capture.commands().eq(other.commands.iter().copied())
                                && other.matches_version(v)
                        })
                        .collect();
                    assert_eq!(hits.len(), 1, "{name} matches {} rows", hits.len());
                }
                None => assert_eq!(got, Fingerprint::Unknown, "{name} has no row"),
            }
        }
    }

    /// The families the captures could not tell apart by commands alone
    /// (btcd, Floresta and bitnodes dialing us) are told apart by their
    /// `version` fields, and say so with a low confidence.
    #[test]
    fn a_shape_shared_by_families_is_known_with_low_confidence() {
        for (name, family) in [
            ("btcd-0.27.0-inbound", Family::Btcd),
            ("floresta-0.9.1-inbound", Family::Floresta),
            ("bitnodes-036dc5c-inbound", Family::Bitnodes),
        ] {
            let r = replay_fixture(name);
            assert_eq!(classify(true, &r.capture, r.version.as_ref(), true), Fingerprint::Known(family, Confidence::Low));
        }
        let r = replay_fixture("core-31.2-inbound");
        assert_eq!(
            classify(true, &r.capture, r.version.as_ref(), true),
            Fingerprint::Known(Family::Core, Confidence::High)
        );
    }

    /// A Core user agent on btcd's handshake is a mismatch; Knots is Core.
    #[test]
    fn a_user_agent_naming_another_family_is_a_mismatch() {
        let r = replay_fixture("btcd-0.27.0-inbound");
        let mut v = r.version.clone().unwrap();
        v.user_agent = "/Satoshi:31.2.0/".into();
        assert_eq!(
            classify(true, &r.capture, Some(&v), true),
            Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }
        );
        // A user agent naming no family is not a claim.
        v.user_agent = "/whatever:1.0/".into();
        assert_eq!(classify(true, &r.capture, Some(&v), true), Fingerprint::Known(Family::Btcd, Confidence::Low));

        let r = replay_fixture("knots-29.4.3.knots20260508-outbound");
        assert_eq!(
            classify(false, &r.capture, r.version.as_ref(), true),
            Fingerprint::Known(Family::Core, Confidence::High)
        );
    }

    /// The direction is part of the shape: Core dialing us and Core dialed
    /// by us send different transcripts, and neither matches the other row.
    #[test]
    fn a_shape_from_the_other_direction_is_unknown() {
        let r = replay_fixture("core-31.2-outbound");
        assert_eq!(classify(true, &r.capture, r.version.as_ref(), true), Fingerprint::Unknown);
        let r = replay_fixture("btcd-0.27.0-inbound");
        assert_eq!(classify(false, &r.capture, r.version.as_ref(), true), Fingerprint::Unknown);
    }

    /// An open transcript is judged only once settled.
    #[test]
    fn an_open_transcript_waits_until_settled() {
        let r = replay_fixture("btcd-0.27.0-outbound");
        assert!(r.capture.is_open(), "btcd sends nothing past verack");
        assert_eq!(classify(false, &r.capture, r.version.as_ref(), false), Fingerprint::Unknown);
        assert_eq!(
            classify(false, &r.capture, r.version.as_ref(), true),
            Fingerprint::Known(Family::Btcd, Confidence::High)
        );
        // A closed one needs no wait.
        let r = replay_fixture("core-31.2-inbound");
        assert!(!r.capture.is_open());
        assert_eq!(classify(true, &r.capture, r.version.as_ref(), false).observed(), Some(Family::Core));
    }

    /// A pre-70016 shape pins its protocol version, so an old Core dialing
    /// us with `version verack getaddr` is not taken for the seeder.
    #[test]
    fn a_shape_without_negotiation_pins_its_protocol_version() {
        let r = replay_fixture("bitcoin-seeder-92d2b46-inbound");
        let mut v = r.version.clone().unwrap();
        assert_eq!(classify(true, &r.capture, Some(&v), true).observed(), Some(Family::BitcoinSeeder));
        v.protocol_version = 70015;
        assert_eq!(classify(true, &r.capture, Some(&v), true), Fingerprint::Unknown);
    }

    // ---- Crawl rows ----

    use crate::net::behavior::{crawl_fixture_names, replay_crawl_fixture};

    fn crawl(name: &str) -> Fingerprint {
        let (r, f) = replay_crawl_fixture(name);
        classify_crawl(&r.capture, r.version.as_ref(), &f)
    }

    /// Crawl fixture replay: every crawl-shape capture with a `version` is
    /// named by exactly one crawl row and classifies as that row's family
    /// with high confidence, no other row admits it, and a capture with no
    /// `version` (the node refused us) is named by none and is unknown.
    /// Every name a row lists is a crawl capture.
    #[test]
    fn every_crawl_capture_classifies_as_its_own_family_and_no_other() {
        let names = crawl_fixture_names();
        assert!(names.len() >= 8, "the crawl captures: {names:?}");
        for row in CRAWL_TABLE {
            for capture in row.captures {
                assert!(names.iter().any(|n| n == capture), "crawl row names {capture}, which is not a crawl capture");
            }
        }
        for name in &names {
            let (r, f) = replay_crawl_fixture(name);
            let got = classify_crawl(&r.capture, r.version.as_ref(), &f);
            let own: Vec<&CrawlRow> = CRAWL_TABLE.iter().filter(|row| row.captures.contains(&name.as_str())).collect();
            let Some(v) = r.version.as_ref() else {
                assert!(own.is_empty(), "{name} has no version, so no row");
                assert_eq!(got, Fingerprint::Unknown, "{name}");
                continue;
            };
            assert_eq!(own.len(), 1, "{name} is named by {} crawl rows", own.len());
            assert_eq!(got, Fingerprint::Known(own[0].family, Confidence::High), "{name}");
            let hits = CRAWL_TABLE.iter().filter(|row| row.admits_session(&r.capture, &f) && row.matches_version(v)).count();
            assert_eq!(hits, 1, "{name} matches {hits} crawl rows");
        }
    }

    /// The crawl rows are the crawl's: the survey's table does not know
    /// satd greeted as a crawler (no `getheaders` to services 0), and the
    /// crawl's table does not know a node greeted as a node.
    #[test]
    fn crawl_shapes_and_node_shapes_are_judged_by_their_own_tables() {
        let (r, _) = replay_crawl_fixture("satd-0.8.0-pre-outbound-crawl");
        assert_eq!(classify(false, &r.capture, r.version.as_ref(), true), Fingerprint::Unknown);
        assert_eq!(crawl("satd-0.8.0-pre-outbound-crawl"), Fingerprint::Known(Family::Satd, Confidence::High));
        let r = replay_fixture("satd-0.7.0-outbound");
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &CrawlFeatures::default()), Fingerprint::Unknown);
    }

    /// The `getdata` probe pins the satd and rbitcoin rows, which send
    /// `notfound`, silence is no capture of theirs. Core's row leaves it
    /// open: Core is silent on a connection that set relay off unless its
    /// operator grants relay, and then answers.
    #[test]
    fn a_crawl_shape_with_a_probe_answer_its_captures_never_gave_is_unknown() {
        for name in ["core-32.1-outbound-crawl", "core-24.0.1-outbound-crawl-v2"] {
            let (r, mut f) = replay_crawl_fixture(name);
            f.probes.set(Probe::GetData, ProbeOutcome::Answered(1));
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Known(Family::Core, Confidence::High), "{name}");
        }
        for (name, flipped) in [
            ("satd-0.8.0-pre-outbound-crawl", ProbeOutcome::Silent),
            ("rbitcoin-0.8.99-outbound-crawl-v2", ProbeOutcome::Silent),
        ] {
            let (r, mut f) = replay_crawl_fixture(name);
            f.probes.set(Probe::GetData, flipped);
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Unknown, "{name}");
        }
        // The unknown message: every capture leaves it unanswered.
        let (r, mut f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        f.probes.set(Probe::Unknown, ProbeOutcome::Answered(0));
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Unknown);
        // A disconnect on any probe matches no row.
        for p in Probe::ALL {
            let (r, mut f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
            f.probes.set(p, ProbeOutcome::Disconnected);
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Unknown, "{}", p.name());
        }
        // `ping` and `getheaders` are not pinned: a slow pong or a node in
        // initial block download keeping quiet is no other implementation.
        let (r, mut f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        f.probes.set(Probe::Ping, ProbeOutcome::Silent);
        f.probes.set(Probe::GetHeaders, ProbeOutcome::Silent);
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Known(Family::Core, Confidence::High));
        // A session that sent no probe is judged on the rest.
        let (r, mut f) = replay_crawl_fixture("satd-0.8.0-pre-outbound-crawl-v2");
        f.probes = ProbeResults::default();
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Known(Family::Satd, Confidence::High));
    }

    /// No capture shows a decoy packet or a version packet with contents;
    /// the garbage length is random per connection and is not pinned.
    #[test]
    fn a_v2_greeting_its_captures_never_showed_is_unknown() {
        for name in ["core-32.1-outbound-crawl-v2", "satd-0.8.0-pre-outbound-crawl-v2", "rbitcoin-0.8.99-outbound-crawl-v2"] {
            let (r, f) = replay_crawl_fixture(name);
            let mut g = f.v2.expect("a v2 capture");
            g.decoys = 1;
            let decoy = CrawlFeatures { v2: Some(g), ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &decoy), Fingerprint::Unknown, "{name}");
            let mut g = f.v2.unwrap();
            g.version_len = 4;
            let contents = CrawlFeatures { v2: Some(g), ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &contents), Fingerprint::Unknown, "{name}");
            for garbage_len in [0, 4095] {
                let mut g = f.v2.unwrap();
                g.garbage_len = garbage_len;
                let any = CrawlFeatures { v2: Some(g), ..f };
                assert!(matches!(classify_crawl(&r.capture, r.version.as_ref(), &any), Fingerprint::Known(..)), "{name}");
            }
        }
    }

    /// rbitcoin closes a v1 connection before its `version`, so its shape
    /// over v1 is no capture's; Core's and satd's are the same over both.
    #[test]
    fn a_v2_only_shape_over_v1_is_unknown() {
        let (r, f) = replay_crawl_fixture("rbitcoin-0.8.99-outbound-crawl-v2");
        let v1 = CrawlFeatures { v2: None, ..f };
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &v1), Fingerprint::Unknown);
        let (r, f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        let v1 = CrawlFeatures { v2: None, ..f };
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &v1), Fingerprint::Known(Family::Core, Confidence::High));
    }

    /// Every capture answered `getaddr` in `addrv2`, as it was asked to;
    /// a legacy `addr` answer is no capture's.
    #[test]
    fn a_legacy_addr_answer_is_unknown() {
        for name in ["core-24.0.1-outbound-crawl", "satd-0.8.0-pre-outbound-crawl", "rbitcoin-0.8.99-outbound-crawl-v2"] {
            let (r, f) = replay_crawl_fixture(name);
            let addr = CrawlFeatures { getaddr: Some(AddrKind::Addr), ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &addr), Fingerprint::Unknown, "{name}");
            let none = CrawlFeatures { getaddr: None, ..f };
            assert!(matches!(classify_crawl(&r.capture, r.version.as_ref(), &none), Fingerprint::Known(..)), "{name}");
        }
    }

    /// A user agent naming another family on a crawl shape is a mismatch.
    #[test]
    fn a_crawl_shape_under_another_familys_user_agent_is_a_mismatch() {
        let (r, f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        let mut v = r.version.clone().unwrap();
        v.user_agent = "/satd:0.8.0/".into();
        assert_eq!(
            classify_crawl(&r.capture, Some(&v), &f),
            Fingerprint::Mismatch { claimed: Family::Satd, observed: Family::Core }
        );
        v.user_agent = "/Satoshi:29.4.3/Knots:20260508/".into();
        assert_eq!(classify_crawl(&r.capture, Some(&v), &f), Fingerprint::Known(Family::Core, Confidence::High));
    }

    /// Where two families' crawl rows share the commands, a session whose
    /// probe answers rule one out is `high`: the survey, which sends no
    /// probe before it judges, can only be `low` there. Only the `version`
    /// fields telling them apart is `low`. (A table built for the test: no
    /// two captured families share crawl commands.)
    #[test]
    fn a_probe_answer_that_tells_families_apart_is_high_confidence() {
        let base = &CRAWL_TABLE[1];
        let table = [
            CrawlRow { captures: &[], family: Family::Satd, ..*base },
            CrawlRow { captures: &[], family: Family::Btcd, probes: [Answer::Either, Answer::Either, Answer::Silent, Answer::Silent], ..*base },
            CrawlRow { captures: &[], family: Family::Bcoin, protocol_version: Some(1), ..*base },
        ];
        let (r, f) = replay_crawl_fixture("satd-0.8.0-pre-outbound-crawl");
        // btcd's row is ruled out by the notfound, bcoin's only by the protocol version.
        assert_eq!(classify_crawl_in(&table, &r.capture, r.version.as_ref(), &f), Fingerprint::Known(Family::Satd, Confidence::Low));
        assert_eq!(
            classify_crawl_in(&table[..2], &r.capture, r.version.as_ref(), &f),
            Fingerprint::Known(Family::Satd, Confidence::High)
        );
        // Without the probe nothing but the version could tell them apart.
        let unprobed = CrawlFeatures { probes: ProbeResults::default(), ..f };
        assert_eq!(
            classify_crawl_in(&table[..2], &r.capture, r.version.as_ref(), &unprobed),
            Fingerprint::Known(Family::Satd, Confidence::Low)
        );
    }

    #[test]
    fn user_agents_name_their_family() {
        for (ua, family) in [
            ("/Satoshi:31.2.0/", Some(Family::Core)),
            ("/Satoshi:29.4.3/Knots:20260508/", Some(Family::Core)),
            ("/btcwire:0.5.0/btcd:0.27.0/", Some(Family::Btcd)),
            ("/bcoin:2.2.0/", Some(Family::Bcoin)),
            ("/libbitcoin:3.8.0/", Some(Family::Libbitcoin)),
            ("/Floresta:0.9.1/", Some(Family::Floresta)),
            ("/rbitcoin:0.8.0/", Some(Family::Rbitcoin)),
            ("/satd:0.7.0/", Some(Family::Satd)),
            ("/bitcoin-seeder:0.01/", Some(Family::BitcoinSeeder)),
            ("/bitnodes.io:0.3/", Some(Family::Bitnodes)),
            ("/Satoshi:31.2.0(comment)/", Some(Family::Core)),
            ("/other:1/", None),
            ("", None),
        ] {
            assert_eq!(Family::claimed_by(ua), family, "{ua}");
        }
    }
}
