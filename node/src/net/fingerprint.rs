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
//! Crawl sessions are judged by [`classify_crawl`] against
//! [`CRAWL_TABLE`], whose rows match a family's traits rather than one
//! release's transcript; with no row matching, it reports the family the
//! user agent names at [`Confidence::Claimed`], which is never an observed
//! family ([`Fingerprint::observed`]). [`classify`] never claims.
//!
//! Knots and the other Core forks share Core's networking code and are the
//! [`Family::Core`] family.

use std::fmt;

use crate::net::behavior::{is_handshake_announcement, HandshakeCapture, VersionFields};
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
    /// No row matched: the family is the one the user agent names, and
    /// nothing the peer did confirmed it. Only crawl sessions are judged so
    /// ([`classify_crawl`]). A claimed family is never an observed one
    /// ([`Fingerprint::observed`]), and never a mismatch.
    Claimed,
}

impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Low => "low",
            Confidence::Claimed => "claimed",
        }
    }
}

/// What [`classify`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Fingerprint {
    /// The transcript matches this family's row, and the user agent names
    /// it or no family at all; or, at [`Confidence::Claimed`], no row
    /// matches and the user agent names this family.
    Known(Family, Confidence),
    /// No row matches (and, for a crawl session, the user agent names no
    /// family), or the transcript is not settled yet.
    #[default]
    Unknown,
    /// The user agent names one family and the transcript matches another.
    Mismatch { claimed: Family, observed: Family },
}

impl Fingerprint {
    /// The family the transcript matched, whatever the user agent says.
    /// `None` for [`Confidence::Claimed`]: a user agent is not an
    /// observation.
    pub fn observed(&self) -> Option<Family> {
        match *self {
            Fingerprint::Known(_, Confidence::Claimed) => None,
            Fingerprint::Known(f, _) => Some(f),
            Fingerprint::Mismatch { observed, .. } => Some(observed),
            Fingerprint::Unknown => None,
        }
    }

    /// The family of a [`Confidence::Claimed`] result: no row matched, and
    /// the user agent names it. `None` for every other result.
    pub fn claimed_only(&self) -> Option<Family> {
        match *self {
            Fingerprint::Known(f, Confidence::Claimed) => Some(f),
            _ => None,
        }
    }
}

impl fmt::Display for Fingerprint {
    /// `core/high`, `core/claimed`, `unknown`, or
    /// `mismatch(claimed=core,observed=btcd)`.
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
// greets it (`contrib/peer-fingerprint/fixtures/crawl`). A crawl row
// names the traits that set its family apart, checked against captures of
// two or more releases, so another release with the same traits matches
// too. A crawl session also sees more than the survey's transcript: the
// BIP 324 greeting, the probes' answers and the `getaddr` answer, and its
// rows hold what no capture contradicted of them. A session no row
// matches reports the family its user agent names at
// [`Confidence::Claimed`], never counted as observed.

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
    /// v1 only: it failed our BIP 324 attempt, and the v1 redial completed.
    V1Only,
}

impl Transports {
    fn admits(self, v2: bool) -> bool {
        match self {
            Transports::Both => true,
            Transports::V2Only => v2,
            Transports::V1Only => !v2,
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

/// A crawl session's transcript cut at its `verack`: what the peer sent
/// between its `version` and its `verack` (the feature negotiation), the
/// announcements it sent after `verack`, and the first other message after
/// them.
#[derive(Debug)]
struct Phases {
    negotiation: Vec<String>,
    announcements: Vec<String>,
    /// The first message after the announcements; `None` when none came
    /// before the session ended, so the announcements may be incomplete.
    then: Option<String>,
}

impl Phases {
    /// `None` for a transcript with no `verack` (a session judged before
    /// its handshake completed matches no row).
    fn of(capture: &HandshakeCapture) -> Option<Phases> {
        let commands: Vec<String> = capture.commands().collect();
        if commands.first().map(String::as_str) != Some("version") {
            return None;
        }
        let verack = commands.iter().position(|c| c == "verack")?;
        let rest = &commands[verack + 1..];
        let end = rest.iter().position(|c| !is_handshake_announcement(c)).unwrap_or(rest.len());
        Some(Phases {
            negotiation: commands[1..verack].to_vec(),
            announcements: rest[..end].to_vec(),
            then: rest.get(end).cloned(),
        })
    }
}

/// One trait a crawl row requires of a session.
///
/// A crawl session records what the node sends unprompted: the handshake
/// and the passive wait after it. Answers to the crawl's own `getaddr` and
/// probes are not recorded, so an answer can never stand in for an
/// unprompted message (a node answering `getaddr` with `addr` must not pass
/// for bcoin's `Then("addr")`). A node whose first message after its
/// announcements comes only after the passive wait has no `then`: the
/// traits that need it do not hold, and the session falls to `Claimed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trait {
    /// Sends this message between its `version` and its `verack`.
    Negotiates(&'static str),
    /// Sends no such message between its `version` and its `verack`.
    NeverNegotiates(&'static str),
    /// Sends this announcement after `verack`, before any other message.
    Announces(&'static str),
    /// Sends no such announcement before its first other message after
    /// `verack`. Holds only once that message came: until then the
    /// announcements may not be complete.
    NeverAnnounces(&'static str),
    /// Its first message after `verack` and its announcements, within
    /// the passive wait.
    Then(&'static str),
    /// The protocol version of its `version`.
    Protocol(u32),
    /// The `relay` flag of its `version`.
    Relay(bool),
}

impl Trait {
    /// A trait of the `version` fields, which alone make a match `low`.
    fn of_version(self) -> bool {
        matches!(self, Trait::Protocol(_) | Trait::Relay(_))
    }

    fn holds(self, p: &Phases, v: &VersionFields) -> bool {
        let has = |list: &[String], cmd: &str| list.iter().any(|c| c == cmd);
        match self {
            Trait::Negotiates(cmd) => has(&p.negotiation, cmd),
            Trait::NeverNegotiates(cmd) => !has(&p.negotiation, cmd),
            Trait::Announces(cmd) => has(&p.announcements, cmd),
            Trait::NeverAnnounces(cmd) => p.then.is_some() && !has(&p.announcements, cmd),
            Trait::Then(cmd) => p.then.as_deref() == Some(cmd),
            Trait::Protocol(n) => v.protocol_version == n,
            Trait::Relay(r) => v.relay == r,
        }
    }
}

/// One family's shape as greeted by the crawl's `version`: the traits that
/// set it apart from every other family's, checked against captures of
/// two or three releases of it, rather than the whole transcript of one.
/// A message, field or answer no trait names (`ping` timing, whether
/// `feefilter` comes, a `getblocks`) is left open, so other releases match.
///
/// Besides its traits a row states what no capture of it contradicted: the
/// transports it completed a handshake on, its BIP 324 greeting, its probe
/// answers and the message of its `getaddr` answer. A feature the session
/// did not measure (no probes on a liveness session, no BIP 324 greeting
/// over v1, no `getaddr` answer) is not held against a row.
#[derive(Debug)]
pub struct CrawlRow {
    /// The captures it was checked against, as names under
    /// `fixtures/crawl` without `.json`.
    pub captures: &'static [&'static str],
    pub family: Family,
    /// Every one must hold.
    pub traits: &'static [Trait],
    pub transports: Transports,
    /// Inside BIP 324: decoy packets before the version packet.
    pub v2_decoys: bool,
    /// Inside BIP 324: a version packet with contents.
    pub v2_version_contents: bool,
    /// The probes' answers, in [`Probe::ALL`]'s order.
    pub probes: [Answer; 4],
    /// The message the `getaddr` answer comes in; `None` when no capture
    /// got an answer (btcd, bcoin, libbitcoin: nothing seeds their address
    /// books over RPC, so they had nothing to give), and so it is not
    /// pinned.
    pub getaddr: Option<AddrKind>,
}

impl CrawlRow {
    fn matches_version(&self, p: &Phases, v: &VersionFields) -> bool {
        self.traits.iter().filter(|t| t.of_version()).all(|t| t.holds(p, v))
    }

    /// Every trait but the `version` fields' holds, and the features agree.
    fn admits_session(&self, p: &Phases, v: &VersionFields, f: &CrawlFeatures) -> bool {
        self.traits.iter().filter(|t| !t.of_version()).all(|t| t.holds(p, v)) && self.admits_features(f)
    }

    /// The BIP 324 greeting, the probes and the `getaddr` answer agree.
    fn admits_features(&self, f: &CrawlFeatures) -> bool {
        self.transports.admits(f.v2.is_some())
            && f.v2.is_none_or(|g| (g.decoys > 0) == self.v2_decoys && (g.version_len > 0) == self.v2_version_contents)
            && Probe::ALL
                .iter()
                .zip(self.probes)
                .all(|(p, answer)| f.probes.get(*p).is_none_or(|o| answer.admits(o)))
            && f.getaddr.is_none_or(|k| self.getaddr.is_none_or(|g| g == k))
    }
}

/// The families' shapes against the crawl's `version`, one row each, in
/// no particular order: every capture matches its own family's row and no
/// other (the fixture replay test). Captures with no row: those in which
/// the implementation sent no `version` (rbitcoin closing our v1
/// connection, bcoin refusing the v1 redial after banning us for the v2
/// attempt). Knots shares Core's row, as it shares Core's networking code.
#[rustfmt::skip]
pub const CRAWL_TABLE: &[CrawlRow] = &[
    CrawlRow {
        captures: &[
            "core-24.0.1-outbound-crawl", "core-24.0.1-outbound-crawl-v2",
            "core-28.1-outbound-crawl", "core-28.1-outbound-crawl-v2",
            "core-31.1-outbound-crawl", "core-31.1-outbound-crawl-v2",
            "core-32.1-outbound-crawl", "core-32.1-outbound-crawl-v2",
            "knots-28.1.knots20250305-outbound-crawl", "knots-28.1.knots20250305-outbound-crawl-v2",
            "knots-29.5.1.knots20260508-outbound-crawl", "knots-29.5.1.knots20260508-outbound-crawl-v2",
        ],
        family: Family::Core,
        // Both negotiation messages, then `sendcmpct` alone before its
        // first other message (`ping` in every capture): no `feefilter`
        // before it, which sets satd apart, and no `sendheaders`, which
        // sets rbitcoin apart.
        traits: &[
            Trait::Negotiates("wtxidrelay"), Trait::Negotiates("sendaddrv2"),
            Trait::Announces("sendcmpct"), Trait::NeverAnnounces("feefilter"), Trait::NeverAnnounces("sendheaders"),
        ],
        transports: Transports::Both,
        v2_decoys: false, v2_version_contents: false,
        // Core leaves the unknown transaction unanswered when we set relay
        // off, as the Core captures show, but not when its operator grants
        // us relay (`-whitelist` with the relay permission): live Core
        // nodes of 30.x to 32.1 answered it, and Knots 28.1 answers it
        // anyway. So it is not pinned.
        probes: [Answer::Either, Answer::Either, Answer::Either, Answer::Silent],
        getaddr: Some(AddrKind::AddrV2),
    },
    CrawlRow {
        // satd since 0.8: no `getheaders` to services 0, and `feefilter`
        // before its first other message (`ping`), where Core sends it
        // after. No release has this shape yet: both captures are of the
        // development tree.
        captures: &["satd-0.8.0-pre-outbound-crawl", "satd-0.8.0-pre-outbound-crawl-v2"],
        family: Family::Satd,
        traits: &[
            Trait::Negotiates("wtxidrelay"), Trait::Negotiates("sendaddrv2"),
            Trait::Announces("sendcmpct"), Trait::Announces("feefilter"), Trait::NeverAnnounces("sendheaders"),
        ],
        transports: Transports::Both,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: Some(AddrKind::AddrV2),
    },
    CrawlRow {
        // satd 0.6 and 0.7 ask for headers straight after `verack`, before
        // any announcement, though the crawl's `version` has services 0:
        // no other family's capture does. (0.6.3 gave no `getaddr` answer:
        // its address book took none of the seeded addresses.)
        captures: &[
            "satd-0.6.3-outbound-crawl", "satd-0.6.3-outbound-crawl-v2",
            "satd-0.7.2-outbound-crawl", "satd-0.7.2-outbound-crawl-v2",
        ],
        family: Family::Satd,
        traits: &[Trait::Negotiates("wtxidrelay"), Trait::Negotiates("sendaddrv2"), Trait::Then("getheaders")],
        transports: Transports::Both,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: Some(AddrKind::AddrV2),
    },
    CrawlRow {
        // Every v1 capture shows rbitcoin closing the connection before
        // its `version`: hence v2 only.
        captures: &[
            "rbitcoin-0.8.0-outbound-crawl-v2", "rbitcoin-0.8.99-outbound-crawl-v2", "rbitcoin-0.9.2-outbound-crawl-v2",
        ],
        family: Family::Rbitcoin,
        // `sendheaders` among its announcements: no other family's capture
        // sends it to the crawl.
        traits: &[Trait::Negotiates("wtxidrelay"), Trait::Negotiates("sendaddrv2"), Trait::Announces("sendheaders")],
        transports: Transports::V2Only,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: Some(AddrKind::AddrV2),
    },
        CrawlRow {
        // btcd resets our BIP 324 attempt with nothing sent, and the v1
        // redial completes: hence v1 only. 0.24.2 asks for blocks
        // (`getblocks`) after `verack`, and closes 30 s in when none come,
        // before any probe; 0.25.0 and 0.27.0 send nothing after it.
        captures: &[
            "btcd-0.24.2-outbound-crawl", "btcd-0.24.2-outbound-crawl-v2",
            "btcd-0.25.0-outbound-crawl", "btcd-0.25.0-outbound-crawl-v2",
            "btcd-0.27.0-outbound-crawl", "btcd-0.27.0-outbound-crawl-v2",
        ],
        family: Family::Btcd,
        // `sendaddrv2` with no `wtxidrelay`: btcd negotiates addrv2 but
        // relays transactions by txid.
        traits: &[Trait::Negotiates("sendaddrv2"), Trait::NeverNegotiates("wtxidrelay")],
        transports: Transports::V1Only,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: None,
    },
    CrawlRow {
        // bcoin reads our BIP 324 attempt as v1 messages with a bad magic
        // and bans us, so only the v1 captures have its shape.
        captures: &["bcoin-2.0.0-outbound-crawl", "bcoin-2.1.2-outbound-crawl", "bcoin-2.2.0-outbound-crawl"],
        family: Family::Bcoin,
        // It speaks 70015, so negotiates nothing, and announces its own
        // address straight after `verack`.
        traits: &[Trait::Then("addr"), Trait::Protocol(70015)],
        transports: Transports::V1Only,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Answered, Answer::Silent],
        getaddr: None,
    },
    CrawlRow {
        // libbitcoin answers our BIP 324 attempt with its v1 `version`
        // and closes; the v1 redial completes. It closes the session 60 s
        // in with no `getaddr` answer, before any probe: so no probe
        // answer is pinned.
        captures: &[
            "libbitcoin-3.6.0-outbound-crawl", "libbitcoin-3.6.0-outbound-crawl-v2",
            "libbitcoin-3.8.0-outbound-crawl", "libbitcoin-3.8.0-outbound-crawl-v2",
        ],
        family: Family::Libbitcoin,
        // 70013 with relay off, so nothing negotiated, and its own `ping`
        // straight after `verack`.
        traits: &[
            Trait::NeverNegotiates("wtxidrelay"), Trait::NeverNegotiates("sendaddrv2"), Trait::Then("ping"),
            Trait::Protocol(70013), Trait::Relay(false),
        ],
        transports: Transports::V1Only,
        v2_decoys: false, v2_version_contents: false,
        probes: [Answer::Either, Answer::Either, Answer::Either, Answer::Either],
        getaddr: None,
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
    let phases = Phases::of(capture)?;
    table.iter().find(|row| row.admits_session(&phases, version, features) && row.matches_version(&phases, version))
}

/// Judge a crawl session, once it has ended, against [`CRAWL_TABLE`]. A
/// row's match is read as [`classify`]'s is, except that `high` also covers
/// a session another family's row shares the traits of when its BIP 324
/// greeting, probes or `getaddr` answer ruled that row out; `low` is left
/// for the sessions only the `version` fields told apart.
///
/// With no row matching, a user agent that names a family gives that
/// family at [`Confidence::Claimed`]; one that names none is
/// [`Fingerprint::Unknown`]. A claimed result is never a mismatch: nothing
/// was observed to contradict the claim.
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
    let claimed = Family::claimed_by(&version.user_agent);
    let Some(row) = matching_crawl_row_in(table, capture, version, features) else {
        return claimed.map_or(Fingerprint::Unknown, |f| Fingerprint::Known(f, Confidence::Claimed));
    };
    let observed = row.family;
    match claimed {
        Some(claimed) if claimed != observed => Fingerprint::Mismatch { claimed, observed },
        _ => {
            let phases = Phases::of(capture).expect("a row matched");
            let only_version_tells = table
                .iter()
                .any(|other| other.family != observed && other.admits_session(&phases, version, features));
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

    /// A transcript of these commands, as the node would take them.
    fn transcript<S: AsRef<str>>(commands: &[S]) -> HandshakeCapture {
        let mut c = HandshakeCapture::default();
        for cmd in commands {
            c.observe(cmd.as_ref(), false);
        }
        c
    }

    /// The family a crawl capture's own row names.
    fn own_family(name: &str) -> Family {
        let own: Vec<&CrawlRow> = CRAWL_TABLE.iter().filter(|row| row.captures.contains(&name)).collect();
        assert_eq!(own.len(), 1, "{name} is named by {} crawl rows", own.len());
        own[0].family
    }

    /// Crawl fixture replay: every crawl-shape capture with a `version` is
    /// named by exactly one crawl row and classifies as that row's family,
    /// `high` or `low`, and no other row admits it; a capture with no
    /// `version` (the node refused us) is named by none and is unknown.
    /// Every name a row lists is a crawl capture.
    #[test]
    fn every_crawl_capture_classifies_as_its_own_family_and_no_other() {
        let names = crawl_fixture_names();
        assert!(names.len() >= 38, "the crawl captures: {names:?}");
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
            assert!(
                matches!(got, Fingerprint::Known(f, Confidence::High | Confidence::Low) if f == own[0].family),
                "{name}: {got}"
            );
            let phases = Phases::of(&r.capture).unwrap();
            let hits: Vec<Family> = CRAWL_TABLE
                .iter()
                .filter(|row| row.admits_session(&phases, v, &f) && row.matches_version(&phases, v))
                .map(|row| row.family)
                .collect();
            assert_eq!(hits, [own[0].family], "{name} matches these rows");
        }
    }

    /// Each family's rows were checked against captures of more than one
    /// release of its client: a capture's release is its name less the
    /// direction suffix. (satd has two rows, one per greeting it has
    /// sent; the newer has only the development tree's captures.)
    #[test]
    fn every_crawl_family_was_checked_against_more_than_one_release() {
        let families: std::collections::BTreeSet<Family> = CRAWL_TABLE.iter().map(|r| r.family).collect();
        for family in families {
            let releases: std::collections::BTreeSet<&str> = CRAWL_TABLE
                .iter()
                .filter(|r| r.family == family)
                .flat_map(|r| r.captures.iter())
                .map(|c| c.strip_suffix("-v2").unwrap_or(c).strip_suffix("-outbound-crawl").unwrap())
                .collect();
            assert!(releases.len() >= 2, "{family}: {releases:?}");
        }
    }

    /// A shape no capture shows, but with its family's traits, still
    /// matches by them: what no trait names (the order of the negotiation
    /// messages, an extra one such as Core's `sendtxrcncl` under
    /// `-txreconciliation`, `feefilter` after the first other message, a
    /// newer protocol version, another release's user agent) is left open.
    #[test]
    fn a_perturbed_transcript_still_matches_by_its_traits() {
        type Edit = fn(&mut Vec<String>, &mut VersionFields);
        let cases: &[(&str, &str, Edit)] = &[
            ("core-32.1-outbound-crawl", "erlay, the other order, 70018", |c, v| {
                c.swap(1, 2);
                c.insert(3, "sendtxrcncl".into());
                v.protocol_version = 70018;
                v.user_agent = "/Satoshi:33.0.0/".into();
            }),
            ("knots-29.5.1.knots20260508-outbound-crawl-v2", "a later first message", |c, v| {
                let ping = c.iter().position(|x| x == "ping").unwrap();
                c[ping] = "getheaders".into();
                v.user_agent = "/Satoshi:30.2.0/Knots:20261201/".into();
            }),
            ("satd-0.8.0-pre-outbound-crawl", "feefilter before sendcmpct, 70017", |c, v| {
                c.swap(4, 5);
                v.protocol_version = 70017;
                v.user_agent = "/satd:0.9.0/".into();
            }),
            ("satd-0.7.2-outbound-crawl-v2", "the other negotiation order", |c, v| {
                c.swap(1, 2);
                v.user_agent = "/satd:0.7.3/".into();
            }),
            ("rbitcoin-0.9.2-outbound-crawl-v2", "sendheaders last, a feefilter", |c, v| {
                c.splice(4..6, ["sendcmpct".to_string(), "feefilter".into(), "sendheaders".into()]);
                v.user_agent = "/rbitcoin:0.10.0/".into();
            }),
            ("btcd-0.27.0-outbound-crawl", "a getblocks after verack, 70017", |c, v| {
                c.push("getblocks".into());
                v.protocol_version = 70017;
                v.user_agent = "/btcwire:0.5.0/btcd:0.28.0/".into();
            }),
            ("bcoin-2.2.0-outbound-crawl", "relay off, other services", |_, v| {
                v.relay = false;
                v.services = 1;
                v.user_agent = "/bcoin:2.3.0/".into();
            }),
            ("libbitcoin-3.8.0-outbound-crawl", "other services and height", |_, v| {
                v.services = 1;
                v.start_height = 900_000;
                v.user_agent = "/libbitcoin:4.0.0/".into();
            }),
        ];
        for (name, what, edit) in cases {
            let (r, f) = replay_crawl_fixture(name);
            let mut commands: Vec<String> = r.capture.commands().collect();
            let mut v = r.version.clone().unwrap();
            edit(&mut commands, &mut v);
            let got = classify_crawl(&transcript(&commands), Some(&v), &f);
            assert!(
                matches!(got, Fingerprint::Known(fam, Confidence::High | Confidence::Low) if fam == own_family(name)),
                "{name} with {what}: {got}"
            );
        }
    }

    /// With no row matching, the family is the one the user agent names,
    /// at `claimed`: never observed, never a mismatch, whichever family it
    /// names. A user agent that names none is unknown. The session here is
    /// a Core node closing just after `verack`, as one live Core 28.1 node
    /// did: no row can tell it from satd's or rbitcoin's.
    #[test]
    fn a_shape_no_row_matches_is_claimed_by_its_user_agent() {
        let (r, f) = replay_crawl_fixture("core-28.1-outbound-crawl");
        let early = transcript(&["version", "wtxidrelay", "sendaddrv2", "verack"]);
        let v = r.version.clone().unwrap();
        let got = classify_crawl(&early, Some(&v), &f);
        assert_eq!(got, Fingerprint::Known(Family::Core, Confidence::Claimed));
        assert_eq!(got.observed(), None);
        assert_eq!(got.claimed_only(), Some(Family::Core));
        assert_eq!(got.to_string(), "core/claimed");
        for (ua, want) in [
            ("/btcwire:0.5.0/btcd:0.27.0/", Fingerprint::Known(Family::Btcd, Confidence::Claimed)),
            ("/satd:0.9.0/", Fingerprint::Known(Family::Satd, Confidence::Claimed)),
            ("/bitcoin-lisp:0.1.0/", Fingerprint::Unknown),
            ("", Fingerprint::Unknown),
        ] {
            let v = VersionFields { user_agent: ua.into(), ..v.clone() };
            assert_eq!(classify_crawl(&early, Some(&v), &f), want, "{ua}");
        }
        // A matched row still settles it: the claim plays no part then.
        assert_eq!(crawl("core-28.1-outbound-crawl"), Fingerprint::Known(Family::Core, Confidence::High));
        assert_eq!(Fingerprint::Known(Family::Core, Confidence::High).claimed_only(), None);
        // No version, no user agent: unknown.
        assert_eq!(classify_crawl(&early, None, &f), Fingerprint::Unknown);
    }

    /// `NeverAnnounces` holds only once a message other than an
    /// announcement came: before it, the announcements may be incomplete.
    #[test]
    fn an_absent_announcement_counts_only_once_the_announcements_ended() {
        let v = replay_crawl_fixture("core-32.1-outbound-crawl").0.version.unwrap();
        let open = Phases::of(&transcript(&["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct"])).unwrap();
        assert!(open.then.is_none());
        assert!(!Trait::NeverAnnounces("feefilter").holds(&open, &v));
        assert!(Trait::Announces("sendcmpct").holds(&open, &v));
        let ended = Phases::of(&transcript(&["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct", "ping"])).unwrap();
        assert!(Trait::NeverAnnounces("feefilter").holds(&ended, &v));
        assert!(Trait::Then("ping").holds(&ended, &v));
        assert!(Phases::of(&transcript(&["version", "wtxidrelay"])).is_none(), "no verack, no phases");
    }

    /// The crawl rows are the crawl's: the survey's table does not know
    /// satd greeted as a crawler (no `getheaders` to services 0). The
    /// crawl's traits are not tied to the crawl's greeting, though: satd
    /// 0.7.0 dialled as a node shows the traits of its crawl row too.
    #[test]
    fn crawl_shapes_and_node_shapes_are_judged_by_their_own_tables() {
        let (r, _) = replay_crawl_fixture("satd-0.8.0-pre-outbound-crawl");
        assert_eq!(classify(false, &r.capture, r.version.as_ref(), true), Fingerprint::Unknown);
        assert_eq!(crawl("satd-0.8.0-pre-outbound-crawl"), Fingerprint::Known(Family::Satd, Confidence::High));
        let r = replay_fixture("satd-0.7.0-outbound");
        assert_eq!(
            classify_crawl(&r.capture, r.version.as_ref(), &CrawlFeatures::default()),
            Fingerprint::Known(Family::Satd, Confidence::High)
        );
        // The passive survey never claims: no row, unknown.
        let v = VersionFields { user_agent: "/satd:0.7.0/".into(), ..r.version.clone().unwrap() };
        assert_eq!(classify(false, &transcript(&["version", "verack", "inv"]), Some(&v), true), Fingerprint::Unknown);
    }

    /// The `getdata` probe pins the satd, rbitcoin, btcd and bcoin rows,
    /// which send `notfound`: silence is no capture of theirs. Core's row
    /// leaves it open: Core is silent on a connection that set relay off
    /// unless its operator grants relay, and Knots 28.1 answers. A
    /// contradicted row leaves only the user agent's claim.
    #[test]
    fn a_crawl_shape_with_a_probe_answer_its_captures_never_gave_is_only_claimed() {
        for name in ["core-32.1-outbound-crawl", "core-24.0.1-outbound-crawl-v2"] {
            let (r, mut f) = replay_crawl_fixture(name);
            f.probes.set(Probe::GetData, ProbeOutcome::Answered(1));
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Known(Family::Core, Confidence::High), "{name}");
        }
        let claimed = |f: Family| Fingerprint::Known(f, Confidence::Claimed);
        for (name, family) in [
            ("satd-0.8.0-pre-outbound-crawl", Family::Satd),
            ("rbitcoin-0.8.99-outbound-crawl-v2", Family::Rbitcoin),
            ("btcd-0.27.0-outbound-crawl", Family::Btcd),
        ] {
            let (r, mut f) = replay_crawl_fixture(name);
            f.probes.set(Probe::GetData, ProbeOutcome::Silent);
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), claimed(family), "{name}");
        }
        // The unknown message: every capture leaves it unanswered.
        let (r, mut f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        f.probes.set(Probe::Unknown, ProbeOutcome::Answered(0));
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), claimed(Family::Core));
        // A disconnect on any probe matches no row.
        for p in Probe::ALL {
            let (r, mut f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
            f.probes.set(p, ProbeOutcome::Disconnected);
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), claimed(Family::Core), "{}", p.name());
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
    fn a_v2_greeting_its_captures_never_showed_is_only_claimed() {
        for name in ["core-32.1-outbound-crawl-v2", "satd-0.8.0-pre-outbound-crawl-v2", "rbitcoin-0.8.99-outbound-crawl-v2"] {
            let claimed = Fingerprint::Known(own_family(name), Confidence::Claimed);
            let (r, f) = replay_crawl_fixture(name);
            let mut g = f.v2.expect("a v2 capture");
            g.decoys = 1;
            let decoy = CrawlFeatures { v2: Some(g), ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &decoy), claimed, "{name}");
            let mut g = f.v2.unwrap();
            g.version_len = 4;
            let contents = CrawlFeatures { v2: Some(g), ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &contents), claimed, "{name}");
            for garbage_len in [0, 4095] {
                let mut g = f.v2.unwrap();
                g.garbage_len = garbage_len;
                let any = CrawlFeatures { v2: Some(g), ..f };
                assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &any).observed(), Some(own_family(name)), "{name}");
            }
        }
    }

    /// rbitcoin closes a v1 connection before its `version`, so its shape
    /// over v1 is no capture's; Core's and satd's are the same over both.
    #[test]
    fn a_v2_only_shape_over_v1_is_only_claimed() {
        let (r, f) = replay_crawl_fixture("rbitcoin-0.8.99-outbound-crawl-v2");
        let v1 = CrawlFeatures { v2: None, ..f };
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &v1), Fingerprint::Known(Family::Rbitcoin, Confidence::Claimed));
        let (r, f) = replay_crawl_fixture("core-32.1-outbound-crawl-v2");
        let v1 = CrawlFeatures { v2: None, ..f };
        assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &v1), Fingerprint::Known(Family::Core, Confidence::High));
    }

    /// Every capture answered `getaddr` in `addrv2`, as it was asked to;
    /// a legacy `addr` answer is no capture's.
    #[test]
    fn a_legacy_addr_answer_is_only_claimed() {
        for name in ["core-24.0.1-outbound-crawl", "satd-0.8.0-pre-outbound-crawl", "rbitcoin-0.8.99-outbound-crawl-v2"] {
            let (r, f) = replay_crawl_fixture(name);
            let addr = CrawlFeatures { getaddr: Some(AddrKind::Addr), ..f };
            assert_eq!(
                classify_crawl(&r.capture, r.version.as_ref(), &addr),
                Fingerprint::Known(own_family(name), Confidence::Claimed),
                "{name}"
            );
            let none = CrawlFeatures { getaddr: None, ..f };
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &none).observed(), Some(own_family(name)), "{name}");
        }
    }

    /// A user agent naming another family on a crawl shape a row matched
    /// is a mismatch.
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

    /// The v1-only rows admit no BIP 324 session: btcd, bcoin and
    /// libbitcoin never completed one, so the same shape inside BIP 324 is
    /// some other implementation. bcoin's and libbitcoin's rows pin their
    /// protocol versions, and libbitcoin's its relay flag.
    #[test]
    fn the_v1_only_crawl_rows_pin_their_transport_and_version() {
        for (name, family) in [
            ("btcd-0.27.0-outbound-crawl", Family::Btcd),
            ("bcoin-2.2.0-outbound-crawl", Family::Bcoin),
            ("libbitcoin-3.8.0-outbound-crawl", Family::Libbitcoin),
        ] {
            let (r, f) = replay_crawl_fixture(name);
            assert_eq!(classify_crawl(&r.capture, r.version.as_ref(), &f), Fingerprint::Known(family, Confidence::High), "{name}");
            let inside_v2 = CrawlFeatures { v2: Some(V2Greeting { garbage_len: 0, decoys: 0, version_len: 0 }), ..f };
            assert_eq!(
                classify_crawl(&r.capture, r.version.as_ref(), &inside_v2),
                Fingerprint::Known(family, Confidence::Claimed),
                "{name} over v2"
            );
        }
        for (name, protocol_version) in [("bcoin-2.2.0-outbound-crawl", 70016), ("libbitcoin-3.8.0-outbound-crawl", 70015)] {
            let (r, f) = replay_crawl_fixture(name);
            let mut v = r.version.clone().unwrap();
            v.protocol_version = protocol_version;
            assert_eq!(classify_crawl(&r.capture, Some(&v), &f).observed(), None, "{name} at {protocol_version}");
        }
        let (r, f) = replay_crawl_fixture("libbitcoin-3.8.0-outbound-crawl");
        let mut v = r.version.clone().unwrap();
        v.relay = true;
        assert_eq!(classify_crawl(&r.capture, Some(&v), &f).observed(), None, "libbitcoin with relay on");
    }

    /// Where two families' rows share the traits, a session whose probe
    /// answers rule one out is `high`: the survey, which sends no probe
    /// before it judges, can only be `low` there. Only the `version`
    /// fields telling them apart is `low`. (A table built for the test: no
    /// two captured families share their traits; Knots is Core.)
    #[test]
    fn a_probe_answer_that_tells_families_apart_is_high_confidence() {
        let base = CRAWL_TABLE.iter().find(|r| r.family == Family::Satd).unwrap();
        let table = [
            CrawlRow { captures: &[], family: Family::Satd, ..*base },
            CrawlRow { captures: &[], family: Family::Btcd, probes: [Answer::Either, Answer::Either, Answer::Silent, Answer::Silent], ..*base },
            CrawlRow { captures: &[], family: Family::Bcoin, traits: &[Trait::Protocol(1)], ..*base },
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
