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
