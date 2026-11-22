//! Alt-slots (`-altslots`, `-altprefer`, `-altuatrust`, `-altfillwait`):
//! some of the full-relay outbound slots filled by peers that match the
//! operator's preference rules instead of by plain address-book selection,
//! and the configurable full-relay outbound count they are carved out of
//! (`-maxoutboundfullrelay`).
//!
//! This module holds what needs no connection: the limits, the rule parser,
//! the user-agent trust levels and the match itself. The manager's side (the
//! dials, the judgement once a handshake settles, the fallback, the reload)
//! is `manager_altslots.rs`.
//!
//! A rule is one or more terms joined by `+`, all of which must hold, with
//! an optional `@k` cap on how many slots it may fill:
//!
//! - `family:<name>`: the observed fingerprint family
//!   ([`crate::net::fingerprint`]), or `non-core` for any family but Core's.
//! - `ua:<glob>`: the claimed user agent, `*` and `?` wildcards, subject to
//!   the trust level ([`UaTrust`]).
//! - `svc:<name>`: an advertised service bit, by `getpeerinfo`'s
//!   `servicesnames` name in lower case.
//!
//! Earlier rules have priority. With alt-slots on and no rule, the one rule
//! is `family:non-core`.

use std::fmt;
use std::time::Duration;

use crate::net::fingerprint::{Family, Fingerprint};
use crate::net::flags::{Flag, FlagSet};

/// `-maxoutboundfullrelay`'s default: Core's
/// `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` (`src/net.h`).
pub const DEFAULT_MAX_OUTBOUND_FULL_RELAY: usize = 8;
/// Above this, `-maxoutboundfullrelay` is warned about at startup and on a
/// reload: every extra outbound takes an inbound slot on someone else's node.
pub const MAX_OUTBOUND_FULL_RELAY_WARN: usize = 8;
/// Above this, `-maxoutboundfullrelay` needs
/// `-enable-dangerously-large-outbound-peer-limit`.
pub const MAX_OUTBOUND_FULL_RELAY_UNGUARDED: usize = 16;
/// `-maxoutboundfullrelay`'s ceiling, which the override does not lift. It
/// is also the full-relay target during initial block download.
pub const MAX_OUTBOUND_FULL_RELAY_CEILING: usize = 64;
/// Above this many alt-slots the node warns about the eclipse trade-off.
pub const ALT_SLOTS_WARN: usize = 4;
/// `-altfillwait`'s default, in seconds.
pub const DEFAULT_ALT_FILL_WAIT_SECS: u64 = 600;
/// The least time between a trial connection that did not match and the
/// next trial dial.
pub const ALT_TRIAL_INTERVAL: Duration = Duration::from_secs(30);

/// The name `-enable-dangerously-large-outbound-peer-limit` goes by in
/// messages.
pub const DANGEROUS_OUTBOUND_OVERRIDE: &str = "-enable-dangerously-large-outbound-peer-limit";

/// Check `-maxoutboundfullrelay` and `-altslots` against their limits and
/// each other, and against `-maxconnections`. `Err` is a startup error, and
/// a reload that would cross it is refused with the running values kept.
pub fn check_outbound_limits(
    max_full_relay: usize,
    dangerous_override: bool,
    alt_slots: usize,
    max_connections: usize,
) -> Result<(), String> {
    if max_full_relay == 0 {
        return Err("-maxoutboundfullrelay must be at least 1 (-connect=0 opens no automatic connections)".into());
    }
    if max_full_relay > MAX_OUTBOUND_FULL_RELAY_CEILING {
        return Err(format!(
            "-maxoutboundfullrelay={max_full_relay} is above the ceiling of {MAX_OUTBOUND_FULL_RELAY_CEILING}, which {DANGEROUS_OUTBOUND_OVERRIDE} does not lift"
        ));
    }
    if max_full_relay > MAX_OUTBOUND_FULL_RELAY_UNGUARDED && !dangerous_override {
        return Err(format!(
            "-maxoutboundfullrelay={max_full_relay} is above {MAX_OUTBOUND_FULL_RELAY_UNGUARDED}: each outbound connection takes an inbound slot on another node; pass {DANGEROUS_OUTBOUND_OVERRIDE} to allow it"
        ));
    }
    if alt_slots > max_full_relay {
        return Err(format!(
            "-altslots={alt_slots} is more than the {max_full_relay} full-relay outbound connections (-maxoutboundfullrelay) it is carved out of"
        ));
    }
    if alt_slots > max_connections {
        return Err(format!("-maxconnections={max_connections} is too small to hold -altslots={alt_slots}"));
    }
    Ok(())
}

/// The warnings the same settings get at startup and on a reload that
/// changes them.
pub fn outbound_limit_warnings(max_full_relay: usize, alt_slots: usize) -> Vec<String> {
    let mut out = Vec::new();
    if max_full_relay > MAX_OUTBOUND_FULL_RELAY_WARN {
        out.push(format!(
            "-maxoutboundfullrelay={max_full_relay} is above Bitcoin Core's {MAX_OUTBOUND_FULL_RELAY_WARN}: each extra outbound connection takes an inbound slot on another node, and the network has a limited number of them"
        ));
    }
    if alt_slots > ALT_SLOTS_WARN {
        out.push(format!(
            "-altslots={alt_slots}: the peers that match -altprefer are a far smaller pool than the address book, so with this many alt-slots transaction and address relay could be served entirely by peers an attacker can choose to match; the block-relay-only connections stay ordinary"
        ));
    }
    out
}

/// The service names a `svc:` term takes: `getpeerinfo`'s `servicesnames`
/// in lower case, with their bits.
pub const SERVICE_NAMES: &[(&str, u64)] = &[
    ("network", 1 << 0),
    ("bloom", 1 << 2),
    ("witness", 1 << 3),
    ("compact_filters", 1 << 6),
    ("network_limited", 1 << 10),
    ("p2p_v2", 1 << 11),
    ("intact_blocks", 1 << 28),
    ("nap", 1 << 30),
];

/// A `family:` term's operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyTerm {
    Is(Family),
    /// Any observed family outside Core's (Knots and the other Core forks are
    /// in Core's).
    NonCore,
}

/// One term of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Family(FamilyTerm),
    /// A glob over the claimed user agent.
    Ua(String),
    /// A service bit, with the name it was given by.
    Svc(&'static str, u64),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Family(FamilyTerm::Is(family)) => write!(f, "family:{family}"),
            Term::Family(FamilyTerm::NonCore) => f.write_str("family:non-core"),
            Term::Ua(glob) => write!(f, "ua:{glob}"),
            Term::Svc(name, _) => write!(f, "svc:{name}"),
        }
    }
}

/// One `-altprefer` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub terms: Vec<Term>,
    /// `@k`: at most this many slots.
    pub cap: Option<usize>,
}

impl fmt::Display for Rule {
    /// The canonical text: `family:btcd+svc:compact_filters@2`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, term) in self.terms.iter().enumerate() {
            if i > 0 {
                f.write_str("+")?;
            }
            write!(f, "{term}")?;
        }
        if let Some(k) = self.cap {
            write!(f, "@{k}")?;
        }
        Ok(())
    }
}

impl Rule {
    /// The rule with alt-slots on and no `-altprefer`.
    pub fn default_rule() -> Rule {
        Rule { terms: vec![Term::Family(FamilyTerm::NonCore)], cap: None }
    }

    /// Parse one `-altprefer` value. An unknown term kind, family or service
    /// is an error, as any other bad config value is.
    pub fn parse(text: &str) -> Result<Rule, String> {
        let s = text.trim();
        if s.is_empty() {
            return Err("-altprefer: an empty rule".into());
        }
        // `@k` only when what follows the last `@` is a count, so a glob
        // may hold an `@` of its own.
        let (body, cap) = match s.rsplit_once('@') {
            Some((body, k)) if !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) => {
                let k: usize = k.parse().map_err(|_| format!("-altprefer={s}: the cap @{k} is too large"))?;
                if k == 0 {
                    return Err(format!("-altprefer={s}: a cap of @0 fills no slot"));
                }
                (body, Some(k))
            }
            _ => (s, None),
        };
        let mut terms = Vec::new();
        for term in body.split('+') {
            let Some((kind, value)) = term.split_once(':') else {
                return Err(format!("-altprefer={s}: \"{term}\" is not family:, ua: or svc:"));
            };
            if value.is_empty() {
                return Err(format!("-altprefer={s}: \"{term}\" has no value"));
            }
            terms.push(match kind.to_ascii_lowercase().as_str() {
                "family" => Term::Family(parse_family(value).ok_or_else(|| {
                    let names: Vec<&str> = Family::ALL.iter().map(|f| f.name()).chain(["non-core"]).collect();
                    format!("-altprefer={s}: unknown family \"{value}\" (one of {})", names.join(", "))
                })?),
                "ua" => Term::Ua(value.to_string()),
                "svc" => {
                    let lower = value.to_ascii_lowercase();
                    let (name, bit) = SERVICE_NAMES.iter().find(|(n, _)| *n == lower).copied().ok_or_else(|| {
                        let names: Vec<&str> = SERVICE_NAMES.iter().map(|(n, _)| *n).collect();
                        format!("-altprefer={s}: unknown service \"{value}\" (one of {})", names.join(", "))
                    })?;
                    Term::Svc(name, bit)
                }
                _ => return Err(format!("-altprefer={s}: \"{term}\" is not family:, ua: or svc:")),
            });
        }
        Ok(Rule { terms, cap })
    }

    /// Whether `c` meets every term under trust mode `mode`, and is not
    /// kept out by its flags.
    pub fn matches(&self, c: &Candidate, mode: UaTrust) -> bool {
        if mode != UaTrust::Any && c.excluded_by_flags() {
            return false;
        }
        let trust = c.trust();
        self.terms.iter().all(|term| match term {
            Term::Family(FamilyTerm::Is(f)) => c.fingerprint.observed() == Some(*f),
            Term::Family(FamilyTerm::NonCore) => c.fingerprint.observed().is_some_and(|f| f != Family::Core),
            Term::Ua(glob) => mode.admits(trust) && glob_match(glob, c.user_agent),
            Term::Svc(_, bit) => c.services & bit == *bit,
        })
    }

    /// Whether a peer with `services` can meet the rule's `svc:` terms: what
    /// the address book tells before a dial.
    pub fn services_may_match(&self, services: u64) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Svc(_, bit) => services & bit == *bit,
            _ => true,
        })
    }
}

fn parse_family(value: &str) -> Option<FamilyTerm> {
    let lower = value.to_ascii_lowercase();
    if lower == "non-core" {
        return Some(FamilyTerm::NonCore);
    }
    Family::ALL.iter().find(|f| f.name() == lower).map(|f| FamilyTerm::Is(*f))
}

/// `-altuatrust`: how far a `ua:` term trusts the claimed user agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UaTrust {
    /// Verified agents only.
    Strict,
    /// Verified and unverified agents; verified ones preferred.
    #[default]
    Consistent,
    /// The agent alone decides, contradicted ones and flagged peers included.
    Any,
}

impl UaTrust {
    pub fn parse(s: &str) -> Result<UaTrust, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(UaTrust::Strict),
            "consistent" => Ok(UaTrust::Consistent),
            "any" => Ok(UaTrust::Any),
            other => Err(format!("-altuatrust must be strict, consistent or any, not \"{other}\"")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            UaTrust::Strict => "strict",
            UaTrust::Consistent => "consistent",
            UaTrust::Any => "any",
        }
    }

    fn admits(self, trust: Trust) -> bool {
        match self {
            UaTrust::Strict => trust == Trust::Verified,
            UaTrust::Consistent => trust != Trust::Contradicted,
            UaTrust::Any => true,
        }
    }
}

/// How far a candidate's claimed user agent agrees with its fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// The fingerprint's family is the one the agent names (a Knots agent
    /// with a Core-family fingerprint is verified: Knots is a Core fork).
    Verified,
    /// The fingerprint is unknown, or the agent names no family the table
    /// knows: nothing confirms the agent, and nothing contradicts it.
    Unverified,
    /// The fingerprint names a family other than the agent's (flag `F`).
    Contradicted,
}

impl Trust {
    pub fn name(self) -> &'static str {
        match self {
            Trust::Verified => "verified",
            Trust::Unverified => "unverified",
            Trust::Contradicted => "contradicted",
        }
    }
}

/// What a rule is judged on: a connected peer once its fingerprint settles,
/// or a survey record.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    pub fingerprint: Fingerprint,
    pub user_agent: &'a str,
    pub services: u64,
    pub flags: FlagSet,
}

impl Candidate<'_> {
    pub fn trust(&self) -> Trust {
        match (self.fingerprint, Family::claimed_by(self.user_agent)) {
            (Fingerprint::Unknown, _) => Trust::Unverified,
            (Fingerprint::Mismatch { .. }, _) => Trust::Contradicted,
            (Fingerprint::Known(observed, _), Some(claimed)) if claimed == observed => Trust::Verified,
            (Fingerprint::Known(..), Some(_)) => Trust::Contradicted,
            (Fingerprint::Known(..), None) => Trust::Unverified,
        }
    }

    /// Carries `C`, `S` or `F` (a mismatch counts as `F` before the flags
    /// are next evaluated).
    fn excluded_by_flags(&self) -> bool {
        self.flags.contains(Flag::Crawler)
            || self.flags.contains(Flag::Spy)
            || self.flags.contains(Flag::FingerprintMismatch)
            || matches!(self.fingerprint, Fingerprint::Mismatch { .. })
    }
}

/// The alt-slot settings as they run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltConfig {
    /// `-altslots`.
    pub slots: usize,
    /// `-altprefer`, in priority order; [`Rule::default_rule`] when none was
    /// given.
    pub rules: Vec<Rule>,
    pub ua_trust: UaTrust,
    /// `-altfillwait`.
    pub fill_wait: Duration,
}

impl Default for AltConfig {
    fn default() -> Self {
        AltConfig {
            slots: 0,
            rules: vec![Rule::default_rule()],
            ua_trust: UaTrust::default(),
            fill_wait: Duration::from_secs(DEFAULT_ALT_FILL_WAIT_SECS),
        }
    }
}

impl AltConfig {
    /// From the options' values; `rules` empty takes the default rule.
    pub fn new(slots: usize, rules: Vec<Rule>, ua_trust: UaTrust, fill_wait: Duration) -> AltConfig {
        let rules = if rules.is_empty() { vec![Rule::default_rule()] } else { rules };
        AltConfig { slots, rules, ua_trust, fill_wait }
    }

    /// The first rule `c` matches that has a slot left under its cap, with
    /// `used(rule)` the slots the rule already fills.
    pub fn choose(&self, c: &Candidate, used: impl Fn(&Rule) -> usize) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|r| r.cap.is_none_or(|k| used(r) < k) && r.matches(c, self.ua_trust))
    }

    /// The rules with a slot left under their cap.
    pub fn open_rules(&self, used: impl Fn(&Rule) -> usize) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.cap.is_none_or(|k| used(r) < k)).collect()
    }
}

/// What an outbound full-relay peer is to the alt-slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltRole {
    /// Dialled for an alt-slot; judged once its fingerprint settles, and
    /// disconnected if it matches no rule.
    Trial,
    /// Fills an alt-slot under `rule` (its canonical text).
    Matched { rule: String, trust: Trust },
    /// An ordinary peer holding an alt-slot left empty past `-altfillwait`,
    /// until a match takes the slot.
    Fallback,
}

/// `*` matches any run of characters, `?` any one; everything else matches
/// itself. Case-sensitive, as user agents are.
pub fn glob_match(glob: &str, text: &str) -> bool {
    let g: Vec<char> = glob.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut gi, mut ti) = (0usize, 0usize);
    // The last `*` seen and the text position it was tried at.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if gi < g.len() && (g[gi] == '?' || (g[gi] != '*' && g[gi] == t[ti])) {
            gi += 1;
            ti += 1;
        } else if gi < g.len() && g[gi] == '*' {
            star = Some((gi, ti));
            gi += 1;
        } else if let Some((sg, st)) = star {
            gi = sg + 1;
            ti = st + 1;
            star = Some((sg, st + 1));
        } else {
            return false;
        }
    }
    g[gi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fingerprint::Confidence;

    fn cand(fp: Fingerprint, ua: &str) -> Candidate<'_> {
        Candidate { fingerprint: fp, user_agent: ua, services: 0, flags: FlagSet::default() }
    }

    fn known(f: Family) -> Fingerprint {
        Fingerprint::Known(f, Confidence::High)
    }

    #[test]
    fn each_term_parses_and_prints_back() {
        for (text, want) in [
            ("family:btcd", "family:btcd"),
            ("family:non-core", "family:non-core"),
            ("FAMILY:Floresta", "family:floresta"),
            ("ua:/Knots:*", "ua:/Knots:*"),
            ("svc:compact_filters", "svc:compact_filters"),
            ("svc:P2P_V2", "svc:p2p_v2"),
        ] {
            assert_eq!(Rule::parse(text).unwrap().to_string(), want, "{text}");
        }
    }

    #[test]
    fn terms_join_with_plus_and_take_a_cap() {
        let r = Rule::parse("family:floresta+svc:compact_filters@2").unwrap();
        assert_eq!(r.cap, Some(2));
        assert_eq!(
            r.terms,
            vec![Term::Family(FamilyTerm::Is(Family::Floresta)), Term::Svc("compact_filters", 1 << 6)]
        );
        assert_eq!(Rule::parse("ua:/Knots:*@1").unwrap().cap, Some(1));
        // An `@` not followed by a count is part of the glob.
        let r = Rule::parse("ua:/a@b/").unwrap();
        assert_eq!((r.cap, r.terms), (None, vec![Term::Ua("/a@b/".into())]));
    }

    #[test]
    fn unknown_names_are_refused() {
        for bad in [
            "family:knots",
            "svc:fast",
            "colour:red",
            "btcd",
            "family:",
            "",
            "family:btcd@0",
            "family:btcd+",
            "family:btcd@99999999999999999999999",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn the_default_rule_is_non_core() {
        let c = AltConfig::new(2, Vec::new(), UaTrust::Consistent, Duration::ZERO);
        assert_eq!(c.rules, vec![Rule::parse("family:non-core").unwrap()]);
        assert!(c.rules[0].matches(&cand(known(Family::Btcd), "/btcwire:0.5.0/btcd:0.24.2/"), c.ua_trust));
        assert!(!c.rules[0].matches(&cand(known(Family::Core), "/Satoshi:28.1.0/"), c.ua_trust));
        assert!(!c.rules[0].matches(&cand(Fingerprint::Unknown, "/btcd:0.24.2/"), c.ua_trust));
    }

    /// Knots with a Core-family fingerprint is verified, Knots with an
    /// unknown one unverified, Knots with a btcd one contradicted.
    #[test]
    fn trust_levels() {
        let knots = "/Satoshi:28.1.0/Knots:20250305/";
        assert_eq!(cand(known(Family::Core), knots).trust(), Trust::Verified);
        assert_eq!(cand(Fingerprint::Unknown, knots).trust(), Trust::Unverified);
        let contradicted = Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd };
        assert_eq!(cand(contradicted, knots).trust(), Trust::Contradicted);
        // An agent naming no family the table knows.
        assert_eq!(cand(known(Family::Core), "/Custom:1.0/").trust(), Trust::Unverified);
    }

    #[test]
    fn each_trust_mode_against_each_trust_level() {
        let rule = Rule::parse("ua:/Satoshi:*Knots*").unwrap();
        let knots = "/Satoshi:28.1.0/Knots:20250305/";
        let verified = cand(known(Family::Core), knots);
        let unverified = cand(Fingerprint::Unknown, knots);
        let contradicted = cand(Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }, knots);
        let got = |mode| {
            [verified, unverified, contradicted].map(|c| rule.matches(&c, mode))
        };
        assert_eq!(got(UaTrust::Strict), [true, false, false]);
        assert_eq!(got(UaTrust::Consistent), [true, true, false]);
        assert_eq!(got(UaTrust::Any), [true, true, true]);
    }

    #[test]
    fn crawler_spy_and_mismatch_flags_keep_a_peer_out_except_under_any() {
        let rule = Rule::parse("family:btcd").unwrap();
        for flag in [Flag::Crawler, Flag::Spy, Flag::FingerprintMismatch] {
            let mut flags = FlagSet::default();
            flags.insert(flag);
            let c = Candidate { flags, ..cand(known(Family::Btcd), "/btcd:0.24.2/") };
            assert!(!rule.matches(&c, UaTrust::Strict), "{flag:?}");
            assert!(!rule.matches(&c, UaTrust::Consistent), "{flag:?}");
            assert!(rule.matches(&c, UaTrust::Any), "{flag:?}");
        }
        // Another flag does not.
        let mut flags = FlagSet::default();
        flags.insert(Flag::Stalling);
        let c = Candidate { flags, ..cand(known(Family::Btcd), "/btcd:0.24.2/") };
        assert!(rule.matches(&c, UaTrust::Strict));
    }

    #[test]
    fn svc_terms_need_every_bit() {
        let rule = Rule::parse("family:floresta+svc:compact_filters").unwrap();
        let c = Candidate { services: 1 | (1 << 6), ..cand(known(Family::Floresta), "/Floresta:0.7.0/") };
        assert!(rule.matches(&c, UaTrust::Consistent));
        assert!(!rule.matches(&Candidate { services: 1, ..c }, UaTrust::Consistent));
        assert!(rule.services_may_match(1 | (1 << 6)));
        assert!(!rule.services_may_match(1));
        assert!(Rule::parse("family:btcd").unwrap().services_may_match(0));
    }

    #[test]
    fn earlier_rules_first_and_caps_hold() {
        let c = AltConfig::new(
            4,
            vec![Rule::parse("family:btcd@1").unwrap(), Rule::parse("family:non-core").unwrap()],
            UaTrust::Consistent,
            Duration::ZERO,
        );
        let btcd = cand(known(Family::Btcd), "/btcd:0.24.2/");
        assert_eq!(c.choose(&btcd, |_| 0).unwrap().to_string(), "family:btcd@1");
        // The capped rule is full; the next takes it.
        let first = c.rules[0].clone();
        assert_eq!(c.choose(&btcd, |r| usize::from(*r == first)).unwrap().to_string(), "family:non-core");
        assert!(c.choose(&cand(known(Family::Core), "/Satoshi:28.1.0/"), |_| 0).is_none());
    }

    #[test]
    fn globs() {
        assert!(glob_match("/Knots:*", "/Knots:20250305/"));
        assert!(glob_match("*Knots*", "/Satoshi:28.1.0/Knots:20250305/"));
        assert!(glob_match("/Satoshi:2?.1.0/", "/Satoshi:28.1.0/"));
        assert!(!glob_match("/Knots:*", "/Satoshi:28.1.0/Knots:20250305/"));
        assert!(!glob_match("/knots:*", "/Knots:1/"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("?", ""));
        assert!(glob_match("a*b*c", "aXbYbZc"));
    }

    #[test]
    fn outbound_limits() {
        assert!(check_outbound_limits(8, false, 0, 125).is_ok());
        assert!(check_outbound_limits(16, false, 0, 125).is_ok());
        assert!(check_outbound_limits(17, false, 0, 125).is_err());
        assert!(check_outbound_limits(17, true, 0, 125).is_ok());
        assert!(check_outbound_limits(64, true, 0, 125).is_ok());
        assert!(check_outbound_limits(65, true, 0, 125).is_err());
        assert!(check_outbound_limits(0, false, 0, 125).is_err());
        assert!(check_outbound_limits(8, false, 8, 125).is_ok());
        assert!(check_outbound_limits(8, false, 9, 125).is_err());
        assert!(check_outbound_limits(12, false, 9, 125).is_ok());
        assert!(check_outbound_limits(8, false, 6, 5).is_err());
        assert!(check_outbound_limits(8, false, 0, 0).is_ok(), "-maxconnections=0 with no alt-slots stays Core's");
        assert!(outbound_limit_warnings(8, 4).is_empty());
        assert_eq!(outbound_limit_warnings(9, 0).len(), 1);
        assert_eq!(outbound_limit_warnings(8, 5).len(), 1);
    }
}
