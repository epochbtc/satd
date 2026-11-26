//! Peer behaviour as this TUI shows it: each peer's fingerprint and flags
//! from satd's `getpeerbehavior`.
//!
//! The method is satd's own and newer than the TUI's other calls. A node
//! that answers it with "method not found" (an older satd, or another
//! implementation) has no behaviour data, and every surface built on it is
//! hidden: no Flags column, no mismatch marker, no detail overlay, no
//! filter, and the Peer clients panel counts user agents as before.
//!
//! The user agent, the handshake commands and every other string in the
//! reply come from the peer or describe it. satd sanitizes the user agent,
//! but the TUI does not rely on the node it talks to: each string goes
//! through [`printable`] before it is drawn.

use std::collections::HashMap;

use serde_json::Value;

use crate::nap::printable;
use crate::rpc::{JSONRPC_METHOD_NOT_FOUND, RpcError};

/// What the fingerprint classifier found for a peer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Fingerprint {
    /// The transcript matches this family; the user agent agrees or names none.
    Known { family: String, confidence: String },
    /// No row matches, or the transcript is not settled yet.
    #[default]
    Unknown,
    /// No row matches, and the user agent names `family`: nothing the peer
    /// did confirmed it, so it is never counted as an observed family.
    Claimed { family: String },
    /// The user agent names `claimed`; the transcript matches `observed`.
    Mismatch { claimed: String, observed: String },
}

impl Fingerprint {
    /// The family the transcript matched, or `unknown`.
    pub fn observed(&self) -> &str {
        match self {
            Fingerprint::Known { family, .. } => family,
            Fingerprint::Mismatch { observed, .. } => observed,
            Fingerprint::Unknown | Fingerprint::Claimed { .. } => "unknown",
        }
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self, Fingerprint::Mismatch { .. })
    }
}

/// One flag with the numbers that raised it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    pub code: String,
    pub name: String,
    /// `(key, value)` in the order the node gave them.
    pub evidence: Vec<(String, String)>,
}

/// One peer's entry in `getpeerbehavior`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerBehavior {
    pub id: u64,
    pub connection_type: String,
    pub session_secs: u64,
    pub subver: String,
    pub evaluated: bool,
    pub fingerprint: Fingerprint,
    pub settled: bool,
    pub handshake: Vec<String>,
    /// The flag codes, one character each (`CF`).
    pub flag_codes: String,
    pub flags: Vec<Flag>,
    /// The raw counters, flattened to `(name, value)` lines.
    pub counters: Vec<(String, String)>,
    /// The peer's alt-slot (`-altslots`), if it holds one.
    pub alt_slot: Option<AltSlot>,
}

/// An alt-slot peer as `getpeerbehavior`'s `alt_slot` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltSlot {
    /// Matched `rule`; its user agent was `trust` (verified, unverified,
    /// contradicted).
    Matched { rule: String, trust: String },
    /// An ordinary peer holding an empty alt-slot.
    Fallback,
}

impl PeerBehavior {
    pub fn is_flagged(&self) -> bool {
        !self.flag_codes.is_empty()
    }
}

/// Every connected peer's behaviour, by id.
pub type BehaviorMap = HashMap<u64, PeerBehavior>;

/// How one poll of `getpeerbehavior` moves the TUI's copy.
#[derive(Debug)]
pub enum Poll {
    /// Answered: replace the copy.
    Answered(BehaviorMap),
    /// The node does not serve the method: hide every behaviour surface.
    NotServed,
    /// Any other failure: keep the copy, show the failure.
    Failed(String),
}

/// Classify one `getpeerbehavior` result.
pub fn classify(res: Result<Value, RpcError>) -> Poll {
    match res {
        Ok(v) => match parse(&v) {
            Some(map) => Poll::Answered(map),
            None => Poll::Failed("unexpected reply".into()),
        },
        Err(RpcError::Rpc { code, .. }) if code == JSONRPC_METHOD_NOT_FOUND => Poll::NotServed,
        Err(e) => Poll::Failed(e.to_string()),
    }
}

/// A JSON scalar as text; `None` for objects and arrays.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(printable(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".into()),
        _ => None,
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(printable)
        .unwrap_or_default()
}

/// Flatten the counters object: scalars as they are, `getdata_latency` and
/// `version` as `name.field`, arrays (the latency histogram) joined.
fn flatten_counters(v: &Value) -> Vec<(String, String)> {
    let Some(obj) = v.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, val) in obj {
        let k = printable(k);
        match val {
            Value::Object(inner) => {
                for (k2, v2) in inner {
                    let shown = match v2 {
                        Value::Array(a) => {
                            a.iter().filter_map(scalar).collect::<Vec<_>>().join(" ")
                        }
                        other => scalar(other).unwrap_or_default(),
                    };
                    out.push((format!("{k}.{}", printable(k2)), shown));
                }
            }
            Value::Array(a) => {
                out.push((k, a.iter().filter_map(scalar).collect::<Vec<_>>().join(" ")));
            }
            other => out.push((k, scalar(other).unwrap_or_default())),
        }
    }
    out
}

fn parse_peer(v: &Value) -> Option<PeerBehavior> {
    let id = v.get("id")?.as_u64()?;
    let fp = v.get("fingerprint");
    let fingerprint = match fp.and_then(|f| f.get("result")).and_then(Value::as_str) {
        Some("known") => {
            let f = fp?;
            Fingerprint::Known {
                family: text(f, "family"),
                confidence: text(f, "confidence"),
            }
        }
        Some("mismatch") => {
            let f = fp?;
            Fingerprint::Mismatch {
                claimed: text(f, "claimed"),
                observed: text(f, "observed"),
            }
        }
        Some("claimed") => Fingerprint::Claimed {
            family: text(fp?, "claimed"),
        },
        _ => Fingerprint::Unknown,
    };
    let flags = v
        .get("flags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|f| Flag {
                    code: text(f, "code"),
                    name: text(f, "name"),
                    evidence: f
                        .get("evidence")
                        .and_then(Value::as_object)
                        .map(|e| {
                            e.iter()
                                .map(|(k, v)| (printable(k), scalar(v).unwrap_or_default()))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    Some(PeerBehavior {
        id,
        connection_type: text(v, "connection_type"),
        session_secs: v.get("session_secs").and_then(Value::as_u64).unwrap_or(0),
        subver: text(v, "subver"),
        evaluated: v.get("evaluated").and_then(Value::as_bool).unwrap_or(false),
        fingerprint,
        settled: fp
            .and_then(|f| f.get("settled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        handshake: fp
            .and_then(|f| f.get("handshake"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(printable).collect())
            .unwrap_or_default(),
        flag_codes: text(v, "flag_codes"),
        flags,
        counters: v.get("counters").map(flatten_counters).unwrap_or_default(),
        alt_slot: v.get("alt_slot").filter(|a| a.is_object()).map(|a| {
            if a.get("fallback").and_then(Value::as_bool).unwrap_or(false) {
                AltSlot::Fallback
            } else {
                AltSlot::Matched {
                    rule: text(a, "rule"),
                    trust: text(a, "trust"),
                }
            }
        }),
    })
}

/// Parse a `getpeerbehavior` reply. `None` unless it is an array; entries
/// without an id are skipped.
pub fn parse(v: &Value) -> Option<BehaviorMap> {
    Some(
        v.as_array()?
            .iter()
            .filter_map(parse_peer)
            .map(|p| (p.id, p))
            .collect(),
    )
}

/// Width of the Flags column: room for an alt-slot tag and two flag codes
/// (`alt* CF`).
pub const FLAGS_WIDTH: u16 = 7;

/// How the Flags cell is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagsTone {
    /// No flags: the cell is empty.
    None,
    /// One flag other than `S`.
    Warn,
    /// `S`, or two flags or more.
    Alarm,
}

/// The Flags cell for a peer: `alt` for an alt-slot peer (`alt*` for a
/// fallback), then its codes, cut to the column, and the tone of the codes.
pub fn flags_cell(p: &PeerBehavior) -> (String, FlagsTone) {
    let tag = match p.alt_slot {
        Some(AltSlot::Matched { .. }) => "alt ",
        Some(AltSlot::Fallback) => "alt* ",
        None => "",
    };
    let codes: String = format!("{tag}{}", p.flag_codes)
        .trim_end()
        .chars()
        .take(FLAGS_WIDTH as usize)
        .collect();
    let n = p.flag_codes.chars().count();
    let tone = if n == 0 {
        FlagsTone::None
    } else if n >= 2 || p.flag_codes.contains('S') {
        FlagsTone::Alarm
    } else {
        FlagsTone::Warn
    };
    (codes, tone)
}

/// The marker drawn after the Agent cell when the fingerprint disagrees
/// with the user agent.
pub const MISMATCH_MARKER: &str = "≠";

/// The Agent cell: the claimed user agent, escaped, with [`MISMATCH_MARKER`]
/// after it when the peer's fingerprint is a mismatch.
pub fn agent_cell(subver: &str, behavior: Option<&PeerBehavior>) -> String {
    let agent = printable(subver);
    if behavior.is_some_and(|b| b.fingerprint.is_mismatch()) {
        format!("{agent} {MISMATCH_MARKER}")
    } else {
        agent
    }
}

/// Peer clients by observed family: `(label, count)`, largest first, the
/// tail past `top_n` folded into `other`. A mismatch is counted under the
/// family its transcript matched, labelled with the family its user agent
/// claimed in brackets (`btcd [core]`).
pub fn family_distribution(map: &BehaviorMap, top_n: usize) -> Vec<(String, usize)> {
    if map.is_empty() || top_n == 0 {
        return Vec::new();
    }
    let mut counts: HashMap<String, usize> = HashMap::new();
    for p in map.values() {
        let label = match &p.fingerprint {
            Fingerprint::Mismatch { claimed, observed } => format!("{observed} [{claimed}]"),
            // Unknown to the classifier: under `unknown`, the agent's
            // family in brackets as a mismatch's is.
            Fingerprint::Claimed { family } => format!("unknown [{family}]"),
            other => other.observed().to_string(),
        };
        *counts.entry(label).or_default() += 1;
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if sorted.len() <= top_n {
        return sorted;
    }
    let other: usize = sorted[top_n..].iter().map(|(_, c)| c).sum();
    sorted.truncate(top_n);
    sorted.push(("other".into(), other));
    sorted
}

/// The alt-slot peers: (matched, fallback). Peer clients shows them when
/// any are connected.
pub fn alt_slot_counts(map: &BehaviorMap) -> (usize, usize) {
    map.values().fold((0, 0), |(m, f), p| match p.alt_slot {
        Some(AltSlot::Matched { .. }) => (m + 1, f),
        Some(AltSlot::Fallback) => (m, f + 1),
        None => (m, f),
    })
}

/// Peers whose fingerprint is a mismatch.
pub fn mismatch_count(map: &BehaviorMap) -> usize {
    map.values().filter(|p| p.fingerprint.is_mismatch()).count()
}

/// The fingerprint as the detail overlay states it.
pub fn fingerprint_line(p: &PeerBehavior) -> String {
    match &p.fingerprint {
        Fingerprint::Known { family, confidence } => format!("{family} ({confidence} confidence)"),
        Fingerprint::Mismatch { claimed, observed } => {
            format!("{observed}, but the user agent names {claimed}")
        }
        Fingerprint::Claimed { family } => {
            format!("unknown; the user agent names {family} (claimed)")
        }
        Fingerprint::Unknown if !p.settled => "unknown (not settled yet)".into(),
        Fingerprint::Unknown => "unknown".into(),
    }
}

/// A flag's evidence line: `key=value key=value`.
pub fn evidence_line(f: &Flag) -> String {
    f.evidence
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// A reply in the shape satd's `getpeerbehavior` gives.
    pub(crate) fn reply() -> Value {
        json!([
            {
                "id": 3, "connection_type": "outbound-full-relay", "session_secs": 4000,
                "subver": "/Satoshi:27.0.0/", "evaluated": true,
                "fingerprint": {"result": "mismatch", "claimed": "core", "observed": "btcd",
                                "settled": true, "handshake": ["version", "verack", "sendaddrv2"]},
                "flag_codes": "F", "flags": [{"code": "F", "name": "fingerprint-mismatch",
                                              "evidence": {"claimed": "core", "observed": "btcd"}}],
                "counters": {"inv_tx_in": 12, "getdata_latency": {"count": 2, "p10_ms": 4, "buckets": [1, 1]},
                             "version": {"relay": true, "start_height": 900000}}
            },
            {
                "id": 7, "connection_type": "inbound", "session_secs": 4,
                "subver": "/bitcoin-seeder:0.01/", "evaluated": true,
                "fingerprint": {"result": "known", "family": "bitcoin-seeder", "confidence": "high",
                                "settled": true, "handshake": ["version", "verack", "getaddr"]},
                "flag_codes": "C", "flags": [{"code": "C", "name": "crawler",
                                              "evidence": {"session_secs": 4, "getaddr_in": 1}}],
                "counters": {"getaddr_in": 1}
            },
            {
                "id": 9, "connection_type": "inbound", "session_secs": 9000,
                "subver": "/Satoshi:28.1.0/", "evaluated": true,
                "fingerprint": {"result": "known", "family": "core", "confidence": "high",
                                "settled": true, "handshake": []},
                "flag_codes": "ST", "flags": [], "counters": {}
            },
            {
                "id": 11, "connection_type": "inbound", "session_secs": 2,
                "subver": "", "evaluated": false,
                "fingerprint": {"result": "unknown", "settled": false, "handshake": ["version"]},
                "flag_codes": "", "flags": [], "counters": {}
            }
        ])
    }

    #[test]
    fn parses_the_getpeerbehavior_shape() {
        let map = parse(&reply()).expect("array");
        assert_eq!(map.len(), 4);
        let p = &map[&3];
        assert_eq!(p.connection_type, "outbound-full-relay");
        assert_eq!(
            p.fingerprint,
            Fingerprint::Mismatch {
                claimed: "core".into(),
                observed: "btcd".into()
            }
        );
        assert_eq!(p.handshake, ["version", "verack", "sendaddrv2"]);
        assert_eq!(p.flags[0].code, "F");
        assert_eq!(evidence_line(&p.flags[0]), "claimed=core observed=btcd");
        assert!(p.counters.contains(&("inv_tx_in".into(), "12".into())));
        assert!(
            p.counters
                .contains(&("getdata_latency.buckets".into(), "1 1".into()))
        );
        assert!(
            p.counters
                .contains(&("version.start_height".into(), "900000".into()))
        );
        assert_eq!(map[&11].fingerprint, Fingerprint::Unknown);
        assert!(!map[&11].settled);
        assert!(parse(&json!({"not": "an array"})).is_none());
    }

    /// An older node, or another implementation, has no `getpeerbehavior`:
    /// its "method not found" hides the feature rather than showing a
    /// failure, and any other error keeps what the TUI had.
    #[test]
    fn method_not_found_means_not_served() {
        let mnf = RpcError::Rpc {
            code: JSONRPC_METHOD_NOT_FOUND,
            message: "Method not found".into(),
        };
        assert!(matches!(classify(Err(mnf)), Poll::NotServed));
        assert!(matches!(classify(Err(RpcError::Timeout)), Poll::Failed(_)));
        assert!(matches!(classify(Ok(json!({}))), Poll::Failed(_)));
        assert!(matches!(classify(Ok(reply())), Poll::Answered(m) if m.len() == 4));
    }

    #[test]
    fn flags_cell_colours() {
        let map = parse(&reply()).unwrap();
        assert_eq!(
            flags_cell(&map[&7]),
            ("C".into(), FlagsTone::Warn),
            "one flag is yellow"
        );
        assert_eq!(
            flags_cell(&map[&9]),
            ("ST".into(), FlagsTone::Alarm),
            "two flags are red"
        );
        assert_eq!(
            flags_cell(&map[&11]),
            (String::new(), FlagsTone::None),
            "none is empty"
        );
        let spy = PeerBehavior {
            flag_codes: "S".into(),
            ..Default::default()
        };
        assert_eq!(
            flags_cell(&spy),
            ("S".into(), FlagsTone::Alarm),
            "S alone is red"
        );
        let many = PeerBehavior {
            flag_codes: "CSFAHNT".into(),
            ..Default::default()
        };
        assert_eq!(flags_cell(&many).0.chars().count(), FLAGS_WIDTH as usize);
    }

    /// An alt-slot peer carries `alt` in the Flags column, a fallback
    /// `alt*`, ahead of its codes; a reply without `alt_slot` has neither.
    #[test]
    fn alt_slot_tags() {
        let mut v = reply();
        v[0]["alt_slot"] = json!({"rule": "family:btcd@2", "trust": "verified", "fallback": false});
        v[1]["alt_slot"] = json!({"rule": null, "trust": null, "fallback": true});
        let map = parse(&v).unwrap();
        assert_eq!(
            map[&3].alt_slot,
            Some(AltSlot::Matched {
                rule: "family:btcd@2".into(),
                trust: "verified".into()
            })
        );
        assert_eq!(flags_cell(&map[&3]).0, "alt F");
        assert_eq!(flags_cell(&map[&7]).0, "alt* C");
        assert_eq!(flags_cell(&map[&11]).0, "", "no tag without an alt_slot");
        let quiet = PeerBehavior {
            alt_slot: Some(AltSlot::Fallback),
            ..Default::default()
        };
        assert_eq!(flags_cell(&quiet), ("alt*".into(), FlagsTone::None));
        assert_eq!(alt_slot_counts(&map), (1, 1));
        assert_eq!(alt_slot_counts(&parse(&reply()).unwrap()), (0, 0));
    }

    #[test]
    fn mismatch_marker_follows_the_agent() {
        let map = parse(&reply()).unwrap();
        assert_eq!(
            agent_cell("/Satoshi:27.0.0/", Some(&map[&3])),
            "/Satoshi:27.0.0/ ≠"
        );
        assert_eq!(
            agent_cell("/Satoshi:28.1.0/", Some(&map[&9])),
            "/Satoshi:28.1.0/"
        );
        assert_eq!(
            agent_cell("/Satoshi:27.0.0/", None),
            "/Satoshi:27.0.0/",
            "no data, no marker"
        );
    }

    /// A user agent is the peer's own text: an escape sequence in it must
    /// not reach the terminal.
    #[test]
    fn peer_strings_are_escaped() {
        assert_eq!(agent_cell("/evil\x1b[2J:1/", None), "/evil?[2J:1/");
        let v = json!([{
            "id": 1, "subver": "/x\x07/",
            "fingerprint": {"result": "known", "family": "core\x1b", "confidence": "high",
                            "settled": true, "handshake": ["ver\nsion"]},
            "flag_codes": "", "flags": [{"code": "C", "name": "n", "evidence": {"k\x1b": "v\x1b"}}],
            "counters": {"c": "\x1b"}
        }]);
        let p = &parse(&v).unwrap()[&1];
        assert_eq!(p.subver, "/x?/");
        assert_eq!(p.fingerprint.observed(), "core?");
        assert_eq!(p.handshake, ["ver?sion"]);
        assert_eq!(evidence_line(&p.flags[0]), "k?=v?");
        assert_eq!(p.counters, [("c".to_string(), "?".to_string())]);
    }

    /// A claimed fingerprint is unknown to the classifier: never counted
    /// as its family, and labelled apart.
    #[test]
    fn a_claimed_fingerprint_is_not_an_observed_family() {
        let v = json!([
            {"id": 1, "subver": "/Satoshi:25.1.0/", "flag_codes": "", "flags": [], "counters": {},
             "fingerprint": {"result": "claimed", "claimed": "core", "settled": true, "handshake": ["version"]}},
            {"id": 2, "subver": "/Satoshi:31.2.0/", "flag_codes": "", "flags": [], "counters": {},
             "fingerprint": {"result": "known", "family": "core", "confidence": "high", "settled": true, "handshake": []}}
        ]);
        let map = parse(&v).unwrap();
        assert_eq!(
            map[&1].fingerprint,
            Fingerprint::Claimed {
                family: "core".into()
            }
        );
        assert_eq!(map[&1].fingerprint.observed(), "unknown");
        assert_eq!(
            fingerprint_line(&map[&1]),
            "unknown; the user agent names core (claimed)"
        );
        assert_eq!(
            family_distribution(&map, 8),
            [("core".to_string(), 1), ("unknown [core]".to_string(), 1)]
        );
    }

    #[test]
    fn family_distribution_by_observed_family() {
        let map = parse(&reply()).unwrap();
        let dist = family_distribution(&map, 5);
        assert_eq!(
            dist,
            [
                ("bitcoin-seeder".to_string(), 1),
                ("btcd [core]".to_string(), 1),
                ("core".to_string(), 1),
                ("unknown".to_string(), 1),
            ]
        );
        assert_eq!(mismatch_count(&map), 1);
        let folded = family_distribution(&map, 2);
        assert_eq!(folded.last(), Some(&("other".to_string(), 2)));
        assert!(family_distribution(&BehaviorMap::new(), 5).is_empty());
    }

    #[test]
    fn fingerprint_lines() {
        let map = parse(&reply()).unwrap();
        assert_eq!(
            fingerprint_line(&map[&3]),
            "btcd, but the user agent names core"
        );
        assert_eq!(
            fingerprint_line(&map[&7]),
            "bitcoin-seeder (high confidence)"
        );
        assert_eq!(fingerprint_line(&map[&11]), "unknown (not settled yet)");
    }
}
