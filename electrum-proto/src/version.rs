//! Electrum protocol version negotiation and the per-version method table.
//!
//! A connection negotiates one protocol version with `server.version`, and
//! every later request is checked against it: a method the negotiated version
//! does not have answers "method not found", as ElectrumX's
//! `set_request_handlers` does (spesmilo/electrumx 2.0.1,
//! `src/electrumx/server/session.py`).
//!
//! The rule is the spec's (spesmilo/electrum-protocol `b3db795b`,
//! `docs/protocol-methods.rst`, `server.version`):
//! `version = min(client_max, server_max)`, and there is no common version
//! when that is below `max(client_min, server_min)`.
//!
//! A connection that never sends `server.version` is served as
//! [`PROTOCOL_MIN`], as before negotiation existed. Since 1.6 the spec asks
//! clients to send it first; satd does not require that, so a script that
//! skips it keeps working.

use std::cmp::Ordering;
use std::fmt;

use serde_json::Value;

use crate::PROTOCOL_ASOF;

/// A dotted protocol version, compared component by component the way
/// ElectrumX compares its version tuples: `1.4 < 1.4.0 < 1.4.2 < 1.6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolVersion(Vec<u32>);

impl ProtocolVersion {
    /// The version with these components.
    pub fn new(parts: &[u32]) -> Self {
        Self(parts.to_vec())
    }

    /// Parse a dotted version. Components that are not numbers are skipped,
    /// as satd always has: `"1.x.4"` reads as `1.4`, and a string with no
    /// numeric component reads as the empty version, below every real one,
    /// so it can never be negotiated.
    pub fn parse(s: &str) -> Self {
        Self(s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect())
    }

    pub fn parts(&self) -> &[u32] {
        &self.0
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u32::to_string).collect();
        f.write_str(&parts.join("."))
    }
}

/// The lowest protocol version satd speaks, as `server.features` reports it.
pub const PROTOCOL_MIN: &str = "1.4";

/// The highest protocol version satd speaks, as `server.features` reports it.
pub const PROTOCOL_MAX: &str = "1.4";

/// The version a `1.4.2-asof` session speaks: rbitcoin's dialect is 1.4.2
/// with stamps and `asof:`, and a client that asks for it gets it whatever
/// else its range names.
const ASOF_VERSION: &[u32] = &[1, 4, 2];

pub fn protocol_min() -> ProtocolVersion {
    ProtocolVersion::parse(PROTOCOL_MIN)
}

pub fn protocol_max() -> ProtocolVersion {
    ProtocolVersion::parse(PROTOCOL_MAX)
}

/// What a successful `server.version` agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The version the connection's methods are gated on.
    pub version: ProtocolVersion,
    /// The string `server.version` answers with: the version, or
    /// [`PROTOCOL_ASOF`] for rbitcoin's dialect.
    pub answer: String,
}

/// Negotiate from `server.version`'s parameters. `None` when the client's
/// range and satd's have no version in common.
///
/// The protocol argument is the second parameter; anything after it is
/// ignored, as the spec requires since 1.6. A missing or null argument is the
/// spec's default, a single `PROTOCOL_MIN`. A single string `v` is the range
/// `[v, v]`. In a pair, a missing or non-string end is that default too,
/// [`PROTOCOL_MIN`], so a short or malformed range never negotiates more
/// than a client that sent nothing; an argument of any other type is treated
/// as missing, as satd always has.
pub fn negotiate(params: &Value) -> Option<Negotiated> {
    if asks_for_asof(params) {
        return Some(Negotiated {
            version: ProtocolVersion::new(ASOF_VERSION),
            answer: PROTOCOL_ASOF.to_string(),
        });
    }
    let (server_min, server_max) = (protocol_min(), protocol_max());
    let arg = params.as_array().and_then(|a| a.get(1));
    let (client_min, client_max) = match arg {
        Some(Value::String(v)) => (ProtocolVersion::parse(v), ProtocolVersion::parse(v)),
        Some(Value::Array(range)) => {
            let end = |i: usize| {
                range
                    .get(i)
                    .and_then(Value::as_str)
                    .map_or_else(protocol_min, ProtocolVersion::parse)
            };
            (end(0), end(1))
        }
        _ => (server_min.clone(), server_min.clone()),
    };
    let version = client_max.min(server_max);
    if version < client_min.max(server_min) {
        return None;
    }
    Some(Negotiated {
        answer: version.to_string(),
        version,
    })
}

/// Whether `server.version`'s `protocol_version` names [`PROTOCOL_ASOF`]:
/// the single string, or either end of a `[min, max]` pair, as rbitcoin
/// negotiates it.
pub fn asks_for_asof(params: &Value) -> bool {
    match params.as_array().and_then(|a| a.get(1)) {
        Some(Value::String(s)) => s == PROTOCOL_ASOF,
        Some(Value::Array(range)) => range
            .iter()
            .take(2)
            .any(|v| v.as_str() == Some(PROTOCOL_ASOF)),
        _ => false,
    }
}

/// One connection's negotiation state.
#[derive(Debug, Clone, Default)]
pub struct Session {
    negotiated: Option<Negotiated>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// The version this connection's requests are served at: the negotiated
    /// one, or [`PROTOCOL_MIN`] before (or without) `server.version`.
    pub fn version(&self) -> ProtocolVersion {
        self.negotiated
            .as_ref()
            .map_or_else(protocol_min, |n| n.version.clone())
    }

    /// Whether `server.version` has already succeeded on this connection.
    pub fn negotiated(&self) -> Option<&Negotiated> {
        self.negotiated.as_ref()
    }

    pub(crate) fn set(&mut self, negotiated: Negotiated) {
        self.negotiated = Some(negotiated);
    }
}

/// The versions a method is served at: from `since`, and below `until` when
/// it was removed.
struct MethodVersions {
    method: &'static str,
    since: &'static [u32],
    until: Option<&'static [u32]>,
}

const fn served(method: &'static str, since: &'static [u32]) -> MethodVersions {
    MethodVersions { method, since, until: None }
}

const V1_4: &[u32] = &[1, 4];

/// Every method satd serves, with the versions it is served at. A method not
/// listed here, or listed but outside the connection's version, is "method not
/// found".
///
/// satd's extensions are served at every version: `blockchain.headers.get`,
/// `blockchain.scripthash.get_first_use`, `blockchain.tweaks.subscribe` and
/// `blockchain.transaction.broadcast_package` (served at 1.4 before the spec
/// added it at 1.6). `blockchain.scripthash.unsubscribe` is a 1.4.2 method in
/// the spec, but 1.4 clients have always had it here, so it stays ungated.
const METHODS: &[MethodVersions] = &[
    served("server.version", V1_4),
    served("server.ping", V1_4),
    served("server.banner", V1_4),
    served("server.donation_address", V1_4),
    served("server.features", V1_4),
    served("server.peers.subscribe", V1_4),
    served("blockchain.headers.subscribe", V1_4),
    served("blockchain.headers.get", V1_4),
    served("blockchain.block.header", V1_4),
    served("blockchain.block.headers", V1_4),
    served("blockchain.scripthash.get_history", V1_4),
    served("blockchain.scripthash.get_balance", V1_4),
    served("blockchain.scripthash.listunspent", V1_4),
    served("blockchain.scripthash.get_mempool", V1_4),
    served("blockchain.scripthash.get_first_use", V1_4),
    served("blockchain.scripthash.subscribe", V1_4),
    served("blockchain.scripthash.unsubscribe", V1_4),
    served("blockchain.tweaks.subscribe", V1_4),
    served("blockchain.transaction.get", V1_4),
    served("blockchain.transaction.get_merkle", V1_4),
    served("blockchain.transaction.id_from_pos", V1_4),
    served("blockchain.transaction.broadcast", V1_4),
    served("blockchain.transaction.broadcast_package", V1_4),
    served("blockchain.estimatefee", V1_4),
    served("blockchain.relayfee", V1_4),
    served("mempool.get_fee_histogram", V1_4),
];

/// Whether `method` is served at `version`.
pub fn method_served(method: &str, version: &ProtocolVersion) -> bool {
    served_in(METHODS, method, version)
}

fn served_in(table: &[MethodVersions], method: &str, version: &ProtocolVersion) -> bool {
    table.iter().any(|m| {
        m.method == method
            && version.parts() >= m.since
            && m.until.is_none_or(|until| version.parts() < until)
    })
}

/// Every method in the table, for tests that walk it.
#[cfg(test)]
pub(crate) fn all_methods() -> impl Iterator<Item = &'static str> {
    METHODS.iter().map(|m| m.method)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn answer(params: Value) -> Option<String> {
        negotiate(&params).map(|n| n.answer)
    }

    #[test]
    fn versions_compare_like_electrumx_tuples() {
        let v = ProtocolVersion::parse;
        assert!(v("1.4") < v("1.4.0"));
        assert!(v("1.4.0") < v("1.4.2"));
        assert!(v("1.4.5") < v("1.5"));
        assert!(v("2.0") > v("1.99"));
        assert_eq!(v("1.4.5"), v("1.4.5"));
        assert_eq!(v("1.4.2").to_string(), "1.4.2");
    }

    /// At satd's 1.4..1.4 the spec rule gives the answers satd gave before it
    /// negotiated: an exact `1.4`, a range containing it, and nothing else.
    #[test]
    fn negotiation_at_one_four_matches_the_old_exact_check() {
        assert_eq!(answer(json!(["w", "1.4"])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", "1.4.5"])), None);
        assert_eq!(answer(json!(["w", "1.5"])), None);
        assert_eq!(answer(json!(["w", "1.3"])), None);
        // Sparrow.
        assert_eq!(answer(json!(["w", ["1.3", "1.4.2"]])).as_deref(), Some("1.4"));
        // Electrum, BDK: 1.5 and 1.6 lie inside the range, 1.4 is the overlap.
        assert_eq!(answer(json!(["w", ["1.4", "1.6"]])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", ["1.2", "1.5"]])).as_deref(), Some("1.4"));
        // No overlap, either side.
        assert_eq!(answer(json!(["w", ["1.4.5", "1.7"]])), None);
        assert_eq!(answer(json!(["w", ["1.0", "1.3"]])), None);
        assert_eq!(answer(json!(["w", ["1.5", "1.3"]])), None);
        assert_eq!(answer(json!(["w", "garbage"])), None);
    }

    /// The spec default and satd's long-standing leniency: no argument, null,
    /// a non-string argument, and a pair with a missing end, which is the
    /// default too.
    #[test]
    fn missing_arguments_take_the_defaults() {
        assert_eq!(answer(json!([])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w"])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", null])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", 14])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", ["1.3"]])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", [null, "1.4"]])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!(["w", []])).as_deref(), Some("1.4"));
        assert_eq!(answer(json!({"client": "w"})).as_deref(), Some("1.4"));
    }

    /// Extra arguments after the protocol version are ignored (spec 1.6).
    #[test]
    fn extra_arguments_are_ignored() {
        assert_eq!(
            answer(json!(["electrum/4.6.2", ["1.4", "1.6"], "trailing_garbage1", 9999.9, {"dd": {}}]))
                .as_deref(),
            Some("1.4")
        );
        assert_eq!(answer(json!(["w", "1.5", "1.4"])), None);
    }

    /// rbitcoin's dialect wins over any dotted range that names it, and is a
    /// 1.4.2 session.
    #[test]
    fn the_asof_dialect_is_a_one_four_two_session() {
        for params in [
            json!(["w", "1.4.2-asof"]),
            json!(["w", ["1.4", "1.4.2-asof"]]),
            json!(["w", ["1.4.2-asof", "1.7"]]),
        ] {
            let n = negotiate(&params).expect("asof negotiates");
            assert_eq!(n.answer, PROTOCOL_ASOF);
            assert_eq!(n.version, ProtocolVersion::parse("1.4.2"));
        }
    }

    #[test]
    fn asof_dialect_is_named_not_ranged() {
        assert!(asks_for_asof(&json!(["w", "1.4.2-asof"])));
        assert!(asks_for_asof(&json!(["w", ["1.4", "1.4.2-asof"]])));
        assert!(asks_for_asof(&json!(["w", ["1.4.2-asof", "1.6"]])));
        assert!(!asks_for_asof(&json!(["w", "1.4"])));
        assert!(!asks_for_asof(&json!(["w", ["1.4", "1.6"]])));
        assert!(!asks_for_asof(&json!(["w"])));
        assert!(!asks_for_asof(&json!([])));
    }

    #[test]
    fn an_unnegotiated_session_is_served_at_the_minimum() {
        let mut s = Session::new();
        assert_eq!(s.version(), protocol_min());
        assert!(s.negotiated().is_none());
        s.set(negotiate(&json!(["w", "1.4.2-asof"])).unwrap());
        assert_eq!(s.version(), ProtocolVersion::parse("1.4.2"));
    }

    /// The gate on the table's `since` and `until` bounds, on a table of its
    /// own, since every method satd serves today is served from 1.4 on.
    #[test]
    fn a_method_outside_its_versions_is_not_served() {
        let table = [
            served("added.later", &[1, 6]),
            MethodVersions { method: "removed.later", since: V1_4, until: Some(&[1, 6]) },
        ];
        let v = ProtocolVersion::parse;
        assert!(!served_in(&table, "added.later", &v("1.4")));
        assert!(!served_in(&table, "added.later", &v("1.5")));
        assert!(served_in(&table, "added.later", &v("1.6")));
        assert!(served_in(&table, "added.later", &v("1.7")));
        assert!(served_in(&table, "removed.later", &v("1.4")));
        assert!(served_in(&table, "removed.later", &v("1.4.2")));
        assert!(!served_in(&table, "removed.later", &v("1.6")));
        assert!(!served_in(&table, "unknown", &v("1.6")));
    }

    #[test]
    fn every_method_is_served_at_the_minimum() {
        for m in all_methods() {
            assert!(method_served(m, &protocol_min()), "{m}");
        }
    }
}
