//! The network crawl as this TUI shows it: satd's `getcrawlinfo`, for the
//! Chain view's Network crawl row.
//!
//! `getcrawlinfo` carries counts only, and the TUI asks for nothing else:
//! never `getcrawlnodes` or `dumpcrawlsnapshot`, whose output holds peer
//! addresses. Only known keys are read, and every name the node sends (a
//! family, a hold reason) is drawn only when it is a short word of
//! letters, digits, `_` and `-`, so no address can reach the screen even
//! from a node that put one in its reply.
//!
//! The row is drawn only while the crawl is on. It is hidden, and nothing
//! is shown as failing, when the node:
//! - answers "method not found" (an older satd, or another implementation);
//! - reports the crawl off (`enabled: false`);
//! - refuses the method. `getcrawlinfo` is a read, so satd serves it on
//!   the read-only listener and to an `rpc:read` token; a refusal is
//!   treated as the survey row treats one, so the TUI keeps polling.

use serde_json::Value;

use crate::rpc::{RpcError, JSONRPC_METHOD_NOT_FOUND};
use crate::survey::{CAPABILITY_DENIED_CODE, READONLY_REJECT_CODE, TOP_FAMILIES};

/// The networks the crawl dials, in the order the panel lists them (satd
/// `node/src/net/crawlreport.rs`, `DIALLED`).
pub const NETWORKS: [&str; 3] = ["ipv4", "ipv6", "onion"];

/// The longest name drawn as the node sent it.
const NAME_MAX: usize = 24;

/// A name from the node as the panel draws it: as sent when it is 1 to
/// [`NAME_MAX`] letters, digits, `_` or `-`, else `?`. Family and hold
/// names are such words; anything else (an address, an escape sequence)
/// is not drawn.
pub fn word(name: &str) -> String {
    let ok = !name.is_empty()
        && name.len() <= NAME_MAX
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok { name.to_string() } else { "?".into() }
}

/// What the crawl is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrawlState {
    Running,
    /// No session may start, for each of these reasons.
    Held(Vec<String>),
    /// Stopped after a panic in a crawl task.
    Stopped,
}

/// The reachable addresses by transport, as `getcrawlinfo` classes them.
/// The four classes add up to the reachable total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Transport {
    pub v2_and_v1: u64,
    pub v1_only: u64,
    pub v2_only: u64,
    pub v2_unconfirmed: u64,
    /// Advertised with `NODE_P2P_V2`: not a fifth class.
    pub v2_advertised: u64,
}

/// One `getcrawlinfo` answer from a node running the crawl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crawl {
    pub state: CrawlState,
    /// `-peersurvey` was asked for too: the survey row says it is
    /// superseded.
    pub peersurvey_superseded: bool,
    /// Addresses with a handshake inside the liveness window.
    pub reachable: u64,
    /// `(network, count)` for each of [`NETWORKS`].
    pub by_network: Vec<(&'static str, u64)>,
    pub transport: Transport,
    /// `(family, count)` for every family with a reachable address,
    /// `unknown` included, largest first.
    pub families: Vec<(String, u64)>,
    pub mismatches: u64,
    /// Sessions since start that completed a handshake, and that did not.
    pub reached: u64,
    pub unreached: u64,
    /// Sessions open now, and the concurrency limits in force.
    pub in_flight_clearnet: u64,
    pub in_flight_tor: u64,
    pub concurrency: u64,
    pub tor_concurrency: u64,
    /// Entries in the book, and its cap.
    pub book: u64,
    pub book_max: u64,
}

impl Default for Crawl {
    fn default() -> Self {
        Crawl {
            state: CrawlState::Running,
            peersurvey_superseded: false,
            reachable: 0,
            by_network: NETWORKS.iter().map(|n| (*n, 0)).collect(),
            transport: Transport::default(),
            families: Vec::new(),
            mismatches: 0,
            reached: 0,
            unreached: 0,
            in_flight_clearnet: 0,
            in_flight_tor: 0,
            concurrency: 0,
            tor_concurrency: 0,
            book: 0,
            book_max: 0,
        }
    }
}

/// How one poll of `getcrawlinfo` moves the TUI's copy.
#[derive(Debug)]
pub enum Poll {
    /// The crawl is on: replace the copy.
    On(Crawl),
    /// Hide the row: the crawl is off, the node does not serve the method,
    /// or it refuses it to this connection.
    Hidden,
    /// Any other failure: keep the copy, show the failure.
    Failed(String),
}

/// Classify one `getcrawlinfo` result.
pub fn classify(res: Result<Value, RpcError>) -> Poll {
    match res {
        Ok(v) => match v.get("enabled").and_then(Value::as_bool) {
            Some(false) => Poll::Hidden,
            Some(true) => match parse(&v) {
                Some(c) => Poll::On(c),
                None => Poll::Failed("unexpected reply".into()),
            },
            None => Poll::Failed("unexpected reply".into()),
        },
        Err(RpcError::Rpc { code, .. })
            if code == JSONRPC_METHOD_NOT_FOUND || code == READONLY_REJECT_CODE || code == CAPABILITY_DENIED_CODE =>
        {
            Poll::Hidden
        }
        Err(e) => Poll::Failed(e.to_string()),
    }
}

fn count(v: Option<&Value>, key: &str) -> u64 {
    v.and_then(|v| v.get(key)).and_then(Value::as_u64).unwrap_or(0)
}

/// Parse the answer of a node running the crawl. `None` without a
/// reachable total or a state.
pub fn parse(v: &Value) -> Option<Crawl> {
    let reachable_obj = v.get("reachable")?;
    let reachable = reachable_obj.get("total")?.as_u64()?;
    let state = match v.get("state")?.as_str()? {
        "running" => CrawlState::Running,
        "stopped" => CrawlState::Stopped,
        "held" => CrawlState::Held(
            v.get("held_by")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(word).collect())
                .unwrap_or_default(),
        ),
        _ => return None,
    };
    let by_network = NETWORKS.iter().map(|n| (*n, count(Some(reachable_obj), n))).collect();
    let t = v.get("transport");
    let class = |name: &str| count(t.and_then(|t| t.get(name)), "count");
    let transport = Transport {
        v2_and_v1: class("v2_and_v1"),
        v1_only: class("v1_only"),
        v2_only: class("v2_only"),
        v2_unconfirmed: class("v2_unconfirmed"),
        v2_advertised: class("v2_advertised"),
    };
    let mut families: Vec<(String, u64)> = v
        .get("families")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(name, f)| (word(name), count(Some(f), "count"))).filter(|(_, n)| *n > 0).collect())
        .unwrap_or_default();
    families.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let sessions = v.get("sessions");
    let in_flight = sessions.and_then(|s| s.get("in_flight"));
    let limits = v.get("limits");
    let book = v.get("book");
    Some(Crawl {
        state,
        peersurvey_superseded: v.get("peersurvey_superseded").and_then(Value::as_bool).unwrap_or(false),
        reachable,
        by_network,
        transport,
        families,
        mismatches: count(Some(v), "mismatches"),
        reached: count(sessions, "reached"),
        unreached: count(sessions, "unreached"),
        in_flight_clearnet: count(in_flight, "clearnet"),
        in_flight_tor: count(in_flight, "tor"),
        concurrency: count(limits, "concurrency"),
        tor_concurrency: count(limits, "tor_concurrency"),
        book: count(book, "entries"),
        book_max: count(book, "max_entries"),
    })
}

/// A hold reason as the panel states it.
pub fn hold_text(reason: &str) -> String {
    match reason {
        "initial_block_download" => "initial block download".into(),
        "connect" => "-connect".into(),
        "network_inactive" => "networking off".into(),
        other => word(other),
    }
}

impl Crawl {
    /// `n` as a percentage of the reachable addresses; 0 with none.
    pub fn pct(&self, n: u64) -> f64 {
        if self.reachable == 0 { 0.0 } else { n as f64 * 100.0 / self.reachable as f64 }
    }

    /// The bars: the [`TOP_FAMILIES`] largest families, the rest folded
    /// into `other`.
    pub fn family_bars(&self) -> Vec<(String, u64)> {
        if self.families.len() <= TOP_FAMILIES {
            return self.families.clone();
        }
        let other = self.families[TOP_FAMILIES..].iter().map(|(_, n)| n).sum();
        let mut out = self.families[..TOP_FAMILIES].to_vec();
        out.push(("other".into(), other));
        out
    }

    /// Reachable addresses whose handshake matched a family other than
    /// Core's, as a percentage, counted as the survey row counts them:
    /// Core's forks count as Core, `unknown` is left out.
    pub fn non_core_pct(&self) -> f64 {
        let non_core = self.families.iter().filter(|(f, _)| f != "core" && f != "unknown").map(|(_, n)| n).sum();
        self.pct(non_core)
    }

    /// The state as the panel and the summary line state it.
    pub fn state_text(&self) -> String {
        match &self.state {
            CrawlState::Running => "running".into(),
            CrawlState::Stopped => "stopped (a crawl task panicked)".into(),
            CrawlState::Held(reasons) if reasons.is_empty() => "held".into(),
            CrawlState::Held(reasons) => {
                format!("held: {}", reasons.iter().map(|r| hold_text(r)).collect::<Vec<_>>().join(", "))
            }
        }
    }

    /// The one line the row collapses to on a short terminal.
    pub fn summary(&self) -> String {
        format!(
            "crawl: {}, {} reachable, non-Core {:.1} %, v2-only {}",
            self.state_text(),
            crate::ui::format_num(self.reachable),
            self.non_core_pct(),
            crate::ui::format_num(self.transport.v2_only)
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// An answer in the shape satd's `getcrawlinfo` gives with the crawl on.
    pub(crate) fn reply() -> Value {
        json!({
            "enabled": true,
            "state": "running",
            "held_by": [],
            "stopped_by": null,
            "started": true,
            "peersurvey_superseded": true,
            "limits": {"concurrency": 32, "tor_concurrency": 8, "rate": 10,
                       "liveness": 7200, "max_age": 432000, "probes": true,
                       "networks": ["ipv4", "ipv6", "onion"], "bind": false},
            "book": {"entries": 61234, "max_entries": 250000,
                     "learned": {"ipv4": 41000, "ipv6": 9000, "onion": 11000, "i2p": 200, "cjdns": 34},
                     "ever_reached": {"ipv4": 14000, "ipv6": 3100, "onion": 6400, "i2p": 0, "cjdns": 0}},
            "reachable": {"total": 21000, "ipv4": 12500, "ipv6": 2600, "onion": 5900},
            "transport": {"v2_and_v1": {"count": 9000, "share": 0.4286},
                          "v1_only": {"count": 11500, "share": 0.5476},
                          "v2_only": {"count": 40, "share": 0.0019},
                          "v2_unconfirmed": {"count": 460, "share": 0.0219},
                          "v2_advertised": {"count": 9400, "share": 0.4476}},
            "families": {"core": {"count": 20100, "share": 0.9571},
                         "btcd": {"count": 150, "share": 0.0071},
                         "satd": {"count": 60, "share": 0.0029},
                         "rbitcoin": {"count": 40, "share": 0.0019},
                         "bcoin": {"count": 20, "share": 0.001},
                         "libbitcoin": {"count": 15, "share": 0.0007},
                         "floresta": {"count": 10, "share": 0.0005},
                         "bitcoin-seeder": {"count": 5, "share": 0.0002},
                         "bitnodes": {"count": 0, "share": 0.0},
                         "unknown": {"count": 600, "share": 0.0286}},
            "mismatches": 12,
            "sessions": {"reached": 50213, "unreached": 140022,
                         "in_flight": {"clearnet": 31, "tor": 8}},
            "totals": {"totalbytessent": 81234567, "totalbytesrecv": 912345678}
        })
    }

    /// The reply of a crawl that is off: the same keys, counts zero.
    pub(crate) fn off_reply() -> Value {
        let mut v = reply();
        v["enabled"] = json!(false);
        v["state"] = json!("off");
        v
    }

    #[test]
    fn parses_the_getcrawlinfo_shape() {
        let c = parse(&reply()).expect("aggregate");
        assert_eq!(c.state, CrawlState::Running);
        assert!(c.peersurvey_superseded);
        assert_eq!(c.reachable, 21000);
        assert_eq!(c.by_network, [("ipv4", 12500), ("ipv6", 2600), ("onion", 5900)]);
        assert_eq!(
            c.transport,
            Transport { v2_and_v1: 9000, v1_only: 11500, v2_only: 40, v2_unconfirmed: 460, v2_advertised: 9400 }
        );
        assert_eq!(c.families.len(), 9, "bitnodes has no reachable address");
        assert_eq!(c.families[0], ("core".to_string(), 20100));
        assert_eq!(c.families[1], ("unknown".to_string(), 600));
        assert_eq!((c.mismatches, c.reached, c.unreached), (12, 50213, 140022));
        assert_eq!((c.in_flight_clearnet, c.in_flight_tor, c.concurrency, c.tor_concurrency), (31, 8, 32, 8));
        assert_eq!((c.book, c.book_max), (61234, 250000));
    }

    #[test]
    fn held_and_stopped() {
        let mut v = reply();
        v["state"] = json!("held");
        v["held_by"] = json!(["initial_block_download", "connect"]);
        let c = parse(&v).unwrap();
        assert_eq!(c.state, CrawlState::Held(vec!["initial_block_download".into(), "connect".into()]));
        assert_eq!(c.state_text(), "held: initial block download, -connect");
        v["held_by"] = json!(["network_inactive", "a_new_reason"]);
        assert_eq!(parse(&v).unwrap().state_text(), "held: networking off, a_new_reason");
        v["state"] = json!("stopped");
        v["stopped_by"] = json!("panic");
        assert_eq!(parse(&v).unwrap().state_text(), "stopped (a crawl task panicked)");
        v["state"] = json!("dancing");
        assert!(parse(&v).is_none(), "an unknown state is not guessed at");
    }

    /// The row is hidden, with nothing failing, on a node without the
    /// method, with the crawl off, and where the method is refused.
    /// Anything else keeps the last answer and shows the failure.
    #[test]
    fn hidden_off_unserved_or_refused() {
        assert!(matches!(classify(Ok(off_reply())), Poll::Hidden));
        for code in [JSONRPC_METHOD_NOT_FOUND, READONLY_REJECT_CODE, CAPABILITY_DENIED_CODE] {
            let e = RpcError::Rpc { code, message: "no".into() };
            assert!(matches!(classify(Err(e)), Poll::Hidden), "{code}");
        }
        assert!(matches!(classify(Err(RpcError::Timeout)), Poll::Failed(_)));
        assert!(matches!(classify(Err(RpcError::Rpc { code: -1, message: "x".into() })), Poll::Failed(_)));
        assert!(matches!(classify(Ok(json!({"enabled": true}))), Poll::Failed(_)), "no counts");
        assert!(matches!(classify(Ok(json!([]))), Poll::Failed(_)));
        assert!(matches!(classify(Ok(reply())), Poll::On(c) if c.reachable == 21000));
    }

    #[test]
    fn top_eight_families_then_other() {
        let c = parse(&reply()).unwrap();
        let bars = c.family_bars();
        assert_eq!(bars.len(), TOP_FAMILIES + 1);
        assert_eq!(bars[TOP_FAMILIES], ("other".to_string(), 5), "bitcoin-seeder's 5 folded");
        assert_eq!(bars.iter().map(|(_, n)| n).sum::<u64>(), 21000);
    }

    #[test]
    fn non_core_share_and_the_collapsed_line() {
        let c = parse(&reply()).unwrap();
        // 150 + 60 + 40 + 20 + 15 + 10 + 5 = 300 of 21,000.
        assert!((c.non_core_pct() - 300.0 * 100.0 / 21000.0).abs() < 1e-9);
        assert_eq!(c.summary(), "crawl: running, 21,000 reachable, non-Core 1.4 %, v2-only 40");
        assert_eq!(Crawl::default().non_core_pct(), 0.0, "no address, no division by zero");
    }

    /// A name from the node is drawn only as a plain word: an address or
    /// an escape sequence in a family or hold name never reaches the
    /// terminal.
    #[test]
    fn names_are_words_or_not_drawn() {
        assert_eq!(word("bitcoin-seeder"), "bitcoin-seeder");
        assert_eq!(word("initial_block_download"), "initial_block_download");
        for bad in ["203.0.113.7", "203.0.113.7:8333", "[2001:db8::1]:8333", "2001:db8::1",
                    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion", "co\x1b[2Jre", "", "a b"] {
            assert_eq!(word(bad), "?", "{bad:?}");
        }
        // A bare onion's 56 base32 characters are too long to be a name.
        assert_eq!(word(&"a".repeat(56)), "?");
    }
}
