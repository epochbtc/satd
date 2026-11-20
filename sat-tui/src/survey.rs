//! The network survey as this TUI shows it: satd's `getpeersurvey`
//! aggregate, for the Chain view's Network survey row.
//!
//! The TUI only ever asks for the aggregate, never `getpeersurvey true`:
//! the per-address rows hold peer addresses, and nothing here needs them.
//!
//! The row is drawn only while the node runs the survey. It is hidden, and
//! nothing is shown as failing, when the node:
//! - answers "method not found" (an older satd, or another implementation);
//! - reports the survey off (`enabled: false`);
//! - refuses the method: `getpeersurvey` is operator control, so the
//!   read-only listener and a bearer token without `rpc:write` are refused
//!   it. The TUI keeps polling, since a reloaded authfile can grant it.
//!
//! Family names come from the node, which is not trusted to keep them
//! printable: each goes through [`printable`] before it is drawn.

use serde_json::Value;

use crate::nap::printable;
use crate::rpc::{RpcError, JSONRPC_METHOD_NOT_FOUND};

/// The read-only RPC listener's code for a method it does not expose
/// (satd `node/src/rpc/readonly.rs`, `READONLY_REJECT_CODE`).
pub const READONLY_REJECT_CODE: i64 = -32001;

/// The code for a method the bearer token lacks the capability for (satd
/// `node/src/rpc/capability.rs`, `CAPABILITY_DENIED_CODE`).
pub const CAPABILITY_DENIED_CODE: i64 = -32004;

/// How long the node keeps a record it has not seen again: the window the
/// aggregate covers (satd `node/src/net/survey.rs`, `EXPIRY_SECS`).
pub const WINDOW_DAYS: u64 = 30;

/// Families drawn as bars before the rest fold into `other`.
pub const TOP_FAMILIES: usize = 8;

/// Autonomous systems listed.
pub const TOP_AS: usize = 5;

/// The survey's last connection to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastConnection {
    /// Unix seconds, by the node's clock.
    pub time: u64,
    pub completed: bool,
}

/// One `getpeersurvey` answer from a node running the survey.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Survey {
    /// Addresses in the store: those reached in the last [`WINDOW_DAYS`].
    pub addresses: u64,
    /// `(family, count)` for every family with a record, `unknown`
    /// included, largest first.
    pub families: Vec<(String, u64)>,
    pub mismatches: u64,
    pub v2: u64,
    /// `(asn, count)`, largest first, as the node lists them.
    pub top_as: Vec<(u64, u64)>,
    /// Records with at least one probe outcome.
    pub probed: u64,
    /// `-peersurveyprobes`.
    pub probes: bool,
    /// Survey connections since the node started.
    pub completed: u64,
    pub failed: u64,
    /// `None` until a survey connection has ended, and from a node that
    /// does not report it.
    pub last: Option<LastConnection>,
}

/// How one poll of `getpeersurvey` moves the TUI's copy.
#[derive(Debug)]
pub enum Poll {
    /// The survey runs: replace the copy.
    On(Survey),
    /// Hide the row: the survey is off, the node does not serve the method,
    /// or it refuses it to this connection.
    Hidden,
    /// Any other failure: keep the copy, show the failure.
    Failed(String),
}

/// Classify one `getpeersurvey` result.
pub fn classify(res: Result<Value, RpcError>) -> Poll {
    match res {
        Ok(v) => match v.get("enabled").and_then(Value::as_bool) {
            Some(false) => Poll::Hidden,
            Some(true) => match parse(&v) {
                Some(s) => Poll::On(s),
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

fn count(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Parse the aggregate of a node running the survey. `None` without an
/// `addresses` count.
pub fn parse(v: &Value) -> Option<Survey> {
    let addresses = v.get("addresses")?.as_u64()?;
    let mut families: Vec<(String, u64)> = v
        .get("families")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(name, f)| (printable(name), count(f, "count"))).filter(|(_, n)| *n > 0).collect())
        .unwrap_or_default();
    families.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_as = v
        .get("top_as")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|e| Some((e.get("asn")?.as_u64()?, count(e, "count")))).collect())
        .unwrap_or_default();
    let conns = v.get("connections");
    let last = conns.and_then(|c| c.get("last")).and_then(|l| {
        Some(LastConnection {
            time: l.get("time")?.as_u64()?,
            completed: l.get("result")?.as_str()? == "completed",
        })
    });
    Some(Survey {
        addresses,
        families,
        mismatches: count(v, "mismatches"),
        v2: v.get("v2").map(|x| count(x, "count")).unwrap_or(0),
        top_as,
        probed: count(v, "probed"),
        probes: v.get("probes").and_then(Value::as_bool).unwrap_or(false),
        completed: conns.map(|c| count(c, "completed")).unwrap_or(0),
        failed: conns.map(|c| count(c, "failed")).unwrap_or(0),
        last,
    })
}

impl Survey {
    /// `n` as a percentage of the addresses; 0 with none.
    pub fn pct(&self, n: u64) -> f64 {
        if self.addresses == 0 { 0.0 } else { n as f64 * 100.0 / self.addresses as f64 }
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

    /// Records whose handshake matched a family other than Core's, as a
    /// percentage of the addresses. Core's forks share its networking code
    /// and count as Core; `unknown` is not counted, since it says nothing
    /// about which implementation answered.
    pub fn non_core_pct(&self) -> f64 {
        let non_core = self.families.iter().filter(|(f, _)| f != "core" && f != "unknown").map(|(_, n)| n).sum();
        self.pct(non_core)
    }

    /// The one line the row collapses to on a short terminal.
    pub fn summary(&self) -> String {
        format!(
            "survey: {} addrs, non-Core {:.1} %, v2 {:.0} %",
            crate::ui::format_num(self.addresses),
            self.non_core_pct(),
            self.pct(self.v2)
        )
    }

    /// The last connection as the panel states it, against `now` (Unix
    /// seconds).
    pub fn last_line(&self, now: u64) -> String {
        match self.last {
            Some(l) => format!(
                "{} ago, {}",
                crate::ui::format_duration(now.saturating_sub(l.time)),
                if l.completed { "completed" } else { "failed" }
            ),
            None => "none yet".into(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// An answer in the shape satd's `getpeersurvey` gives with the survey on.
    pub(crate) fn reply() -> Value {
        json!({
            "addresses": 1204,
            "families": {
                "core": {"count": 1080, "share": 0.897},
                "btcd": {"count": 30, "share": 0.025},
                "bcoin": {"count": 4, "share": 0.003},
                "libbitcoin": {"count": 3, "share": 0.002},
                "floresta": {"count": 2, "share": 0.002},
                "rbitcoin": {"count": 9, "share": 0.007},
                "satd": {"count": 12, "share": 0.01},
                "bitcoin-seeder": {"count": 6, "share": 0.005},
                "bitnodes": {"count": 0, "share": 0.0},
                "unknown": {"count": 58, "share": 0.048}
            },
            "mismatches": 5,
            "v2": {"count": 494, "share": 0.41},
            "top_as": [{"asn": 64496, "count": 84}, {"asn": 64497, "count": 61}],
            "probed": 600,
            "enabled": true,
            "probes": true,
            "interval": 60,
            "connections": {"completed": 1300, "failed": 2100,
                            "last": {"time": 1_790_000_000u64, "result": "completed"}}
        })
    }

    #[test]
    fn parses_the_getpeersurvey_shape() {
        let s = parse(&reply()).expect("aggregate");
        assert_eq!(s.addresses, 1204);
        assert_eq!(s.families.len(), 9, "bitnodes has no record");
        assert_eq!(s.families[0], ("core".to_string(), 1080));
        assert_eq!(s.families[1], ("unknown".to_string(), 58));
        assert_eq!(s.v2, 494);
        assert_eq!(s.top_as, [(64496, 84), (64497, 61)]);
        assert_eq!((s.completed, s.failed, s.probed, s.probes), (1300, 2100, 600, true));
        assert_eq!(s.last, Some(LastConnection { time: 1_790_000_000, completed: true }));

        // Before any connection ends, and from a node without the field.
        let mut v = reply();
        v["connections"]["last"] = Value::Null;
        assert_eq!(parse(&v).unwrap().last, None);
        v["connections"].as_object_mut().unwrap().remove("last");
        assert_eq!(parse(&v).unwrap().last, None);
    }

    /// The row is hidden, with nothing failing, on a node without the
    /// method, with the survey off, and where the method is refused (the
    /// read-only listener, a token without `rpc:write`). Anything else
    /// keeps the last answer and shows the failure.
    #[test]
    fn hidden_off_unserved_or_refused() {
        let off = json!({"addresses": 0, "families": {}, "mismatches": 0, "v2": {"count": 0, "share": 0.0},
                         "top_as": [], "probed": 0, "enabled": false});
        assert!(matches!(classify(Ok(off)), Poll::Hidden));
        for code in [JSONRPC_METHOD_NOT_FOUND, READONLY_REJECT_CODE, CAPABILITY_DENIED_CODE] {
            let e = RpcError::Rpc { code, message: "no".into() };
            assert!(matches!(classify(Err(e)), Poll::Hidden), "{code}");
        }
        assert!(matches!(classify(Err(RpcError::Timeout)), Poll::Failed(_)));
        assert!(matches!(classify(Err(RpcError::Rpc { code: -1, message: "x".into() })), Poll::Failed(_)));
        assert!(matches!(classify(Ok(json!({"enabled": true}))), Poll::Failed(_)), "no counts");
        assert!(matches!(classify(Ok(json!([]))), Poll::Failed(_)));
        assert!(matches!(classify(Ok(reply())), Poll::On(s) if s.addresses == 1204));
    }

    #[test]
    fn top_eight_families_then_other() {
        let s = parse(&reply()).unwrap();
        let bars = s.family_bars();
        assert_eq!(bars.len(), TOP_FAMILIES + 1);
        assert_eq!(bars[TOP_FAMILIES], ("other".to_string(), 2), "floresta's 2 folded");
        assert_eq!(bars.iter().map(|(_, n)| n).sum::<u64>(), 1204);
        let few = Survey { families: vec![("core".into(), 2)], addresses: 2, ..Default::default() };
        assert_eq!(few.family_bars(), [("core".to_string(), 2)]);
    }

    #[test]
    fn non_core_share_leaves_out_core_and_unknown() {
        let s = parse(&reply()).unwrap();
        // 30 + 4 + 3 + 2 + 9 + 12 + 6 = 66 of 1204.
        assert!((s.non_core_pct() - 66.0 * 100.0 / 1204.0).abs() < 1e-9);
        assert_eq!(Survey::default().non_core_pct(), 0.0, "no address, no division by zero");
    }

    #[test]
    fn the_collapsed_line() {
        let s = parse(&reply()).unwrap();
        assert_eq!(s.summary(), "survey: 1,204 addrs, non-Core 5.5 %, v2 41 %");
        assert_eq!(Survey::default().summary(), "survey: 0 addrs, non-Core 0.0 %, v2 0 %");
    }

    #[test]
    fn last_connection_line() {
        let mut s = parse(&reply()).unwrap();
        assert_eq!(s.last_line(1_790_000_042), "42s ago, completed");
        s.last = Some(LastConnection { time: 1_790_000_000, completed: false });
        assert_eq!(s.last_line(1_790_000_000), "0s ago, failed");
        assert_eq!(s.last_line(1_789_999_000), "0s ago, failed", "a node clock ahead of ours");
        s.last = None;
        assert_eq!(s.last_line(1_790_000_000), "none yet");
    }

    /// A family name comes from the node: an escape sequence in it must
    /// not reach the terminal.
    #[test]
    fn family_names_are_escaped() {
        let v = json!({"addresses": 1, "enabled": true, "families": {"co\x1b[2Jre": {"count": 1}}});
        assert_eq!(parse(&v).unwrap().families, [("co?[2Jre".to_string(), 1)]);
    }
}
