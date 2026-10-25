//! The Node Attestation Protocol (NAP) as this TUI shows it: what the node
//! publishes (`listnapattestations`) and the report on what it aggregates
//! (`getnapreport`).
//!
//! Each half is polled on its own and is either answered, off on the node,
//! or not known yet. The view is offered only while one of them is on.
//!
//! Keys, values and outpoints come from holders and peers. satd allows only
//! printable ASCII in keys and values, but the TUI does not rely on the node
//! it talks to: every such string goes through [`printable`] before it is
//! drawn.

use serde_json::Value;

use crate::rpc::{RpcError, JSONRPC_METHOD_NOT_FOUND};

/// The message satd answers `listnapattestations` with when `nap=1` is off.
pub const PUBLISHER_DISABLED: &str = "NAP is disabled";
/// The message satd answers `getnapreport` with when `napaggregator=1` is off.
pub const AGGREGATOR_DISABLED: &str = "the NAP aggregator is disabled";

/// One half of NAP on the polled node.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Half<T> {
    /// No answer yet.
    #[default]
    Unknown,
    /// Off on the node (or a node without NAP at all).
    Off,
    /// On; the last answer.
    On(T),
}

impl<T> Half<T> {
    pub fn is_on(&self) -> bool {
        matches!(self, Half::On(_))
    }
}

/// How one poll of a NAP RPC moves its half.
#[derive(Debug)]
pub enum Poll<T> {
    On(T),
    Off,
    /// A failure that says nothing about whether NAP is on (a timeout, a
    /// tip that kept moving). The half keeps what it had, and the failure
    /// is shown like any other RPC's.
    Failed(String),
}

/// Classify one NAP RPC result. `disabled` is the message satd gives when
/// that half is off. A method the node does not know is off too: a satd
/// older than NAP.
pub fn classify<T>(
    res: Result<Value, RpcError>,
    disabled: &str,
    parse: impl FnOnce(&Value) -> Option<T>,
) -> Poll<T> {
    match res {
        Ok(v) => match parse(&v) {
            Some(t) => Poll::On(t),
            None => Poll::Failed("unexpected reply".into()),
        },
        Err(RpcError::Rpc { code: -1, message }) if message == disabled => Poll::Off,
        Err(RpcError::Rpc { code, .. }) if code == JSONRPC_METHOD_NOT_FOUND => Poll::Off,
        Err(e) => Poll::Failed(e.to_string()),
    }
}

/// `s` with every character outside printable ASCII (0x20-0x7E) replaced by
/// `?`, so an escape sequence or control character in a holder-chosen string
/// can neither reach the terminal nor vanish unnoticed.
pub fn printable(s: &str) -> String {
    s.chars().map(|c| if (' '..='~').contains(&c) { c } else { '?' }).collect()
}

/// One attestation the node publishes.
#[derive(Debug, Clone, PartialEq)]
pub struct Published {
    pub outpoint: String,
    pub key: String,
    pub value: String,
    pub anchor_height: u64,
    /// `valid`, the rule it fails, or `unknown`.
    pub status: String,
    /// The coin's value, when valid.
    pub amount_sat: Option<u64>,
}

/// Parse `listnapattestations`.
pub fn parse_published(v: &Value) -> Option<Vec<Published>> {
    v.as_array()?
        .iter()
        .map(|a| {
            Some(Published {
                outpoint: printable(a.get("outpoint")?.as_str()?),
                key: printable(a.get("key")?.as_str()?),
                value: printable(a.get("value")?.as_str()?),
                anchor_height: a.get("anchor_height")?.as_u64()?,
                status: printable(a.get("status")?.as_str()?),
                amount_sat: a.get("amount").and_then(|amount| amount_sat(amount, a)),
            })
        })
        .collect()
}

/// An `amount` in satoshis: an integer when the reply is tagged
/// `"_units": "sats"`, otherwise BTC with eight decimals.
fn amount_sat(amount: &Value, reply: &Value) -> Option<u64> {
    if reply.get("_units").and_then(|u| u.as_str()) == Some("sats") {
        return amount.as_u64();
    }
    // Parse the decimal text rather than an f64, so 8 places stay exact.
    let text = amount.to_string();
    let (whole, frac) = text.split_once('.').unwrap_or((&text, ""));
    if frac.len() > 8 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let frac: u64 = format!("{frac:0<8}").parse().ok()?;
    whole.parse::<u64>().ok()?.checked_mul(100_000_000)?.checked_add(frac)
}

/// A weight and how many outpoints carry it.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Sum {
    pub weight_sat: u64,
    pub outpoints: u64,
}

fn parse_sum(v: &Value) -> Option<Sum> {
    Some(Sum {
        weight_sat: v.get("weight_sat")?.as_u64()?,
        outpoints: v.get("outpoints")?.as_u64()?,
    })
}

/// One bucket of a breakdown.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    pub label: String,
    pub sum: Sum,
}

/// One value of one key.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportValue {
    pub value: String,
    pub sum: Sum,
    pub share_ppm: u64,
    pub coverage_ppm: u64,
    pub value_tiers: Vec<Bucket>,
    pub anchor_age: Vec<Bucket>,
    pub coin_age: Vec<Bucket>,
    pub script_types: Vec<Bucket>,
    /// `(n, ppm)`: the heaviest `n` outpoints' share of the value's weight.
    pub concentration: Vec<(u64, u64)>,
}

/// One key.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportKey {
    pub key: String,
    pub sum: Sum,
    pub coverage_ppm: u64,
    pub withdrawn: Sum,
    /// Heaviest first, as the node orders them.
    pub values: Vec<ReportValue>,
}

/// `getnapreport`.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub height: u64,
    pub hash: String,
    pub utxo_total_sat: u64,
    pub digest: String,
    pub attestations: u64,
    pub invalid: u64,
    pub counting: u64,
    pub keys: Vec<ReportKey>,
}

fn parse_buckets(v: &Value, label: &str) -> Option<Vec<Bucket>> {
    v.as_array()?
        .iter()
        .map(|b| Some(Bucket { label: printable(b.get(label)?.as_str()?), sum: parse_sum(b)? }))
        .collect()
}

fn parse_value(v: &Value) -> Option<ReportValue> {
    let mut concentration: Vec<(u64, u64)> = v
        .get("concentration")?
        .as_object()?
        .iter()
        .map(|(name, ppm)| {
            let n = name.strip_prefix("top")?.strip_suffix("_ppm")?.parse().ok()?;
            Some((n, ppm.as_u64()?))
        })
        .collect::<Option<_>>()?;
    concentration.sort_unstable();
    Some(ReportValue {
        value: printable(v.get("value")?.as_str()?),
        sum: parse_sum(v)?,
        share_ppm: v.get("share_ppm")?.as_u64()?,
        coverage_ppm: v.get("coverage_ppm")?.as_u64()?,
        value_tiers: parse_buckets(v.get("value_tiers")?, "tier")?,
        anchor_age: parse_buckets(v.get("anchor_age")?, "blocks")?,
        coin_age: parse_buckets(v.get("coin_age")?, "blocks")?,
        script_types: parse_buckets(v.get("script_types")?, "type")?,
        concentration,
    })
}

/// Parse `getnapreport`.
pub fn parse_report(v: &Value) -> Option<Report> {
    let keys = v
        .get("keys")?
        .as_array()?
        .iter()
        .map(|k| {
            Some(ReportKey {
                key: printable(k.get("key")?.as_str()?),
                sum: parse_sum(k)?,
                coverage_ppm: k.get("coverage_ppm")?.as_u64()?,
                withdrawn: parse_sum(k.get("withdrawn")?)?,
                values: k.get("values")?.as_array()?.iter().map(parse_value).collect::<Option<_>>()?,
            })
        })
        .collect::<Option<_>>()?;
    Some(Report {
        height: v.get("height")?.as_u64()?,
        hash: printable(v.get("hash")?.as_str()?),
        utxo_total_sat: v.get("utxo_total_sat")?.as_u64()?,
        digest: printable(v.get("digest")?.as_str()?),
        attestations: v.get("attestations")?.as_u64()?,
        invalid: v.get("invalid")?.as_u64()?,
        counting: v.get("counting")?.as_u64()?,
        keys,
    })
}

impl Report {
    /// Every value of every key, in display order, as (key index, value
    /// index): the rows the selection moves over.
    pub fn value_rows(&self) -> Vec<(usize, usize)> {
        self.keys
            .iter()
            .enumerate()
            .flat_map(|(k, key)| (0..key.values.len()).map(move |v| (k, v)))
            .collect()
    }
}

/// Parts per million as a percentage with two decimals, rounded down, in
/// integers only: `123456` is `12.34%`.
pub fn ppm_percent(ppm: u64) -> String {
    format!("{}.{:02}%", ppm / 10_000, (ppm % 10_000) / 100)
}

/// `part` of `whole` in parts per million, rounded down; 0 of nothing. The
/// node computes its own shares the same way.
pub fn ppm(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        0
    } else {
        (u128::from(part) * 1_000_000 / u128::from(whole)) as u64
    }
}

/// Satoshis as BTC with all eight decimals, exactly: `1.00000000 BTC`.
pub fn sat_btc(sat: u64) -> String {
    format!("{}.{:08} BTC", sat / 100_000_000, sat % 100_000_000)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn printable_replaces_everything_outside_printable_ascii() {
        assert_eq!(printable("g1.sparrow-2.5.5 ~ok~"), "g1.sparrow-2.5.5 ~ok~");
        assert_eq!(printable("a\u{1b}[31mb"), "a?[31mb");
        assert_eq!(printable("\u{7}\t\n\r\u{7f}"), "?????");
        assert_eq!(printable("é\u{202e}x"), "??x");
    }

    #[test]
    fn a_disabled_half_is_off_and_other_failures_say_nothing() {
        let rpc = |code: i64, message: &str| -> Result<Value, RpcError> {
            Err(RpcError::Rpc { code, message: message.into() })
        };
        let parse = |_: &Value| Some(());
        assert!(matches!(classify(rpc(-1, PUBLISHER_DISABLED), PUBLISHER_DISABLED, parse), Poll::Off));
        assert!(matches!(classify(rpc(-1, AGGREGATOR_DISABLED), AGGREGATOR_DISABLED, parse), Poll::Off));
        // An older satd has no NAP methods at all.
        assert!(matches!(classify(rpc(JSONRPC_METHOD_NOT_FOUND, "Method not found"), PUBLISHER_DISABLED, parse), Poll::Off));
        // The other half's message, a busy node, a timeout: not off.
        assert!(matches!(classify(rpc(-1, AGGREGATOR_DISABLED), PUBLISHER_DISABLED, parse), Poll::Failed(_)));
        assert!(matches!(classify(rpc(-1, "the chain tip kept changing"), AGGREGATOR_DISABLED, parse), Poll::Failed(_)));
        assert!(matches!(classify(Err(RpcError::Timeout), AGGREGATOR_DISABLED, parse), Poll::Failed(_)));
        assert!(matches!(classify(Ok(json!([])), PUBLISHER_DISABLED, parse), Poll::On(())));
        // A reply that does not parse is a failure, not "on with nothing".
        assert!(matches!(classify(Ok(json!({})), PUBLISHER_DISABLED, parse_published), Poll::Failed(_)));
    }

    #[test]
    fn published_amounts_are_exact_in_either_unit() {
        let one = |amount: Value, units: Option<&str>| {
            let mut a = json!({
                "outpoint": "ab:1", "key": "k", "value": "v", "anchor_height": 7,
                "status": "valid", "amount": amount,
            });
            if let Some(u) = units {
                a["_units"] = json!(u);
            }
            parse_published(&json!([a])).unwrap().remove(0).amount_sat
        };
        assert_eq!(one(json!(0.0001), None), Some(10_000));
        assert_eq!(one(serde_json::from_str("21000000.00000001").unwrap(), None), Some(2_100_000_000_000_001));
        assert_eq!(one(json!(12_345), Some("sats")), Some(12_345));
    }

    #[test]
    fn integer_formatting_rounds_down_and_never_goes_through_floats() {
        assert_eq!(ppm_percent(0), "0.00%");
        assert_eq!(ppm_percent(123_456), "12.34%");
        assert_eq!(ppm_percent(999_999), "99.99%");
        assert_eq!(ppm_percent(1_000_000), "100.00%");
        assert_eq!(ppm(1, 3), 333_333);
        assert_eq!(ppm(5, 0), 0);
        assert_eq!(ppm(u64::MAX, u64::MAX), 1_000_000);
        assert_eq!(sat_btc(100_000_000), "1.00000000 BTC");
        assert_eq!(sat_btc(2_100_000_000_000_001), "21000000.00000001 BTC");
    }

    #[test]
    fn a_report_parses_with_every_breakdown() {
        let r = parse_report(&sample_report()).unwrap();
        assert_eq!((r.height, r.attestations, r.counting, r.invalid), (900, 3, 3, 0));
        assert_eq!(r.keys[0].key, "fork.x");
        assert_eq!(r.keys[0].withdrawn, Sum { weight_sat: 50_000, outpoints: 1 });
        let v = &r.keys[0].values[0];
        assert_eq!(v.value, "yes");
        assert_eq!(v.coin_age[4].label, ">=262080");
        assert_eq!(v.concentration, vec![(10, 1_000_000), (100, 1_000_000)]);
        assert_eq!(r.value_rows(), vec![(0, 0), (0, 1)]);
    }

    pub(crate) fn sample_report() -> Value {
        let buckets = |labels: &[&str], name: &str, weight: u64| -> Value {
            labels
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let w = if i == 0 { weight } else { 0 };
                    json!({ name: l, "weight_sat": w, "outpoints": u64::from(w > 0) })
                })
                .collect()
        };
        let value = |value: &str, weight: u64, share: u64| {
            json!({
                "value": value, "weight_sat": weight, "outpoints": 1,
                "share_ppm": share, "coverage_ppm": ppm(weight, 2_000_000_000),
                "value_tiers": buckets(&["<0.01", "0.01-1", "1-100", ">=100"], "tier", weight),
                "anchor_age": buckets(&["<2016", "<13104", "<26208"], "blocks", weight),
                "coin_age": buckets(&["<13104", "<52416", "<104832", "<262080", ">=262080"], "blocks", weight),
                "script_types": buckets(&["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr", "other"], "type", weight),
                "concentration": { "top10_ppm": 1_000_000, "top100_ppm": 1_000_000 },
            })
        };
        json!({
            "height": 900, "hash": "00".repeat(32), "utxo_total_sat": 2_000_000_000u64,
            "digest": "ab".repeat(32), "attestations": 3, "invalid": 0, "counting": 3,
            "keys": [{
                "key": "fork.x", "weight_sat": 300_000_000u64, "outpoints": 2,
                "coverage_ppm": 150_000,
                "withdrawn": { "weight_sat": 50_000, "outpoints": 1 },
                "values": [value("yes", 200_000_000, 666_666), value("no", 100_000_000, 333_333)],
            }],
        })
    }
}
