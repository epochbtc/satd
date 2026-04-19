//! Amount-unit formatting for JSON-RPC responses.
//!
//! Bitcoin Core emits all amounts as IEEE-754 doubles in whole-BTC units
//! (e.g. `0.0005`). This is a long-standing integrator footgun — see Bitcoin
//! Core issue #3249 (open since 2013). Floating-point rounding near dust and
//! at the max supply boundary silently loses precision.
//!
//! satd supports both representations, controlled by a per-server default
//! (`--rpc-default-units=sats|btc`). The default remains `Btc` to preserve
//! byte-compatibility with Bitcoin-Core-expecting clients (bitcoin-cli,
//! BTCPay, Electrum personal-server, etc.). Operators who drive satd only
//! with satoshi-aware clients can flip the default to `Sats` and get exact
//! JSON integers everywhere.
//!
//! Per-request override via HTTP header is a planned follow-up.
//!
//! When `Sats` is active, `format_amount` emits JSON integers (no
//! precision loss up to the Bitcoin max supply and beyond). When `Btc` is
//! active, the output matches Bitcoin Core exactly: `f64` with 8 decimals
//! of precision.

use serde_json::Value;
use std::sync::atomic::{AtomicU8, Ordering};

/// Unit used to emit amounts on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AmountUnit {
    /// Core-compatible: JSON `Number` (f64) in whole BTC. Default.
    #[default]
    Btc,
    /// Exact: JSON `Number` (integer) in satoshis.
    Sats,
}

/// Server-wide default. Set once at startup by `set_default()`; read from
/// any RPC handler via `default_unit()`. The value is a simple `AtomicU8`
/// because it's set once and otherwise read-only — no contention.
static DEFAULT_UNIT: AtomicU8 = AtomicU8::new(0); // 0 = Btc, 1 = Sats

/// Set the server-wide default unit. Call at server start; do not call
/// multiple times.
pub fn set_default(unit: AmountUnit) {
    let v = match unit {
        AmountUnit::Btc => 0,
        AmountUnit::Sats => 1,
    };
    DEFAULT_UNIT.store(v, Ordering::Relaxed);
}

/// Read the current server-wide default unit.
pub fn default_unit() -> AmountUnit {
    match DEFAULT_UNIT.load(Ordering::Relaxed) {
        1 => AmountUnit::Sats,
        _ => AmountUnit::Btc,
    }
}

impl AmountUnit {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "btc" | "bitcoin" => Some(Self::Btc),
            "sat" | "sats" | "satoshi" | "satoshis" => Some(Self::Sats),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Btc => "btc",
            Self::Sats => "sats",
        }
    }
}

/// Format a satoshi amount according to the requested unit.
///
/// - `Btc`: returns `Value::Number` as `f64`, matching Core's exact output.
/// - `Sats`: returns `Value::Number` as integer (`u64`), no precision loss.
pub fn format_amount(sats: u64, unit: AmountUnit) -> Value {
    match unit {
        AmountUnit::Btc => {
            let btc = sats as f64 / 100_000_000.0;
            // `Number::from_f64` returns `None` for NaN/Inf; neither is
            // reachable from a `u64 / 100_000_000.0` division, so we unwrap.
            Value::Number(serde_json::Number::from_f64(btc).unwrap())
        }
        AmountUnit::Sats => Value::Number(serde_json::Number::from(sats)),
    }
}

/// Annotate an already-built response object with `_units` **only** when
/// the active unit differs from the Core-compatible default (`Btc`). That
/// way default responses remain byte-identical to Bitcoin Core; clients
/// opting into sats get a machine-readable tag confirming the shape.
pub fn annotate_units(response: &mut Value, unit: AmountUnit) {
    if unit == AmountUnit::Sats
        && let Some(obj) = response.as_object_mut()
    {
        obj.insert("_units".to_string(), Value::String(unit.as_str().into()));
    }
}

/// Format a fee-rate value in sat/kvB according to the requested unit.
///
/// Fee rates are conventionally expressed in satoshis per virtual kilobyte.
/// When `Btc` is active we emit BTC/kvB (same as `estimatesmartfee` in Core).
/// When `Sats` is active we emit the raw sat/kvB integer — that's what
/// modern wallets actually want.
pub fn format_feerate_sat_per_kvb(sat_per_kvb: u64, unit: AmountUnit) -> Value {
    match unit {
        AmountUnit::Btc => {
            let btc_per_kvb = sat_per_kvb as f64 / 100_000_000.0;
            Value::Number(serde_json::Number::from_f64(btc_per_kvb).unwrap())
        }
        AmountUnit::Sats => Value::Number(serde_json::Number::from(sat_per_kvb)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_output_matches_core_formatting() {
        let v = format_amount(50_000, AmountUnit::Btc);
        // 50_000 sats = 0.0005 BTC
        assert_eq!(
            v,
            Value::Number(serde_json::Number::from_f64(0.0005).unwrap())
        );
    }

    #[test]
    fn sats_output_is_integer() {
        let v = format_amount(50_000, AmountUnit::Sats);
        assert!(v.is_number());
        assert_eq!(v.as_u64(), Some(50_000));
        // Serialized form has no decimal point.
        assert_eq!(v.to_string(), "50000");
    }

    #[test]
    fn max_supply_roundtrips_exactly_in_sats() {
        // 21_000_000 * 100_000_000 satoshis
        let max_supply = 21_000_000u64 * 100_000_000;
        let v = format_amount(max_supply, AmountUnit::Sats);
        assert_eq!(v.as_u64(), Some(max_supply));
    }

    #[test]
    fn zero_formats_in_both_units() {
        assert_eq!(format_amount(0, AmountUnit::Btc).as_f64(), Some(0.0));
        assert_eq!(format_amount(0, AmountUnit::Sats).as_u64(), Some(0));
    }

    #[test]
    fn parse_recognizes_common_aliases() {
        assert_eq!(AmountUnit::parse("BTC"), Some(AmountUnit::Btc));
        assert_eq!(AmountUnit::parse("sat"), Some(AmountUnit::Sats));
        assert_eq!(AmountUnit::parse("SATOSHIS"), Some(AmountUnit::Sats));
        assert_eq!(AmountUnit::parse("xxx"), None);
    }

    #[test]
    fn annotate_units_only_tags_sats_mode() {
        // Btc default must NOT tag — preserves Core wire compatibility.
        let mut obj = serde_json::json!({"value": 1.23});
        annotate_units(&mut obj, AmountUnit::Btc);
        assert!(
            obj.get("_units").is_none(),
            "Btc mode must not add _units; got: {}",
            obj
        );

        // Sats mode adds the tag.
        let mut obj = serde_json::json!({"value": 123});
        annotate_units(&mut obj, AmountUnit::Sats);
        assert_eq!(obj["_units"], serde_json::Value::String("sats".into()));
    }

    #[test]
    fn feerate_formats_in_both_units() {
        // 1000 sat/kvB = 0.00001 BTC/kvB
        assert_eq!(
            format_feerate_sat_per_kvb(1000, AmountUnit::Btc).as_f64(),
            Some(0.00001)
        );
        assert_eq!(
            format_feerate_sat_per_kvb(1000, AmountUnit::Sats).as_u64(),
            Some(1000)
        );
    }
}
