//! Positional-argument reading for the JSON-RPC handlers.
//!
//! # Why this module exists
//!
//! jsonrpsee's [`ParamsSequence`] deserializes each slot directly into the
//! caller's Rust type, and `next_inner` sets its remaining buffer to `""` on
//! *any* deserialize error. A type mismatch therefore does not merely fail
//! that one argument — it erases every argument after it, and each later
//! `optional_next()` answers `Ok(None)`.
//!
//! Written against that primitive, the natural-looking shape
//!
//! ```ignore
//! let x: T = seq.optional_next().unwrap_or(Some(d)).unwrap_or(d);
//! ```
//!
//! turns a caller's mistyped argument into a silently-applied default *and*
//! discards everything the caller passed after it. The sharp case is
//! `generateblock`: a mistyped `transactions` discards `submit`, so
//! `submit=false` mines and connects a block — the caller asked for a block
//! back without touching the chain and got a new tip (#672).
//!
//! # What this module does instead
//!
//! [`Args`] does not use [`ParamsSequence`] at all. It parses the request's
//! `params` array once into [`serde_json::Value`]s and indexes it, so there is
//! no cursor to poison and no ordering between reads. The declared type is
//! then checked against the value, and the conversion happens from a value
//! that already matched. A mismatch is *recorded*, not thrown, so that
//! [`Args::check`] can report every bad argument at once the way Core does:
//!
//! ```text
//! -3  Wrong type passed:
//!     {
//!         "Position 1 (nblocks)": "JSON value of type string is not of expected type number",
//!         "Position 2 (height)": "JSON value of type array is not of expected type number"
//!     }
//! ```
//!
//! Every handler must call [`Args::check`] after reading its arguments and
//! before doing any work. `Args` carries a `Drop` assertion that fires in
//! debug and test builds if a handler recorded a mismatch and never checked,
//! so the omission cannot reach a release build unnoticed.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::types::Params;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Core's `uvTypeName` for a JSON value (`src/univalue/lib/univalue.cpp`).
pub(crate) fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The Core `RPCArg` type a Rust argument type corresponds to, as
/// `uvTypeName` spells it. `RPCArg::MatchesType` compares exactly this.
///
/// Types Core declares with `skip_type_check` (or whose `ExpectedType` is
/// `nullopt`, i.e. `AMOUNT` and `RANGE`) have no single expected JSON type;
/// read those slots with [`Args::raw`] and validate them by hand.
pub(crate) trait ArgType: DeserializeOwned {
    const CORE_TYPE: &'static str;

    /// Convert a value whose JSON type already matched [`Self::CORE_TYPE`].
    fn from_arg(v: Value) -> Result<Self, ArgValueError> {
        serde_json::from_value(v).map_err(|e| ArgValueError::Domain(e.to_string()))
    }
}

/// Why a value of the right JSON type still did not convert.
pub(crate) enum ArgValueError {
    /// Core's `UniValue::getInt` failed: `-1 JSON integer out of range`.
    IntRange,
    /// Anything else: `-8 Invalid value for argument ...`.
    Domain(String),
}

/// Core's message when `UniValue::getInt<T>` cannot convert a number.
pub(crate) const INT_OUT_OF_RANGE: &str = "JSON integer out of range";

/// Core's `UniValue::getInt<T>` (`src/univalue/include/univalue.h`): the
/// number's literal text must parse whole, by `std::from_chars`, as a `T`.
/// A fraction (`1.5`, `1.0`), an exponent (`1e0`), or a value outside `T`
/// fails, and Core answers the bare `std::runtime_error` as
/// `RPC_MISC_ERROR` (-1) "JSON integer out of range". The workspace builds
/// `serde_json` with `arbitrary_precision`, so a `Number` keeps the
/// caller's text and Rust's integer `parse` sees what `from_chars` sees. The
/// one exception: `serde_json` reads `-0` as the integer 0, so an unsigned
/// slot takes `-0` as 0 where Core's `from_chars` refuses the sign.
pub(crate) fn core_int<T: std::str::FromStr>(
    n: &serde_json::Number,
) -> Result<T, ErrorObjectOwned> {
    n.to_string()
        .parse::<T>()
        .map_err(|_| ErrorObjectOwned::owned(-1, INT_OUT_OF_RANGE, None::<()>))
}

macro_rules! arg_type {
    ($core:literal: $($t:ty),+ $(,)?) => {
        $(impl ArgType for $t { const CORE_TYPE: &'static str = $core; })+
    };
}

/// Integer slots convert as Core's `getInt<T>` does; see [`core_int`]. The
/// Rust type is the one Core's handler names (`int` is `i32`, `uint32_t` is
/// `u32`, `int64_t` is `i64`), so the accepted range is Core's too.
macro_rules! int_arg_type {
    ($($t:ty),+ $(,)?) => {
        $(impl ArgType for $t {
            const CORE_TYPE: &'static str = "number";
            fn from_arg(v: Value) -> Result<Self, ArgValueError> {
                match &v {
                    Value::Number(n) => n.to_string().parse().map_err(|_| ArgValueError::IntRange),
                    _ => Err(ArgValueError::IntRange),
                }
            }
        })+
    };
}

arg_type!("string": String);
arg_type!("bool": bool);
arg_type!("number": f64, serde_json::Number);
int_arg_type!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl<T: DeserializeOwned> ArgType for Vec<T> {
    const CORE_TYPE: &'static str = "array";
}

impl ArgType for serde_json::Map<String, Value> {
    const CORE_TYPE: &'static str = "object";
}

/// A non-poisoning reader over a JSON-RPC positional parameter array.
///
/// See the module documentation for why reading through `Value` matters.
pub(crate) struct Args {
    /// The request's `params` array, parsed once. Absent and explicit-`null`
    /// stay distinguishable, which a `ParamsSequence` cannot do:
    /// `optional_next::<T>()` deserializes into `Option<T>`, so an explicit
    /// `null` and a missing element both arrive as `Ok(None)` -- and Core
    /// treats them differently in a *required* slot.
    slots: Vec<Value>,
    /// 0-based index of the next slot; `pos + 1` is Core's `Position N`.
    pos: usize,
    /// `(position, name, message)` for each argument whose type did not match.
    mismatches: Vec<(usize, String, String)>,
    checked: bool,
}

impl Args {
    pub(crate) fn new(params: &Params<'_>) -> Self {
        // Handlers see an array: the named-parameter layer rewrites an object
        // `params` into positional form before dispatch. Anything else (an
        // absent or malformed `params`) reads as no arguments, which the
        // `required` path then reports.
        let slots = params
            .as_str()
            .and_then(|s| serde_json::from_str::<Vec<Value>>(s).ok())
            .unwrap_or_default();
        Args {
            slots,
            pos: 0,
            mismatches: Vec::new(),
            checked: false,
        }
    }

    /// Take the next slot, or `None` if the caller stopped before it.
    ///
    /// Absent and explicit `null` are kept apart here. Core's
    /// `RPCArg::MatchesType` forgives a null only when the argument is
    /// *optional*; an explicit null in a required slot is "JSON value of type
    /// null is not of expected type ...", and `rpc_invalid_address_message.py`
    /// asserts exactly that.
    fn next_slot(&mut self) -> Option<Value> {
        let v = self.slots.get(self.pos).cloned();
        self.pos += 1;
        v
    }

    /// The slot's value with absent and `null` collapsed -- the right reading
    /// for every *optional* argument.
    fn next_value(&mut self) -> Option<Value> {
        match self.next_slot() {
            None | Some(Value::Null) => None,
            some => some,
        }
    }

    /// Record a type mismatch at the slot just read.
    fn record(&mut self, name: &str, actual: &str, expected: &str) {
        self.mismatches.push((
            self.pos,
            name.to_string(),
            format!("JSON value of type {actual} is not of expected type {expected}"),
        ));
    }

    /// Read a slot Core declares with no single expected JSON type
    /// (`AMOUNT`, `RANGE`, `skip_type_check`). No type check is applied; the
    /// caller validates the shape itself.
    pub(crate) fn raw(&mut self, _name: &str) -> Result<Option<Value>, ErrorObjectOwned> {
        Ok(self.next_value())
    }

    /// As [`Args::raw`], but keeping an explicit `null` distinct from an
    /// absent argument.
    ///
    /// A `skip_type_check` argument reaches Core's handler untouched --
    /// `RPCArg::MatchesType` returns `true` before it can look at the value --
    /// so a `null` there is answered by the handler, not by the type checker.
    /// `createrawtransaction`'s is `NormalizeOutputs`'s "Invalid parameter,
    /// output argument must be non-null". Collapsing the null to `None` here
    /// meant the handler's missing-argument path answered instead, with a
    /// different code and a message naming nothing.
    pub(crate) fn raw_or_null(&mut self, _name: &str) -> Result<Option<Value>, ErrorObjectOwned> {
        Ok(self.next_slot())
    }

    /// Read an optional argument of Core-declared type `T`.
    ///
    /// A mismatch is recorded and `Ok(None)` returned, so reading continues
    /// and later arguments are still seen; [`Args::check`] turns the record
    /// into Core's error before the handler acts on anything.
    pub(crate) fn optional<T: ArgType>(
        &mut self,
        name: &str,
    ) -> Result<Option<T>, ErrorObjectOwned> {
        let Some(v) = self.next_value() else {
            return Ok(None);
        };
        let actual = json_type_name(&v);
        if actual != T::CORE_TYPE {
            self.record(name, actual, T::CORE_TYPE);
            return Ok(None);
        }
        match T::from_arg(v) {
            Ok(t) => Ok(Some(t)),
            Err(e) => Err(self.conversion_error(name, e)),
        }
    }

    /// Read an optional argument, substituting `default` when it is absent.
    /// A *mismatched* argument is still recorded — it does not become the
    /// default, which is the whole point of #672.
    pub(crate) fn optional_or<T: ArgType>(
        &mut self,
        name: &str,
        default: T,
    ) -> Result<T, ErrorObjectOwned> {
        Ok(self.optional::<T>(name)?.unwrap_or(default))
    }

    /// Read a required argument. A missing argument is Core's
    /// `RPC_INVALID_PARAMS`; a mistyped one reports every mismatch seen so
    /// far, including this one.
    pub(crate) fn required<T: ArgType>(&mut self, name: &str) -> Result<T, ErrorObjectOwned> {
        let v = match self.next_slot() {
            None => {
                return Err(self.arity_error(ErrorObjectOwned::owned(
                    -1,
                    format!("Missing required argument {name}"),
                    None::<()>,
                )));
            }
            // Explicit null in a required slot is a type error, not an
            // omission.
            Some(Value::Null) => {
                self.record(name, "null", T::CORE_TYPE);
                return Err(self.take_mismatch_error().expect("mismatch just recorded"));
            }
            Some(v) => v,
        };
        let actual = json_type_name(&v);
        if actual != T::CORE_TYPE {
            self.record(name, actual, T::CORE_TYPE);
            // No value to carry on with, so report now rather than at the
            // handler's `check()`.
            return Err(self.take_mismatch_error().expect("mismatch just recorded"));
        }
        T::from_arg(v).map_err(|e| self.conversion_error(name, e))
    }

    /// The error for a value of the right JSON type that did not convert.
    /// An integer that is fractional or outside the slot's type is Core's
    /// `getInt` failure, -1; any other domain error names the argument, -8.
    fn conversion_error(&mut self, name: &str, e: ArgValueError) -> ErrorObjectOwned {
        let e = match e {
            ArgValueError::IntRange => ErrorObjectOwned::owned(-1, INT_OUT_OF_RANGE, None::<()>),
            ArgValueError::Domain(e) => ErrorObjectOwned::owned(
                -8,
                format!("Invalid value for argument {name}: {e}"),
                None::<()>,
            ),
        };
        self.value_error(e)
    }

    /// Core's `ParseVerbosity` (`src/rpc/util.cpp`): a `verbose`/`verbosity`
    /// slot accepts **either** a bool or a number -- `false` is 0, `true` is
    /// 1 -- and a number is read with `getInt<int>`, so any `int` is
    /// returned, negative ones included, for the caller to clamp the way its
    /// Core handler does. A fraction or a value outside `int` is -1 "JSON
    /// integer out of range".
    pub(crate) fn verbosity(&mut self, name: &str, default: i32) -> Result<i32, ErrorObjectOwned> {
        let Some(v) = self.next_value() else {
            return Ok(default);
        };
        match &v {
            Value::Bool(b) => Ok(i32::from(*b)),
            Value::Number(n) => match core_int::<i32>(n) {
                Ok(v) => Ok(v),
                Err(e) => Err(self.value_error(e)),
            },
            other => {
                self.record(name, json_type_name(other), "number");
                Ok(default)
            }
        }
    }

    /// `ParseVerbosity` with `allow_bool = false`: a number only. A bool is
    /// refused rather than read as 0 or 1, and any `int` is returned for the
    /// caller to range-check, so the error names the value.
    pub(crate) fn int_verbosity(
        &mut self,
        name: &str,
        default: i32,
    ) -> Result<i32, ErrorObjectOwned> {
        let Some(v) = self.next_value() else {
            return Ok(default);
        };
        match &v {
            Value::Bool(_) => Err(self.value_error(ErrorObjectOwned::owned(
                -3,
                "Verbosity was boolean but only integer allowed",
                None::<()>,
            ))),
            Value::Number(n) => match core_int::<i32>(n) {
                Ok(v) => Ok(v),
                Err(e) => Err(self.value_error(e)),
            },
            other => {
                self.record(name, json_type_name(other), "number");
                Ok(default)
            }
        }
    }

    /// Return `e`, unless a type mismatch is already pending -- in which case
    /// that is the error Core would report.
    ///
    /// `RPCHelpMan::Check` (`src/rpc/util.cpp`) validates *every* argument's
    /// type before the handler body runs, so a `-8` raised while reading a
    /// later argument can never be the error a caller sees ahead of a `-3`
    /// for an earlier one. Routing value errors through here also keeps this
    /// module's invariant intact: an `Args` that returns an error has always
    /// either reported what it recorded or deliberately superseded it, so
    /// `Drop`'s check stays meaningful instead of firing on a live path.
    fn value_error(&mut self, e: ErrorObjectOwned) -> ErrorObjectOwned {
        self.checked = true;
        self.take_mismatch_error().unwrap_or(e)
    }

    /// Return `e`, discarding any pending type mismatch.
    ///
    /// Core checks arity first (`IsValidNumArgs` precedes the `MatchesType`
    /// loop) and throws the help text without ever reaching the type check,
    /// so a missing required argument outranks a mismatch rather than
    /// deferring to it.
    fn arity_error(&mut self, e: ErrorObjectOwned) -> ErrorObjectOwned {
        self.checked = true;
        self.mismatches.clear();
        e
    }

    fn take_mismatch_error(&mut self) -> Option<ErrorObjectOwned> {
        if self.mismatches.is_empty() {
            return None;
        }
        self.checked = true;
        // Core builds a UniValue object and writes it with 4-space indent:
        //   Wrong type passed:
        //   {
        //       "Position 1 (nblocks)": "JSON value of type ..."
        //   }
        let body = self
            .mismatches
            .iter()
            .map(|(pos, name, msg)| {
                format!(
                    "    {}: {}",
                    json_str(&format!("Position {pos} ({name})")),
                    json_str(msg)
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        self.mismatches.clear();
        Some(ErrorObjectOwned::owned(
            -3,
            format!("Wrong type passed:\n{{\n{body}\n}}"),
            None::<()>,
        ))
    }

    /// Report every recorded type mismatch, in Core's shape. Call this after
    /// reading the handler's arguments and before doing anything with them.
    pub(crate) fn check(&mut self) -> Result<(), ErrorObjectOwned> {
        self.checked = true;
        match self.take_mismatch_error() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for Args {
    fn drop(&mut self) {
        // A handler that recorded a mismatch and never called `check()` would
        // act on defaults for arguments the caller got wrong -- exactly the
        // #672 failure this module exists to remove. Catch it in debug and
        // test builds rather than shipping the silent version.
        debug_assert!(
            self.checked || self.mismatches.is_empty(),
            "rpc handler dropped Args with {} unreported argument type mismatch(es); \
             call args.check()? after reading arguments",
            self.mismatches.len()
        );
    }
}

/// Minimal JSON string encoder for the error body above. `serde_json` would
/// do, but this keeps the message construction allocation-light and its
/// escaping obvious.
fn json_str(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::types::Params;

    fn params(s: &str) -> Params<'_> {
        Params::new(Some(s))
    }

    /// The defect itself: a mistyped slot must not poison the ones after it.
    #[test]
    fn a_mistyped_argument_does_not_erase_the_arguments_after_it() {
        let p = params(r#"["addr","not-an-array",false]"#);
        let mut a = Args::new(&p);
        let output: String = a.required("output").unwrap();
        let txs: Option<Vec<Value>> = a.optional("transactions").unwrap();
        // The whole point: `submit` is still read, and still `false`.
        let submit: bool = a.optional_or("submit", true).unwrap();

        assert_eq!(output, "addr");
        assert_eq!(txs, None);
        assert!(!submit, "the caller's `submit=false` must survive");

        let err = a.check().expect_err("the type mismatch must be reported");
        assert_eq!(err.code(), -3);
        assert!(
            err.message().contains("Position 2 (transactions)"),
            "{}",
            err.message()
        );
    }

    /// Core reports every mismatch at once, in position order.
    #[test]
    fn every_mismatch_is_reported_in_core_s_shape() {
        let p = params(r#"["a",[]]"#);
        let mut a = Args::new(&p);
        let _: Option<u32> = a.optional("nblocks").unwrap();
        let _: Option<u32> = a.optional("height").unwrap();
        let err = a.check().unwrap_err();
        assert_eq!(err.code(), -3);
        assert_eq!(
            err.message(),
            "Wrong type passed:\n{\n    \
             \"Position 1 (nblocks)\": \"JSON value of type string is not of expected type number\",\n    \
             \"Position 2 (height)\": \"JSON value of type array is not of expected type number\"\n}"
        );
    }

    /// Absent and explicit-null are both "not supplied" for an optional
    /// argument, as in Core's `RPCArg::MatchesType`.
    #[test]
    fn absent_and_null_take_the_default() {
        for src in [r#"["h"]"#, r#"["h",null]"#] {
            let p = params(src);
            let mut a = Args::new(&p);
            let _: String = a.required("blockhash").unwrap();
            assert!(a.optional_or("verbose", true).unwrap(), "{src}");
            a.check().unwrap();
        }
    }

    /// `ParseVerbosity`: a `verbose`/`verbosity` slot takes a bool or a number.
    #[test]
    fn verbosity_accepts_bool_or_number() {
        for (src, want) in [
            (r#"["h"]"#, 1i32),
            (r#"["h",false]"#, 0),
            (r#"["h",true]"#, 1),
            (r#"["h",0]"#, 0),
            (r#"["h",2]"#, 2),
            // Any `int`: the handler clamps, as Core's does.
            (r#"["h",-1]"#, -1),
            (r#"["h",-0]"#, 0),
            (r#"["h",2147483647]"#, i32::MAX),
        ] {
            let p = params(src);
            let mut a = Args::new(&p);
            let _: String = a.required("blockhash").unwrap();
            assert_eq!(a.verbosity("verbosity", 1).unwrap(), want, "{src}");
            a.check().unwrap();
        }
        // A string is neither, and is reported rather than defaulted.
        let p = params(r#"["h","yes"]"#);
        let mut a = Args::new(&p);
        let _: String = a.required("blockhash").unwrap();
        let _ = a.verbosity("verbosity", 1).unwrap();
        assert_eq!(a.check().unwrap_err().code(), -3);
    }

    /// A required argument of the wrong type reports immediately, naming it —
    /// there is no value to carry on with.
    #[test]
    fn a_mistyped_required_argument_reports_at_once() {
        let p = params(r#"[42]"#);
        let mut a = Args::new(&p);
        let err = a.required::<String>("blockhash").unwrap_err();
        assert_eq!(err.code(), -3);
        assert!(
            err.message().contains("Position 1 (blockhash)"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn a_missing_required_argument_is_invalid_params() {
        let p = params("[]");
        let mut a = Args::new(&p);
        let err = a.required::<String>("blockhash").unwrap_err();
        assert_eq!(err.code(), -1);
        assert!(err.message().contains("blockhash"), "{}", err.message());
        a.check().unwrap();
    }

    /// Right JSON type, but not an integer of the slot's type: Core's
    /// `getInt<T>` fails, and its dispatcher answers the bare
    /// `std::runtime_error` as -1 "JSON integer out of range".
    #[test]
    fn a_number_that_does_not_fit_the_slot_is_json_integer_out_of_range() {
        for (src, ok) in [
            ("[-1]", false),
            ("[4294967296]", false),
            ("[1.5]", false),
            ("[1.0]", false),
            ("[1e0]", false),
            ("[99999999999999999999]", false),
            ("[4294967295]", true),
            ("[0]", true),
        ] {
            let p = params(src);
            let mut a = Args::new(&p);
            match a.optional::<u32>("n") {
                Ok(v) => assert!(ok && v.is_some(), "{src}"),
                Err(err) => {
                    assert!(!ok, "{src}: {}", err.message());
                    assert_eq!((err.code(), err.message()), (-1, INT_OUT_OF_RANGE), "{src}");
                }
            }
        }
        // `int`: the sign is allowed, `-0` is 0, and the bounds are `i32`'s.
        for (src, want) in [
            ("[-0]", Some(0)),
            ("[-2147483648]", Some(i32::MIN)),
            ("[2147483648]", None),
        ] {
            let p = params(src);
            let mut a = Args::new(&p);
            assert_eq!(a.required::<i32>("height").ok(), want, "{src}");
        }
        // Every integer width fails the same way.
        let p = params(r#"[256]"#);
        let mut a = Args::new(&p);
        let err = a.required::<u8>("x").unwrap_err();
        assert_eq!(err.code(), -1, "{}", err.message());
    }

    /// `verbosity` reads with `getInt<int>`: past `int` is the same -1.
    #[test]
    fn verbosity_outside_int_is_json_integer_out_of_range() {
        for src in [
            r#"["h",2147483648]"#,
            r#"["h",-2147483649]"#,
            r#"["h",1.5]"#,
        ] {
            let p = params(src);
            let mut a = Args::new(&p);
            let _: String = a.required("blockhash").unwrap();
            let err = a.verbosity("verbosity", 1).unwrap_err();
            assert_eq!((err.code(), err.message()), (-1, INT_OUT_OF_RANGE), "{src}");
            let p = params(src);
            let mut a = Args::new(&p);
            let _: String = a.required("blockhash").unwrap();
            let err = a.int_verbosity("verbosity", 0).unwrap_err();
            assert_eq!((err.code(), err.message()), (-1, INT_OUT_OF_RANGE), "{src}");
        }
    }

    /// Core forgives an explicit `null` only for an *optional* argument. In a
    /// required slot it is a type error, not an omission -- a distinction a
    /// `ParamsSequence` cannot make, because `optional_next::<T>()` collapses
    /// both onto `Ok(None)`.
    #[test]
    fn an_explicit_null_differs_from_a_missing_argument() {
        // Required slot: null is -3, naming the position.
        let p = params("[null]");
        let mut a = Args::new(&p);
        let err = a.required::<String>("address").unwrap_err();
        assert_eq!(err.code(), -3);
        assert!(
            err.message()
                .contains("JSON value of type null is not of expected type string"),
            "{}",
            err.message()
        );

        // Absent: -1, the missing-argument path.
        let p = params("[]");
        let mut a = Args::new(&p);
        assert_eq!(a.required::<String>("address").unwrap_err().code(), -1);

        // Optional slot: null is simply "not supplied".
        let p = params(r#"["h",null,false]"#);
        let mut a = Args::new(&p);
        let _: String = a.required("blockhash").unwrap();
        assert_eq!(a.optional::<u32>("verbosity").unwrap(), None);
        // And the argument after the null is still read.
        assert_eq!(a.optional::<bool>("extra").unwrap(), Some(false));
        a.check().unwrap();
    }

    /// `raw` is for slots Core declares with no single expected JSON type
    /// (`AMOUNT`, `RANGE`, `skip_type_check`): every shape passes through and
    /// nothing is recorded.
    #[test]
    fn raw_slots_accept_any_shape_and_still_advance() {
        let p = params(r#"["hex","0.001",1]"#);
        let mut a = Args::new(&p);
        let _: String = a.required("hexstring").unwrap();
        assert_eq!(
            a.raw("maxfeerate").unwrap(),
            Some(Value::String("0.001".into()))
        );
        assert_eq!(a.raw("maxburnamount").unwrap(), Some(Value::from(1)));
        a.check().unwrap();
    }

    /// A recorded mismatch must survive an error raised while reading a
    /// *later* argument.
    ///
    /// Every `Err` return used to leave `check()` uncalled, so the mismatch
    /// was never reported: in a debug build `Drop`'s assertion fired and the
    /// caller's connection died with no response at all, and in a release
    /// build the `-3` was silently discarded and the caller was told only
    /// about the second argument -- #672's own failure mode, one argument
    /// along. Core reports the type mismatch, because `RPCHelpMan::Check`
    /// validates every argument's type before the handler body runs.
    #[test]
    fn a_pending_mismatch_outranks_a_later_value_error() {
        // Position 1 is mistyped; position 2 is the right JSON type but out
        // of the slot's domain (negative in a `u32`).
        let p = params(r#"["a",-1]"#);
        let mut a = Args::new(&p);
        assert_eq!(a.optional::<u32>("nblocks").unwrap(), None);
        let err = a.optional::<u32>("height").unwrap_err();
        assert_eq!(
            err.code(),
            -3,
            "the earlier mismatch is the error Core reports"
        );
        assert!(
            err.message().contains("Position 1 (nblocks)"),
            "{}",
            err.message()
        );
        // Reported, so dropping the `Args` is not a violation.
        drop(a);
    }

    /// The same, for the domain error a *required* slot raises.
    #[test]
    fn a_pending_mismatch_outranks_a_required_slots_value_error() {
        let p = params(r#"[true,-1]"#);
        let mut a = Args::new(&p);
        assert_eq!(a.optional::<u32>("nblocks").unwrap(), None);
        let err = a.required::<u32>("height").unwrap_err();
        assert_eq!(err.code(), -3);
        assert!(
            err.message().contains("Position 1 (nblocks)"),
            "{}",
            err.message()
        );
        drop(a);
    }

    /// Arity outranks type: Core's `IsValidNumArgs` throws before the
    /// `MatchesType` loop is ever reached, so a missing required argument
    /// supersedes a mismatch rather than deferring to it.
    #[test]
    fn a_missing_required_argument_outranks_a_pending_mismatch() {
        let p = params(r#"["a"]"#);
        let mut a = Args::new(&p);
        assert_eq!(a.optional::<u32>("nblocks").unwrap(), None);
        let err = a.required::<String>("blockhash").unwrap_err();
        assert_eq!(err.code(), -1);
        assert!(
            err.message()
                .contains("Missing required argument blockhash")
        );
        drop(a);
    }

    /// `verbosity`'s range error is a value error like any other.
    #[test]
    fn a_pending_mismatch_outranks_a_verbosity_range_error() {
        let p = params(r#"["a",2147483648]"#);
        let mut a = Args::new(&p);
        assert_eq!(a.optional::<u32>("nblocks").unwrap(), None);
        let err = a.verbosity("verbosity", 1).unwrap_err();
        assert_eq!(err.code(), -3);
        assert!(
            err.message().contains("Position 1 (nblocks)"),
            "{}",
            err.message()
        );
        drop(a);
    }
}
