//! Errors for the raw PSBT codec and the typed version 2 view.
//!
//! Every variant carries enough context to be shown to the caller of a
//! JSON-RPC method, and every variant has a real `Display` impl. That is not
//! a given: the `psbt-v2` crate's `DeserializeError` has a `todo!()` for its
//! `Display`, so formatting a parse error from untrusted input panics. A
//! panic on the read-only RPC listener is the thing this crate exists to
//! avoid, so the rule here is that a `PsbtError` is always printable.

use std::fmt;

/// Which map a problem was found in. Used only to make errors legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapId {
    Global,
    Input(usize),
    Output(usize),
}

impl fmt::Display for MapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MapId::Global => write!(f, "global map"),
            MapId::Input(i) => write!(f, "input {i}"),
            MapId::Output(i) => write!(f, "output {i}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PsbtError {
    #[error("not a PSBT: magic bytes are missing")]
    BadMagic,

    #[error("PSBT data ends while reading {0}")]
    UnexpectedEof(&'static str),

    #[error("non-minimal compact size encoding")]
    NonMinimalCompactSize,

    #[error("declared length {declared} exceeds the {remaining} bytes remaining")]
    LengthOverrun { declared: u64, remaining: usize },

    #[error("{0} is not terminated by a separator")]
    UnterminatedMap(MapId),

    #[error("{map} has a duplicate key of type {key_type:#x}")]
    DuplicateKey { map: MapId, key_type: u64 },

    #[error("{0} bytes of trailing data after the last map")]
    TrailingData(usize),

    #[error("PSBT version {0} is not supported; this node reads versions 0 and 2")]
    UnsupportedVersion(u32),

    #[error("{map} field {key_type:#x} has length {len}, expected {expected}")]
    BadFieldLength {
        map: MapId,
        key_type: u64,
        len: usize,
        expected: &'static str,
    },

    #[error("{map} field {key_type:#x} carries a key of {len} bytes, expected {expected}")]
    BadKeyDataLength {
        map: MapId,
        key_type: u64,
        len: usize,
        expected: &'static str,
    },

    #[error("{map} field {key_type:#x} is not a valid compressed public key")]
    BadPublicKey { map: MapId, key_type: u64 },

    #[error("a version 0 PSBT has no PSBT_GLOBAL_UNSIGNED_TX")]
    MissingUnsignedTx,

    #[error("PSBT_GLOBAL_UNSIGNED_TX is not a valid transaction")]
    MalformedUnsignedTx,

    #[error("a version 2 PSBT must not carry PSBT_GLOBAL_UNSIGNED_TX")]
    UnsignedTxInV2,

    #[error("a version 0 PSBT must not carry the version 2 global field {0:#x}")]
    V2FieldInV0(u64),

    #[error("a version 0 PSBT must not carry the version 2 field {key_type:#x} in {map}")]
    V2FieldInV0Map { map: MapId, key_type: u64 },

    #[error("a pair of type {0:#x} is already present in this map")]
    DuplicateInsert(u64),

    #[error("a version 2 PSBT has no {0}")]
    MissingGlobal(&'static str),

    #[error("{map} has no {field}")]
    MissingField { map: MapId, field: &'static str },

    #[error(
        "the declared count of {kind} ({declared}) exceeds the {remaining} bytes remaining"
    )]
    ImplausibleCount {
        kind: &'static str,
        declared: u64,
        remaining: usize,
    },

    #[error(
        "no lock time satisfies every input: input {0} requires a height lock time and \
         input {1} requires a time lock time"
    )]
    ConflictingLockTimes(usize, usize),

    #[error("PSBT_IN_REQUIRED_TIME_LOCKTIME of input {0} is below 500000000")]
    TimeLockTimeTooSmall(usize),

    #[error("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of input {0} is not below 500000000")]
    HeightLockTimeTooLarge(usize),

    #[error("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of input {0} is zero")]
    HeightLockTimeZero(usize),

    #[error("output {0} has no script; it has not been computed yet")]
    OutputScriptNotComputed(usize),

    #[error("output {0} has an amount above the 21 million coin supply")]
    OutputAmountOutOfRange(usize),

    /// Raised only by `to_v0`, when the version 0 bytes this crate produced
    /// are somehow rejected by `bitcoin::Psbt`. It should be unreachable; it
    /// is an error rather than a panic because this code is reachable from a
    /// read-only RPC method.
    #[error("converting to a version 0 PSBT produced bytes the v0 parser rejected: {0}")]
    V0Roundtrip(String),

    #[error(
        "this PSBT asks for more than {limit} silent payment checks; \
         no transaction that can be relayed needs that many"
    )]
    TooMuchWork { limit: usize },

    #[error("{0}")]
    Structure(String),
}

impl PsbtError {
    /// A structural complaint with a message the caller composed. Kept
    /// separate from the typed variants so `validate_structure` can report
    /// BIP 375's rules in the BIP's own wording.
    pub fn structure(msg: impl Into<String>) -> Self {
        PsbtError::Structure(msg.into())
    }
}
