//! Read-side and codec error types for the silent-payment index.

/// Disabled / not-found surface error for the SP index read trait. The
/// serving surfaces (`getsilentpaymentblockdata` RPC and the streaming
/// `tweaks` category) map these to their respective error conventions.
///
/// - `Disabled`: index turned off via runtime config.
/// - `Incomplete`: enabled but `sp_index.complete` is false (backfill in
///   progress or never run) — the D4 rescan fast path and deep-replay
///   exemption both gate on completeness, so callers must not treat a
///   partial index as authoritative.
/// - `NotFound`: no row for this height (below taproot activation, above
///   tip, or a not-yet-backfilled range). Per-row presence is the serving
///   gate: a height-by-height scanner cannot silently miss its own
///   outputs, it just cannot proceed past a missing row.
/// - `Storage`: surfaced storage-backend failure.
#[derive(Debug, thiserror::Error)]
pub enum SpIndexError {
    #[error("silent payment index is disabled — restart with silentpaymentindex=1 to enable")]
    Disabled,
    #[error(
        "silent payment index is not synced — wait for backfill to complete or run reindex-chainstate"
    )]
    Incomplete,
    #[error("no silent payment tweak row at height {0}")]
    NotFound(u32),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Failure decoding a persisted `sp_tweaks` row. A row is written by this
/// same codec inside the chainstate-atomic batch, so a decode failure at
/// read time means on-disk corruption or a version the binary predates.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpCodecError {
    #[error("sp_tweaks row too short: {0} bytes")]
    TooShort(usize),
    #[error("unknown sp_tweaks row version: {0:#04x}")]
    UnknownVersion(u8),
    #[error("sp_tweaks row length {len} not consistent with entry count {count}")]
    LengthMismatch { len: usize, count: u32 },
    #[error("invalid tweak point in sp_tweaks row entry {0}")]
    InvalidTweak(u32),
}
