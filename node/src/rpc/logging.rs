//! The live surface behind Bitcoin Core's `logging` RPC.
//!
//! Core keeps a category bitmask inside its logger, so `logging` reads and
//! writes the same state that decides whether a line is emitted. satd's
//! verbosity lives in a `tracing_subscriber` `EnvFilter`, which is owned by the
//! binary, not by this crate — so the RPC reaches it through this trait rather
//! than through a map of its own.
//!
//! That indirection is the whole point. `logging` used to answer from a static
//! `OnceLock<BTreeMap<String, bool>>` initialised to "everything on", which
//! nothing else in the process ever read: toggling a category flipped a bit in
//! a private map, the filter was untouched, and the RPC reported 30 categories
//! enabled on a node running with no `-debug` at all. Every answer it gave was
//! wrong, and the RPC exists precisely to answer that question.

/// Read and write the node's live log-category state.
///
/// Implemented by the binary, which owns the filter-reload handle.
pub trait LogControl: Send + Sync {
    /// Every category this node can express, with whether it is currently
    /// being logged. Order is the caller's problem — the RPC sorts.
    fn categories(&self) -> Vec<(&'static str, bool)>;

    /// Core's `EnableOrDisableLogCategories`, applied in Core's order:
    /// `include` first, then `exclude`, so a category named in both ends up
    /// excluded.
    ///
    /// Returns the first unrecognised category name, which the RPC turns into
    /// Core's `-8 unknown logging category <cat>`. Nothing is applied when a
    /// name is rejected, so a partially-applied change is not observable.
    fn update(&self, include: &[String], exclude: &[String]) -> Result<(), String>;
}

/// The category names Core's `GetLogCategory` (`src/logging.cpp`) resolves to
/// `BCLog::ALL`:
///
/// ```cpp
/// if (str.empty() || str == "1" || str == "all") { flag = BCLog::ALL; return true; }
/// ```
///
/// Note what is *not* here. `none` and `0` are Core's spellings for the
/// `-debug` **config option** only, where `SetLoggingCategories`
/// (`src/init/common.cpp`) special-cases them as a drain over the argument
/// list. They are absent from `LOG_CATEGORIES_BY_STR`, so `EnableCategory` and
/// `DisableCategory` both fail on them and the `logging` RPC answers
/// `-8 unknown logging category none`. Treating them as "disable everything"
/// here meant `logging '["none"]'` silently turned off all logging on a node
/// where Core would have refused the call.
pub const ALL_CATEGORIES: [&str; 3] = ["", "all", "1"];
