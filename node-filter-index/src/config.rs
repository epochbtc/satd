//! Runtime configuration for the BIP 158 compact block filter index.
//!
//! Matches the `AddressIndexConfig` shape: a runtime opt-in
//! (`--blockfilterindex=basic` / `-noindex=blockfilter`) gates index
//! work without conditional compilation. The Cargo `block-filter-index`
//! feature flag controls whether the module is even compiled in (so a
//! `--no-default-features` consensus-only build pays nothing). Once
//! compiled in, the runtime config decides per-block emission.

#[derive(Clone, Debug, Default)]
pub struct FilterIndexConfig {
    /// Whether per-block emission of basic filter rows is active.
    /// Disabled via `--blockfilterindex=0` or `-noindex=blockfilter`.
    pub enabled: bool,
    /// Whether the BIP 157 P2P service is exposed (advertise
    /// `NODE_COMPACT_FILTERS` and answer `getcfilters` /
    /// `getcfheaders` / `getcfcheckpt`).
    ///
    /// Implies `enabled`; the `Config::load` reconciliation in `satd`
    /// rejects `peer_serve && !enabled` at startup.
    pub peer_serve: bool,
}
