//! Runtime configuration for the BIP 352 silent-payment tweak index.
//!
//! Design decision D5: always compiled, runtime opt-in — the
//! address-index pattern, not the filter index's cargo feature. The only
//! new dependency surface is `bitcoin::secp256k1`, already in the tree,
//! so "tested == shipped" holds without a feature-gated build.

#[derive(Clone, Debug, Default)]
pub struct SpIndexConfig {
    /// Whether per-block emission of `sp_tweaks` rows is active. Enabled
    /// via `silentpaymentindex=1`; default off.
    pub enabled: bool,
}

impl SpIndexConfig {
    pub fn enabled(enabled: bool) -> Self {
        Self { enabled }
    }
}
