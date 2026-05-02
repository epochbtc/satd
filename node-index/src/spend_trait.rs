//! `SpendIndex` trait — read-side surface that maps a spent outpoint
//! to the input that consumed it. Used by Esplora's `outspend` /
//! `outspends` endpoints, by `gettxspendingprevout` for confirmed
//! inputs, and by future Electrum query handlers.
//!
//! The trait is intentionally narrow. Mempool spends are tracked
//! separately by the mempool itself; this trait answers "is this
//! confirmed-side outpoint spent on the active chain, and if so by
//! what" only.

use bitcoin::OutPoint;

use crate::spend_keys::SpendingRef;
use crate::types::IndexError;

pub trait SpendIndex: Send + Sync {
    /// Look up the (confirmed) input that spent `outpoint`. Returns
    /// `Ok(None)` when the outpoint is unspent on the active chain or
    /// has never existed; `Err(Disabled)` when the address-index gate
    /// is off (the spend index rides on the same flag).
    fn spend_of(&self, outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError>;
}
