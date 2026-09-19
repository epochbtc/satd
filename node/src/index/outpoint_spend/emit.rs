//! Emission helpers for the `spent` column family. Mirrors
//! `index::address::emit` but writes a single row per consumed UTXO,
//! keyed by the ordinal of the transaction that created the output
//! rather than by scripthash.

use crate::index::address::config::AddressIndexConfig;
use crate::storage::StoreBatch;
use node_index::SpentRow;

/// Emit a `spent` row for input `vin` of the transaction with ordinal
/// `spending_txseq`, consuming output `vout` of the transaction with
/// ordinal `funding_txseq`. Called from `connect_block` immediately
/// after the address-index spending row is queued, sharing the same
/// guard. No-op when the index is disabled.
///
/// The caller resolves `funding_txseq` — it comes out of the spent coin
/// on the hot path, which is why the coin carries it — and skips the
/// call entirely when it cannot, rather than passing a placeholder.
#[inline]
pub fn emit_spend(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    funding_txseq: u64,
    vout: u32,
    spending_txseq: u64,
    vin: u32,
) {
    if !cfg.enabled {
        return;
    }
    batch.spent_puts.push(SpentRow {
        funding_txseq,
        vout,
        spending_txseq,
        vin,
    });
}

/// Build the removal key for a spending input. Used by
/// `disconnect_block` when reversing a connected block's spends.
/// Returns `None` when the index is disabled so the caller can skip
/// the push without an extra branch.
#[inline]
pub fn remove_key(cfg: &AddressIndexConfig, funding_txseq: u64, vout: u32) -> Option<(u64, u32)> {
    if !cfg.enabled {
        return None;
    }
    Some((funding_txseq, vout))
}
