//! Emission helpers for the `outpoint_spend` CF. Mirrors
//! `index::address::emit` but writes a single row per consumed UTXO
//! keyed by the spent outpoint instead of by scripthash.

use bitcoin::{OutPoint, Txid};

use crate::index::address::config::AddressIndexConfig;
use crate::index::outpoint_spend::SpendingRef;
use crate::storage::StoreBatch;

/// Emit an `outpoint_spend` row for input `vin` of `txid` at `height`
/// consuming `prev_outpoint`. Called from `connect_block` immediately
/// after the address-index spending row is queued, sharing the same
/// guard. No-op when the index is disabled.
#[inline]
pub fn emit_spend(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    height: u32,
    txid: Txid,
    vin: u32,
    prev_outpoint: OutPoint,
) {
    if !cfg.enabled {
        return;
    }
    batch.outpoint_spend_puts.push((
        prev_outpoint,
        SpendingRef {
            spending_txid: txid,
            spending_vin: vin,
            height,
        },
    ));
}

/// Build the removal key for a spending input. Used by
/// `disconnect_block` when reversing a connected block's spends.
/// Returns `None` when the index is disabled so the caller can skip
/// the push without an extra branch.
#[inline]
pub fn remove_key(cfg: &AddressIndexConfig, prev_outpoint: OutPoint) -> Option<OutPoint> {
    if !cfg.enabled {
        return None;
    }
    Some(prev_outpoint)
}
