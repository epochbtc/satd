//! Emission helpers used by `connect_block` / `disconnect_block` to
//! produce address-index rows alongside the existing coin and undo
//! writes. Each helper is a no-op when the index is disabled at
//! runtime, so callers can integrate unconditionally and pay only the
//! per-output / per-input cfg branch.
//!
//! The helpers reach into `StoreBatch`'s `addr_funding_*` /
//! `addr_spending_*` vectors directly. Atomicity with the chainstate
//! comes from the existing `RocksDBStore::write_batch_mode` path which
//! commits all CFs in a single `rocksdb::WriteBatch`.

use bitcoin::{OutPoint, TxOut, Txid};

use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow, scripthash_of,
};
use crate::storage::StoreBatch;
use crate::storage::coinview::Coin;

/// Emit a funding row for an output created at `(txid, vout)` in the
/// block at `height`. Called from the per-output loop of
/// `connect_block`, immediately after the coin is appended to
/// `coin_puts`.
#[inline]
pub fn emit_funding(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    height: u32,
    txid: Txid,
    vout: u32,
    txout: &TxOut,
) {
    if !cfg.enabled {
        return;
    }
    batch.addr_funding_puts.push(AddrFundingRow {
        scripthash: scripthash_of(&txout.script_pubkey),
        height,
        txid,
        vout,
        amount_sat: txout.value.to_sat(),
    });
}

/// Emit a spending row for input `vin` of `txid` at `height` consuming
/// a previously-funded output. The spent `Coin` is the resolved input
/// (from the UTXO cache, intra-block coins, or the store) — its
/// `script_pubkey` is the scripthash source, and `prev_outpoint` is
/// what the row will reference.
#[inline]
pub fn emit_spending(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    height: u32,
    txid: Txid,
    vin: u32,
    spent: &Coin,
    prev_outpoint: OutPoint,
) {
    if !cfg.enabled {
        return;
    }
    batch.addr_spending_puts.push(AddrSpendingRow {
        scripthash: scripthash_of(&spent.script_pubkey),
        height,
        txid,
        vin,
        prev_outpoint,
    });
}

/// Build a funding-removal key for `(scripthash, height, txid, vout)`.
/// Used by `disconnect_block` when reversing a connected block's
/// funding rows.
#[inline]
pub fn funding_remove_key(
    cfg: &AddressIndexConfig,
    height: u32,
    txid: Txid,
    vout: u32,
    txout: &TxOut,
) -> Option<AddrFundingKey> {
    if !cfg.enabled {
        return None;
    }
    Some(AddrFundingKey {
        scripthash: scripthash_of(&txout.script_pubkey),
        height,
        txid,
        vout,
    })
}

/// Build a spending-removal key for `(scripthash, height, txid, vin)`.
/// Used by `disconnect_block` when reversing a connected block's
/// spending rows.
#[inline]
pub fn spending_remove_key(
    cfg: &AddressIndexConfig,
    height: u32,
    txid: Txid,
    vin: u32,
    spent: &Coin,
) -> Option<AddrSpendingKey> {
    if !cfg.enabled {
        return None;
    }
    Some(AddrSpendingKey {
        scripthash: scripthash_of(&spent.script_pubkey),
        height,
        txid,
        vin,
    })
}
