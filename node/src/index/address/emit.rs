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

use bitcoin::TxOut;

use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::{
    AddrFundingKeyV3, AddrFundingRowV3, AddrSpendingKeyV3, AddrSpendingRowV3, scripthash_of,
};
use crate::storage::StoreBatch;
use crate::storage::coinview::Coin;

/// Emit a funding row for output `vout` of the transaction with
/// chain-order ordinal `txseq`. Called from the per-output loop of
/// `connect_block`, immediately after the coin is appended to
/// `coin_puts`.
///
/// The row is keyed on the ordinal rather than the height and txid the
/// public key carries — both are recoverable from it, and the store
/// resolves them before the row leaves.
#[inline]
pub fn emit_funding(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    txseq: u64,
    vout: u32,
    txout: &TxOut,
) {
    if !cfg.enabled {
        return;
    }
    batch.addr_funding_puts.push(AddrFundingRowV3 {
        scripthash: scripthash_of(&txout.script_pubkey),
        txseq,
        vout,
        amount_sat: txout.value.to_sat(),
    });
    // Counters are bumped at the commit boundary in
    // `RocksDbStore::write_batch_mode`, not here — a block can fail
    // validation after `connect_block` produces a batch, in which
    // case the rows never reach disk.
}

/// Emit a spending row for input `vin` of the transaction with ordinal
/// `txseq`, consuming output `funding_vout` of the transaction with
/// ordinal `funding_txseq`. The spent `Coin` is the resolved input (from
/// the UTXO cache, intra-block coins, or the store) — its
/// `script_pubkey` is the scripthash source.
///
/// The caller resolves `funding_txseq` — it comes out of the spent coin
/// on the hot path — and skips the call entirely when it cannot, rather
/// than passing a placeholder. Ordinal 0 is the genesis coinbase's, so a
/// placeholder would point the row at a real transaction.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn emit_spending(
    batch: &mut StoreBatch,
    cfg: &AddressIndexConfig,
    txseq: u64,
    vin: u32,
    spent: &Coin,
    funding_txseq: u64,
    funding_vout: u32,
) {
    if !cfg.enabled {
        return;
    }
    batch.addr_spending_puts.push(AddrSpendingRowV3 {
        scripthash: scripthash_of(&spent.script_pubkey),
        txseq,
        vin,
        funding_txseq,
        funding_vout,
    });
    // Counters are bumped at the commit boundary — see emit_funding.
}

/// Build a funding-removal key for `(scripthash, txseq, vout)`. Used by
/// `disconnect_block` when reversing a connected block's funding rows.
#[inline]
pub fn funding_remove_key(
    cfg: &AddressIndexConfig,
    txseq: u64,
    vout: u32,
    txout: &TxOut,
) -> Option<AddrFundingKeyV3> {
    if !cfg.enabled {
        return None;
    }
    Some(AddrFundingKeyV3 {
        scripthash: scripthash_of(&txout.script_pubkey),
        txseq,
        vout,
    })
}

/// Build a spending-removal key for `(scripthash, txseq, vin)`. Used by
/// `disconnect_block` when reversing a connected block's spending rows.
#[inline]
pub fn spending_remove_key(
    cfg: &AddressIndexConfig,
    txseq: u64,
    vin: u32,
    spent: &Coin,
) -> Option<AddrSpendingKeyV3> {
    if !cfg.enabled {
        return None;
    }
    Some(AddrSpendingKeyV3 {
        scripthash: scripthash_of(&spent.script_pubkey),
        txseq,
        vin,
    })
}
