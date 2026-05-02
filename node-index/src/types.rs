//! Read-side types for the address-history index.
//!
//! `HistoryEntry` mirrors the on-disk schema and is what the trait's
//! `confirmed_history` returns. `Utxo` is one live UTXO belonging to a
//! scripthash. `MempoolHistoryEntry` and `StatusUpdate` are reserved
//! shapes used by M4 / M5 — defined here so the trait surface is stable
//! across the milestone series.

use bitcoin::{OutPoint, Txid};

use crate::keys::Scripthash;

/// Disabled / "not enabled" surface error. Returned by the trait when
/// `--addressindex=0` is in effect so callers can distinguish "no rows
/// for this scripthash" (Ok empty) from "the index isn't running"
/// (`Err(IndexError::Disabled)`).
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("address index is disabled — restart with --addressindex=1 to enable")]
    Disabled,
    #[error("storage error: {0}")]
    Storage(String),
}

/// One confirmed history row: either a funding or a spending event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryEntry {
    Funding {
        height: u32,
        txid: Txid,
        vout: u32,
        amount_sat: u64,
    },
    Spending {
        height: u32,
        txid: Txid,
        vin: u32,
        prev_outpoint: OutPoint,
    },
}

impl HistoryEntry {
    pub fn height(&self) -> u32 {
        match self {
            HistoryEntry::Funding { height, .. } => *height,
            HistoryEntry::Spending { height, .. } => *height,
        }
    }

    pub fn txid(&self) -> Txid {
        match self {
            HistoryEntry::Funding { txid, .. } => *txid,
            HistoryEntry::Spending { txid, .. } => *txid,
        }
    }
}

/// One mempool history row. M4 fills this in; the type lives here so
/// the trait's `mempool_history` method can be defined now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MempoolHistoryEntry {
    pub txid: Txid,
}

/// One live UTXO for a scripthash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub height: u32,
    pub amount_sat: u64,
}

/// Status-hash update emitted to a per-scripthash subscriber. M5 fills
/// in the `status_hash` computation; this shape is the contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusUpdate {
    pub scripthash: Scripthash,
    pub status_hash: [u8; 32],
}
