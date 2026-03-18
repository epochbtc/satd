//! BIP 152 compact block relay support.
//!
//! Handles receiving compact blocks, reconstructing full blocks from mempool,
//! and requesting/providing missing transactions.

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::{Block, BlockHash, Transaction};
use std::collections::HashMap;

use crate::mempool::pool::Mempool;

/// A partially-reconstructed compact block awaiting missing transactions.
pub struct PendingCompact {
    pub header: bitcoin::block::Header,
    /// Ordered transaction slots: Some = have it, None = need it.
    pub txs: Vec<Option<Transaction>>,
    /// Indices of transactions we requested via GetBlockTxn.
    pub missing_indices: Vec<u64>,
}

/// Attempt to reconstruct a full block from a compact block using the mempool.
///
/// Returns Ok(Block) if all transactions were found, or Err(PendingCompact)
/// with the missing indices if some transactions are not in the mempool.
#[allow(clippy::result_large_err)]
pub fn try_reconstruct(
    compact: &HeaderAndShortIds,
    mempool: &Mempool,
) -> Result<Block, PendingCompact> {
    let siphash_keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);

    // Build a lookup table: short_id -> Transaction from mempool
    let all_entries = mempool.get_all_entries();
    let mut mempool_by_short_id: HashMap<ShortId, Transaction> = HashMap::new();
    for (_txid, entry) in &all_entries {
        let wtxid = entry.tx.compute_wtxid();
        let short_id = ShortId::with_siphash_keys(&wtxid.to_raw_hash(), siphash_keys);
        mempool_by_short_id.insert(short_id, entry.tx.clone());
    }

    // Total number of transactions in the block
    let total_txs = compact.prefilled_txs.len() + compact.short_ids.len();
    let mut txs: Vec<Option<Transaction>> = vec![None; total_txs];

    // Place prefilled transactions (differentially encoded indices)
    let mut idx = 0usize;
    for prefilled in &compact.prefilled_txs {
        idx += prefilled.idx as usize;
        if idx >= total_txs {
            // Malformed compact block
            return Err(PendingCompact {
                header: compact.header,
                txs: vec![],
                missing_indices: vec![],
            });
        }
        txs[idx] = Some(prefilled.tx.clone());
        idx += 1;
    }

    // Fill in remaining slots from mempool using short IDs
    let mut short_id_iter = compact.short_ids.iter();
    let mut missing_indices = Vec::new();
    for (i, slot) in txs.iter_mut().enumerate() {
        if slot.is_some() {
            continue; // Already prefilled
        }
        if let Some(short_id) = short_id_iter.next() {
            if let Some(tx) = mempool_by_short_id.get(short_id) {
                *slot = Some(tx.clone());
            } else {
                missing_indices.push(i as u64);
            }
        }
    }

    if missing_indices.is_empty() {
        // All transactions found — reconstruct the block
        let txdata: Vec<Transaction> = txs.into_iter().map(|t| t.unwrap()).collect();
        Ok(Block {
            header: compact.header,
            txdata,
        })
    } else {
        Err(PendingCompact {
            header: compact.header,
            txs,
            missing_indices,
        })
    }
}

/// Complete a pending compact block with the missing transactions from a BlockTxn response.
pub fn complete_pending(
    pending: PendingCompact,
    block_txns: &BlockTransactions,
) -> Option<Block> {
    let mut txs = pending.txs;

    if block_txns.transactions.len() != pending.missing_indices.len() {
        return None;
    }

    for (tx, &idx) in block_txns.transactions.iter().zip(pending.missing_indices.iter()) {
        let i = idx as usize;
        if i >= txs.len() {
            return None;
        }
        txs[i] = Some(tx.clone());
    }

    // Check all slots are filled
    if txs.iter().any(|t| t.is_none()) {
        return None;
    }

    let txdata: Vec<Transaction> = txs.into_iter().map(|t| t.unwrap()).collect();
    Some(Block {
        header: pending.header,
        txdata,
    })
}

/// Create a GetBlockTxn request for missing transactions.
pub fn make_get_block_txn(block_hash: BlockHash, missing_indices: &[u64]) -> BlockTransactionsRequest {
    BlockTransactionsRequest {
        block_hash,
        indexes: missing_indices.to_vec(),
    }
}

/// Create a HeaderAndShortIds from a full block for sending as a compact block.
pub fn make_compact_block(block: &Block) -> Option<HeaderAndShortIds> {
    let nonce: u64 = rand::random();
    // Version 2 = with witness data
    HeaderAndShortIds::from_block(block, nonce, 2, &[]).ok()
}
