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

    // Build a lookup table: short_id -> Transaction from mempool.
    //
    // This is the one assist-adjacent consumer that deliberately reads the
    // FULL union (`get_all_entries`), NOT a scope-filtered view: a peer's
    // compact block may contain transactions our policy quarantines, and a
    // quarantined tx we already hold lets us reconstruct the block locally
    // instead of paying a `getblocktxn` round trip (design §2.4). Filtering by
    // scope here would silently reintroduce those round trips. Validating /
    // reconstructing someone else's block is consensus-only and never
    // consults policy (I1 corollary, design §3) — so do NOT filter here.
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::constants::genesis_block;
    use bitcoin::Network;

    fn regtest_genesis() -> Block {
        genesis_block(Network::Regtest)
    }

    /// Helper: create a simple coinbase-like transaction for testing.
    fn make_test_tx(value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_make_compact_block() {
        let block = regtest_genesis();
        let compact = make_compact_block(&block);
        assert!(compact.is_some());
        let compact = compact.unwrap();
        // The compact block's header should match the original
        assert_eq!(compact.header, block.header);
    }

    #[test]
    fn test_make_compact_preserves_header() {
        let block = regtest_genesis();
        let compact = make_compact_block(&block).unwrap();
        assert_eq!(compact.header.prev_blockhash, block.header.prev_blockhash);
        assert_eq!(compact.header.merkle_root, block.header.merkle_root);
        assert_eq!(compact.header.time, block.header.time);
        assert_eq!(compact.header.bits, block.header.bits);
        assert_eq!(compact.header.nonce, block.header.nonce);
        assert_eq!(compact.header.version, block.header.version);
    }

    #[test]
    fn test_make_get_block_txn() {
        let hash = regtest_genesis().block_hash();
        let indices = vec![1, 3, 5];
        let req = make_get_block_txn(hash, &indices);
        assert_eq!(req.block_hash, hash);
        assert_eq!(req.indexes, vec![1, 3, 5]);
    }

    #[test]
    fn test_complete_pending_wrong_count() {
        let header = regtest_genesis().header;
        let tx = make_test_tx(5000);
        let pending = PendingCompact {
            header,
            txs: vec![Some(tx.clone()), None, None],
            missing_indices: vec![1, 2],
        };
        // Provide only 1 transaction but 2 are missing
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![make_test_tx(100)],
        };
        assert!(complete_pending(pending, &block_txns).is_none());
    }

    #[test]
    fn test_complete_pending_success() {
        let header = regtest_genesis().header;
        let tx0 = make_test_tx(5000);
        let tx1 = make_test_tx(1000);
        let tx2 = make_test_tx(2000);

        let pending = PendingCompact {
            header,
            txs: vec![Some(tx0.clone()), None, None],
            missing_indices: vec![1, 2],
        };
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![tx1.clone(), tx2.clone()],
        };
        let result = complete_pending(pending, &block_txns);
        assert!(result.is_some());
        let block = result.unwrap();
        assert_eq!(block.header, header);
        assert_eq!(block.txdata.len(), 3);
        assert_eq!(block.txdata[0], tx0);
        assert_eq!(block.txdata[1], tx1);
        assert_eq!(block.txdata[2], tx2);
    }

    #[test]
    fn test_complete_pending_index_out_of_bounds() {
        let header = regtest_genesis().header;
        let tx0 = make_test_tx(5000);

        let pending = PendingCompact {
            header,
            txs: vec![Some(tx0)],
            // Index 5 is out of bounds (only 1 slot)
            missing_indices: vec![5],
        };
        let block_txns = BlockTransactions {
            block_hash: header.block_hash(),
            transactions: vec![make_test_tx(100)],
        };
        assert!(complete_pending(pending, &block_txns).is_none());
    }

    #[test]
    fn test_reconstruct_coinbase_only_block() {
        // The regtest genesis block has only a coinbase transaction.
        // When we make a compact block from it, the coinbase is prefilled.
        // Reconstruction with an empty mempool should succeed since all
        // transactions are prefilled.
        let block = regtest_genesis();
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        let result = try_reconstruct(&compact, &mempool);
        match result {
            Ok(reconstructed) => {
                assert_eq!(reconstructed.header, block.header);
                assert_eq!(reconstructed.txdata.len(), block.txdata.len());
            }
            Err(_) => panic!("expected successful reconstruction of coinbase-only block"),
        }
    }

    #[test]
    fn test_reconstruct_empty_mempool_missing_txs() {
        // Create a block with coinbase + extra transaction.
        // The compact block will prefill the coinbase but the extra tx
        // needs to come from the mempool. With an empty mempool, we get
        // Err(PendingCompact) with the missing index.
        let mut block = regtest_genesis();
        let extra_tx = make_test_tx(1234);
        block.txdata.push(extra_tx);

        let compact = make_compact_block(&block).unwrap();
        let mempool = Mempool::new(300_000_000, 1_000);
        let result = try_reconstruct(&compact, &mempool);
        match result {
            Ok(_) => panic!("expected Err(PendingCompact) with missing transactions"),
            Err(pending) => {
                assert_eq!(pending.header, block.header);
                // At least one index should be missing
                assert!(!pending.missing_indices.is_empty());
            }
        }
    }

    // PR 5: compact-block reconstruction is the one assist-adjacent consumer
    // that reads the FULL union — a tx our policy fully quarantines must still
    // reconstruct the peer's block locally, sparing a `getblocktxn` round trip
    // (design §2.4). Reconstructing someone else's block is consensus-only.
    #[test]
    fn reconstruct_uses_quarantined_txs() {
        use crate::mempool::pool::QuarantineScope;
        let full_quarantine = QuarantineScope { relay: true, template: true };

        let mut block = regtest_genesis();
        let extra_tx = make_test_tx(4321);
        block.txdata.push(extra_tx.clone());
        let compact = make_compact_block(&block).unwrap();

        let mempool = Mempool::new(300_000_000, 1_000);
        // The extra tx is present but fully quarantined (assisted on neither
        // relay nor template).
        mempool.insert_tx_scoped_for_test(extra_tx, full_quarantine);

        match try_reconstruct(&compact, &mempool) {
            Ok(reconstructed) => {
                assert_eq!(reconstructed.header, block.header);
                assert_eq!(reconstructed.txdata.len(), block.txdata.len());
            }
            Err(_) => panic!("quarantined tx must still be available for reconstruction"),
        }
    }
}
