use bitcoin::{Block, OutPoint, TxOut};

use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
use crate::storage::coinview::Coin;
use crate::storage::flatfile::FlatFilePos;
use crate::storage::{Store, StoreBatch};
use crate::validation::script::ScriptVerifier;
use crate::validation::tx::check_transaction;

/// Coinbase maturity: outputs cannot be spent until this many confirmations.
const COINBASE_MATURITY: u32 = 100;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("bad-txns-inputs-missingorspent")]
    MissingOrSpentInput,
    #[error("bad-txns-premature-spend-of-coinbase")]
    PrematureCoinbaseSpend,
    #[error("bad-txns-in-belowout")]
    BadAmounts,
    #[error("bad-cb-amount")]
    BadCoinbaseValue,
    #[error("mandatory-script-verify-flag-failed ({0})")]
    ScriptFailed(String),
    #[error("{0}")]
    TxValidation(#[from] crate::validation::ValidationError),
}

/// Block subsidy (coinbase reward) for a given height.
fn block_subsidy(height: u32) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    (50 * 100_000_000) >> halvings
}

/// Process a block's transactions and produce a StoreBatch with all UTXO and index updates.
///
/// Validates:
/// - Context-free transaction checks
/// - Non-coinbase inputs reference existing UTXOs
/// - Coinbase maturity (100 blocks)
/// - Input amounts >= output amounts
/// - Coinbase value <= subsidy + fees
/// - Script verification via ScriptVerifier
///
/// The genesis block (height 0) is special: its coinbase is NOT added to the UTXO set,
/// matching Bitcoin Core behavior.
pub fn connect_block(
    store: &dyn Store,
    block: &Block,
    height: u32,
    parent_chainwork: &[u8; 32],
    flat_pos: FlatFilePos,
    script_verifier: &dyn ScriptVerifier,
) -> Result<StoreBatch, ConnectError> {
    let mut batch = StoreBatch::default();
    let block_hash = block.block_hash();
    let is_genesis = height == 0;
    let mut total_fees: u64 = 0;

    // Process each transaction
    for tx in &block.txdata {
        let is_coinbase = tx.is_coinbase();

        // Context-free transaction checks
        check_transaction(tx)?;

        // Spend inputs (skip for coinbase which has no real inputs)
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();

        if !is_coinbase {
            for input in &tx.input {
                let outpoint = input.previous_output;

                // Check that the UTXO exists
                let coin = store.get_coin(&outpoint);

                // Also check coins created earlier in this same block (within batch)
                let coin = coin.or_else(|| {
                    batch
                        .coin_puts
                        .iter()
                        .find(|(op, _)| *op == outpoint)
                        .map(|(_, c)| c.clone())
                });

                let coin = coin.ok_or(ConnectError::MissingOrSpentInput)?;

                // Check coinbase maturity
                if coin.coinbase && height - coin.height < COINBASE_MATURITY {
                    return Err(ConnectError::PrematureCoinbaseSpend);
                }

                sum_inputs += coin.amount;

                // Build TxOut for script verification
                prev_outputs.push(TxOut {
                    value: bitcoin::Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });

                batch.coin_removes.push(outpoint);
            }

            // Sum outputs
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

            // Check amounts
            if sum_inputs < sum_outputs {
                return Err(ConnectError::BadAmounts);
            }

            total_fees += sum_inputs - sum_outputs;

            // Script verification
            for (input_index, _) in tx.input.iter().enumerate() {
                script_verifier
                    .verify_input(tx, input_index, &prev_outputs[input_index])
                    .map_err(|e| ConnectError::ScriptFailed(e.to_string()))?;
            }
        }

        // Add outputs as new UTXOs (skip genesis coinbase)
        if !is_genesis || !is_coinbase {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                let coin = Coin {
                    amount: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.clone(),
                    height,
                    coinbase: is_coinbase,
                };
                batch.coin_puts.push((outpoint, coin));
            }
        }
    }

    // Check coinbase value doesn't exceed subsidy + fees
    if !is_genesis && !block.txdata.is_empty() {
        let coinbase_value: u64 = block.txdata[0]
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        let max_coinbase = block_subsidy(height) + total_fees;
        if coinbase_value > max_coinbase {
            return Err(ConnectError::BadCoinbaseValue);
        }
    }

    // Build BlockIndexEntry
    let chainwork = add_u256(parent_chainwork, &work_for_bits(block.header.bits));
    let entry = BlockIndexEntry {
        header: block.header,
        height,
        status: BlockStatus::Valid,
        num_tx: block.txdata.len() as u32,
        file_number: flat_pos.file_number,
        data_pos: flat_pos.data_pos,
        chainwork,
    };

    batch.block_index_puts.push((block_hash, entry));
    batch.tip = Some(block_hash);
    batch.height_hash_puts.push((height, block_hash));

    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_connect_genesis_block() {
        let store = InMemoryStore::new();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let pos = FlatFilePos {
            file_number: 0,
            data_pos: 0,
        };
        let parent_work = [0u8; 32];
        let verifier = NoopVerifier;

        let batch =
            connect_block(&store, &genesis, 0, &parent_work, pos, &verifier).unwrap();

        // Genesis coinbase should NOT be in coin_puts
        assert!(batch.coin_puts.is_empty());
        // But the block index entry should be there
        assert_eq!(batch.block_index_puts.len(), 1);
        assert_eq!(batch.height_hash_puts.len(), 1);
        assert!(batch.tip.is_some());
    }

    #[test]
    fn test_block_subsidy() {
        assert_eq!(block_subsidy(0), 50 * 100_000_000);
        assert_eq!(block_subsidy(209_999), 50 * 100_000_000);
        assert_eq!(block_subsidy(210_000), 25 * 100_000_000);
        assert_eq!(block_subsidy(420_000), 1_250_000_000);
        assert_eq!(block_subsidy(210_000 * 64), 0);
    }
}
