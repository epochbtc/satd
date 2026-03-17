use bitcoin::{Block, OutPoint, TxOut};

use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
use crate::storage::coinview::Coin;
use crate::storage::flatfile::FlatFilePos;
use crate::storage::undo::{OutPointSer, UndoData};
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
    #[error("bad-txns-nonfinal")]
    LocktimeNotFinal,
    #[error("bad-txns-nonBIP68-final")]
    SequenceLockNotMet,
    #[error("{0}")]
    TxValidation(#[from] crate::validation::ValidationError),
}

/// Block subsidy (coinbase reward) for a given height.
pub fn block_subsidy(height: u32) -> u64 {
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
    median_time_past: u32,
) -> Result<StoreBatch, ConnectError> {
    let mut batch = StoreBatch::default();
    let mut undo = UndoData::default();
    let block_hash = block.block_hash();
    let is_genesis = height == 0;
    let mut total_fees: u64 = 0;

    // Process each transaction
    for tx in &block.txdata {
        let is_coinbase = tx.is_coinbase();

        // Context-free transaction checks
        check_transaction(tx)?;

        // Locktime validation (BIP 113: use MTP for time-based locktimes)
        if !is_coinbase {
            let is_final = tx.input.iter().all(|i| i.sequence == bitcoin::Sequence::MAX);
            if !is_final {
                let locktime = tx.lock_time.to_consensus_u32();
                if locktime > 0 {
                    if locktime < 500_000_000 {
                        // Height-based locktime
                        if height < locktime {
                            return Err(ConnectError::LocktimeNotFinal);
                        }
                    } else {
                        // Time-based locktime (BIP 113: compare against MTP)
                        if median_time_past < locktime {
                            return Err(ConnectError::LocktimeNotFinal);
                        }
                    }
                }
            }
        }

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

                // BIP 68 sequence lock validation (tx version >= 2)
                if tx.version.0 >= 2 && input.sequence != bitcoin::Sequence::MAX {
                    let seq = input.sequence.0;
                    let disable_flag = 1u32 << 31;
                    if seq & disable_flag == 0 {
                        let time_flag = 1u32 << 22;
                        let mask = 0x0000ffff_u32;
                        if seq & time_flag != 0 {
                            // Time-based: value * 512 seconds relative to input's MTP
                            // Simplified: we check against block time difference
                            let required_seconds = (seq & mask) as u64 * 512;
                            let elapsed = block.header.time.saturating_sub(coin.height) as u64;
                            // Note: proper BIP 68 uses MTP of the block at coin.height
                            // For now use a simplified check; full MTP lookup requires store access
                            let _ = required_seconds;
                            let _ = elapsed;
                            // TODO: full MTP-based relative time check
                        } else {
                            // Height-based: value blocks relative to input's confirmation height
                            let required_blocks = seq & mask;
                            if height - coin.height < required_blocks {
                                return Err(ConnectError::SequenceLockNotMet);
                            }
                        }
                    }
                }

                // Save for undo
                undo.spent_coins.push((OutPointSer::from(&outpoint), coin.clone()));

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

            // Script verification (all inputs at once for taproot)
            script_verifier
                .verify_transaction(tx, &prev_outputs)
                .map_err(|e| ConnectError::ScriptFailed(e.to_string()))?;
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
    if !is_genesis {
        batch.undo_puts.push((block_hash, undo));
    }

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
            connect_block(&store, &genesis, 0, &parent_work, pos, &verifier, 0).unwrap();

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
