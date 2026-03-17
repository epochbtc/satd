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
    #[error("bad-cb-height")]
    BadCoinbaseHeight,
    #[error("{0}")]
    TxValidation(#[from] crate::validation::ValidationError),
}

/// Decode the block height from a BIP 34 coinbase scriptSig.
///
/// The height is encoded via `Builder::push_int(height)` which produces:
/// - OP_0 (0x00) for height 0
/// - OP_1..OP_16 (0x51..0x60) for heights 1-16
/// - [push_size, LE bytes...] for heights 17+
fn decode_coinbase_height(bytes: &[u8]) -> Option<u32> {
    let first = bytes[0];
    match first {
        0x00 => Some(0), // OP_0
        0x51..=0x60 => Some((first - 0x50) as u32), // OP_1..OP_16
        0x01..=0x04 => {
            // Data push: first byte = number of bytes, followed by LE height
            let num_bytes = first as usize;
            if 1 + num_bytes > bytes.len() {
                return None;
            }
            let mut height: u32 = 0;
            for i in 0..num_bytes {
                height |= (bytes[1 + i] as u32) << (8 * i);
            }
            Some(height)
        }
        _ => None,
    }
}

/// Compute median time past (MTP) for a given height using the store directly.
/// MTP is the median of the timestamps of the previous 11 blocks.
fn get_median_time_past(store: &dyn Store, height: u32) -> u32 {
    let start = if height > 11 { height - 11 } else { 0 };
    let mut timestamps: Vec<u32> = Vec::new();
    for h in start..height {
        if let Some(hash) = store.get_block_hash_by_height(h) {
            if let Some(entry) = store.get_block_index(&hash) {
                timestamps.push(entry.header.time);
            }
        }
    }
    if timestamps.is_empty() {
        return 0;
    }
    timestamps.sort();
    timestamps[timestamps.len() / 2]
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

        // BIP 34: verify coinbase encodes the correct block height
        if is_coinbase && height > 0 {
            let script = &tx.input[0].script_sig;
            let bytes = script.as_bytes();
            if bytes.is_empty() {
                return Err(ConnectError::BadCoinbaseHeight);
            }
            let encoded_height = decode_coinbase_height(bytes)
                .ok_or(ConnectError::BadCoinbaseHeight)?;
            if encoded_height != height {
                return Err(ConnectError::BadCoinbaseHeight);
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
                            // BIP 68: compare MTP at current height vs MTP at coin height
                            let required_seconds = (seq & mask) as u64 * 512;
                            let mtp_coin = get_median_time_past(store, coin.height) as u64;
                            let mtp_block = median_time_past as u64;
                            if mtp_block.saturating_sub(mtp_coin) < required_seconds {
                                return Err(ConnectError::SequenceLockNotMet);
                            }
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
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, BlockHash, Network, Sequence, Transaction, TxIn, TxOut, Witness,
    };

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

    // ── decode_coinbase_height tests ──────────────────────────────────

    #[test]
    fn test_decode_coinbase_height_op_0() {
        assert_eq!(decode_coinbase_height(&[0x00]), Some(0));
    }

    #[test]
    fn test_decode_coinbase_height_op_1_through_16() {
        for h in 1u32..=16 {
            assert_eq!(decode_coinbase_height(&[0x50 + h as u8]), Some(h));
        }
    }

    #[test]
    fn test_decode_coinbase_height_data_push() {
        assert_eq!(decode_coinbase_height(&[0x01, 0x11]), Some(17));
        assert_eq!(decode_coinbase_height(&[0x01, 0xff]), Some(255));
        assert_eq!(decode_coinbase_height(&[0x02, 0x00, 0x01]), Some(256));
        assert_eq!(decode_coinbase_height(&[0x02, 0xe8, 0x03]), Some(1000));
        assert_eq!(
            decode_coinbase_height(&[0x03, 0xa0, 0x86, 0x01]),
            Some(100_000)
        );
    }

    #[test]
    fn test_decode_coinbase_height_invalid() {
        // Push size 5 is out of the 0x01..=0x04 range
        assert_eq!(
            decode_coinbase_height(&[0x05, 0x00, 0x00, 0x00, 0x00, 0x00]),
            None
        );
        // Push 1 byte but no data following
        assert_eq!(decode_coinbase_height(&[0x01]), None);
    }

    // ── helpers for connect_block tests ───────────────────────────────

    /// Create an InMemoryStore pre-loaded with a single coin.
    fn make_test_store_with_coin(coin_height: u32, coinbase: bool) -> (InMemoryStore, OutPoint, Coin) {
        let store = InMemoryStore::new();
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
        );
        let outpoint = OutPoint { txid, vout: 0 };
        let coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: coin_height,
            coinbase,
        };

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin.clone()));
        store.write_batch(batch).unwrap();

        (store, outpoint, coin)
    }

    /// Build a block containing a coinbase and a spending transaction.
    ///
    /// The coinbase encodes `height` via BIP 34 and pays exactly `block_subsidy(height)`.
    /// The spending tx consumes `outpoint` (expected to hold 50_000_000 sats)
    /// and produces a single output of the same value (zero fee).
    fn make_block_spending(
        outpoint: OutPoint,
        height: u32,
        tx_version: i32,
        sequence: u32,
        locktime: u32,
    ) -> Block {
        // Coinbase tx with BIP 34 height encoding
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Spending tx
        let spending_tx = Transaction {
            version: Version(tx_version),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let txdata = vec![coinbase, spending_tx];

        // Build block with a placeholder merkle root, then fix it
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn default_pos() -> FlatFilePos {
        FlatFilePos {
            file_number: 0,
            data_pos: 0,
        }
    }

    // ── BIP 68 sequence-lock tests ────────────────────────────────────

    #[test]
    fn test_bip68_height_lock_met() {
        // Coin at height 50, sequence requires 10 blocks, block at height 60 -> pass
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 60, 2, 10, 0);
        let result = connect_block(
            &store,
            &block,
            60,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_height_lock_not_met() {
        // Coin at height 50, sequence requires 10 blocks, block at height 55 -> fail
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 55, 2, 10, 0);
        let result = connect_block(
            &store,
            &block,
            55,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(matches!(result, Err(ConnectError::SequenceLockNotMet)));
    }

    #[test]
    fn test_bip68_disabled() {
        // Bit 31 set disables the sequence lock
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 2, 0x8000_0000 | 100, 0);
        let result = connect_block(
            &store,
            &block,
            51,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_version1_no_enforcement() {
        // tx version 1: BIP 68 not enforced even though sequence < required blocks
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 1, 10, 0);
        let result = connect_block(
            &store,
            &block,
            51,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_sequence_max_final() {
        // Sequence::MAX bypasses BIP 68 entirely
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 2, 0xffff_ffff, 0);
        let result = connect_block(
            &store,
            &block,
            51,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    // ── BIP 113 locktime tests ────────────────────────────────────────

    #[test]
    fn test_locktime_height_met() {
        // locktime=50, height=60 -> pass
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 60, 2, 0, 50);
        let result = connect_block(
            &store,
            &block,
            60,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_locktime_height_not_met() {
        // locktime=50, height=49 -> fail
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 49, 2, 0, 50);
        let result = connect_block(
            &store,
            &block,
            49,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(matches!(result, Err(ConnectError::LocktimeNotFinal)));
    }

    #[test]
    fn test_locktime_time_not_met() {
        // locktime=500_000_001 (time-based), MTP=500_000_000 (too early)
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 60, 2, 0, 500_000_001);
        let result = connect_block(
            &store,
            &block,
            60,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            500_000_000,
        );
        assert!(matches!(result, Err(ConnectError::LocktimeNotFinal)));
    }

    #[test]
    fn test_locktime_all_inputs_final() {
        // All inputs have Sequence::MAX -> locktime skipped even if not met
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 49, 2, 0xffff_ffff, 50);
        let result = connect_block(
            &store,
            &block,
            49,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }

    // ── UTXO / amount tests ──────────────────────────────────────────

    #[test]
    fn test_spend_nonexistent_utxo() {
        let store = InMemoryStore::new();
        let fake_outpoint = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xab; 32]),
            ),
            vout: 0,
        };
        let block = make_block_spending(fake_outpoint, 1, 2, 0xffff_ffff, 0);
        let result = connect_block(
            &store,
            &block,
            1,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(matches!(result, Err(ConnectError::MissingOrSpentInput)));
    }

    #[test]
    fn test_immature_coinbase_spend() {
        // Coinbase at height 50, spending at height 149 (99 confirmations, need 100)
        let (store, outpoint, _) = make_test_store_with_coin(50, true);
        let block = make_block_spending(outpoint, 149, 2, 0xffff_ffff, 0);
        let result = connect_block(
            &store,
            &block,
            149,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(matches!(result, Err(ConnectError::PrematureCoinbaseSpend)));
    }

    #[test]
    fn test_mature_coinbase_spend() {
        // Coinbase at height 50, spending at height 150 (exactly 100 confirmations)
        let (store, outpoint, _) = make_test_store_with_coin(50, true);
        let block = make_block_spending(outpoint, 150, 2, 0xffff_ffff, 0);
        let result = connect_block(
            &store,
            &block,
            150,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok());
    }
}
