use bitcoin::{Block, OutPoint, Transaction, TxOut};
use rayon::prelude::*;

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
    let start = height.saturating_sub(11);
    let mut timestamps: Vec<u32> = Vec::new();
    for h in start..height {
        if let Some(hash) = store.get_block_hash_by_height(h)
            && let Some(entry) = store.get_block_index(&hash) {
                timestamps.push(entry.header.time);
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

    // Transactions queued for parallel script verification after UTXO resolution
    let mut verify_queue: Vec<(&Transaction, Vec<TxOut>)> = Vec::new();

    // Process each transaction: resolve UTXOs sequentially, defer script verification
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

            // Collect for parallel script verification
            verify_queue.push((tx, prev_outputs));
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

    // Parallel script verification: verify all transactions concurrently
    if !verify_queue.is_empty() {
        let result: Result<(), ConnectError> = verify_queue
            .par_iter()
            .try_for_each(|(tx, prev_outputs)| {
                script_verifier
                    .verify_transaction(tx, prev_outputs)
                    .map_err(|e| ConnectError::ScriptFailed(e.to_string()))
            });
        result?;
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

    // Populate txindex: map each txid to its containing block
    for tx in &block.txdata {
        batch.tx_index_puts.push((tx.compute_txid(), block_hash));
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

    #[test]
    fn test_bip68_time_lock_met() {
        // Coin at height 10, spending at height 20.
        // Time-based sequence: bit 22 set, 1 unit = 512 seconds required.
        // MTP at coin height < MTP at block height by >= 512 seconds.
        let coin_height = 10u32;
        let block_height = 20u32;
        let (store, outpoint, _) = make_test_store_with_coin(coin_height, false);

        // Add block index entries so get_median_time_past can compute MTP.
        // MTP for coin_height uses blocks at heights max(0, 10-11)..10 = 0..10
        // MTP for block_height uses blocks at heights max(0, 20-11)..20 = 9..20
        let base_time = 1_700_000_000u32;
        let mut batch = StoreBatch::default();
        for h in 0..block_height {
            let hash = BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array({
                    let mut arr = [0u8; 32];
                    arr[0] = h as u8;
                    arr[1] = (h >> 8) as u8;
                    arr[3] = 0xAA; // distinguish from coin txid
                    arr
                }),
            );
            let mut hdr = bitcoin::constants::genesis_block(Network::Regtest).header;
            hdr.time = base_time + h * 100; // 100s apart
            let entry = BlockIndexEntry {
                header: hdr,
                height: h,
                status: BlockStatus::Valid,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            };
            batch.block_index_puts.push((hash, entry));
            batch.height_hash_puts.push((h, hash));
        }
        store.write_batch(batch).unwrap();

        // MTP at coin_height=10 uses timestamps for heights 0..10 (10 values)
        // sorted: base, base+100, ..., base+900 -> median = timestamps[5] = base+500
        // MTP at block_height=20 uses timestamps for heights 9..20 (11 values)
        // sorted: base+900, base+1000, ..., base+1900 -> median = timestamps[5] = base+1400
        // Difference = base+1400 - (base+500) = 900 seconds >= 512 seconds

        // Time-based BIP68 sequence: bit 22 set, 1 unit (512 seconds)
        let seq = (1u32 << 22) | 1; // time-based, 1 unit = 512s
        let block = make_block_spending(outpoint, block_height, 2, seq, 0);

        // The connect_block receives MTP for the block (median_time_past param).
        // But BIP68 internally calls get_median_time_past(store, coin.height) for the coin MTP.
        // We pass median_time_past = MTP at block height.
        // MTP at block_height=20: timestamps[9..20] = base+900..base+1900
        // sorted = [base+900, base+1000, ..., base+1900], median = timestamps[5] = base+1400
        let mtp_block = base_time + 1400;

        let result = connect_block(
            &store,
            &block,
            block_height,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            mtp_block,
        );
        assert!(result.is_ok(), "BIP68 time lock should be met, got {:?}", result.err());
    }

    #[test]
    fn test_bip68_time_lock_not_met() {
        // Same setup but with insufficient MTP difference.
        let coin_height = 10u32;
        let block_height = 11u32; // Only 1 block ahead
        let (store, outpoint, _) = make_test_store_with_coin(coin_height, false);

        let base_time = 1_700_000_000u32;
        let mut batch = StoreBatch::default();
        for h in 0..block_height {
            let hash = BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array({
                    let mut arr = [0u8; 32];
                    arr[0] = h as u8;
                    arr[1] = (h >> 8) as u8;
                    arr[3] = 0xAA;
                    arr
                }),
            );
            let mut hdr = bitcoin::constants::genesis_block(Network::Regtest).header;
            // Only 10 seconds apart — not enough for 512s requirement
            hdr.time = base_time + h * 10;
            let entry = BlockIndexEntry {
                header: hdr,
                height: h,
                status: BlockStatus::Valid,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            };
            batch.block_index_puts.push((hash, entry));
            batch.height_hash_puts.push((h, hash));
        }
        store.write_batch(batch).unwrap();

        // MTP at coin_height=10: heights 0..10, timestamps base..base+90,
        // median = timestamps[5] = base+50
        // MTP at block_height=11: heights 0..11, timestamps base..base+100,
        // median = timestamps[5] = base+50
        // Difference = 0 seconds < 512 seconds
        let mtp_block = base_time + 50;

        let seq = (1u32 << 22) | 1; // time-based, 1 unit = 512s
        let block = make_block_spending(outpoint, block_height, 2, seq, 0);

        let result = connect_block(
            &store,
            &block,
            block_height,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            mtp_block,
        );
        assert!(
            matches!(result, Err(ConnectError::SequenceLockNotMet)),
            "BIP68 time lock should NOT be met, got Ok",
        );
    }

    #[test]
    fn test_coinbase_value_too_high() {
        // Coinbase output exceeds block_subsidy + fees -> BadCoinbaseValue.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);

        // Build block manually: coinbase pays too much
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(101)
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
                // subsidy at height 101 = 50 BTC, fees = 0, but we pay 60 BTC
                value: Amount::from_sat(60 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Spending tx: consumes 50_000_000 sats, produces 50_000_000 sats (zero fee)
        let spending_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, spending_tx],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let result = connect_block(
            &store,
            &block,
            101,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(
            matches!(result, Err(ConnectError::BadCoinbaseValue)),
            "Expected BadCoinbaseValue",
        );
    }

    #[test]
    fn test_intra_block_spending() {
        // Second non-coinbase tx spends an output from the first non-coinbase tx.
        // This should succeed because connect_block checks batch.coin_puts for in-block UTXOs.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let height = 101u32;

        // Coinbase
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

        // First spending tx: consumes the store coin, produces 50M sats
        let tx1 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx1_txid = tx1.compute_txid();

        // Second spending tx: consumes tx1's output (in-block UTXO)
        let tx2 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: tx1_txid,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, tx1, tx2],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let result = connect_block(
            &store,
            &block,
            height,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok(), "Intra-block spending should succeed, got {:?}", result.err());
    }

    #[test]
    fn test_bip34_correct_height() {
        // Block at height 101 with correctly encoded BIP 34 height. Should pass.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 101, 2, 0xffff_ffff, 0);
        let result = connect_block(
            &store,
            &block,
            101,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(result.is_ok(), "BIP 34 correct height should pass, got {:?}", result.err());
    }

    #[test]
    fn test_bip34_wrong_height() {
        // Block at height 101 but coinbase encodes height 999 -> BadCoinbaseHeight.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);

        // Build coinbase with wrong height
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(999) // Wrong height!
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
                value: Amount::from_sat(block_subsidy(101)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, spending_tx],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let result = connect_block(
            &store,
            &block,
            101,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(
            matches!(result, Err(ConnectError::BadCoinbaseHeight)),
            "Expected BadCoinbaseHeight",
        );
    }

    #[test]
    fn test_output_overflow() {
        // Spending tx outputs exceed inputs -> BadAmounts.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        // Coin has 50_000_000 sats. Build a tx that outputs more.

        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(101)
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
                value: Amount::from_sat(block_subsidy(101)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Spending tx: input has 50_000_000, but output has 60_000_000
        let spending_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(60_000_000), // More than input!
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, spending_tx],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let result = connect_block(
            &store,
            &block,
            101,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        );
        assert!(
            matches!(result, Err(ConnectError::BadAmounts)),
            "Expected BadAmounts",
        );
    }

    #[test]
    fn test_txindex_populated() {
        // After connect_block, verify all txids from the block appear in batch.tx_index_puts.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 101, 2, 0xffff_ffff, 0);

        let batch = connect_block(
            &store,
            &block,
            101,
            &[0u8; 32],
            default_pos(),
            &NoopVerifier,
            0,
        )
        .unwrap();

        // Collect all txids from the block
        let block_txids: Vec<_> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

        // Collect all txids from tx_index_puts
        let indexed_txids: Vec<_> = batch.tx_index_puts.iter().map(|(txid, _)| *txid).collect();

        assert_eq!(
            block_txids.len(),
            indexed_txids.len(),
            "tx_index_puts should have one entry per transaction"
        );
        for txid in &block_txids {
            assert!(
                indexed_txids.contains(txid),
                "txid {:?} should be in tx_index_puts",
                txid
            );
        }

        // Verify they all point to the correct block hash
        let block_hash = block.block_hash();
        for (_, bh) in &batch.tx_index_puts {
            assert_eq!(*bh, block_hash, "tx_index entry should point to the block hash");
        }
    }
}
