use bitcoin::{Block, Network, OutPoint, Transaction, TxOut};
use std::collections::{HashMap, HashSet};

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
/// BIP 34 requires the coinbase scriptSig to start with a CScript push of the
/// block height. The push opcode specifies how many bytes follow. We interpret
/// those bytes as a little-endian integer. Early BIP 34 blocks sometimes used
/// non-minimal pushes (e.g., 4-byte push for a 3-byte height), so we only
/// compare the decoded value, not the encoding length.
fn decode_coinbase_height(bytes: &[u8]) -> Option<u32> {
    let first = bytes[0];
    match first {
        0x00 => Some(0), // OP_0
        0x51..=0x60 => Some((first - 0x50) as u32), // OP_1..OP_16
        0x01..=0x08 => {
            // Data push: first byte = number of bytes to push
            let num_bytes = first as usize;
            if 1 + num_bytes > bytes.len() {
                return None;
            }
            // Read as little-endian, but cap to u32 (only use first 4 bytes)
            let mut height: u32 = 0;
            for i in 0..num_bytes.min(4) {
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
/// BIP 34 activation height per network.
pub fn bip34_activation_height(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 227_931,  // BIP 34 activated at this height per Bitcoin Core
        Network::Testnet => 21_111,
        _ => 1, // Signet, Regtest: always active
    }
}

/// BIP 113 (MTP for locktime) / BIP 68 (sequence locks) activation height.
/// Before this height, time-based locktimes compare against block timestamp,
/// not MTP. BIP 68 sequence locks are not enforced before this height.
pub fn bip113_activation_height(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 419_328,
        Network::Testnet => 770_112,
        _ => 1, // Signet, Regtest: always active
    }
}

/// Parameters for block connection. Groups the many inputs needed by connect_block
/// into a single struct for readability.
pub struct ConnectParams<'a> {
    pub store: &'a dyn Store,
    pub block: &'a Block,
    pub height: u32,
    pub parent_chainwork: &'a [u8; 32],
    pub flat_pos: FlatFilePos,
    pub script_verifier: &'a dyn ScriptVerifier,
    pub median_time_past: u32,
    pub network: Network,
    /// Tx indices whose scripts were pre-verified by the prefetch pipeline.
    /// Those txs skip re-verification.
    pub pre_verified_txs: Option<&'a std::collections::HashSet<usize>>,
    /// Number of threads for parallel UTXO resolution and script verification.
    pub num_threads: usize,
    /// Pre-computed txids from prefetch. Avoids rehashing all transactions.
    pub precomputed_txids: Option<&'a [bitcoin::Txid]>,
}

pub fn connect_block(params: &ConnectParams) -> Result<StoreBatch, ConnectError> {
    let ConnectParams {
        store, block, height, parent_chainwork, flat_pos,
        script_verifier, median_time_past, network,
        pre_verified_txs, num_threads, precomputed_txids,
    } = params;
    let store: &dyn Store = *store;
    let script_verifier: &dyn ScriptVerifier = *script_verifier;
    let height = *height;
    let median_time_past = *median_time_past;
    let network = *network;
    let num_threads = *num_threads;
    let flat_pos = *flat_pos;
    let block_hash = block.block_hash();
    let is_genesis = height == 0;
    let mut total_fees: u64 = 0;

    // Pre-allocate based on block size
    let total_inputs: usize = block.txdata.iter().map(|tx| tx.input.len()).sum();
    let total_outputs: usize = block.txdata.iter().map(|tx| tx.output.len()).sum();
    let mut batch = StoreBatch {
        coin_puts: Vec::with_capacity(total_outputs),
        coin_removes: Vec::with_capacity(total_inputs),
        ..Default::default()
    };
    let mut undo = UndoData {
        spent_coins: Vec::with_capacity(total_inputs),
    };

    // Transactions queued for parallel script verification after UTXO resolution
    let mut verify_queue: Vec<(&Transaction, Vec<TxOut>)> = Vec::with_capacity(block.txdata.len());

    // Reuse precomputed txids from prefetch if available, otherwise compute once
    let computed_txids: Vec<bitcoin::Txid>;
    let txid_slice: &[bitcoin::Txid] = if let Some(pre) = precomputed_txids {
        pre
    } else {
        computed_txids = block.txdata.iter().map(|tx| tx.compute_txid()).collect();
        &computed_txids
    };
    let mut txids: Vec<bitcoin::Txid> = Vec::with_capacity(block.txdata.len());

    // Fast lookup for coins created earlier in this block (intra-block spends).
    let mut intra_block_coins: HashMap<OutPoint, Coin> = HashMap::new();

    // --- UTXO pre-resolution for external inputs ---
    // Batch-lookup from authoritative store. Prefetch warmed the CoinCache,
    // so most external lookups hit the cache.
    let block_txids: HashSet<bitcoin::Txid> = txid_slice.iter().copied().collect();

    // Collect external inputs (not intra-block spends)
    let external_lookups: Vec<(usize, usize, OutPoint)> = block.txdata.iter()
        .enumerate()
        .flat_map(|(tx_idx, tx)| {
            if tx.is_coinbase() {
                return Vec::new();
            }
            tx.input.iter().enumerate()
                .filter(|(_, input)| !block_txids.contains(&input.previous_output.txid))
                .map(|(in_idx, input)| (tx_idx, in_idx, input.previous_output))
                .collect::<Vec<_>>()
        })
        .collect();

    // Resolve external inputs. Speculative coins from prefetch are used as hints:
    // they warm the cache but each coin is still verified against the authoritative
    // store to prevent stale reads (e.g., if an earlier block spent the coin after
    // prefetch resolved it).
    let pre_resolved: HashMap<(usize, usize), Coin> = if external_lookups.is_empty() {
        HashMap::new()
    } else {
        // Batch lookup from authoritative store (hits CoinCache which was warmed by prefetch)
        let outpoints: Vec<OutPoint> = external_lookups.iter()
            .map(|(_, _, op)| *op)
            .collect();
        let coins = store.get_coins_batch(&outpoints);
        external_lookups.iter()
            .zip(coins)
            .filter_map(|((tx_idx, in_idx, _), coin_opt)| {
                coin_opt.map(|coin| ((*tx_idx, *in_idx), coin))
            })
            .collect()
    };

    // Process each transaction: resolve UTXOs sequentially, defer script verification
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        let is_coinbase = tx.is_coinbase();
        let txid = txid_slice[tx_idx];

        // Context-free transaction checks
        check_transaction(tx)?;

        // Locktime validation
        // Before BIP 113 activation: time-based locktimes compare against block timestamp.
        // After BIP 113: time-based locktimes compare against MTP.
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
                        // Time-based locktime
                        let time_threshold = if height >= bip113_activation_height(network) {
                            median_time_past
                        } else {
                            block.header.time
                        };
                        if time_threshold < locktime {
                            return Err(ConnectError::LocktimeNotFinal);
                        }
                    }
                }
            }
        }

        // BIP 34: verify coinbase encodes the correct block height
        if is_coinbase && height >= bip34_activation_height(network) {
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
            for (in_idx, input) in tx.input.iter().enumerate() {
                let outpoint = input.previous_output;

                // Lookup order: pre-resolved → intra-block → store (avoids DB hit for intra-block spends)
                let coin = pre_resolved.get(&(tx_idx, in_idx)).cloned()
                    .or_else(|| intra_block_coins.remove(&outpoint))
                    .or_else(|| store.get_coin(&outpoint));

                let coin = coin.ok_or(ConnectError::MissingOrSpentInput)?;

                // Check coinbase maturity
                if coin.coinbase && height - coin.height < COINBASE_MATURITY {
                    return Err(ConnectError::PrematureCoinbaseSpend);
                }

                // BIP 68 sequence lock validation (tx version >= 2, only after activation)
                if height >= bip113_activation_height(network)
                    && tx.version.0 >= 2 && input.sequence != bitcoin::Sequence::MAX {
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

                batch.coin_removes.push((outpoint, coin.amount, coin.height));
            }

            // Sum outputs
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

            // Check amounts
            if sum_inputs < sum_outputs {
                return Err(ConnectError::BadAmounts);
            }

            total_fees += sum_inputs - sum_outputs;

            // Collect for parallel script verification
            // Skip if this tx was already pre-verified by the prefetch pipeline
            let already_verified = pre_verified_txs
                .map(|set| set.contains(&tx_idx))
                .unwrap_or(false);
            if !already_verified {
                verify_queue.push((tx, prev_outputs));
            }
        }

        // Add outputs as new UTXOs (skip genesis coinbase)
        if !is_genesis || !is_coinbase {
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
                intra_block_coins.insert(outpoint, coin.clone());
                batch.coin_puts.push((outpoint, coin));
            }
        }

        txids.push(txid);
    }

    // Parallel script verification: verify all transactions concurrently.
    // If a shadow verifier is present, run it in parallel at the block level
    // (one thread pool for primary, one for shadow) — wall-clock = max(primary, shadow).
    if !verify_queue.is_empty() {
        let shadow = script_verifier.shadow_verifier();

        if verify_queue.len() <= 1 || num_threads <= 1 {
            for (tx, prev_outputs) in &verify_queue {
                script_verifier
                    .verify_transaction(tx, prev_outputs, height)
                    .map_err(|e| ConnectError::ScriptFailed(e.to_string()))?;
            }
            // Run shadow sequentially for small blocks (no threading overhead)
            if let Some(shadow_v) = shadow {
                for (tx, prev_outputs) in &verify_queue {
                    let shadow_result = shadow_v.verify_transaction(tx, prev_outputs, height);
                    if let Err(e) = &shadow_result {
                        let primary_ok = script_verifier.verify_transaction(tx, prev_outputs, height).is_ok();
                        if primary_ok {
                            tracing::error!("SHADOW MISMATCH: primary accepted but shadow REJECTED: {} (txid={})", e, tx.compute_txid());
                        }
                    }
                }
            }
        } else {
            let queue_ref = &verify_queue;

            let errors: Vec<ConnectError> = std::thread::scope(|s| {
                // With shadow: split threads evenly — half primary, half shadow
                // Without shadow: all threads for primary
                let primary_threads = if shadow.is_some() { num_threads / 2 } else { num_threads };
                let shadow_threads = if shadow.is_some() { num_threads - primary_threads } else { 0 };

                let primary_chunk_size = verify_queue.len().div_ceil(primary_threads.max(1));
                let shadow_chunk_size = verify_queue.len().div_ceil(shadow_threads.max(1));

                // Spawn shadow thread pool concurrently
                let shadow_handles: Vec<_> = if let Some(shadow_v) = shadow {
                    queue_ref
                        .chunks(shadow_chunk_size)
                        .map(|chunk| {
                            s.spawn(move || {
                                let mut mismatches = Vec::new();
                                for (tx, prev_outputs) in chunk {
                                    if let Err(e) = shadow_v.verify_transaction(tx, prev_outputs, height) {
                                        mismatches.push((tx.compute_txid(), e));
                                    }
                                }
                                mismatches
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                // Primary thread pool
                let handles: Vec<_> = queue_ref
                    .chunks(primary_chunk_size)
                    .map(|chunk| {
                        s.spawn(move || {
                            let mut errs = Vec::new();
                            for (tx, prev_outputs) in chunk {
                                if let Err(e) = script_verifier
                                    .verify_transaction(tx, prev_outputs, height)
                                {
                                    errs.push(ConnectError::ScriptFailed(e.to_string()));
                                }
                            }
                            errs
                        })
                    })
                    .collect();

                let mut all_errors = Vec::new();
                for handle in handles {
                    all_errors.extend(handle.join().unwrap());
                }

                // Collect shadow results and log mismatches
                for sh in shadow_handles {
                    let mismatches = sh.join().unwrap();
                    for (txid, err) in mismatches {
                        if all_errors.is_empty() {
                            tracing::error!("SHADOW MISMATCH: primary accepted but shadow REJECTED: {} (txid={})", err, txid);
                        }
                    }
                }

                all_errors
            });
            if let Some(err) = errors.into_iter().next() {
                return Err(err);
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

    // Populate txindex: map each txid to its containing block
    for txid in &txids {
        batch.tx_index_puts.push((*txid, block_hash));
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

        let batch = connect_block(&ConnectParams {
            store: &store,
            block: &genesis,
            height: 0,
            parent_chainwork: &parent_work,
            flat_pos: pos,
            script_verifier: &verifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        }).unwrap();

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
        // Push 1 byte but no data following
        assert_eq!(decode_coinbase_height(&[0x01]), None);
        // Push size 0x09+ is out of range
        assert_eq!(
            decode_coinbase_height(&[0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            None
        );
        // 5-byte push is valid (extra nonce bytes, height in first 4)
        assert_eq!(
            decode_coinbase_height(&[0x05, 0x01, 0x00, 0x00, 0x00, 0x00]),
            Some(1)
        );
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
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 60,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_height_lock_not_met() {
        // Coin at height 50, sequence requires 10 blocks, block at height 55 -> fail
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 55, 2, 10, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 55,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(matches!(result, Err(ConnectError::SequenceLockNotMet)));
    }

    #[test]
    fn test_bip68_disabled() {
        // Bit 31 set disables the sequence lock
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 2, 0x8000_0000 | 100, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 51,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_version1_no_enforcement() {
        // tx version 1: BIP 68 not enforced even though sequence < required blocks
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 1, 10, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 51,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip68_sequence_max_final() {
        // Sequence::MAX bypasses BIP 68 entirely
        let (store, outpoint, _) = make_test_store_with_coin(50, false);
        let block = make_block_spending(outpoint, 51, 2, 0xffff_ffff, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 51,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok());
    }

    // ── BIP 113 locktime tests ────────────────────────────────────────

    #[test]
    fn test_locktime_height_met() {
        // locktime=50, height=60 -> pass
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 60, 2, 0, 50);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 60,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_locktime_height_not_met() {
        // locktime=50, height=49 -> fail
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 49, 2, 0, 50);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 49,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(matches!(result, Err(ConnectError::LocktimeNotFinal)));
    }

    #[test]
    fn test_locktime_time_not_met() {
        // locktime=500_000_001 (time-based), MTP=500_000_000 (too early)
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 60, 2, 0, 500_000_001);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 60,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 500_000_000,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(matches!(result, Err(ConnectError::LocktimeNotFinal)));
    }

    #[test]
    fn test_locktime_all_inputs_final() {
        // All inputs have Sequence::MAX -> locktime skipped even if not met
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 49, 2, 0xffff_ffff, 50);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 49,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 1,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(matches!(result, Err(ConnectError::MissingOrSpentInput)));
    }

    #[test]
    fn test_immature_coinbase_spend() {
        // Coinbase at height 50, spending at height 149 (99 confirmations, need 100)
        let (store, outpoint, _) = make_test_store_with_coin(50, true);
        let block = make_block_spending(outpoint, 149, 2, 0xffff_ffff, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 149,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(matches!(result, Err(ConnectError::PrematureCoinbaseSpend)));
    }

    #[test]
    fn test_mature_coinbase_spend() {
        // Coinbase at height 50, spending at height 150 (exactly 100 confirmations)
        let (store, outpoint, _) = make_test_store_with_coin(50, true);
        let block = make_block_spending(outpoint, 150, 2, 0xffff_ffff, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 150,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: block_height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: mtp_block,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: block_height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: mtp_block,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 101,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(result.is_ok(), "Intra-block spending should succeed, got {:?}", result.err());
    }

    #[test]
    fn test_bip34_correct_height() {
        // Block at height 101 with correctly encoded BIP 34 height. Should pass.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let block = make_block_spending(outpoint, 101, 2, 0xffff_ffff, 0);
        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 101,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 101,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 101,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
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

        let batch = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: 101,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Regtest,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        })
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

    // ── BIP 34/113/68 activation-height tests ────────────────────────

    #[test]
    fn test_bip34_activation_heights() {
        assert_eq!(bip34_activation_height(Network::Bitcoin), 227_931);
        assert_eq!(bip34_activation_height(Network::Testnet), 21_111);
        assert_eq!(bip34_activation_height(Network::Signet), 1);
        assert_eq!(bip34_activation_height(Network::Regtest), 1);
    }

    #[test]
    fn test_bip113_activation_heights() {
        assert_eq!(bip113_activation_height(Network::Bitcoin), 419_328);
        assert_eq!(bip113_activation_height(Network::Testnet), 770_112);
        assert_eq!(bip113_activation_height(Network::Signet), 1);
        assert_eq!(bip113_activation_height(Network::Regtest), 1);
    }

    #[test]
    fn test_bip34_not_enforced_before_activation() {
        // On Bitcoin mainnet, BIP 34 activates at height 227,931.
        // Before that, a coinbase with the WRONG height should still succeed.
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let height = 100u32; // well below 227,931

        // Build a block whose coinbase encodes height 999 (wrong), but at height 100
        // on Network::Bitcoin this should be fine because BIP 34 is not active yet.
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
                value: Amount::from_sat(block_subsidy(height)),
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

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Bitcoin,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(
            result.is_ok(),
            "BIP 34 should not be enforced before activation height on mainnet, got {:?}",
            result.err(),
        );
    }

    #[test]
    fn test_locktime_time_uses_block_time_before_bip113() {
        // On Bitcoin mainnet, BIP 113 activates at height 419,328.
        // Before activation, time-based locktimes compare against block.header.time,
        // NOT MTP. Create a scenario where block time > locktime but MTP < locktime:
        // this should succeed pre-activation (block time is used).
        let (store, outpoint, _) = make_test_store_with_coin(10, false);
        let height = 100u32; // well below 419,328
        let locktime = 500_000_100u32; // time-based (>= 500_000_000)

        let mut block = make_block_spending(outpoint, height, 2, 0, locktime);
        // Set block time above the locktime so block.header.time >= locktime
        block.header.time = 500_000_200;
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        // Pass MTP < locktime. Pre-BIP113, this doesn't matter because
        // block.header.time is used instead of MTP.
        let mtp = 500_000_000; // below locktime

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: mtp,
            network: Network::Bitcoin,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(
            result.is_ok(),
            "Pre-BIP113, time-based locktime should compare against block time, got {:?}",
            result.err(),
        );
    }

    #[test]
    fn test_bip68_not_enforced_before_activation() {
        // On Bitcoin mainnet, BIP 68 activates at height 419,328 (same as BIP 113).
        // Before that, sequence locks should NOT be enforced even if the lock is not met.
        let coin_height = 50u32;
        let block_height = 100u32; // well below 419,328
        let (store, outpoint, _) = make_test_store_with_coin(coin_height, false);

        // Sequence requires 200 blocks relative to coin height.
        // height - coin_height = 100 - 50 = 50 < 200, so the lock is NOT met.
        // But BIP 68 is not active on mainnet at height 100, so this should succeed.
        let seq = 200u32; // height-based, requires 200 blocks
        let block = make_block_spending(outpoint, block_height, 2, seq, 0);

        let result = connect_block(&ConnectParams {
            store: &store,
            block: &block,
            height: block_height,
            parent_chainwork: &[0u8; 32],
            flat_pos: default_pos(),
            script_verifier: &NoopVerifier,
            median_time_past: 0,
            network: Network::Bitcoin,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
        });
        assert!(
            result.is_ok(),
            "BIP 68 should not be enforced before activation height on mainnet, got {:?}",
            result.err(),
        );
    }

    #[test]
    fn test_coinbase_height_nonminimal_push() {
        // Early BIP 34 blocks sometimes used non-minimal pushes: 4-byte push
        // for a height that fits in 3 bytes. decode_coinbase_height should
        // decode the value correctly regardless.
        // Height 100,000 = 0x0186A0, fits in 3 bytes.
        // Non-minimal: encoded as 4-byte push (0x04) with a trailing zero byte.
        let bytes = [0x04, 0xA0, 0x86, 0x01, 0x00];
        assert_eq!(
            decode_coinbase_height(&bytes),
            Some(100_000),
            "Non-minimal 4-byte push for 3-byte height should decode correctly",
        );
    }

    #[test]
    fn test_coinbase_height_5_byte_push() {
        // 5-byte push: decode_coinbase_height uses only the first 4 bytes for
        // the height (u32), so the 5th byte is extra nonce / padding.
        // Height = 1 (0x01), encoded as 5-byte push.
        let bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0xFF];
        assert_eq!(
            decode_coinbase_height(&bytes),
            Some(1),
            "5-byte push should decode height from first 4 bytes",
        );

        // Height = 0x01020304 = 16,909,060
        let bytes2 = [0x05, 0x04, 0x03, 0x02, 0x01, 0xAB];
        assert_eq!(
            decode_coinbase_height(&bytes2),
            Some(0x01020304),
            "5-byte push should decode height from first 4 bytes (larger value)",
        );
    }
}
