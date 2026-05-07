use bitcoin::{Block, BlockHash, Transaction, TxOut, Txid};
use crossbeam_channel::bounded;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
use crate::storage::coinview::Coin;
use crate::storage::flatfile::FlatFilePos;
use crate::storage::Store;
use crate::validation::script::{ConsensusVerifier, PrimaryEngine, RustVerifier, ScriptVerifier};
use crate::validation::tx::check_transaction;

/// A block that has been pre-read, deserialized, and partially validated
/// by a background prefetch worker.
pub struct PreprocessedBlock {
    pub height: u32,
    pub hash: BlockHash,
    pub block: Block,
    pub entry: BlockIndexEntry,
    pub parent: BlockIndexEntry,
    pub flat_pos: FlatFilePos,
    pub mtp: u32,
    /// Pre-computed txids (one per transaction in the block).
    pub txids: Vec<Txid>,
    /// Tx indices where all inputs were speculatively resolved AND scripts
    /// were pre-verified successfully. Only populated in assumevalid mode.
    pub script_verified_txs: HashSet<usize>,
}

/// Read a block from a flat file without holding the FlatFileManager mutex.
/// Replicates the `read_block_direct` pattern from `ChainState`.
fn read_block_from_file(blocks_dir: &Path, pos: &FlatFilePos) -> Option<Block> {
    let path = blocks_dir.join(format!("blk{:05}.dat", pos.file_number));
    let mut file = File::open(&path).ok()?;
    // Flat file layout: [magic:4][size:4][block_data:size]
    // data_pos points to the start of the record (the magic bytes).
    file.seek(SeekFrom::Start(pos.data_pos as u64)).ok()?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header).ok()?;
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let mut data = vec![0u8; size];
    file.read_exact(&mut data).ok()?;
    bitcoin::consensus::deserialize(&data).ok()
}

/// Compute median time past for a height using read-only store lookups.
/// Same algorithm as `connect::get_median_time_past` and `ChainState::get_median_time_past`.
fn compute_mtp(store: &dyn Store, height: u32) -> u32 {
    let start = height.saturating_sub(11);
    let mut timestamps: Vec<u32> = Vec::new();
    for h in start..height {
        if let Some(hash) = store.get_block_hash_by_height(h)
            && let Some(entry) = store.get_block_index(&hash)
        {
            timestamps.push(entry.header.time);
        }
    }
    if timestamps.is_empty() {
        return 0;
    }
    timestamps.sort();
    timestamps[timestamps.len() / 2]
}

/// Prefetch and pre-process a single block at the given height.
///
/// Performs the following work off the connect thread:
/// 1. Reads the block index entry and parent entry
/// 2. Reads the raw block from flat files (no mutex)
/// 3. Computes MTP via read-only store lookups
/// 4. Computes txids and runs context-free `check_transaction`
/// 5. Speculatively resolves UTXO inputs (cache warming)
pub fn prefetch_block(
    store: &dyn Store,
    blocks_dir: &Path,
    height: u32,
    _assumevalid: bool,
    primary_engine: PrimaryEngine,
) -> Option<PreprocessedBlock> {
    // 1. Get block hash and entry
    let hash = store.get_block_hash_by_height(height)?;
    let entry = store.get_block_index(&hash)?;

    if !matches!(entry.status, BlockStatus::DataStored | BlockStatus::Valid) {
        return None;
    }

    // 2. Get parent entry
    let parent = store.get_block_index(&entry.header.prev_blockhash)?;

    // 3. Read block from flat file (no lock — direct file read)
    let flat_pos = FlatFilePos {
        file_number: entry.file_number,
        data_pos: entry.data_pos,
    };
    let block = read_block_from_file(blocks_dir, &flat_pos)?;

    // 4. Compute MTP (read-only store lookups)
    let mtp = compute_mtp(store, height);

    // 5. Context-free work: txids + check_transaction
    let mut txids = Vec::with_capacity(block.txdata.len());
    for tx in &block.txdata {
        txids.push(tx.compute_txid());
        // Context-free check — if it fails, connect_block will catch it
        let _ = check_transaction(tx);
    }

    // 6. Speculative UTXO resolution (cache warming) + optional script pre-verification.
    //
    // The batch lookup always warms the CoinCache for the connect thread.
    // In assumevalid mode, the results are also used for script pre-verification.
    // Single batch lookup — no redundant DB queries.
    let input_keys: Vec<(usize, usize, bitcoin::OutPoint)> = block
        .txdata
        .iter()
        .enumerate()
        .flat_map(|(tx_idx, tx)| {
            if tx.is_coinbase() { return Vec::new(); }
            tx.input.iter().enumerate()
                .map(|(input_idx, input)| (tx_idx, input_idx, input.previous_output))
                .collect::<Vec<_>>()
        })
        .collect();
    let outpoints: Vec<bitcoin::OutPoint> = input_keys.iter().map(|(_, _, op)| *op).collect();
    let coins = store.get_coins_batch(&outpoints); // single batch lookup — warms cache

    // 7. Speculative script verification — always attempted, not just assumevalid.
    //
    // Pre-verifies scripts using the coins resolved above. The connect thread
    // will skip primary verification for txs where all inputs still exist
    // (coins are immutable — if the connect thread finds the coin, it is
    // necessarily the same data the prefetch worker used). Shadow dispatch
    // is handled separately by the connect thread via dispatch_shadow().
    //
    // Uses std::thread::scope (not rayon) to avoid deadlock risk with the
    // connect thread's rayon pool.
    let script_verified_txs: HashSet<usize> = {
        let mut spec_coins: HashMap<(usize, usize), Coin> = HashMap::new();
        for ((tx_idx, input_idx, _), coin_opt) in input_keys.into_iter().zip(coins) {
            if let Some(coin) = coin_opt {
                spec_coins.insert((tx_idx, input_idx), coin);
            }
        }

        let verifiable: Vec<(usize, &Transaction, Vec<TxOut>)> = block.txdata.iter()
            .enumerate()
            .filter_map(|(tx_idx, tx)| {
                if tx.is_coinbase() { return None; }
                let mut prev_outputs = Vec::with_capacity(tx.input.len());
                for (input_idx, _) in tx.input.iter().enumerate() {
                    let coin = spec_coins.get(&(tx_idx, input_idx))?;
                    prev_outputs.push(TxOut {
                        value: bitcoin::Amount::from_sat(coin.amount),
                        script_pubkey: coin.script_pubkey.clone(),
                    });
                }
                Some((tx_idx, tx, prev_outputs))
            })
            .collect();

        if verifiable.is_empty() {
            HashSet::new()
        } else {
            let num_threads = std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(4);
            let chunk_size = verifiable.len().div_ceil(num_threads);
            let mut verified = HashSet::new();
            // Use whichever concrete engine the user configured as primary.
            // Prefetch's "OK" result causes the connect thread to skip its
            // own primary verify, so this engine must match the user's
            // authoritative choice — otherwise we'd covertly promote the
            // other engine to authoritative for pre-verified txs.
            std::thread::scope(|s| {
                let handles: Vec<_> = verifiable.chunks(chunk_size)
                    .map(|chunk| {
                        s.spawn(move || {
                            chunk.iter()
                                .filter(|(_, tx, prev_outputs)| match primary_engine {
                                    PrimaryEngine::Cpp => ConsensusVerifier
                                        .verify_transaction(tx, prev_outputs, height)
                                        .is_ok(),
                                    PrimaryEngine::Rust => RustVerifier
                                        .verify_transaction(tx, prev_outputs, height)
                                        .is_ok(),
                                })
                                .map(|(tx_idx, _, _)| *tx_idx)
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                for h in handles {
                    verified.extend(h.join().unwrap());
                }
            });
            verified
        }
    };

    Some(PreprocessedBlock {
        height,
        hash,
        block,
        entry,
        parent,
        flat_pos,
        mtp,
        txids,
        script_verified_txs,
    })
}

/// Handle returned by `start_prefetcher` to control the background pipeline.
pub struct PrefetchHandle {
    shutdown: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
    /// Update this to tell the prefetcher the connect cursor has advanced.
    pub cursor: Arc<AtomicU32>,
    /// Shared buffer: workers insert, connect thread removes by height.
    buffer: PrefetchBuffer,
}

impl PrefetchHandle {
    /// Signal all workers to stop and join their threads.
    pub fn stop(self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for w in self.workers {
            let _ = w.join();
        }
    }

    /// Notify the prefetcher that the connect thread has advanced to `height`.
    pub fn advance_cursor(&self, height: u32) {
        self.cursor.store(height, Ordering::Relaxed);
    }

    /// Try to take a preprocessed block for the given height.
    /// Returns None if the block hasn't been prefetched yet.
    pub fn take_block(&self, height: u32) -> Option<PreprocessedBlock> {
        self.buffer.lock().remove(&height)
    }
}

/// Shared prefetch buffer: workers insert by height, connect thread removes by height.
/// No coordinator needed — direct lookup eliminates the ordering bottleneck that
/// caused 0% prefetch hit rates.
pub type PrefetchBuffer = Arc<parking_lot::Mutex<HashMap<u32, PreprocessedBlock>>>;

/// Start the prefetch pipeline.
///
/// Spawns `num_workers` background threads that read, deserialize, and
/// pre-process upcoming blocks. Results go into a shared buffer keyed by
/// height. The connect thread calls `take_block(height)` to retrieve them.
///
/// Call `prefetch_handle.advance_cursor(height)` after each successful
/// connection so the dispatcher assigns new work ahead of the cursor.
pub fn start_prefetcher(
    store: Arc<dyn Store + Send + Sync>,
    blocks_dir: PathBuf,
    start_height: u32,
    num_workers: usize,
    lookahead: usize,
    assumevalid: bool,
    primary_engine: PrimaryEngine,
) -> PrefetchHandle {
    let shutdown = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicU32::new(start_height));
    let buffer: PrefetchBuffer = Arc::new(parking_lot::Mutex::new(HashMap::new()));

    // Work dispatch channel
    let (work_tx, work_rx) = bounded::<u32>(lookahead * 2);

    let mut workers = Vec::with_capacity(num_workers + 1);

    // Spawn worker threads — process heights, insert into shared buffer
    for _ in 0..num_workers {
        let w_rx = work_rx.clone();
        let w_store = store.clone();
        let w_dir = blocks_dir.clone();
        let w_shutdown = shutdown.clone();
        let w_buffer = buffer.clone();

        workers.push(thread::spawn(move || {
            while !w_shutdown.load(Ordering::Relaxed) {
                match w_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                    Ok(height) => {
                        if let Some(pre) = prefetch_block(&*w_store, &w_dir, height, assumevalid, primary_engine) {
                            w_buffer.lock().insert(height, pre);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }));
    }

    // Dispatcher thread: assigns work ahead of the connect cursor
    let disp_shutdown = shutdown.clone();
    let disp_cursor = cursor.clone();
    let disp_store = store.clone();
    let disp_buffer = buffer.clone();

    workers.push(thread::spawn(move || {
        let mut next_to_assign = disp_cursor.load(Ordering::Relaxed);

        while !disp_shutdown.load(Ordering::Relaxed) {
            let current_cursor = disp_cursor.load(Ordering::Relaxed);
            if current_cursor > next_to_assign {
                next_to_assign = current_cursor;
            }

            // Evict stale entries below cursor
            {
                let mut buf = disp_buffer.lock();
                buf.retain(|h, _| *h >= current_cursor);
            }

            // Assign work up to lookahead ahead of cursor
            while next_to_assign < current_cursor + lookahead as u32 {
                let has_data = disp_store
                    .get_block_hash_by_height(next_to_assign)
                    .and_then(|hash| disp_store.get_block_index(&hash))
                    .is_some_and(|entry| {
                        matches!(
                            entry.status,
                            BlockStatus::DataStored | BlockStatus::Valid
                        )
                    });
                if has_data {
                    let _ = work_tx.try_send(next_to_assign);
                }
                next_to_assign += 1;
            }

            thread::sleep(std::time::Duration::from_millis(10));
        }
    }));

    PrefetchHandle {
        shutdown,
        workers,
        cursor,
        buffer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_block_from_nonexistent_file() {
        let pos = FlatFilePos {
            file_number: 999,
            data_pos: 0,
        };
        assert!(read_block_from_file(Path::new("/nonexistent"), &pos).is_none());
    }
}
