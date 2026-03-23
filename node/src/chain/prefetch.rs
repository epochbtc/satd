use bitcoin::{Block, BlockHash, Txid};
use crossbeam_channel::{bounded, Receiver};
use std::collections::HashMap;
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
    /// Speculatively resolved coins: (tx_index, input_index) -> Coin.
    /// These are best-effort; the connect thread re-validates against the
    /// authoritative UTXO set.
    pub speculative_coins: HashMap<(usize, usize), Coin>,
    /// Pre-computed txids (one per transaction in the block).
    pub txids: Vec<Txid>,
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

    // 6. Speculative UTXO resolution (cache warming)
    let mut speculative_coins = HashMap::new();
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        for (input_idx, input) in tx.input.iter().enumerate() {
            if let Some(coin) = store.get_coin(&input.previous_output) {
                speculative_coins.insert((tx_idx, input_idx), coin);
            }
        }
    }

    Some(PreprocessedBlock {
        height,
        hash,
        block,
        entry,
        parent,
        flat_pos,
        mtp,
        speculative_coins,
        txids,
    })
}

/// Handle returned by `start_prefetcher` to control the background pipeline.
pub struct PrefetchHandle {
    shutdown: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
    /// Update this to tell the prefetcher the connect cursor has advanced.
    pub cursor: Arc<AtomicU32>,
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
}

/// Start the prefetch pipeline.
///
/// Spawns `num_workers` background threads that read, deserialize, and
/// pre-process upcoming blocks. A coordinator thread reorders the results
/// and feeds them to the connect thread in height order via the returned
/// `Receiver<PreprocessedBlock>`.
///
/// The connect thread should call `prefetch_handle.advance_cursor(height)`
/// after each successful connection so the coordinator can dispatch new work.
pub fn start_prefetcher(
    store: Arc<dyn Store + Send + Sync>,
    blocks_dir: PathBuf,
    start_height: u32,
    num_workers: usize,
    lookahead: usize,
) -> (Receiver<PreprocessedBlock>, PrefetchHandle) {
    let (tx, rx) = bounded::<PreprocessedBlock>(lookahead);
    let shutdown = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicU32::new(start_height));

    // Work dispatch and result collection channels
    let (work_tx, work_rx) = bounded::<u32>(lookahead * 2);
    let (result_tx, result_rx) = bounded::<PreprocessedBlock>(lookahead * 2);

    // Spawn worker threads
    let mut workers = Vec::with_capacity(num_workers + 1);

    for _ in 0..num_workers {
        let w_rx = work_rx.clone();
        let w_tx = result_tx.clone();
        let w_store = store.clone();
        let w_dir = blocks_dir.clone();
        let w_shutdown = shutdown.clone();

        workers.push(thread::spawn(move || {
            while !w_shutdown.load(Ordering::Relaxed) {
                match w_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                    Ok(height) => {
                        if let Some(pre) = prefetch_block(&*w_store, &w_dir, height) {
                            let _ = w_tx.send(pre);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }));
    }
    drop(result_tx); // Workers hold the only senders

    // Coordinator thread: assigns work and reorders results for in-order delivery
    let coord_shutdown = shutdown.clone();
    let coord_cursor = cursor.clone();
    let coord_store = store.clone();
    let coord_tx = tx;

    workers.push(thread::spawn(move || {
        let mut next_to_send = coord_cursor.load(Ordering::Relaxed);
        let mut next_to_assign = next_to_send;
        let mut buffer: HashMap<u32, PreprocessedBlock> = HashMap::new();

        while !coord_shutdown.load(Ordering::Relaxed) {
            // Update cursor from connect thread
            let current_cursor = coord_cursor.load(Ordering::Relaxed);
            if current_cursor > next_to_send {
                // Connect thread advanced past us, catch up
                next_to_send = current_cursor;
                // Discard buffered blocks below cursor
                buffer.retain(|h, _| *h >= next_to_send);
                if next_to_assign < next_to_send {
                    next_to_assign = next_to_send;
                }
            }

            // Assign work up to lookahead ahead of next_to_send
            while next_to_assign < next_to_send + lookahead as u32 {
                // Check if block data is available before dispatching
                if coord_store
                    .get_block_hash_by_height(next_to_assign)
                    .is_some()
                {
                    let _ = work_tx.try_send(next_to_assign);
                }
                next_to_assign += 1;
            }

            // Collect results from workers
            while let Ok(pre) = result_rx.try_recv() {
                buffer.insert(pre.height, pre);
            }

            // Send in-order results to connect thread
            while let Some(pre) = buffer.remove(&next_to_send) {
                if coord_tx.send(pre).is_err() {
                    return; // Connect thread dropped receiver
                }
                next_to_send += 1;
            }

            // Brief sleep if nothing ready to avoid busy-spinning
            if buffer.is_empty() {
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }));

    let handle = PrefetchHandle {
        shutdown,
        workers,
        cursor,
    };

    (rx, handle)
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
