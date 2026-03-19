use bitcoin::consensus::serialize;
use bitcoin::{Block, BlockHash, Network, OutPoint};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, RwLock};

use crate::chain::checkpoints::{self, Checkpoint};
use crate::chain::{connect, disconnect};
use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
use crate::storage::coinview::Coin;
use crate::storage::flatfile::{FlatFileManager, FlatFilePos};
use crate::storage::{Store, StoreError};
use crate::validation;
use crate::validation::script::{NoopVerifier, ScriptVerifier};

/// Controls script verification skipping during IBD.
/// Matches Bitcoin Core's `--assumevalid` semantics as a superset.
#[derive(Debug, Clone)]
pub enum AssumeValid {
    /// Verify all scripts (equivalent to `--assumevalid=0`).
    Disabled,
    /// Skip script verification for blocks at or below the given hash.
    /// The hash must appear in the block index before skipping takes effect.
    Hash(BlockHash),
    /// Skip script verification for blocks older than a cutoff duration.
    /// satd extension (`--assumevalid=all`) — trusts the network for the existing
    /// chain but fully verifies recent and new blocks.
    /// The cutoff is controlled by `--assumevalidage` (default: 86400 seconds / 24 hours).
    All { max_age_secs: u64 },
}

/// Per-network default assumevalid hashes.
/// These are well-known blocks deep in the chain that the community has validated.
/// Matches Bitcoin Core's approach of shipping a default per release.
pub fn default_assumevalid(network: Network) -> AssumeValid {
    match network {
        Network::Bitcoin => {
            // Bitcoin Core v28.0 default (height 840,000)
            AssumeValid::Hash(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                    .parse()
                    .unwrap(),
            )
        }
        Network::Signet => {
            // Signet block at height 218,000 (before the heavy-tx region)
            AssumeValid::Hash(
                "000000f085851d46ad302bcc9246d00435ec24f2095fb9cfa9523837bbac1da3"
                    .parse()
                    .unwrap(),
            )
        }
        Network::Testnet => {
            // Testnet4 — no default yet
            AssumeValid::Disabled
        }
        Network::Regtest => {
            // Regtest has no meaningful default
            AssumeValid::Disabled
        }
        _ => AssumeValid::Disabled,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("duplicate")]
    Duplicate,
    #[error("bad-prevblk")]
    BadPrevBlock,
    #[error("Block decode failed")]
    DecodeFailed,
    #[error("checkpoint mismatch at height {0}")]
    CheckpointMismatch(u32),
    #[error("{0}")]
    Validation(#[from] validation::ValidationError),
    #[error("{0}")]
    Connect(#[from] connect::ConnectError),
    #[error("{0}")]
    Storage(#[from] StoreError),
    #[error("block file write failed: {0}")]
    FlatFile(String),
}

struct ChainTip {
    hash: BlockHash,
    height: u32,
}

/// Central chain state manager.
pub struct ChainState {
    store: Box<dyn Store>,
    flat_files: Mutex<FlatFileManager>,
    /// Path to the blocks directory, for mutex-free reads.
    blocks_dir: PathBuf,
    tip: RwLock<ChainTip>,
    pub network: Network,
    script_verifier: Box<dyn ScriptVerifier>,
    assumevalid: AssumeValid,
    checkpoints: Vec<Checkpoint>,
    /// Highest header height stored (may be ahead of connected block tip during IBD).
    headers_tip_height: AtomicU32,
}

impl ChainState {
    /// Create a new ChainState. If the store is empty, initializes with the genesis block.
    pub fn new(
        store: Box<dyn Store>,
        mut flat_files: FlatFileManager,
        network: Network,
        script_verifier: Box<dyn ScriptVerifier>,
        assumevalid: AssumeValid,
    ) -> Result<Self, ChainError> {
        let genesis = bitcoin::constants::genesis_block(network);
        let genesis_hash = genesis.block_hash();
        let blocks_dir = flat_files.blocks_dir().to_path_buf();

        let checkpoints = checkpoints::checkpoints_for_network(network);

        // Check if we have an existing tip
        if let Some(tip_hash) = store.get_tip()
            && let Some(entry) = store.get_block_index(&tip_hash) {
                // Scan forward from the block tip to find the highest stored header.
                // Headers may be ahead of blocks if we crashed during IBD.
                let mut htip = entry.height;
                while store.get_block_hash_by_height(htip + 1).is_some() {
                    htip += 1;
                }

                tracing::info!(
                    height = entry.height,
                    headers_tip = htip,
                    hash = %tip_hash,
                    "Loaded chain tip from storage"
                );
                return Ok(Self {
                    store,
                    flat_files: Mutex::new(flat_files),
                    blocks_dir,
                    tip: RwLock::new(ChainTip {
                        hash: tip_hash,
                        height: entry.height,
                    }),
                    network,
                    script_verifier,
                    assumevalid,
                    checkpoints,
                    headers_tip_height: AtomicU32::new(htip),
                });
            }

        // Fresh node: store genesis block
        tracing::info!("Initializing chain with genesis block");

        let block_data = serialize(&genesis);
        let flat_pos = flat_files
            .write_block(&block_data, network_magic(network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

        let parent_work = [0u8; 32];
        let noop = NoopVerifier; // Genesis has no scripts to verify
        let batch =
            connect::connect_block(&*store, &genesis, 0, &parent_work, flat_pos, &noop, 0)?;
        store.write_batch(batch)?;

        Ok(Self {
            store,
            flat_files: Mutex::new(flat_files),
            blocks_dir,
            tip: RwLock::new(ChainTip {
                hash: genesis_hash,
                height: 0,
            }),
            network,
            script_verifier,
            assumevalid,
            checkpoints,
            headers_tip_height: AtomicU32::new(0),
        })
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.tip.read().unwrap().hash
    }

    pub fn tip_height(&self) -> u32 {
        self.tip.read().unwrap().height
    }

    pub fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.store.get_block_index(hash)
    }

    pub fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.store.get_block_hash_by_height(height)
    }

    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.store.get_coin(outpoint)
    }

    /// Check if we have block data (not just a header) for a block.
    pub fn has_block_data(&self, hash: &BlockHash) -> bool {
        self.store
            .get_block_index(hash)
            .map(|e| matches!(e.status, BlockStatus::Valid | BlockStatus::DataStored))
            .unwrap_or(false)
    }

    /// Accept a block header without block data (for headers-first sync).
    /// Validates PoW and difficulty but does not process transactions.
    pub fn accept_header(&self, header: &bitcoin::block::Header) -> Result<BlockHash, ChainError> {
        let hash = header.block_hash();

        // Already known?
        if self.store.get_block_index(&hash).is_some() {
            return Err(ChainError::Duplicate);
        }

        // Parent must exist
        let parent = self
            .store
            .get_block_index(&header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;

        let new_height = parent.height + 1;

        // PoW validation
        validation::pow::check_proof_of_work(header)?;

        // Difficulty check
        validation::pow::check_difficulty(header, &parent, self.network, |h| {
            let hash = self.store.get_block_hash_by_height(h)?;
            self.store.get_block_index(&hash)
        })?;

        // Store as header-only
        let chainwork =
            crate::storage::blockindex::add_u256(&parent.chainwork, &crate::storage::blockindex::work_for_bits(header.bits));
        let entry = BlockIndexEntry {
            header: *header,
            height: new_height,
            status: BlockStatus::HeaderOnly,
            num_tx: 0,
            file_number: 0,
            data_pos: 0,
            chainwork,
        };

        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((new_height, hash));
        self.store.write_batch(batch)?;

        // Track highest header for locator construction
        self.headers_tip_height.fetch_max(new_height, Ordering::Relaxed);

        Ok(hash)
    }

    /// Get the highest header height stored (may be ahead of block tip during IBD).
    pub fn headers_tip_height(&self) -> u32 {
        self.headers_tip_height.load(Ordering::Relaxed)
    }

    /// Check if script verification should be skipped (assumevalid optimization).
    fn should_skip_scripts(&self, height: u32) -> bool {
        match &self.assumevalid {
            AssumeValid::Disabled => false,
            AssumeValid::Hash(av_hash) => {
                // Check if we've seen the assumevalid block in the index
                if let Some(entry) = self.store.get_block_index(av_hash) {
                    return height <= entry.height;
                }
                // Haven't seen it yet — might still be syncing headers.
                // Conservative: don't skip until we've confirmed the hash exists.
                false
            }
            AssumeValid::All { max_age_secs } => {
                // Skip scripts for blocks whose header timestamp is older than the cutoff.
                // This naturally transitions to full verification once the node catches up.
                if let Some(hash) = self.store.get_block_hash_by_height(height)
                    && let Some(entry) = self.store.get_block_index(&hash)
                {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let block_time = entry.header.time as u64;
                    return now.saturating_sub(block_time) > *max_age_secs;
                }
                false
            }
        }
    }

    /// Compute median time past (MTP) for a given height.
    /// MTP is the median of the timestamps of the previous 11 blocks.
    pub fn get_median_time_past(&self, height: u32) -> u32 {
        let start = height.saturating_sub(11);
        let mut timestamps: Vec<u32> = Vec::new();
        for h in start..height {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash) {
                    timestamps.push(entry.header.time);
                }
        }
        if timestamps.is_empty() {
            return 0;
        }
        timestamps.sort();
        timestamps[timestamps.len() / 2]
    }

    /// Get the total number of UTXOs in the set.
    pub fn coin_count(&self) -> u64 {
        self.store.coin_count()
    }

    /// Get the total amount (in satoshis) across all UTXOs.
    pub fn coin_total_amount(&self) -> u64 {
        self.store.coin_total_amount()
    }

    /// Access the script verifier (for mempool use).
    pub fn script_verifier(&self) -> &dyn ScriptVerifier {
        &*self.script_verifier
    }

    /// Read a full block from flat file storage.
    /// Look up which block contains a transaction (requires -txindex).
    pub fn get_tx_location(&self, txid: &bitcoin::Txid) -> Option<BlockHash> {
        self.store.get_tx_location(txid)
    }

    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        let entry = self.store.get_block_index(hash)?;
        if matches!(
            entry.status,
            BlockStatus::HeaderOnly | BlockStatus::Invalid | BlockStatus::Pruned
        ) {
            return None;
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let data = self.flat_files.lock().unwrap().read_block(&pos).ok()?;
        bitcoin::consensus::deserialize(&data).ok()
    }

    /// Read a block from flat files without acquiring the flat_files mutex.
    /// Safe because read_block() opens a fresh file handle each time.
    fn read_block_direct(&self, pos: &FlatFilePos) -> Option<Block> {
        let path = self.blocks_dir.join(format!("blk{:05}.dat", pos.file_number));
        let mut file = std::fs::File::open(&path).ok()?;
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(pos.data_pos as u64)).ok()?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header).ok()?;
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let mut data = vec![0u8; size];
        file.read_exact(&mut data).ok()?;
        bitcoin::consensus::deserialize(&data).ok()
    }

    /// Store block data to disk without connecting it to the chain.
    /// Used during parallel IBD: blocks arrive out of order and are stored
    /// immediately, then connected sequentially later.
    ///
    /// Returns `(block_hash, height)` on success.
    pub fn store_block(&self, block: &Block) -> Result<(BlockHash, u32), ChainError> {
        let block_hash = block.block_hash();

        // Check for duplicate — skip if already DataStored or Valid
        if let Some(existing) = self.store.get_block_index(&block_hash)
            && existing.status != BlockStatus::HeaderOnly
        {
            return Err(ChainError::Duplicate);
        }

        // Parent must exist as at least HeaderOnly
        let prev_hash = block.header.prev_blockhash;
        let parent = self
            .store
            .get_block_index(&prev_hash)
            .ok_or(ChainError::BadPrevBlock)?;

        let new_height = parent.height + 1;

        // Context-free block validation
        validation::block::check_block(block)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(&block.header, &parent, self.network, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Checkpoint validation
        if !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints) {
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file
        let block_data = serialize(block);
        let flat_pos = self
            .flat_files
            .lock()
            .unwrap()
            .write_block(&block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

        // Store block index entry as DataStored
        let chainwork = add_u256(&parent.chainwork, &work_for_bits(block.header.bits));
        let entry = BlockIndexEntry {
            header: block.header,
            height: new_height,
            status: BlockStatus::DataStored,
            num_tx: block.txdata.len() as u32,
            file_number: flat_pos.file_number,
            data_pos: flat_pos.data_pos,
            chainwork,
        };

        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((block_hash, entry));
        // Don't write height_hash_puts here — accept_header already did that
        self.store.write_batch(batch)?;

        Ok((block_hash, new_height))
    }

    /// Connect an already-stored block (DataStored) to the chain tip.
    /// The block's parent must be the current chain tip.
    ///
    /// Returns the block hash on success.
    pub fn connect_stored_block(&self, hash: &BlockHash) -> Result<BlockHash, ChainError> {
        let entry = self
            .store
            .get_block_index(hash)
            .ok_or(ChainError::BadPrevBlock)?;

        if entry.status != BlockStatus::DataStored {
            return Err(ChainError::Duplicate);
        }

        // Parent must be current tip (sequential connection)
        let current_tip = self.tip_hash();
        if entry.header.prev_blockhash != current_tip {
            return Err(ChainError::BadPrevBlock);
        }

        // Read block from flat file (mutex-free)
        let flat_pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let block = self
            .read_block_direct(&flat_pos)
            .ok_or(ChainError::FlatFile("failed to read stored block".to_string()))?;

        let parent = self
            .store
            .get_block_index(&entry.header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;

        // Determine script verifier
        let use_noop = self.should_skip_scripts(entry.height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };

        // Connect block
        let mtp = self.get_median_time_past(entry.height);
        let batch = connect::connect_block(
            &*self.store,
            &block,
            entry.height,
            &parent.chainwork,
            flat_pos,
            verifier,
            mtp,
        )?;

        // Atomic commit
        self.store.write_batch(batch)?;

        // Update in-memory tip
        {
            let mut tip = self.tip.write().unwrap();
            tip.hash = *hash;
            tip.height = entry.height;
        }

        Ok(*hash)
    }

    /// Accept a new block into the chain.
    pub fn accept_block(&self, block: &Block) -> Result<BlockHash, ChainError> {
        let block_hash = block.block_hash();

        // Check for duplicate (HeaderOnly entries are OK — we're now providing data)
        if let Some(existing) = self.store.get_block_index(&block_hash)
            && existing.status != BlockStatus::HeaderOnly {
                return Err(ChainError::Duplicate);
            }

        // Find parent
        let prev_hash = block.header.prev_blockhash;
        let parent = self
            .store
            .get_block_index(&prev_hash)
            .ok_or(ChainError::BadPrevBlock)?;

        let new_height = parent.height + 1;

        // Context-free block validation
        validation::block::check_block(block)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(&block.header, &parent, self.network, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Timestamp check (median time past)
        validation::pow::check_timestamp(&block.header, new_height, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Checkpoint validation
        if !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints) {
            tracing::warn!(
                height = new_height,
                hash = %block_hash,
                "Block rejected: checkpoint mismatch"
            );
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file
        let block_data = serialize(block);
        let flat_pos = self
            .flat_files
            .lock()
            .unwrap()
            .write_block(&block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

        // Check if this extends the current tip or is a side chain
        let current_tip = self.tip_hash();
        let new_chainwork = add_u256(&parent.chainwork, &work_for_bits(block.header.bits));

        if prev_hash != current_tip {
            // Side chain block — store it first
            let entry = BlockIndexEntry {
                header: block.header,
                height: new_height,
                status: BlockStatus::DataStored,
                num_tx: block.txdata.len() as u32,
                file_number: flat_pos.file_number,
                data_pos: flat_pos.data_pos,
                chainwork: new_chainwork,
            };
            let mut batch = crate::storage::StoreBatch::default();
            batch.block_index_puts.push((block_hash, entry.clone()));
            self.store.write_batch(batch)?;

            // Check if this side chain now has more work than the current tip
            let tip_entry = self.store.get_block_index(&current_tip)
                .ok_or(ChainError::BadPrevBlock)?;
            if compare_u256(&new_chainwork, &tip_entry.chainwork) <= 0 {
                // Side chain has less or equal work — don't reorg
                return Ok(block_hash);
            }

            // During IBD, if the side chain is far ahead of our tip, don't attempt
            // reorg — the intermediate blocks will arrive and connect in order.
            // This avoids expensive failed reorg attempts when blocks arrive
            // out of order from multiple peers.
            if new_height > tip_entry.height + 128 {
                return Ok(block_hash);
            }

            // Side chain has more work — find fork point and reorg
            tracing::info!(
                new_height,
                old_tip_height = tip_entry.height,
                "Reorg: side chain has more work, activating"
            );

            // Walk back from the side chain block to find the fork point
            let fork_entry = {
                let mut side_hash = prev_hash;
                loop {
                    let side_entry = self.store.get_block_index(&side_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    // Fork point is a block that's on the main chain (Valid status)
                    if side_entry.status == BlockStatus::Valid {
                        break side_entry;
                    }
                    side_hash = side_entry.header.prev_blockhash;
                }
            };

            // Disconnect blocks from current tip down to fork point
            self.perform_reorg(&fork_entry, current_tip)?;

            // Now connect the side chain blocks from fork point up to (but not including)
            // the new block. Collect them first since we need to connect in forward order.
            let mut to_connect = Vec::new();
            {
                let mut hash = prev_hash;
                let fork_hash = fork_entry.header.block_hash();
                while hash != fork_hash {
                    to_connect.push(hash);
                    let e = self.store.get_block_index(&hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    hash = e.header.prev_blockhash;
                }
                to_connect.reverse();
            }
            for side_hash in &to_connect {
                let side_block = self.get_block(side_hash)
                    .ok_or(ChainError::FlatFile("block data missing for reorg connect".to_string()))?;
                let side_entry = self.store.get_block_index(side_hash)
                    .ok_or(ChainError::BadPrevBlock)?;
                let parent_entry = self.store.get_block_index(&side_entry.header.prev_blockhash)
                    .ok_or(ChainError::BadPrevBlock)?;
                let use_noop = self.should_skip_scripts(side_entry.height);
                let noop = NoopVerifier;
                let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };
                let mtp = self.get_median_time_past(side_entry.height);
                let side_flat_pos = FlatFilePos {
                    file_number: side_entry.file_number,
                    data_pos: side_entry.data_pos,
                };
                let batch = connect::connect_block(
                    &*self.store, &side_block, side_entry.height,
                    &parent_entry.chainwork, side_flat_pos, verifier, mtp,
                )?;
                self.store.write_batch(batch)?;
                {
                    let mut tip = self.tip.write().unwrap();
                    tip.hash = *side_hash;
                    tip.height = side_entry.height;
                }
                tracing::info!(height = side_entry.height, hash = %side_hash, "Reorg: block connected");
            }

            // Fall through to connect the new block as a tip-extending block
        }

        // Determine script verifier: skip if below assumevalid height
        let use_noop = self.should_skip_scripts(new_height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };

        // Connect block (process transactions, update UTXOs, verify scripts)
        let mtp = self.get_median_time_past(new_height);
        let batch = connect::connect_block(
            &*self.store,
            block,
            new_height,
            &parent.chainwork,
            flat_pos,
            verifier,
            mtp,
        )?;

        // Atomic commit
        self.store.write_batch(batch)?;

        // Update in-memory tip
        {
            let mut tip = self.tip.write().unwrap();
            tip.hash = block_hash;
            tip.height = new_height;
        }

        tracing::info!(
            height = new_height,
            hash = %block_hash,
            txs = block.txdata.len(),
            "Block connected"
        );

        Ok(block_hash)
    }

    /// Disconnect blocks from current tip down to the fork point (parent of the new chain).
    /// All disconnections are batched into a single atomic write.
    fn perform_reorg(&self, fork_entry: &BlockIndexEntry, old_tip: BlockHash) -> Result<(), ChainError> {
        let fork_hash = fork_entry.header.block_hash();
        let mut current = old_tip;
        let mut combined_batch = crate::storage::StoreBatch::default();

        // Walk back from old tip to fork point, accumulating disconnect batches
        loop {
            if current == fork_hash {
                break;
            }

            let entry = self.store.get_block_index(&current)
                .ok_or(ChainError::BadPrevBlock)?;

            let block = self.get_block(&current)
                .ok_or(ChainError::FlatFile("block data missing for reorg".to_string()))?;

            let undo = self.store.get_undo(&current)
                .ok_or(ChainError::FlatFile("undo data missing for reorg".to_string()))?;

            let prev_hash = entry.header.prev_blockhash;
            let batch = disconnect::disconnect_block(&block, &undo, entry.height, prev_hash);
            combined_batch.merge(batch);

            tracing::info!(height = entry.height, hash = %current, "Block disconnected");
            current = prev_hash;
        }

        // Atomic commit of all disconnections
        self.store.write_batch(combined_batch)?;

        // Update in-memory tip to fork point
        {
            let mut tip = self.tip.write().unwrap();
            tip.hash = fork_hash;
            tip.height = fork_entry.height;
        }

        Ok(())
    }
    /// Prune old block data files whose blocks are deep enough in the chain.
    /// `keep_blocks` is the number of recent blocks to keep data for.
    /// Returns the number of files deleted.
    pub fn prune_blocks(&self, keep_blocks: u32) -> u32 {
        let tip_height = self.tip_height();
        if tip_height <= keep_blocks {
            return 0;
        }
        let prune_below = tip_height - keep_blocks;

        // Collect file_numbers used by pruneable blocks (height <= prune_below)
        let mut pruneable_files: std::collections::HashMap<u32, Vec<(BlockHash, u32)>> =
            std::collections::HashMap::new();
        for h in 0..=prune_below {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash)
                && entry.status == BlockStatus::Valid
            {
                pruneable_files
                    .entry(entry.file_number)
                    .or_default()
                    .push((hash, h));
            }
        }

        // Collect file_numbers used by recent blocks (must NOT be deleted)
        let mut keep_files: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for h in (prune_below + 1)..=tip_height {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash)
            {
                keep_files.insert(entry.file_number);
            }
        }

        let mut deleted = 0u32;
        let flat_files = self.flat_files.lock().unwrap();
        let mut batch = crate::storage::StoreBatch::default();

        for (file_num, blocks) in &pruneable_files {
            // Only delete files that have NO recent blocks in them
            if keep_files.contains(file_num) {
                continue;
            }
            // Only delete if the file actually exists (not already pruned)
            if !flat_files.file_exists(*file_num) {
                continue;
            }
            if let Err(e) = flat_files.delete_file(*file_num) {
                tracing::warn!(file = file_num, "Failed to delete block file: {}", e);
                continue;
            }
            // Mark all blocks in this file as Pruned
            for (hash, height) in blocks {
                if let Some(mut entry) = self.store.get_block_index(hash) {
                    entry.status = BlockStatus::Pruned;
                    batch.block_index_puts.push((*hash, entry));
                }
                tracing::debug!(file = file_num, height, "Block data pruned");
            }
            deleted += 1;
            tracing::info!(file = file_num, "Deleted block file");
        }
        drop(flat_files);

        if !batch.block_index_puts.is_empty()
            && let Err(e) = self.store.write_batch(batch)
        {
            tracing::error!("Failed to update block index after pruning: {}", e);
        }

        deleted
    }

    /// Check if a block has been pruned.
    pub fn is_pruned(&self, hash: &BlockHash) -> bool {
        self.store
            .get_block_index(hash)
            .map(|e| e.status == BlockStatus::Pruned)
            .unwrap_or(false)
    }
}

/// Compare two big-endian U256 values. Returns -1, 0, or 1.
fn compare_u256(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] > b[i] {
            return 1;
        }
        if a[i] < b[i] {
            return -1;
        }
    }
    0
}

/// Get the network magic bytes for flat file headers.
fn network_magic(network: Network) -> [u8; 4] {
    match network {
        Network::Bitcoin => [0xf9, 0xbe, 0xb4, 0xd9],
        Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
        Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
        Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        _ => [0xf9, 0xbe, 0xb4, 0xd9],
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;

    pub(crate) fn make_chain_state() -> (ChainState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-chain-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
        )
        .unwrap();
        (cs, dir)
    }

    #[test]
    fn test_genesis_initialization() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);

        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip_hash(), genesis.block_hash());

        let entry = cs.get_block_index(&genesis.block_hash()).unwrap();
        assert_eq!(entry.height, 0);
        assert_eq!(entry.status, BlockStatus::Valid);

        let read_back = cs.get_block(&genesis.block_hash()).unwrap();
        assert_eq!(read_back.block_hash(), genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_duplicate_rejection() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);

        let result = cs.accept_block(&genesis);
        assert!(matches!(result, Err(ChainError::Duplicate)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a valid regtest block at the given height with the given parent hash and timestamp.
    pub(crate) fn build_test_block(parent_hash: BlockHash, height: u32, time: u32) -> Block {
        use bitcoin::block::Header;
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::pow::CompactTarget;
        use bitcoin::transaction;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        let bits = CompactTarget::from_consensus(0x207fffff);

        // BIP 34 coinbase scriptSig: push height, then push the timestamp
        // as extra nonce to ensure each block's coinbase has a unique txid.
        let height_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_int(time as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();

        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: height_script,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let coinbase_output = TxOut {
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: ScriptBuf::new(),
        };

        let coinbase_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: vec![coinbase_output],
        };

        let txdata = vec![coinbase_tx];

        // Build block with a dummy merkle root first, then compute the real one
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x20000000),
                prev_blockhash: parent_hash,
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                ),
                time,
                bits,
                nonce: 0,
            },
            txdata,
        };

        // Set the real merkle root
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        // Mine: find a nonce whose hash satisfies PoW for 0x207fffff
        let target = crate::storage::blockindex::target_from_compact(bits);
        for nonce in 0u32..1_000_000 {
            block.header.nonce = nonce;
            let hash_bytes = *block.block_hash().as_raw_hash().as_byte_array();
            // Block hash is displayed as little-endian but the byte array from
            // to_byte_array() is the internal representation. For comparison with
            // a big-endian target we need to reverse it.
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_bytes[31 - i];
            }
            // hash_be <= target means PoW satisfied
            let mut ok = true;
            for i in 0..32 {
                if hash_be[i] < target[i] {
                    break;
                }
                if hash_be[i] > target[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return block;
            }
        }
        panic!("Failed to mine test block within 1,000,000 nonce iterations");
    }

    #[test]
    fn test_reorg_longer_chain_wins() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();
        assert_eq!(cs.tip_height(), 0);

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");

        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");

        assert_eq!(cs.tip_hash(), a2_hash);
        assert_eq!(cs.tip_height(), 2);

        // Build chain B: genesis -> B1 -> B2 -> B3 (different timestamps => different hashes)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        // B1 is a side chain block; tip should still be A2
        assert_eq!(cs.tip_hash(), a2_hash);

        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        // Equal work (2 blocks each); no reorg
        assert_eq!(cs.tip_hash(), a2_hash);

        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");
        // B chain now has more work => reorg
        assert_eq!(cs.tip_hash(), b3_hash);
        assert_eq!(cs.tip_height(), 3);

        assert_eq!(cs.get_block_hash_by_height(1), Some(b1_hash));
        assert_eq!(cs.get_block_hash_by_height(2), Some(b2_hash));
        assert_eq!(cs.get_block_hash_by_height(3), Some(b3_hash));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_shorter_chain_no_switch() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2 -> A3
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        let a3 = build_test_block(a2_hash, 3, 1_300_000_003);
        let a3_hash = cs.accept_block(&a3).expect("accept A3");

        assert_eq!(cs.tip_hash(), a3_hash);
        assert_eq!(cs.tip_height(), 3);

        // Submit B1 forking from genesis (shorter chain, less work)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        cs.accept_block(&b1).expect("accept B1");

        // Tip should remain A3
        assert_eq!(cs.tip_hash(), a3_hash);
        assert_eq!(cs.tip_height(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_equal_work_no_switch() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        assert_eq!(cs.tip_hash(), a1_hash);

        // Submit B1 forking from genesis (equal work)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        cs.accept_block(&b1).expect("accept B1");

        // Tip should remain A1 (equal work => no switch)
        assert_eq!(cs.tip_hash(), a1_hash);
        assert_eq!(cs.tip_height(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_utxo_consistency() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a1_coinbase_txid = a1.txdata[0].compute_txid();

        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        cs.accept_block(&a2).expect("accept A2");
        let a2_coinbase_txid = a2.txdata[0].compute_txid();

        // Verify A-chain UTXOs exist before reorg
        let a1_cb_op = OutPoint { txid: a1_coinbase_txid, vout: 0 };
        let a2_cb_op = OutPoint { txid: a2_coinbase_txid, vout: 0 };
        assert!(cs.get_coin(&a1_cb_op).is_some());
        assert!(cs.get_coin(&a2_cb_op).is_some());

        // Build chain B: genesis -> B1 -> B2 -> B3 (more work => triggers reorg)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b1_coinbase_txid = b1.txdata[0].compute_txid();

        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b2_coinbase_txid = b2.txdata[0].compute_txid();

        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        cs.accept_block(&b3).expect("accept B3");
        let b3_coinbase_txid = b3.txdata[0].compute_txid();

        // Reorg should have happened — tip is B3
        assert_eq!(cs.tip_height(), 3, "tip should be at height 3 after reorg");
        assert_eq!(cs.tip_hash(), b3.block_hash(), "tip should be B3");

        // After reorg: A-chain coinbase UTXOs must NOT exist
        assert!(
            cs.get_coin(&OutPoint { txid: a1_coinbase_txid, vout: 0 }).is_none(),
            "A1 coinbase UTXO should not exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: a2_coinbase_txid, vout: 0 }).is_none(),
            "A2 coinbase UTXO should not exist after reorg"
        );

        // B-chain coinbase UTXOs must exist
        assert!(
            cs.get_coin(&OutPoint { txid: b1_coinbase_txid, vout: 0 }).is_some(),
            "B1 coinbase UTXO should exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: b2_coinbase_txid, vout: 0 }).is_some(),
            "B2 coinbase UTXO should exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: b3_coinbase_txid, vout: 0 }).is_some(),
            "B3 coinbase UTXO should exist after reorg"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_checkpoint_mismatch_rejected() {
        // Build a ChainState with a fake checkpoint at height 1 that won't match
        use crate::chain::checkpoints::Checkpoint;

        let dir = std::env::temp_dir().join(format!(
            "satd-checkpoint-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let mut cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
        )
        .unwrap();

        // Inject a fake checkpoint at height 1 with an impossible hash
        let fake_hash: BlockHash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        cs.checkpoints = vec![Checkpoint { height: 1, hash: fake_hash }];

        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let result = cs.accept_block(&block1);
        assert!(
            matches!(result, Err(ChainError::CheckpointMismatch(1))),
            "Block at checkpoint height with wrong hash should be rejected, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_blocks() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a chain of 5 blocks
        let mut parent = genesis_hash;
        let mut hashes = vec![genesis_hash];
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).unwrap_or_else(|_| panic!("accept block {}", i));
            hashes.push(parent);
        }
        assert_eq!(cs.tip_height(), 5);

        // Verify we can read all blocks
        for h in &hashes {
            assert!(cs.get_block(h).is_some(), "block should be readable");
        }

        // Prune keeping only the last 2 blocks (blocks 4 and 5 kept, 0-3 pruned)
        let deleted = cs.prune_blocks(2);
        // All blocks are in file 0, and blocks 4,5 are also in file 0,
        // so the file should NOT be deleted (contains recent blocks too)
        // This tests the safety check.
        assert_eq!(deleted, 0, "Should not delete file containing recent blocks");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pruned_block_returns_none() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a single block
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash1 = cs.accept_block(&block1).unwrap();

        // Manually mark it as pruned
        let mut entry = cs.get_block_index(&hash1).unwrap();
        entry.status = BlockStatus::Pruned;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash1, entry));
        cs.store.write_batch(batch).unwrap();

        // get_block should return None for pruned blocks
        assert!(cs.get_block(&hash1).is_none());
        assert!(cs.is_pruned(&hash1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_block_creates_data_stored() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // First, accept the header so the block's parent chain is known
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();

        // Store the block without connecting
        let (hash, height) = cs.store_block(&block1).unwrap();
        assert_eq!(hash, block1.block_hash());
        assert_eq!(height, 1);

        // Verify it's DataStored, not Valid
        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(entry.status, BlockStatus::DataStored);
        assert_eq!(entry.height, 1);

        // Tip should still be genesis (not connected)
        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip_hash(), genesis_hash);

        // Block data should be readable from flat file
        assert!(cs.has_block_data(&hash));
        assert!(cs.get_block(&hash).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        let (hash, _) = cs.store_block(&block1).unwrap();

        // Connect the stored block
        let connected_hash = cs.connect_stored_block(&hash).unwrap();
        assert_eq!(connected_hash, hash);

        // Tip should now be at height 1
        assert_eq!(cs.tip_height(), 1);
        assert_eq!(cs.tip_hash(), hash);

        // Entry should be Valid now
        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(entry.status, BlockStatus::Valid);

        // Coinbase UTXO should exist
        let coinbase_txid = block1.txdata[0].compute_txid();
        assert!(cs.get_coin(&OutPoint { txid: coinbase_txid, vout: 0 }).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block_wrong_order() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Create blocks 1 and 2
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let block1_hash = block1.block_hash();
        cs.accept_header(&block1.header).unwrap();
        let (_, _) = cs.store_block(&block1).unwrap();

        let block2 = build_test_block(block1_hash, 2, 1_300_000_002);
        cs.accept_header(&block2.header).unwrap();
        let (hash2, _) = cs.store_block(&block2).unwrap();

        // Try to connect block 2 before block 1 — should fail
        let result = cs.connect_stored_block(&hash2);
        assert!(
            matches!(result, Err(ChainError::BadPrevBlock)),
            "Connecting height 2 before 1 should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_block_duplicate() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        cs.store_block(&block1).unwrap();

        // Store same block again — should be Duplicate
        let result = cs.store_block(&block1);
        assert!(
            matches!(result, Err(ChainError::Duplicate)),
            "Storing same block twice should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_creates_header_only() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash = cs.accept_header(&block1.header).unwrap();

        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(
            entry.status,
            BlockStatus::HeaderOnly,
            "accept_header should create HeaderOnly entry"
        );
        assert_eq!(entry.height, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_requires_parent() {
        let (cs, dir) = make_chain_state();

        // Build a header whose prev_blockhash is unknown
        let fake_parent: BlockHash = "0000000000000000000000000000000000000000000000000000000000abcdef"
            .parse()
            .unwrap();
        let block = build_test_block(fake_parent, 1, 1_300_000_001);

        let result = cs.accept_header(&block.header);
        assert!(
            matches!(result, Err(ChainError::BadPrevBlock)),
            "accept_header with unknown parent should return BadPrevBlock, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_duplicate_returns_duplicate() {
        // accept_header returns Err(Duplicate) for already-known headers
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        let result = cs.accept_header(&block1.header);

        assert!(
            matches!(result, Err(ChainError::Duplicate)),
            "Duplicate accept_header should return Err(Duplicate), got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_bad_pow() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a valid test block, then corrupt its nonce so PoW is invalid
        let mut block = build_test_block(genesis_hash, 1, 1_300_000_001);
        // Set bits to mainnet difficulty (extremely hard) — the hash won't meet it
        block.header.bits = bitcoin::pow::CompactTarget::from_consensus(0x1d00ffff);

        let result = cs.accept_header(&block.header);
        // This should fail either on PoW check or difficulty check (regtest expects 0x207fffff)
        assert!(
            result.is_err(),
            "accept_header with bad PoW/difficulty should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_updates_headers_tip() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        assert_eq!(cs.headers_tip_height(), 0, "Initial headers_tip should be 0");

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash1 = cs.accept_header(&block1.header).unwrap();

        assert_eq!(
            cs.headers_tip_height(),
            1,
            "headers_tip_height should be 1 after accepting header at height 1"
        );

        let block2 = build_test_block(hash1, 2, 1_300_000_002);
        cs.accept_header(&block2.header).unwrap();

        assert_eq!(
            cs.headers_tip_height(),
            2,
            "headers_tip_height should be 2 after accepting header at height 2"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_should_skip_scripts_disabled() {
        let (cs, dir) = make_chain_state();
        // make_chain_state creates with AssumeValid::Disabled
        assert!(
            !cs.should_skip_scripts(0),
            "should_skip_scripts should be false at height 0 with Disabled"
        );
        assert!(
            !cs.should_skip_scripts(100),
            "should_skip_scripts should be false at height 100 with Disabled"
        );
        assert!(
            !cs.should_skip_scripts(1_000_000),
            "should_skip_scripts should be false at height 1M with Disabled"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_should_skip_scripts_hash() {
        // Create a ChainState with AssumeValid::Hash pointing to a block we'll connect.
        let dir = std::env::temp_dir().join(format!(
            "satd-av-hash-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();

        // First build the chain to find the block hash
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let block1_hash = block1.block_hash();

        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Hash(block1_hash),
        )
        .unwrap();

        // Before accepting the block, should_skip_scripts returns false
        // (hash not yet in index)
        assert!(
            !cs.should_skip_scripts(0),
            "Before block is known, should not skip scripts"
        );

        // Accept the block (connects it, adding to index)
        cs.accept_block(&block1).unwrap();

        // Now the hash is in the index at height 1
        // Height <= 1 should skip scripts
        assert!(
            cs.should_skip_scripts(0),
            "Height 0 <= 1, should skip scripts"
        );
        assert!(
            cs.should_skip_scripts(1),
            "Height 1 <= 1, should skip scripts"
        );
        // Height > 1 should NOT skip scripts
        assert!(
            !cs.should_skip_scripts(2),
            "Height 2 > 1, should not skip scripts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_median_time_past_short_chain() {
        // Build a chain shorter than 11 blocks and verify MTP uses available blocks.
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Build 3 blocks with known timestamps.
        // t3 is between t1 and t2 (out of chronological order) to test sorting.
        // All must be above MTP at their respective heights to pass timestamp validation.
        let t1 = 1_300_000_100;
        let t2 = 1_300_000_200;
        let t3 = 1_300_000_150; // Out of order vs t2 to test sorting

        let b1 = build_test_block(genesis_hash, 1, t1);
        let h1 = cs.accept_block(&b1).unwrap();

        let b2 = build_test_block(h1, 2, t2);
        let h2 = cs.accept_block(&b2).unwrap();

        let b3 = build_test_block(h2, 3, t3);
        cs.accept_block(&b3).unwrap();

        // MTP at height 4 uses blocks at heights max(0, 4-11)..4 = 0..4
        // Timestamps: genesis.time, t1, t2, t3
        // genesis.time for regtest = 1296688602
        // Sorted: [1296688602, 1_300_000_100, 1_300_000_150, 1_300_000_200]
        // Median of 4 elements = element at index 2 = 1_300_000_150
        let mtp = cs.get_median_time_past(4);
        let genesis_time = genesis.header.time;
        let mut timestamps = [genesis_time, t1, t2, t3];
        timestamps.sort();
        let expected_median = timestamps[timestamps.len() / 2];
        assert_eq!(
            mtp, expected_median,
            "MTP should be the median of available block timestamps"
        );

        // Also verify MTP at height 1 (only genesis block)
        let mtp_1 = cs.get_median_time_past(1);
        assert_eq!(mtp_1, genesis_time, "MTP at height 1 should be genesis time");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
