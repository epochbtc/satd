use bitcoin::consensus::serialize;
use bitcoin::{Block, BlockHash, Network, OutPoint};
use std::sync::{Mutex, RwLock};

use crate::chain::{connect, disconnect};
use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
use crate::storage::coinview::Coin;
use crate::storage::flatfile::{FlatFileManager, FlatFilePos};
use crate::storage::{Store, StoreError};
use crate::validation;
use crate::validation::script::{NoopVerifier, ScriptVerifier};

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("duplicate")]
    Duplicate,
    #[error("bad-prevblk")]
    BadPrevBlock,
    #[error("Block decode failed")]
    DecodeFailed,
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
    tip: RwLock<ChainTip>,
    pub network: Network,
    script_verifier: Box<dyn ScriptVerifier>,
    assumevalid: Option<BlockHash>,
}

impl ChainState {
    /// Create a new ChainState. If the store is empty, initializes with the genesis block.
    pub fn new(
        store: Box<dyn Store>,
        mut flat_files: FlatFileManager,
        network: Network,
        script_verifier: Box<dyn ScriptVerifier>,
        assumevalid: Option<BlockHash>,
    ) -> Result<Self, ChainError> {
        let genesis = bitcoin::constants::genesis_block(network);
        let genesis_hash = genesis.block_hash();

        // Check if we have an existing tip
        if let Some(tip_hash) = store.get_tip() {
            if let Some(entry) = store.get_block_index(&tip_hash) {
                tracing::info!(
                    height = entry.height,
                    hash = %tip_hash,
                    "Loaded chain tip from storage"
                );
                return Ok(Self {
                    store,
                    flat_files: Mutex::new(flat_files),
                    tip: RwLock::new(ChainTip {
                        hash: tip_hash,
                        height: entry.height,
                    }),
                    network,
                    script_verifier,
                    assumevalid,
                });
            }
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
            tip: RwLock::new(ChainTip {
                hash: genesis_hash,
                height: 0,
            }),
            network,
            script_verifier,
            assumevalid,
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
            .map(|e| e.status == BlockStatus::Valid || e.status == BlockStatus::DataStored)
            .unwrap_or(false)
    }

    /// Accept a block header without block data (for headers-first sync).
    /// Validates PoW and difficulty but does not process transactions.
    pub fn accept_header(&self, header: &bitcoin::block::Header) -> Result<BlockHash, ChainError> {
        let hash = header.block_hash();

        // Already known?
        if self.store.get_block_index(&hash).is_some() {
            return Ok(hash);
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

        Ok(hash)
    }

    /// Check if script verification should be skipped (assumevalid optimization).
    fn should_skip_scripts(&self, height: u32) -> bool {
        if let Some(ref av_hash) = self.assumevalid {
            // Check if we've seen the assumevalid block in the index
            if let Some(entry) = self.store.get_block_index(av_hash) {
                return height <= entry.height;
            }
            // Haven't seen it yet — might still be syncing headers
            // Conservative: don't skip until we've confirmed the hash exists
        }
        false
    }

    /// Compute median time past (MTP) for a given height.
    /// MTP is the median of the timestamps of the previous 11 blocks.
    pub fn get_median_time_past(&self, height: u32) -> u32 {
        let start = if height > 11 { height - 11 } else { 0 };
        let mut timestamps: Vec<u32> = Vec::new();
        for h in start..height {
            if let Some(hash) = self.store.get_block_hash_by_height(h) {
                if let Some(entry) = self.store.get_block_index(&hash) {
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

    /// Get the total number of UTXOs in the set.
    pub fn coin_count(&self) -> u64 {
        self.store.coin_count()
    }

    /// Access the script verifier (for mempool use).
    pub fn script_verifier(&self) -> &dyn ScriptVerifier {
        &*self.script_verifier
    }

    /// Read a full block from flat file storage.
    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        let entry = self.store.get_block_index(hash)?;
        if entry.status == BlockStatus::HeaderOnly || entry.status == BlockStatus::Invalid {
            return None;
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let data = self.flat_files.lock().unwrap().read_block(&pos).ok()?;
        bitcoin::consensus::deserialize(&data).ok()
    }

    /// Accept a new block into the chain.
    pub fn accept_block(&self, block: &Block) -> Result<BlockHash, ChainError> {
        let block_hash = block.block_hash();

        // Check for duplicate
        if self.store.get_block_index(&block_hash).is_some() {
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
            // Side chain block — check if it has more work
            let tip_entry = self.store.get_block_index(&current_tip).unwrap();
            if compare_u256(&new_chainwork, &tip_entry.chainwork) <= 0 {
                // Less or equal work — store but don't activate
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
                batch.block_index_puts.push((block_hash, entry));
                self.store.write_batch(batch)?;
                tracing::info!(
                    height = new_height,
                    hash = %block_hash,
                    "Side chain block stored (not activated)"
                );
                return Ok(block_hash);
            }

            // More work — perform reorg
            tracing::info!(
                old_tip = %current_tip,
                new_tip = %block_hash,
                "Reorganizing to longer chain"
            );
            self.perform_reorg(&parent, current_tip)?;
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
        Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        _ => [0xf9, 0xbe, 0xb4, 0xd9],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;

    fn make_chain_state() -> (ChainState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "btcd-chain-test-{}-{}",
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
            None,
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
}
