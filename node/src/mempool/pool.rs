use bitcoin::{Block, OutPoint, Transaction, TxOut, Txid};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::chain::state::ChainState;
use crate::mempool::policy::MAX_STANDARD_TX_WEIGHT;
use crate::validation::script::ScriptVerifier;
use crate::validation::tx::check_transaction;

/// Coinbase maturity: outputs cannot be spent until this many confirmations.
const COINBASE_MATURITY: u32 = 100;

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("txn-already-in-mempool")]
    AlreadyExists,
    #[error("txn-mempool-conflict")]
    ConflictingSpend,
    #[error("bad-txns-inputs-missingorspent")]
    MissingInputs,
    #[error("min relay fee not met. {0} < {1}")]
    InsufficientFee(u64, u64),
    #[error("mempool full")]
    MempoolFull,
    #[error("{0}")]
    Validation(String),
    #[error("mandatory-script-verify-flag-failed ({0})")]
    Script(String),
    #[error("bad-txns-in-belowout")]
    BadAmounts,
    #[error("bad-txns-premature-spend-of-coinbase")]
    PrematureCoinbaseSpend,
    #[error("TX decode failed")]
    DecodeFailed,
}

/// Metadata for a transaction in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub fee: u64,
    pub weight: usize,
    pub fee_rate: u64,
    pub time: u64,
}

/// Statistics about the mempool.
#[derive(Debug, Clone)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
    pub max_size: usize,
    pub min_fee_rate: u64,
}

struct MempoolInner {
    entries: HashMap<Txid, MempoolEntry>,
    spends: HashMap<OutPoint, Txid>,
    total_bytes: usize,
}

/// In-memory transaction pool.
pub struct Mempool {
    inner: RwLock<MempoolInner>,
    max_size_bytes: usize,
    min_fee_rate: u64,
}

impl Mempool {
    pub fn new(max_size_bytes: usize, min_fee_rate: u64) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                entries: HashMap::new(),
                spends: HashMap::new(),
                total_bytes: 0,
            }),
            max_size_bytes,
            min_fee_rate,
        }
    }

    /// Accept a transaction into the mempool after full validation.
    pub fn accept_transaction(
        &self,
        tx: Transaction,
        chain_state: &ChainState,
        script_verifier: &dyn ScriptVerifier,
    ) -> Result<Txid, MempoolError> {
        let txid = tx.compute_txid();

        // Context-free checks
        check_transaction(&tx).map_err(|e| MempoolError::Validation(e.to_string()))?;

        // Must not be coinbase
        if tx.is_coinbase() {
            return Err(MempoolError::Validation(
                "coinbase not accepted in mempool".to_string(),
            ));
        }

        // Policy: check weight
        let weight = tx.weight().to_wu() as usize;
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolError::Validation("tx-size".to_string()));
        }

        let tx_size = bitcoin::consensus::serialize(&tx).len();

        // Take write lock for the rest (prevents TOCTOU races)
        let mut inner = self.inner.write().unwrap();

        // Check not already in mempool
        if inner.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }

        // Check for conflicting spends
        for input in &tx.input {
            if inner.spends.contains_key(&input.previous_output) {
                return Err(MempoolError::ConflictingSpend);
            }
        }

        // Look up UTXOs and validate inputs
        let tip_height = chain_state.tip_height();
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();

        for input in &tx.input {
            let coin = chain_state
                .get_coin(&input.previous_output)
                .ok_or(MempoolError::MissingInputs)?;

            // Check coinbase maturity
            if coin.coinbase && tip_height - coin.height < COINBASE_MATURITY {
                return Err(MempoolError::PrematureCoinbaseSpend);
            }

            sum_inputs += coin.amount;
            prev_outputs.push(TxOut {
                value: bitcoin::Amount::from_sat(coin.amount),
                script_pubkey: coin.script_pubkey.clone(),
            });
        }

        // Check amounts
        let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if sum_inputs < sum_outputs {
            return Err(MempoolError::BadAmounts);
        }

        let fee = sum_inputs - sum_outputs;

        // Check fee rate (sat per 1000 weight units)
        let fee_rate = if weight > 0 {
            fee * 1000 / weight as u64
        } else {
            0
        };
        if fee_rate < self.min_fee_rate {
            return Err(MempoolError::InsufficientFee(fee_rate, self.min_fee_rate));
        }

        // Check mempool size
        if inner.total_bytes + tx_size > self.max_size_bytes {
            return Err(MempoolError::MempoolFull);
        }

        // Script verification (all inputs at once for taproot)
        script_verifier
            .verify_transaction(&tx, &prev_outputs)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        // Insert
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for input in &tx.input {
            inner.spends.insert(input.previous_output, txid);
        }

        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                weight,
                fee_rate,
                time: now,
            },
        );
        inner.total_bytes += tx_size;

        tracing::info!(%txid, fee, fee_rate, "Transaction accepted to mempool");

        Ok(txid)
    }

    /// Remove all transactions confirmed in the given block.
    pub fn remove_for_block(&self, block: &Block) {
        let mut inner = self.inner.write().unwrap();

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if let Some(entry) = inner.entries.remove(&txid) {
                let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                inner.total_bytes = inner.total_bytes.saturating_sub(tx_size);
                for input in &entry.tx.input {
                    inner.spends.remove(&input.previous_output);
                }
            }

            // Also remove any mempool txs whose inputs are now double-spent by block txs
            if !tx.is_coinbase() {
                for input in &tx.input {
                    if let Some(conflict_txid) = inner.spends.remove(&input.previous_output) {
                        if let Some(conflict_entry) = inner.entries.remove(&conflict_txid) {
                            let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                            inner.total_bytes = inner.total_bytes.saturating_sub(sz);
                            // Clean up remaining spends for the conflicting tx
                            for ci in &conflict_entry.tx.input {
                                inner.spends.remove(&ci.previous_output);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get a transaction by txid.
    pub fn get(&self, txid: &Txid) -> Option<MempoolEntry> {
        self.inner.read().unwrap().entries.get(txid).cloned()
    }

    /// Get all txids in the mempool.
    pub fn get_all_entries(&self) -> Vec<(Txid, MempoolEntry)> {
        self.inner
            .read()
            .unwrap()
            .entries
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Get mempool statistics.
    pub fn info(&self) -> MempoolInfo {
        let inner = self.inner.read().unwrap();
        MempoolInfo {
            size: inner.entries.len(),
            bytes: inner.total_bytes,
            max_size: self.max_size_bytes,
            min_fee_rate: self.min_fee_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    fn make_test_env() -> (ChainState, Mempool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-mempool-test-{}-{}",
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
            bitcoin::Network::Regtest,
            Box::new(NoopVerifier),
            None,
        )
        .unwrap();
        let mp = Mempool::new(1_000_000, 0); // 1MB, no min fee for tests
        (cs, mp, dir)
    }

    #[test]
    fn test_mempool_info_empty() {
        let (_cs, mp, dir) = make_test_env();
        let info = mp.info();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
