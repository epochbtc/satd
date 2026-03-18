use bitcoin::{Block, OutPoint, Transaction, TxOut, Txid};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::chain::state::ChainState;
use crate::mempool::policy::{self, MAX_STANDARD_TX_WEIGHT};
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
    #[error("dust")]
    Dust,
    #[error("scriptpubkey")]
    NonStandardOpReturn,
    #[error("insufficient fee for RBF. {0} < {1}")]
    InsufficientReplacementFee(u64, u64),
    #[error("too-long-mempool-chain")]
    TooLongMempoolChain,
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

        // Policy: dust output check
        for output in &tx.output {
            if output.script_pubkey.is_op_return() {
                continue;
            }
            let threshold = policy::dust_threshold(&output.script_pubkey);
            if output.value.to_sat() < threshold {
                return Err(MempoolError::Dust);
            }
        }

        // Policy: OP_RETURN limits — at most one, max size
        let mut op_return_count = 0;
        for output in &tx.output {
            if output.script_pubkey.is_op_return() {
                op_return_count += 1;
                if op_return_count > 1 {
                    return Err(MempoolError::NonStandardOpReturn);
                }
                if output.script_pubkey.len() > policy::MAX_OP_RETURN_SIZE {
                    return Err(MempoolError::NonStandardOpReturn);
                }
            }
        }

        let tx_size = bitcoin::consensus::serialize(&tx).len();

        // Take write lock for the rest (prevents TOCTOU races)
        let mut inner = self.inner.write().unwrap();

        // Check not already in mempool
        if inner.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }

        // Detect conflicting spends (RBF candidates)
        let mut conflicts: HashSet<Txid> = HashSet::new();
        for input in &tx.input {
            if let Some(conflict_txid) = inner.spends.get(&input.previous_output) {
                conflicts.insert(*conflict_txid);
            }
        }

        // Look up UTXOs and validate inputs (with CPFP support)
        let tip_height = chain_state.tip_height();
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();
        let mut ancestors: HashSet<Txid> = HashSet::new();

        for input in &tx.input {
            // First try chain state (confirmed UTXOs)
            if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                // Check coinbase maturity
                if coin.coinbase && tip_height - coin.height < COINBASE_MATURITY {
                    return Err(MempoolError::PrematureCoinbaseSpend);
                }
                sum_inputs += coin.amount;
                prev_outputs.push(TxOut {
                    value: bitcoin::Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });
                continue;
            }

            // CPFP: check if the input references an output from a mempool transaction
            let parent_txid = input.previous_output.txid;
            let parent_vout = input.previous_output.vout as usize;
            if let Some(parent) = inner.entries.get(&parent_txid)
                && let Some(output) = parent.tx.output.get(parent_vout)
            {
                ancestors.insert(parent_txid);
                sum_inputs += output.value.to_sat();
                prev_outputs.push(output.clone());
                continue;
            }

            return Err(MempoolError::MissingInputs);
        }

        // CPFP: build full ancestor set (transitive) and enforce limits
        if !ancestors.is_empty() {
            let mut queue: Vec<Txid> = ancestors.iter().copied().collect();
            while let Some(ancestor_txid) = queue.pop() {
                if let Some(ancestor) = inner.entries.get(&ancestor_txid) {
                    for anc_input in &ancestor.tx.input {
                        let grandparent = anc_input.previous_output.txid;
                        if inner.entries.contains_key(&grandparent)
                            && ancestors.insert(grandparent)
                        {
                            queue.push(grandparent);
                        }
                    }
                }
                if ancestors.len() > policy::MAX_ANCESTOR_COUNT {
                    return Err(MempoolError::TooLongMempoolChain);
                }
            }
        }

        // RBF: if there are conflicts, check replacement rules
        if !conflicts.is_empty() {
            // Sum fees of all conflicted transactions
            let mut conflict_fee_total: u64 = 0;
            for conflict_txid in &conflicts {
                if let Some(conflict_entry) = inner.entries.get(conflict_txid) {
                    // Opt-in RBF: conflicted tx must signal replaceability
                    // (any input with sequence < 0xfffffffe)
                    let signals_rbf = conflict_entry
                        .tx
                        .input
                        .iter()
                        .any(|i| i.sequence.0 < 0xffff_fffe);
                    if !signals_rbf {
                        return Err(MempoolError::ConflictingSpend);
                    }
                    conflict_fee_total += conflict_entry.fee;
                }
            }

            // Compute new tx fee (we have sum_inputs and sum_outputs from below)
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            if sum_inputs < sum_outputs {
                return Err(MempoolError::BadAmounts);
            }
            let new_fee = sum_inputs - sum_outputs;

            // New fee must exceed old fees + incremental relay fee
            let min_replacement_fee =
                conflict_fee_total + policy::INCREMENTAL_RELAY_FEE * weight as u64 / 1000;
            if new_fee < min_replacement_fee {
                return Err(MempoolError::InsufficientReplacementFee(
                    new_fee,
                    min_replacement_fee,
                ));
            }
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

        // RBF: remove conflicted transactions before inserting replacement
        for conflict_txid in &conflicts {
            if let Some(conflict_entry) = inner.entries.remove(conflict_txid) {
                let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                inner.total_bytes = inner.total_bytes.saturating_sub(sz);
                for ci in &conflict_entry.tx.input {
                    inner.spends.remove(&ci.previous_output);
                }
                tracing::info!(%conflict_txid, "RBF: evicted conflicting transaction");
            }
        }

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

        if !conflicts.is_empty() {
            tracing::info!(%txid, fee, fee_rate, replaced = conflicts.len(), "RBF replacement accepted to mempool");
        } else {
            tracing::info!(%txid, fee, fee_rate, ancestors = ancestors.len(), "Transaction accepted to mempool");
        }

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
                    if let Some(conflict_txid) = inner.spends.remove(&input.previous_output)
                        && let Some(conflict_entry) = inner.entries.remove(&conflict_txid) {
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

    /// Remove transactions that have been in the mempool longer than the expiry time.
    /// Returns the number of transactions removed.
    pub fn remove_expired(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut inner = self.inner.write().unwrap();
        let expired: Vec<Txid> = inner
            .entries
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.time) > policy::MEMPOOL_EXPIRY_SECS)
            .map(|(txid, _)| *txid)
            .collect();

        let count = expired.len();
        for txid in expired {
            if let Some(entry) = inner.entries.remove(&txid) {
                let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                inner.total_bytes = inner.total_bytes.saturating_sub(tx_size);
                for input in &entry.tx.input {
                    inner.spends.remove(&input.previous_output);
                }
            }
        }

        if count > 0 {
            tracing::info!(count, "Expired transactions removed from mempool");
        }

        count
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
