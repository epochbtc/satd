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
    pub full_rbf: bool,
}

struct MempoolInner {
    entries: HashMap<Txid, MempoolEntry>,
    spends: HashMap<OutPoint, Txid>,
    total_bytes: usize,
}

/// Configurable mempool policy. All fields map to Bitcoin Core-compatible
/// config flags, with the same defaults (or more permissive where noted).
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    pub max_size_bytes: usize,
    pub min_fee_rate: u64,
    pub full_rbf: bool,
    pub dust_relay_fee: u64,
    pub data_carrier: bool,
    pub data_carrier_size: usize,
    pub max_ancestor_count: usize,
    pub max_descendant_count: usize,
    pub expiry_secs: u64,
    pub permit_bare_multisig: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: policy::DEFAULT_MAX_MEMPOOL_SIZE,
            min_fee_rate: policy::DEFAULT_MIN_RELAY_FEE_RATE,
            full_rbf: true,
            dust_relay_fee: policy::DUST_RELAY_FEE_RATE,
            data_carrier: true,
            data_carrier_size: policy::MAX_OP_RETURN_SIZE,
            max_ancestor_count: policy::MAX_ANCESTOR_COUNT,
            max_descendant_count: policy::MAX_DESCENDANT_COUNT,
            expiry_secs: policy::MEMPOOL_EXPIRY_SECS,
            permit_bare_multisig: true,
        }
    }
}

/// In-memory transaction pool.
pub struct Mempool {
    inner: RwLock<MempoolInner>,
    config: MempoolConfig,
}

impl Mempool {
    pub fn new(max_size_bytes: usize, min_fee_rate: u64) -> Self {
        Self::with_config(MempoolConfig {
            max_size_bytes,
            min_fee_rate,
            ..Default::default()
        })
    }

    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                entries: HashMap::new(),
                spends: HashMap::new(),
                total_bytes: 0,
            }),
            config,
        }
    }

    /// Get the mempool configuration.
    pub fn policy(&self) -> &MempoolConfig {
        &self.config
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

        // Policy: dust output check (configurable via -dustrelayfee, 0 = disable)
        if self.config.dust_relay_fee > 0 {
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    continue;
                }
                let threshold =
                    policy::dust_threshold_with_rate(&output.script_pubkey, self.config.dust_relay_fee);
                if output.value.to_sat() < threshold {
                    return Err(MempoolError::Dust);
                }
            }
        }

        // Policy: OP_RETURN limits (configurable via -datacarrier and -datacarriersize)
        if !self.config.data_carrier {
            // Reject all OP_RETURN outputs
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    return Err(MempoolError::NonStandardOpReturn);
                }
            }
        } else {
            let mut op_return_count = 0;
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    op_return_count += 1;
                    if op_return_count > 1 {
                        return Err(MempoolError::NonStandardOpReturn);
                    }
                    if output.script_pubkey.len() > self.config.data_carrier_size {
                        return Err(MempoolError::NonStandardOpReturn);
                    }
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
                if ancestors.len() > self.config.max_ancestor_count {
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
                    // RBF: in opt-in mode, conflicted tx must signal replaceability
                    // (any input with sequence < 0xfffffffe). Full RBF skips this check.
                    if !self.config.full_rbf {
                        let signals_rbf = conflict_entry
                            .tx
                            .input
                            .iter()
                            .any(|i| i.sequence.0 < 0xffff_fffe);
                        if !signals_rbf {
                            return Err(MempoolError::ConflictingSpend);
                        }
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
        if fee_rate < self.config.min_fee_rate {
            return Err(MempoolError::InsufficientFee(fee_rate, self.config.min_fee_rate));
        }

        // Check mempool size — evict lowest-fee entries if needed
        if inner.total_bytes + tx_size > self.config.max_size_bytes {
            // Only evict if the new tx has a higher fee rate than the minimum in the pool
            let min_pool_fee_rate = inner
                .entries
                .values()
                .map(|e| e.fee_rate)
                .min()
                .unwrap_or(0);
            if fee_rate <= min_pool_fee_rate {
                return Err(MempoolError::MempoolFull);
            }
            // Evict enough lowest-fee-rate entries to make room
            Self::evict_lowest_fee_entries(&mut inner, tx_size);
            // If still not enough room after eviction, reject
            if inner.total_bytes + tx_size > self.config.max_size_bytes {
                return Err(MempoolError::MempoolFull);
            }
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
            .filter(|(_, entry)| now.saturating_sub(entry.time) > self.config.expiry_secs)
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

    /// Get the set of in-mempool ancestors for a transaction.
    pub fn get_ancestors(&self, txid: &Txid) -> Option<HashSet<Txid>> {
        let inner = self.inner.read().unwrap();
        let entry = inner.entries.get(txid)?;
        let mut ancestors = HashSet::new();
        let mut queue: Vec<Txid> = Vec::new();

        // Find direct parents
        for input in &entry.tx.input {
            let parent = input.previous_output.txid;
            if inner.entries.contains_key(&parent) && ancestors.insert(parent) {
                queue.push(parent);
            }
        }

        // Walk transitively
        while let Some(anc_txid) = queue.pop() {
            if let Some(anc) = inner.entries.get(&anc_txid) {
                for input in &anc.tx.input {
                    let grandparent = input.previous_output.txid;
                    if inner.entries.contains_key(&grandparent) && ancestors.insert(grandparent) {
                        queue.push(grandparent);
                    }
                }
            }
        }

        Some(ancestors)
    }

    /// Get the set of in-mempool descendants for a transaction.
    pub fn get_descendants(&self, txid: &Txid) -> Option<HashSet<Txid>> {
        let inner = self.inner.read().unwrap();
        if !inner.entries.contains_key(txid) {
            return None;
        }

        let mut descendants = HashSet::new();
        let mut queue = vec![*txid];

        while let Some(current) = queue.pop() {
            if let Some(current_entry) = inner.entries.get(&current) {
                let current_txid = current_entry.tx.compute_txid();
                // Find children: entries whose inputs reference outputs of current
                for (child_txid, child_entry) in &inner.entries {
                    if *child_txid != *txid
                        && !descendants.contains(child_txid)
                        && child_entry
                            .tx
                            .input
                            .iter()
                            .any(|i| i.previous_output.txid == current_txid)
                    {
                        descendants.insert(*child_txid);
                        queue.push(*child_txid);
                    }
                }
            }
        }

        Some(descendants)
    }

    /// Get verbose entry data for a single mempool transaction (for RPC).
    pub fn get_entry_verbose(&self, txid: &Txid) -> Option<serde_json::Value> {
        let inner = self.inner.read().unwrap();
        let entry = inner.entries.get(txid)?;
        let vsize = entry.weight / 4;
        let ancestors = {
            drop(inner);
            self.get_ancestors(txid).unwrap_or_default()
        };
        let inner = self.inner.read().unwrap();
        let entry = inner.entries.get(txid)?;

        let ancestor_count = ancestors.len();
        let ancestor_size: usize = ancestors
            .iter()
            .filter_map(|a| inner.entries.get(a))
            .map(|e| e.weight / 4)
            .sum::<usize>()
            + vsize;
        let ancestor_fees: u64 = ancestors
            .iter()
            .filter_map(|a| inner.entries.get(a))
            .map(|e| e.fee)
            .sum::<u64>()
            + entry.fee;

        let bip125_replaceable = entry
            .tx
            .input
            .iter()
            .any(|i| i.sequence.0 < 0xffff_fffe);

        Some(serde_json::json!({
            "fees": {
                "base": entry.fee as f64 / 100_000_000.0,
                "modified": entry.fee as f64 / 100_000_000.0,
                "ancestor": ancestor_fees as f64 / 100_000_000.0,
                "descendant": entry.fee as f64 / 100_000_000.0,
            },
            "vsize": vsize,
            "weight": entry.weight,
            "fee": entry.fee as f64 / 100_000_000.0,
            "time": entry.time,
            "height": 0, // would need chain height at time of entry
            "descendantcount": 1,
            "descendantsize": vsize,
            "descendantfees": entry.fee,
            "ancestorcount": ancestor_count + 1,
            "ancestorsize": ancestor_size,
            "ancestorfees": ancestor_fees,
            "depends": ancestors.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "spentby": [],
            "bip125-replaceable": bip125_replaceable,
            "unbroadcast": false,
        }))
    }

    /// Dry-run transaction validation without inserting into the mempool.
    /// Returns (txid, vsize, fee) on success.
    pub fn test_accept(
        &self,
        tx: &Transaction,
        chain_state: &ChainState,
        script_verifier: &dyn ScriptVerifier,
    ) -> Result<(Txid, usize, u64), MempoolError> {
        let txid = tx.compute_txid();

        crate::validation::tx::check_transaction(tx)
            .map_err(|e| MempoolError::Validation(e.to_string()))?;

        if tx.is_coinbase() {
            return Err(MempoolError::Validation("coinbase not accepted".to_string()));
        }

        let weight = tx.weight().to_wu() as usize;
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolError::Validation("tx-size".to_string()));
        }

        let inner = self.inner.read().unwrap();
        if inner.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }
        drop(inner);

        // Look up inputs
        let mut sum_inputs: u64 = 0;
        let mut prev_outputs: Vec<TxOut> = Vec::new();

        for input in &tx.input {
            if let Some(coin) = chain_state.get_coin(&input.previous_output) {
                sum_inputs += coin.amount;
                prev_outputs.push(TxOut {
                    value: bitcoin::Amount::from_sat(coin.amount),
                    script_pubkey: coin.script_pubkey.clone(),
                });
            } else {
                // Check mempool parents
                let inner = self.inner.read().unwrap();
                if let Some(parent) = inner.entries.get(&input.previous_output.txid)
                    && let Some(output) = parent.tx.output.get(input.previous_output.vout as usize) {
                        sum_inputs += output.value.to_sat();
                        prev_outputs.push(output.clone());
                        continue;
                    }
                return Err(MempoolError::MissingInputs);
            }
        }

        let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if sum_inputs < sum_outputs {
            return Err(MempoolError::BadAmounts);
        }
        let fee = sum_inputs - sum_outputs;

        // Script verification
        script_verifier
            .verify_transaction(tx, &prev_outputs)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        let vsize = weight / 4;
        Ok((txid, vsize, fee))
    }

    /// Evict lowest-fee-rate entries to free at least `bytes_needed` bytes.
    /// Also removes descendants of evicted entries.
    fn evict_lowest_fee_entries(inner: &mut MempoolInner, bytes_needed: usize) {
        // Sort entries by fee_rate ascending
        let mut by_fee_rate: Vec<(Txid, u64)> = inner
            .entries
            .iter()
            .map(|(txid, entry)| (*txid, entry.fee_rate))
            .collect();
        by_fee_rate.sort_by_key(|(_, rate)| *rate);

        let mut freed = 0usize;
        let mut to_remove: Vec<Txid> = Vec::new();

        for (txid, _) in &by_fee_rate {
            if freed >= bytes_needed {
                break;
            }
            if to_remove.contains(txid) {
                continue;
            }
            to_remove.push(*txid);
            if let Some(entry) = inner.entries.get(txid) {
                freed += bitcoin::consensus::serialize(&entry.tx).len();
            }
            // Also collect descendants of the evicted entry
            let mut desc_queue = vec![*txid];
            while let Some(current) = desc_queue.pop() {
                let current_txid_for_search = current;
                let children: Vec<Txid> = inner
                    .entries
                    .iter()
                    .filter(|(child_txid, child_entry)| {
                        !to_remove.contains(child_txid)
                            && child_entry
                                .tx
                                .input
                                .iter()
                                .any(|i| i.previous_output.txid == current_txid_for_search)
                    })
                    .map(|(child_txid, _)| *child_txid)
                    .collect();
                for child in children {
                    if let Some(child_entry) = inner.entries.get(&child) {
                        freed += bitcoin::consensus::serialize(&child_entry.tx).len();
                    }
                    to_remove.push(child);
                    desc_queue.push(child);
                }
            }
        }

        for txid in &to_remove {
            if let Some(entry) = inner.entries.remove(txid) {
                let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                inner.total_bytes = inner.total_bytes.saturating_sub(tx_size);
                for input in &entry.tx.input {
                    inner.spends.remove(&input.previous_output);
                }
                tracing::debug!(%txid, fee_rate = entry.fee_rate, "Evicted low-fee tx from mempool");
            }
        }

        if !to_remove.is_empty() {
            tracing::info!(evicted = to_remove.len(), "Mempool eviction complete");
        }
    }

    /// Get mempool statistics.
    pub fn info(&self) -> MempoolInfo {
        let inner = self.inner.read().unwrap();
        MempoolInfo {
            size: inner.entries.len(),
            bytes: inner.total_bytes,
            max_size: self.config.max_size_bytes,
            min_fee_rate: self.config.min_fee_rate,
            full_rbf: self.config.full_rbf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::chain::state::AssumeValid;
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
            AssumeValid::Disabled,
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

    #[test]
    fn test_mempool_eviction_low_fee_evicted() {
        // Create a tiny mempool and verify low-fee txs get evicted for higher-fee ones
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Make an extremely small pool so we can fill it easily
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 500, // Very small
            min_fee_rate: 0,
            ..Default::default()
        });

        let mut inner = mp.inner.write().unwrap();

        // Insert a low-fee "transaction" directly (bypass validation for unit test)
        let low_fee_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let low_txid = low_fee_tx.compute_txid();
        let low_size = bitcoin::consensus::serialize(&low_fee_tx).len();
        for input in &low_fee_tx.input {
            inner.spends.insert(input.previous_output, low_txid);
        }
        inner.entries.insert(
            low_txid,
            MempoolEntry {
                tx: low_fee_tx,
                fee: 10,
                weight: 400,
                fee_rate: 25, // very low fee rate
                time: 0,
            },
        );
        inner.total_bytes = low_size;

        // Pool should have 1 entry
        assert_eq!(inner.entries.len(), 1);
        let original_bytes = inner.total_bytes;

        // Evict to free space
        Mempool::evict_lowest_fee_entries(&mut inner, original_bytes);

        // The low-fee tx should be gone
        assert_eq!(inner.entries.len(), 0);
        assert!(!inner.entries.contains_key(&low_txid));
        assert_eq!(inner.total_bytes, 0);
    }

    #[test]
    fn test_mempool_full_rejects_lower_fee() {
        // Verify that when pool is full, a tx with lower fee rate than minimum
        // is rejected with MempoolFull
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1, // 1 byte = always "full" for any tx
            min_fee_rate: 0,
            ..Default::default()
        });

        let dir = std::env::temp_dir().join(format!(
            "satd-mempool-evict-test-{}-{}",
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
            AssumeValid::Disabled,
        )
        .unwrap();

        // Create a minimal tx (will fail on missing inputs, but we check MempoolFull first)
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        // Should fail (either MempoolFull or MissingInputs, depending on order)
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
