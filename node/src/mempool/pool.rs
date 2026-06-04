use bitcoin::{Block, OutPoint, Transaction, TxOut, Txid};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::broadcast;

use crate::chain::state::ChainState;
use crate::mempool::events::{EvictReason, MempoolEvent};
use crate::mempool::policy::{self, MAX_STANDARD_TX_WEIGHT};
use crate::validation::script::ScriptVerifier;
use crate::validation::tx::check_transaction;
use node_index::keys::{scripthash_of, Scripthash};

/// Capacity of the broadcast channel for `subscribemempool`. Large
/// enough to absorb short bursts; a subscriber that lags past this
/// will see `RecvError::Lagged` and skip to the latest events —
/// correct behavior for a best-effort stream.
pub const EVENT_BROADCAST_CAPACITY: usize = 1024;

/// Capacity of the in-memory event ring tapped by MCP
/// `subscribe_mempool_snapshot`. Kept small — MCP is request/response,
/// clients pull the last N events, not a long history.
pub const EVENT_RING_CAPACITY: usize = 50;

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
    /// Miner-adjustable fee delta (satoshis) from `prioritisetransaction`.
    pub fee_delta: i64,
    /// BIP 141 witness-aware sigop cost of this tx. Computed at admission
    /// using the resolved `prev_outputs` so P2SH / P2WSH redeem scripts are
    /// accounted for accurately.
    pub sigop_cost: u64,
    /// `sha256(scriptPubKey)` of each spent prevout, one per input in input
    /// order (`prev_scripthashes[i]` ↔ `tx.input[i]`). Resolved once at
    /// admission from `prev_outputs` (which is otherwise discarded) so the
    /// streaming watch matcher can do **mempool spend-side** matching (exact
    /// script and prefix bucket) — the unconfirmed analogue of the undo-driven
    /// confirmed path — without re-resolving prevouts off the hot path. Hashes
    /// (32 B/input), not full scripts: enough to match, bounded by mempool size.
    /// Empty for entries built outside admission (test fixtures, direct inserts).
    pub prev_scripthashes: Vec<Scripthash>,
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
    /// Mempool/relay policy. Behind a `RwLock` so SIGHUP config reload can swap
    /// it live (`reload_policy`); `accept_transaction` snapshots it once at
    /// entry so a transaction is judged against a single policy version.
    ///
    /// Lock discipline: this is a **leaf lock** — acquire, read/clone what you
    /// need, release. NEVER hold it while acquiring `inner` (snapshot the needed
    /// fields into locals first, as `remove_expired`/`info` do). This keeps the
    /// lock order uniform so a concurrent `reload_policy` write can never form a
    /// cycle with `inner`.
    config: RwLock<MempoolConfig>,
    /// Broadcast channel fanout for `subscribemempool`. Populated via
    /// `set_event_sender`; remains `None` in tests that don't need
    /// event emission.
    event_tx: Mutex<Option<broadcast::Sender<MempoolEvent>>>,
    /// Bounded ring of recent events for MCP snapshot consumption.
    /// Always maintained (cheap) so MCP tools work whether or not
    /// the broadcast sender is wired.
    event_ring: Mutex<VecDeque<MempoolEvent>>,
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
            config: RwLock::new(config),
            event_tx: Mutex::new(None),
            event_ring: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAPACITY)),
        }
    }

    /// Wire a broadcast sender for mempool events. Must be called
    /// once at startup before any mempool mutations that should be
    /// observed by subscribers.
    pub fn set_event_sender(&self, tx: broadcast::Sender<MempoolEvent>) {
        *self.event_tx.lock() = Some(tx);
    }

    /// Subscribe to live mempool events. Returns `None` if no sender
    /// has been wired (typical in tests that bypass `main.rs`).
    pub fn subscribe_events(&self) -> Option<broadcast::Receiver<MempoolEvent>> {
        self.event_tx.lock().as_ref().map(|tx| tx.subscribe())
    }

    /// Return the most recent `EVENT_RING_CAPACITY` events tapped
    /// off the broadcast. Used by MCP `subscribe_mempool_snapshot`.
    pub fn recent_events(&self) -> Vec<MempoolEvent> {
        self.event_ring.lock().iter().cloned().collect()
    }

    /// Emit an event: push into the ring, then best-effort broadcast.
    /// Never blocks; broadcast backpressure is the subscriber's problem.
    fn emit(&self, event: MempoolEvent) {
        {
            let mut ring = self.event_ring.lock();
            ring.push_back(event.clone());
            while ring.len() > EVENT_RING_CAPACITY {
                ring.pop_front();
            }
        }
        if let Some(tx) = self.event_tx.lock().as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Get a snapshot of the current mempool policy. Returns a clone because
    /// the policy is behind a lock (live-reloadable via [`Mempool::reload_policy`]).
    pub fn policy(&self) -> MempoolConfig {
        self.config.read().clone()
    }

    /// Current minimum relay fee rate (sat/kvB). Scalar accessor so hot paths
    /// (e.g. per-peer `feefilter`) avoid cloning the whole policy struct.
    pub fn min_fee_rate(&self) -> u64 {
        self.config.read().min_fee_rate
    }

    /// Current maximum mempool size in bytes.
    pub fn max_size_bytes(&self) -> usize {
        self.config.read().max_size_bytes
    }

    /// Swap in a new mempool/relay policy live (SIGHUP config reload). Takes
    /// effect on the next `accept_transaction` call; already-admitted entries
    /// are not re-evaluated.
    pub fn reload_policy(&self, new: MempoolConfig) {
        *self.config.write() = new;
    }

    /// Accept a transaction into the mempool after full validation.
    pub fn accept_transaction(
        &self,
        tx: Transaction,
        chain_state: &ChainState,
        script_verifier: &dyn ScriptVerifier,
    ) -> Result<Txid, MempoolError> {
        let txid = tx.compute_txid();

        // Snapshot the live policy once so the entire acceptance is judged
        // against a single config version. A concurrent SIGHUP reload can swap
        // `self.config` between calls but never mid-transaction.
        let cfg = self.config.read().clone();

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
        if cfg.dust_relay_fee > 0 {
            for output in &tx.output {
                if output.script_pubkey.is_op_return() {
                    continue;
                }
                let threshold =
                    policy::dust_threshold_with_rate(&output.script_pubkey, cfg.dust_relay_fee);
                if output.value.to_sat() < threshold {
                    return Err(MempoolError::Dust);
                }
            }
        }

        // Policy: OP_RETURN limits (configurable via -datacarrier and -datacarriersize)
        if !cfg.data_carrier {
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
                    if output.script_pubkey.len() > cfg.data_carrier_size {
                        return Err(MempoolError::NonStandardOpReturn);
                    }
                }
            }
        }

        // Policy: reject non-standard output scripts
        for output in &tx.output {
            if !policy::is_standard_output_script(
                &output.script_pubkey,
                cfg.permit_bare_multisig,
            ) {
                return Err(MempoolError::Validation("scriptpubkey".to_string()));
            }
        }

        let tx_size = bitcoin::consensus::serialize(&tx).len();

        // Take write lock for the rest (prevents TOCTOU races)
        let mut inner = self.inner.write();

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
                if ancestors.len() > cfg.max_ancestor_count {
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
                    if !cfg.full_rbf {
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
        if fee_rate < cfg.min_fee_rate {
            return Err(MempoolError::InsufficientFee(fee_rate, cfg.min_fee_rate));
        }

        // Check mempool size — evict lowest-fee entries if needed
        let mut evicted_full_pool: Vec<Txid> = Vec::new();
        if inner.total_bytes + tx_size > cfg.max_size_bytes {
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
            evicted_full_pool = Self::evict_lowest_fee_entries(&mut inner, tx_size);
            // If still not enough room after eviction, reject
            if inner.total_bytes + tx_size > cfg.max_size_bytes {
                return Err(MempoolError::MempoolFull);
            }
        }

        // Script verification (all inputs at once for taproot)
        // Use tip_height + 1 since the tx will be mined in the next block
        script_verifier
            .verify_transaction(&tx, &prev_outputs, tip_height + 1)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        // RBF: remove conflicted transactions before inserting replacement.
        // Collect replaced txids so we can emit LeaveReplaced events
        // after the write lock is dropped (broadcast is best-effort but
        // still prefer not to hold a lock while sending).
        let mut replaced: Vec<Txid> = Vec::new();
        for conflict_txid in &conflicts {
            if let Some(conflict_entry) = inner.entries.remove(conflict_txid) {
                let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                inner.total_bytes = inner.total_bytes.saturating_sub(sz);
                for ci in &conflict_entry.tx.input {
                    inner.spends.remove(&ci.previous_output);
                }
                replaced.push(*conflict_txid);
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

        let prev_outputs_map: HashMap<OutPoint, TxOut> = tx
            .input
            .iter()
            .zip(prev_outputs.iter())
            .map(|(i, o)| (i.previous_output, o.clone()))
            .collect();
        let sigop_cost = tx.total_sigop_cost(|op| prev_outputs_map.get(op).cloned()) as u64;

        // Retain the spent prevout scripthashes (input order) for mempool
        // spend-side matching (exact script + prefix bucket). `prev_outputs` is
        // fully resolved above and dropped after this; hashing it now is the one
        // chance to keep the data without re-resolving prevouts in the
        // (decoupled) matcher.
        let prev_scripthashes: Vec<Scripthash> = prev_outputs
            .iter()
            .map(|o| scripthash_of(&o.script_pubkey))
            .collect();

        let entry_weight_u64 = weight as u64;
        let vsize_u64 = entry_weight_u64 / 4;
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                weight,
                fee_rate,
                time: now,
                fee_delta: 0,
                sigop_cost,
                prev_scripthashes,
            },
        );
        inner.total_bytes += tx_size;

        if !conflicts.is_empty() {
            tracing::info!(%txid, fee, fee_rate, replaced = conflicts.len(), "RBF replacement accepted to mempool");
        } else {
            tracing::info!(%txid, fee, fee_rate, ancestors = ancestors.len(), "Transaction accepted to mempool");
        }

        // Drop the write lock before emitting events — broadcast sends
        // are best-effort but keeping the lock duration tight is the rule.
        drop(inner);

        for evicted_txid in &evicted_full_pool {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *evicted_txid,
                reason: EvictReason::FullPool,
            });
        }
        for conflict_txid in &replaced {
            self.emit(MempoolEvent::LeaveReplaced {
                txid: *conflict_txid,
                replacing_txid: txid,
            });
        }
        self.emit(MempoolEvent::Enter {
            txid,
            fee,
            vsize: vsize_u64,
            fee_rate_sat_per_kvb: fee_rate,
            time: now,
        });

        Ok(txid)
    }

    /// Remove all transactions confirmed in the given block. Emits
    /// `LeaveConfirmed` events for txids that were in the mempool.
    /// `height` is the connected block's height and is threaded into
    /// the event so subscribers can filter / correlate.
    pub fn remove_for_block(&self, block: &Block, height: u32) {
        let block_hash = block.block_hash();
        let mut confirmed: Vec<Txid> = Vec::new();
        let mut evicted_conflicts: Vec<Txid> = Vec::new();
        {
            let mut inner = self.inner.write();
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                if let Some(entry) = inner.entries.remove(&txid) {
                    let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                    inner.total_bytes = inner.total_bytes.saturating_sub(tx_size);
                    for input in &entry.tx.input {
                        inner.spends.remove(&input.previous_output);
                    }
                    confirmed.push(txid);
                }

                // Also remove any mempool txs whose inputs are now
                // double-spent by the block. The chain — not policy —
                // retired these, surfaced as
                // `LeaveEvicted { BlockConflict }` so operators don't
                // read them as mempool pressure.
                if !tx.is_coinbase() {
                    for input in &tx.input {
                        if let Some(conflict_txid) =
                            inner.spends.remove(&input.previous_output)
                            && let Some(conflict_entry) = inner.entries.remove(&conflict_txid)
                        {
                            let sz = bitcoin::consensus::serialize(&conflict_entry.tx).len();
                            inner.total_bytes = inner.total_bytes.saturating_sub(sz);
                            for ci in &conflict_entry.tx.input {
                                inner.spends.remove(&ci.previous_output);
                            }
                            evicted_conflicts.push(conflict_txid);
                        }
                    }
                }
            }
        }

        for txid in &confirmed {
            self.emit(MempoolEvent::LeaveConfirmed {
                txid: *txid,
                block_hash,
                height,
            });
        }
        for txid in &evicted_conflicts {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *txid,
                reason: EvictReason::BlockConflict,
            });
        }
    }

    /// Get a transaction by txid.
    pub fn get(&self, txid: &Txid) -> Option<MempoolEntry> {
        self.inner.read().entries.get(txid).cloned()
    }

    /// Adjust the fee delta for a transaction in the mempool (for mining priority).
    pub fn prioritise_transaction(&self, txid: &Txid, fee_delta: i64) -> bool {
        let mut inner = self.inner.write();
        if let Some(entry) = inner.entries.get_mut(txid) {
            // Saturating: fee_delta comes from `prioritisetransaction` RPC
            // and from re-admitted persisted mempool entries (untrusted
            // mempool.dat), so a malicious/corrupt value must not overflow.
            entry.fee_delta = entry.fee_delta.saturating_add(fee_delta);
            true
        } else {
            false
        }
    }

    /// Get all txids in the mempool.
    pub fn get_all_entries(&self) -> Vec<(Txid, MempoolEntry)> {
        self.inner
            .read()
            
            .entries
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Cheap O(1) lookup: which mempool tx (and which input vin) consumes
    /// `outpoint`? Returns `None` if the outpoint is not consumed by any
    /// mempool tx. Used by Esplora's `/tx/:txid/outspend/:vout` so the
    /// single-output path doesn't have to clone the whole mempool to
    /// answer one question (review M4).
    ///
    /// The outer lookup hits the existing `spends` index in O(1); the
    /// inner walk over the spending tx's inputs is bounded by that
    /// tx's own input count, not by mempool size.
    pub fn spending_tx(&self, outpoint: &OutPoint) -> Option<(Txid, u32)> {
        let inner = self.inner.read();
        let spending_txid = *inner.spends.get(outpoint)?;
        let entry = inner.entries.get(&spending_txid)?;
        let vin = entry
            .tx
            .input
            .iter()
            .position(|i| i.previous_output == *outpoint)?
            as u32;
        Some((spending_txid, vin))
    }

    /// Remove transactions that have been in the mempool longer than the expiry time.
    /// Returns the number of transactions removed.
    pub fn remove_expired(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Snapshot the policy field BEFORE locking `inner`, so the policy lock
        // is never held while `inner` is. This keeps the policy lock a leaf
        // (acquire → read → release) and the lock order uniform across the pool,
        // so a concurrent `reload_policy` (config.write) can never form a lock
        // cycle with the mempool lock.
        let expiry_secs = self.config.read().expiry_secs;
        let mut expired_txids: Vec<Txid> = Vec::new();
        {
            let mut inner = self.inner.write();
            let expired: Vec<Txid> = inner
                .entries
                .iter()
                .filter(|(_, entry)| now.saturating_sub(entry.time) > expiry_secs)
                .map(|(txid, _)| *txid)
                .collect();

            for txid in &expired {
                if let Some(entry) = inner.entries.remove(txid) {
                    let tx_size = bitcoin::consensus::serialize(&entry.tx).len();
                    inner.total_bytes = inner.total_bytes.saturating_sub(tx_size);
                    for input in &entry.tx.input {
                        inner.spends.remove(&input.previous_output);
                    }
                    expired_txids.push(*txid);
                }
            }
        }

        let count = expired_txids.len();
        for txid in &expired_txids {
            self.emit(MempoolEvent::LeaveEvicted {
                txid: *txid,
                reason: EvictReason::Expiry,
            });
        }

        if count > 0 {
            tracing::info!(count, "Expired transactions removed from mempool");
        }

        count
    }

    /// Get the set of in-mempool ancestors for a transaction.
    pub fn get_ancestors(&self, txid: &Txid) -> Option<HashSet<Txid>> {
        let inner = self.inner.read();
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
        let inner = self.inner.read();
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

    /// Get the direct in-mempool children of `txid` — transactions
    /// that spend any output of `txid`. Uses the `spends` reverse
    /// index for O(outputs) lookup. Does *not* recurse.
    pub fn get_children(&self, txid: &Txid) -> Option<Vec<Txid>> {
        let inner = self.inner.read();
        let entry = inner.entries.get(txid)?;
        let n_outs = entry.tx.output.len() as u32;
        let mut children: Vec<Txid> = Vec::new();
        let mut seen: HashSet<Txid> = HashSet::new();
        for vout in 0..n_outs {
            let op = OutPoint { txid: *txid, vout };
            if let Some(child) = inner.spends.get(&op)
                && seen.insert(*child)
            {
                children.push(*child);
            }
        }
        Some(children)
    }

    /// Get verbose entry data for a single mempool transaction (for RPC).
    pub fn get_entry_verbose(&self, txid: &Txid) -> Option<serde_json::Value> {
        let inner = self.inner.read();
        let entry = inner.entries.get(txid)?;
        let vsize = entry.weight / 4;
        let entry_fee = entry.fee;
        let entry_weight = entry.weight;
        let entry_time = entry.time;
        let entry_tx_inputs: Vec<_> = entry.tx.input.clone();
        drop(inner);

        let ancestors = self.get_ancestors(txid).unwrap_or_default();
        let descendants = self.get_descendants(txid).unwrap_or_default();
        let children = self.get_children(txid).unwrap_or_default();

        let inner = self.inner.read();

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
            + entry_fee;

        let descendant_count = descendants.len() + 1; // includes self
        let descendant_size: usize = descendants
            .iter()
            .filter_map(|d| inner.entries.get(d))
            .map(|e| e.weight / 4)
            .sum::<usize>()
            + vsize;
        let descendant_fees: u64 = descendants
            .iter()
            .filter_map(|d| inner.entries.get(d))
            .map(|e| e.fee)
            .sum::<u64>()
            + entry_fee;

        let bip125_replaceable = entry_tx_inputs
            .iter()
            .any(|i| i.sequence.0 < 0xffff_fffe);

        Some(serde_json::json!({
            "fees": {
                "base": entry_fee as f64 / 100_000_000.0,
                "modified": entry_fee as f64 / 100_000_000.0,
                "ancestor": ancestor_fees as f64 / 100_000_000.0,
                "descendant": descendant_fees as f64 / 100_000_000.0,
            },
            "vsize": vsize,
            "weight": entry_weight,
            "fee": entry_fee as f64 / 100_000_000.0,
            "time": entry_time,
            "height": 0, // would need chain height at time of entry
            "descendantcount": descendant_count,
            "descendantsize": descendant_size,
            "descendantfees": descendant_fees,
            "ancestorcount": ancestor_count + 1,
            "ancestorsize": ancestor_size,
            "ancestorfees": ancestor_fees,
            "depends": ancestors.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "spentby": children.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
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

        let inner = self.inner.read();
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
                let inner = self.inner.read();
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

        // Script verification (tip + 1 = next block height)
        let tip_height = chain_state.tip_height();
        script_verifier
            .verify_transaction(tx, &prev_outputs, tip_height + 1)
            .map_err(|e| MempoolError::Script(e.to_string()))?;

        let vsize = weight / 4;
        Ok((txid, vsize, fee))
    }

    /// Evict lowest-fee-rate entries to free at least `bytes_needed` bytes.
    /// Also removes descendants of evicted entries. Returns the list of
    /// evicted txids so the caller can emit `LeaveEvicted { FullPool }`
    /// events after dropping the write lock.
    fn evict_lowest_fee_entries(inner: &mut MempoolInner, bytes_needed: usize) -> Vec<Txid> {
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
        to_remove
    }

    /// Get mempool statistics.
    pub fn info(&self) -> MempoolInfo {
        // Snapshot policy first (lock released) so the policy lock is never held
        // while `inner` is — uniform leaf-lock discipline (see `remove_expired`).
        let (max_size, min_fee_rate, full_rbf) = {
            let cfg = self.config.read();
            (cfg.max_size_bytes, cfg.min_fee_rate, cfg.full_rbf)
        };
        let inner = self.inner.read();
        MempoolInfo {
            size: inner.entries.len(),
            bytes: inner.total_bytes,
            max_size,
            min_fee_rate,
            full_rbf,
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
            450,
            4,
            Default::default(),
            Default::default(),
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

        let mut inner = mp.inner.write();

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
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
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
            450,
            4,
            Default::default(),
            Default::default(),
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

    #[test]
    fn reload_policy_swaps_live() {
        // SIGHUP config reload swaps the policy behind the RwLock; every read
        // path (the scalar accessors, policy(), and info() — which shares the
        // exact `self.config.read()` path accept_transaction snapshots) must
        // observe the new values immediately.
        let mp = Mempool::with_config(MempoolConfig {
            min_fee_rate: 1_000,
            max_size_bytes: 1_000_000,
            full_rbf: true,
            ..Default::default()
        });
        assert_eq!(mp.min_fee_rate(), 1_000);
        assert_eq!(mp.max_size_bytes(), 1_000_000);
        assert!(mp.info().full_rbf);

        mp.reload_policy(MempoolConfig {
            min_fee_rate: 5_000,
            max_size_bytes: 2_000_000,
            full_rbf: false,
            ..Default::default()
        });
        assert_eq!(
            mp.min_fee_rate(),
            5_000,
            "scalar accessor must read the reloaded policy"
        );
        assert_eq!(mp.max_size_bytes(), 2_000_000);
        assert_eq!(
            mp.policy().min_fee_rate,
            5_000,
            "policy() must read the reloaded policy"
        );
        let info = mp.info();
        assert_eq!(info.min_fee_rate, 5_000, "info() must read the reloaded policy");
        assert_eq!(info.max_size, 2_000_000);
        assert!(!info.full_rbf, "info() must reflect the reloaded full_rbf");
    }

    #[test]
    fn test_coinbase_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a coinbase transaction (input with null outpoint)
        let coinbase_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = mp.accept_transaction(coinbase_tx, &cs, &NoopVerifier);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("coinbase"),
            "Expected coinbase rejection, got: {}",
            err
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_inputs() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a tx referencing a non-existent UTXO
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac,
                ]),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        assert!(matches!(result, Err(MempoolError::MissingInputs)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dust_output_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create mempool with default dust relay fee
        let (cs, _mp, dir) = make_test_env();
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            dust_relay_fee: 3_000, // 3 sat/vB — standard dust relay fee
            ..Default::default()
        });

        // Build a tx with a tiny (1 sat) P2PKH output — well below dust threshold
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1), // 1 sat — definitely dust
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0x88, 0xac,
                ]),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        assert!(matches!(result, Err(MempoolError::Dust)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_op_return_too_large() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build an OP_RETURN output > 83 bytes
        let mut op_return_script = vec![0x6a]; // OP_RETURN
        op_return_script.extend_from_slice(&[0x00; 90]); // 91 bytes total > 83

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xcc; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(op_return_script),
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_op_return_rejected() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let (cs, mp, dir) = make_test_env();

        // Build a tx with two OP_RETURN outputs (each within size limit)
        let op_return_script = ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xdd; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return_script.clone(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return_script,
                },
            ],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_data_carrier_disabled() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        // Create mempool with data_carrier disabled
        let (cs, _mp, dir) = make_test_env();
        let mp = Mempool::with_config(MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate: 0,
            data_carrier: false,
            ..Default::default()
        });

        // A small, valid OP_RETURN output
        let op_return_script = ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0xee; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            }],
        };

        let result = mp.accept_transaction(tx, &cs, &NoopVerifier);
        assert!(matches!(result, Err(MempoolError::NonStandardOpReturn)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_remove_for_block_empty_pool() {
        let (_cs, mp, dir) = make_test_env();

        // Verify remove_for_block on an empty pool is a no-op and doesn't panic
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        mp.remove_for_block(&genesis, 0);

        let info = mp.info();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_for_block_conflict_emits_block_conflict_not_full_pool() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        let (_cs, mp, dir) = make_test_env();
        let (event_tx, mut event_rx) =
            tokio::sync::broadcast::channel::<MempoolEvent>(64);
        mp.set_event_sender(event_tx);

        // A mempool tx spending UTXO X. We bypass accept_transaction
        // validation and wire the state by hand — the scenario we need
        // is "tx is in the mempool, a conflicting block arrives" and
        // that state is awkward to reach through the public API.
        let contested = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
            ),
            vout: 0,
        };
        let mempool_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: contested,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mempool_txid = mempool_tx.compute_txid();
        {
            let mut inner = mp.inner.write();
            inner.spends.insert(contested, mempool_txid);
            inner.entries.insert(
                mempool_txid,
                MempoolEntry {
                    tx: mempool_tx,
                    fee: 500,
                    weight: 400,
                    fee_rate: 1_250,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                },
            );
        }

        // Build a block containing a different tx that spends the same
        // UTXO X — chain-induced conflict.
        let block_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: contested,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // Minimum-viable block: take regtest genesis and append our tx.
        let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        block.txdata.push(block_tx);

        mp.remove_for_block(&block, 123);

        // Consume events until we see the LeaveEvicted for mempool_txid.
        // The broadcast is synchronous in-process; a handful of recv
        // iterations is enough.
        let mut saw_block_conflict = false;
        for _ in 0..8 {
            match event_rx.try_recv() {
                Ok(MempoolEvent::LeaveEvicted { txid, reason })
                    if txid == mempool_txid =>
                {
                    assert_eq!(
                        reason,
                        EvictReason::BlockConflict,
                        "chain-induced removal must be BlockConflict, not {:?}",
                        reason
                    );
                    saw_block_conflict = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(
            saw_block_conflict,
            "expected a LeaveEvicted{{BlockConflict}} event for the conflicting mempool tx"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getrawmempool_verbose_includes_ancestor_descendant_fields() {
        // Regression guard: the sat-tui mempool pane reads
        // `ancestorfees` / `ancestorsize` / `descendantcount` from
        // getrawmempool verbose to build its top-N table. If those
        // fields are ever dropped from the response, the TUI silently
        // displays an empty table on real nodes.
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let mp = Mempool::new(1_000_000, 0);

        // Build a parent tx spending some synthetic prevout.
        let parent_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        // Build a child spending parent:0 — establishes an ancestor link
        // inside the mempool so the rollup stats exceed the self values.
        let child_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: parent_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(8_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let child_txid = child_tx.compute_txid();

        {
            let mut inner = mp.inner.write();
            for input in &parent_tx.input {
                inner.spends.insert(input.previous_output, parent_txid);
            }
            inner.entries.insert(
                parent_txid,
                MempoolEntry {
                    tx: parent_tx,
                    fee: 1_000,
                    weight: 400,
                    fee_rate: 10_000,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                },
            );
            for input in &child_tx.input {
                inner.spends.insert(input.previous_output, child_txid);
            }
            inner.entries.insert(
                child_txid,
                MempoolEntry {
                    tx: child_tx,
                    fee: 2_000,
                    weight: 400,
                    fee_rate: 20_000,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                },
            );
        }

        let resp = crate::rpc::rawtx::get_raw_mempool(&mp, true);
        let map = resp.as_object().expect("verbose response is a map");
        let parent_v = &map[&parent_txid.to_string()];
        let child_v = &map[&child_txid.to_string()];

        // Self-only: parent has no ancestors, child has parent as ancestor.
        assert_eq!(parent_v["ancestorcount"].as_u64(), Some(1));
        assert_eq!(child_v["ancestorcount"].as_u64(), Some(2));

        // Descendants: parent has the child, child has none.
        assert_eq!(parent_v["descendantcount"].as_u64(), Some(2));
        assert_eq!(child_v["descendantcount"].as_u64(), Some(1));

        // Fee rollups include the entry itself.
        assert_eq!(child_v["ancestorfees"].as_u64(), Some(1_000 + 2_000));
        assert_eq!(parent_v["descendantfees"].as_u64(), Some(1_000 + 2_000));

        // Sizes in vbytes (weight/4 ceil).
        assert_eq!(parent_v["ancestorsize"].as_u64(), Some(100));
        assert_eq!(child_v["ancestorsize"].as_u64(), Some(200));

        // Confirm the tui-critical shape: fields are u64 integers, not strings.
        assert!(parent_v["ancestorfees"].is_u64());
        assert!(parent_v["ancestorsize"].is_u64());
        assert!(parent_v["descendantcount"].is_u64());
    }

    #[test]
    fn mempool_entry_retains_prev_scripthashes() {
        // Admission must hash each spent prevout's scriptPubKey (input order)
        // onto the entry so the streaming matcher can prefix-match mempool
        // spends without re-resolving prevouts. Exercise the real admission
        // path via CPFP: a parent already in the pool supplies the child's
        // prevout script, so accept_transaction resolves it from the mempool.
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        let (cs, mp, dir) = make_test_env();

        // A distinctive *standard* prevout script (P2WPKH) the child will spend
        // — admission enforces output standardness, so it can't be arbitrary.
        let prevout_spk = {
            let mut b = vec![0x00, 0x14];
            b.extend_from_slice(&[0xab; 20]);
            ScriptBuf::from(b)
        };
        let child_spk = {
            let mut b = vec![0x00, 0x14];
            b.extend_from_slice(&[0xcd; 20]);
            ScriptBuf::from(b)
        };
        let parent_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([9u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: prevout_spk.clone(),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        // Seed the parent directly (bypass its own input resolution); the child
        // then goes through the public accept path, which is what we test.
        {
            let mut inner = mp.inner.write();
            inner.entries.insert(
                parent_txid,
                MempoolEntry {
                    tx: parent_tx,
                    fee: 0,
                    weight: 400,
                    fee_rate: 0,
                    time: 0,
                    fee_delta: 0,
                    sigop_cost: 0,
                    prev_scripthashes: Vec::new(),
                },
            );
        }

        let child_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: child_spk,
            }],
        };
        let child_txid = child_tx.compute_txid();

        mp.accept_transaction(child_tx, &cs, &NoopVerifier)
            .expect("child admits via CPFP");

        let entry = mp.get(&child_txid).expect("child in mempool");
        assert_eq!(
            entry.prev_scripthashes,
            vec![scripthash_of(&prevout_spk)],
            "entry retains the spent prevout's scripthash in input order"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
