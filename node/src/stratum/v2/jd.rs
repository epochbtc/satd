//! Stratum V2 Job Declaration, with solo-mining semantics.
//!
//! A miner that wants to choose its own transactions runs a Job Declarator
//! Client. It opens a Job Declaration connection (`SetupConnection` with the
//! Job Declaration Protocol), asks for a token (`AllocateMiningJobToken`),
//! and declares a coinbase plus a list of transactions by wtxid
//! (`DeclareMiningJob`). On its mining connection it then sends
//! `SetCustomMiningJob` on an extended channel, naming the declared token, and
//! mines the job the server hands back.
//!
//! The server's side is deliberately narrow. Every declared transaction must
//! already be in this node's mempool, in an order the block could actually
//! be mined in; a declaration naming anything else is refused, and the server
//! never asks for missing transactions (`ProvideMissingTransactions` is the
//! template-distribution role, which this server does not take). The coinbase
//! must build on the current tip, pay the address the token was issued for,
//! and claim no more than the subsidy plus the declared transactions' fees.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Transaction, TxOut, Txid, Witness};

use super::wire::{DeclareMiningJob, SetCustomMiningJob};
use crate::mempool::pool::Mempool;
use crate::stratum::config::Payout;
use crate::stratum::template::{Work, merkle_branch};

/// Length of the tokens this server issues.
pub const TOKEN_LEN: usize = 16;
/// Tokens kept at once; the oldest go first.
const MAX_TOKENS: usize = 1024;
/// A token not used within this long is forgotten.
const TOKEN_TTL: Duration = Duration::from_secs(600);
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// A declared job: what `SetCustomMiningJob` and `PushSolution` are checked
/// against.
#[derive(Debug)]
pub struct DeclaredJob {
    pub payout: Payout,
    pub prev_hash: BlockHash,
    pub height: u32,
    /// The difficulty the job's blocks need: the work's when it was declared.
    pub bits: bitcoin::CompactTarget,
    /// The declared coinbase, split where the extranonce goes.
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    pub extranonce_len: usize,
    pub txdata: Vec<Transaction>,
    pub merkle_branch: Vec<[u8; 32]>,
    /// The most the coinbase may claim: subsidy plus the declared fees.
    pub max_coinbase_value: u64,
    pub fees: u64,
}

enum TokenState {
    Allocated(Payout),
    Declared(Arc<DeclaredJob>),
}

struct Token {
    issued: Instant,
    /// The connection the token was issued to.
    owner: u32,
    state: TokenState,
}

impl Token {
    fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued) < TOKEN_TTL
    }
}

/// Tokens of one kind (allocated, or declared) a connection may hold. A
/// connection that asks for more loses its own oldest, not another's.
const TOKENS_PER_CONNECTION: usize = 16;

/// Tokens issued by this server, shared by every connection: a token is
/// allocated on a Job Declaration connection and redeemed on a mining one.
#[derive(Default)]
pub struct Tokens {
    inner: parking_lot::Mutex<HashMap<[u8; TOKEN_LEN], Token>>,
}

impl Tokens {
    /// Issue a token for `payout` to connection `owner`.
    pub fn allocate(&self, owner: u32, payout: Payout) -> [u8; TOKEN_LEN] {
        self.insert(owner, TokenState::Allocated(payout), Instant::now())
    }

    /// Redeem an allocated token for a declaration. A token declares once.
    pub fn take_allocated(&self, token: &[u8]) -> Option<Payout> {
        self.take_allocated_at(token, Instant::now())
    }

    fn take_allocated_at(&self, token: &[u8], now: Instant) -> Option<Payout> {
        let key: [u8; TOKEN_LEN] = token.try_into().ok()?;
        let mut inner = self.inner.lock();
        if !matches!(inner.get(&key), Some(t) if t.fresh(now) && matches!(t.state, TokenState::Allocated(_))) {
            return None;
        }
        match inner.remove(&key)?.state {
            TokenState::Allocated(payout) => Some(payout),
            TokenState::Declared(_) => None,
        }
    }

    /// Record a job declared by connection `owner` under a new token.
    pub fn declare(&self, owner: u32, job: Arc<DeclaredJob>) -> [u8; TOKEN_LEN] {
        self.insert(owner, TokenState::Declared(job), Instant::now())
    }

    /// The declared job a token names.
    pub fn declared(&self, token: &[u8]) -> Option<Arc<DeclaredJob>> {
        self.declared_at(token, Instant::now())
    }

    fn declared_at(&self, token: &[u8], now: Instant) -> Option<Arc<DeclaredJob>> {
        let key: [u8; TOKEN_LEN] = token.try_into().ok()?;
        match self.inner.lock().get(&key) {
            Some(t @ Token { state: TokenState::Declared(job), .. }) if t.fresh(now) => Some(job.clone()),
            _ => None,
        }
    }

    fn insert(&self, owner: u32, state: TokenState, now: Instant) -> [u8; TOKEN_LEN] {
        let token: [u8; TOKEN_LEN] = rand::random();
        let declared = matches!(state, TokenState::Declared(_));
        let mut inner = self.inner.lock();
        inner.retain(|_, t| t.fresh(now));
        // The owner's own oldest of this kind makes room first, then the
        // table's oldest allocated token, and a declared job (which miners
        // may be hashing on) only when nothing else is left.
        let oldest = |inner: &HashMap<[u8; TOKEN_LEN], Token>, pick: &dyn Fn(&Token) -> bool| {
            inner.iter().filter(|(_, t)| pick(t)).min_by_key(|(_, t)| t.issued).map(|(k, _)| *k)
        };
        let same_kind = |t: &Token| matches!(t.state, TokenState::Declared(_)) == declared;
        let owned = inner.values().filter(|t| t.owner == owner && same_kind(t)).count();
        let evict = if owned >= TOKENS_PER_CONNECTION {
            oldest(&inner, &|t| t.owner == owner && same_kind(t))
        } else if inner.len() >= MAX_TOKENS {
            oldest(&inner, &|t| matches!(t.state, TokenState::Allocated(_))).or_else(|| oldest(&inner, &|_| true))
        } else {
            None
        };
        if let Some(key) = evict {
            inner.remove(&key);
        }
        inner.insert(token, Token { issued: now, owner, state });
        token
    }
}

/// The coinbase outputs a Job Declaration client must include, as sent in
/// `AllocateMiningJobTokenSuccess`: the payout script, consensus-serialized as
/// an output list. The value is zero; the client assigns the reward.
pub fn coinbase_outputs(payout: &ScriptBuf) -> Vec<u8> {
    bitcoin::consensus::serialize(&vec![TxOut { value: Amount::ZERO, script_pubkey: payout.clone() }])
}

/// A declaration or custom job that is refused: a Stratum V2 error code and
/// a human-readable reason.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub details: String,
}

fn refuse(code: &'static str, details: impl Into<String>) -> Refusal {
    Refusal { code, details: details.into() }
}

/// Job Declaration state shared by every connection.
#[derive(Default)]
pub struct JobDeclaration {
    pub tokens: Tokens,
    pub wtxids: WtxidIndex,
}

/// The mempool's transactions by wtxid, which the mempool itself does not
/// index. Kept up to date incrementally: a refresh walks the mempool's keys
/// and hashes only transactions it has not seen before, and runs at most
/// once per [`INDEX_REFRESH_INTERVAL`] however many declarations arrive.
#[derive(Default)]
pub struct WtxidIndex {
    inner: parking_lot::Mutex<IndexState>,
}

#[derive(Default)]
struct IndexState {
    by_txid: HashMap<Txid, bitcoin::Wtxid>,
    by_wtxid: HashMap<bitcoin::Wtxid, Txid>,
    refreshed: Option<Instant>,
}

const INDEX_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

impl WtxidIndex {
    /// The txid of each of `wtxids` that the mempool holds, as far as the
    /// index knows; an unknown wtxid refreshes the index first, rate limits
    /// permitting. A txid may be stale: callers confirm the wtxid against the
    /// entry they fetch.
    pub fn lookup(&self, mempool: &Mempool, wtxids: &[bitcoin::Wtxid]) -> Vec<Option<Txid>> {
        let mut state = self.inner.lock();
        let due = state.refreshed.is_none_or(|at| at.elapsed() >= INDEX_REFRESH_INTERVAL);
        if due && wtxids.iter().any(|w| !state.by_wtxid.contains_key(w)) {
            let state = &mut *state;
            mempool.with_entries(|entries| {
                state.by_txid.retain(|txid, _| entries.contains_key(txid));
                state.by_wtxid.retain(|_, txid| entries.contains_key(txid));
                for (txid, entry) in entries {
                    if !state.by_txid.contains_key(txid) {
                        let wtxid = entry.tx.compute_wtxid();
                        state.by_txid.insert(*txid, wtxid);
                        state.by_wtxid.insert(wtxid, *txid);
                    }
                }
            });
            state.refreshed = Some(Instant::now());
        }
        wtxids.iter().map(|w| state.by_wtxid.get(w).copied()).collect()
    }
}

/// The part of the mempool a declaration is checked against.
#[derive(Default)]
pub struct MempoolView {
    /// The declared transactions this node holds and would mine, by wtxid:
    /// `(transaction, fee, weight)`.
    pub by_wtxid: HashMap<bitcoin::Wtxid, (Transaction, u64, u64)>,
    /// Inputs of those transactions that spend another mempool transaction,
    /// eligible or not: the parents a block must include first.
    pub txids: HashSet<Txid>,
    /// The declared transactions outweigh a block; lookup stopped copying.
    pub over_weight: bool,
}

impl MempoolView {
    /// Look up the declared `wtxids` under one read of the mempool, copying
    /// only those transactions, and no more than a block's weight of them.
    pub fn for_declaration(mempool: &Mempool, index: &WtxidIndex, wtxids: &[[u8; 32]]) -> MempoolView {
        let wtxids: Vec<bitcoin::Wtxid> = wtxids.iter().map(|w| bitcoin::Wtxid::from_byte_array(*w)).collect();
        let txids = index.lookup(mempool, &wtxids);
        mempool.with_entries(|entries| {
            let mut view = MempoolView::default();
            let mut weight = 0u64;
            for (wtxid, txid) in wtxids.iter().zip(txids) {
                let Some(entry) = txid.and_then(|txid| entries.get(&txid)) else { continue };
                if !entry.scope.assists_template()
                    || view.by_wtxid.contains_key(wtxid)
                    || entry.tx.compute_wtxid() != *wtxid
                {
                    continue;
                }
                weight = weight.saturating_add(entry.weight as u64);
                if weight > MAX_BLOCK_WEIGHT {
                    view.over_weight = true;
                    break;
                }
                for input in &entry.tx.input {
                    let parent = input.previous_output.txid;
                    if entries.contains_key(&parent) {
                        view.txids.insert(parent);
                    }
                }
                view.by_wtxid.insert(*wtxid, (entry.tx.clone(), entry.fee, entry.weight as u64));
            }
            view
        })
    }
}

/// Check a `DeclareMiningJob` against the current work and mempool.
pub fn check_declaration(
    msg: &DeclareMiningJob,
    payout: Payout,
    work: &Work,
    subsidy: u64,
    mempool: &MempoolView,
) -> Result<DeclaredJob, Refusal> {
    let (coinbase, extranonce_len) = decode_split_coinbase(&msg.coinbase_tx_prefix, &msg.coinbase_tx_suffix)
        .ok_or_else(|| refuse("invalid-job-param-value-coinbase_tx_prefix", "the coinbase does not decode"))?;
    if coinbase_height(&coinbase) != Some(work.height) {
        return Err(refuse(
            "invalid-job-param-value-coinbase_tx_prefix",
            format!("the coinbase does not commit to height {}, the next block on the current tip", work.height),
        ));
    }

    if mempool.over_weight {
        return Err(refuse("invalid-job-param-value-wtxid_list", "the declared transactions outweigh a block"));
    }

    // Every transaction is in the mempool, eligible for a template, and after
    // any in-mempool parent it spends.
    let mut txdata = Vec::with_capacity(msg.wtxid_list.len());
    let mut included: HashSet<Txid> = HashSet::with_capacity(msg.wtxid_list.len());
    let mut fees = 0u64;
    let mut weight = coinbase.weight().to_wu();
    let mut missing = 0usize;
    for raw in &msg.wtxid_list {
        let wtxid = bitcoin::Wtxid::from_byte_array(*raw);
        let Some((tx, fee, tx_weight)) = mempool.by_wtxid.get(&wtxid) else {
            missing += 1;
            continue;
        };
        let txid = tx.compute_txid();
        if !included.insert(txid) {
            return Err(refuse("invalid-job-param-value-wtxid_list", format!("{wtxid} is listed twice")));
        }
        for input in &tx.input {
            let parent = input.previous_output.txid;
            if mempool.txids.contains(&parent) && !included.contains(&parent) {
                return Err(refuse(
                    "invalid-job-param-value-wtxid_list",
                    format!("{txid} spends unconfirmed {parent}, which is not listed before it"),
                ));
            }
        }
        fees = fees.saturating_add(*fee);
        weight = weight.saturating_add(*tx_weight);
        txdata.push(tx.clone());
    }
    if missing > 0 {
        return Err(refuse(
            "invalid-job-param-value-wtxid_list",
            format!("{missing} of {} transactions are not in this node's mempool", msg.wtxid_list.len()),
        ));
    }
    if weight > MAX_BLOCK_WEIGHT {
        return Err(refuse("invalid-job-param-value-wtxid_list", format!("the block would weigh {weight} WU")));
    }

    let max_coinbase_value = subsidy.saturating_add(fees);
    check_outputs(&coinbase.output, &payout.script, max_coinbase_value)
        .map_err(|d| refuse("invalid-job-param-value-coinbase_tx_suffix", d))?;

    let txids: Vec<[u8; 32]> =
        txdata.iter().map(|tx| tx.compute_txid().to_raw_hash().to_byte_array()).collect();
    let block = block_with(coinbase, &txdata, work);
    if !block.check_witness_commitment() {
        return Err(refuse(
            "invalid-job-param-value-coinbase_tx_suffix",
            "the coinbase's witness commitment does not match the declared transactions",
        ));
    }
    Ok(DeclaredJob {
        payout,
        prev_hash: work.prev_hash,
        height: work.height,
        bits: work.bits,
        coinbase_tx_prefix: msg.coinbase_tx_prefix.clone(),
        coinbase_tx_suffix: msg.coinbase_tx_suffix.clone(),
        extranonce_len,
        merkle_branch: merkle_branch(&txids),
        txdata,
        max_coinbase_value,
        fees,
    })
}

/// A checked `SetCustomMiningJob`: the work to hash and the coinbase split
/// around a hole of the channel's extranonce length.
pub struct CustomJob {
    pub work: Arc<Work>,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
}

/// Check a `SetCustomMiningJob` against the job it names and the current work.
pub fn check_custom_job(
    msg: &SetCustomMiningJob,
    job: &DeclaredJob,
    work: &Work,
    hole_len: usize,
) -> Result<CustomJob, Refusal> {
    if msg.prev_hash != work.prev_hash.to_byte_array() || job.prev_hash != work.prev_hash {
        return Err(refuse("invalid-job-param-value-prev_hash", "the job is not on the current tip"));
    }
    if msg.nbits != work.bits.to_consensus() {
        return Err(refuse("invalid-job-param-value-nbits", "nbits is not the required difficulty"));
    }
    if msg.min_ntime < work.min_time {
        return Err(refuse("invalid-job-param-value-min_ntime", "min_ntime is below the median time past"));
    }
    if msg.merkle_path != job.merkle_branch {
        return Err(refuse("invalid-job-param-value-merkle_path", "the merkle path is not the declared job's"));
    }
    let script_len = msg.coinbase_prefix.len() + hole_len;
    if msg.coinbase_prefix.len() > 8
        || !(2..=100).contains(&script_len)
        || script_height(&msg.coinbase_prefix) != Some(work.height)
    {
        return Err(refuse(
            "invalid-job-param-value-coinbase_prefix",
            "the coinbase prefix must be at most 8 bytes and start with the block height",
        ));
    }
    let outputs: Vec<TxOut> = bitcoin::consensus::deserialize(&msg.coinbase_tx_outputs)
        .map_err(|_| refuse("invalid-job-param-value-coinbase_tx_outputs", "the outputs do not decode"))?;
    let coinbase_value = check_outputs(&outputs, &job.payout.script, job.max_coinbase_value)
        .map_err(|d| refuse("invalid-job-param-value-coinbase_tx_outputs", d))?;

    // version | input count | null prevout | scriptSig length | prefix | hole
    // | sequence | outputs | locktime — the non-witness serialization.
    let mut coinbase_prefix = Vec::with_capacity(64);
    coinbase_prefix.extend_from_slice(&msg.coinbase_tx_version.to_le_bytes());
    coinbase_prefix.push(1);
    coinbase_prefix.extend_from_slice(&[0u8; 32]);
    coinbase_prefix.extend_from_slice(&u32::MAX.to_le_bytes());
    coinbase_prefix.extend_from_slice(&bitcoin::consensus::serialize(&VarInt(script_len as u64)));
    coinbase_prefix.extend_from_slice(&msg.coinbase_prefix);
    let mut coinbase_suffix = Vec::with_capacity(msg.coinbase_tx_outputs.len() + 8);
    coinbase_suffix.extend_from_slice(&msg.coinbase_tx_input_n_sequence.to_le_bytes());
    coinbase_suffix.extend_from_slice(&msg.coinbase_tx_outputs);
    coinbase_suffix.extend_from_slice(&msg.coinbase_tx_locktime.to_le_bytes());

    let custom = Work {
        id: work.id,
        height: work.height,
        prev_hash: work.prev_hash,
        version: msg.version as i32,
        bits: work.bits,
        block_target: work.block_target,
        cur_time: msg.min_ntime,
        min_time: work.min_time,
        min_difficulty_after: work.min_difficulty_after,
        coinbase_value,
        fees: job.fees,
        witness_commitment: [0u8; 32],
        merkle_branch: job.merkle_branch.clone(),
        txdata: job.txdata.clone(),
    };

    // The coinbase with any extranonce must make a block whose merkle root
    // and witness commitment hold. Checked once with a zero extranonce: the
    // extranonce is inside the coinbase scriptSig, which neither depends on.
    let mut bytes = coinbase_prefix.clone();
    bytes.extend(std::iter::repeat_n(0u8, hole_len));
    bytes.extend_from_slice(&coinbase_suffix);
    let coinbase: Transaction = bitcoin::consensus::deserialize(&bytes)
        .map_err(|_| refuse("invalid-job-param-value-coinbase_tx_outputs", "the coinbase does not assemble"))?;
    let block = block_with(coinbase, &job.txdata, &custom);
    if !block.check_witness_commitment() {
        return Err(refuse(
            "invalid-job-param-value-coinbase_tx_outputs",
            "the coinbase's witness commitment does not match the declared transactions",
        ));
    }
    Ok(CustomJob { work: Arc::new(custom), coinbase_prefix, coinbase_suffix })
}

/// Assemble the block a `PushSolution` describes from a declared job, if the
/// extranonce fits it, the header builds on the job's tip at the job's
/// difficulty, and the header's proof of work holds. The declared
/// transactions are copied only after all of that: a frame that names no real
/// block costs one coinbase decode per job, not a block's worth of copying.
pub fn solution_block(
    job: &DeclaredJob,
    extranonce: &[u8],
    prev_hash: &[u8; 32],
    ntime: u32,
    nonce: u32,
    nbits: u32,
    version: u32,
) -> Option<Block> {
    if extranonce.len() != job.extranonce_len
        || *prev_hash != job.prev_hash.to_byte_array()
        || nbits != job.bits.to_consensus()
    {
        return None;
    }
    let mut bytes = job.coinbase_tx_prefix.clone();
    bytes.extend_from_slice(extranonce);
    bytes.extend_from_slice(&job.coinbase_tx_suffix);
    let mut coinbase: Transaction = bitcoin::consensus::deserialize(&bytes).ok()?;
    if coinbase.input[0].witness.is_empty() {
        coinbase.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    }
    let root = crate::stratum::template::merkle_root_from_branch(
        coinbase.compute_txid().to_raw_hash().to_byte_array(),
        &job.merkle_branch,
    );
    let header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(version as i32),
        prev_blockhash: job.prev_hash,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
        time: ntime,
        bits: job.bits,
        nonce,
    };
    header.validate_pow(header.target()).ok()?;
    let mut txdata = Vec::with_capacity(job.txdata.len() + 1);
    txdata.push(coinbase);
    txdata.extend(job.txdata.iter().cloned());
    Some(Block { header, txdata })
}

/// Pays `payout` something, and claims no more than `max_value` in total.
/// Returns the total. Output values come from the client, so the sum is
/// checked: a wrapped total would pass for a small one.
fn check_outputs(outputs: &[TxOut], payout: &ScriptBuf, max_value: u64) -> Result<u64, String> {
    let Some(total) = outputs.iter().try_fold(0u64, |sum, o| sum.checked_add(o.value.to_sat())) else {
        return Err("the coinbase's output values overflow".into());
    };
    if total > max_value {
        return Err(format!("the coinbase claims {total} sat; at most {max_value} is available"));
    }
    if !outputs.iter().any(|o| o.script_pubkey == *payout && o.value > Amount::ZERO) {
        return Err("the coinbase does not pay the address the token was issued for".into());
    }
    Ok(total)
}

/// Find the extranonce length that makes `prefix ++ zeros ++ suffix` exactly
/// one coinbase transaction with the hole inside its scriptSig.
fn decode_split_coinbase(prefix: &[u8], suffix: &[u8]) -> Option<(Transaction, usize)> {
    for len in 0..=crate::stratum::template::MAX_EXTRANONCE_LEN {
        let mut bytes = Vec::with_capacity(prefix.len() + len + suffix.len());
        bytes.extend_from_slice(prefix);
        bytes.extend(std::iter::repeat_n(0u8, len));
        bytes.extend_from_slice(suffix);
        let Ok((tx, consumed)) = bitcoin::consensus::deserialize_partial::<Transaction>(&bytes) else {
            continue;
        };
        if consumed != bytes.len() || !tx.is_coinbase() || tx.input.len() != 1 {
            continue;
        }
        // Where the scriptSig sits in the serialization: after version,
        // the segwit marker if present, the input count and the prevout.
        let segwit = bytes.get(4) == Some(&0) && bytes.get(5) == Some(&1);
        let script = tx.input[0].script_sig.as_bytes();
        let start = 4 + if segwit { 2 } else { 0 } + 1 + 36 + VarInt(script.len() as u64).size();
        if prefix.len() >= start && prefix.len() + len <= start + script.len() {
            return Some((tx, len));
        }
    }
    None
}

/// The BIP 34 height a coinbase commits to.
fn coinbase_height(tx: &Transaction) -> Option<u32> {
    script_height(tx.input.first()?.script_sig.as_bytes())
}

/// The height pushed at the start of a coinbase scriptSig (possibly
/// truncated after the push).
fn script_height(script: &[u8]) -> Option<u32> {
    let op = *script.first()?;
    match op {
        0x51..=0x60 => Some(u32::from(op - 0x50)),
        1..=4 => {
            let n = usize::from(op);
            let bytes = script.get(1..1 + n)?;
            let mut buf = [0u8; 4];
            buf[..n].copy_from_slice(bytes);
            // A sign bit would make the number negative, which no height is.
            (bytes[n - 1] & 0x80 == 0).then(|| u32::from_le_bytes(buf))
        }
        _ => None,
    }
}

fn block_with(mut coinbase: Transaction, txdata: &[Transaction], work: &Work) -> Block {
    if coinbase.input[0].witness.is_empty() {
        coinbase.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    }
    let mut all = Vec::with_capacity(txdata.len() + 1);
    all.push(coinbase);
    all.extend(txdata.iter().cloned());
    Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(work.version),
            prev_blockhash: work.prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: work.cur_time,
            bits: work.bits,
            nonce: 0,
        },
        txdata: all,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mining::template::{BlockTemplate, TemplateTx};
    use crate::stratum::template::ActiveTemplate;
    use bitcoin::{Network, OutPoint, Sequence, TxIn};

    fn payout(seed: u8) -> Payout {
        Payout {
            script: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([seed; 20])),
            address: None,
            worker: None,
        }
    }

    fn tx(spends: OutPoint, tag: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spends,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![tag; 72], vec![2; 33]]),
            }],
            output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new_op_return([tag]) }],
        }
    }

    const SUBSIDY: u64 = 50 * 100_000_000;
    const FEE: u64 = 500;

    /// Work over `txs`, each paying `FEE`, and the mempool holding them.
    fn setup(txs: Vec<Transaction>) -> (Arc<Work>, MempoolView) {
        let template = BlockTemplate {
            version: 0x2000_0000,
            prev_hash: BlockHash::from_byte_array([7; 32]),
            height: 321,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            cur_time: 1_700_000_000,
            min_time: 1_699_999_000,
            transactions: txs
                .iter()
                .map(|t| TemplateTx { tx: t.clone(), fee: FEE, weight: t.weight().to_wu() as usize })
                .collect(),
            coinbase_value: SUBSIDY + FEE * txs.len() as u64,
        };
        let mempool = MempoolView {
            by_wtxid: txs
                .iter()
                .map(|t| (t.compute_wtxid(), (t.clone(), FEE, t.weight().to_wu())))
                .collect(),
            txids: txs.iter().map(|t| t.compute_txid()).collect(),
            over_weight: false,
        };
        (Arc::new(Work::new(template, Network::Regtest, 1_699_999_900)), mempool)
    }

    fn three_txs() -> Vec<Transaction> {
        (1..=3u8)
            .map(|i| tx(OutPoint { txid: Txid::from_byte_array([i; 32]), vout: 0 }, i))
            .collect()
    }

    /// A declaration built the way a client would: our own coinbase for the
    /// work, paying `who`.
    fn declaration(work: &Arc<Work>, who: &Payout, wtxids: Vec<[u8; 32]>) -> DeclareMiningJob {
        let job = ActiveTemplate::build(work.clone(), 1, who.script.clone(), 8).unwrap();
        DeclareMiningJob {
            request_id: 1,
            mining_job_token: vec![0; TOKEN_LEN],
            version: 0x2000_0000,
            coinbase_tx_prefix: job.coinbase_prefix,
            coinbase_tx_suffix: job.coinbase_suffix,
            wtxid_list: wtxids,
            excess_data: Vec::new(),
        }
    }

    fn wtxids(txs: &[Transaction]) -> Vec<[u8; 32]> {
        txs.iter().map(|t| t.compute_wtxid().to_raw_hash().to_byte_array()).collect()
    }

    #[test]
    fn stratum_v2_jd_accepts_mempool_subset() {
        let txs = three_txs();
        let (work, mempool) = setup(txs.clone());
        let declared = check_declaration(&declaration(&work, &payout(1), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool)
            .expect("every declared transaction is in the mempool");
        assert_eq!(declared.extranonce_len, 8);
        assert_eq!(declared.merkle_branch, work.merkle_branch);
        assert_eq!(declared.fees, 3 * FEE);
        assert_eq!(declared.height, 321);
    }

    #[test]
    fn stratum_v2_jd_rejects_unknown_tx() {
        let txs = three_txs();
        let (work, mut mempool) = setup(txs.clone());
        mempool.by_wtxid.remove(&txs[1].compute_wtxid());
        let err = check_declaration(&declaration(&work, &payout(1), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-wtxid_list");
        assert!(err.details.contains("1 of 3"), "{err:?}");
    }

    #[test]
    fn a_declaration_is_refused_for_each_broken_rule() {
        let txs = three_txs();
        let (work, mempool) = setup(txs.clone());

        // The coinbase pays someone other than the token's address.
        let err = check_declaration(&declaration(&work, &payout(2), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-coinbase_tx_suffix");

        // It claims more than the subsidy plus the declared fees: here the
        // coinbase was built for three transactions but only two are declared.
        let err = check_declaration(&declaration(&work, &payout(1), wtxids(&txs[..2])), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-coinbase_tx_suffix");
        assert!(err.details.contains("at most"), "{err:?}");

        // It is for another height.
        let (other_work, _) = {
            let mut t = setup(txs.clone());
            Arc::get_mut(&mut t.0).unwrap().height = 400;
            t
        };
        let err = check_declaration(&declaration(&other_work, &payout(1), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-coinbase_tx_prefix");

        // A transaction is listed twice.
        let mut doubled = wtxids(&txs);
        doubled.push(doubled[0]);
        let err = check_declaration(&declaration(&work, &payout(1), doubled), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-wtxid_list");
    }

    #[test]
    fn a_child_listed_before_its_mempool_parent_is_refused() {
        let parent = tx(OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, 9);
        let child = tx(OutPoint { txid: parent.compute_txid(), vout: 0 }, 10);
        let (work, mempool) = setup(vec![parent.clone(), child.clone()]);
        let in_order = wtxids(&[parent.clone(), child.clone()]);
        assert!(check_declaration(&declaration(&work, &payout(1), in_order), payout(1), &work, SUBSIDY, &mempool).is_ok());
        let reversed = wtxids(&[child, parent]);
        let err = check_declaration(&declaration(&work, &payout(1), reversed), payout(1), &work, SUBSIDY, &mempool)
            .unwrap_err();
        assert_eq!(err.code, "invalid-job-param-value-wtxid_list");
        assert!(err.details.contains("not listed before it"), "{err:?}");
    }

    fn custom_job_msg(work: &Work, declared: &DeclaredJob, value: u64, commitment: bool) -> SetCustomMiningJob {
        let mut outputs = vec![TxOut { value: Amount::from_sat(value), script_pubkey: declared.payout.script.clone() }];
        if commitment {
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(&work.witness_commitment);
            outputs.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) });
        }
        SetCustomMiningJob {
            channel_id: 1,
            request_id: 2,
            token: vec![0; TOKEN_LEN],
            version: 0x2000_0000,
            prev_hash: work.prev_hash.to_byte_array(),
            min_ntime: work.cur_time,
            nbits: work.bits.to_consensus(),
            coinbase_tx_version: 2,
            coinbase_prefix: bitcoin::script::Builder::new().push_int(i64::from(work.height)).into_script().into_bytes(),
            coinbase_tx_input_n_sequence: u32::MAX,
            coinbase_tx_outputs: bitcoin::consensus::serialize(&outputs),
            coinbase_tx_locktime: 0,
            merkle_path: declared.merkle_branch.clone(),
        }
    }

    #[test]
    fn a_custom_job_on_a_declared_set_mines_a_valid_block() {
        let txs = three_txs();
        let (work, mempool) = setup(txs.clone());
        let declared = check_declaration(&declaration(&work, &payout(1), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool).unwrap();
        let hole = 10;
        let msg = custom_job_msg(&work, &declared, declared.max_coinbase_value, true);
        let custom = check_custom_job(&msg, &declared, &work, hole).expect("a well-formed custom job");
        let job = ActiveTemplate::from_parts(custom.work.clone(), 5, declared.payout.script.clone(), custom.coinbase_prefix, custom.coinbase_suffix, hole);
        let extranonce: [u8; 10] = rand::random();
        let block = job.reconstruct_block(&extranonce, work.cur_time, 0, 0x2000_0000);
        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());
        assert_eq!(block.bip34_block_height().unwrap(), 321);
        assert_eq!(block.txdata.len(), 4);

        // Each field the job is checked on, broken in turn.
        let mut bad = msg.clone();
        bad.prev_hash = [1; 32];
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-prev_hash");
        let mut bad = msg.clone();
        bad.nbits = 0x1d00ffff;
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-nbits");
        let mut bad = msg.clone();
        bad.merkle_path.reverse();
        bad.merkle_path.push([0; 32]);
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-merkle_path");
        let mut bad = msg.clone();
        bad.coinbase_prefix = vec![0x51];
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-coinbase_prefix");
        let bad = custom_job_msg(&work, &declared, declared.max_coinbase_value + 1, true);
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-coinbase_tx_outputs");
        let bad = custom_job_msg(&work, &declared, declared.max_coinbase_value, false);
        assert_eq!(check_custom_job(&bad, &declared, &work, hole).err().unwrap().code, "invalid-job-param-value-coinbase_tx_outputs");
    }

    #[test]
    fn a_pushed_solution_assembles_the_declared_block() {
        let txs = three_txs();
        let (work, mempool) = setup(txs.clone());
        let declared = check_declaration(&declaration(&work, &payout(1), wtxids(&txs)), payout(1), &work, SUBSIDY, &mempool).unwrap();
        let prev = work.prev_hash.to_byte_array();
        let solve = |nonce| solution_block(&declared, &[3; 8], &prev, work.cur_time, nonce, 0x207fffff, 0x2000_0000);
        let nonce = (0..1_000).find(|n| solve(*n).is_some()).unwrap();
        let block = solve(nonce).unwrap();
        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());
        assert!(block.header.validate_pow(block.header.target()).is_ok());
        assert!((0..1_000).any(|n| solve(n).is_none()), "a header short of its target assembles nothing");
        assert!(solution_block(&declared, &[3; 4], &prev, work.cur_time, nonce, 0x207fffff, 0x2000_0000).is_none());
        assert!(solution_block(&declared, &[3; 8], &[0; 32], work.cur_time, nonce, 0x207fffff, 0x2000_0000).is_none());
        // An easier nbits than the job's is not the job's block.
        let easier = solution_block(&declared, &[3; 8], &prev, work.cur_time, nonce, 0x2100ffff, 0x2000_0000);
        assert!(easier.is_none());
    }

    #[test]
    fn coinbase_output_total_cannot_wrap() {
        let script = payout(1).script;
        let outputs = vec![
            TxOut { value: Amount::from_sat(u64::MAX), script_pubkey: script.clone() },
            TxOut { value: Amount::from_sat(2), script_pubkey: script.clone() },
        ];
        assert!(check_outputs(&outputs, &script, SUBSIDY).is_err(), "a total that wraps to 1 sat is refused");
        let fair = vec![TxOut { value: Amount::from_sat(SUBSIDY), script_pubkey: script.clone() }];
        assert_eq!(check_outputs(&fair, &script, SUBSIDY), Ok(SUBSIDY));
    }

    #[test]
    fn tokens_declare_once() {
        let tokens = Tokens::default();
        let t = tokens.allocate(1, payout(1));
        assert!(tokens.take_allocated(&t).is_some());
        assert!(tokens.take_allocated(&t).is_none(), "a token declares once");
        assert!(tokens.take_allocated(&[0u8; 3]).is_none());
    }

    #[test]
    fn tokens_expire_by_time() {
        let tokens = Tokens::default();
        let (work, _) = setup(Vec::new());
        let allocated = tokens.allocate(1, payout(1));
        let declared = tokens.declare(1, Arc::new(declared_job(&work)));
        let later = Instant::now() + TOKEN_TTL;
        assert!(tokens.declared_at(&declared, later).is_none());
        assert!(tokens.take_allocated_at(&allocated, later).is_none());
        assert!(tokens.declared(&declared).is_some(), "both are live now");
        assert!(tokens.take_allocated(&allocated).is_some());
    }

    #[test]
    fn a_connection_cannot_evict_another_connections_tokens() {
        let tokens = Tokens::default();
        let (work, _) = setup(Vec::new());
        let theirs = tokens.allocate(1, payout(1));
        let their_job = tokens.declare(1, Arc::new(declared_job(&work)));
        let first_own = tokens.allocate(2, payout(2));
        for _ in 0..MAX_TOKENS {
            tokens.allocate(2, payout(2));
        }
        assert!(tokens.declared(&their_job).is_some());
        assert!(tokens.take_allocated(&first_own).is_none(), "a connection's own oldest token goes first");
        assert!(tokens.take_allocated(&theirs).is_some());

        // A full table of allocated tokens from many connections gives up an
        // allocated token before a declared job.
        let tokens = Tokens::default();
        let their_job = tokens.declare(0, Arc::new(declared_job(&work)));
        for owner in 1..=(MAX_TOKENS as u32) {
            tokens.allocate(owner, payout(2));
        }
        assert!(tokens.declared(&their_job).is_some());
        assert_eq!(tokens.inner.lock().len(), MAX_TOKENS);
    }

    fn declared_job(work: &Work) -> DeclaredJob {
        DeclaredJob {
            payout: payout(1),
            prev_hash: work.prev_hash,
            height: work.height,
            bits: work.bits,
            coinbase_tx_prefix: Vec::new(),
            coinbase_tx_suffix: Vec::new(),
            extranonce_len: 8,
            txdata: Vec::new(),
            merkle_branch: Vec::new(),
            max_coinbase_value: SUBSIDY,
            fees: 0,
        }
    }

    #[test]
    fn the_mempool_view_copies_only_declared_transactions() {
        let mempool = Mempool::new(300_000_000, 1_000);
        let parent = tx(OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 }, 1);
        let child = tx(OutPoint { txid: parent.compute_txid(), vout: 0 }, 2);
        let bystander = tx(OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 0 }, 3);
        for t in [&parent, &child, &bystander] {
            mempool.insert_entry_for_test(t.compute_txid(), t.clone(), FEE);
        }
        let index = WtxidIndex::default();
        let absent = tx(OutPoint { txid: Txid::from_byte_array([4; 32]), vout: 0 }, 4);
        let view = MempoolView::for_declaration(&mempool, &index, &wtxids(&[child.clone(), absent.clone()]));
        assert_eq!(view.by_wtxid.len(), 1, "only the declared transaction the mempool holds");
        assert!(view.by_wtxid.contains_key(&child.compute_wtxid()));
        assert_eq!(view.txids, HashSet::from([parent.compute_txid()]), "its in-mempool parent is known");
        assert!(!view.over_weight);

        // A transaction that arrives later is found once the index refreshes,
        // which hashes only what it has not seen.
        let late = tx(OutPoint { txid: Txid::from_byte_array([5; 32]), vout: 0 }, 5);
        mempool.insert_entry_for_test(late.compute_txid(), late.clone(), FEE);
        index.inner.lock().refreshed = None;
        let view = MempoolView::for_declaration(&mempool, &index, &wtxids(std::slice::from_ref(&late)));
        assert!(view.by_wtxid.contains_key(&late.compute_wtxid()));
        assert_eq!(index.inner.lock().by_txid.len(), 4);
    }
}
