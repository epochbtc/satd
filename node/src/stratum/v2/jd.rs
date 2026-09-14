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

/// Tokens issued by this server, shared by every connection: a token is
/// allocated on a Job Declaration connection and redeemed on a mining one.
#[derive(Default)]
pub struct Tokens {
    inner: parking_lot::Mutex<HashMap<[u8; TOKEN_LEN], (Instant, TokenState)>>,
}

impl Tokens {
    /// Issue a token for `payout`.
    pub fn allocate(&self, payout: Payout) -> [u8; TOKEN_LEN] {
        self.insert(TokenState::Allocated(payout))
    }

    /// Redeem an allocated token for a declaration. A token declares once.
    pub fn take_allocated(&self, token: &[u8]) -> Option<Payout> {
        let key: [u8; TOKEN_LEN] = token.try_into().ok()?;
        let mut inner = self.inner.lock();
        match inner.get(&key) {
            Some((_, TokenState::Allocated(_))) => match inner.remove(&key) {
                Some((_, TokenState::Allocated(p))) => Some(p),
                _ => None,
            },
            _ => None,
        }
    }

    /// Record a declared job under a new token.
    pub fn declare(&self, job: Arc<DeclaredJob>) -> [u8; TOKEN_LEN] {
        self.insert(TokenState::Declared(job))
    }

    /// The declared job a token names.
    pub fn declared(&self, token: &[u8]) -> Option<Arc<DeclaredJob>> {
        let key: [u8; TOKEN_LEN] = token.try_into().ok()?;
        match self.inner.lock().get(&key) {
            Some((at, TokenState::Declared(job))) if at.elapsed() < TOKEN_TTL => Some(job.clone()),
            _ => None,
        }
    }

    fn insert(&self, state: TokenState) -> [u8; TOKEN_LEN] {
        let token: [u8; TOKEN_LEN] = rand::random();
        let mut inner = self.inner.lock();
        inner.retain(|_, (at, _)| at.elapsed() < TOKEN_TTL);
        if inner.len() >= MAX_TOKENS
            && let Some(oldest) = inner.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| *k)
        {
            inner.remove(&oldest);
        }
        inner.insert(token, (Instant::now(), state));
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

/// The mempool, as a declaration is checked against it.
pub struct MempoolView {
    /// Template-eligible transactions by wtxid: `(transaction, fee, weight)`.
    pub by_wtxid: HashMap<bitcoin::Wtxid, (Transaction, u64, u64)>,
    /// Every transaction in the mempool, eligible or not.
    pub txids: HashSet<Txid>,
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
        fees += fee;
        weight += tx_weight;
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

    let max_coinbase_value = subsidy + fees;
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
    check_outputs(&outputs, &job.payout.script, job.max_coinbase_value)
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
        coinbase_value: outputs.iter().map(|o| o.value.to_sat()).sum(),
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
/// extranonce fits it and the header builds on the job's tip.
pub fn solution_block(
    job: &DeclaredJob,
    extranonce: &[u8],
    prev_hash: &[u8; 32],
    ntime: u32,
    nonce: u32,
    nbits: u32,
    version: u32,
) -> Option<Block> {
    if extranonce.len() != job.extranonce_len || *prev_hash != job.prev_hash.to_byte_array() {
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
    let mut txdata = Vec::with_capacity(job.txdata.len() + 1);
    txdata.push(coinbase);
    txdata.extend(job.txdata.iter().cloned());
    Some(Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(version as i32),
            prev_blockhash: job.prev_hash,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
            time: ntime,
            bits: bitcoin::CompactTarget::from_consensus(nbits),
            nonce,
        },
        txdata,
    })
}

/// Pays `payout` something, and claims no more than `max_value` in total.
fn check_outputs(outputs: &[TxOut], payout: &ScriptBuf, max_value: u64) -> Result<(), String> {
    let total: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    if total > max_value {
        return Err(format!("the coinbase claims {total} sat; at most {max_value} is available"));
    }
    if !outputs.iter().any(|o| o.script_pubkey == *payout && o.value > Amount::ZERO) {
        return Err("the coinbase does not pay the address the token was issued for".into());
    }
    Ok(())
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
        let block = solution_block(&declared, &[3; 8], &prev, work.cur_time, 7, 0x207fffff, 0x2000_0000).unwrap();
        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());
        assert!(solution_block(&declared, &[3; 4], &prev, work.cur_time, 7, 0x207fffff, 0x2000_0000).is_none());
        assert!(solution_block(&declared, &[3; 8], &[0; 32], work.cur_time, 7, 0x207fffff, 0x2000_0000).is_none());
    }

    #[test]
    fn tokens_declare_once_and_expire_by_count() {
        let tokens = Tokens::default();
        let t = tokens.allocate(payout(1));
        assert!(tokens.take_allocated(&t).is_some());
        assert!(tokens.take_allocated(&t).is_none(), "a token declares once");
        assert!(tokens.take_allocated(&[0u8; 3]).is_none());
        let first = tokens.allocate(payout(1));
        for _ in 0..MAX_TOKENS {
            tokens.allocate(payout(2));
        }
        assert!(tokens.take_allocated(&first).is_none(), "the oldest token was evicted");
    }
}
