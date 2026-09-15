//! Hashable work built from a block template.
//!
//! Two layers, because the expensive part is shared and the cheap part is
//! not. A [`Work`] is one assembled [`BlockTemplate`] — its transactions, the
//! merkle branch over them, the witness commitment — built once per template
//! refresh and shared by every connection. An [`ActiveTemplate`] is one
//! miner's job on that work: a coinbase paying that miner's address, split
//! around the extranonce hole the miner fills in.

use std::sync::Arc;

use bitcoin::block::{Header, Version};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::pow::CompactTarget;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};

use crate::mining::template::{BlockTemplate, compute_witness_commitment};
use crate::storage::blockindex::target_from_compact;

/// Bytes of the coinbase scriptSig after the extranonce hole.
pub const COINBASE_TAG: &[u8] = b"/satd/";

/// Consensus limit on a coinbase scriptSig.
const MAX_COINBASE_SCRIPT_SIG: usize = 100;

/// Largest extranonce hole a job may carry. The hole is a single direct
/// push, so it must stay below `OP_PUSHDATA1`; SV2 allows at most 32 bytes.
pub const MAX_EXTRANONCE_LEN: usize = 32;

/// One assembled block template, ready to be turned into per-miner jobs.
pub struct Work {
    pub height: u32,
    pub prev_hash: BlockHash,
    pub version: i32,
    pub bits: CompactTarget,
    /// The block target `bits` encodes, big-endian.
    pub block_target: [u8; 32],
    /// The timestamp the template was built for; the `ntime` a miner starts
    /// from.
    pub cur_time: u32,
    /// Median time past plus one: the smallest valid `ntime`.
    pub min_time: u32,
    /// testnet3/testnet4 only, and not at a retarget boundary: the parent's
    /// timestamp plus twenty minutes. A block stamped after it may use the
    /// minimum difficulty, so `bits` holds only on the same side of it as
    /// `cur_time`.
    pub min_difficulty_after: Option<u32>,
    pub coinbase_value: u64,
    /// Sum of the included transactions' fees.
    pub fees: u64,
    pub witness_commitment: [u8; 32],
    /// The stratum merkle branch: the sibling hashes that combine with the
    /// coinbase txid, bottom-up, to give the merkle root.
    pub merkle_branch: Vec<[u8; 32]>,
    /// Non-coinbase transactions, in template order.
    pub txdata: Vec<Transaction>,
}

impl Work {
    /// Build from a template. `prev_time` is the parent block's timestamp.
    pub fn new(template: BlockTemplate, network: Network, prev_time: u32) -> Self {
        let witness_commitment = compute_witness_commitment(&template.transactions);
        let fees = template.transactions.iter().map(|t| t.fee).sum();
        let txdata: Vec<Transaction> = template.transactions.into_iter().map(|t| t.tx).collect();
        let txids: Vec<[u8; 32]> = txdata
            .iter()
            .map(|tx| tx.compute_txid().to_raw_hash().to_byte_array())
            .collect();
        let testnet = matches!(network, Network::Testnet | Network::Testnet4);
        let min_difficulty_after = (testnet
            && !template
                .height
                .is_multiple_of(crate::validation::pow::RETARGET_INTERVAL))
        .then(|| prev_time.saturating_add(20 * 60));
        Self {
            height: template.height,
            prev_hash: template.prev_hash,
            version: template.version,
            bits: template.bits,
            block_target: target_from_compact(template.bits),
            cur_time: template.cur_time,
            min_time: template.min_time,
            min_difficulty_after,
            coinbase_value: template.coinbase_value,
            fees,
            witness_commitment,
            merkle_branch: merkle_branch(&txids),
            txdata,
        }
    }
}

/// The stratum merkle branch for the coinbase at position 0 of a block whose
/// other transactions have the given txids.
pub fn merkle_branch(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    // Level 0 holds a placeholder for the coinbase, which is always the
    // leftmost node, so only its right-hand siblings are ever needed.
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txids.len() + 1);
    level.push([0u8; 32]);
    level.extend_from_slice(txids);
    while level.len() > 1 {
        branch.push(level[1]);
        if !level.len().is_multiple_of(2) {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        next.push([0u8; 32]);
        for pair in level[2..].chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next;
    }
    branch
}

/// Fold a coinbase txid up a merkle branch to the merkle root.
pub fn merkle_root_from_branch(coinbase_txid: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    branch.iter().fold(coinbase_txid, |acc, sibling| hash_pair(&acc, sibling))
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// A job could not be built.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("extranonce of {0} bytes is outside 1..={MAX_EXTRANONCE_LEN}")]
    ExtranonceLength(usize),
    #[error("coinbase scriptSig would be {0} bytes, above the 100-byte limit")]
    ScriptSigTooLong(usize),
}

/// One miner's job: a [`Work`] plus a coinbase paying `payout_script`, split
/// around the extranonce hole.
///
/// `coinbase_prefix ++ extranonce ++ coinbase_suffix` is the coinbase in its
/// non-witness serialization, which is what the txid — and so the merkle
/// root and the header — commits to. The witness reserved value is added back
/// only when the block is reconstructed.
pub struct ActiveTemplate {
    pub job_id: u32,
    pub work: Arc<Work>,
    pub payout_script: ScriptBuf,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_suffix: Vec<u8>,
    pub extranonce_len: usize,
}

impl ActiveTemplate {
    /// Build a job paying `payout_script` with an extranonce hole of
    /// `extranonce_len` bytes.
    pub fn build(
        work: Arc<Work>,
        job_id: u32,
        payout_script: ScriptBuf,
        extranonce_len: usize,
    ) -> Result<Self, TemplateError> {
        if extranonce_len == 0 || extranonce_len > MAX_EXTRANONCE_LEN {
            return Err(TemplateError::ExtranonceLength(extranonce_len));
        }
        // scriptSig: BIP 34 height push, a push of the extranonce, a push of
        // the tag. Pushes rather than raw bytes, so the scriptSig still parses
        // as a script. The height push is exactly what `connect_block` expects
        // at the start of the scriptSig (`push_int`, as the built-in miner
        // uses).
        let height_push = Builder::new().push_int(i64::from(work.height)).into_script();
        let hole = PushBytesBuf::try_from(vec![0u8; extranonce_len]).expect("≤ 32 bytes");
        let tag = PushBytesBuf::try_from(COINBASE_TAG.to_vec()).expect("short tag");
        let script_sig = Builder::from(height_push.to_bytes())
            .push_slice(hole)
            .push_slice(tag)
            .into_script();
        if script_sig.len() > MAX_COINBASE_SCRIPT_SIG {
            return Err(TemplateError::ScriptSigTooLong(script_sig.len()));
        }

        let mut output = vec![TxOut {
            value: Amount::from_sat(work.coinbase_value),
            script_pubkey: payout_script.clone(),
        }];
        let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment.extend_from_slice(&work.witness_commitment);
        output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(commitment),
        });
        let coinbase = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        };
        // No witness on the transaction yet, so this is the non-witness
        // serialization.
        let bytes = bitcoin::consensus::serialize(&coinbase);

        // version (4) | input count (1) | prevout (36) | scriptSig length
        // (compact size) | height push | extranonce push opcode | hole.
        let script_len = coinbase.input[0].script_sig.len();
        let script_len_size = bitcoin::consensus::encode::VarInt(script_len as u64).size();
        let split = 4 + 1 + 36 + script_len_size + height_push.len() + 1;
        debug_assert_eq!(bytes[split - 1] as usize, extranonce_len, "push opcode");
        debug_assert!(bytes[split..split + extranonce_len].iter().all(|b| *b == 0));

        Ok(Self {
            job_id,
            coinbase_prefix: bytes[..split].to_vec(),
            coinbase_suffix: bytes[split + extranonce_len..].to_vec(),
            payout_script,
            work,
            extranonce_len,
        })
    }

    /// The coinbase txid for a given extranonce.
    pub fn coinbase_txid(&self, extranonce: &[u8]) -> [u8; 32] {
        let mut engine = sha256d::Hash::engine();
        use bitcoin::hashes::HashEngine;
        engine.input(&self.coinbase_prefix);
        engine.input(extranonce);
        engine.input(&self.coinbase_suffix);
        sha256d::Hash::from_engine(engine).to_byte_array()
    }

    /// The merkle root for a given extranonce.
    pub fn merkle_root(&self, extranonce: &[u8]) -> TxMerkleNode {
        TxMerkleNode::from_byte_array(merkle_root_from_branch(
            self.coinbase_txid(extranonce),
            &self.work.merkle_branch,
        ))
    }

    /// The 80-byte header a miner hashes.
    pub fn header(&self, extranonce: &[u8], ntime: u32, nonce: u32, version: i32) -> Header {
        Header {
            version: Version::from_consensus(version),
            prev_blockhash: self.work.prev_hash,
            merkle_root: self.merkle_root(extranonce),
            time: ntime,
            bits: self.work.bits,
            nonce,
        }
    }

    /// The full coinbase, including the witness reserved value.
    pub fn reassemble_coinbase(&self, extranonce: &[u8]) -> Transaction {
        let mut bytes =
            Vec::with_capacity(self.coinbase_prefix.len() + extranonce.len() + self.coinbase_suffix.len());
        bytes.extend_from_slice(&self.coinbase_prefix);
        bytes.extend_from_slice(extranonce);
        bytes.extend_from_slice(&self.coinbase_suffix);
        let mut tx = Transaction::consensus_decode(&mut bytes.as_slice())
            .expect("the prefix and suffix came from a serialized transaction");
        tx.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
        tx
    }

    /// The complete block for a solution.
    pub fn reconstruct_block(&self, extranonce: &[u8], ntime: u32, nonce: u32, version: i32) -> Block {
        let mut txdata = Vec::with_capacity(self.work.txdata.len() + 1);
        txdata.push(self.reassemble_coinbase(extranonce));
        txdata.extend(self.work.txdata.iter().cloned());
        Block { header: self.header(extranonce, ntime, nonce, version), txdata }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mining::template::TemplateTx;

    /// A version-2 transaction spending `seed`'s outpoint, with a witness so
    /// wtxid ≠ txid.
    fn tx(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![seed; 72], vec![2; 33]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([seed]),
            }],
        }
    }

    pub(crate) fn work_with(n: usize, bits: u32) -> Arc<Work> {
        let template = BlockTemplate {
            version: 0x2000_0000,
            prev_hash: BlockHash::from_byte_array([7; 32]),
            height: 1_234,
            bits: CompactTarget::from_consensus(bits),
            cur_time: 1_700_000_000,
            min_time: 1_699_999_000,
            transactions: (0..n)
                .map(|i| TemplateTx { tx: tx(i as u8 + 1), fee: 100, weight: 400 })
                .collect(),
            coinbase_value: 50 * 100_000_000 + 100 * n as u64,
        };
        Arc::new(Work::new(template, Network::Regtest, 1_699_999_900))
    }

    fn payout() -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9; 20]))
    }

    #[test]
    fn coinbase_split_reassembles_and_commits_witness() {
        let job = ActiveTemplate::build(work_with(3, 0x207fffff), 1, payout(), 8).unwrap();
        let extranonce: [u8; 8] = rand::random();
        let block = job.reconstruct_block(&extranonce, 1_700_000_001, 42, 0x2000_0000);

        // The coinbase really carries the miner's bytes where the hole was.
        let script_sig = block.txdata[0].input[0].script_sig.as_bytes();
        let hole_at = script_sig.windows(8).position(|w| w == extranonce);
        assert!(hole_at.is_some(), "extranonce inside the scriptSig");
        assert!(script_sig.ends_with(COINBASE_TAG));

        // The split form hashes to the same txid as the reassembled
        // transaction: the witness is not part of what the miner hashed.
        assert_eq!(
            job.coinbase_txid(&extranonce),
            block.txdata[0].compute_txid().to_raw_hash().to_byte_array()
        );
        assert!(block.check_merkle_root(), "merkle root from the branch");
        assert!(block.check_witness_commitment(), "witness commitment");
        assert_eq!(block.txdata[0].output[0].script_pubkey, payout());
        assert_eq!(block.bip34_block_height().unwrap(), 1_234);
    }

    #[test]
    fn merkle_branch_matches_bitcoin_merkle_root() {
        for n in [0usize, 1, 2, 7] {
            let job = ActiveTemplate::build(work_with(n, 0x207fffff), 1, payout(), 8).unwrap();
            let block = job.reconstruct_block(&[0xab; 8], 1_700_000_001, 0, 0x2000_0000);
            let expected = block.compute_merkle_root().expect("non-empty");
            assert_eq!(block.header.merkle_root, expected, "{n} transactions");
            assert_eq!(block.txdata.len(), n + 1);
        }
    }

    #[test]
    fn extranonce_bounds_are_enforced() {
        let work = work_with(0, 0x207fffff);
        assert!(ActiveTemplate::build(work.clone(), 1, payout(), 0).is_err());
        assert!(ActiveTemplate::build(work.clone(), 1, payout(), 33).is_err());
        assert!(ActiveTemplate::build(work, 1, payout(), 32).is_ok());
    }
}
