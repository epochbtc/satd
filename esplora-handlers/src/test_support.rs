//! An Esplora state over a real regtest chainstate, and regtest blocks to
//! move it with, for tests that need the chain to change under a request.

use std::sync::Arc;

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, transaction,
};
use node::chain::state::{AssumeValid, ChainState};
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::NoopVerifier;
use node_index::{
    AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, SpendIndex,
    SpendingRef, StatusUpdate, SubscribeError, Utxo,
};
use tokio::sync::{Semaphore, broadcast};

use crate::config::EsploraConfig;
use crate::state::EsploraState;

/// An index with no history for any script.
pub struct EmptyIndex;

impl AddressIndex for EmptyIndex {
    fn confirmed_history(&self, _sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        Ok(Vec::new())
    }
    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        Vec::new()
    }
    fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        Ok((0, 0))
    }
    fn utxos(&self, _sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        Ok(Vec::new())
    }
    fn subscribe(
        &self,
        _sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        Ok(broadcast::channel(4).1)
    }
}

/// A spend index with no spends.
pub struct NoSpends;

impl SpendIndex for NoSpends {
    fn spend_of(&self, _outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError> {
        Ok(None)
    }
    fn spends_of_tx(&self, _txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, IndexError> {
        Ok(Vec::new())
    }
}

struct NoBroadcast;

impl node::net::manager::TxBroadcaster for NoBroadcast {
    fn submit_and_announce(
        &self,
        _tx: Transaction,
        _source: node::mempool::pool::TxSource,
        _allow_quarantined: bool,
    ) -> Result<Txid, node::mempool::pool::MempoolError> {
        unreachable!("no test broadcasts")
    }
}

/// An Esplora state over a regtest chainstate holding only genesis.
pub fn regtest_state() -> (EsploraState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let chain = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            16,
            1,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    let state = EsploraState {
        chain,
        mempool: Arc::new(Mempool::new(1_000_000, 0)),
        tx_broadcaster: Arc::new(NoBroadcast),
        address_index: Arc::new(EmptyIndex),
        spend_index: Arc::new(NoSpends),
        fee_estimator: Arc::new(FeeEstimator::new()),
        network: Network::Regtest,
        config: Arc::new(EsploraConfig::default()),
        sse_semaphore: Arc::new(Semaphore::new(16)),
        work_permits: None,
    };
    (state, dir)
}

/// A coinbase-only regtest block on `parent` at `height`. `salt` goes into
/// the coinbase, so two blocks at one height on one parent differ.
pub fn regtest_block(parent: BlockHash, height: u32, salt: u32) -> Block {
    let time = 1_708_000_000 + 600 * height + salt;
    let coinbase = Transaction {
        version: transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(height as i64)
                .push_int(salt as i64)
                .push_opcode(bitcoin::opcodes::OP_FALSE)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: parent,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = block.header.target();
    while !target.is_met_by(block.block_hash()) {
        block.header.nonce += 1;
    }
    block
}

/// Connect a block on the current tip and return its hash.
pub fn extend_tip(chain: &ChainState, salt: u32) -> BlockHash {
    let (tip, height) = chain.tip_snapshot();
    let block = regtest_block(tip, height + 1, salt);
    chain.accept_block(&block).expect("connect test block");
    assert_eq!(chain.tip_snapshot().0, block.block_hash(), "the block became the tip");
    block.block_hash()
}
