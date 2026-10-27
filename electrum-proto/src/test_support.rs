//! Regtest blocks to move a test chainstate with, for tests that need a
//! chain of some height or need it to change under a request.

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    transaction,
};
use node::chain::state::ChainState;

/// A regtest block on `parent` at `height`: a coinbase, then `txs`. `salt`
/// goes into the coinbase, so two blocks at one height on one parent differ.
pub fn regtest_block(parent: BlockHash, height: u32, salt: u32, txs: Vec<Transaction>) -> Block {
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
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut txdata = vec![coinbase];
    txdata.extend(txs);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: parent,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = block.header.target();
    while !target.is_met_by(block.block_hash()) {
        block.header.nonce += 1;
    }
    block
}

/// Connect a block holding `txs` on the current tip and return it.
pub fn extend_tip_with(chain: &ChainState, salt: u32, txs: Vec<Transaction>) -> Block {
    let (tip, height) = chain.tip_snapshot();
    let block = regtest_block(tip, height + 1, salt, txs);
    chain.accept_block(&block).expect("connect test block");
    assert_eq!(chain.tip_snapshot().0, block.block_hash(), "the block became the tip");
    block
}

/// Connect a coinbase-only block on the current tip and return its hash.
pub fn extend_tip(chain: &ChainState, salt: u32) -> BlockHash {
    extend_tip_with(chain, salt, Vec::new()).block_hash()
}
