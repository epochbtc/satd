//! Shared block-building helpers for the Phase C Layer 2 fuzz target and its
//! corpus generator. Mirrors the builders in
//! `satd/tests/phase_c_differential.rs` (the fuzz crate is a standalone
//! workspace and can't share that test-only module).

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    absolute::LockTime, Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxMerkleNode, TxOut, Witness,
};

pub const POWLIMIT_BITS: u32 = 0x207f_ffff;
pub const BLOCK_VERSION: i32 = 0x2000_0000;
pub const GENESIS_TIME: u32 = 1_296_688_602;
pub const BLOCK_SPACING: u32 = 600;

/// Regtest genesis hash — the shared base tip both nodes start from.
pub fn genesis_hash() -> BlockHash {
    bitcoin::constants::genesis_block(Network::Regtest).block_hash()
}

/// Anyone-can-spend bare `OP_TRUE` scriptPubKey.
pub fn op_true() -> ScriptBuf {
    ScriptBuf::from(vec![0x51])
}

/// A BIP34 coinbase paying `value` to `spk`. `push_int(height)` matches Core's
/// `CScript() << height`; the trailing `OP_0` pads the scriptSig to ≥ 2 bytes.
pub fn coinbase(height: u32, value: u64, spk: ScriptBuf) -> Transaction {
    let script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .push_opcode(bitcoin::opcodes::all::OP_PUSHBYTES_0)
        .into_script();
    Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: spk }],
    }
}

/// A non-coinbase transaction spending one outpoint to `OP_TRUE`.
pub fn spend(prevout: OutPoint, value: u64) -> Transaction {
    Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: op_true() }],
    }
}

/// Grind the (trivial) regtest PoW.
pub fn grind(header: &mut Header) {
    loop {
        if header.validate_pow(header.target()).is_ok() {
            return;
        }
        header.nonce = header.nonce.wrapping_add(1);
        if header.nonce == 0 {
            header.time += 1;
        }
    }
}

/// Build a block on `prev` at `time` carrying `txdata`, with a correct merkle
/// root and ground PoW (regtest difficulty).
pub fn assemble(prev: BlockHash, time: u32, txdata: Vec<Transaction>) -> Block {
    let mut b = Block {
        header: Header {
            version: Version::from_consensus(BLOCK_VERSION),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(POWLIMIT_BITS),
            nonce: 0,
        },
        txdata,
    };
    b.header.merkle_root = b.compute_merkle_root().unwrap_or(TxMerkleNode::all_zeros());
    grind(&mut b.header);
    b
}
