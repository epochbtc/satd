//! Seed-corpus generator for the `block_differential` fuzz target.
//!
//! Writes a handful of representative height-1 blocks (valid + variously
//! invalid) so libFuzzer starts from interesting, deserializable inputs rather
//! than random noise. The fuzz target overwrites each block's header
//! connectivity fields, so seeds need only deserialize — PoW is not ground
//! here. Run via `scripts/fuzz/run-block-differential.sh` (idempotent).
//!
//! Usage: `cargo run --bin gen_corpus -- <output-dir>`

use std::fs;
use std::path::PathBuf;

use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::{Amount, Block, OutPoint, ScriptBuf, Transaction, TxMerkleNode, TxOut, Txid};

use satd_fuzz::{coinbase, genesis_hash, op_true, spend, BLOCK_VERSION, GENESIS_TIME, POWLIMIT_BITS};

const SUBSIDY: u64 = 50_0000_0000;

fn raw_block(txdata: Vec<Transaction>) -> Block {
    let mut b = Block {
        header: Header {
            version: Version::from_consensus(BLOCK_VERSION),
            prev_blockhash: genesis_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: GENESIS_TIME + 600,
            bits: CompactTarget::from_consensus(POWLIMIT_BITS),
            nonce: 0,
        },
        txdata,
    };
    b.header.merkle_root = b.compute_merkle_root().unwrap_or(TxMerkleNode::all_zeros());
    b
}

fn main() {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "corpus/block_differential".to_string())
        .into();
    fs::create_dir_all(&dir).expect("create corpus dir");

    let fake = OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 };
    let t1 = spend(OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 }, 1_000);
    let t2 = spend(OutPoint { txid: Txid::from_byte_array([0x22; 32]), vout: 0 }, 1_000);

    let bad_version = {
        let mut b = raw_block(vec![coinbase(1, SUBSIDY, op_true())]);
        b.header.version = Version::from_consensus(1);
        b
    };
    let oversize_output = {
        let mut cb = coinbase(1, 0, op_true());
        cb.output = vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from(vec![0u8; 20_000]),
        }];
        raw_block(vec![cb])
    };

    let seeds: Vec<(&str, Block)> = vec![
        ("valid_coinbase", raw_block(vec![coinbase(1, SUBSIDY, op_true())])),
        (
            "multiple_coinbase",
            raw_block(vec![coinbase(1, SUBSIDY, op_true()), coinbase(1, SUBSIDY / 2, op_true())]),
        ),
        ("coinbase_value_too_high", raw_block(vec![coinbase(1, SUBSIDY + 1, op_true())])),
        ("spend_nonexistent", raw_block(vec![coinbase(1, SUBSIDY, op_true()), spend(fake, 1_000)])),
        (
            "merkle_mutation",
            raw_block(vec![coinbase(1, SUBSIDY, op_true()), t1, t2.clone(), t2]),
        ),
        ("bad_version", bad_version),
        ("oversize_output", oversize_output),
    ];

    for (name, block) in seeds {
        let path = dir.join(name);
        fs::write(&path, serialize(&block)).expect("write seed");
        println!("wrote {}", path.display());
    }
}
