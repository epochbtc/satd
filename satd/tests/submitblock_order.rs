//! `submitblock` with a child before its parent (#922), against a live
//! regtest node.
//!
//! Core's `AcceptBlock` indexes every block's header through
//! `AcceptBlockHeader` (`validation.cpp:4307`), which raises the best header
//! to any entry with more work (`node/blockstorage.cpp:249`), and
//! `ReceivedBlockTransactions` makes a block whose parent lacked data a
//! candidate once that data arrives, so `ActivateBestChain` connects it.

mod common;

use common::{TestNode, poll_until, test_timeout};
use serde_json::{Value, json};

/// Build a regtest block on `prev` at `height` whose coinbase pays
/// `subsidy + overpay` satoshis, and grind its nonce.
fn build_block(prev: bitcoin::BlockHash, height: u32, time: u32, overpay: u64) -> bitcoin::Block {
    use bitcoin::hashes::Hash as _;
    let subsidy = (50u64 * 100_000_000) >> (height / 150).min(63);
    let script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .push_int(time as i64)
        .push_opcode(bitcoin::opcodes::OP_FALSE)
        .into_script();
    let coinbase = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig,
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(subsidy + overpay),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    // The regtest target's top byte is 0x7f.
    for nonce in 0u32..u32::MAX {
        block.header.nonce = nonce;
        if block.block_hash().as_raw_hash().as_byte_array()[31] < 0x7f {
            return block;
        }
    }
    panic!("could not grind a regtest block header");
}

fn hex_of<T: bitcoin::consensus::Encodable>(t: &T) -> String {
    hex::encode(bitcoin::consensus::serialize(t))
}

/// The `result` of a call that must succeed.
fn call(node: &TestNode, method: &str, params: Vec<Value>) -> Value {
    let r = node.rpc_call_with_params(method, params).expect("node reachable");
    assert!(r["error"].is_null(), "{method}: {r}");
    r["result"].clone()
}

fn counts(node: &TestNode) -> (u64, u64) {
    let info = call(node, "getblockchaininfo", vec![]);
    (info["blocks"].as_u64().unwrap(), info["headers"].as_u64().unwrap())
}

fn tip_status(node: &TestNode, hash: &bitcoin::BlockHash) -> Option<String> {
    call(node, "getchaintips", vec![])
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["hash"] == hash.to_string())
        .map(|t| t["status"].as_str().unwrap().to_string())
}

/// The parent and child of a two-block chain on the node's genesis.
fn two_blocks(node: &TestNode, child_overpay: u64) -> (bitcoin::Block, bitcoin::Block) {
    let template = call(node, "getblocktemplate", vec![json!({"rules": ["segwit"]})]);
    let genesis: bitcoin::BlockHash =
        template["previousblockhash"].as_str().unwrap().parse().unwrap();
    let time = template["curtime"].as_u64().unwrap() as u32;
    let parent = build_block(genesis, 1, time, 0);
    let child = build_block(parent.block_hash(), 2, time + 1, child_overpay);
    (parent, child)
}

/// The steps from #922: the parent's header, the child's block, then the
/// parent's block. The child is the best header as soon as it is stored,
/// and connects once its parent has.
///
/// Fails without the fix: `headers` stays 1 after the child is stored, and
/// the node stays at height 1 with the child `valid-headers`.
#[test]
fn submitblock_child_before_parent_connects_both() {
    let mut node = TestNode::start(&[]);
    let (parent, child) = two_blocks(&node, 0);

    assert!(call(&node, "submitheader", vec![json!(hex_of(&parent.header))]).is_null());
    assert_eq!(counts(&node), (0, 1));

    let r = call(&node, "submitblock", vec![json!(hex_of(&child))]);
    assert_eq!(r, json!("inconclusive"), "the child waits for its parent");
    assert_eq!(counts(&node), (0, 2), "the stored child's header is the best header");

    assert!(call(&node, "submitblock", vec![json!(hex_of(&parent))]).is_null());
    poll_until(
        || counts(&node) == (2, 2),
        test_timeout(30),
        "the child connects after its parent",
    );
    let best = call(&node, "getbestblockhash", vec![]);
    assert_eq!(best, json!(child.block_hash().to_string()));
    assert_eq!(tip_status(&node, &child.block_hash()).as_deref(), Some("active"));
    node.stop();
}

/// Must-succeed pair: the same two blocks in order connect at once.
#[test]
fn submitblock_in_order_connects_each_block() {
    let mut node = TestNode::start(&[]);
    let (parent, child) = two_blocks(&node, 0);
    assert!(call(&node, "submitblock", vec![json!(hex_of(&parent))]).is_null());
    assert_eq!(counts(&node), (1, 1));
    assert!(call(&node, "submitblock", vec![json!(hex_of(&child))]).is_null());
    assert_eq!(counts(&node), (2, 2));
    node.stop();
}

/// A child that is invalid (its coinbase pays one satoshi too much,
/// `bad-cb-amount`) is stored before its parent and is not connected once
/// the parent is: it is marked invalid and the header tip moves back to the
/// parent.
#[test]
fn submitblock_invalid_child_before_parent_is_not_connected() {
    let mut node = TestNode::start(&[]);
    let (parent, child) = two_blocks(&node, 1);

    assert!(call(&node, "submitheader", vec![json!(hex_of(&parent.header))]).is_null());
    let r = call(&node, "submitblock", vec![json!(hex_of(&child))]);
    assert_eq!(r, json!("inconclusive"));
    assert!(call(&node, "submitblock", vec![json!(hex_of(&parent))]).is_null());

    poll_until(
        || tip_status(&node, &child.block_hash()).as_deref() == Some("invalid"),
        test_timeout(30),
        "the child is marked invalid",
    );
    assert_eq!(counts(&node), (1, 1));
    let best = call(&node, "getbestblockhash", vec![]);
    assert_eq!(best, json!(parent.block_hash().to_string()));
    node.stop();
}
