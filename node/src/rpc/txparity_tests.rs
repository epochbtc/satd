//! `getblock` and `getrawtransaction` field sets checked against Core v31's
//! `blockToJSON` (src/rpc/blockchain.cpp), `TxToUniv` (src/core_io.cpp) and
//! `TxToJSON` (src/rpc/rawtransaction.cpp) (#978).

use bitcoin::{Block, BlockHash, Network, OutPoint, Witness};
use serde_json::{Value, json};

use crate::chain::state::ChainState;
use crate::chain::state::tests::{
    build_test_block, build_test_block_spending, make_chain_state, make_chain_state_with_store,
};
use crate::storage::test_store::ControllableStore;
use crate::mempool::pool::Mempool;
use crate::rpc::{blockchain, rawtx};

fn time(h: u32) -> u32 {
    1_300_000_000 + h * 600
}

/// 101 blocks, then block 102 spending block 1's coinbase, then block 103,
/// so the spent coin is gone from the UTXO set.
fn chain_with_a_spend() -> (ChainState, std::path::PathBuf, Vec<Block>) {
    let (cs, dir) = make_chain_state();
    let blocks = mine_a_spend(&cs);
    (cs, dir, blocks)
}

fn mine_a_spend(cs: &ChainState) -> Vec<Block> {
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    let mut blocks: Vec<Block> = Vec::new();
    for h in 1..=103 {
        let b = if h == 102 {
            let spend = OutPoint { txid: blocks[0].txdata[0].compute_txid(), vout: 0 };
            build_test_block_spending(parent, h, time(h), spend)
        } else {
            build_test_block(parent, h, time(h))
        };
        cs.accept_block(&b).expect("the test block connects");
        parent = b.block_hash();
        blocks.push(b);
    }
    blocks
}

fn getblock(cs: &ChainState, hash: BlockHash, verbosity: u32) -> Value {
    blockchain::get_block(cs, &hash.to_string(), verbosity).unwrap()
}

fn sats(v: &Value) -> u64 {
    (v.as_f64().unwrap() * 1e8).round() as u64
}

/// Core's `getblock` has `strippedsize` and v31's `coinbase_tx`.
#[test]
fn getblock_has_strippedsize_and_coinbase_tx() {
    let (cs, dir, blocks) = chain_with_a_spend();
    let b = &blocks[101];
    let v = getblock(&cs, b.block_hash(), 1);
    // No witness anywhere: the stripped block is the block.
    assert_eq!(v["strippedsize"], json!(bitcoin::consensus::serialize(b).len()), "{v}");
    let cb = &b.txdata[0];
    assert_eq!(
        v["coinbase_tx"],
        json!({
            "version": cb.version.0,
            "locktime": cb.lock_time.to_consensus_u32(),
            "sequence": cb.input[0].sequence.0,
            "coinbase": hex::encode(cb.input[0].script_sig.as_bytes()),
        }),
        "{v}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Verbosity 2 gives each transaction its `fee`, and 3 each input its
/// `prevout`, from the block's undo data, which is there without
/// `-txindex` and after the coin is spent. satd rendered every transaction
/// at verbosity 1, with neither, and stamped each one with `blockhash`,
/// `blockheight` and `confirmations`, which Core's do not carry.
#[test]
fn getblock_takes_fees_and_prevouts_from_undo_data() {
    let (cs, dir, blocks) = chain_with_a_spend();
    let b = &blocks[101];
    let funding = &blocks[0].txdata[0].output[0];
    let fee = funding.value.to_sat() - b.txdata[1].output[0].value.to_sat();

    let v2 = getblock(&cs, b.block_hash(), 2);
    let txs = v2["tx"].as_array().unwrap();
    assert_eq!(txs[0].get("fee"), None, "a coinbase has no fee: {v2}");
    assert_eq!(sats(&txs[1]["fee"]), fee, "{v2}");
    assert_eq!(txs[1]["vin"][0].get("prevout"), None, "verbosity 2 has no prevout: {v2}");
    for tx in txs {
        for f in ["blockhash", "blockheight", "confirmations", "time", "blocktime"] {
            assert_eq!(tx.get(f), None, "{f} in a getblock tx: {tx}");
        }
        assert!(tx["hex"].is_string(), "{tx}");
    }

    let v3 = getblock(&cs, b.block_hash(), 3);
    let prevout = &v3["tx"][1]["vin"][0]["prevout"];
    assert_eq!(prevout["generated"], json!(true), "{v3}");
    assert_eq!(prevout["height"], json!(1), "{v3}");
    assert_eq!(sats(&prevout["value"]), funding.value.to_sat(), "{v3}");
    assert_eq!(prevout["scriptPubKey"]["hex"], json!(hex::encode(funding.script_pubkey.as_bytes())));
    assert_eq!(sats(&v3["tx"][1]["fee"]), fee, "{v3}");
    let _ = std::fs::remove_dir_all(dir);
}

/// `getrawtransaction` verbosity 2 for a confirmed transaction: `fee` and
/// `prevout` from undo data, and Core's chain fields, with no `blockheight`.
#[test]
fn getrawtransaction_of_a_confirmed_spend_matches_core() {
    let (cs, dir, blocks) = chain_with_a_spend();
    let b = &blocks[101];
    let txid = b.txdata[1].compute_txid().to_string();
    let hash = b.block_hash().to_string();
    let pool = Mempool::new(1_000_000, 0);

    let v1 = rawtx::get_raw_transaction(&cs, &pool, &txid, true, 1, Some(&hash)).unwrap();
    assert_eq!(v1.get("fee"), None, "{v1}");
    assert_eq!(v1.get("blockheight"), None, "{v1}");
    assert_eq!(v1["confirmations"], json!(2), "{v1}");
    assert_eq!(v1["in_active_chain"], json!(true), "{v1}");
    assert_eq!(v1["blockhash"], json!(hash));
    assert_eq!(v1["time"], json!(b.header.time));
    assert_eq!(v1["blocktime"], json!(b.header.time));

    let v2 = rawtx::get_raw_transaction(&cs, &pool, &txid, true, 2, Some(&hash)).unwrap();
    assert!(v2["fee"].is_number(), "{v2}");
    assert_eq!(v2["vin"][0]["prevout"]["height"], json!(1), "{v2}");
    assert_eq!(v2["vin"][0]["prevout"]["generated"], json!(true), "{v2}");

    // A coinbase has no undo data: no fee, as in Core.
    let cb = b.txdata[0].compute_txid().to_string();
    let v = rawtx::get_raw_transaction(&cs, &pool, &cb, true, 2, Some(&hash)).unwrap();
    assert_eq!(v.get("fee"), None, "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A mempool transaction has no `confirmations` (satd said 0), and at
/// verbosity 2 no fee or prevout: Core takes those from undo data only.
#[test]
fn getrawtransaction_of_a_mempool_tx_has_no_chain_fields() {
    let (cs, dir, blocks) = chain_with_a_spend();
    let spend = OutPoint { txid: blocks[1].txdata[0].compute_txid(), vout: 0 };
    let tx = build_test_block_spending(blocks[102].block_hash(), 104, time(104), spend).txdata[1].clone();
    let txid = tx.compute_txid();
    let pool = Mempool::new(1_000_000, 0);
    pool.insert_entry_for_test(txid, tx, 1);
    for verbosity in [1, 2] {
        let v = rawtx::get_raw_transaction(&cs, &pool, &txid.to_string(), true, verbosity, None).unwrap();
        for f in ["confirmations", "blockhash", "blockheight", "time", "blocktime", "fee"] {
            assert_eq!(v.get(f), None, "{f} at verbosity {verbosity}: {v}");
        }
        assert_eq!(v["vin"][0].get("prevout"), None, "{v}");
        assert!(v["hex"].is_string(), "{v}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Core prints a coinbase's witness (the witness reserved value), and
/// `decoderawtransaction` echoes no `hex`.
#[test]
fn a_coinbase_witness_is_shown_and_decoderawtransaction_has_no_hex() {
    let mut cb = build_test_block(bitcoin::constants::genesis_block(Network::Regtest).block_hash(), 1, time(1))
        .txdata[0]
        .clone();
    cb.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    let hex_tx = hex::encode(bitcoin::consensus::serialize(&cb));
    let v = rawtx::decode_raw_transaction(&hex_tx, None, Network::Regtest).unwrap();
    assert_eq!(v["vin"][0]["txinwitness"], json!([hex::encode([0u8; 32])]), "{v}");
    assert_eq!(v.get("hex"), None, "{v}");
}

/// Undo data that is there but cannot be read is Core's internal error,
/// not an answer with the fees left out.
#[test]
fn unreadable_undo_data_is_an_internal_error() {
    let store = ControllableStore::new();
    let controls = store.controls();
    let (cs, dir) = make_chain_state_with_store(Box::new(store));
    let blocks = mine_a_spend(&cs);
    let b = &blocks[101];
    // Read from the store, not the cache of recently written undo rows.
    cs.store_ref().flush().expect("flush");
    cs.store_ref().drop_read_overlays();
    controls.set_undo_unreadable(true);

    let err = blockchain::get_block(&cs, &b.block_hash().to_string(), 2).unwrap_err();
    assert_eq!(err, rawtx::UNDO_UNREADABLE);
    // Verbosity 1 reads no undo data.
    assert!(blockchain::get_block(&cs, &b.block_hash().to_string(), 1).is_ok());

    let pool = Mempool::new(1_000_000, 0);
    let txid = b.txdata[1].compute_txid().to_string();
    let hash = b.block_hash().to_string();
    let err = rawtx::get_raw_transaction(&cs, &pool, &txid, true, 2, Some(&hash)).unwrap_err();
    assert_eq!(err, (-32603, rawtx::UNDO_UNREADABLE.to_string()));
    assert!(rawtx::get_raw_transaction(&cs, &pool, &txid, true, 1, Some(&hash)).is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

/// Without a transaction index the fee and prevouts still come from undo
/// data: satd looked the spent coins up in the UTXO set and the index.
#[test]
fn getrawtransaction_needs_no_txindex_for_the_fee() {
    let store = ControllableStore::new();
    let controls = store.controls();
    controls.set_txindex(false, false);
    let (cs, dir) = make_chain_state_with_store(Box::new(store));
    let blocks = mine_a_spend(&cs);
    let b = &blocks[101];
    let pool = Mempool::new(1_000_000, 0);
    let txid = b.txdata[1].compute_txid().to_string();
    let v = rawtx::get_raw_transaction(&cs, &pool, &txid, true, 2, Some(&b.block_hash().to_string())).unwrap();
    assert!(v["fee"].is_number(), "{v}");
    assert_eq!(v["vin"][0]["prevout"]["height"], json!(1), "{v}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The not-found text says what the node actually searched (#1066). With
/// `-txindex` on, satd told the caller to enable it. Core v31's
/// `getrawtransaction` (src/rpc/rawtransaction.cpp) picks its text by index
/// state; satd's "incomplete" index stands in for Core's still-syncing one.
#[test]
fn getrawtransaction_not_found_text_follows_the_index() {
    use bitcoin::hashes::Hash;
    let missing = bitcoin::Txid::from_byte_array([0x5a; 32]).to_string();
    let cases = [
        ((false, false), "No such mempool transaction. Use -txindex or provide a block hash"),
        ((true, false), "No such mempool transaction. The transaction index does not cover blocks"),
        ((true, true), "No such mempool or blockchain transaction. Use gettransaction"),
    ];
    for ((enabled, complete), want) in cases {
        let store = ControllableStore::new();
        store.controls().set_txindex(enabled, complete);
        let (cs, dir) = make_chain_state_with_store(Box::new(store));
        let pool = Mempool::new(1_000_000, 0);
        let (code, msg) = rawtx::get_raw_transaction(&cs, &pool, &missing, false, 0, None).unwrap_err();
        assert_eq!(code, -5, "txindex={enabled} complete={complete}");
        assert!(msg.starts_with(want), "txindex={enabled} complete={complete}: {msg}");
        assert!(msg.ends_with("Use gettransaction for wallet transactions."), "{msg}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
