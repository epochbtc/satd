//! The notifier's pushed status against Electrum history order.
//!
//! A client checks a pushed status by hashing `get_history` in the order it
//! arrived, so the status has to cover confirmed rows by height and block
//! position, then mempool rows with height 0 before -1 and the txid in
//! display order. The fixture makes block order, `Txid`'s `Ord` and display
//! order disagree wherever the test relies on one of them.

use std::sync::Arc;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{OutPoint, Transaction, TxIn, Txid};
use parking_lot::RwLock;

use super::recompute_for;
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::{AddrFundingRowV3, Scripthash};
use crate::index::address::lookups::RocksAddressIndex;
use crate::index::address::mempool::MempoolAddrIndex;
use crate::mempool::pool::Mempool;
use crate::storage::db::InMemoryStore;
use crate::storage::{Store, StoreBatch};

/// A txid whose internal bytes start with `first` and end with `last`.
/// `Txid`'s `Ord` follows `first`; display hex is the reverse, so it follows
/// `last`.
fn txid(first: u8, last: u8) -> Txid {
    let mut b = [0u8; 32];
    b[0] = first;
    b[31] = last;
    Txid::from_byte_array(b)
}

/// Write `txs` as confirmed transactions paying `sh`, numbered in the order
/// given (which must be chain order): the ordinal families a v3 row
/// resolves through, the block rows `block_of_seq` checks, and one funding
/// row each.
fn seed_confirmed(store: &InMemoryStore, sh: Scripthash, txs: &[(u32, Txid)]) {
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};

    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let mut batch = StoreBatch::default();
    let mut blocks: std::collections::BTreeMap<u32, (u64, u32)> = Default::default();
    for (i, (height, txid)) in txs.iter().enumerate() {
        let seq = i as u64 + 1;
        batch.tx_loc_puts.push((*txid, seq));
        batch.txseq_txid_puts.push((seq, *txid));
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: seq,
            vout: 0,
            amount_sat: 1_000,
        });
        blocks
            .entry(*height)
            .and_modify(|(_, n)| *n += 1)
            .or_insert((seq, 1));
    }
    for (height, (first_txseq, num_tx)) in blocks {
        let hash = bitcoin::BlockHash::from_byte_array([height as u8; 32]);
        batch.block_index_puts.push((
            hash,
            BlockIndexEntry {
                header: genesis.header,
                height,
                status: BlockStatus::Valid,
                num_tx,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            },
        ));
        batch.height_hash_puts.push((height, hash));
        batch.txseq_block_puts.push((first_txseq, height));
    }
    store.write_batch(batch).unwrap();
}

/// A mempool transaction spending output 0 of `parent`.
fn spend_of(parent: Txid) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: parent, vout: 0 },
            ..Default::default()
        }],
        output: Vec::new(),
    }
}

#[test]
fn test_notifier_status_covers_history_in_electrum_order() {
    let sh: Scripthash = [0x5a; 32];

    // Confirmed: one tx at height 5, three in one block at height 10 whose
    // block order (p0, p1, p2) is neither their `Ord` order (p1, p2, p0)
    // nor their display order (p2, p0, p1).
    let c0 = txid(0x09, 0x09);
    let p0 = txid(0x03, 0x02);
    let p1 = txid(0x01, 0x03);
    let p2 = txid(0x02, 0x01);
    let store = Arc::new(InMemoryStore::new());
    seed_confirmed(&store, sh, &[(5, c0), (10, p0), (10, p1), (10, p2)]);

    // Mempool: `free_a` and `free_b` spend confirmed outputs (height 0),
    // `chained` spends `free_a` (height -1). `free_a` comes first by `Ord`,
    // `free_b` first by display, and `chained` first by both, so only the
    // protocol order puts them free_b, free_a, chained. `gone` is still in
    // the address mempool index but has left the mempool.
    let free_a = txid(0x01, 0x30);
    let free_b = txid(0x30, 0x10);
    let chained = txid(0x00, 0x00);
    let gone = txid(0x40, 0x40);
    let mempool = Mempool::new(8 * 1024 * 1024, 1);
    mempool.insert_entry_for_test(free_a, spend_of(c0), 111);
    mempool.insert_entry_for_test(free_b, spend_of(p0), 222);
    mempool.insert_entry_for_test(chained, spend_of(free_a), 333);
    let mut mp_index = MempoolAddrIndex::new();
    for t in [chained, gone, free_b, free_a] {
        mp_index.add_tx(t, &[(sh, 1_000)], &[]);
    }

    let index = RocksAddressIndex::with_mempool_index(
        store.clone() as Arc<dyn Store>,
        AddressIndexConfig::default(),
        Arc::new(RwLock::new(mp_index)),
    );
    let registry = index.subscription_registry();
    let mut rx = registry.subscribe(sh).unwrap();

    recompute_for(&index, &registry, &mempool, &[sh]);
    let pushed = rx.try_recv().expect("the recompute pushed a status");

    let text = format!(
        "{c0}:5:{p0}:10:{p1}:10:{p2}:10:{free_b}:0:{free_a}:0:{chained}:-1:"
    );
    let expected = sha256::Hash::hash(text.as_bytes()).to_byte_array();
    assert_eq!(
        hex::encode(pushed.status_hash),
        hex::encode(expected),
        "pushed status must be sha256 over the history in Electrum order: {text}"
    );

    // The rows `get_history` serves come from the same helper, in the same
    // order, with a fee on each mempool row.
    let rows = node_index::history_rows(&index, &sh, usize::MAX, |t| super::mempool_facts(&mempool, t))
        .unwrap();
    let got: Vec<(i64, Txid, Option<u64>)> =
        rows.iter().map(|r| (r.height, r.txid, r.fee_sat)).collect();
    assert_eq!(
        got,
        vec![
            (5, c0, None),
            (10, p0, None),
            (10, p1, None),
            (10, p2, None),
            (0, free_b, Some(222)),
            (0, free_a, Some(111)),
            (-1, chained, Some(333)),
        ]
    );
}
