//! Reload order: a `mempool.dat` record is never re-admitted before a parent
//! that is in the same file, whatever the records' one-second `time` values
//! say and whatever order the file was written in.

use super::tests::{dummy_tx, frame, funded, funded_spend, p2wpkh};
use super::*;
use crate::validation::script::NoopVerifier;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// A spend of every listed outpoint of `parents`, paying `fee` and splitting
/// what is left over `outputs` outputs.
fn spend(parents: &[(&Transaction, u32)], fee: u64, outputs: usize) -> Transaction {
    let value: u64 = parents.iter().map(|(p, v)| p.output[*v as usize].value.to_sat()).sum();
    let each = (value - fee) / outputs as u64;
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: parents
            .iter()
            .map(|(p, v)| TxIn {
                previous_output: OutPoint { txid: p.compute_txid(), vout: *v },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..outputs)
            .map(|i| TxOut { value: Amount::from_sat(each), script_pubkey: p2wpkh(0x40 + i as u8) })
            .collect(),
    }
}

/// Eight generations off the coin for tag 1: a two-output root, two
/// children of it, a grandchild spending both children, then a chain of
/// four more. Returned parent-first.
fn family() -> Vec<Transaction> {
    let mut root = funded_spend(1, 1_000);
    let half = root.output[0].value.to_sat() / 2;
    root.output = vec![
        TxOut { value: Amount::from_sat(half), script_pubkey: p2wpkh(0x21) },
        TxOut { value: Amount::from_sat(half), script_pubkey: p2wpkh(0x22) },
    ];
    let a = spend(&[(&root, 0)], 1_000, 1);
    let b = spend(&[(&root, 1)], 1_000, 1);
    let mut txs = vec![root.clone(), a.clone(), b.clone()];
    let mut last = spend(&[(&a, 0), (&b, 0)], 1_000, 1);
    txs.push(last.clone());
    for _ in 0..4 {
        last = spend(&[(&last, 0)], 1_000, 1);
        txs.push(last.clone());
    }
    txs
}

/// A fresh pool under the same policy `funded` sets, standing in for the
/// pool of the restarted node.
fn restarted_pool() -> Mempool {
    let mp = Mempool::new(1_000_000, 0);
    mp.reload_policy(crate::mempool::pool::MempoolConfig {
        max_size_bytes: 1_000_000,
        min_fee_rate: 0,
        ..Default::default()
    });
    mp
}

/// Panics unless every record whose parent is also in `txs` comes after it.
fn assert_parent_first(txs: &[Transaction]) {
    let pos: std::collections::HashMap<bitcoin::Txid, usize> =
        txs.iter().enumerate().map(|(i, t)| (t.compute_txid(), i)).collect();
    for (i, tx) in txs.iter().enumerate() {
        for input in &tx.input {
            if let Some(&p) = pos.get(&input.previous_output.txid) {
                assert!(p < i, "record {i} comes before its parent at record {p}");
            }
        }
    }
}

#[test]
fn dump_writes_same_second_parents_before_children_and_all_reload() {
    // Every entry shares one second, so `time` cannot order them. The file
    // must still be parent-first, and a restart must keep the whole family.
    let (cs, mp, dir) = funded(&[1], 0);
    let then = crate::time::now_secs() - 60;
    let txs = family();
    for tx in &txs {
        mp.accept_persisted_transaction(tx.clone(), &cs, &NoopVerifier, then)
            .expect("the family is admissible parent-first");
    }
    assert_eq!(dump_mempool(&mp, &dir).unwrap(), txs.len());

    let written = parse(&std::fs::read(dir.join("mempool.dat")).unwrap()).unwrap();
    let written: Vec<Transaction> = written.records.into_iter().map(|r| r.tx).collect();
    assert_eq!(written.len(), txs.len());
    assert_parent_first(&written);

    let fresh = restarted_pool();
    let stats = load_mempool(&fresh, &cs, &NoopVerifier, &dir).unwrap();
    assert_eq!((stats.accepted, stats.skipped, stats.expired), (txs.len(), 0, 0));
    for tx in &txs {
        assert_eq!(fresh.get(&tx.compute_txid()).expect("re-admitted").time, then);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_admits_a_file_written_children_first() {
    // The shape an older satd could write: children ahead of their parents,
    // all in the same second. Every record is still re-admitted.
    let (cs, mp, dir) = funded(&[1], 0);
    let then = crate::time::now_secs() - 60;
    let txs = family();
    let records: Vec<(u64, i64, Transaction)> =
        txs.iter().rev().map(|tx| (then, 0, tx.clone())).collect();
    std::fs::write(dir.join("mempool.dat"), frame(&records)).unwrap();

    let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
    assert_eq!((stats.accepted, stats.skipped, stats.expired), (txs.len(), 0, 0));
    for tx in &txs {
        assert!(mp.get(&tx.compute_txid()).is_some(), "every generation is re-admitted");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_admits_a_parent_stamped_later_than_its_child() {
    // A dependency in the file outranks the times: the child's earlier
    // stamp does not put it ahead of its parent.
    let (cs, mp, dir) = funded(&[1], 0);
    let now = crate::time::now_secs();
    let parent = funded_spend(1, 1_000);
    let child = spend(&[(&parent, 0)], 1_000, 1);
    std::fs::write(
        dir.join("mempool.dat"),
        frame(&[(now - 50, 0, parent.clone()), (now - 90, 0, child.clone())]),
    )
    .unwrap();

    let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
    assert_eq!((stats.accepted, stats.skipped), (2, 0));
    assert_eq!(mp.get(&parent.compute_txid()).expect("parent").time, now - 50);
    assert_eq!(mp.get(&child.compute_txid()).expect("child").time, now - 90);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_still_skips_a_child_whose_parent_is_missing() {
    // The reordering only moves records; it admits nothing new. A child of
    // a transaction that is neither in the file nor confirmed is skipped,
    // and an unrelated record beside it is admitted.
    let (cs, mp, dir) = funded(&[1, 2], 0);
    let then = crate::time::now_secs() - 60;
    let absent_parent = funded_spend(1, 1_000);
    let orphan = spend(&[(&absent_parent, 0)], 1_000, 1);
    let other = funded_spend(2, 1_000);
    std::fs::write(
        dir.join("mempool.dat"),
        frame(&[(then, 0, orphan.clone()), (then, 0, other.clone())]),
    )
    .unwrap();

    let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
    assert_eq!((stats.accepted, stats.skipped), (1, 1));
    assert!(mp.get(&orphan.compute_txid()).is_none());
    assert!(mp.get(&other.compute_txid()).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parent_first_order_keeps_unrelated_records_in_place() {
    // No in-set links: the order is the input order, so the oldest-first
    // sort ahead of it survives.
    let txs: Vec<Transaction> = (1..=5).map(dummy_tx).collect();
    assert_eq!(parent_first_order(txs.iter()), vec![0, 1, 2, 3, 4]);
}

#[test]
fn parent_first_order_reorders_a_reversed_family() {
    let mut txs = family();
    txs.reverse();
    let order = parent_first_order(txs.iter());
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..txs.len()).collect::<Vec<_>>(), "a permutation");
    assert_parent_first(&permute(txs, &order));
}

#[test]
fn parent_first_order_handles_a_long_reversed_chain_and_duplicates() {
    // Depth is walked on the heap, not the call stack, and a repeated
    // record is kept rather than dropped.
    let mut txs = vec![dummy_tx(7)];
    for _ in 0..20_000 {
        let last = txs.last().unwrap().clone();
        let mut next = dummy_tx(7);
        next.input[0].previous_output = OutPoint { txid: last.compute_txid(), vout: 0 };
        txs.push(next);
    }
    txs.push(txs[3].clone());
    txs.reverse();
    let order = parent_first_order(txs.iter());
    assert_eq!(order.len(), txs.len());
    let ordered = permute(txs, &order);
    // The duplicate links to nothing new; drop it before the parent check.
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<Transaction> =
        ordered.into_iter().filter(|t| seen.insert(t.compute_txid())).collect();
    assert_eq!(unique.len(), 20_001);
    assert_parent_first(&unique);
}
