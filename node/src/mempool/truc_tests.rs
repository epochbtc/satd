//! The TRUC checks over a hand-built mempool, for the package shapes Core's
//! `mempool_truc.py` puts through `testmempoolaccept`.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
use std::collections::HashMap;

#[derive(Default)]
struct Pool(HashMap<Txid, Transaction>);

impl Pool {
    fn with(txs: &[&Transaction]) -> Self {
        Pool(txs.iter().map(|t| (t.compute_txid(), (*t).clone())).collect())
    }

    fn parents(&self, tx: &Transaction) -> Vec<Txid> {
        let mut out = Vec::new();
        for i in &tx.input {
            let p = i.previous_output.txid;
            if self.0.contains_key(&p) && !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }
}

impl TrucView for Pool {
    fn mempool_tx(&self, txid: &Txid) -> Option<&Transaction> {
        self.0.get(txid)
    }

    fn ancestor_count(&self, txid: &Txid, cap: usize) -> usize {
        let Some(tx) = self.0.get(txid) else { return 0 };
        let mut n = 1;
        for p in self.parents(tx) {
            n += self.ancestor_count(&p, cap);
        }
        n.min(cap)
    }

    fn descendants(&self, txid: &Txid, cap: usize) -> Vec<Txid> {
        let mut out: Vec<Txid> = Vec::new();
        for (t, tx) in &self.0 {
            if tx.input.iter().any(|i| i.previous_output.txid == *txid) {
                out.push(*t);
                out.extend(self.descendants(t, cap));
            }
        }
        out.truncate(cap);
        out
    }
}

fn tx(version: i32, spends: &[(Txid, u32)], outs: usize, tag: u8) -> Transaction {
    let input = if spends.is_empty() {
        vec![(Txid::from_byte_array([tag; 32]), 0)]
    } else {
        spends.to_vec()
    };
    Transaction {
        version: bitcoin::transaction::Version(version),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: input
            .iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint { txid: *txid, vout: *vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..outs)
            .map(|_| TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() })
            .collect(),
    }
}

fn id(tx: &Transaction) -> String {
    format!("{} (wtxid={})", tx.compute_txid(), tx.compute_wtxid())
}

/// Every member's package check, as a multi-transaction evaluation runs
/// them: the first refusal.
fn package(pool: &Pool, txs: &[&Transaction]) -> Option<String> {
    txs.iter().find_map(|t| package_truc_checks(pool, t, 100, txs, &pool.parents(t)))
}

#[test]
fn versions_are_checked_within_the_package() {
    let none = Pool::default();
    let plain = tx(2, &[], 1, 1);
    let truc = tx(3, &[], 1, 2);
    let truc_from_plain = tx(3, &[(plain.compute_txid(), 0)], 1, 3);
    let plain_from_truc = tx(2, &[(truc.compute_txid(), 0)], 1, 4);

    // Unrelated transactions of both versions are fine together.
    assert_eq!(package(&none, &[&plain, &truc]), None);
    assert_eq!(
        package(&none, &[&plain, &truc_from_plain]),
        Some(format!("version=3 tx {} cannot spend from non-version=3 tx {}", id(&truc_from_plain), id(&plain)))
    );
    assert_eq!(
        package(&none, &[&truc, &plain_from_truc]),
        Some(format!("non-version=3 tx {} cannot spend from version=3 tx {}", id(&plain_from_truc), id(&truc)))
    );
}

#[test]
fn a_parent_has_one_child_within_the_package() {
    let none = Pool::default();
    let parent = tx(3, &[], 2, 1);
    let first = tx(3, &[(parent.compute_txid(), 0)], 1, 2);
    let second = tx(3, &[(parent.compute_txid(), 1)], 1, 3);
    let unrelated = tx(3, &[], 1, 4);
    let exceeds = Some(format!("tx {} would exceed descendant count limit", id(&parent)));

    assert_eq!(package(&none, &[&parent, &first, &second]), exceeds);
    // An unrelated member is not taken for a second child, nor does it hide
    // one.
    assert_eq!(package(&none, &[&parent, &first, &unrelated]), None);
    assert_eq!(package(&none, &[&parent, &first, &second, &unrelated]), exceeds);
    // The same with the parent already in the mempool.
    let resident = Pool::with(&[&parent]);
    assert_eq!(package(&resident, &[&first, &second]), exceeds);
}

#[test]
fn a_grandchild_is_refused_within_the_package() {
    let none = Pool::default();
    let parent = tx(3, &[], 1, 1);
    let child = tx(3, &[(parent.compute_txid(), 0)], 1, 2);
    let grandchild = tx(3, &[(child.compute_txid(), 0)], 1, 3);

    assert_eq!(
        package(&none, &[&parent, &child, &grandchild]),
        Some(format!("tx {} would have too many ancestors", id(&grandchild)))
    );
}

#[test]
fn a_child_of_a_parent_with_a_mempool_child_exceeds_the_limit() {
    let parent = tx(3, &[], 2, 1);
    let resident_child = tx(3, &[(parent.compute_txid(), 0)], 1, 2);
    let pool = Pool::with(&[&parent, &resident_child]);
    let second = tx(3, &[(parent.compute_txid(), 1)], 1, 3);

    assert_eq!(
        package(&pool, &[&second]),
        Some(format!("tx {} would exceed descendant count limit", id(&parent)))
    );
    // On its own the same child is offered the sibling to evict.
    let single = single_truc_checks(&pool, &second, 100, &pool.parents(&second), &HashSet::new());
    assert_eq!(single.map(|f| f.sibling), Some(Some(resident_child.compute_txid())));
}

#[test]
fn no_sibling_is_offered_when_the_sibling_has_a_parent_of_its_own() {
    // A reorg can leave the sibling with a second unconfirmed parent.
    let parent = tx(3, &[], 2, 1);
    let other = tx(3, &[], 1, 2);
    let sibling = tx(3, &[(parent.compute_txid(), 0), (other.compute_txid(), 0)], 1, 3);
    let pool = Pool::with(&[&parent, &other, &sibling]);
    let second = tx(3, &[(parent.compute_txid(), 1)], 1, 4);

    let single = single_truc_checks(&pool, &second, 100, &pool.parents(&second), &HashSet::new())
        .expect("refused");
    assert_eq!(single.sibling, None);
    assert_eq!(single.detail, format!("tx {} would exceed descendant count limit", id(&parent)));
}

#[test]
fn non_truc_transactions_are_held_only_to_the_version_boundary() {
    let parent = tx(2, &[], 2, 1);
    let first = tx(2, &[(parent.compute_txid(), 0)], 1, 2);
    let pool = Pool::with(&[&parent, &first]);
    let second = tx(2, &[(parent.compute_txid(), 1)], 1, 3);

    assert_eq!(single_truc_checks(&pool, &second, 50_000, &pool.parents(&second), &HashSet::new()), None);
    assert_eq!(package(&pool, &[&second]), None);
}
