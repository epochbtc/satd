//! A multi-transaction `testmempoolaccept` ([`Mempool::test_accept_package`])
//! judged as Core's `AcceptMultipleTransactions` does with
//! `PackageTestAccept`, through the cases of `mempool_truc.py` and
//! `rpc_packages.py`.

use super::fullpool_tests::{COIN_VALUE, env, prev, spend};
use super::*;
use crate::validation::script::NoopVerifier;

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

fn v3(mut tx: Transaction) -> Transaction {
    tx.version = bitcoin::transaction::Version(3);
    tx
}

fn id(tx: &Transaction) -> String {
    format!("{} (wtxid={})", tx.compute_txid(), tx.compute_wtxid())
}

fn test(mp: &Mempool, cs: &ChainState, txs: &[&Transaction]) -> PackageTestResult {
    let owned: Vec<Transaction> = txs.iter().map(|t| (*t).clone()).collect();
    mp.test_accept_package(&owned, cs, &NoopVerifier, &|_| false)
}

fn allowed(r: &PackageTestResult, tx: &Transaction) -> bool {
    matches!(r.results.get(&tx.compute_wtxid()), Some(Ok(_)))
}

fn refusal(r: &PackageTestResult, tx: &Transaction) -> Option<String> {
    match r.results.get(&tx.compute_wtxid()) {
        Some(Err(e)) => Some(e.state_string()),
        _ => None,
    }
}

fn judged(r: &PackageTestResult, tx: &Transaction) -> bool {
    r.results.contains_key(&tx.compute_wtxid())
}

/// A member may spend an earlier one: each was refused `missing-inputs`
/// when judged against the mempool alone.
#[test]
fn a_member_may_spend_an_earlier_one() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 1_000, 1, 2);
    let grandchild = spend(&[out(child.compute_txid(), 0)], child.output[0].value.to_sat(), 1_000, 1, 3);

    let r = test(&mp, &cs, &[&parent, &child, &grandchild]);
    assert_eq!(r.package_error, None);
    for tx in [&parent, &child, &grandchild] {
        assert!(allowed(&r, tx), "{:?}", refusal(&r, tx));
    }
    assert!(mp.inner.read().entries.is_empty(), "a test admits nothing");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The TRUC package checks refuse the package as a whole: the refusal is
/// every member's `package-error`, and no member has a result.
#[test]
fn a_truc_violation_is_a_package_error() {
    let (cs, mp, dir) = env(&[1, 2]);
    let plain = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let truc_from_plain = v3(spend(&[out(plain.compute_txid(), 0)], plain.output[0].value.to_sat(), 1_000, 1, 2));
    let r = test(&mp, &cs, &[&plain, &truc_from_plain]);
    assert_eq!(
        r.package_error,
        Some(format!(
            "TRUC-violation, version=3 tx {} cannot spend from non-version=3 tx {}",
            id(&truc_from_plain),
            id(&plain)
        ))
    );
    assert!(r.results.is_empty());

    // Two children of one parent, and an unrelated member that neither
    // counts as a child nor hides one.
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 3));
    let share = parent.output[1].value.to_sat();
    let first = v3(spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 1_000, 1, 4));
    let second = v3(spend(&[out(parent.compute_txid(), 1)], share, 1_000, 1, 5));
    let unrelated = v3(spend(&[prev(2)], COIN_VALUE, 1_000, 1, 6));
    let exceeds = Some(format!("TRUC-violation, tx {} would exceed descendant count limit", id(&parent)));
    assert_eq!(test(&mp, &cs, &[&parent, &first, &second, &unrelated]).package_error, exceeds);
    let r = test(&mp, &cs, &[&parent, &first, &unrelated]);
    assert_eq!(r.package_error, None);
    assert!(allowed(&r, &unrelated));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A member's own TRUC check runs with sibling eviction off, and its refusal
/// ends the evaluation with that member's error.
#[test]
fn a_member_may_not_evict_a_sibling() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let p = mp.accept_transaction(parent.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("parent");
    let share = parent.output[1].value.to_sat();
    mp.accept_transaction(v3(spend(&[out(p, 0)], parent.output[0].value.to_sat(), 1_000, 1, 2)), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("resident child");

    let sibling = v3(spend(&[out(p, 1)], share, 20_000, 1, 3));
    let unrelated = v3(spend(&[prev(2)], COIN_VALUE, 1_000, 1, 4));
    let r = test(&mp, &cs, &[&sibling, &unrelated]);
    assert_eq!(r.package_error, None);
    assert_eq!(
        refusal(&r, &sibling),
        Some(format!("TRUC-violation, tx {} would exceed descendant count limit", id(&parent)))
    );
    assert!(!judged(&r, &unrelated), "the rest are not judged");
    // Alone, the same transaction may evict its sibling.
    mp.test_accept(&sibling, &cs, &NoopVerifier).expect("single testmempoolaccept allows sibling eviction");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Replacement is off: a member that conflicts with the mempool is
/// `bip125-replacement-disallowed`.
#[test]
fn a_member_may_not_replace() {
    let (cs, mp, dir) = env(&[1, 2]);
    mp.accept_transaction(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("resident");
    let other = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2);
    let conflict = spend(&[prev(1)], COIN_VALUE, 50_000, 1, 3);
    let r = test(&mp, &cs, &[&other, &conflict]);
    assert_eq!(refusal(&r, &conflict).as_deref(), Some("bip125-replacement-disallowed"));
    // Core records a success only after the scripts, which nothing reached.
    assert!(!judged(&r, &other));
    mp.test_accept(&conflict, &cs, &NoopVerifier).expect("alone it replaces");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The cluster limits hold over the package and its mempool relatives
/// together, as a package-wide refusal.
#[test]
fn the_cluster_limits_cover_the_package() {
    let (cs, mp, dir) = env(&[1, 2]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 1_000, 1, 2);
    let grandchild = spend(&[out(child.compute_txid(), 0)], child.output[0].value.to_sat(), 1_000, 1, 3);
    let r = test(&mp, &cs, &[&parent, &child, &grandchild]);
    assert_eq!(r.package_error.as_deref(), Some("too-large-cluster"));
    assert!(r.results.is_empty());
    assert_eq!(test(&mp, &cs, &[&parent, &child]).package_error, None);

    // With the parent in the mempool, the package's two make three.
    let p = mp.accept_transaction(parent.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("parent");
    assert_eq!(p, parent.compute_txid());
    assert_eq!(test(&mp, &cs, &[&child, &grandchild]).package_error.as_deref(), Some("too-large-cluster"));
    // Unrelated members are clusters of their own.
    let lone = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 4);
    assert_eq!(test(&mp, &cs, &[&child, &lone]).package_error, None);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child must spend every dust output of a parent in the package.
#[test]
fn a_child_must_spend_its_parents_dust() {
    let (cs, mp, dir) = env(&[1]);
    // Zero fee and one dust output: Core's ephemeral dust parent.
    let mut parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 1);
    parent.output[0].value = bitcoin::Amount::from_sat(COIN_VALUE - 100);
    parent.output.push(TxOut { value: bitcoin::Amount::from_sat(100), script_pubkey: parent.output[0].script_pubkey.clone() });
    let p = parent.compute_txid();
    let around = spend(&[out(p, 0)], COIN_VALUE - 100, 1_000, 1, 2);
    let sweeps = spend(&[out(p, 0), out(p, 1)], COIN_VALUE, 1_000, 1, 3);

    let r = test(&mp, &cs, &[&parent, &around]);
    assert_eq!(r.package_error, None);
    assert_eq!(
        refusal(&r, &around),
        Some(format!("missing-ephemeral-spends, tx {} did not spend parent's ephemeral dust", id(&around)))
    );
    assert!(!judged(&r, &parent), "a dust failure leaves the rest unjudged");
    let r = test(&mp, &cs, &[&parent, &sweeps]);
    assert!(allowed(&r, &parent) && allowed(&r, &sweeps), "{:?}", refusal(&r, &sweeps));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Members are judged by their own feerates: a zero-fee parent is refused
/// for its fee, whatever its child pays.
#[test]
fn members_are_judged_by_their_own_feerates() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().min_fee_rate = 1_000;
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 20_000, 1, 2);
    let r = test(&mp, &cs, &[&parent, &child]);
    assert!(refusal(&r, &parent).unwrap().starts_with("min relay fee not met"));
    assert!(!judged(&r, &child));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A member whose outputs are already coins is `txn-already-known`.
#[test]
fn an_already_known_member_ends_the_evaluation() {
    let (cs, mp, dir) = env(&[1, 2]);
    let a = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let b = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2);
    let a_wtxid = a.compute_wtxid();
    let r = mp.test_accept_package(&[a.clone(), b.clone()], &cs, &NoopVerifier, &|t| t.compute_wtxid() == a_wtxid);
    assert_eq!(refusal(&r, &a).as_deref(), Some("txn-already-known"));
    assert!(!judged(&r, &b));

    let _ = std::fs::remove_dir_all(&dir);
}
