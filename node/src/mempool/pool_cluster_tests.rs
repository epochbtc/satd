//! Core v31's cluster limits (`-limitclustercount`, `-limitclustersize`) on
//! admission: the cluster a transaction joins is everything connected to it
//! through spends, the transaction included.

use super::fullpool_tests::{COIN_VALUE, env, pool, prev, spend};
use super::*;
use crate::validation::script::NoopVerifier;

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

fn accept(mp: &Mempool, cs: &ChainState, tx: &Transaction) -> Result<Txid, MempoolError> {
    mp.accept_transaction(tx.clone(), cs, &NoopVerifier, TxSource::Rpc, false)
}

fn too_large(r: Result<impl std::fmt::Debug, MempoolError>) -> bool {
    matches!(r, Err(ref e) if e.state_string() == "too-large-cluster")
}

fn vsize(tx: &Transaction) -> u64 {
    policy::weight_to_vsize(tx.weight().to_wu())
}

/// A parent's children are one cluster with it. The ancestor count alone let
/// a parent take any number of them.
#[test]
fn a_parent_takes_no_more_children_than_the_cluster_count_allows() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().max_cluster_count = 3;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 3, 1);
    let share = parent.output[1].value.to_sat();
    let p = accept(&mp, &cs, &parent).expect("parent");
    let first = spend(&[out(p, 1)], share, 1_000, 1, 2);
    let second = spend(&[out(p, 2)], share, 1_000, 1, 3);
    accept(&mp, &cs, &first).expect("a cluster of two");
    accept(&mp, &cs, &second).expect("a cluster of three, at the limit");

    let third = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 1_000, 1, 4);
    assert!(too_large(mp.test_accept(&third, &cs, &NoopVerifier)));
    assert!(too_large(accept(&mp, &cs, &third)));
    assert_eq!(pool(&mp).len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The cluster reaches a transaction's other relatives through their
/// children: B's child C also spends A, so D, spending B, joins A too.
#[test]
fn the_cluster_reaches_other_parents_through_a_shared_child() {
    let (cs, mp, dir) = env(&[1, 2]);
    mp.config.write().max_cluster_count = 3;
    let a = accept(&mp, &cs, &spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1)).expect("a");
    let b_tx = spend(&[prev(2)], COIN_VALUE, 1_000, 2, 2);
    let b = accept(&mp, &cs, &b_tx).expect("b");
    let share = b_tx.output[1].value.to_sat();
    accept(&mp, &cs, &spend(&[out(a, 0), out(b, 1)], COIN_VALUE - 1_000 + share, 1_000, 1, 3))
        .expect("c joins a and b: three");

    let d = spend(&[out(b, 0)], b_tx.output[0].value.to_sat(), 1_000, 1, 4);
    assert!(too_large(accept(&mp, &cs, &d)), "d would make four, a included");

    let _ = std::fs::remove_dir_all(&dir);
}

/// At the default 64 a chain of 64 is accepted and the 65th refused: the
/// count includes the transaction itself. It used to count only its
/// ancestors, which let 65 in.
#[test]
fn a_chain_stops_at_the_cluster_count_counting_itself() {
    let (cs, mp, dir) = env(&[1]);
    assert_eq!(mp.config.read().max_cluster_count, 64);
    let mut prevout = prev(1);
    let mut value = COIN_VALUE;
    for _ in 0..64 {
        let tx = spend(&[prevout], value, 100, 1, 1);
        value -= 100;
        prevout = out(accept(&mp, &cs, &tx).expect("within the limit"), 0);
    }
    let sixty_fifth = spend(&[prevout], value, 100, 1, 1);
    assert!(too_large(mp.test_accept(&sixty_fifth, &cs, &NoopVerifier)));
    assert!(too_large(accept(&mp, &cs, &sixty_fifth)));
    assert_eq!(pool(&mp).len(), 64);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `-limitclustersize` bounds the cluster's sigop-adjusted vsize: a child
/// that would take its parent's cluster one vbyte past it is refused, and at
/// the limit it is accepted.
#[test]
fn a_cluster_is_held_to_its_size() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let p = accept(&mp, &cs, &parent).expect("parent");
    let child = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 1_000, 1, 2);
    let total = vsize(&parent) + vsize(&child);

    mp.config.write().max_cluster_vsize = total - 1;
    assert!(too_large(mp.test_accept(&child, &cs, &NoopVerifier)));
    assert!(too_large(accept(&mp, &cs, &child)));

    mp.config.write().max_cluster_vsize = total;
    accept(&mp, &cs, &child).expect("at the size limit");

    // A transaction alone can be too large for a cluster.
    let (cs2, mp2, dir2) = env(&[1]);
    mp2.config.write().max_cluster_vsize = vsize(&parent) - 1;
    assert!(too_large(accept(&mp2, &cs2, &parent)));
    let _ = std::fs::remove_dir_all(&dir2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// What a replacement evicts leaves the cluster before it is counted, as
/// Core checks the limits after `ReplacementChecks`: a parent with its one
/// child at a limit of two may still have that child replaced.
#[test]
fn a_replacement_is_counted_without_what_it_evicts() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let p = accept(&mp, &cs, &parent).expect("parent");
    let value = parent.output[0].value.to_sat();
    let child = accept(&mp, &cs, &spend(&[out(p, 0)], value, 1_000, 1, 2)).expect("child");

    let replacement = spend(&[out(p, 0)], value, 5_000, 1, 3);
    mp.test_accept(&replacement, &cs, &NoopVerifier).expect("testmempoolaccept agrees");
    let r = accept(&mp, &cs, &replacement).expect("the child it evicts does not count");
    assert_eq!(pool(&mp), HashSet::from([p, r]));
    assert!(!pool(&mp).contains(&child));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reorg's returned transaction is not held to the cluster limits: satd
/// does not trim a cluster afterwards the way Core does, so it keeps what
/// the block gave back.
#[test]
fn a_reorg_is_not_held_to_the_cluster_limits() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1);
    let share = parent.output[1].value.to_sat();
    let p = accept(&mp, &cs, &parent).expect("parent");
    accept(&mp, &cs, &spend(&[out(p, 1)], share, 1_000, 1, 2)).expect("child");

    let second = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 1_000, 1, 3);
    assert!(too_large(accept(&mp, &cs, &second)));
    mp.accept_reorged_transaction(second, &cs, &NoopVerifier).expect("a reorg skips the cluster limits");
    assert_eq!(pool(&mp).len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The exemption covers the ancestor count too: a reorg that returns a chain
/// of 65 keeps all of it. The walk refused the 65th, and every descendant
/// after it then failed for missing inputs.
#[test]
fn a_reorg_keeps_a_chain_longer_than_the_cluster_count() {
    let (cs, mp, dir) = env(&[1]);
    let mut prevout = prev(1);
    let mut value = COIN_VALUE;
    for _ in 0..66 {
        let tx = spend(&[prevout], value, 100, 1, 1);
        value -= 100;
        prevout = out(
            mp.accept_reorged_transaction(tx, &cs, &NoopVerifier).expect("a reorg skips the cluster limits"),
            0,
        );
    }
    assert_eq!(pool(&mp).len(), 66);

    let _ = std::fs::remove_dir_all(&dir);
}
