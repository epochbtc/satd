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

/// A reorg's returned transaction is held to the cluster limits, as Core
/// holds it whatever `bypass_limits` says. satd let it past them, having no
/// trim to cut the cluster back afterwards.
#[test]
fn a_reorg_returns_a_transaction_only_within_the_cluster_limits() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1);
    let share = parent.output[1].value.to_sat();
    let p = accept(&mp, &cs, &parent).expect("parent");
    accept(&mp, &cs, &spend(&[out(p, 1)], share, 1_000, 1, 2)).expect("child");

    let second = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 1_000, 1, 3);
    assert!(too_large(mp.accept_reorged_transaction(second, &cs, &NoopVerifier)));
    assert_eq!(pool(&mp).len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reorg that returns a chain of 66 keeps 64: the 65th is past the
/// cluster count and the 66th has lost its parent. Core's
/// `mempool_packages.py` expects this of a node at a lower limit.
#[test]
fn a_reorg_returns_a_chain_up_to_the_cluster_count() {
    let (cs, mp, dir) = env(&[1]);
    let mut prevout = prev(1);
    let mut value = COIN_VALUE;
    let mut results = Vec::new();
    for _ in 0..66 {
        let tx = spend(&[prevout], value, 100, 1, 1);
        value -= 100;
        prevout = out(tx.compute_txid(), 0);
        results.push(mp.accept_reorged_transaction(tx, &cs, &NoopVerifier));
    }
    assert!(results[..64].iter().all(|r| r.is_ok()));
    assert!(matches!(results[64], Err(ref e) if e.state_string() == "too-large-cluster"));
    assert!(matches!(results[65], Err(MempoolError::MissingInputs)));
    assert_eq!(pool(&mp).len(), 64);

    let _ = std::fs::remove_dir_all(&dir);
}

/// After a reorg, a cluster its returned transactions share with the
/// mempool's spenders is cut back to the limits, and what is cut leaves as
/// a reorg eviction. Here the limit is lowered after the fact, which gives
/// the same cluster a reorg would: a returned root with a chain of spenders
/// past the count.
#[test]
fn a_reorg_trims_a_cluster_its_spenders_take_past_the_limit() {
    let (cs, mp, dir) = env(&[1]);
    let root = spend(&[prev(1)], COIN_VALUE, 5_000, 1, 1);
    let r = accept(&mp, &cs, &root).expect("root");
    let mut prevout = out(r, 0);
    let mut value = root.output[0].value.to_sat();
    let mut chain = Vec::new();
    for _ in 0..4 {
        let tx = spend(&[prevout], value, 1_000, 1, 1);
        value -= 1_000;
        let t = accept(&mp, &cs, &tx).expect("spender");
        prevout = out(t, 0);
        chain.push(t);
    }
    mp.config.write().max_cluster_count = 3;
    let (sender, mut rx) = tokio::sync::broadcast::channel(16);
    mp.set_event_sender(sender);

    mp.trim_reorged_clusters(&[r]);

    assert_eq!(pool(&mp), HashSet::from([r, chain[0], chain[1]]));
    let mut gone = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let MempoolEvent::LeaveEvicted { txid, reason, .. } = event {
            assert_eq!(reason, EvictReason::Reorg);
            gone.push(txid);
        }
    }
    gone.sort();
    let mut expected = vec![chain[2], chain[3]];
    expected.sort();
    assert_eq!(gone, expected);

    // A cluster within the limits, or none returned, is left alone.
    mp.trim_reorged_clusters(&[r]);
    mp.trim_reorged_clusters(&[]);
    assert_eq!(pool(&mp).len(), 3);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `getrawmempool` lists in mining order, the same whatever order the
/// transactions arrived in: a reorg that puts the same set back gives the
/// same list, which Core's `mempool_packages.py` checks.
#[test]
fn the_mining_order_does_not_depend_on_arrival() {
    let (cs, mp, dir) = env(&[1, 2, 3]);
    let (cs2, mp2, dir2) = env(&[1, 2, 3]);
    let cheap_parent = spend(&[prev(1)], COIN_VALUE, 500, 1, 1);
    let rich_child = spend(&[out(cheap_parent.compute_txid(), 0)], cheap_parent.output[0].value.to_sat(), 20_000, 1, 2);
    let middling = spend(&[prev(2)], COIN_VALUE, 5_000, 1, 3);
    let poor = spend(&[prev(3)], COIN_VALUE, 300, 1, 4);
    for tx in [&cheap_parent, &rich_child, &middling, &poor] {
        accept(&mp, &cs, tx).expect("in order");
    }
    for tx in [&poor, &middling, &cheap_parent, &rich_child] {
        accept(&mp2, &cs2, tx).expect("another order");
    }
    let order = mp.acting_txids_in_mining_order();
    assert_eq!(order, mp2.acting_txids_in_mining_order());
    // The child pays for its parent, so they come first, together.
    let txid = |t: &Transaction| t.compute_txid();
    assert_eq!(order, vec![txid(&cheap_parent), txid(&rich_child), txid(&middling), txid(&poor)]);
    let listed = crate::rpc::rawtx::get_raw_mempool(&mp, false);
    let listed: Vec<Txid> = listed.as_array().expect("a list").iter().map(|v| v.as_str().unwrap().parse().unwrap()).collect();
    assert_eq!(listed, order);
    assert_eq!(mp.acting_txids_with_sequence().0, order);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// The cluster check of a reorg's returned transaction does not step from
/// an earlier returned one to the mempool transactions already spending it,
/// as Core links those only after the whole reorg is offered. Counting them
/// refused a high-fee child of a returned parent and kept the parent's
/// cheaper mempool spenders; the trim keeps the child instead.
#[test]
fn a_returned_child_is_checked_without_its_parents_mempool_spenders() {
    let (cs, mp, dir) = env(&[1]);
    mp.config.write().max_cluster_count = 3;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1);
    let share = parent.output[1].value.to_sat();
    let r = accept(&mp, &cs, &parent).expect("the returned parent");
    let a_tx = spend(&[out(r, 1)], share, 1_000, 1, 2);
    let a = accept(&mp, &cs, &a_tx).expect("a mempool spender");
    let b = accept(&mp, &cs, &spend(&[out(a, 0)], a_tx.output[0].value.to_sat(), 1_000, 1, 3)).expect("its child");
    let child = spend(&[out(r, 0)], parent.output[0].value.to_sat(), 20_000, 1, 4);

    // Without the reorg's returned set, the walk counts a and b.
    assert!(too_large(mp.accept_reorged_transaction(child.clone(), &cs, &NoopVerifier)));

    let mut returned = HashSet::from([r]);
    let s = mp.accept_reorged_with(child, &cs, &NoopVerifier, &mut returned).expect("checked as Core checks it");
    assert_eq!(returned, HashSet::from([r, s]));

    mp.trim_reorged_clusters(&[r, s]);
    assert_eq!(pool(&mp), HashSet::from([r, s, a]));
    assert!(!pool(&mp).contains(&b));

    let _ = std::fs::remove_dir_all(&dir);
}
