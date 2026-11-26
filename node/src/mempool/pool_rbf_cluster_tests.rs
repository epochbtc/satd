//! RBF over the clusters a replacement touches, as Core v31 compares them,
//! for the topologies the two-transaction diagrams cannot describe.

use super::fullpool_tests::{COIN_VALUE, env, pool, prev, spend};
use super::*;
use crate::validation::script::NoopVerifier;

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

fn accept(mp: &Mempool, cs: &ChainState, tx: &Transaction) -> Result<Txid, MempoolError> {
    mp.accept_transaction(tx.clone(), cs, &NoopVerifier, TxSource::Rpc, false)
}

/// `tx` with an `OP_RETURN` output carrying `bytes` of data.
fn padded(mut tx: Transaction, bytes: usize) -> Transaction {
    let data = bitcoin::script::PushBytesBuf::try_from(vec![0u8; bytes]).expect("pushable");
    tx.output.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(data),
    });
    tx
}

fn rate(tx: &Transaction, fee: u64) -> u64 {
    policy::fee_rate_sat_per_kvb(fee, tx.weight().to_wu())
}

/// `mempool_truc.py`'s `test_reorg_sibling_eviction_1p2c`, at version 2: a
/// cheap parent with two children, and a replacement of one child paying
/// more. Weighed with its cheap parent against the child alone, it lost; over
/// the parent's cluster, before and after, it improves the diagram, and Core
/// accepts it.
#[test]
fn bumping_one_of_two_children_of_a_cheap_parent_is_accepted() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1);
    let share = parent.output[1].value.to_sat();
    let p = accept(&mp, &cs, &parent).expect("parent");
    let first = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 30_000, 1, 2);
    let second = spend(&[out(p, 1)], share, 30_000, 1, 3);
    accept(&mp, &cs, &first).expect("first child");
    let s2 = accept(&mp, &cs, &second).expect("second child");

    let replacement = spend(&[out(p, 0)], parent.output[0].value.to_sat(), 45_000, 1, 4);
    // The fixture: with its parent the replacement pays less than the child
    // it replaces, which is what the per-conflict rule refused.
    let with_parent = policy::fee_rate_sat_per_kvb(
        46_000,
        replacement.weight().to_wu() + parent.weight().to_wu(),
    );
    assert!(with_parent < rate(&first, 30_000));
    mp.test_accept(&replacement, &cs, &NoopVerifier)
        .expect("testmempoolaccept agrees");
    let r = accept(&mp, &cs, &replacement).expect("the cluster's diagram improves");
    assert_eq!(pool(&mp), HashSet::from([p, r, s2]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other way: a replacement that out-pays its conflict's own feerate
/// but evicts the conflict's rich child is worse for a miner, and Core
/// refuses it. The per-conflict rule saw only the cheap conflict and let it
/// through.
#[test]
fn a_replacement_that_drops_a_rich_grandchild_is_refused() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1);
    let p = accept(&mp, &cs, &parent).expect("parent");
    let first_in = parent.output[0].value.to_sat();
    let first = spend(&[out(p, 0)], first_in, 200, 1, 2);
    let f = accept(&mp, &cs, &first).expect("a cheap child");
    let rich = spend(&[out(f, 0)], first.output[0].value.to_sat(), 22_000, 1, 3);
    accept(&mp, &cs, &rich).expect("its rich child");
    // A second child makes the topology one the pair diagrams cannot take.
    accept(
        &mp,
        &cs,
        &spend(&[out(p, 1)], parent.output[1].value.to_sat(), 1_000, 1, 4),
    )
    .expect("second child");

    // Pays every evicted fee and its relay, at a feerate above the cheap
    // child's, over many vbytes.
    let replacement = padded(spend(&[out(p, 0)], first_in, 26_000, 1, 5), 2_400);
    assert!(rate(&replacement, 26_000) > rate(&first, 200));
    let before = pool(&mp);
    let verdict = accept(&mp, &cs, &replacement);
    assert!(
        matches!(verdict, Err(MempoolError::DoesNotImproveFeerateDiagram(ref d)) if d.contains("does not improve")),
        "{verdict:?}"
    );
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Core checks the cluster limits inside `ReplacementChecks`, after the
/// fees and before the diagram, so a replacement that would grow its
/// cluster past them is `too-large-cluster` even where its diagram would
/// fail too.
#[test]
fn a_replacement_past_the_cluster_limit_is_too_large_before_its_diagram() {
    let (cs, mp, dir) = env(&[1, 2]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let p = accept(&mp, &cs, &parent).expect("parent");
    let value = parent.output[0].value.to_sat();
    accept(&mp, &cs, &spend(&[out(p, 0)], value, 1_000, 1, 2)).expect("child");
    let other = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 3);
    let o = accept(&mp, &cs, &other).expect("an unrelated transaction");

    // Replaces the child and also spends the unrelated one: three together.
    // Padded, it pays more than the child but at a lower feerate, which
    // leaves the diagram worse at its start.
    let replacement = padded(
        spend(
            &[out(p, 0), out(o, 0)],
            value + other.output[0].value.to_sat(),
            10_000,
            1,
            4,
        ),
        5_000,
    );
    let err = accept(&mp, &cs, &replacement).expect_err("refused");
    assert_eq!(err.state_string(), "too-large-cluster");
    assert_eq!(
        mp.test_accept(&replacement, &cs, &NoopVerifier)
            .expect_err("refused")
            .state_string(),
        "too-large-cluster"
    );
    // Within the limits, the diagram is what refuses it.
    mp.config.write().max_cluster_count = 64;
    assert_eq!(
        mp.test_accept(&replacement, &cs, &NoopVerifier)
            .expect_err("refused")
            .state_string(),
        "replacement-failed, insufficient feerate: does not improve feerate diagram"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The replacement is chunked with the parent it needs. Over a large
/// zero-fee parent, a large replacement pays less as a pair than the child
/// it replaces did, though alone it pays more; a miner takes the pair, and
/// Core refuses it.
#[test]
fn a_replacement_is_chunked_with_the_cheap_parent_it_spends() {
    let (cs, mp, dir) = env(&[1]);
    let parent = padded(spend(&[prev(1)], COIN_VALUE, 0, 2, 1), 900);
    let p = accept(&mp, &cs, &parent).expect("a large zero-fee parent");
    let value = parent.output[0].value.to_sat();
    accept(&mp, &cs, &spend(&[out(p, 0)], value, 10_000, 1, 2)).expect("a child that pays for it");
    accept(
        &mp,
        &cs,
        &spend(&[out(p, 1)], parent.output[1].value.to_sat(), 100, 1, 3),
    )
    .expect("a cheap child");

    let replacement = padded(spend(&[out(p, 0)], value, 10_300, 1, 4), 900);
    let before = pool(&mp);
    let verdict = accept(&mp, &cs, &replacement);
    assert!(
        matches!(verdict, Err(MempoolError::DoesNotImproveFeerateDiagram(_))),
        "{verdict:?}"
    );
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `tx` padded with an `OP_RETURN` to exactly `vsize` vbytes.
fn sized(tx: Transaction, vsize: u64) -> Transaction {
    let base = policy::weight_to_vsize(tx.weight().to_wu());
    let mut pad = (vsize - base).saturating_sub(40) as usize;
    loop {
        let t = padded(tx.clone(), pad);
        let v = policy::weight_to_vsize(t.weight().to_wu());
        if v == vsize {
            return t;
        }
        assert!(v < vsize, "cannot pad to {vsize}: {v}");
        pad += 1;
    }
}

/// A fee-only bump of a diamond's last transaction (A parents B and C, D
/// spends both) is accepted: same inputs, same size, more fee. Laid out as
/// one block, D's ancestor set chunked worse after the bump than before, and
/// the replacement was refused.
#[test]
fn a_fee_bump_of_a_diamonds_tail_is_accepted() {
    let (cs, mp, dir) = env(&[1]);
    let a = sized(spend(&[prev(1)], COIN_VALUE, 600, 2, 1), 400);
    let a_id = accept(&mp, &cs, &a).expect("a");
    let b = sized(
        spend(&[out(a_id, 0)], a.output[0].value.to_sat(), 2_600, 1, 2),
        400,
    );
    let b_id = accept(&mp, &cs, &b).expect("b");
    let c = sized(
        spend(&[out(a_id, 1)], a.output[1].value.to_sat(), 1_400, 1, 3),
        200,
    );
    let c_id = accept(&mp, &cs, &c).expect("c");
    let d_in = b.output[0].value.to_sat() + c.output[0].value.to_sat();
    let d = sized(spend(&[out(b_id, 0), out(c_id, 0)], d_in, 1_400, 1, 4), 600);
    accept(&mp, &cs, &d).expect("d");

    let bump = sized(spend(&[out(b_id, 0), out(c_id, 0)], d_in, 2_400, 1, 5), 600);
    let r = accept(&mp, &cs, &bump).expect("a fee-only bump improves the diagram");
    assert_eq!(pool(&mp), HashSet::from([a_id, b_id, c_id, r]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A fee-only bump of a tree's tail (A parents B and C, D spends B) is
/// accepted. Linearized afresh, the bump reordered the cluster into one
/// chunk that paid less at 800 vB than the original order did, and was
/// refused; merged with the old order it can only do better.
#[test]
fn a_fee_bump_that_reorders_a_cluster_is_accepted() {
    let (cs, mp, dir) = env(&[1]);
    let a = sized(spend(&[prev(1)], COIN_VALUE, 800, 2, 1), 500);
    let a_id = accept(&mp, &cs, &a).expect("a");
    let b = sized(
        spend(&[out(a_id, 0)], a.output[0].value.to_sat(), 1_800, 1, 2),
        200,
    );
    let b_id = accept(&mp, &cs, &b).expect("b");
    let c = sized(
        spend(&[out(a_id, 1)], a.output[1].value.to_sat(), 1_300, 1, 3),
        100,
    );
    let c_id = accept(&mp, &cs, &c).expect("c");
    let d_in = b.output[0].value.to_sat();
    accept(
        &mp,
        &cs,
        &sized(spend(&[out(b_id, 0)], d_in, 500, 1, 4), 500),
    )
    .expect("d");

    let bump = sized(spend(&[out(b_id, 0)], d_in, 2_400, 1, 5), 500);
    let r = accept(&mp, &cs, &bump).expect("a fee-only bump improves the diagram");
    assert_eq!(pool(&mp), HashSet::from([a_id, b_id, c_id, r]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule 5 on a single transaction: a replacement may evict 100 clusters and
/// not 101 (Core's `num_clusters > MAX_REPLACEMENT_CANDIDATES`).
#[test]
fn a_replacement_of_101_clusters_is_refused_and_of_100_is_not() {
    let tags: Vec<u8> = (1..=101).collect();
    let (cs, mp, dir) = env(&tags);
    for &t in &tags {
        accept(&mp, &cs, &spend(&[prev(t)], COIN_VALUE, 1_000, 1, t))
            .expect("one cluster per coin");
    }
    let coins: Vec<OutPoint> = tags.iter().map(|&t| prev(t)).collect();
    let before = pool(&mp);

    let all = spend(&coins, 101 * COIN_VALUE, 200_000, 1, 200);
    let verdict = accept(&mp, &cs, &all);
    assert!(
        matches!(verdict, Err(MempoolError::TooManyReplacements(ref d)) if d.ends_with("too many conflicting clusters (101 > 100)")),
        "{verdict:?}"
    );
    assert_eq!(pool(&mp), before);

    let hundred = spend(&coins[..100], 100 * COIN_VALUE, 200_000, 1, 201);
    let r = accept(&mp, &cs, &hundred).expect("100 clusters may be replaced");
    let last = spend(&[prev(101)], COIN_VALUE, 1_000, 1, 101).compute_txid();
    assert_eq!(pool(&mp), HashSet::from([r, last]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict whose parent has another child sits in a cluster of three,
/// which the pair diagrams cannot describe (Core's `CheckConflictTopology`),
/// so the replacement is judged on the cluster. There it gives up the
/// conflict's 10 sat/vB for 7.5 and is refused. Paired with the parent alone,
/// as the pair diagrams would, it looked better.
#[test]
fn a_conflict_whose_parent_has_another_child_is_judged_on_the_cluster() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = sized(spend(&[prev(1)], COIN_VALUE, 210, 2, 1), 210);
    let p = accept(&mp, &cs, &parent).expect("a cheap parent");
    let rich = sized(
        spend(&[out(p, 0)], parent.output[0].value.to_sat(), 5_000, 1, 2),
        100,
    );
    accept(&mp, &cs, &rich).expect("a rich child");
    let conflict_in = parent.output[1].value.to_sat() + COIN_VALUE;
    let conflict = sized(spend(&[out(p, 1), prev(2)], conflict_in, 2_000, 1, 3), 200);
    accept(&mp, &cs, &conflict).expect("a child that also spends a confirmed coin");

    // Spends only the confirmed coin, so it leaves the parent behind.
    let replacement = sized(spend(&[prev(2)], COIN_VALUE, 2_250, 1, 4), 300);
    assert!(rate(&replacement, 2_250) < rate(&conflict, 2_000));
    let with_parent =
        policy::fee_rate_sat_per_kvb(2_210, parent.weight().to_wu() + conflict.weight().to_wu());
    assert!(
        rate(&replacement, 2_250) > with_parent,
        "fixture: it beats the conflict paired with its parent"
    );
    let before = pool(&mp);
    let verdict = accept(&mp, &cs, &replacement);
    assert!(
        matches!(verdict, Err(MempoolError::DoesNotImproveFeerateDiagram(ref d)) if d.contains("does not improve")),
        "{verdict:?}"
    );
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A cluster of exactly 64, the cluster limit, is still linearized before
/// and after: a leaf replacement paying more at the same size improves it.
/// The per-conflict rule kept for larger clusters would have weighed the
/// replacement with its 1 sat/vB parent against the conflict alone, and
/// refused it.
#[test]
fn a_leaf_replacement_in_a_sixty_four_transaction_cluster_uses_the_diagram() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 2_000, 63, 1);
    let p = accept(&mp, &cs, &parent).expect("a parent of 63 outputs");
    let child = |vout: u32, fee: u64, tag: u8| {
        spend(
            &[out(p, vout)],
            parent.output[vout as usize].value.to_sat(),
            fee,
            1,
            tag,
        )
    };
    for vout in 0..63 {
        accept(&mp, &cs, &child(vout, 1_000, 2)).expect("a child");
    }
    let before = pool(&mp);
    assert_eq!(before.len(), crate::mempool::feefrac::MAX_CHUNKED_CLUSTER);
    let conflict = child(5, 1_000, 2);

    let replacement = child(5, 1_100, 3);
    let with_parent = policy::fee_rate_sat_per_kvb(
        3_100,
        parent.weight().to_wu() + replacement.weight().to_wu(),
    );
    assert!(
        with_parent < rate(&conflict, 1_000),
        "fixture: the per-conflict rule refuses it"
    );
    let r = accept(&mp, &cs, &replacement).expect("the cluster's diagram improves");
    let mut after = before;
    after.remove(&conflict.compute_txid());
    after.insert(r);
    assert_eq!(pool(&mp), after);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The replacement goes into the old order after every parent it spends,
/// wherever the conflict sat. Here the conflict follows the root and the
/// replacement's other parent is two places later; put ahead of that cheap,
/// heavy parent, the replacement would chunk without it and look like an
/// improvement it is not.
#[test]
fn a_replacement_whose_parent_follows_the_conflict_is_placed_after_it() {
    let (cs, mp, dir) = env(&[1]);
    let root = sized(spend(&[prev(1)], COIN_VALUE, 210, 2, 1), 210);
    let g = accept(&mp, &cs, &root).expect("root");
    let conflict = sized(
        spend(&[out(g, 0)], root.output[0].value.to_sat(), 5_000, 1, 2),
        100,
    );
    accept(&mp, &cs, &conflict).expect("a rich child of the root");
    let middle = sized(
        spend(&[out(g, 1)], root.output[1].value.to_sat(), 100, 1, 3),
        100,
    );
    let a = accept(&mp, &cs, &middle).expect("a cheap child of the root");
    let heavy = sized(
        spend(&[out(a, 0)], middle.output[0].value.to_sat(), 0, 1, 4),
        1_000,
    );
    let h = accept(&mp, &cs, &heavy).expect("a heavy, free grandchild");

    let r_in = root.output[0].value.to_sat() + heavy.output[0].value.to_sat();
    let replacement = sized(spend(&[out(g, 0), out(h, 0)], r_in, 10_000, 1, 5), 200);
    let before = pool(&mp);
    let verdict = accept(&mp, &cs, &replacement);
    assert!(
        matches!(verdict, Err(MempoolError::DoesNotImproveFeerateDiagram(ref d)) if d.contains("does not improve")),
        "{verdict:?}"
    );
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}
