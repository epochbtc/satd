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
    tx.output.push(TxOut { value: bitcoin::Amount::ZERO, script_pubkey: ScriptBuf::new_op_return(data) });
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
    mp.test_accept(&replacement, &cs, &NoopVerifier).expect("testmempoolaccept agrees");
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
    accept(&mp, &cs, &spend(&[out(p, 1)], parent.output[1].value.to_sat(), 1_000, 1, 4)).expect("second child");

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

/// Core checks the cluster limits inside the replacement checks
/// (`CalculateChunksForRBF`), so a replacement that would grow its cluster
/// past them is `replacement-failed, cluster size limit exceeded`, not
/// `too-large-cluster`.
#[test]
fn a_replacement_past_the_cluster_limit_fails_as_a_replacement() {
    let (cs, mp, dir) = env(&[1, 2]);
    mp.config.write().max_cluster_count = 2;
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let p = accept(&mp, &cs, &parent).expect("parent");
    let value = parent.output[0].value.to_sat();
    accept(&mp, &cs, &spend(&[out(p, 0)], value, 1_000, 1, 2)).expect("child");
    let other = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 3);
    let o = accept(&mp, &cs, &other).expect("an unrelated transaction");

    // Replaces the child and also spends the unrelated one: three together.
    let replacement =
        spend(&[out(p, 0), out(o, 0)], value + other.output[0].value.to_sat(), 10_000, 1, 4);
    let err = accept(&mp, &cs, &replacement).expect_err("refused");
    assert_eq!(err.state_string(), "replacement-failed, cluster size limit exceeded");
    assert_eq!(
        mp.test_accept(&replacement, &cs, &NoopVerifier).expect_err("refused").state_string(),
        "replacement-failed, cluster size limit exceeded"
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
    accept(&mp, &cs, &spend(&[out(p, 1)], parent.output[1].value.to_sat(), 100, 1, 3)).expect("a cheap child");

    let replacement = padded(spend(&[out(p, 0)], value, 10_300, 1, 4), 900);
    let before = pool(&mp);
    let verdict = accept(&mp, &cs, &replacement);
    assert!(matches!(verdict, Err(MempoolError::DoesNotImproveFeerateDiagram(_))), "{verdict:?}");
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}
