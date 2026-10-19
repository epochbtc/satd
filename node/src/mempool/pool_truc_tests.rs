//! TRUC (BIP 431) admission, checked against Bitcoin Core's
//! `policy/truc_policy.cpp` and the cases of its `mempool_truc.py`: the size
//! limits, the one-parent-one-child topology, the version boundary, sibling
//! eviction, packages, and a reorg returning a family the rules would refuse.

use super::fullpool_tests::{COIN_VALUE, env, events, pool, prev, spend};
use super::*;
use crate::validation::script::NoopVerifier;

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
}

fn v3(mut tx: Transaction) -> Transaction {
    tx.version = bitcoin::transaction::Version(3);
    tx
}

/// `tx` with an `OP_RETURN` output carrying `bytes` of data, which adds that
/// many vbytes and a few more.
fn padded(mut tx: Transaction, bytes: usize) -> Transaction {
    let data = bitcoin::script::PushBytesBuf::try_from(vec![0u8; bytes]).expect("pushable");
    tx.output.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(data),
    });
    tx
}

fn vsize(tx: &Transaction) -> u64 {
    policy::weight_to_vsize(tx.weight().to_wu())
}

fn accept(mp: &Mempool, cs: &ChainState, tx: &Transaction) -> Result<Txid, MempoolError> {
    mp.accept_transaction(tx.clone(), cs, &NoopVerifier, TxSource::Rpc, false)
}

fn refusal(mp: &Mempool, cs: &ChainState, tx: &Transaction) -> String {
    accept(mp, cs, tx).expect_err("refused").state_string()
}

fn txids(txs: &[&Transaction]) -> HashSet<Txid> {
    txs.iter().map(|t| t.compute_txid()).collect()
}

/// [`env`] with Core's default relay floor, 1 sat/vB.
fn floor_env(tags: &[u8]) -> (ChainState, Mempool, std::path::PathBuf) {
    let (cs, mp, dir) = env(tags);
    mp.config.write().min_fee_rate = 1_000;
    (cs, mp, dir)
}

fn submit(mp: &Mempool, cs: &ChainState, txs: &[&Transaction]) -> PackageResult {
    mp.accept_package_with(txs.iter().map(|t| (*t).clone()).collect(), cs, &NoopVerifier, None)
}

fn error(r: &PackageResult, tx: &Transaction) -> String {
    r.tx_results.get(&tx.compute_wtxid().to_string()).expect("every member has a result")["error"]
        .as_str()
        .unwrap_or("<accepted>")
        .to_string()
}

fn id(tx: &Transaction) -> String {
    format!("{} (wtxid={})", tx.compute_txid(), tx.compute_wtxid())
}

/// A TRUC transaction may not exceed 10,000 vbytes; the same transaction at
/// version 2 is fine.
#[test]
fn a_truc_transaction_over_ten_thousand_vbytes_is_refused() {
    let (cs, mp, dir) = env(&[1]);
    let heavy = padded(spend(&[prev(1)], COIN_VALUE, 20_000, 1, 1), 10_000);
    assert!(vsize(&heavy) > truc::TRUC_MAX_VSIZE);
    let heavy_v3 = v3(heavy.clone());

    assert_eq!(
        refusal(&mp, &cs, &heavy_v3),
        format!(
            "TRUC-violation, version=3 tx {} is too big: {} > 10000 virtual bytes",
            id(&heavy_v3),
            vsize(&heavy_v3)
        )
    );
    assert!(pool(&mp).is_empty());

    accept(&mp, &cs, &heavy).expect("the same transaction at version 2 is not held to it");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A TRUC child may not exceed 1,000 vbytes.
#[test]
fn a_truc_child_over_a_thousand_vbytes_is_refused() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    accept(&mp, &cs, &parent).expect("parent");
    let child = v3(padded(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 2_000, 1, 2), 950));
    assert!(vsize(&child) > truc::TRUC_CHILD_MAX_VSIZE);

    assert_eq!(
        refusal(&mp, &cs, &child),
        format!("TRUC-violation, version=3 child tx {} is too big: {} > 1000 virtual bytes", id(&child), vsize(&child))
    );
    assert_eq!(pool(&mp), txids(&[&parent]));

    // Without its parent unconfirmed it is a parent itself, and fine.
    let lone = v3(padded(spend(&[prev(2)], COIN_VALUE, 2_000, 1, 2), 950));
    let (cs2, mp2, dir2) = env(&[2]);
    accept(&mp2, &cs2, &lone).expect("a transaction with no unconfirmed parent has 10,000 vbytes");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Unconfirmed, a TRUC transaction spends only TRUC, and the reverse.
#[test]
fn truc_and_non_truc_do_not_spend_each_other_unconfirmed() {
    let (cs, mp, dir) = env(&[1, 2]);
    let truc_parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let plain_parent = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2);
    accept(&mp, &cs, &truc_parent).expect("parent");
    accept(&mp, &cs, &plain_parent).expect("parent");

    let plain_child = spend(&[out(truc_parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 3);
    assert_eq!(
        refusal(&mp, &cs, &plain_child),
        format!(
            "TRUC-violation, non-version=3 tx {} cannot spend from version=3 tx {}",
            id(&plain_child),
            id(&truc_parent)
        )
    );
    let truc_child = v3(spend(&[out(plain_parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 4));
    assert_eq!(
        refusal(&mp, &cs, &truc_child),
        format!(
            "TRUC-violation, version=3 tx {} cannot spend from non-version=3 tx {}",
            id(&truc_child),
            id(&plain_parent)
        )
    );
    assert_eq!(pool(&mp), txids(&[&truc_parent, &plain_parent]));

    // Each version may spend its own.
    accept(&mp, &cs, &v3(plain_child)).expect("a TRUC child of a TRUC parent");
    let mut plain = truc_child.clone();
    plain.version = bitcoin::transaction::Version(2);
    accept(&mp, &cs, &plain).expect("a version 2 child of a version 2 parent");

    let _ = std::fs::remove_dir_all(&dir);
}

/// One unconfirmed ancestor at most: neither a grandchild nor a child of two
/// unconfirmed parents.
#[test]
fn a_truc_transaction_has_at_most_one_unconfirmed_ancestor() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let other = v3(spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2));
    let child = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 3));
    for tx in [&parent, &other, &child] {
        accept(&mp, &cs, tx).expect("admitted");
    }

    let grandchild = v3(spend(&[out(child.compute_txid(), 0)], COIN_VALUE - 2_000, 1_000, 1, 4));
    assert_eq!(
        refusal(&mp, &cs, &grandchild),
        format!("TRUC-violation, tx {} would have too many ancestors", id(&grandchild))
    );
    let two_parents = v3(spend(
        &[out(child.compute_txid(), 0), out(other.compute_txid(), 0)],
        2 * COIN_VALUE - 3_000,
        1_000,
        1,
        5,
    ));
    assert_eq!(
        refusal(&mp, &cs, &two_parents),
        format!("TRUC-violation, tx {} would have too many ancestors", id(&two_parents))
    );
    assert_eq!(pool(&mp), txids(&[&parent, &other, &child]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A second child of a TRUC parent that pays enough evicts the first under
/// the replacement rules, with no input in common.
#[test]
fn a_second_truc_child_evicts_its_sibling_when_it_pays_more() {
    let (cs, mp, dir) = env(&[1]);
    let mut rx = events(&mp);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let first = v3(spend(&[out(parent.compute_txid(), 0)], (COIN_VALUE - 1_000) / 2, 1_000, 1, 2));
    let second = v3(spend(&[out(parent.compute_txid(), 1)], (COIN_VALUE - 1_000) / 2, 3_000, 1, 3));
    for tx in [&parent, &first] {
        accept(&mp, &cs, tx).expect("admitted");
    }

    accept(&mp, &cs, &second).expect("the sibling is evicted");

    assert_eq!(pool(&mp), txids(&[&parent, &second]));
    let replaced: Vec<(Txid, Txid)> = std::iter::from_fn(|| rx.try_recv().ok())
        .filter_map(|ev| match ev {
            MempoolEvent::LeaveReplaced { txid, replacing_txid, .. } => Some((txid, replacing_txid)),
            _ => None,
        })
        .collect();
    assert_eq!(replaced, vec![(first.compute_txid(), second.compute_txid())]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A second child that does not pay for the eviction is refused, and Core
/// says the replacement included a sibling eviction.
#[test]
fn a_second_truc_child_that_pays_less_is_refused_including_sibling_eviction() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let half = (COIN_VALUE - 1_000) / 2;
    let first = v3(spend(&[out(parent.compute_txid(), 0)], half, 2_000, 1, 2));
    for tx in [&parent, &first] {
        accept(&mp, &cs, tx).expect("admitted");
    }

    // Rule 3: less than the sibling's fee.
    let cheaper = v3(spend(&[out(parent.compute_txid(), 1)], half, 1_000, 1, 3));
    let e = accept(&mp, &cs, &cheaper).expect_err("refused");
    assert_eq!(e.reject_reason(), "insufficient fee (including sibling eviction)");
    assert!(
        e.state_string().starts_with(&format!(
            "insufficient fee (including sibling eviction), rejecting replacement {}, less fees than conflicting txs",
            cheaper.compute_txid()
        )),
        "{}",
        e.state_string()
    );
    // Rule 4: one satoshi more than the sibling does not pay for its relay.
    let barely = v3(spend(&[out(parent.compute_txid(), 1)], half, 2_001, 1, 3));
    assert!(
        refusal(&mp, &cs, &barely).starts_with(&format!(
            "insufficient fee (including sibling eviction), rejecting replacement {}, not enough additional fees to relay",
            barely.compute_txid()
        )),
        "{}",
        refusal(&mp, &cs, &barely)
    );
    assert_eq!(pool(&mp), txids(&[&parent, &first]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child that replaces the parent's only child, input for input, is the
/// only child afterwards, so the limit does not count the one it replaces.
#[test]
fn a_child_replacing_the_only_child_counts_once() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let child = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 2));
    let replacement = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 3_000, 1, 3));
    for tx in [&parent, &child] {
        accept(&mp, &cs, tx).expect("admitted");
    }

    accept(&mp, &cs, &replacement).expect("an ordinary replacement");
    assert_eq!(pool(&mp), txids(&[&parent, &replacement]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A version 2 replacement of a TRUC child still may not spend the TRUC
/// parent.
#[test]
fn a_replacement_may_not_cross_the_version_boundary() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let child = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 2));
    for tx in [&parent, &child] {
        accept(&mp, &cs, tx).expect("admitted");
    }
    let plain = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 3_000, 1, 3);

    assert_eq!(
        refusal(&mp, &cs, &plain),
        format!("TRUC-violation, non-version=3 tx {} cannot spend from version=3 tx {}", id(&plain), id(&parent))
    );
    assert_eq!(pool(&mp), txids(&[&parent, &child]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// `testmempoolaccept` of one transaction allows sibling eviction as
/// `sendrawtransaction` does, and changes nothing.
#[test]
fn testmempoolaccept_allows_sibling_eviction() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let half = (COIN_VALUE - 1_000) / 2;
    let first = v3(spend(&[out(parent.compute_txid(), 0)], half, 1_000, 1, 2));
    for tx in [&parent, &first] {
        accept(&mp, &cs, tx).expect("admitted");
    }
    let second = v3(spend(&[out(parent.compute_txid(), 1)], half, 3_000, 1, 3));
    let cheaper = v3(spend(&[out(parent.compute_txid(), 1)], half, 500, 1, 4));

    mp.test_accept(&second, &cs, &NoopVerifier).expect("allowed");
    assert_eq!(
        mp.test_accept(&cheaper, &cs, &NoopVerifier).expect_err("refused").reject_reason(),
        "insufficient fee (including sibling eviction)"
    );
    let grandchild = v3(spend(&[out(first.compute_txid(), 0)], half - 1_000, 1_000, 1, 5));
    assert_eq!(
        mp.test_accept(&grandchild, &cs, &NoopVerifier).expect_err("refused").state_string(),
        format!("TRUC-violation, tx {} would have too many ancestors", id(&grandchild))
    );
    assert_eq!(pool(&mp), txids(&[&parent, &first]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reorg takes a TRUC family back as the block held it, however far past
/// the rules; the same transactions offered any other way are refused.
#[test]
fn a_reorg_returns_a_truc_family_the_rules_would_refuse() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let child = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 1_000, 1, 2));
    let grandchild = v3(spend(&[out(child.compute_txid(), 0)], COIN_VALUE - 2_000, 1_000, 1, 3));
    for tx in [&parent, &child] {
        accept(&mp, &cs, tx).expect("admitted");
    }
    assert!(matches!(accept(&mp, &cs, &grandchild), Err(MempoolError::TrucViolation(_))));

    mp.accept_reorged_transaction(grandchild.clone(), &cs, &NoopVerifier).expect("a reorg skips TRUC");
    assert_eq!(pool(&mp), txids(&[&parent, &child, &grandchild]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A reorg can leave a TRUC parent with two children. Sibling eviction then
/// has no single sibling to take, so a third child is refused; replacing one
/// of the two directly still works.
#[test]
fn a_parent_a_reorg_left_with_two_children_offers_no_sibling() {
    let (cs, mp, dir) = env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 3_000, 3, 1));
    let third_of = |tx: &Transaction| tx.output[1].value.to_sat();
    let share = third_of(&parent);
    let first = v3(spend(&[out(parent.compute_txid(), 1)], share, 1_000, 1, 2));
    let second = v3(spend(&[out(parent.compute_txid(), 2)], share, 1_000, 1, 3));
    accept(&mp, &cs, &parent).expect("parent");
    accept(&mp, &cs, &first).expect("first child");
    for tx in [&second] {
        mp.accept_reorged_transaction(tx.clone(), &cs, &NoopVerifier).expect("a reorg skips TRUC");
    }

    let third = v3(spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 20_000, 1, 4));
    assert_eq!(
        refusal(&mp, &cs, &third),
        format!("TRUC-violation, tx {} would exceed descendant count limit", id(&parent))
    );

    let first_again = v3(spend(&[out(parent.compute_txid(), 1)], share, 5_000, 1, 5));
    accept(&mp, &cs, &first_again).expect("a direct replacement of one child");
    assert_eq!(pool(&mp), txids(&[&parent, &first_again, &second]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The case TRUC exists for: a zero-fee commitment and the child that pays
/// for it.
#[test]
fn a_zero_fee_truc_parent_goes_in_with_its_child() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 1));
    let child = v3(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 1_000, 1, 2));

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(pool(&mp), txids(&[&parent, &child]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two TRUC parents and their common child, evaluated together, break the
/// ancestor limit: a package-wide refusal, with each parent keeping the
/// reason it was refused for alone.
#[test]
fn a_truc_child_of_two_package_parents_is_refused_as_a_package() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let first = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 1));
    let second = v3(spend(&[prev(2)], COIN_VALUE, 0, 1, 2));
    let child = v3(spend(
        &[out(first.compute_txid(), 0), out(second.compute_txid(), 0)],
        2 * COIN_VALUE,
        10_000,
        1,
        3,
    ));

    let r = submit(&mp, &cs, &[&first, &second, &child]);

    assert_eq!(r.package_msg, format!("TRUC-violation, tx {} would have too many ancestors", id(&child)));
    assert!(error(&r, &first).starts_with("min relay fee not met, 0 < "), "{:?}", r.tx_results);
    assert!(pool(&mp).is_empty(), "{:?}", r.tx_results);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child over 1,000 vbytes, in a package with its parent.
#[test]
fn a_heavy_truc_child_is_refused_as_a_package() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 1));
    let child = v3(padded(spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 10_000, 1, 2), 950));

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(
        r.package_msg,
        format!("TRUC-violation, version=3 child tx {} is too big: {} > 1000 virtual bytes", id(&child), vsize(&child))
    );
    assert!(pool(&mp).is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A version 2 child of a TRUC parent, in a package together.
#[test]
fn a_non_truc_child_of_a_truc_parent_is_refused_as_a_package() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 1));
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 10_000, 1, 2);

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(
        r.package_msg,
        format!("TRUC-violation, non-version=3 tx {} cannot spend from version=3 tx {}", id(&child), id(&parent))
    );
    assert!(pool(&mp).is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// With A in the mempool, the package B ← C would make A → B → C: refused,
/// naming C, though neither B nor C breaks a rule on its own terms first.
#[test]
fn a_truc_package_may_not_extend_a_mempool_parent() {
    let (cs, mp, dir) = floor_env(&[1]);
    let a = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    accept(&mp, &cs, &a).expect("A");
    let b = v3(spend(&[out(a.compute_txid(), 0)], COIN_VALUE - 1_000, 0, 1, 2));
    let c = v3(spend(&[out(b.compute_txid(), 0)], COIN_VALUE - 1_000, 10_000, 1, 3));

    let r = submit(&mp, &cs, &[&b, &c]);

    assert_eq!(r.package_msg, format!("TRUC-violation, tx {} would have too many ancestors", id(&c)));
    assert_eq!(pool(&mp), txids(&[&a]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A member evaluated with the rest of its package may not evict a sibling,
/// so a child cannot pay for its parent's sibling eviction. The member
/// carries the refusal.
#[test]
fn a_package_child_cannot_pay_for_a_sibling_eviction() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let half = parent.output[1].value.to_sat();
    let sibling = v3(spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 1_000, 1, 2));
    for tx in [&parent, &sibling] {
        accept(&mp, &cs, tx).expect("admitted");
    }
    let unpaid = v3(spend(&[out(parent.compute_txid(), 1)], half, 0, 1, 3));
    let bump = v3(spend(&[out(unpaid.compute_txid(), 0)], half, 30_000, 1, 4));

    let r = submit(&mp, &cs, &[&unpaid, &bump]);

    assert_eq!(r.package_msg, "transaction failed", "{:?}", r.tx_results);
    assert_eq!(
        error(&r, &unpaid),
        format!("TRUC-violation, tx {} would exceed descendant count limit", id(&parent))
    );
    assert_eq!(pool(&mp), txids(&[&parent, &sibling]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A member tried on its own is a single transaction, and may evict a
/// sibling; its own child is then a third generation.
#[test]
fn a_package_member_tried_alone_may_evict_a_sibling() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 2, 1));
    let half = parent.output[1].value.to_sat();
    let sibling = v3(spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 1_000, 1, 2));
    for tx in [&parent, &sibling] {
        accept(&mp, &cs, tx).expect("admitted");
    }
    let rich = v3(spend(&[out(parent.compute_txid(), 1)], half, 20_000, 1, 3));
    let uncle = v3(spend(&[out(rich.compute_txid(), 0)], half - 20_000, 1_000, 1, 4));

    let r = submit(&mp, &cs, &[&rich, &uncle]);

    assert_eq!(pool(&mp), txids(&[&parent, &rich]), "{:?}", r.tx_results);
    assert_eq!(error(&r, &uncle), format!("TRUC-violation, tx {} would have too many ancestors", id(&uncle)));

    let _ = std::fs::remove_dir_all(&dir);
}
