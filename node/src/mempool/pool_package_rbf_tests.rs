//! Package RBF in `submitpackage`, through the cases of Core's
//! `mempool_package_rbf.py`: a child pays for its parent's replacement
//! (`AcceptMultipleTransactions` with `PackageRBFChecks`), and a package
//! refused at any step leaves the mempool as it was.

use super::fullpool_tests::{COIN_VALUE, env, pool, prev, spend};
use super::*;
use crate::validation::script::{NoopVerifier, ScriptError};

fn out(txid: Txid, vout: u32) -> OutPoint {
    OutPoint { txid, vout }
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

/// A parent spending `coin` and its child, paying `fees`. `tag` keeps the
/// transactions of one package apart from another's on the same coin.
fn package(coin: OutPoint, fees: (u64, u64), tag: u8) -> (Transaction, Transaction) {
    let parent = spend(&[coin], COIN_VALUE, fees.0, 1, tag);
    let child = spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), fees.1, 1, tag + 1);
    (parent, child)
}

fn ids(txs: &[&Transaction]) -> HashSet<Txid> {
    txs.iter().map(|t| t.compute_txid()).collect()
}

fn v3(mut tx: Transaction) -> Transaction {
    tx.version = bitcoin::transaction::Version(3);
    tx
}

/// A child pays to replace its parent's conflict and that conflict's child,
/// which the parent alone could not.
#[test]
fn a_child_pays_to_replace_its_parents_conflicts() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 1_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");
    let (p2, c2) = package(prev(1), (1_000, 4_000), 3);
    assert!(
        matches!(
            mp.test_accept(&p2, &cs, &NoopVerifier),
            Err(MempoolError::InsufficientReplacementFee(..))
        ),
        "the fixture needs a parent that cannot replace on its own"
    );

    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(r.replaced.iter().copied().collect::<HashSet<_>>(), ids(&[&p1, &c1]));
    assert_eq!(pool(&mp), ids(&[&p2, &c2]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The conflict may be a lone transaction.
#[test]
fn a_child_pays_to_replace_a_single_conflict() {
    let (cs, mp, dir) = floor_env(&[1]);
    let single = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    mp.accept_transaction(single.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("single");
    let (p, c) = package(prev(1), (1_000, 2_000), 3);

    let r = submit(&mp, &cs, &[&p, &c]);
    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(r.replaced, vec![single.compute_txid()]);
    assert_eq!(pool(&mp), ids(&[&p, &c]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Rules 3 and 4 over the package: its fees against everything it evicts,
/// then its own relay on top, at its summed vsize.
#[test]
fn the_package_pays_for_what_it_evicts_and_for_its_relay() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 4_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");

    let (p2, c2) = package(prev(1), (1_000, 3_999), 3);
    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert_eq!(
        r.package_msg,
        format!(
            "package RBF failed: insufficient anti-DoS fees, rejecting replacement {}, less fees than conflicting txs; {} < {}",
            c2.compute_txid(),
            format_btc(4_999),
            format_btc(5_000)
        )
    );
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    // The incremental relay fee for the package's size, five sats short.
    let (probe, probe_child) = package(prev(1), (1_000, 4_000), 5);
    let vsize = policy::weight_to_vsize(probe.weight().to_wu()) + policy::weight_to_vsize(probe_child.weight().to_wu());
    let required = (100 * vsize).div_ceil(1000);
    let (p3, c3) = package(prev(1), (1_000, 4_000 + required - 5), 5);
    let r = submit(&mp, &cs, &[&p3, &c3]);
    assert_eq!(
        r.package_msg,
        format!(
            "package RBF failed: insufficient anti-DoS fees, rejecting replacement {}, not enough additional fees to relay; {} < {}",
            c3.compute_txid(),
            format_btc(required - 5),
            format_btc(required)
        )
    );
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let (p4, c4) = package(prev(1), (1_000, 4_000 + required), 7);
    assert_eq!(submit(&mp, &cs, &[&p4, &c4]).package_msg, "success");
    assert_eq!(pool(&mp), ids(&[&p4, &c4]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The child must raise the package above its parent's feerate: a child
/// that only pays the replacement's way is not a CPFP.
#[test]
fn the_package_must_outpay_its_parent() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 4_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");

    // A parent and child of one size, paying alike: equal rates.
    let (p2, c2) = package(prev(1), (4_000, 4_000), 3);
    assert_eq!(p2.weight(), c2.weight(), "the fixture needs equal sizes");
    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert!(
        r.package_msg.starts_with("package RBF failed: package feerate is less than or equal to parent feerate, package feerate "),
        "{}",
        r.package_msg
    );
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let (p3, c3) = package(prev(1), (4_000, 4_001), 5);
    assert_eq!(submit(&mp, &cs, &[&p3, &c3]).package_msg, "success");
    assert_eq!(pool(&mp), ids(&[&p3, &c3]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Only one parent and its child are judged together: two replacing
/// parents are refused.
#[test]
fn package_rbf_takes_one_parent_and_one_child() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let (a1, a2) = package(prev(1), (1_000, 4_000), 1);
    let (b1, b2) = package(prev(2), (1_000, 4_000), 3);
    assert_eq!(submit(&mp, &cs, &[&a1, &a2]).package_msg, "success");
    assert_eq!(submit(&mp, &cs, &[&b1, &b2]).package_msg, "success");

    let pa = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 5);
    let pb = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 6);
    let child = spend(
        &[out(pa.compute_txid(), 0), out(pb.compute_txid(), 0)],
        pa.output[0].value.to_sat() + pb.output[0].value.to_sat(),
        20_000,
        1,
        7,
    );
    let r = submit(&mp, &cs, &[&pa, &pb, &child]);
    assert_eq!(r.package_msg, "package RBF failed: package must be 1-parent-1-child");
    assert_eq!(pool(&mp), ids(&[&a1, &a2, &b1, &b2]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A member with a parent in the mempool is refused, including one that
/// entered on its own from the same package.
#[test]
fn package_rbf_takes_no_mempool_ancestors() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let (p1, c1) = package(prev(1), (1_000, 4_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");

    let replacing = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 3);
    let alone = spend(&[prev(2)], COIN_VALUE, 1_000, 1, 4);
    let child = spend(
        &[out(replacing.compute_txid(), 0), out(alone.compute_txid(), 0)],
        replacing.output[0].value.to_sat() + alone.output[0].value.to_sat(),
        20_000,
        1,
        5,
    );
    let r = submit(&mp, &cs, &[&replacing, &alone, &child]);
    assert_eq!(r.package_msg, "package RBF failed: new transaction cannot have mempool ancestors");
    assert_eq!(pool(&mp), ids(&[&p1, &c1, &alone]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Core's last case: the child conflicts with its own parent's mempool
/// parent. The parent has a mempool ancestor, so the package is refused
/// and the grandparent stays.
#[test]
fn a_child_conflicting_with_its_grandparent_is_refused() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let grandparent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let g = mp.accept_transaction(grandparent.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("grandparent");
    let parent = spend(&[out(g, 0)], grandparent.output[0].value.to_sat(), 0, 1, 2);
    let child = spend(
        &[out(parent.compute_txid(), 0), prev(1)],
        parent.output[0].value.to_sat() + COIN_VALUE,
        40_000,
        1,
        3,
    );
    let r = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(r.package_msg, "package RBF failed: new transaction cannot have mempool ancestors");
    assert_eq!(pool(&mp), HashSet::from([g]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// More fees and a higher package feerate are not enough when the conflict
/// is a parent richer than the package's own rate.
#[test]
fn a_package_that_worsens_the_diagram_is_refused() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (4_000, 1_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");

    let (p2, c2) = package(prev(1), (3_999, 4_000), 3);
    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert_eq!(r.package_msg, "package RBF failed: insufficient feerate: does not improve feerate diagram");
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A zero-fee TRUC parent below the relay floor replaces its conflict on
/// its child's fee.
#[test]
fn a_zero_fee_truc_parent_replaces_on_its_childs_fee() {
    let (cs, mp, dir) = floor_env(&[1]);
    let p1 = v3(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1));
    let c1 = v3(spend(&[out(p1.compute_txid(), 0)], p1.output[0].value.to_sat(), 1_000, 1, 2));
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");

    let p2 = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 3));
    let c2 = v3(spend(&[out(p2.compute_txid(), 0)], COIN_VALUE, 20_000, 1, 4));
    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(r.replaced.iter().copied().collect::<HashSet<_>>(), ids(&[&p1, &c1]));
    assert_eq!(pool(&mp), ids(&[&p2, &c2]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Refuses the scripts of one transaction.
struct RefusesOne(Txid);

impl ScriptVerifier for RefusesOne {
    fn verify_transaction(&self, tx: &Transaction, _: &[TxOut], _: u32) -> Result<(), ScriptError> {
        if tx.compute_txid() == self.0 {
            return Err(ScriptError::VerifyFailed { input: 0, reason: "Invalid Schnorr signature".into() });
        }
        Ok(())
    }

    fn verify_policy(&self, _: &Transaction, _: &[TxOut]) -> Result<(), ScriptError> {
        Ok(())
    }
}

/// A child whose scripts fail evicts nothing: both members are checked,
/// scripts included, before the parent replaces anything.
#[test]
fn a_child_with_bad_scripts_evicts_nothing() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 1_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");
    let (p2, c2) = package(prev(1), (1_000, 4_000), 3);

    let r = mp.accept_package_with(vec![p2.clone(), c2.clone()], &cs, &RefusesOne(c2.compute_txid()), None);
    assert_eq!(r.package_msg, "transaction failed");
    assert!(
        r.tx_results[&c2.compute_wtxid().to_string()]["error"].as_str().unwrap().contains("script"),
        "{:?}",
        r.tx_results
    );
    assert!(r.replaced.is_empty());
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule 5 over the conflicts of both members together.
#[test]
fn the_conflicts_of_both_members_count_toward_rule_five() {
    let tags: Vec<u8> = (1..=101).collect();
    let (cs, mp, dir) = floor_env(&tags);
    for &t in &tags {
        mp.accept_transaction(spend(&[prev(t)], COIN_VALUE, 1_000, 1, t), &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("one cluster per coin");
    }
    // The parent conflicts with 50 clusters, the child with the other 51.
    let parent_coins: Vec<OutPoint> = (1..=50).map(prev).collect();
    let child_coins: Vec<OutPoint> = (51..=101).map(prev).collect();
    let parent = spend(&parent_coins, 50 * COIN_VALUE, 50_000, 1, 200);
    let mut child_inputs = vec![out(parent.compute_txid(), 0)];
    child_inputs.extend(child_coins);
    let child = spend(&child_inputs, parent.output[0].value.to_sat() + 51 * COIN_VALUE, 1_000_000, 1, 201);
    let before = pool(&mp);

    let r = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(
        r.package_msg,
        format!(
            "package RBF failed: too many potential replacements, rejecting replacement {}; too many conflicting clusters (101 > 100)",
            child.compute_txid()
        ),
        "{:?}",
        r.tx_results
    );
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The parent and child are held to the cluster limits as a pair.
#[test]
fn the_package_is_held_to_the_cluster_limits() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 1_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");
    mp.config.write().max_cluster_count = 1;
    let (p2, c2) = package(prev(1), (1_000, 4_000), 3);

    let r = submit(&mp, &cs, &[&p2, &c2]);
    assert_eq!(r.package_msg, "too-large-cluster");
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A zero-fee dust parent that replaces must have its dust swept by its
/// child, as any package's (`CheckEphemeralSpends`), and nothing is evicted
/// when it is not.
#[test]
fn a_replacing_dust_parent_needs_its_dust_swept() {
    let (cs, mp, dir) = floor_env(&[1]);
    let (p1, c1) = package(prev(1), (1_000, 1_000), 1);
    assert_eq!(submit(&mp, &cs, &[&p1, &c1]).package_msg, "success");
    let mut parent = v3(spend(&[prev(1)], COIN_VALUE, 0, 1, 3));
    parent.output[0].value = bitcoin::Amount::from_sat(COIN_VALUE - 100);
    parent.output.push(TxOut { value: bitcoin::Amount::from_sat(100), script_pubkey: parent.output[0].script_pubkey.clone() });
    let p = parent.compute_txid();
    let around = v3(spend(&[out(p, 0)], COIN_VALUE - 100, 20_000, 1, 4));

    let r = submit(&mp, &cs, &[&parent, &around]);
    assert_eq!(
        r.tx_results[&around.compute_wtxid().to_string()]["error"],
        format!(
            "missing-ephemeral-spends, tx {} (wtxid={}) did not spend parent's ephemeral dust",
            around.compute_txid(),
            around.compute_wtxid()
        ),
        "{:?}",
        r.tx_results
    );
    assert_eq!(pool(&mp), ids(&[&p1, &c1]));

    let sweeps = v3(spend(&[out(p, 0), out(p, 1)], COIN_VALUE, 20_000, 1, 5));
    let r = submit(&mp, &cs, &[&parent, &sweeps]);
    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(pool(&mp), ids(&[&parent, &sweeps]));

    let _ = std::fs::remove_dir_all(&dir);
}

fn version(mut tx: Transaction, v: i32) -> Transaction {
    tx.version = bitcoin::transaction::Version(v);
    tx
}

/// With `-mempoolfullrbf=0`, a package replaces only what signals, as a
/// single replacement does. The parent below the floor reaches the package
/// checks without the single replacement rules, so they must ask.
#[test]
fn without_full_rbf_a_package_replaces_only_what_signals() {
    let (cs, mp, dir) = floor_env(&[1]);
    mp.config.write().full_rbf = false;
    let resident = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let r = mp.accept_transaction(resident.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("resident");
    let (parent, child) = package(prev(1), (0, 20_000), 3);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(res.package_msg, "transaction failed", "{:?}", res.tx_results);
    assert_eq!(res.tx_results[&parent.compute_wtxid().to_string()]["error"], "txn-mempool-conflict");
    assert_eq!(pool(&mp), HashSet::from([r]));

    // A resident that signals is replaced.
    mp.config.write().full_rbf = true;
    assert_eq!(submit(&mp, &cs, &[&parent, &child]).package_msg, "success");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child the policy would hold may not displace an acting transaction.
/// That is found before the parent evicts its own conflict, so a refused
/// package takes nothing out.
#[test]
fn a_held_child_conflicting_with_an_acting_transaction_evicts_nothing() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let a = version(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1), 1);
    let b = version(spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2), 1);
    let a_id = mp.accept_transaction(a, &cs, &NoopVerifier, TxSource::Rpc, false).expect("a");
    let b_id = mp.accept_transaction(b, &cs, &NoopVerifier, TxSource::Rpc, false).expect("b");
    let rs = satd_policy::parse_ruleset("version 1\nquarantine catch on template when tx.version == 2").expect("ruleset");
    mp.set_policy(std::sync::Arc::new(rs));

    // The parent replaces A; the child, which the rule holds, also spends B's coin.
    let parent = version(spend(&[prev(1)], COIN_VALUE, 0, 1, 3), 1);
    let child = spend(&[out(parent.compute_txid(), 0), prev(2)], 2 * COIN_VALUE, 20_000, 1, 4);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(res.tx_results[&child.compute_wtxid().to_string()]["error"], "txn-mempool-conflict", "{:?}", res.tx_results);
    assert!(res.replaced.is_empty());
    assert_eq!(pool(&mp), HashSet::from([a_id, b_id]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The child takes on its parent's hold before it reaches the mempool: a
/// held parent replacing a held transaction, with a child that conflicts
/// with an acting one, is refused before the parent evicts anything.
#[test]
fn a_child_held_through_its_parent_is_judged_held() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let b = version(spend(&[prev(2)], COIN_VALUE, 1_000, 1, 2), 1);
    let b_id = mp.accept_transaction(b, &cs, &NoopVerifier, TxSource::Rpc, false).expect("b");
    let rs = satd_policy::parse_ruleset("version 1\nquarantine catch on template when tx.version == 2").expect("ruleset");
    mp.set_policy(std::sync::Arc::new(rs));
    let x = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let x_id = mp.accept_transaction(x, &cs, &NoopVerifier, TxSource::Rpc, false).expect("x, held");

    // Both held by the rule's version or by descent; the child is version 1.
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 3);
    let child = version(spend(&[out(parent.compute_txid(), 0), prev(2)], 2 * COIN_VALUE, 20_000, 1, 4), 1);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(res.tx_results[&child.compute_wtxid().to_string()]["error"], "txn-mempool-conflict", "{:?}", res.tx_results);
    assert!(res.replaced.is_empty());
    assert_eq!(pool(&mp), HashSet::from([x_id, b_id]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// With `-acceptnonstdtxn`, the dust a parent leaves must still be swept:
/// admission enforces it, so the package checks do too, before the parent
/// replaces anything.
#[test]
fn unswept_dust_is_refused_before_eviction_even_with_acceptnonstdtxn() {
    let (cs, mp, dir) = floor_env(&[1]);
    mp.config.write().accept_non_std_txn = true;
    let a = spend(&[prev(1)], COIN_VALUE, 2_000, 1, 1);
    let a_id = mp.accept_transaction(a, &cs, &NoopVerifier, TxSource::Rpc, false).expect("a");
    let mut parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 3);
    parent.output[0].value = bitcoin::Amount::from_sat(COIN_VALUE - 1_100);
    parent.output.push(TxOut { value: bitcoin::Amount::from_sat(100), script_pubkey: parent.output[0].script_pubkey.clone() });
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_100, 20_000, 1, 4);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert!(
        res.tx_results[&child.compute_wtxid().to_string()]["error"].as_str().unwrap_or_default().starts_with("missing-ephemeral-spends"),
        "{:?}",
        res.tx_results
    );
    assert!(res.replaced.is_empty());
    assert_eq!(pool(&mp), HashSet::from([a_id]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The child's policy is judged at the mempool size it will see on
/// admission, after its parent has replaced what it conflicts with.
#[test]
fn the_childs_policy_sees_the_mempool_after_its_parent() {
    let (cs, mp, dir) = floor_env(&[1]);
    let a = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let a_size = bitcoin::consensus::serialize(&a).len();
    let a_id = mp.accept_transaction(a, &cs, &NoopVerifier, TxSource::Rpc, false).expect("a");
    // A larger parent than A, so the mempool grows when it replaces A.
    let parent = version(spend(&[prev(1)], COIN_VALUE, 0, 3, 3), 1);
    let parent_size = bitcoin::consensus::serialize(&parent).len();
    assert!(parent_size > a_size);
    let child = spend(&[out(parent.compute_txid(), 0)], parent.output[0].value.to_sat(), 20_000, 1, 4);
    // Holds a version 2 transaction from relay once the mempool is past A's size.
    let rule = format!("version 1\nquarantine catch when tx.version == 2 and node.mempool_bytes > {a_size}");
    mp.set_policy(std::sync::Arc::new(satd_policy::parse_ruleset(&rule).expect("ruleset")));

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert!(
        res.tx_results[&child.compute_wtxid().to_string()]["error"].as_str().unwrap_or_default().starts_with("txn-policy-quarantined"),
        "{:?}",
        res.tx_results
    );
    assert!(res.replaced.is_empty());
    assert_eq!(pool(&mp), HashSet::from([a_id]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Between the parent's and the child's admissions, spend the given coins
/// as a block connecting there would.
fn spend_between(mp: &Mempool, cs: &ChainState, coins: Vec<OutPoint>) {
    use crate::storage::Store as _;
    let store = cs.store_ref().clone();
    *mp.between_package_members.lock() = Some(Box::new(move || {
        let batch = crate::storage::StoreBatch {
            coin_removes: coins.iter().map(|c| (*c, COIN_VALUE, 1)).collect(),
            ..Default::default()
        };
        store.write_batch(batch).expect("spend the coins");
    }));
}

/// The leave and enter events sent so far.
fn stream(rx: &mut tokio::sync::broadcast::Receiver<MempoolEvent>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        match event {
            MempoolEvent::Enter { txid, .. } => out.push(format!("enter {txid}")),
            MempoolEvent::LeaveReplaced { txid, .. } => out.push(format!("replaced {txid}")),
            MempoolEvent::LeaveEvicted { txid, reason, .. } => out.push(format!("evicted {txid} {reason:?}")),
            _ => {}
        }
    }
    out
}

/// A block spending the child's other coin can connect after the parent
/// has replaced its conflict: the child then fails, the parent comes back
/// out, and what it replaced is restored. Nothing about it was announced.
#[test]
fn a_child_failing_after_its_parent_restores_what_the_parent_replaced() {
    let (cs, mp, dir) = floor_env(&[1, 2]);
    let a = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let a_id = mp.accept_transaction(a, &cs, &NoopVerifier, TxSource::Rpc, false).expect("a");
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    mp.set_event_sender(tx);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 3);
    let child = spend(&[out(parent.compute_txid(), 0), prev(2)], 2 * COIN_VALUE, 20_000, 1, 4);
    spend_between(&mp, &cs, vec![prev(2)]);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(res.package_msg, "transaction failed");
    assert!(res.replaced.is_empty(), "{:?}", res.replaced);
    assert_eq!(pool(&mp), HashSet::from([a_id]));
    assert!(stream(&mut rx).is_empty(), "the replacement that did not happen was announced");
    assert_eq!(mp.spending_tx(&prev(1)).map(|(t, _)| t), Some(a_id), "a spends its coin again");

    let _ = std::fs::remove_dir_all(&dir);
}

/// What the parent replaced is restored only where the chain still allows
/// it: a replaced transaction whose own coin the block spent stays out, and
/// leaves as a block conflict.
#[test]
fn a_replaced_transaction_the_block_invalidated_is_not_restored() {
    let (cs, mp, dir) = floor_env(&[1, 2, 3]);
    let a = spend(&[prev(1), prev(3)], 2 * COIN_VALUE, 1_000, 1, 1);
    let a_id = mp.accept_transaction(a, &cs, &NoopVerifier, TxSource::Rpc, false).expect("a");
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    mp.set_event_sender(tx);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 3);
    let child = spend(&[out(parent.compute_txid(), 0), prev(2)], 2 * COIN_VALUE, 20_000, 1, 4);
    spend_between(&mp, &cs, vec![prev(2), prev(3)]);

    let res = submit(&mp, &cs, &[&parent, &child]);
    assert_eq!(res.package_msg, "transaction failed");
    assert!(pool(&mp).is_empty());
    assert_eq!(stream(&mut rx), vec![format!("evicted {a_id} BlockConflict")]);

    let _ = std::fs::remove_dir_all(&dir);
}
