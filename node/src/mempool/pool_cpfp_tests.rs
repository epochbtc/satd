//! Package CPFP, checked against Bitcoin Core's `AcceptPackage`
//! (src/validation.cpp): a member refused on its own only for its feerate is
//! judged with the child that pays for it, by their combined feerate
//! (`AcceptMultipleTransactions` → `CheckFeeRate`), and the pool is trimmed
//! once the whole package is in (`LimitMempoolSize`), ranking a parent with
//! its child.
//!
//! The case it exists for is Lightning's: a commitment transaction whose
//! feerate was fixed when it was signed, and an anchor spend that pays for
//! both once mempool fees have risen past it.

use super::fullpool_tests::{COIN_VALUE, admit, env, events, evicted, pool, prev, set_max, spend};
use super::*;
use crate::validation::script::NoopVerifier;

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

fn result<'a>(r: &'a PackageResult, tx: &Transaction) -> &'a serde_json::Value {
    r.tx_results.get(&tx.compute_wtxid().to_string()).expect("every member has a result")
}

fn error(r: &PackageResult, tx: &Transaction) -> String {
    result(r, tx)["error"].as_str().unwrap_or("<accepted>").to_string()
}

/// The fee the relay floor asks of `txs` together, as Core's `CheckFeeRate`
/// reports it.
fn floor_fee(txs: &[&Transaction]) -> u64 {
    let weight: u64 = txs.iter().map(|t| t.weight().to_wu()).sum();
    policy::fee_for_rate(1_000, weight)
}

/// The `Enter` events sent so far, in order.
fn entered(rx: &mut broadcast::Receiver<MempoolEvent>) -> Vec<Txid> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let MempoolEvent::Enter { txid, .. } = ev {
            out.push(txid);
        }
    }
    out
}

/// A parent paying nothing — below the relay floor, with no dust — goes in
/// with a child that pays for both, and the two share one effective feerate
/// over the pair.
#[test]
fn a_child_pays_for_a_parent_below_the_relay_floor() {
    let (cs, mp, dir) = floor_env(&[1]);
    let mut rx = events(&mp);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 1_000, 1, 2);
    assert!(
        matches!(
            mp.accept_transaction(parent.clone(), &cs, &NoopVerifier, TxSource::Rpc, false),
            Err(MempoolError::InsufficientFee(0, _))
        ),
        "the fixture needs a parent the floor refuses on its own"
    );

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(pool(&mp), HashSet::from([parent.compute_txid(), child.compute_txid()]));
    let both = serde_json::json!([parent.compute_wtxid().to_string(), child.compute_wtxid().to_string()]);
    for tx in [&parent, &child] {
        let fees = &result(&r, tx)["fees"];
        assert_eq!(fees["effective-includes"], both, "{:?}", r.tx_results);
        assert_eq!(fees["effective-feerate"], result(&r, &child)["fees"]["effective-feerate"]);
    }
    // The parent is announced, and before the child that spends it.
    assert_eq!(entered(&mut rx), vec![parent.compute_txid(), child.compute_txid()]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The same for the rolling minimum a full pool raised: the parent clears the
/// static floor but not the raised one, and the child pays for both.
#[test]
fn a_child_pays_for_a_parent_below_the_rolling_minimum() {
    let (cs, mp, dir) = floor_env(&[1]);
    mp.inner.write().rolling.lock().package_removed(20_000);
    assert!(mp.min_fee() >= 20_000, "the fixture needs a raised floor");
    // 10 sat/vB: above the static floor, below the raised one.
    let parent = spend(&[prev(1)], COIN_VALUE, 820, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 820, 6_000, 1, 2);
    assert!(
        matches!(
            mp.accept_transaction(parent.clone(), &cs, &NoopVerifier, TxSource::Rpc, false),
            Err(MempoolError::MempoolMinFeeNotMet(..))
        ),
        "the fixture needs a parent the rolling minimum refuses on its own"
    );

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(pool(&mp), HashSet::from([parent.compute_txid(), child.compute_txid()]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child whose own feerate clears the floor but whose package's does not is
/// refused with the package's numbers, and the parent keeps the reason it was
/// refused for alone (Core's `FeeFailure` on the last member). Nothing enters.
#[test]
fn a_child_that_cannot_pay_for_both_is_refused_by_the_package_feerate() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 1);
    // 100 sats: enough for its own 82 vB, not for the pair's 164.
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 100, 1, 2);

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "transaction failed", "{:?}", r.tx_results);
    assert_eq!(error(&r, &parent), format!("min relay fee not met, 0 < {}", floor_fee(&[&parent])));
    assert_eq!(
        error(&r, &child),
        format!("min relay fee not met, 100 < {}", floor_fee(&[&parent, &child]))
    );
    assert!(pool(&mp).is_empty(), "{:?}", r.tx_results);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The parent goes in below the floors before its child has been through
/// acceptance. If the child is then refused — here as non-final, which shows
/// only once the parent's outputs resolve — the parent leaves with it, was
/// never announced, and is reported with its own refusal. Core never commits
/// such a package at all.
#[test]
fn an_unpaid_parent_leaves_with_its_child() {
    let (cs, mp, dir) = floor_env(&[1]);
    let mut rx = events(&mp);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 1, 1);
    let mut child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE, 1_000, 1, 2);
    child.input[0].sequence = bitcoin::Sequence(1);

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "transaction failed", "{:?}", r.tx_results);
    assert_eq!(error(&r, &child), "non-BIP68-final");
    assert_eq!(error(&r, &parent), format!("min relay fee not met, 0 < {}", floor_fee(&[&parent])));
    assert!(pool(&mp).is_empty(), "the unpaid parent was left in the pool");
    let inner = mp.inner.read();
    assert!(inner.spends.is_empty(), "the parent's input is still marked spent");
    assert_eq!(inner.total_bytes, 0, "the parent's bytes were not released");
    drop(inner);
    assert!(entered(&mut rx).is_empty(), "a transaction that never stayed was announced");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A parent below the floors that replaces a mempool transaction is Core's
/// package RBF: the child pays for the parent and for what it replaces. The
/// parent's events wait for the child's, as any parent's below the floors.
#[test]
fn a_parent_below_the_floor_replaces_on_its_childs_fee() {
    let (cs, mp, dir) = floor_env(&[1]);
    let resident = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 200, 1, 9));
    mp.inner.write().rolling.lock().package_removed(20_000);
    // Outbids the resident, so the replacement rules pass; below the raised
    // floor, so only a package could let it in.
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 1_000, 10_000, 1, 2);
    assert!(matches!(
        mp.test_accept(&parent, &cs, &NoopVerifier),
        Err(MempoolError::MempoolMinFeeNotMet(..))
    ));
    let mut rx = events(&mp);

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    assert_eq!(pool(&mp), HashSet::from([parent.compute_txid(), child.compute_txid()]));
    assert_eq!(r.replaced, vec![resident]);
    assert_eq!(entered(&mut rx), vec![parent.compute_txid(), child.compute_txid()], "parent first, with its child");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Members that each clear the floors go in without making room, so the
/// first is not evicted for the second before the child that pays for both
/// arrives (Core's `test_mid_package_eviction_success`). The pool is then
/// trimmed once, taking what the package outbids, and ends within its limit.
#[test]
fn a_package_trims_the_pool_once_it_is_all_in() {
    let (cs, mp, dir) = env(&[1, 2, 3, 4, 5, 6]);
    let residents: Vec<Txid> =
        [3, 4, 5, 6].iter().map(|t| admit(&mp, &cs, spend(&[prev(*t)], COIN_VALUE, 500, 1, *t))).collect();
    let first = spend(&[prev(1)], COIN_VALUE, 100, 1, 1);
    let second = spend(&[prev(2)], COIN_VALUE, 100, 1, 2);
    let first_size = bitcoin::consensus::serialize(&first).len();
    // Room for the first parent, not the second.
    set_max(&mp, mp.acting_bytes() + first_size);
    let child = spend(
        &[out(first.compute_txid(), 0), out(second.compute_txid(), 0)],
        2 * (COIN_VALUE - 100),
        20_000,
        1,
        7,
    );

    let r = submit(&mp, &cs, &[&first, &second, &child]);

    assert_eq!(r.package_msg, "success", "{:?}", r.tx_results);
    let now = pool(&mp);
    for tx in [&first, &second, &child] {
        assert!(now.contains(&tx.compute_txid()), "{:?}", r.tx_results);
        // Each was accepted on its own feerate.
        assert_eq!(result(&r, tx)["fees"]["effective-includes"].as_array().map(Vec::len), Some(1));
    }
    assert!(residents.iter().any(|t| !now.contains(t)), "nothing was trimmed");
    assert!(mp.acting_bytes() <= mp.config.read().max_size_bytes, "the pool was left over its limit");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A package that gets in but ranks below everything else is what the trim
/// takes, and each of its members is reported as `mempool full` (Core's
/// `LimitMempoolSize` after `AcceptPackage`). Its members were announced, so
/// their evictions are too.
#[test]
fn a_package_that_ranks_last_is_trimmed_and_reported_mempool_full() {
    let (cs, mp, dir) = env(&[1, 2, 3]);
    let residents: HashSet<Txid> =
        [2, 3].iter().map(|t| admit(&mp, &cs, spend(&[prev(*t)], COIN_VALUE, 5_000, 1, *t))).collect();
    set_max(&mp, mp.acting_bytes());
    let mut rx = events(&mp);
    let parent = spend(&[prev(1)], COIN_VALUE, 100, 1, 1);
    let child = spend(&[out(parent.compute_txid(), 0)], COIN_VALUE - 100, 200, 1, 4);

    let r = submit(&mp, &cs, &[&parent, &child]);

    assert_eq!(r.package_msg, "transaction failed", "{:?}", r.tx_results);
    assert_eq!(error(&r, &parent), "mempool full");
    assert_eq!(error(&r, &child), "mempool full");
    assert_eq!(pool(&mp), residents);
    let mut gone = evicted(&mut rx);
    gone.sort();
    let mut package = vec![parent.compute_txid(), child.compute_txid()];
    package.sort();
    assert_eq!(gone, package);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A parent paying nothing ranks with the child that pays for it when the
/// pool trims, so the pair outlasts an entry paying less than they do
/// together. By the parent's own feerate it would go first, child and all.
#[test]
fn a_parent_ranks_with_the_child_that_pays_for_it() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 0, 1, 1));
    let child = admit(&mp, &cs, spend(&[out(parent, 0)], COIN_VALUE, 20_000, 1, 2));
    let other = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 2_000, 1, 3));

    let mut inner = mp.inner.write();
    let gone: Vec<Txid> =
        Mempool::evict_lowest_fee_entries(&mut inner, 1, false, 0).into_iter().map(|(t, _)| t).collect();
    drop(inner);

    assert_eq!(gone, vec![other]);
    assert_eq!(pool(&mp), HashSet::from([parent, child]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Evicting a low-paying child raises its parent's score, and the parent
/// must be ranked by the new one. Here the parent and its well-paying child
/// together outrank `other` only once the zero-fee sibling has gone; ranked
/// by the stale score, the pair would be evicted in `other`'s place.
#[test]
fn an_eviction_reranks_the_parent_it_leaves_behind() {
    let (cs, mp, dir) = env(&[1, 2]);
    // 1, 100 and 0 sat/vB; together about 30, and about 43 without the
    // zero-fee child. `other` pays 40.
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 113, 2, 1));
    let per = (COIN_VALUE - 113) / 2;
    let rich = admit(&mp, &cs, spend(&[out(parent, 0)], COIN_VALUE - 113 - per, 8_200, 1, 2));
    let poor = admit(&mp, &cs, spend(&[out(parent, 1)], per, 0, 1, 3));
    let other = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 3_280, 1, 4));
    let poor_size = bitcoin::consensus::serialize(&mp.get(&poor).unwrap().tx).len();

    let mut inner = mp.inner.write();
    let mut gone: Vec<Txid> = Mempool::evict_lowest_fee_entries(&mut inner, poor_size + 1, false, 0)
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    drop(inner);

    gone.sort();
    let mut expected = vec![poor, other];
    expected.sort();
    assert_eq!(gone, expected);
    assert_eq!(pool(&mp), HashSet::from([parent, rich]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A family too large to walk is ranked by the parent's own feerate, as every
/// entry was before descendant scores: the walk's cost is bounded, and only a
/// family beyond any Core limit is affected.
#[test]
fn a_family_too_large_to_walk_ranks_by_the_parent_alone() {
    let (cs, mp, dir) = env(&[1, 2]);
    // Past the cluster limit, as only a reorg leaves a family.
    mp.config.write().max_cluster_count = 1_000;
    let children = DESCENDANT_SCORE_WALK as u64 + 1;
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 0, children, 1));
    let per = COIN_VALUE / children;
    for vout in 0..children as u32 {
        let value = if vout == 0 { COIN_VALUE - per * (children - 1) } else { per };
        admit(&mp, &cs, spend(&[out(parent, vout)], value, 500, 1, 2));
    }
    let inner = mp.inner.read();
    assert_eq!(Mempool::descendant_score(&inner, &parent, &HashSet::new()), Some(0));
    drop(inner);

    // One child fewer, and the family is walked: the parent ranks with it.
    let (cs2, mp2, dir2) = env(&[1]);
    mp2.config.write().max_cluster_count = 1_000;
    let parent2 = admit(&mp2, &cs2, spend(&[prev(1)], COIN_VALUE, 0, children - 1, 1));
    let per = COIN_VALUE / (children - 1);
    for vout in 0..(children - 1) as u32 {
        let value = if vout == 0 { COIN_VALUE - per * (children - 2) } else { per };
        admit(&mp2, &cs2, spend(&[out(parent2, vout)], value, 500, 1, 2));
    }
    let inner = mp2.inner.read();
    assert!(Mempool::descendant_score(&inner, &parent2, &HashSet::new()).unwrap() > 0);
    drop(inner);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Evicting a child shared by two parents can *lower* the score of the
/// parent it leaves behind, so the survivors are re-ranked as each package
/// goes. Here B's package (B with the shared child C) goes first; A then pays
/// only its own 10 sat/vB and is next, ahead of D. Ranked by its stale score
/// A would outlast D, and the pool would drop the better-paying transaction.
#[test]
fn evicting_a_shared_child_reranks_its_other_parent_down() {
    let (cs, mp, dir) = env(&[1, 2, 4]);
    let a = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 820, 1, 1));
    let b = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 0, 1, 2));
    let c = admit(&mp, &cs, spend(&[out(a, 0), out(b, 0)], 2 * COIN_VALUE - 820, 12_300, 1, 3));
    let d = admit(&mp, &cs, spend(&[prev(4)], COIN_VALUE, 5_084, 1, 4));
    let size = |t: &Txid| bitcoin::consensus::serialize(&mp.get(t).unwrap().tx).len();
    let need = size(&b) + size(&c) + 1;

    let mut inner = mp.inner.write();
    let score = |t: &Txid| Mempool::descendant_score(&inner, t, &HashSet::new()).unwrap();
    assert!(score(&b) < score(&d) && score(&d) < score(&a), "the fixture needs B < D < A");
    let mut gone: Vec<Txid> =
        Mempool::evict_lowest_fee_entries(&mut inner, need, false, 0).into_iter().map(|(t, _)| t).collect();
    drop(inner);

    gone.sort();
    let mut expected = vec![a, b, c];
    expected.sort();
    assert_eq!(gone, expected);
    assert_eq!(pool(&mp), HashSet::from([d]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Fails the scripts of one transaction, after letting a concurrent
/// admission try to run while the package is still under way.
struct RacesThenFails {
    fail: Txid,
    go: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
}

impl ScriptVerifier for RacesThenFails {
    fn verify_transaction(
        &self,
        tx: &Transaction,
        _prev_outputs: &[TxOut],
        _height: u32,
    ) -> Result<(), crate::validation::script::ScriptError> {
        if tx.compute_txid() != self.fail {
            return Ok(());
        }
        let _ = self.go.lock().unwrap().send(());
        std::thread::sleep(std::time::Duration::from_millis(300));
        Err(crate::validation::script::ScriptError::VerifyFailed { input: 0, reason: "forged".into() })
    }

    fn verify_policy(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
    ) -> Result<(), crate::validation::script::ScriptError> {
        Ok(())
    }
}

/// While a package is under way its below-floor parent is in the pool, and
/// it comes back out if the child fails. A transaction admitted in between
/// could spend that parent and then be left with no input, so admissions wait
/// for the package to finish, as Core's lock does.
#[test]
fn an_admission_waits_for_a_package_that_may_take_its_parent_back() {
    let (cs, mp, dir) = floor_env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 0, 2, 1);
    let per = COIN_VALUE / 2;
    let child = spend(&[out(parent.compute_txid(), 0)], per, 1_000, 1, 2);
    let racer = spend(&[out(parent.compute_txid(), 1)], COIN_VALUE - per, 5_000, 1, 3);
    let (go, ready) = std::sync::mpsc::channel();
    let verifier = RacesThenFails { fail: child.compute_txid(), go: std::sync::Mutex::new(go) };

    let (r, raced) = std::thread::scope(|s| {
        let (mp, cs, racer) = (&mp, &cs, &racer);
        let racing = s.spawn(move || {
            // Bounded, so a package that never reaches the child fails the
            // test rather than hanging it.
            let _ = ready.recv_timeout(std::time::Duration::from_secs(10));
            mp.accept_transaction(racer.clone(), cs, &NoopVerifier, TxSource::P2p, false)
        });
        let r = mp.accept_package_with(vec![parent.clone(), child.clone()], cs, &verifier, None);
        (r, racing.join().unwrap())
    });

    assert_eq!(r.package_msg, "transaction failed", "{:?}", r.tx_results);
    assert!(matches!(raced, Err(MempoolError::MissingInputs)), "{raced:?}");
    assert!(pool(&mp).is_empty(), "a transaction was left spending a parent that left");

    let _ = std::fs::remove_dir_all(&dir);
}
