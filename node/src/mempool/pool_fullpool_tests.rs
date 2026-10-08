//! Admission into a full pool, checked against Bitcoin Core's
//! `MemPoolAccept` (src/validation.cpp, `AcceptSingleTransactionInternal`):
//! the scripts are checked (`PolicyScriptChecks`, `ConsensusScriptChecks`)
//! before anything leaves the pool, and the pool is then trimmed to its
//! limit (`LimitMempoolSize` → `CTxMemPool::TrimToSize`).
//!
//! satd frees room before it inserts rather than trimming after, so it also
//! has to keep the incoming transaction's own ancestors: Core's trim takes a
//! parent together with the child that pays for it, never the parent alone.

use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::{NoopVerifier, ScriptError};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Sequence, TxIn, Witness};

const COIN_VALUE: u64 = 100_000;

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

fn p2wpkh(tag: u8) -> ScriptBuf {
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[tag; 20]);
    ScriptBuf::from_bytes(spk)
}

fn coin() -> Coin {
    Coin {
        amount: COIN_VALUE,
        script_pubkey: p2wpkh(0x11),
        height: 1,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

/// Spend `prevs` (worth `in_value` together), paying `fee` and splitting the
/// rest over `outs` P2WPKH outputs. One input and one output is 82 bytes;
/// each further output adds 31.
fn spend(prevs: &[OutPoint], in_value: u64, fee: u64, outs: u64, tag: u8) -> Transaction {
    let each = (in_value - fee) / outs;
    let mut output: Vec<TxOut> = (0..outs)
        .map(|_| TxOut { value: Amount::from_sat(each), script_pubkey: p2wpkh(tag) })
        .collect();
    output[0].value = Amount::from_sat(in_value - fee - each * (outs - 1));
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: *p,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output,
    }
}

/// A regtest chain holding one coin per tag, and an empty pool with no relay
/// floor.
fn env(tags: &[u8]) -> (ChainState, Mempool, std::path::PathBuf) {
    let coins: Vec<(OutPoint, Coin)> = tags.iter().map(|t| (prev(*t), coin())).collect();
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    *mp.config.write() =
        MempoolConfig { max_size_bytes: 1_000_000, min_fee_rate: 0, ..Default::default() };
    (cs, mp, dir)
}

/// Set the size limit without going through `reload_policy`.
fn set_max(mp: &Mempool, max: usize) {
    mp.config.write().max_size_bytes = max;
}

fn admit(mp: &Mempool, cs: &ChainState, tx: Transaction) -> Txid {
    mp.accept_transaction(tx, cs, &NoopVerifier, TxSource::P2p, false).expect("admitted")
}

fn pool(mp: &Mempool) -> HashSet<Txid> {
    mp.inner.read().entries.keys().copied().collect()
}

fn events(mp: &Mempool) -> broadcast::Receiver<MempoolEvent> {
    let (tx, rx) = broadcast::channel(1024);
    mp.set_event_sender(tx);
    rx
}

/// The `LeaveEvicted { FullPool }` events sent so far.
fn evicted(rx: &mut broadcast::Receiver<MempoolEvent>) -> Vec<Txid> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let MempoolEvent::LeaveEvicted { txid, reason: EvictReason::FullPool } = ev {
            out.push(txid);
        }
    }
    out
}

/// Fails every transaction's scripts, as libconsensus does a forged signature.
struct Refuses;

impl ScriptVerifier for Refuses {
    fn verify_transaction(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
        _height: u32,
    ) -> Result<(), ScriptError> {
        Err(ScriptError::VerifyFailed { input: 0, reason: "Invalid Schnorr signature".into() })
    }
}

/// A transaction that outbids the pool but fails its scripts takes nothing
/// out of it: no entry, no rise in the minimum fee, no `LeaveEvicted`. The
/// same transaction with valid scripts then takes the one entry it needs.
#[test]
fn a_script_failure_on_a_full_pool_evicts_nothing() {
    let (cs, mp, dir) = env(&[1, 2, 3, 4]);
    for t in 1..=3 {
        admit(&mp, &cs, spend(&[prev(t)], COIN_VALUE, 100, 1, t));
    }
    let before = pool(&mp);
    set_max(&mp, mp.acting_bytes());
    let floor = mp.info().mempool_min_fee;
    let mut rx = events(&mp);

    let rich = spend(&[prev(4)], COIN_VALUE, 5_000, 1, 4);
    let err = mp
        .accept_transaction(rich.clone(), &cs, &Refuses, TxSource::P2p, false)
        .expect_err("its scripts fail");
    assert!(matches!(err, MempoolError::Script(..)), "{err:?}");
    assert_eq!(pool(&mp), before, "a transaction whose scripts fail evicted entries");
    assert_eq!(mp.info().mempool_min_fee, floor, "a transaction whose scripts fail raised the floor");
    assert!(evicted(&mut rx).is_empty());

    let txid = mp
        .accept_transaction(rich, &cs, &NoopVerifier, TxSource::P2p, false)
        .expect("admitted");
    let gone = evicted(&mut rx);
    assert_eq!(gone.len(), 1, "one 82-byte entry makes room for one 82-byte transaction");
    assert!(before.contains(&gone[0]));
    assert!(pool(&mp).contains(&txid));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child whose parent is the cheapest entry keeps its parent: the room
/// comes from the cheapest entry that is not one of its ancestors. Evicting
/// the parent left the child in the pool with an input nothing provides.
#[test]
fn a_child_keeps_its_parent_in_a_full_pool() {
    let (cs, mp, dir) = env(&[1, 2, 3]);
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 100, 1, 1));
    let second = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 200, 1, 2));
    let third = admit(&mp, &cs, spend(&[prev(3)], COIN_VALUE, 300, 1, 3));
    set_max(&mp, mp.acting_bytes());

    let child = admit(
        &mp,
        &cs,
        spend(&[OutPoint { txid: parent, vout: 0 }], COIN_VALUE - 100, 10_000, 1, 4),
    );
    let now = pool(&mp);
    assert!(now.contains(&parent), "the child's own parent was evicted to make room for it");
    assert!(!now.contains(&second), "the cheapest entry that is not an ancestor makes the room");
    assert!(now.contains(&third));
    assert!(now.contains(&child));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A child that outbids only its own parent has nothing it may evict, so it
/// is refused and the pool is unchanged. (Core trims the parent and the child
/// together as the worst-paying chunk and answers "mempool full".)
#[test]
fn a_child_that_outbids_only_its_parent_is_refused() {
    let (cs, mp, dir) = env(&[1, 2, 3]);
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 100, 1, 1));
    admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 2_000, 1, 2));
    admit(&mp, &cs, spend(&[prev(3)], COIN_VALUE, 2_000, 1, 3));
    set_max(&mp, mp.acting_bytes());
    let before = pool(&mp);

    let child = spend(&[OutPoint { txid: parent, vout: 0 }], COIN_VALUE - 100, 1_000, 1, 4);
    let err = mp
        .accept_transaction(child, &cs, &NoopVerifier, TxSource::P2p, false)
        .expect_err("it pays less than every entry it could evict");
    assert!(matches!(err, MempoolError::MempoolFull), "{err:?}");
    assert_eq!(pool(&mp), before);

    let _ = std::fs::remove_dir_all(&dir);
}

/// When the room still runs short after eviction, the transaction is refused,
/// and what was evicted on the way is reported: those entries are gone.
#[test]
fn a_full_pool_refusal_reports_its_evictions() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 200, 1, 1));
    let cheap = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 100, 1, 2));
    set_max(&mp, mp.acting_bytes());
    let mut rx = events(&mp);

    // 144 bytes, and only the 82-byte `cheap` can go.
    let child = spend(&[OutPoint { txid: parent, vout: 0 }], COIN_VALUE - 200, 10_000, 3, 3);
    let err = mp
        .accept_transaction(child, &cs, &NoopVerifier, TxSource::P2p, false)
        .expect_err("evicting everything but its parent does not make enough room");
    assert!(matches!(err, MempoolError::MempoolFull), "{err:?}");
    assert_eq!(pool(&mp), HashSet::from([parent]));
    assert_eq!(evicted(&mut rx), vec![cheap], "an eviction was never reported");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Lowering `-maxmempool` on a live node trims the pool to the new limit at
/// once, lowest feerate first, and reports each eviction. Left over the limit,
/// every later admission freed one transaction's worth and was refused.
#[test]
fn lowering_maxmempool_trims_the_pool_at_once() {
    let (cs, mp, dir) = env(&[1, 2, 3, 4, 5]);
    let ids: Vec<Txid> = (1..=4u8)
        .map(|t| admit(&mp, &cs, spend(&[prev(t)], COIN_VALUE, 100 * t as u64, 1, t)))
        .collect();
    let two = mp.acting_bytes() / 2;
    let mut rx = events(&mp);

    let cfg = MempoolConfig { max_size_bytes: two, ..mp.config.read().clone() };
    mp.reload_policy(cfg);
    assert!(mp.acting_bytes() <= two, "{} bytes over a {two}-byte limit", mp.acting_bytes());
    assert_eq!(pool(&mp), HashSet::from([ids[2], ids[3]]));
    let mut gone = evicted(&mut rx);
    gone.sort();
    let mut lowest = vec![ids[0], ids[1]];
    lowest.sort();
    assert_eq!(gone, lowest);

    let txid = admit(&mp, &cs, spend(&[prev(5)], COIN_VALUE, 10_000, 1, 5));
    assert!(pool(&mp).contains(&txid));
    assert!(mp.acting_bytes() <= two);

    let _ = std::fs::remove_dir_all(&dir);
}

/// An admission into a pool that is over its limit trims it to the limit,
/// as Core's `TrimToSize` does, instead of freeing only its own size and
/// refusing because the pool is still over.
#[test]
fn an_admission_trims_an_over_limit_pool() {
    let (cs, mp, dir) = env(&[1, 2, 3, 4, 5]);
    let ids: Vec<Txid> = (1..=4u8)
        .map(|t| admit(&mp, &cs, spend(&[prev(t)], COIN_VALUE, 100 * t as u64, 1, t)))
        .collect();
    let two = mp.acting_bytes() / 2;
    set_max(&mp, two);

    let txid = mp
        .accept_transaction(spend(&[prev(5)], COIN_VALUE, 10_000, 1, 5), &cs, &NoopVerifier, TxSource::P2p, false)
        .expect("the pool is trimmed to its limit and the transaction admitted");
    assert_eq!(pool(&mp), HashSet::from([ids[3], txid]));
    assert!(mp.acting_bytes() <= two);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Evicting a parent takes every descendant once: a child spending two of
/// its outputs, a child spending the third, and a grandchild. The spend
/// index and the byte count follow.
#[test]
fn evicting_a_parent_takes_every_descendant() {
    let (cs, mp, dir) = env(&[1, 2]);
    let parent = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 100, 3, 1));
    let out = |txid, vout| OutPoint { txid, vout };
    let per = (COIN_VALUE - 100) / 3;
    let two_outs = admit(&mp, &cs, spend(&[out(parent, 1), out(parent, 2)], 2 * per, 5_000, 1, 2));
    let one_out = admit(&mp, &cs, spend(&[out(parent, 0)], COIN_VALUE - 100 - 2 * per, 5_000, 1, 3));
    let grandchild = admit(&mp, &cs, spend(&[out(two_outs, 0)], 2 * per - 5_000, 5_000, 1, 4));
    let other = admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 1_000, 1, 5));
    let other_size = bitcoin::consensus::serialize(&mp.get(&other).unwrap().tx).len();

    let mut inner = mp.inner.write();
    let mut gone = Mempool::evict_lowest_fee_entries(&mut inner, 1, false, 0);
    assert_eq!(inner.entries.keys().copied().collect::<HashSet<_>>(), HashSet::from([other]));
    assert_eq!(inner.spends.len(), 1);
    assert_eq!(inner.acting_bytes(), other_size);
    drop(inner);
    gone.sort();
    let mut family = vec![parent, two_outs, one_out, grandchild];
    family.sort();
    assert_eq!(gone, family, "each descendant is evicted, and only once");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The cost of eviction follows what it evicts, not the pool size times the
/// evictions. 600 evictions from a pool of 20,000 scanned the whole pool once
/// per eviction, each scan checking a growing list of what was already
/// chosen: billions of comparisons under the pool's write lock.
#[test]
fn eviction_cost_follows_what_it_evicts() {
    const N: u32 = 20_000;
    const EVICT: usize = 600;
    let mp = Mempool::with_config(MempoolConfig {
        max_size_bytes: usize::MAX,
        min_fee_rate: 0,
        ..Default::default()
    });
    let mut inner = mp.inner.write();
    let mut by_rate: Vec<Txid> = Vec::new();
    let mut size = 0;
    for i in 0..N {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        let tx = spend(&[OutPoint { txid: Txid::from_byte_array(bytes), vout: 0 }], COIN_VALUE, 1_000, 1, 7);
        let txid = tx.compute_txid();
        size = bitcoin::consensus::serialize(&tx).len();
        inner.spends.insert(tx.input[0].previous_output, txid);
        // A distinct feerate per entry, highest first.
        let fee = 1_000 + (N - i) as u64;
        inner.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                weight: 4 * size,
                fee_rate: policy::fee_rate_sat_per_kvb(fee, 4 * size as u64),
                time: 0,
                fee_delta: 0,
                sigop_cost: 0,
                prev_scripthashes: Vec::new(),
                prev_amounts: Vec::new(),
                prev_scripts: Vec::new(),
                sp_tweak: None,
                source: TxSource::P2p,
                scope: QuarantineScope::acting(),
                quarantine_rule: None,
            },
        );
        inner.account_insert(QuarantineScope::acting(), size);
        by_rate.push(txid);
    }

    let start = std::time::Instant::now();
    let gone = Mempool::evict_lowest_fee_entries(&mut inner, EVICT * size, false, 0);
    let took = start.elapsed();
    drop(inner);

    let mut expected: Vec<Txid> = by_rate[by_rate.len() - EVICT..].to_vec();
    expected.sort();
    let mut got = gone.clone();
    got.sort();
    assert_eq!(got, expected, "the {EVICT} lowest feerates go");
    assert!(took < std::time::Duration::from_secs(2), "evicting {EVICT} of {N} took {took:?}");
}

/// Fails every transaction with libbitcoinconsensus's coarse reason, and
/// records whether the pool was free when asked to name the failure.
struct NamesWhenAsked<'a> {
    mp: &'a Mempool,
    pool_free: Mutex<Option<bool>>,
}

impl ScriptVerifier for NamesWhenAsked<'_> {
    fn verify_transaction(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
        _height: u32,
    ) -> Result<(), ScriptError> {
        Err(ScriptError::VerifyFailed { input: 0, reason: "ERR_SCRIPT".into() })
    }

    fn name_failure(
        &self,
        _tx: &Transaction,
        _prev_outputs: &[TxOut],
        _height: u32,
        err: ScriptError,
    ) -> ScriptError {
        *self.pool_free.lock() = Some(self.mp.inner.try_write().is_some());
        ScriptError::VerifyFailed { input: err.input(), reason: "Invalid Schnorr signature".into() }
    }
}

/// The rejection carries the specific script error, and finding it (which
/// can mean running the second script engine over the input) happens after
/// the pool is released, so block connection and template building do not
/// wait on it.
#[test]
fn a_script_failure_is_named_after_the_pool_is_released() {
    let (cs, mp, dir) = env(&[1]);
    let verifier = NamesWhenAsked { mp: &mp, pool_free: Mutex::new(None) };
    let err = mp
        .accept_transaction(spend(&[prev(1)], COIN_VALUE, 1_000, 1, 1), &cs, &verifier, TxSource::P2p, false)
        .expect_err("its scripts fail");
    match err {
        MempoolError::Script(reason, _) => assert_eq!(reason, "Invalid Schnorr signature"),
        other => panic!("{other:?}"),
    }
    assert_eq!(*verifier.pool_free.lock(), Some(true), "the failure was named under the pool's write lock");
    assert!(pool(&mp).is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
