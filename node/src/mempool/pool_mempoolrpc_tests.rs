//! The mempool's half of the RPC surface, checked against Bitcoin Core:
//! `getmempoolentry` / `getrawmempool verbose` (`entryToJSON`,
//! src/rpc/mempool.cpp), `getmempoolinfo` (`MempoolInfoToJSON`),
//! `removeForBlock` (src/txmempool.cpp) and the expiry pass behind every
//! admission (`CTxMemPool::Expire`).

use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
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

/// Spend `prevs` (worth `in_value` together) to one P2WPKH output, paying
/// `fee`, with each input's `sequence` and a one-byte witness. The witness
/// makes the weight something other than a multiple of four.
fn spend_seq(prevs: &[OutPoint], in_value: u64, fee: u64, tag: u8, sequence: u32) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: *p,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::from_slice(&[[tag]]),
            })
            .collect(),
        output: vec![TxOut { value: Amount::from_sat(in_value - fee), script_pubkey: p2wpkh(tag) }],
    }
}

fn spend(prevs: &[OutPoint], in_value: u64, fee: u64, tag: u8) -> Transaction {
    spend_seq(prevs, in_value, fee, tag, Sequence::MAX.0)
}

/// Output 0 of `tx`.
fn out0(tx: &Transaction) -> OutPoint {
    OutPoint { txid: tx.compute_txid(), vout: 0 }
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

fn admit(mp: &Mempool, cs: &ChainState, tx: Transaction) -> Txid {
    mp.accept_transaction(tx, cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted")
}

fn entry_json(mp: &Mempool, txid: &Txid) -> serde_json::Value {
    mp.get_entry_verbose(txid).expect("entry is in the pool")
}

/// A BTC amount as `getmempoolentry` prints it, back in satoshis.
fn sats(v: &serde_json::Value) -> u64 {
    let s = v.to_string();
    (s.trim_matches('"').parse::<f64>().expect("an amount") * 100_000_000.0).round() as u64
}

#[test]
fn entry_vsize_rounds_up_as_core_does() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2);
    let child = spend(&[out0(&parent)], COIN_VALUE - 1_000, 1_000, 3);
    let weight = parent.weight().to_wu();
    assert_ne!(weight % 4, 0, "the fixture must have a weight that is not a multiple of four");
    let p = admit(&mp, &cs, parent);
    let c = admit(&mp, &cs, child.clone());

    // Core's `GetVirtualTransactionSize`: (weight + 3) / 4.
    let vsize = weight.div_ceil(4);
    let child_vsize = child.weight().to_wu().div_ceil(4);
    let pv = entry_json(&mp, &p);
    assert_eq!(pv["vsize"].as_u64(), Some(vsize), "{pv}");
    assert_eq!(pv["descendantsize"].as_u64(), Some(vsize + child_vsize), "{pv}");
    let cv = entry_json(&mp, &c);
    assert_eq!(cv["ancestorsize"].as_u64(), Some(vsize + child_vsize), "{cv}");

    // `getmempoolinfo.bytes` is the sum of those, and `getmempoolsummary`
    // reports the same rows and total.
    assert_eq!(mp.info().vsize as u64, vsize + child_vsize);
    let summary = mp.summary(10);
    assert_eq!(summary.bytes as u64, vsize + child_vsize);
    let row = summary.top.iter().find(|r| r.txid == c.to_string()).expect("child row");
    assert_eq!(row.vsize as u64, child_vsize);
    assert_eq!(row.ancestorsize as u64, vsize + child_vsize);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entry_height_is_the_tip_when_it_entered() {
    let (cs, mp, dir) = env(&[1]);
    let script = p2wpkh(0x42);
    crate::mining::miner::mine_blocks_to_script(&cs, &mp, script, 3, u64::MAX).expect("mined");
    assert_eq!(cs.tip_height(), 3);

    let txid = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 1_000, 2));
    // Core's `entryHeight` is the active chain's height in `PreChecks`.
    assert_eq!(entry_json(&mp, &txid)["height"].as_u64(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entry_depends_names_direct_parents_only() {
    // a → b → c, and c also spends a confirmed coin.
    let (cs, mp, dir) = env(&[1, 2]);
    let a = spend(&[prev(1)], COIN_VALUE, 1_000, 3);
    let b = spend(&[out0(&a)], COIN_VALUE - 1_000, 1_000, 4);
    let c = spend(&[out0(&b), prev(2)], 2 * COIN_VALUE - 2_000, 1_000, 5);
    let a = admit(&mp, &cs, a);
    let b = admit(&mp, &cs, b);
    let c = admit(&mp, &cs, c);

    assert_eq!(entry_json(&mp, &c)["depends"], serde_json::json!([b.to_string()]));
    assert_eq!(entry_json(&mp, &b)["depends"], serde_json::json!([a.to_string()]));
    assert_eq!(entry_json(&mp, &a)["depends"], serde_json::json!([]));
    // Every ancestor still counts toward the ancestor fields.
    assert_eq!(entry_json(&mp, &c)["ancestorcount"].as_u64(), Some(3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entry_bip125_replaceable_follows_an_ancestor_that_signals() {
    let (cs, mp, dir) = env(&[1, 2]);
    // The parent signals BIP 125; its child does not.
    let parent = spend_seq(&[prev(1)], COIN_VALUE, 1_000, 3, 0xffff_fffd);
    let child = spend(&[out0(&parent)], COIN_VALUE - 1_000, 1_000, 4);
    // An unrelated transaction that signals nothing and has no ancestors.
    let lone = spend(&[prev(2)], COIN_VALUE, 1_000, 5);
    let parent = admit(&mp, &cs, parent);
    let child = admit(&mp, &cs, child);
    let lone = admit(&mp, &cs, lone);

    assert_eq!(entry_json(&mp, &parent)["bip125-replaceable"], true);
    // Core's `IsRBFOptIn` looks through the in-mempool ancestors.
    assert_eq!(entry_json(&mp, &child)["bip125-replaceable"], true);
    assert_eq!(entry_json(&mp, &lone)["bip125-replaceable"], false);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entry_fee_rollups_use_modified_fees() {
    let (cs, mp, dir) = env(&[1]);
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 2);
    let child = spend(&[out0(&parent)], COIN_VALUE - 1_000, 2_000, 3);
    let p = admit(&mp, &cs, parent);
    let c = admit(&mp, &cs, child);
    mp.prioritise_transaction(&p, 5_000).expect("prioritised");

    // Core sums `GetModifiedFee` over the relatives.
    let cv = entry_json(&mp, &c);
    assert_eq!(sats(&cv["fees"]["ancestor"]), 1_000 + 5_000 + 2_000, "{cv}");
    assert_eq!(cv["ancestorfees"].as_u64(), Some(1_000 + 5_000 + 2_000), "{cv}");
    let pv = entry_json(&mp, &p);
    assert_eq!(sats(&pv["fees"]["base"]), 1_000);
    assert_eq!(sats(&pv["fees"]["modified"]), 6_000);
    assert_eq!(sats(&pv["fees"]["descendant"]), 6_000 + 2_000, "{pv}");
    assert_eq!(pv["descendantfees"].as_u64(), Some(6_000 + 2_000), "{pv}");

    // `getmempoolsummary` rows read the same rollup.
    let summary = mp.summary(10);
    let row = summary.top.iter().find(|r| r.txid == c.to_string()).expect("child row");
    assert_eq!(row.ancestorfees, 1_000 + 5_000 + 2_000);

    // `total_fee` is Core's `GetTotalFee`: base fees, deltas ignored.
    assert_eq!(mp.info().total_fee, 1_000 + 2_000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn info_usage_grows_with_the_pool() {
    let (cs, mp, dir) = env(&[1, 2]);
    assert_eq!(mp.info().usage, 0);
    admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 1_000, 3));
    let one = mp.info().usage;
    // An estimate, but never less than the transaction's own bytes.
    assert!(one > mp.info().bytes, "usage {one} must cover the serialized bytes");
    admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 1_000, 4));
    assert!(mp.info().usage > one);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block of `txs` after a coinbase. Only `remove_for_block` reads it, so
/// its header is never checked.
fn block_with(txs: Vec<Transaction>) -> bitcoin::Block {
    let coinbase = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51, 0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: p2wpkh(0x99) }],
    };
    let mut txdata = vec![coinbase];
    txdata.extend(txs);
    bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    }
}

#[test]
fn block_conflict_takes_the_conflicts_descendants() {
    let (cs, mp, dir) = env(&[1, 2]);
    // parent spends coin 1; child and grandchild descend from it. An
    // unrelated transaction spends coin 2.
    let parent = spend(&[prev(1)], COIN_VALUE, 1_000, 3);
    let child = spend(&[out0(&parent)], COIN_VALUE - 1_000, 1_000, 4);
    let grandchild = spend(&[out0(&child)], COIN_VALUE - 2_000, 1_000, 5);
    let other = spend(&[prev(2)], COIN_VALUE, 1_000, 6);
    let p = admit(&mp, &cs, parent);
    let c = admit(&mp, &cs, child);
    let g = admit(&mp, &cs, grandchild);
    let o = admit(&mp, &cs, other);
    let bytes_before = mp.info().bytes;

    // A block confirms another spend of coin 1.
    let rival = spend(&[prev(1)], COIN_VALUE, 3_000, 7);
    mp.remove_for_block(&block_with(vec![rival]), 1);

    // Core's `removeConflicts` → `removeRecursive`: the conflict and
    // everything descending from it.
    for (txid, what) in [(p, "the conflict"), (c, "its child"), (g, "its grandchild")] {
        assert!(mp.get(&txid).is_none(), "{what} must leave the pool");
    }
    assert!(mp.get(&o).is_some(), "an unrelated transaction stays");
    assert_eq!(mp.info().size, 1);
    assert!(mp.info().bytes < bytes_before);
    let inner = mp.inner.read();
    assert!(
        inner.spends.values().all(|t| *t == o),
        "no spend of a removed transaction may stay indexed"
    );
    drop(inner);

    let evicted: HashSet<Txid> = mp
        .recent_events()
        .into_iter()
        .filter_map(|e| match e {
            MempoolEvent::LeaveEvicted { txid, reason: EvictReason::BlockConflict } => Some(txid),
            _ => None,
        })
        .collect();
    assert_eq!(evicted, HashSet::from([p, c, g]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_clears_the_priority_of_what_it_confirms() {
    let (cs, mp, dir) = env(&[1, 2, 3]);
    let confirmed = spend(&[prev(1)], COIN_VALUE, 1_000, 4);
    let conflict = spend(&[prev(2)], COIN_VALUE, 1_000, 5);
    let kept = spend(&[prev(3)], COIN_VALUE, 1_000, 6);
    let confirmed_txid = admit(&mp, &cs, confirmed.clone());
    let conflict_txid = admit(&mp, &cs, conflict);
    let kept_txid = admit(&mp, &cs, kept);
    // A delta for a transaction the pool has never seen, which the block
    // confirms too.
    let unseen = spend(&[prev(9)], COIN_VALUE, 1_000, 7);
    let unseen_txid = unseen.compute_txid();
    for txid in [confirmed_txid, conflict_txid, kept_txid, unseen_txid] {
        mp.prioritise_transaction(&txid, 1_000).expect("prioritised");
    }

    let rival = spend(&[prev(2)], COIN_VALUE, 2_000, 8);
    mp.remove_for_block(&block_with(vec![confirmed, unseen, rival]), 1);

    // Core's `removeForBlock` clears each block transaction's delta, and
    // `removeConflicts` the direct conflict's.
    let deltas = mp.get_prioritised_transactions();
    assert!(!deltas.contains_key(&confirmed_txid), "a confirmed transaction's delta is cleared");
    assert!(!deltas.contains_key(&unseen_txid), "a confirmed non-resident delta is cleared");
    assert!(!deltas.contains_key(&conflict_txid), "a block conflict's delta is cleared");
    assert_eq!(deltas.get(&kept_txid), Some(&(1_000, true, Some(1_000 + 1_000))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expiry_pass_skips_the_walk_until_something_can_have_expired() {
    let (cs, mp, dir) = env(&[1, 2]);
    let a = admit(&mp, &cs, spend(&[prev(1)], COIN_VALUE, 1_000, 3));
    admit(&mp, &cs, spend(&[prev(2)], COIN_VALUE, 1_000, 4));
    let expiry = mp.config.read().expiry_secs;
    let cutoff = crate::time::now_secs().saturating_sub(expiry);

    // Every entry is new: the pass has nothing to look for, so an admission
    // costs no walk over the pool.
    assert!(!mp.inner.read().entries.may_hold_older_than(cutoff));

    // An entry whose time is moved back in place is found again.
    mp.inner.write().entries.get_mut(&a).expect("a").time = 0;
    assert!(mp.inner.read().entries.may_hold_older_than(cutoff));
    assert_eq!(mp.remove_expired(), 1);
    assert!(mp.get(&a).is_none());
    // And once it is gone, the floor is the oldest entry left.
    assert!(!mp.inner.read().entries.may_hold_older_than(cutoff));
    let _ = std::fs::remove_dir_all(&dir);
}
