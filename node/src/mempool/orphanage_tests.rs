//! The orphanage's limits and indexes, after Core's
//! `src/test/orphanage_tests.cpp` (`peer_dos_limits`,
//! `same_txid_diff_witness`, `process_block`, `multiple_announcers`).

use super::*;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

/// A distinct txid for each seed.
fn txid(seed: u64) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[31] = 0xAA;
    Txid::from_byte_array(bytes)
}

/// Core's `MakeTransactionSpending`: spends `outpoints`, with a witness so
/// the wtxid differs from the txid. Every transaction with as many inputs
/// has the same weight.
fn spending(outpoints: &[OutPoint], tag: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: outpoints
            .iter()
            .map(|o| TxIn {
                previous_output: *o,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[1u8]]),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(tag),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

/// A one-input orphan of the unique parent `txid(seed)`.
fn orphan(seed: u64) -> Transaction {
    spending(&[OutPoint { txid: txid(seed), vout: 0 }], seed)
}

/// `n` outpoints of distinct parents, starting at `seed`.
fn outpoints(seed: u64, n: u64) -> Vec<OutPoint> {
    (0..n).map(|i| OutPoint { txid: txid(seed + i), vout: i as u32 }).collect()
}

/// Core's `MakeMutation`: the same txid with another witness.
fn mutation(tx: &Transaction) -> Transaction {
    let mut tx = tx.clone();
    tx.input[0].witness.push([5u8]);
    tx
}

/// `tx` padded with an output script to at least `weight`.
fn bulked(mut tx: Transaction, weight: u64) -> Transaction {
    let short = weight.saturating_sub(tx.weight().to_wu());
    tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a; short.div_ceil(4) as usize]),
    });
    tx
}

fn parents(tx: &Transaction) -> HashSet<Txid> {
    tx.input.iter().map(|i| i.previous_output.txid).collect()
}

fn add(pool: &TxOrphanage, tx: &Transaction, peer: PeerId) -> AddOutcome {
    pool.add(tx.clone(), peer, parents(tx)).unwrap()
}

fn has(pool: &TxOrphanage, tx: &Transaction) -> bool {
    pool.contains_wtxid(&tx.compute_wtxid())
}

fn limited(max_global_latency_score: u32, reserved_peer_usage: u64) -> TxOrphanage {
    TxOrphanage::new(OrphanageConfig { max_global_latency_score, reserved_peer_usage })
}

/// The weight of a one-input orphan, the same for all of them.
fn unit() -> u64 {
    let w = orphan(0).weight().to_wu();
    assert_eq!(orphan(1).weight().to_wu(), w);
    w
}

#[test]
fn an_orphan_added_and_erased_leaves_nothing_behind() {
    let pool = TxOrphanage::with_defaults();
    let tx = orphan(1);
    assert_eq!(add(&pool, &tx, 42), AddOutcome::Added);
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&tx.compute_txid()));
    assert_eq!(pool.children_of(&txid(1)), vec![tx.compute_wtxid()]);
    assert_eq!(pool.weight(), tx.weight().to_wu());
    assert_eq!(pool.announcements_from_peer(42), 1);
    pool.sanity_check();

    assert!(pool.erase(&tx.compute_wtxid()));
    assert!(!pool.erase(&tx.compute_wtxid()), "already gone");
    assert!(pool.is_empty());
    assert_eq!((pool.bytes(), pool.weight(), pool.announcements(), pool.latency_score()), (0, 0, 0, 0));
    let inner = pool.inner.lock();
    assert!(inner.by_txid.is_empty() && inner.by_parent.is_empty() && inner.by_outpoint.is_empty());
    assert!(inner.peers.is_empty(), "a peer with nothing announced is not tracked");
}

#[test]
fn an_orphan_over_the_standard_weight_is_refused() {
    let pool = TxOrphanage::with_defaults();
    let tx = bulked(orphan(1), MAX_STANDARD_TX_WEIGHT as u64 + 1);
    assert!(matches!(pool.add(tx.clone(), 1, parents(&tx)), Err(OrphanReject::TooLarge)));
    assert!(pool.is_empty());
}

/// Empty `missing_parents` would strand the orphan: `by_parent` stays
/// empty for it, so `children_of()` never returns it.
#[test]
fn an_orphan_with_no_missing_parent_is_refused() {
    let pool = TxOrphanage::with_defaults();
    assert!(matches!(pool.add(orphan(1), 1, HashSet::new()), Err(OrphanReject::NoMissingParents)));
    assert!(pool.is_empty());
}

/// Core's `multiple_announcers`: adding a held orphan again makes the
/// sender an announcer, and changes nothing else.
#[test]
fn a_held_orphan_sent_again_records_the_sender() {
    let pool = TxOrphanage::with_defaults();
    let tx = orphan(1);
    let wtxid = tx.compute_wtxid();
    assert_eq!(add(&pool, &tx, 0), AddOutcome::Added);
    assert_eq!(add(&pool, &tx, 0), AddOutcome::Duplicate);
    assert_eq!(pool.announcements(), 1, "the same peer again is no new announcement");

    assert!(pool.add_announcer(&wtxid, 2));
    assert!(!pool.add_announcer(&wtxid, 2), "already an announcer");
    assert!(!pool.add_announcer(&orphan(9).compute_wtxid(), 2), "no such orphan");
    assert_eq!(add(&pool, &tx, 1), AddOutcome::Duplicate);
    assert!(pool.has_announcer(&wtxid, 1), "AddTx of a held orphan is AddAnnouncer");
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.announcements(), 3);
    assert_eq!(pool.weight(), tx.weight().to_wu(), "an orphan's weight counts once");
    assert_eq!(pool.entry(&wtxid).unwrap().announcers(), vec![0, 1, 2]);
    pool.sanity_check();
}

/// Core's `multiple_announcers`: a departing peer stops announcing, and
/// only the orphans no other peer announced go.
#[test]
fn a_departing_peer_takes_only_its_own_orphans() {
    let pool = TxOrphanage::with_defaults();
    let shared = orphan(1);
    let own = orphan(2);
    add(&pool, &shared, 1);
    add(&pool, &own, 1);
    pool.add_announcer(&shared.compute_wtxid(), 2);

    assert_eq!(pool.erase_for_peer(1), vec![own.compute_wtxid()]);
    assert!(!has(&pool, &own));
    assert!(!pool.contains(&own.compute_txid()), "every index forgets it");
    assert_eq!(pool.entry(&shared.compute_wtxid()).unwrap().announcers(), vec![2]);
    assert!(pool.children_from_peer(&txid(1), 1).is_empty());
    assert!(pool.erase_for_peer(1).is_empty());
    pool.sanity_check();

    pool.erase_for_peer(2);
    assert!(pool.is_empty());
    assert!(pool.inner.lock().peers.is_empty());
}

/// Core's `same_txid_diff_witness`: orphans that differ only in their
/// witness are both held, and each is erased on its own.
#[test]
fn orphans_differing_only_in_witness_are_both_held() {
    let pool = TxOrphanage::with_defaults();
    let normal = orphan(1);
    let mutated = mutation(&normal);
    assert_eq!(normal.compute_txid(), mutated.compute_txid());
    assert_ne!(normal.compute_wtxid(), mutated.compute_wtxid());

    assert_eq!(add(&pool, &normal, 0), AddOutcome::Added);
    assert!(!pool.erase(&mutated.compute_wtxid()), "not held");
    assert_eq!(add(&pool, &mutated, 0), AddOutcome::Added);
    assert!(has(&pool, &normal) && has(&pool, &mutated));
    assert_eq!(pool.children_of(&txid(1)).len(), 2);
    assert_eq!(pool.children_from_peer(&txid(1), 0), vec![mutated.clone(), normal.clone()], "newest first");
    pool.sanity_check();

    assert!(pool.erase(&mutated.compute_wtxid()));
    assert!(has(&pool, &normal) && !has(&pool, &mutated));
    assert!(pool.contains(&normal.compute_txid()));
    assert!(pool.erase(&normal.compute_wtxid()));
    assert!(!pool.contains(&normal.compute_txid()));
}

/// Core's `process_block`: a block takes out every orphan spending an
/// outpoint one of its transactions spends: the orphan it includes, one
/// with the same txid and another witness, and those that conflict with
/// it in all or some inputs.
#[test]
fn a_block_takes_out_the_orphans_it_includes_or_conflicts_with() {
    let pool = TxOrphanage::with_defaults();
    let o = outpoints(100, 6);
    let control = orphan(1);
    add(&pool, &control, 0);

    let included = spending(&[o[0]], 1);
    add(&pool, &included, 0);
    let in_block_mutated = spending(&[o[1]], 2);
    let held_mutation = mutation(&in_block_mutated);
    add(&pool, &held_mutation, 0);
    let in_block_conflict = spending(&[o[2]], 3);
    let held_conflict = spending(&[o[2]], 4);
    add(&pool, &held_conflict, 0);
    let in_block_partial = spending(&[o[3], o[4]], 5);
    let held_partial = spending(&[o[4], o[5]], 6);
    add(&pool, &held_partial, 1);

    let block = bitcoin::Block {
        header: bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header,
        txdata: vec![included.clone(), in_block_mutated, in_block_conflict, in_block_partial],
    };
    let mut removed = pool.erase_for_block(&block);
    removed.sort_unstable();
    let mut expected: Vec<Wtxid> =
        [&included, &held_mutation, &held_conflict, &held_partial].iter().map(|t| t.compute_wtxid()).collect();
    expected.sort_unstable();
    assert_eq!(removed, expected);
    assert_eq!(pool.len(), 1);
    assert!(has(&pool, &control));
    assert_eq!(pool.announcements_from_peer(1), 0, "every announcer's share goes with it");
    pool.sanity_check();
}

/// Core's `peer_dos_limits`, single peer: past either limit, the older
/// orphan goes.
#[test]
fn one_peer_past_either_limit_loses_its_oldest() {
    let w = unit();
    let low_ann = limited(1, w * 10);
    let low_mem = limited(10, w);
    for pool in [&low_ann, &low_mem] {
        add(pool, &orphan(0), 8);
        add(pool, &orphan(1), 8);
        assert!(!has(pool, &orphan(0)), "the older one is evicted");
        assert!(has(pool, &orphan(1)));
        pool.sanity_check();
    }
}

/// Core's `peer_dos_limits`: the latency score counts one per ten inputs,
/// so two announcements can be past a limit of five.
#[test]
fn the_latency_score_counts_inputs() {
    let pool = limited(5, unit() * 1000);
    add(&pool, &orphan(0), 10);
    let wide = spending(&outpoints(1000, 45), 1);
    add(&pool, &wide, 10);
    assert!(!has(&pool, &orphan(0)));
    assert!(has(&pool, &wide));
    assert_eq!(pool.latency_score(), 1 + 4);
    pool.sanity_check();
}

/// Core's `peer_dos_limits`: with the announcement limit hit, the peer
/// with the highest DoS score loses its oldest, one for each new one, and
/// no other peer loses anything.
#[test]
fn the_dosiest_peer_loses_its_oldest() {
    let max_announcements: u64 = 60;
    let pool = limited(max_announcements as u32, unit() * 1000);
    let txns: Vec<Transaction> = (0..100).map(orphan).collect();
    let (dosy, peer1, peer2) = (0, 1, 2);
    for tx in &txns[..60] {
        add(&pool, tx, dosy);
    }
    assert_eq!(pool.announcements_from_peer(dosy), 60);
    pool.sanity_check();

    // Peer 1's ten new orphans each evict the oldest of peer 0's.
    for i in 0..10u64 {
        add(&pool, &txns[(max_announcements + i) as usize], peer1);
        assert_eq!(pool.announcements_from_peer(peer1), (i + 1) as u32);
        assert_eq!(pool.announcements_from_peer(dosy), (max_announcements - i - 1) as u32);
        assert!(!has(&pool, &txns[i as usize]), "FIFO within the peer");
    }
    // Peer 2 announcing orphans peer 0 announced takes peer 0's
    // announcement, not the orphan.
    for i in 10..20u64 {
        let tx = &txns[i as usize];
        assert!(pool.has_announcer(&tx.compute_wtxid(), dosy));
        add(&pool, tx, peer2);
        assert_eq!(pool.announcements_from_peer(dosy), (max_announcements - i - 1) as u32);
        assert_eq!(pool.announcements_from_peer(peer1), 10);
        assert_eq!(pool.announcements_from_peer(peer2), (i + 1 - 10) as u32);
        assert!(!pool.has_announcer(&tx.compute_wtxid(), dosy));
        assert!(has(&pool, tx));
    }
    // Six peers, ten each: still only peer 0 loses announcements.
    let per_peer = max_announcements / 6;
    let total = pool.announcements();
    for peer in 3..6u64 {
        for i in 0..per_peer {
            add(&pool, &txns[(peer * per_peer + i) as usize], peer);
            assert_eq!(pool.announcements(), total, "each one in evicts one");
        }
    }
    for peer in 0..6 {
        assert_eq!(pool.announcements_from_peer(peer), per_peer as u32, "peer {peer}");
    }
    pool.sanity_check();
}

/// Core's `peer_dos_limits`: the weight limit grows with each peer that has
/// an announcement and the per-peer latency share shrinks; a peer with none
/// left no longer counts.
#[test]
fn the_limits_follow_the_number_of_peers() {
    let pool = TxOrphanage::with_defaults();
    let lat = DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE;
    let res = DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER;
    let limits = |pool: &TxOrphanage| {
        let inner = pool.inner.lock();
        (pool.max_global_usage(&inner), pool.max_peer_latency_score(&inner))
    };
    assert_eq!(limits(&pool), (res, lat));
    add(&pool, &orphan(0), 0);
    assert_eq!(limits(&pool), (res, lat));
    add(&pool, &orphan(1), 1);
    assert_eq!(limits(&pool), (res * 2, lat / 2));
    add(&pool, &orphan(2), 2);
    assert_eq!(limits(&pool), (res * 3, lat / 3));
    add(&pool, &orphan(3), 2);
    assert_eq!(limits(&pool), (res * 3, lat / 3), "the same peer again");
    pool.erase_for_peer(2);
    assert_eq!(limits(&pool), (res * 2, lat / 2));
    pool.erase(&orphan(0).compute_wtxid());
    assert_eq!(limits(&pool), (res, lat));
    assert_eq!(pool.max_latency_score(), lat);
    assert_eq!(pool.max_weight(), res);
    pool.sanity_check();
}

/// Core's `peer_dos_limits`: one large orphan can evict all of its
/// sender's earlier ones at once, and none of another peer's.
#[test]
fn one_large_orphan_evicts_several_of_its_senders() {
    let w = unit();
    let large = bulked(spending(&outpoints(5000, 1), 0), 10 * w);
    let large_weight = large.weight().to_wu();
    assert!(large_weight > 10 * w && large_weight < 11 * w, "{large_weight} vs {w}");
    let pool = limited(20, large_weight);
    let (normal, big) = (0, 1);
    for i in 0..20 {
        add(&pool, &orphan(i), if i < 10 { normal } else { big });
    }
    assert!(pool.latency_score() <= pool.max_latency_score());
    assert!(pool.weight() <= pool.max_weight());

    add(&pool, &large, big);
    assert_eq!(pool.announcements_from_peer(normal), 10);
    assert_eq!(pool.announcements_from_peer(big), 1);
    assert!(pool.has_announcer(&large.compute_wtxid(), big));
    assert_eq!(pool.announcements(), 11);
    pool.sanity_check();
}

/// Core's `peer_dos_limits`: an orphan's input score counts once, and
/// once more against each peer that announced it.
#[test]
fn the_input_score_counts_once_per_orphan() {
    let pool = TxOrphanage::with_defaults();
    let nine = outpoints(1000, 9);
    for i in 0..10 {
        add(&pool, &spending(&nine, i), 0);
    }
    assert_eq!((pool.announcements(), pool.latency_score()), (10, 10));

    let fifty = outpoints(2000, 50);
    for i in 0..10 {
        let tx = spending(&fifty, 100 + i);
        assert_eq!(add(&pool, &tx, 0), AddOutcome::Added);
        if i < 5 {
            assert_eq!(add(&pool, &tx, 1), AddOutcome::Duplicate);
        }
    }
    assert_eq!(pool.announcements(), 25);
    assert_eq!(pool.latency_score(), 25 + 50);
    assert_eq!(pool.announcements_from_peer(0), 20);
    assert_eq!(pool.latency_score_from_peer(0), 20 + 10 * 5);
    assert_eq!(pool.announcements_from_peer(1), 5);
    assert_eq!(pool.latency_score_from_peer(1), 5 + 5 * 5);
    pool.sanity_check();
}

/// What `p2p_opportunistic_1p1c.py` `test_orphanage_dos_large` relies on:
/// with ten peers holding one ~400 kWU orphan each and an eleventh peer
/// streaming dozens, a twelfth peer's orphan of the same size survives,
/// because it is within that peer's reservation.
#[test]
fn a_peer_within_its_reservation_keeps_its_orphan() {
    let pool = TxOrphanage::with_defaults();
    let big = |seed: u64| bulked(spending(&outpoints(seed * 10, 1), seed), 396_000);
    let normal_peer = 100;
    let doser = 200;
    for peer in 0..10 {
        add(&pool, &big(peer), peer);
    }
    let kept = big(50);
    add(&pool, &kept, normal_peer);
    for seed in 60..100 {
        add(&pool, &big(seed), doser);
    }
    assert!(has(&pool, &kept), "the normal peer's orphan was evicted");
    assert!(pool.len() < 10 + 1 + 40, "something was evicted");
    for peer in 0..10 {
        assert!(has(&pool, &big(peer)), "peer {peer} is within its reservation");
    }
    assert!(pool.weight() <= pool.max_weight());
    pool.sanity_check();
}

/// Core's `GetChildrenFromSamePeer`: newest announcement first, and only
/// the peer's own.
#[test]
fn children_from_a_peer_come_newest_first() {
    let pool = TxOrphanage::with_defaults();
    let parent = txid(7);
    let kids: Vec<Transaction> = (0..3).map(|i| spending(&[OutPoint { txid: parent, vout: i }], i as u64)).collect();
    add(&pool, &kids[0], 1);
    add(&pool, &kids[1], 2);
    add(&pool, &kids[2], 1);
    pool.add_announcer(&kids[1].compute_wtxid(), 1);
    assert_eq!(pool.children_from_peer(&parent, 1), vec![kids[1].clone(), kids[2].clone(), kids[0].clone()]);
    assert_eq!(pool.children_from_peer(&parent, 2), vec![kids[1].clone()]);
    assert!(pool.children_from_peer(&parent, 3).is_empty());
}

/// A reconsidered orphan still missing inputs waits for its new parents,
/// and one left with none goes.
#[test]
fn a_reconsidered_orphan_waits_for_its_new_parents() {
    let pool = TxOrphanage::with_defaults();
    let tx = spending(&outpoints(10, 2), 0);
    let wtxid = tx.compute_wtxid();
    add(&pool, &tx, 1);
    assert_eq!(pool.children_of(&txid(10)), vec![wtxid]);

    assert!(pool.set_missing_parents(&wtxid, HashSet::from([txid(11)])));
    assert!(pool.children_of(&txid(10)).is_empty(), "the arrived parent is forgotten");
    assert_eq!(pool.children_of(&txid(11)), vec![wtxid]);
    pool.sanity_check();

    assert!(!pool.set_missing_parents(&wtxid, HashSet::new()));
    assert!(pool.is_empty());
    assert!(!pool.set_missing_parents(&wtxid, HashSet::from([txid(11)])), "not held");
    pool.sanity_check();
}

/// Core's `GetOrphanTransactions` lists the orphans in wtxid order.
#[test]
fn the_orphans_are_listed_in_wtxid_order() {
    let pool = TxOrphanage::with_defaults();
    for i in 0..20 {
        add(&pool, &orphan(i), i % 3);
    }
    let listed: Vec<Wtxid> = pool.orphans().iter().map(|(tx, _)| tx.compute_wtxid()).collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    assert_eq!(listed.len(), 20);
    assert_eq!(listed, sorted);
}

/// A peer streaming orphans holds no more than its share, and the
/// orphanage's indexes stay the size of what it holds.
#[test]
fn a_streaming_peer_does_not_grow_the_orphanage() {
    let pool = TxOrphanage::with_defaults();
    for i in 0..10_000 {
        add(&pool, &orphan(i), 1);
    }
    assert!(pool.latency_score() <= DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE);
    assert!(pool.weight() <= DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER);
    {
        let inner = pool.inner.lock();
        assert_eq!(inner.by_outpoint.len(), inner.by_wtxid.len());
        assert_eq!(inner.peers[&1].announcements.len(), inner.by_wtxid.len());
    }
    pool.sanity_check();
}

/// The DoS score orders as Core's `FeeFrac`: by value, and between equal
/// values the smaller denominator is greater.
#[test]
fn the_dos_score_orders_as_a_feefrac() {
    let s = |num, den| DosScore { num, den };
    assert!(s(2, 3) > s(1, 2));
    assert!(s(1, 2) > s(2, 4), "equal value, smaller denominator");
    assert!(s(3, 2).exceeds(DosScore::ONE));
    assert!(!s(2, 2).exceeds(DosScore::ONE));
    assert!(s(2, 2) < DosScore::ONE);
}
