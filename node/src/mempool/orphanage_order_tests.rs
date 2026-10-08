//! The orphanage's eviction queue holds each live orphan exactly once.
//!
//! It kept the txid of every orphan it had ever held: a removal or an
//! expiry left the txid behind, and only a full pool popped stale ones off
//! the front. A peer at its per-peer quota scans the queue on every add, so
//! the scan grew with every orphan that peer had sent.

use super::*;
use bitcoin::hashes::Hash;

fn parent(i: u32) -> Txid {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&i.to_le_bytes());
    Txid::from_byte_array(bytes)
}

/// An orphan spending output 0 of [`parent`]`(i)`.
fn orphan(i: u32) -> (Transaction, HashSet<Txid>) {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid: parent(i), vout: 0 },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    (tx, HashSet::from([parent(i)]))
}

fn add(pool: &TxOrphanage, i: u32, peer: PeerId) -> Txid {
    let (tx, missing) = orphan(i);
    let txid = tx.compute_txid();
    assert_eq!(pool.add(tx, peer, missing).unwrap(), AddOutcome::Added);
    txid
}

fn queued(pool: &TxOrphanage) -> usize {
    pool.inner.lock().order.len()
}

/// One peer streaming orphans past its quota of 50: each add evicts that
/// peer's oldest, and the queue stays the size of the pool.
#[test]
fn a_peer_at_its_quota_does_not_grow_the_queue() {
    let pool = TxOrphanage::with_defaults();
    for i in 0..10_000 {
        add(&pool, i, 1);
    }
    assert_eq!(pool.len(), DEFAULT_MAX_ORPHAN_PER_PEER);
    assert_eq!(queued(&pool), pool.len(), "the queue kept evicted orphans");
}

/// Removal and expiry take the orphan out of the queue too.
#[test]
fn removed_and_expired_orphans_leave_the_queue() {
    let pool = TxOrphanage::with_defaults();
    let ids: Vec<Txid> = (0..20).map(|i| add(&pool, i, i as PeerId)).collect();
    for txid in &ids[..10] {
        pool.remove(txid).expect("present");
    }
    assert_eq!(queued(&pool), 10, "removed orphans stayed queued");
    pool.expire(Instant::now() + DEFAULT_ORPHAN_EXPIRY);
    assert!(pool.is_empty());
    assert_eq!(queued(&pool), 0, "expired orphans stayed queued");
}

/// An orphan that is removed and sent again queues as the newest, once.
/// With its first place still queued, the full pool evicted it in place of
/// the orphan that really was the oldest.
#[test]
fn a_returning_orphan_queues_as_the_newest() {
    let pool = TxOrphanage::new(OrphanageConfig {
        max_count: 2,
        max_per_peer: 10,
        expiry: DEFAULT_ORPHAN_EXPIRY,
    });
    let a = add(&pool, 1, 1);
    let b = add(&pool, 2, 1);
    pool.remove(&a).expect("present");
    assert_eq!(add(&pool, 1, 1), a);
    assert_eq!(queued(&pool), 2);

    let c = add(&pool, 3, 1);
    assert!(!pool.contains(&b), "the oldest orphan should make the room");
    assert!(pool.contains(&a), "the orphan that came back was evicted as if it were the oldest");
    assert!(pool.contains(&c));
}

/// The per-peer quota still evicts that peer's oldest orphan, and no one
/// else's.
#[test]
fn the_quota_evicts_the_peers_own_oldest() {
    let pool = TxOrphanage::new(OrphanageConfig {
        max_count: 100,
        max_per_peer: 3,
        expiry: DEFAULT_ORPHAN_EXPIRY,
    });
    let first = add(&pool, 1, 1);
    let other = add(&pool, 2, 2);
    let second = add(&pool, 3, 1);
    let third = add(&pool, 4, 1);
    let fourth = add(&pool, 5, 1);
    assert!(!pool.contains(&first));
    for txid in [other, second, third, fourth] {
        assert!(pool.contains(&txid));
    }
    assert_eq!(queued(&pool), 4);
}
