use super::*;
use bitcoin::hashes::Hash;

fn wtxid(i: u8) -> Wtxid {
    Wtxid::from_byte_array([i; 32])
}

fn started() -> TxRelay {
    let mut relay = TxRelay::default();
    assert!(relay.due(0, false, || 10));
    relay
}

/// Core's `broadcast_max`: 70, five more per thousand queued, at most 1000.
#[test]
fn a_flush_announces_more_of_a_longer_queue() {
    assert_eq!(broadcast_max(0), 70);
    assert_eq!(broadcast_max(999), 70);
    assert_eq!(broadcast_max(1_000), 75);
    assert_eq!(broadcast_max(10_500), 120);
    assert_eq!(broadcast_max(1_000_000), INVENTORY_BROADCAST_MAX);
}

/// Nothing is queued before the handshake's first flush, and nothing the
/// peer is known to have.
#[test]
fn only_a_started_peer_queues_and_only_what_it_does_not_know() {
    let mut relay = TxRelay::default();
    relay.queue(wtxid(1), &[1; 32]);
    assert_eq!(relay.inv_to_send(), 0, "queued before the handshake");
    assert_eq!(relay.last_inv_sequence(), 1, "Core starts it at 1");

    let mut relay = started();
    relay.add_known(&[2; 32]);
    relay.queue(wtxid(1), &[1; 32]);
    relay.queue(wtxid(2), &[2; 32]);
    assert_eq!(relay.inv_to_send(), 1);
    assert!(relay.knows(&[2; 32]) && !relay.knows(&[1; 32]));
}

/// Core's `fSendTrickle`: due when the timer has passed, and then the next
/// time is drawn; a `noban` peer every time, its timer kept.
#[test]
fn a_peer_is_due_when_its_timer_passes_or_it_has_noban() {
    let mut relay = TxRelay::default();
    assert!(!relay.started());
    assert!(relay.due(100, false, || 200), "never flushed");
    assert!(relay.started());
    assert!(!relay.due(150, false, || unreachable!("not due")));
    assert!(!relay.due(200, false, || unreachable!("not past yet")));
    assert!(relay.due(150, true, || unreachable!("noban keeps the timer")));
    assert!(relay.due(201, false, || 300));
    assert!(!relay.due(250, false, || unreachable!()));
}

/// A flush takes the whole queue and a waiting `mempool` request; what it
/// does not announce goes back, and the mempool sequence is recorded.
#[test]
fn a_flush_takes_the_queue_and_returns_what_it_did_not_send() {
    let mut relay = started();
    for i in 1..=3 {
        relay.queue(wtxid(i), &[i; 32]);
    }
    relay.request_mempool();
    let flush = relay.take(true);
    assert_eq!(flush.queued.len(), 3);
    assert!(flush.mempool);
    assert_eq!(relay.inv_to_send(), 0);
    assert!(!relay.take(true).mempool, "answered once");

    relay.queue(wtxid(4), &[4; 32]);
    relay.finish([wtxid(3)], Some(9));
    assert_eq!(relay.inv_to_send(), 2, "the unsent one and one queued meanwhile");
    assert_eq!(relay.last_inv_sequence(), 9);
    relay.unqueue(&wtxid(4));
    assert_eq!(relay.inv_to_send(), 1);
}

/// Core clears the queue of a peer that does not want transactions.
#[test]
fn a_peer_that_relays_no_transactions_has_its_queue_dropped() {
    let mut relay = started();
    relay.queue(wtxid(1), &[1; 32]);
    assert!(relay.take(false).queued.is_empty());
    assert_eq!(relay.inv_to_send(), 0);
}

fn candidate(i: u8, ancestors: u64, modified_fee: i64, vsize: u64) -> Candidate {
    Candidate {
        wtxid: wtxid(i),
        txid: Txid::from_byte_array([i; 32]),
        ancestors,
        modified_fee,
        vsize,
        fee_rate: 0,
    }
}

/// Core's `CompareDepthAndScore`: fewer ancestors first, so a parent goes
/// before its child; then the higher modified feerate; then the lower txid.
#[test]
fn announcements_go_parents_first_then_by_feerate() {
    let mut c = [
        candidate(1, 2, 10_000, 100),
        candidate(2, 1, 100, 100),
        candidate(3, 1, 300, 100),
        candidate(5, 1, 200, 100),
        candidate(4, 1, 400, 200),
    ];
    c.sort_by(announce_order);
    let order: Vec<u8> = c.iter().map(|c| c.wtxid.to_byte_array()[0]).collect();
    assert_eq!(order, vec![3, 4, 5, 2, 1], "equal feerates 3 and 4 by txid");
}

/// The known filter holds Core's 50,000 and forgets the oldest past that.
#[test]
fn the_known_filter_forgets_its_oldest() {
    let mut relay = TxRelay::default();
    let hash = |i: u32| {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h
    };
    for i in 0..=KNOWN_INVENTORY_CAPACITY as u32 {
        relay.add_known(&hash(i));
    }
    assert!(!relay.knows(&hash(0)));
    assert!(relay.knows(&hash(1)));
    assert!(relay.knows(&hash(KNOWN_INVENTORY_CAPACITY as u32)));
}

/// The flushes are a Poisson process: exponential delays with the mean
/// asked for.
#[test]
fn the_delay_is_exponential_with_the_mean_asked_for() {
    let n = 20_000;
    let mean = OUTBOUND_INVENTORY_BROADCAST_INTERVAL;
    let draws: Vec<u64> = (0..n).map(|_| exp_delay(mean)).collect();
    let avg = draws.iter().sum::<u64>() as f64 / n as f64;
    assert!((avg - mean as f64).abs() < mean as f64 * 0.05, "mean {avg}");
    // About 1/e of an exponential's draws exceed its mean.
    let over = draws.iter().filter(|d| **d > mean).count() as f64 / n as f64;
    assert!((over - (-1f64).exp()).abs() < 0.02, "{over}");
}

/// A transaction counts as announced if it entered before the last flush,
/// or was announced by a flush that could not send everything; a complete
/// flush moves the sequence and clears those exceptions in one step.
#[test]
fn announced_is_by_sequence_or_by_a_partial_flush() {
    let mut relay = started();
    relay.finish(std::iter::empty(), Some(5));
    assert!(relay.was_announced(4, &[1; 32]));
    assert!(!relay.was_announced(5, &[1; 32]));
    relay.announced_out_of_sequence(&[1; 32]);
    assert!(relay.was_announced(7, &[1; 32]));
    assert!(!relay.was_announced(7, &[2; 32]));
    relay.finish(std::iter::empty(), Some(8));
    assert!(relay.was_announced(7, &[1; 32]), "by sequence now");
    assert!(!relay.was_announced(8, &[1; 32]), "the exception is gone");
}
