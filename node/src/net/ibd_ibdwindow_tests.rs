//! What counts against the download window and the stall clock: only a block
//! that was asked for, above the connect cursor.

use super::*;
use crate::chain::state::AssumeValid;
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;
use crate::validation::script::NoopVerifier;
use bitcoin::Network;

fn chain(num_blocks: u32) -> (ChainState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        flat_files,
        Network::Regtest,
        Box::new(NoopVerifier),
        AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    let mut parent = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    for i in 1..=num_blocks {
        let block = crate::chain::state::tests::build_test_block(parent, i, 1_300_000_000 + i);
        parent = cs.accept_block(&block).unwrap().hash();
    }
    (cs, dir)
}

fn hash_at(cs: &ChainState, height: u32) -> BlockHash {
    cs.get_block_hash_by_height(height).unwrap()
}

/// A block re-sent for a height the connector has already passed is not
/// recorded as downloaded. `downloaded` only drains as the cursor passes a
/// height, so such an entry would sit in the window for the rest of the
/// download.
#[test]
fn a_re_sent_connected_block_does_not_count_as_downloaded() {
    let (cs, _dir) = chain(20);
    let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
    sched.connect_cursor_advanced(10);
    for h in 1..=3 {
        sched.block_received(2, h, hash_at(&cs, h));
    }
    assert_eq!(sched.progress().0, 0, "connected heights entered the window");

    // A block that was asked for still counts.
    let asked = sched.assign_blocks(1);
    assert!(asked.contains(&hash_at(&cs, 11)));
    sched.block_received(1, 11, hash_at(&cs, 11));
    assert!(sched.is_downloaded(11), "a requested block counts as downloaded");
    assert_eq!(sched.progress().0, 1);
}

/// An unrequested block above the cursor is not recorded either: only a
/// height that is in flight is.
#[test]
fn an_unrequested_block_above_the_cursor_does_not_count() {
    let (cs, _dir) = chain(20);
    let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
    sched.register_peer(2);
    sched.block_received(2, 7, hash_at(&cs, 7));
    assert!(!sched.is_downloaded(7));
    assert_eq!(sched.progress().0, 0);
}

/// The window is full of blocks that are downloaded but not connected, and
/// the height the connector needs next is not in flight. It is still handed
/// out, or nothing would ever fetch it.
#[test]
fn a_full_window_still_hands_out_the_next_height() {
    let (cs, _dir) = chain(20);
    let mut sched = IbdScheduler::new(20, 0, &cs, 3);
    for h in 2..=4 {
        sched.mark_downloaded(h);
    }
    let hashes = sched.assign_blocks(1);
    assert!(
        hashes.contains(&hash_at(&cs, 1)),
        "height 1 not handed out with the window full: {hashes:?}"
    );
}

/// A peer that withholds the next height and delivers the rest: once that
/// height is released, another peer is given it, even with the window full.
#[test]
fn a_released_next_height_goes_to_another_peer_with_the_window_full() {
    let (cs, _dir) = chain(20);
    let mut sched = IbdScheduler::new(20, 0, &cs, 3);
    sched.register_peer(2);
    for h in 2..=4 {
        sched.mark_downloaded(h);
    }
    sched.register_peer(1);
    sched.in_flight.insert(1, 1);
    sched.in_flight_at.insert(1, Instant::now());
    sched.peer_slots.get_mut(&1).unwrap().assigned.push(1);
    assert!(sched.release_height(1, 1));
    assert!(!sched.assign_blocks(1).contains(&hash_at(&cs, 1)), "peer 1 is on cooldown for height 1");
    let hashes = sched.assign_blocks(2);
    assert!(
        hashes.contains(&hash_at(&cs, 1)),
        "height 1 not given to peer 2: {hashes:?}"
    );
}

/// A released height that waited in the pool while the cursor passed it is
/// not handed out again.
#[test]
fn a_pooled_height_below_the_cursor_is_not_handed_out() {
    let (cs, _dir) = chain(20);
    let mut sched = IbdScheduler::new(20, 0, &cs, 50_000);
    sched.connect_cursor_advanced(10);
    let hashes = sched.assign_blocks(1);
    let heights: Vec<u32> = (1..=20).filter(|h| hashes.contains(&hash_at(&cs, *h))).collect();
    assert!(!heights.is_empty(), "heights above the cursor are handed out");
    assert!(heights.iter().all(|h| *h > 10), "connected heights handed out: {heights:?}");
}

/// Only a block asked of the peer resets its stall clock and failure count.
/// A block it was not asked for (connected already, or held by another peer)
/// says nothing about the heights it still owes.
#[test]
fn only_a_requested_block_resets_the_stall_clock() {
    let (cs, _dir) = chain(40);
    let mut sched = IbdScheduler::new(40, 0, &cs, 50_000);
    sched.assign_blocks(1);
    sched.assign_blocks(2);
    let theirs = sched.peer_inflight_heights(2)[0];
    let old = Instant::now() - Duration::from_secs(100);
    {
        let slots = sched.peer_slots.get_mut(&1).unwrap();
        slots.last_activity = old;
        slots.consecutive_failures = 2;
    }

    // Peer 1 sends a block peer 2 was asked for.
    sched.block_received(1, theirs, hash_at(&cs, theirs));
    let slots = &sched.peer_slots[&1];
    assert_eq!(slots.consecutive_failures, 2, "an unrequested block reset the failure count");
    assert_eq!(slots.last_activity, old, "an unrequested block reset the stall clock");
    assert_eq!(sched.take_stalled_peer(), Some(1), "peer 1 still stalls");

    // Its own block does reset it.
    let mut sched = IbdScheduler::new(40, 0, &cs, 50_000);
    sched.assign_blocks(1);
    {
        let slots = sched.peer_slots.get_mut(&1).unwrap();
        slots.last_activity = old;
        slots.consecutive_failures = 2;
    }
    let h = sched.peer_inflight_heights(1)[0];
    sched.block_received(1, h, hash_at(&cs, h));
    let slots = &sched.peer_slots[&1];
    assert_eq!(slots.consecutive_failures, 0);
    assert!(slots.last_activity > old);
}
