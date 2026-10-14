//! How the background download shares heights out: a per-peer cap on what is
//! outstanding, a released height going to a different peer, and `notfound`.

use super::*;
use bitcoin::hashes::Hash as _;

fn h(n: u32) -> (u32, BlockHash) {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    (n, BlockHash::from_byte_array(bytes))
}

fn heights(range: std::ops::RangeInclusive<u32>) -> Vec<(u32, BlockHash)> {
    range.map(h).collect()
}

fn given_to(out: &[(PeerId, Vec<BlockHash>)], peer: PeerId) -> Vec<u32> {
    out.iter()
        .filter(|(p, _)| *p == peer)
        .flat_map(|(_, hashes)| hashes.iter().map(|x| u32::from_le_bytes(x.to_byte_array()[..4].try_into().unwrap())))
        .collect()
}

/// The cap is on what a peer has outstanding, not on what one pass adds:
/// a peer that has not answered gets nothing more on the next pass.
#[test]
fn a_peer_at_the_cap_gets_nothing_more_on_the_next_pass() {
    let mut d = BgDownloader::new(1024, Duration::from_secs(30));
    let now = Instant::now();
    let first = d.assign(&heights(1..=40), &[1], 16, now);
    assert_eq!(given_to(&first, 1).len(), 16);
    let second = d.assign(&heights(17..=40), &[1], 16, now);
    assert!(given_to(&second, 1).is_empty(), "peer 1 given more with 16 outstanding: {second:?}");

    // As it delivers, it has room again.
    d.note_stored(1);
    d.note_stored(2);
    let third = d.assign(&heights(17..=40), &[1], 16, now);
    assert_eq!(given_to(&third, 1), vec![17, 18]);
}

/// A height that timed out goes to another peer, not back to the one that
/// held it; with only that peer, it goes back to it.
#[test]
fn a_released_height_goes_to_a_different_peer() {
    let t0 = Instant::now();
    // From either round-robin start.
    for start in 0..2 {
        let mut d = BgDownloader::new(1024, Duration::from_secs(30));
        for _ in 0..start {
            d.assign(&[], &[1, 2], 16, t0);
        }
        d.mark_in_flight(5, 1, t0);
        d.release_stale(t0 + Duration::from_secs(31));
        assert!(!d.is_in_flight(5));
        let out = d.assign(&[h(5)], &[1, 2], 16, t0);
        assert_eq!(given_to(&out, 2), vec![5], "start {start}: height 5 went back to peer 1: {out:?}");
    }

    let mut alone = BgDownloader::new(1024, Duration::from_secs(30));
    alone.mark_in_flight(5, 1, t0);
    alone.release_stale(t0 + Duration::from_secs(31));
    assert_eq!(given_to(&alone.assign(&[h(5)], &[1], 16, t0), 1), vec![5]);
}

/// The round-robin start moves on each pass, so the lowest needed height is
/// not asked of the same peer every time.
#[test]
fn the_round_robin_start_moves_each_pass() {
    let mut d = BgDownloader::new(1024, Duration::from_secs(30));
    let now = Instant::now();
    let first = d.assign(&[h(1)], &[1, 2], 16, now);
    d.note_stored(1);
    let second = d.assign(&[h(2)], &[1, 2], 16, now);
    let firsts: Vec<PeerId> = [&first, &second].iter().map(|o| o[0].0).collect();
    assert_ne!(firsts[0], firsts[1], "both passes started at the same peer");
}

/// `notfound` from the peer asked releases the height at once, for a
/// different peer; `notfound` from anyone else releases nothing.
#[test]
fn notfound_releases_only_the_askers_height() {
    let mut d = BgDownloader::new(1024, Duration::from_secs(30));
    let now = Instant::now();
    d.mark_in_flight(5, 1, now);
    assert!(!d.note_not_found(5, 2), "peer 2 was not asked");
    assert!(d.is_in_flight(5));
    assert!(d.note_not_found(5, 1));
    assert!(!d.is_in_flight(5));
    let out = d.assign(&[h(5)], &[1, 2], 16, now);
    assert_eq!(given_to(&out, 2), vec![5]);
}
