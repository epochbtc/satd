use std::time::{Duration, Instant};

use bitcoin::OutPoint;
use bitcoin::hashes::Hash as _;

use super::p2p::*;
use super::publisher::encode_signature;
use super::tests::*;
use super::validity::Coin;
use super::*;

/// A publisher serving `keys` attestations on each of coins `1..=coins`,
/// in a directory the caller keeps alive.
pub(crate) fn serving_publisher(coins: u8, keys: usize) -> (tempfile::TempDir, Publisher, Vec<Attestation>) {
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::new();
    let signer = p2wpkh();
    let mut atts = Vec::new();
    for n in 1..=coins {
        let op = outpoint(n);
        chain.coins.insert(
            op,
            Coin { value: VALUE, script_pubkey: signer.spk.clone(), height: COIN_HEIGHT, coinbase: false },
        );
        for k in 0..keys {
            atts.push(attest(&chain, &signer, op, &format!("key{k}"), "yes", ANCHOR));
        }
    }
    let p = Publisher::open(dir.path().join("attestations.dat"), &chain).unwrap();
    for att in &atts {
        p.submit(&chain, &att.message(), &encode_signature(att.signature())).unwrap();
    }
    atts.sort_by(|a, b| (a.outpoint(), a.key()).cmp(&(b.outpoint(), b.key())));
    (dir, p, atts)
}

fn req(cursor: Option<OutPoint>) -> GetNapAtt {
    GetNapAtt { anchor_height_min: 0, keys: vec![], cursor }
}

// --- Encoding ---------------------------------------------------------------

#[test]
fn messages_round_trip() {
    let (_dir, _p, atts) = serving_publisher(2, 2);
    for get in [
        req(None),
        GetNapAtt { anchor_height_min: 7, keys: vec!["a".into(), "bip_xyz.support".into()], cursor: Some(outpoint(3)) },
    ] {
        assert_eq!(GetNapAtt::from_bytes(&get.to_bytes()), Ok(get));
    }
    for page in [
        NapAtt { attestations: vec![], next_cursor: None },
        NapAtt { attestations: atts.clone(), next_cursor: Some(outpoint(2)) },
    ] {
        assert_eq!(NapAtt::from_bytes(&page.to_bytes()), Ok(page));
    }
}

#[test]
fn getnapatt_refuses_malformed_bytes() {
    let good = GetNapAtt { anchor_height_min: 1, keys: vec!["k".into()], cursor: None }.to_bytes();
    assert!(GetNapAtt::from_bytes(&good).is_ok());
    // Truncated. Trailing bytes are a later version's fields, and ignored.
    assert!(GetNapAtt::from_bytes(&good[..good.len() - 1]).is_err());
    assert_eq!(GetNapAtt::from_bytes(&[good.clone(), vec![0, 9]].concat()), GetNapAtt::from_bytes(&good));
    // A cursor flag other than 0 or 1.
    let mut bad = good.clone();
    *bad.last_mut().unwrap() = 2;
    assert!(GetNapAtt::from_bytes(&bad).is_err());
    // A key no attestation could carry: empty, non-printable, too long.
    for key in [vec![], vec![0x07], vec![b'a'; MAX_KEY_LEN + 1]] {
        let mut b = 1u32.to_le_bytes().to_vec();
        b.push(1);
        b.push(key.len() as u8);
        b.extend(&key);
        b.push(0);
        assert!(GetNapAtt::from_bytes(&b).is_err(), "{key:?}");
    }
    // A non-minimal compact size for the key count.
    let mut b = 1u32.to_le_bytes().to_vec();
    b.extend([0xfd, 0x00, 0x00, 0x00]);
    assert!(GetNapAtt::from_bytes(&b).is_err());
}

#[test]
fn getnapatt_takes_at_most_32_keys() {
    let keys = |n: usize| (0..n).map(|i| format!("k{i}")).collect::<Vec<_>>();
    let at_limit = GetNapAtt { anchor_height_min: 0, keys: keys(MAX_GETNAPATT_KEYS), cursor: None };
    assert!(GetNapAtt::from_bytes(&at_limit.to_bytes()).is_ok());
    let over = GetNapAtt { keys: keys(MAX_GETNAPATT_KEYS + 1), ..at_limit };
    assert!(GetNapAtt::from_bytes(&over.to_bytes()).is_err());
}

#[test]
fn napatt_refuses_oversize_and_malformed_bytes() {
    let (_dir, _p, atts) = serving_publisher(1, 1);
    let good = NapAtt { attestations: atts, next_cursor: None }.to_bytes();
    assert!(NapAtt::from_bytes(&good[..good.len() - 1]).is_err());
    assert_eq!(NapAtt::from_bytes(&[good.clone(), vec![0, 9]].concat()), NapAtt::from_bytes(&good));
    // A count larger than the payload could hold, refused before reading.
    let mut b = vec![0xfe];
    b.extend(u32::MAX.to_le_bytes());
    assert!(NapAtt::from_bytes(&b).is_err());
    assert!(NapAtt::from_bytes(&vec![0; MAX_NAPATT_SIZE + 1]).is_err());
}

// --- Paging -------------------------------------------------------------------

#[test]
fn pages_follow_outpoint_order_and_never_split_an_outpoint() {
    let (_dir, p, atts) = serving_publisher(5, 3);
    let one = super::wire::serialized_size(&atts[0]);
    // Room for two outpoints of three attestations, not a third.
    let max = 46 + 7 * one;
    let mut cursor = None;
    let mut got = Vec::new();
    let mut pages = 0;
    loop {
        let page = p.page(&req(cursor), max).unwrap();
        assert!(page.to_bytes().len() <= max);
        assert!(page.attestations.len() % 3 == 0, "a page holds whole outpoints");
        got.extend(page.attestations);
        pages += 1;
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(got, atts, "every attestation once, in order");
}

#[test]
fn the_first_outpoint_is_always_served() {
    let (_dir, p, atts) = serving_publisher(2, 3);
    let page = p.page(&req(None), 1).unwrap();
    assert_eq!(page.attestations, atts[..3]);
    assert_eq!(page.next_cursor, Some(outpoint(1)));
}

#[test]
fn a_cursor_past_the_end_is_an_empty_last_page() {
    let (_dir, p, _atts) = serving_publisher(2, 1);
    let page = p.page(&req(Some(OutPoint { txid: bitcoin::Txid::from_byte_array([0xff; 32]), vout: u32::MAX })), MAX_NAPATT_SIZE).unwrap();
    assert_eq!(page, NapAtt { attestations: vec![], next_cursor: None });
}

#[test]
fn requests_filter_by_key_and_anchor_height() {
    let (_dir, p, atts) = serving_publisher(2, 3);
    let by_key = p.page(&GetNapAtt { anchor_height_min: 0, keys: vec!["key1".into()], cursor: None }, MAX_NAPATT_SIZE).unwrap();
    assert_eq!(by_key.attestations, atts.iter().filter(|a| a.key() == "key1").cloned().collect::<Vec<_>>());
    let above = p.page(&GetNapAtt { anchor_height_min: ANCHOR + 1, keys: vec![], cursor: None }, MAX_NAPATT_SIZE).unwrap();
    assert!(above.attestations.is_empty());
    let at = p.page(&GetNapAtt { anchor_height_min: ANCHOR, keys: vec![], cursor: None }, MAX_NAPATT_SIZE).unwrap();
    assert_eq!(at.attestations, atts);
}

#[test]
fn only_attestations_valid_at_the_tip_are_served() {
    let (_dir, p, atts) = serving_publisher(2, 1);
    let mut chain = Chain::new();
    chain.coins.insert(
        outpoint(2),
        Coin { value: VALUE, script_pubkey: p2wpkh().spk, height: COIN_HEIGHT, coinbase: false },
    );
    // Coin 1 is spent.
    p.on_tip(&chain);
    assert_eq!(p.page(&req(None), MAX_NAPATT_SIZE).unwrap().attestations, atts[1..]);
}

// --- Serving limits -----------------------------------------------------------

const G: &[u8] = &[10, 0];

/// Admit and commit a request of `size` bytes.
fn serve(l: &mut ServeLimits, peer: u64, group: &[u8], cursor: Option<OutPoint>, size: usize, next: Option<OutPoint>, now: Instant) -> Result<(), Refused> {
    let a = l.admit(peer, group, cursor, now)?;
    l.commit(peer, a, size, next, now)
}

#[test]
fn a_connection_starts_one_pull_per_interval() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    assert_eq!(serve(&mut l, 1, G, None, 100, None, t), Ok(()));
    assert_eq!(serve(&mut l, 1, G, None, 100, None, t + PULL_INTERVAL - Duration::from_secs(1)), Err(Refused::ConnPull));
    assert_eq!(serve(&mut l, 1, G, None, 100, None, t + PULL_INTERVAL), Ok(()));
}

#[test]
fn a_continuation_must_quote_the_cursor_it_was_sent() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    serve(&mut l, 1, G, None, 100, Some(outpoint(1)), t).unwrap();
    // The cursor it was sent continues the pull, as often as pages remain.
    serve(&mut l, 1, G, Some(outpoint(1)), 100, Some(outpoint(2)), t).unwrap();
    serve(&mut l, 1, G, Some(outpoint(2)), 100, None, t).unwrap();
    // Any other cursor, or one already used, starts a pull.
    assert_eq!(serve(&mut l, 1, G, Some(outpoint(2)), 100, None, t), Err(Refused::ConnPull));
    assert_eq!(serve(&mut l, 1, G, Some(outpoint(9)), 100, None, t), Err(Refused::ConnPull));
}

#[test]
fn a_group_starts_eight_pulls_per_interval() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    for peer in 0..GROUP_MULTIPLE {
        assert_eq!(serve(&mut l, peer, G, None, 100, None, t), Ok(()));
    }
    assert_eq!(serve(&mut l, 100, G, None, 100, None, t), Err(Refused::GroupPull));
    // Another group is unaffected.
    assert_eq!(serve(&mut l, 101, &[10, 1], None, 100, None, t), Ok(()));
    assert_eq!(serve(&mut l, 100, G, None, 100, None, t + PULL_INTERVAL), Ok(()));
}

#[test]
fn a_connection_byte_budget_is_spent_and_resets() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    let size = 1_000_000;
    let pages = (CONN_BUDGET_BYTES / size as u64) as usize;
    serve(&mut l, 1, G, None, size, Some(outpoint(0)), t).unwrap();
    for i in 1..pages {
        serve(&mut l, 1, G, Some(outpoint(0)), size, Some(outpoint(0)), t)
            .unwrap_or_else(|e| panic!("page {i}: {e:?}"));
    }
    assert_eq!(serve(&mut l, 1, G, Some(outpoint(0)), size, Some(outpoint(0)), t), Err(Refused::ConnBytes));
    // Less than a whole page left is spent: refused before a page is built,
    // since a page that fits the remainder may not exist.
    let mut l2 = ServeLimits::default();
    let left = MAX_NAPATT_SIZE as u64 - 1;
    serve(&mut l2, 1, G, None, (CONN_BUDGET_BYTES - left) as usize, Some(outpoint(0)), t).unwrap();
    assert_eq!(l2.admit(1, G, Some(outpoint(0)), t), Err(Refused::ConnBytes));
    let mut l3 = ServeLimits::default();
    serve(&mut l3, 1, G, None, (CONN_BUDGET_BYTES - left - 1) as usize, Some(outpoint(0)), t).unwrap();
    assert!(l3.admit(1, G, Some(outpoint(0)), t).is_ok(), "a whole page left");
    // The window resets an hour after it opened.
    assert_eq!(serve(&mut l, 1, G, Some(outpoint(0)), size, None, t + BUDGET_WINDOW), Ok(()));
}

#[test]
fn one_connection_does_not_starve_another_in_its_group() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    serve(&mut l, 1, G, None, CONN_BUDGET_BYTES as usize, Some(outpoint(0)), t).unwrap();
    assert_eq!(l.admit(1, G, Some(outpoint(0)), t), Err(Refused::ConnBytes));
    assert_eq!(serve(&mut l, 2, G, None, CONN_BUDGET_BYTES as usize, None, t), Ok(()));
}

#[test]
fn reconnecting_does_not_reset_the_group_budget() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    let budget = CONN_BUDGET_BYTES as usize;
    // Each connection spends its own budget and goes; a new one takes over.
    for peer in 0..GROUP_MULTIPLE {
        let now = t + PULL_INTERVAL * peer as u32 / GROUP_MULTIPLE as u32;
        serve(&mut l, peer, G, None, budget, None, now).unwrap();
        l.forget(peer);
    }
    let now = t + PULL_INTERVAL + Duration::from_secs(1);
    assert_eq!(l.admit(50, G, None, now), Err(Refused::GroupBytes));
    // A connection's own limits do end with it.
    let mut l = ServeLimits::default();
    serve(&mut l, 1, G, None, budget, None, t).unwrap();
    l.forget(1);
    assert_eq!(serve(&mut l, 2, G, None, 100, None, t), Ok(()));
    // The group's budget resets with its window.
    let mut l = ServeLimits::default();
    for peer in 0..GROUP_MULTIPLE {
        serve(&mut l, peer, G, None, budget, None, t).unwrap();
        l.forget(peer);
    }
    assert_eq!(l.admit(50, G, None, t + BUDGET_WINDOW).map(|_| ()), Ok(()));
}

#[test]
fn idle_groups_are_dropped() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    for g in 0..100u8 {
        serve(&mut l, u64::from(g), &[g], None, 100, None, t).unwrap();
        l.forget(u64::from(g));
    }
    assert_eq!(l.group_count(), 100);
    let _ = l.admit(1_000, &[200], None, t + BUDGET_WINDOW);
    assert_eq!(l.group_count(), 1, "only the requesting connection's group is left");
}

#[test]
fn a_group_with_less_than_a_page_left_admits_no_one() {
    let mut l = ServeLimits::default();
    let t = Instant::now();
    let group_budget = CONN_BUDGET_BYTES * GROUP_MULTIPLE;
    // Leaves the group a few bytes short of a whole page.
    let each = (group_budget - MAX_NAPATT_SIZE as u64) / GROUP_MULTIPLE + 1;
    for peer in 0..GROUP_MULTIPLE {
        serve(&mut l, peer, G, None, each as usize, None, t).unwrap();
    }
    // A fresh connection, its own budget untouched, is refused at once.
    assert_eq!(l.admit(50, G, None, t + PULL_INTERVAL), Err(Refused::GroupBytes));
}

#[test]
fn a_busy_store_serves_no_page() {
    let (_dir, p, atts) = serving_publisher(1, 1);
    assert_eq!(p.with_store_held(|| p.page(&req(None), MAX_NAPATT_SIZE)), None);
    assert_eq!(p.page(&req(None), MAX_NAPATT_SIZE).unwrap().attestations, atts);
}
