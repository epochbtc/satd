use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::aggregate::*;
use super::collect::*;
use super::tests::*;
use super::validity::Coin;
use super::*;

/// An aggregate path in a fresh directory, which the test keeps alive.
fn agg_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nap").join("aggregate").join("aggregate.dat");
    (dir, path)
}

/// A chain holding coins `1..=coins` for `signer`.
fn chain_with(signer: &Signer, coins: u8) -> Chain {
    let mut chain = Chain::new();
    for n in 1..=coins {
        chain.coins.insert(
            outpoint(n),
            Coin { value: VALUE, script_pubkey: signer.spk.clone(), height: COIN_HEIGHT, coinbase: false },
        );
    }
    chain
}

fn open(chain: &Chain) -> (tempfile::TempDir, Collector) {
    let (dir, path) = agg_path();
    (dir, Collector::new(Aggregate::open(path, chain).unwrap()))
}

fn take(c: &Collector, chain: &Chain, source: &str, page: Vec<Attestation>) -> Intake {
    c.intake(chain, source, page, &mut c.pull_budget(), Instant::now())
}

fn counting(c: &Collector) -> Vec<(String, String, u32, String)> {
    c.aggregate()
        .counting()
        .into_iter()
        .map(|h| {
            let a = &h.attestation;
            (a.key().to_owned(), a.value().to_owned(), a.anchor_height(), h.source)
        })
        .collect()
}

/// `att`'s fields with another attestation's signature, which does not sign
/// its text.
fn forged(att: &Attestation, other: &Attestation) -> Attestation {
    Attestation::new(
        att.outpoint(),
        att.key().into(),
        att.value().into(),
        att.anchor_height(),
        att.anchor_hash(),
        other.signature().clone(),
    )
    .unwrap()
}

// --- Supersession and the stored set ------------------------------------------

#[test]
fn the_newest_attestation_counts_whichever_publisher_served_it() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let old = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 10);
    let new = attest(&chain, &s, outpoint(1), "k", "no", ANCHOR);
    for (first, second) in [(&old, &new), (&new, &old)] {
        let (_d, c) = open(&chain);
        assert_eq!(take(&c, &chain, "a", vec![first.clone()]).added, 1);
        assert_eq!(take(&c, &chain, "b", vec![second.clone()]).added, 1);
        let src = if first == &new { "a" } else { "b" };
        assert_eq!(counting(&c), vec![("k".into(), "no".into(), ANCHOR, src.into())]);
        assert_eq!(c.aggregate().len(), 2, "the predecessor is kept while the anchor is shallow");
    }
}

#[test]
fn an_attestation_held_already_is_known() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let (_d, c) = open(&chain);
    take(&c, &chain, "a", vec![att.clone()]);
    let again = take(&c, &chain, "b", vec![att]);
    assert_eq!((again.added, again.known), (0, 1));
    assert_eq!(counting(&c)[0].3, "a", "the first source is kept");
}

#[test]
fn a_withdrawal_supersedes_and_counts_as_an_empty_value() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 10)]);
    take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "", ANCHOR)]);
    let now = c.aggregate().counting();
    assert_eq!(now.len(), 1);
    assert!(now[0].attestation.is_withdrawal());
}

#[test]
fn a_spent_coin_drops_out_at_the_next_tip() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 2);
    let (_d, c) = open(&chain);
    take(
        &c,
        &chain,
        "a",
        vec![
            attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR),
            attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR),
        ],
    );
    chain.coins.remove(&outpoint(1));
    assert_eq!(c.aggregate().on_tip(&chain), 1);
    let left = c.aggregate().counting();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].attestation.outpoint(), outpoint(2));
}

#[test]
fn a_reorg_of_the_newer_anchor_brings_the_predecessor_back() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    take(
        &c,
        &chain,
        "a",
        vec![
            attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 20),
            attest(&chain, &s, outpoint(1), "k", "no", ANCHOR),
        ],
    );
    assert_eq!(counting(&c)[0].1, "no");
    chain.fork_at = ANCHOR - 5;
    assert_eq!(c.aggregate().on_tip(&chain), 0, "the reorganised attestation may come back");
    assert_eq!(counting(&c)[0].1, "yes");
    chain.fork_at = u32::MAX;
    c.aggregate().on_tip(&chain);
    assert_eq!(counting(&c)[0].1, "no", "and it does when its anchor returns");
}

#[test]
fn every_generation_inside_the_window_keeps_its_predecessor() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    for (value, anchor) in [("a", ANCHOR - 30), ("b", ANCHOR - 20), ("c", ANCHOR)] {
        take(&c, &chain, "p", vec![attest(&chain, &s, outpoint(1), "k", value, anchor)]);
    }
    assert_eq!(c.aggregate().len(), 3);
    // A reorg deep enough to take both newer anchors.
    chain.fork_at = ANCHOR - 25;
    c.aggregate().on_tip(&chain);
    assert_eq!(counting(&c)[0].1, "a");
}

#[test]
fn a_predecessor_is_dropped_once_the_newer_anchor_is_deep() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    take(
        &c,
        &chain,
        "a",
        vec![
            attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 20),
            attest(&chain, &s, outpoint(1), "k", "no", ANCHOR),
        ],
    );
    chain.tip = ANCHOR + REORG_DEPTH - 1;
    assert_eq!(c.aggregate().on_tip(&chain), 0);
    assert_eq!(c.aggregate().len(), 2);
    chain.tip = ANCHOR + REORG_DEPTH;
    assert_eq!(c.aggregate().on_tip(&chain), 1);
    assert_eq!(counting(&c)[0].1, "no");
    assert_eq!(c.aggregate().len(), 1);
}

#[test]
fn a_newer_attestation_that_does_not_count_does_not_settle_its_predecessor() {
    // One key, one script; the newer proof sets a locktime of its own, so
    // it is valid only from `lock`, while the older one is valid now.
    let lock = TIP + 2 * REORG_DEPTH;
    let now = p2wsh_full(bitcoin::script::Builder::new(), 2, 0, 0);
    let later = p2wsh_full(bitcoin::script::Builder::new(), 2, lock, 0);
    assert_eq!(now.spk, later.spk);
    let mut chain = chain_with(&now, 1);
    let (_d, c) = open(&chain);
    take(&c, &chain, "a", vec![attest(&chain, &now, outpoint(1), "k", "yes", ANCHOR - 20)]);
    take(&c, &chain, "a", vec![attest(&chain, &later, outpoint(1), "k", "no", ANCHOR)]);
    chain.tip = ANCHOR + REORG_DEPTH + 10;
    c.aggregate().on_tip(&chain);
    assert_eq!(counting(&c)[0].1, "yes", "the older one counts while the newer is not yet valid");
    assert_eq!(c.aggregate().len(), 2, "and is kept, though the newer anchor is deep");
    chain.tip = lock + 1;
    c.aggregate().on_tip(&chain);
    assert_eq!(counting(&c)[0].1, "no");
    assert_eq!(c.aggregate().len(), 1, "once valid and deep, the newer one settles the older");
}

#[test]
fn generations_stop_at_the_limit() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let n = MAX_GENERATIONS as u32 + 2;
    for i in 0..n {
        take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", &format!("v{i}"), ANCHOR - n + i)]);
    }
    assert_eq!(c.aggregate().len(), MAX_GENERATIONS);
    assert_eq!(counting(&c)[0].1, format!("v{}", n - 1));
    // One older than every generation kept is not taken.
    let oldest = attest(&chain, &s, outpoint(1), "k", "v-old", ANCHOR - n - 1);
    assert_eq!(take(&c, &chain, "a", vec![oldest]).known, 1);
    assert_eq!(c.aggregate().len(), MAX_GENERATIONS);
}

#[test]
fn a_stale_attestation_is_dropped() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR)]);
    chain.tip = ANCHOR + FRESHNESS_WINDOW;
    assert_eq!(c.aggregate().on_tip(&chain), 1);
    assert!(c.aggregate().is_empty());
}

#[test]
fn a_lost_anchor_is_kept_while_a_reorg_could_bring_it_back() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR)]);
    chain.fork_at = ANCHOR;
    chain.tip = ANCHOR + REORG_DEPTH - 1;
    assert_eq!(c.aggregate().on_tip(&chain), 0);
    assert!(c.aggregate().counting().is_empty(), "it does not count meanwhile");
    chain.tip = ANCHOR + REORG_DEPTH;
    assert_eq!(c.aggregate().on_tip(&chain), 1);
}

#[test]
fn a_timelocked_attestation_is_held_until_it_counts() {
    let lock = TIP + 10;
    let s = cltv(lock);
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let i = take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR)]);
    assert_eq!(i.added, 1, "a proof not yet valid is verified and held");
    assert!(c.aggregate().counting().is_empty());
    chain.tip = lock + 1;
    c.aggregate().on_tip(&chain);
    assert_eq!(counting(&c).len(), 1);
}

// --- Persistence ------------------------------------------------------------

#[test]
fn the_set_survives_a_restart() {
    let s = p2wpkh();
    let chain = chain_with(&s, 2);
    let (_d, path) = agg_path();
    let c = Collector::new(Aggregate::open(path.clone(), &chain).unwrap());
    take(
        &c,
        &chain,
        "1.2.3.4:8333",
        vec![
            attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR - 10),
            attest(&chain, &s, outpoint(1), "k", "no", ANCHOR),
            attest(&chain, &s, outpoint(2), "j", "", ANCHOR),
        ],
    );
    assert_eq!(c.aggregate().save_if_dirty(), Ok(true));
    assert_eq!(c.aggregate().save_if_dirty(), Ok(false), "nothing changed since");
    let reopened = Aggregate::open(path, &chain).unwrap();
    assert_eq!(reopened.all(), c.aggregate().all());
}

#[test]
fn a_signature_that_does_not_verify_is_dropped_on_load() {
    let s = p2wpkh();
    let chain = chain_with(&s, 2);
    let good = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let other = attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR);
    let (_d, path) = agg_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = encode_for_test(&[(good.clone(), "a".into()), (forged(&good, &other), "b".into())]);
    // `forged` keeps `good`'s fields, so the two differ only in signature.
    std::fs::write(&path, bytes).unwrap();
    let agg = Aggregate::open(path, &chain).unwrap();
    assert_eq!(agg.all().len(), 1);
    assert_eq!(agg.all()[0].attestation, good);
}

#[test]
fn a_damaged_file_is_an_error() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, path) = agg_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = encode_for_test(&[(attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR), "a".into())]);
    bytes[20] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let err = Aggregate::open(path, &chain).err().unwrap();
    assert!(err.contains("checksum"), "{err}");
}

// --- The intake pipeline ------------------------------------------------------

#[test]
fn a_chain_state_failure_is_passed_over_without_a_verification() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    chain.coins.clear();
    let mut pull = c.pull_budget();
    let before = pull.remaining();
    let i = c.intake(&chain, "a", vec![att], &mut pull, Instant::now());
    assert_eq!((i.chain_state, i.misbehaved), (1, None));
    assert_eq!(pull.remaining(), before, "the signature was not checked");
}

#[test]
fn a_bad_signature_is_misbehaviour_and_ends_the_page() {
    let s = p2wpkh();
    let chain = chain_with(&s, 3);
    let (_d, c) = open(&chain);
    let one = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let two = attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR);
    let three = attest(&chain, &s, outpoint(3), "k", "yes", ANCHOR);
    let i = take(&c, &chain, "a", vec![one, forged(&two, &three), three]);
    assert_eq!(i.added, 1);
    assert!(matches!(i.misbehaved, Some(Rejection::SignatureInvalid(_))), "{i:?}");
    assert_eq!(c.aggregate().len(), 1, "nothing after the bad signature is taken");
}

#[test]
fn a_format_that_does_not_apply_is_misbehaviour() {
    // A legacy signature for a P2WPKH coin.
    let s = p2wpkh();
    let legacy = p2pkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let att = attest(&chain, &legacy, outpoint(1), "k", "yes", ANCHOR);
    let i = take(&c, &chain, "a", vec![att]);
    assert!(matches!(i.misbehaved, Some(Rejection::WrongFormat(_))), "{i:?}");
}

#[test]
fn a_cached_result_spends_no_budget() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let n = MAX_GENERATIONS as u32;
    for i in 0..n {
        take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", &format!("v{i}"), ANCHOR - n + i)]);
    }
    // Too old to keep, so it is verified but not held, and comes back.
    let old = attest(&chain, &s, outpoint(1), "k", "old", ANCHOR - n - 1);
    let mut pull = c.pull_budget();
    assert_eq!(c.intake(&chain, "a", vec![old.clone()], &mut pull, Instant::now()).known, 1);
    let spent = pull.remaining();
    assert_eq!(c.intake(&chain, "b", vec![old], &mut pull, Instant::now()).known, 1);
    assert_eq!(pull.remaining(), spent, "the second sighting was a cache hit");
}

#[test]
fn work_over_the_pull_budget_is_deferred_then_done() {
    let s = p2wpkh();
    let chain = chain_with(&s, 5);
    let (_d, path) = agg_path();
    let limits = Limits { pull_verifications: 2, ..Limits::default() };
    let c = Collector::with_limits(Aggregate::open(path, &chain).unwrap(), limits);
    let page: Vec<_> = (1..=5).map(|n| attest(&chain, &s, outpoint(n), "k", "yes", ANCHOR)).collect();
    let i = take(&c, &chain, "a", page);
    assert_eq!((i.added, i.deferred), (2, 3));
    assert_eq!(c.deferred_len(), 3);
    assert!(c.drain_deferred(&chain, Instant::now()).is_empty());
    assert_eq!(c.deferred_len(), 0);
    assert_eq!(c.aggregate().len(), 5, "nothing was dropped");
}

#[test]
fn work_over_the_hourly_budget_waits_for_the_window() {
    let s = p2wpkh();
    let chain = chain_with(&s, 3);
    let (_d, path) = agg_path();
    let limits = Limits { hourly_verifications: 1, ..Limits::default() };
    let c = Collector::with_limits(Aggregate::open(path, &chain).unwrap(), limits);
    let t0 = Instant::now();
    let page: Vec<_> = (1..=3).map(|n| attest(&chain, &s, outpoint(n), "k", "yes", ANCHOR)).collect();
    let i = c.intake(&chain, "a", page, &mut c.pull_budget(), t0);
    assert_eq!((i.added, i.deferred), (1, 2));
    c.drain_deferred(&chain, t0 + Duration::from_secs(60));
    assert_eq!(c.deferred_len(), 2, "still inside the window");
    c.drain_deferred(&chain, t0 + BUDGET_WINDOW);
    assert_eq!(c.deferred_len(), 1, "one more per window");
    c.drain_deferred(&chain, t0 + 2 * BUDGET_WINDOW);
    assert_eq!(c.deferred_len(), 0);
    assert_eq!(c.aggregate().len(), 3);
}

#[test]
fn a_full_deferred_queue_has_no_room_for_another_page() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, path) = agg_path();
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let size = att.to_bytes().len();
    let limits = Limits {
        hourly_verifications: 0,
        max_deferred_bytes: p2p::MAX_NAPATT_SIZE + size,
        ..Limits::default()
    };
    let c = Collector::with_limits(Aggregate::open(path, &chain).unwrap(), limits);
    assert!(c.has_room());
    assert_eq!(take(&c, &chain, "a", vec![att]).deferred, 1);
    assert!(c.has_room(), "exactly a page of room is left");
    let att2 = attest(&chain, &s, outpoint(1), "k", "no", ANCHOR);
    take(&c, &chain, "a", vec![att2]);
    assert!(!c.has_room());
}

#[test]
fn a_deferred_bad_signature_names_its_source() {
    let s = p2wpkh();
    let chain = chain_with(&s, 2);
    let (_d, path) = agg_path();
    let limits = Limits { pull_verifications: 0, ..Limits::default() };
    let c = Collector::with_limits(Aggregate::open(path, &chain).unwrap(), limits);
    let one = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let two = attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR);
    take(&c, &chain, "good", vec![one.clone()]);
    take(&c, &chain, "bad", vec![forged(&two, &one)]);
    let bad = c.drain_deferred(&chain, Instant::now());
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].0, "bad");
    assert_eq!(c.aggregate().len(), 1);
}

// --- Round 1 fixes ------------------------------------------------------------

#[test]
fn a_long_source_name_is_cut_on_a_character_boundary() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    // 255 ASCII bytes then a 3-byte character across the 256-byte limit.
    let source = format!("{}€tail", "a".repeat(255));
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    assert_eq!(take(&c, &chain, &source, vec![att]).added, 1);
    let held = &c.aggregate().all()[0].source;
    assert_eq!(held, &"a".repeat(255));
}

#[test]
fn an_outpoint_holds_at_most_256_keys_first_seen() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, c) = open(&chain);
    let page: Vec<_> = (0..aggregate::MAX_KEYS_PER_OUTPOINT)
        .map(|k| attest(&chain, &s, outpoint(1), &format!("key{k:03}"), "yes", ANCHOR - 10))
        .collect();
    assert_eq!(take(&c, &chain, "a", page).added, aggregate::MAX_KEYS_PER_OUTPOINT);
    // A key new to the outpoint is refused, even one that sorts first.
    let new_key = attest(&chain, &s, outpoint(1), "a-new-key", "yes", ANCHOR);
    let i = take(&c, &chain, "a", vec![new_key]);
    assert_eq!((i.added, i.key_limit), (0, 1));
    // A key already held still takes a newer attestation.
    let newer = attest(&chain, &s, outpoint(1), "key000", "no", ANCHOR);
    assert_eq!(take(&c, &chain, "a", vec![newer]).added, 1);
    assert_eq!(c.aggregate().counting().len(), aggregate::MAX_KEYS_PER_OUTPOINT);
}

#[test]
fn an_attestation_the_chain_cannot_judge_yet_waits_and_survives() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, path) = agg_path();
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    {
        let c = Collector::new(Aggregate::open(path.clone(), &chain).unwrap());
        take(&c, &chain, "a", vec![att.clone()]);
        c.aggregate().save_if_dirty().unwrap();
    }
    // Restarted in IBD, below the coin: neither the anchor nor the coin is
    // there yet.
    let mut behind = chain_with(&s, 0);
    behind.tip = COIN_HEIGHT - 1;
    let agg = Aggregate::open(path.clone(), &behind).unwrap();
    assert_eq!((agg.len(), pending_len(&agg)), (0, 1), "it waits rather than being dropped");
    // It stays in the file meanwhile, across another restart.
    assert_eq!(agg.save_if_dirty(), Ok(false));
    let agg = Aggregate::open(path, &behind).unwrap();
    assert_eq!(pending_len(&agg), 1);
    // The chain catches up: it is judged and counts.
    agg.on_tip(&chain);
    assert_eq!((agg.len(), pending_len(&agg)), (1, 0));
    assert_eq!(agg.counting()[0].attestation, att);
}

#[test]
fn an_attestation_spent_while_stopped_is_dropped_on_load() {
    let s = p2wpkh();
    let mut chain = chain_with(&s, 1);
    let (_d, path) = agg_path();
    {
        let c = Collector::new(Aggregate::open(path.clone(), &chain).unwrap());
        take(&c, &chain, "a", vec![attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR)]);
        c.aggregate().save_if_dirty().unwrap();
    }
    chain.coins.clear();
    let agg = Aggregate::open(path, &chain).unwrap();
    assert_eq!((agg.len(), pending_len(&agg)), (0, 0));
    assert_eq!(agg.save_if_dirty(), Ok(true), "the file loses it too");
}
