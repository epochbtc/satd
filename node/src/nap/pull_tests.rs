use std::sync::Arc;
use std::time::{Duration, Instant};

use super::aggregate::Aggregate;
use super::collect::{Collector, Limits, PullBudget};
use super::p2p::{GetNapAtt, NapAtt};
use super::pull::*;
use super::tests::*;
use super::validity::{ChainView, Coin};
use super::publisher::ChainSource;
use super::*;

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

fn puller(chain: &Chain, limits: Limits) -> (tempfile::TempDir, Puller) {
    let dir = tempfile::tempdir().unwrap();
    let agg = Aggregate::open(dir.path().join("aggregate.dat"), chain).unwrap();
    (dir, Puller::new(Arc::new(Collector::with_limits(agg, limits))))
}

/// Defer one attestation in `collector`, valid against a chain of its own
/// that the peer manager's tests' chain does not hold.
pub(crate) fn defer_one(collector: &Collector) {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let got = collector.intake(&chain, "a", vec![att], &mut PullBudget::empty(), Instant::now());
    assert_eq!(got.deferred, 1);
}

fn page(atts: Vec<Attestation>, next: Option<bitcoin::OutPoint>) -> Vec<u8> {
    NapAtt { attestations: atts, next_cursor: next }.to_bytes()
}

#[test]
fn a_pull_asks_for_everything_and_one_runs_per_peer() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    assert!(p.due("1.2.3.4:8333", now));
    let req = p.start(7, "1.2.3.4:8333", Via::Outbound, now).expect("started");
    assert_eq!(GetNapAtt::from_bytes(&req), Ok(GetNapAtt { anchor_height_min: 0, keys: vec![], cursor: None }));
    assert_eq!(p.start(7, "1.2.3.4:8333", Via::Outbound, now), None, "one pull at a time per peer");
    assert!(!p.due("1.2.3.4:8333", now), "not due again until the interval passes");
    assert!(p.due("1.2.3.4:8333", now + REPULL_INTERVAL));
}

#[test]
fn pages_continue_from_the_cursor_until_the_last() {
    let s = p2wpkh();
    let chain = chain_with(&s, 2);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    p.start(7, "a", Via::Pull, now).unwrap();
    let one = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let two = attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR);
    match p.on_napatt(&chain, 7, &page(vec![one], Some(outpoint(1))), now) {
        Next::Continue(req) => assert_eq!(GetNapAtt::from_bytes(&req).unwrap().cursor, Some(outpoint(1))),
        other => panic!("{other:?}"),
    }
    assert_eq!(p.on_napatt(&chain, 7, &page(vec![two], None), now), Next::Done { close: true });
    assert_eq!(p.stats().pulls_completed, 1);
    assert_eq!(p.stats().pages, 2);
    assert_eq!(p.collector().aggregate().len(), 2);
    assert_eq!(p.active(), 0);
}

#[test]
fn an_unasked_page_is_ignored() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    assert_eq!(p.on_napatt(&chain, 7, &page(vec![att], None), Instant::now()), Next::Unsolicited);
    assert!(p.collector().aggregate().is_empty());
    assert_eq!(p.stats().unsolicited, 1);
}

#[test]
fn a_malformed_page_or_a_bad_signature_is_misbehaviour() {
    let s = p2wpkh();
    let chain = chain_with(&s, 2);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    p.start(7, "a", Via::Outbound, now).unwrap();
    assert!(matches!(p.on_napatt(&chain, 7, &[0xff], now), Next::Misbehaved(_)));
    let one = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let two = attest(&chain, &s, outpoint(2), "k", "yes", ANCHOR);
    let forged = Attestation::new(
        two.outpoint(),
        two.key().into(),
        two.value().into(),
        two.anchor_height(),
        two.anchor_hash(),
        one.signature().clone(),
    )
    .unwrap();
    p.start(8, "b", Via::Outbound, now).unwrap();
    match p.on_napatt(&chain, 8, &page(vec![forged], None), now) {
        Next::Misbehaved(why) => assert!(why.contains("signature-invalid"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(p.stats().misbehaving, 2);
    assert_eq!(p.active(), 0, "both pulls are over");
}

#[test]
fn a_full_deferred_queue_ends_the_pull_and_starts_none() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits { max_deferred_bytes: 0, ..Limits::default() });
    assert_eq!(p.start(7, "a", Via::Outbound, Instant::now()), None);
    let (_d, p) = puller(&chain, Limits { hourly_verifications: 0, max_deferred_bytes: super::p2p::MAX_NAPATT_SIZE, ..Limits::default() });
    let now = Instant::now();
    p.start(7, "a", Via::Pull, now).unwrap();
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    // The page is deferred, which leaves less than a page of room.
    assert_eq!(p.on_napatt(&chain, 7, &page(vec![att], Some(outpoint(1))), now), Next::Done { close: true });
    assert_eq!(p.collector().deferred_len(), 1);
}

#[test]
fn a_silent_publisher_times_out() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let t0 = Instant::now();
    p.start(7, "a", Via::Pull, t0).unwrap();
    p.start(8, "b", Via::Outbound, t0).unwrap();
    assert!(p.expire(t0 + PULL_TIMEOUT / 2).is_empty());
    let mut late = p.expire(t0 + PULL_TIMEOUT);
    late.sort();
    assert_eq!(late, vec![(7, true), (8, false)]);
    assert_eq!(p.stats().pulls_timed_out, 2);
    assert_eq!(p.active(), 0);
}

#[test]
fn dials_count_against_the_pull_connections_until_they_end() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let t0 = Instant::now();
    p.dial_started("1.2.3.4:8333", t0);
    assert_eq!(p.pull_connections(), 1);
    assert!(!p.due("1.2.3.4:8333", t0), "a dial counts as a pull for the interval");
    p.dial_ended("1.2.3.4:8333");
    assert_eq!(p.pull_connections(), 0);
    // One that never ends is counted while its dial and handshake could
    // still be running, then forgotten.
    p.dial_started("5.6.7.8:8333", t0);
    p.expire(t0 + DIAL_TIMEOUT);
    assert_eq!(p.pull_connections(), 1, "still within the dial and handshake timeouts");
    p.expire(t0 + Duration::from_secs(3 * 60));
    assert_eq!(p.pull_connections(), 0);
}

#[test]
fn a_disconnected_peers_pull_is_forgotten() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    p.start(7, "a", Via::Outbound, Instant::now()).unwrap();
    p.forget(7);
    assert_eq!(p.active(), 0);
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    assert_eq!(p.on_napatt(&chain, 7, &page(vec![att], None), Instant::now()), Next::Unsolicited);
}

#[test]
fn a_pull_ends_after_its_page_limit() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    p.start(7, "a", Via::Pull, now).unwrap();
    // Pages that cost nothing to pass over, each promising another.
    let empty = page(vec![], Some(outpoint(1)));
    for n in 1..MAX_PULL_PAGES {
        assert!(matches!(p.on_napatt(&chain, 7, &empty, now), Next::Continue(_)), "page {n}");
    }
    assert_eq!(p.on_napatt(&chain, 7, &empty, now), Next::Done { close: true });
    assert_eq!(p.active(), 0);
}

#[test]
fn at_most_eight_pulls_run_at_once() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    for peer in 0..MAX_ACTIVE_PULLS as u64 {
        assert!(p.start(peer, &format!("p{peer}"), Via::Outbound, now).is_some());
    }
    assert_eq!(p.start(99, "p99", Via::Outbound, now), None);
    p.forget(0);
    assert!(p.start(99, "p99", Via::Outbound, now).is_some(), "a slot freed is taken");
}

/// A chain that runs a hook during the first read: what another thread
/// does while a page is taken.
struct Hooked<'a> {
    chain: &'a Chain,
    hook: std::cell::RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}

impl ChainSource for Hooked<'_> {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        Some(read(self.chain))
    }
}

#[test]
fn a_peer_that_goes_while_its_page_is_taken_ends_its_pull() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    p.start(7, "a", Via::Pull, now).unwrap();
    let hooked = Hooked { chain: &chain, hook: std::cell::RefCell::new(Some(Box::new(|| p.forget(7)))) };
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    // A page promising more, from a peer that disconnects meanwhile: the
    // pull is not taken up again.
    assert_eq!(p.on_napatt(&hooked, 7, &page(vec![att], Some(outpoint(1))), now), Next::Done { close: false });
    assert_eq!(p.active(), 0);
    assert_eq!(p.pull_connections(), 0);
}

#[test]
fn a_page_whose_intake_panics_ends_its_pull() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    p.start(7, "a", Via::Pull, now).unwrap();
    let hooked = Hooked { chain: &chain, hook: std::cell::RefCell::new(Some(Box::new(|| panic!("intake failed")))) };
    let att = attest(&chain, &s, outpoint(1), "k", "yes", ANCHOR);
    let bytes = page(vec![att], Some(outpoint(1)));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.on_napatt(&hooked, 7, &bytes, now)));
    assert!(r.is_err());
    assert_eq!((p.active(), p.pull_connections()), (0, 0), "the slot is free again");
}

#[test]
fn at_most_four_pulls_run_over_inbound_connections() {
    let s = p2wpkh();
    let chain = chain_with(&s, 1);
    let (_d, p) = puller(&chain, Limits::default());
    let now = Instant::now();
    for peer in 0..MAX_INBOUND_PULLS as u64 {
        assert!(p.start(peer, &format!("p{peer}"), Via::Inbound, now).is_some());
    }
    assert_eq!(p.start(50, "p50", Via::Inbound, now), None, "inbound peers choose to connect, and state their own services");
    assert!(p.due("p50", now), "a refused pull is still due");
    assert!(p.start(51, "p51", Via::Outbound, now).is_some(), "the rest are kept for publishers this node chose");
    assert!(p.start(52, "p52", Via::Pull, now).is_some());
}
