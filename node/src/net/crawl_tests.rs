//! The crawl's limits and scheduler. Each limit has a test that fails when
//! the limit is taken out.

use super::*;
use std::net::SocketAddr;

fn v4(a: u8, b: u8, c: u8, d: u8) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from(([a, b, c, d], 8333)))
}

fn onion(i: u8) -> PeerAddr {
    let mut key = [0u8; 32];
    key[0] = i;
    PeerAddr::Onion { host: crate::net::peer::torv3_to_onion_host(&key), port: 8333 }
}

/// Limits that only the one under test can hit.
fn wide() -> Limits {
    Limits::new(MAX_CONCURRENCY, MAX_CONCURRENCY, MAX_RATE)
}

/// Address `i` in a network group of its own.
fn spread(i: usize) -> PeerAddr {
    v4(1 + (i / 250) as u8, (i % 250) as u8, 0, 1)
}

#[test]
fn one_session_per_target() {
    let mut s = Scheduler::new(wide(), 0);
    let a = v4(1, 2, 3, 4);
    assert_eq!(s.try_start(&a, 0), Ok(()));
    assert_eq!(s.try_start(&a, 0), Err(Refusal::TargetBusy));
    assert_eq!(s.open(), (1, 0), "the refusal took nothing");
    s.finish(&a);
    assert_eq!(s.try_start(&a, 0), Ok(()), "free again once the session ends");
}

#[test]
fn clearnet_concurrency_is_bounded() {
    let mut s = Scheduler::new(Limits::new(3, MAX_CONCURRENCY, MAX_RATE), 0);
    for i in 0..3 {
        assert_eq!(s.try_start(&spread(i), 0), Ok(()));
    }
    assert_eq!(s.try_start(&spread(3), 0), Err(Refusal::Concurrency));
    assert_eq!(s.try_start(&onion(1), 0), Ok(()), "Tor has its own limit");
    s.finish(&spread(0));
    assert_eq!(s.try_start(&spread(3), 0), Ok(()));
}

#[test]
fn tor_concurrency_is_bounded() {
    let mut s = Scheduler::new(Limits::new(MAX_CONCURRENCY, 2, MAX_RATE), 0);
    assert_eq!(s.try_start(&onion(1), 0), Ok(()));
    assert_eq!(s.try_start(&onion(2), 0), Ok(()));
    assert_eq!(s.try_start(&onion(3), 0), Err(Refusal::Concurrency));
    assert_eq!(s.try_start(&spread(0), 0), Ok(()), "clearnet has its own limit");
    assert_eq!(s.open(), (1, 2));
}

#[test]
fn two_sessions_per_ipv4_16_and_ipv6_32() {
    let mut s = Scheduler::new(wide(), 0);
    assert_eq!(s.try_start(&v4(5, 6, 1, 1), 0), Ok(()));
    assert_eq!(s.try_start(&v4(5, 6, 200, 9), 0), Ok(()));
    assert_eq!(s.try_start(&v4(5, 6, 7, 7), 0), Err(Refusal::Netgroup));
    assert_eq!(s.try_start(&v4(5, 7, 7, 7), 0), Ok(()), "the next /16 is another group");
    let v6 = |s: &str| PeerAddr::Socket(SocketAddr::new(s.parse().unwrap(), 8333));
    assert_eq!(s.try_start(&v6("2a01:4f8:1::1"), 0), Ok(()));
    assert_eq!(s.try_start(&v6("2a01:4f8:ffff::2"), 0), Ok(()));
    assert_eq!(s.try_start(&v6("2a01:4f8:1:2::3"), 0), Err(Refusal::Netgroup));
    assert_eq!(s.try_start(&v6("2a01:4f9::1"), 0), Ok(()));
    // An IPv4-mapped address is in its IPv4 group.
    assert_eq!(s.try_start(&v6("::ffff:5.6.9.9"), 0), Err(Refusal::Netgroup));
    s.finish(&v4(5, 6, 1, 1));
    assert_eq!(s.try_start(&v4(5, 6, 7, 7), 0), Ok(()));
    // Onions have no group.
    for i in 0..5 {
        assert_eq!(s.try_start(&onion(i), 0), Ok(()));
    }
}

#[test]
fn the_rate_allows_its_sessions_a_second() {
    let mut s = Scheduler::new(Limits::new(MAX_CONCURRENCY, MAX_CONCURRENCY, 10), 0);
    for i in 0..10 {
        assert_eq!(s.try_start(&spread(i), 0), Ok(()), "a second's worth at once");
    }
    assert_eq!(s.try_start(&spread(10), 0), Err(Refusal::Rate));
    assert_eq!(s.try_start(&spread(10), 99), Err(Refusal::Rate));
    assert_eq!(s.try_start(&spread(10), 100), Ok(()), "one more every 100 ms");
    assert_eq!(s.try_start(&spread(11), 150), Err(Refusal::Rate));
    // An idle minute banks no more than a second's worth.
    let mut started = 0;
    for i in 12..100 {
        if s.try_start(&spread(i), 60_000).is_ok() {
            started += 1;
        }
    }
    assert_eq!(started, 10);
    assert_eq!(s.budget(60_000), 0);
}

/// Over a simulated minute at the default rate, the sessions started are
/// a minute's worth and no more.
#[test]
fn the_default_rate_holds_over_a_minute() {
    let mut s = Scheduler::new(Limits::new(MAX_CONCURRENCY, MAX_CONCURRENCY, DEFAULT_RATE), 0);
    let mut started = Vec::new();
    for ms in (0..=60_000).step_by(10) {
        for _ in 0..s.budget(ms) {
            let a = spread(started.len());
            s.try_start(&a, ms).unwrap();
            s.finish(&a);
            started.push(ms);
        }
    }
    // The first second's burst, then ten a second.
    assert_eq!(started.len(), 10 + 600);
}

#[test]
fn the_ceilings_hold_whatever_is_asked() {
    let asked = Limits::new(10_000, 10_000, 10_000);
    assert_eq!(asked, Limits { clearnet: MAX_CONCURRENCY, tor: MAX_CONCURRENCY, rate: MAX_RATE });
    // Built by hand past them, the scheduler clamps again.
    let mut s = Scheduler::new(Limits { clearnet: 10_000, tor: 10_000, rate: 10_000 }, 0);
    assert_eq!(s.limits(), asked);
    let mut opened = 0;
    for i in 0..1_000 {
        // Time enough for the rate, each in a group of its own.
        if s.try_start(&spread(i), (i as u64) * 1_000).is_ok() {
            opened += 1;
        }
    }
    assert_eq!(opened, MAX_CONCURRENCY);
    assert_eq!(s.budget(10_000_000), MAX_RATE as usize, "a second's worth at the ceiling rate");
}

#[test]
fn session_caps_are_the_sum_of_their_phases() {
    let t = Timings::DEFAULT;
    // Two attempts of a 5 s dial and a 5 s handshake, the 10 s wait, the
    // 1 s close.
    assert_eq!(t.session_cap(SessionKind::Liveness, false), Duration::from_secs(31));
    assert_eq!(t.session_cap(SessionKind::V1Recheck, false), Duration::from_secs(21));
    assert_eq!(t.session_cap(SessionKind::Discovery, false), Duration::from_secs(121));
    assert_eq!(t.session_cap(SessionKind::Discovery, true), Duration::from_secs(221));
}

#[test]
fn the_user_agent_declares_a_crawler() {
    let v = env!("CARGO_PKG_VERSION");
    assert_eq!(user_agent(None).unwrap(), format!("/satd:{v}(crawler)/"));
    assert_eq!(user_agent(Some("census@example")).unwrap(), format!("/satd:{v}(crawler; census@example)/"));
    assert!(user_agent(Some("a/b")).is_err(), "a comment cannot forge a field");
}

#[test]
fn crawlnet_names_ipv4_ipv6_and_onion_only() {
    assert_eq!(parse_network("IPv4"), Ok(Network::Ipv4));
    assert_eq!(parse_network("ipv6"), Ok(Network::Ipv6));
    assert_eq!(parse_network("onion"), Ok(Network::Onion));
    assert!(parse_network("i2p").unwrap_err().contains("never dials"));
    assert!(parse_network("cjdns").is_err());
    assert!(parse_network("tor").is_err());
}

// ---- The chain check ----

fn header(prev: bitcoin::BlockHash, nonce: u32) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: bitcoin::hashes::Hash::all_zeros(),
        time: 1_700_000_000,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    }
}

/// `n` headers from `from`, each on the one before.
fn branch(from: bitcoin::BlockHash, n: usize, salt: u32) -> Vec<bitcoin::block::Header> {
    let mut out: Vec<bitcoin::block::Header> = Vec::with_capacity(n);
    for i in 0..n {
        let prev = out.last().map_or(from, |h| h.block_hash());
        out.push(header(prev, salt.wrapping_mul(1_000_003).wrapping_add(i as u32)));
    }
    out
}

/// Our chain: a genesis and `n` blocks on it, and a stale block off it.
struct Ours {
    chain: Vec<bitcoin::block::Header>,
    stale: bitcoin::block::Header,
    asked: std::cell::Cell<u32>,
}

impl Ours {
    fn new(n: usize) -> Ours {
        let genesis = header(bitcoin::hashes::Hash::all_zeros(), 7);
        let mut chain = vec![genesis];
        chain.extend(branch(genesis.block_hash(), n, 1));
        let stale = header(chain[1].block_hash(), 99);
        Ours { chain, stale, asked: Default::default() }
    }

    fn hash(&self, h: usize) -> bitcoin::BlockHash {
        self.chain[h].block_hash()
    }

    fn tip(&self) -> usize {
        self.chain.len() - 1
    }

    fn lookup(&self, hash: &bitcoin::BlockHash) -> OurBlock {
        self.asked.set(self.asked.get() + 1);
        if let Some(h) = self.chain.iter().position(|c| c.block_hash() == *hash) {
            OurBlock::Active(h as u32)
        } else if self.stale.block_hash() == *hash {
            OurBlock::Stale
        } else {
            OurBlock::Unknown
        }
    }

    /// The chain check of the probe a crawl session sends: the tip's parent
    /// as locator, the tip as stop hash.
    fn check(&self, headers: &[bitcoin::block::Header], peer_height: i32) -> ChainCheck {
        let tip = self.tip();
        self.asked.set(0);
        let got = chain_check(&self.hash(tip - 1), (tip - 1) as u32, &self.hash(tip), headers, peer_height, |h| {
            self.lookup(h)
        });
        assert!(self.asked.get() <= 2, "asked about {} hashes", self.asked.get());
        got
    }
}

/// A node with our tip answers with it: on chain. One whose block after
/// our locator is another is on a fork. One that does not know our
/// locator's block on its chain answers from its genesis: behind if what
/// it shows is ours.
#[test]
fn the_chain_check_tells_on_chain_behind_and_fork_apart() {
    let ours = Ours::new(5);
    let tip = ours.tip();
    assert_eq!(ours.check(&[ours.chain[tip]], tip as i32), ChainCheck::OnChain);
    // At our locator's block, nothing past it.
    assert_eq!(ours.check(&[], (tip - 1) as i32), ChainCheck::Behind);
    // A sibling of our tip.
    let sibling = header(ours.hash(tip - 1), 12345);
    assert_eq!(ours.check(&[sibling], tip as i32), ChainCheck::Fork);
    // From its genesis, our blocks up to its tip below our locator.
    assert_eq!(ours.check(&ours.chain[1..3], 2), ChainCheck::Behind);
    // From its genesis, leaving our chain.
    let mut leaving = ours.chain[1..3].to_vec();
    leaving.extend(branch(leaving[1].block_hash(), 2, 2));
    assert_eq!(ours.check(&leaving, 4), ChainCheck::Fork);
    // From a block we hold off our chain.
    assert_eq!(ours.check(&branch(ours.stale.block_hash(), 2, 3), 4), ChainCheck::Fork);
    // From a block past our locator on our chain: it has the locator's.
    assert_eq!(ours.check(&branch(ours.hash(tip), 1, 4), tip as i32 + 1), ChainCheck::OnChain);
}

/// A node whose genesis is not ours (another chain under this network's
/// magic and port) answers from its own genesis, which we do not know.
#[test]
fn the_chain_check_names_another_chain() {
    let ours = Ours::new(5);
    let theirs = branch(header(bitcoin::hashes::Hash::all_zeros(), 8).block_hash(), 3, 5);
    assert_eq!(ours.check(&theirs, 3), ChainCheck::OtherChain);
}

/// A full answer from its genesis that is all ours shows only the start of
/// its chain: a node that states our locator's height or more leaves our
/// chain past it (a fork); one that states less is behind. A short answer
/// is the whole chain and is believed over the stated height.
#[test]
fn a_full_answer_of_our_blocks_is_judged_with_the_stated_height() {
    let max = crate::net::limits::MAX_HEADERS_RESULTS;
    let ours = Ours::new(max + 5);
    let locator_height = (ours.tip() - 1) as i32;
    let shown = &ours.chain[1..=max];
    assert_eq!(ours.check(shown, locator_height), ChainCheck::Fork);
    assert_eq!(ours.check(shown, locator_height - 1), ChainCheck::Behind);
    assert_eq!(ours.check(&shown[..max - 1], locator_height + 10), ChainCheck::Behind);
}

/// An answer whose headers stop linking is judged by the part that links.
#[test]
fn the_chain_check_reads_the_linked_part_of_an_answer() {
    let ours = Ours::new(5);
    let mut broken = ours.chain[1..3].to_vec();
    broken.push(header(bitcoin::hashes::Hash::all_zeros(), 4242));
    assert_eq!(ours.check(&broken, 2), ChainCheck::Behind);
}

/// An answer that starts with a genesis header itself is judged by that
/// genesis: ours, and the rest is our chain below the locator, is behind;
/// another chain's is another chain.
#[test]
fn the_chain_check_reads_an_answer_that_starts_at_genesis() {
    let ours = Ours::new(5);
    assert_eq!(ours.check(&ours.chain[0..3], 2), ChainCheck::Behind);
    let genesis = header(bitcoin::hashes::Hash::all_zeros(), 8);
    let mut theirs = vec![genesis];
    theirs.extend(branch(genesis.block_hash(), 2, 5));
    assert_eq!(ours.check(&theirs, 2), ChainCheck::OtherChain);
}
