//! `CrawlBook`: admission, timers, the snapshot, the bound and the file.

use super::*;
use crate::net::fingerprint::{AddrKind, Confidence, Family};
use crate::net::v2transport::V2Greeting;
use std::net::{Ipv4Addr, SocketAddr};

const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
const NOW: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

/// Public IPv4 address number `i`, one per `/24` (`1.x.y.1`).
fn v4(i: u32) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((Ipv4Addr::from(0x0100_0001 + (i << 8)), 8333)))
}

fn entry(addr: AddrV2, port: u16, time: u64) -> AddrV2Message {
    AddrV2Message { time: time as u32, services: ServiceFlags::NETWORK, addr, port }
}

fn ip_entry(ip: &str, port: u16) -> AddrV2Message {
    let addr = match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(v) => AddrV2::Ipv4(v),
        IpAddr::V6(v) => AddrV2::Ipv6(v),
    };
    entry(addr, port, NOW)
}

/// The answer's IPv4 entries, one per `/24`, from `from` on.
fn v4_answer(from: u32, n: u32) -> Vec<AddrV2Message> {
    (from..from + n)
        .map(|i| match v4(i) {
            PeerAddr::Socket(SocketAddr::V4(sa)) => entry(AddrV2::Ipv4(*sa.ip()), 8333, NOW),
            _ => unreachable!(),
        })
        .collect()
}

fn source(i: u32) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((Ipv4Addr::new(2, 0, 0, i as u8), 8333)))
}

fn observation(at: u64) -> Observation {
    Observation {
        at,
        fingerprint: Fingerprint::Known(Family::Core, Confidence::High),
        user_agent: "/Satoshi:32.1.0/".to_string(),
        protocol_version: 70016,
        services: 0xc09,
        asn: Some(64496),
        probes: ProbeResults::default(),
        v2: true,
        height: 900_000,
        our_height: 900_002,
        chain_check: None,
        clock_offset_secs: Some(-3),
        handshake_rtt_ms: Some(120),
        getaddr: None,
        shape: None,
    }
}

/// An unknown shape, with an odd command and a BIP 324 greeting.
fn shape() -> UnknownShape {
    UnknownShape {
        commands: ["version", "verack", "addrv2", "zzzzzzzzzzzz"].map(str::to_string).to_vec(),
        relay: false,
        v2: Some(V2Greeting { garbage_len: 4095, decoys: 2, version_len: 7 }),
        getaddr: Some(AddrKind::Addr),
    }
}

fn v2_ok(at: u64) -> SessionResult {
    SessionResult { v2: Attempt::Ok, v1: Attempt::NotTried, observation: Some(observation(at)) }
}

fn down() -> SessionResult {
    SessionResult { v2: Attempt::Failed, v1: Attempt::Failed, observation: None }
}

fn due_kind(book: &CrawlBook, addr: &PeerAddr, now: u64) -> Option<SessionKind> {
    book.next_due(now, usize::MAX).into_iter().find(|(a, _)| a == addr).map(|(_, k)| k)
}

/// A book holding `addr`, reached over v2 on first contact at `at` (its
/// discovery) and v1-rechecked at once.
fn reached_book(addr: &PeerAddr, at: u64) -> CrawlBook {
    let mut book = CrawlBook::default();
    assert!(book.seed(addr.clone(), 0, at));
    book.record_result(addr, None, SessionKind::Discovery, v2_ok(at), at);
    book.record_result(addr, None, SessionKind::V1Recheck, SessionResult { v1: Attempt::Ok, ..Default::default() }, at);
    book
}

// ---- Admission ----

#[test]
fn an_answer_over_1000_entries_is_dropped_whole() {
    let mut book = CrawlBook::default();
    let r = book.admit(&source(1), &v4_answer(0, 1_001), NOW);
    assert!(r.dropped_whole);
    assert_eq!((r.entries, r.admitted), (1_001, 0));
    assert!(book.is_empty());
    let r = book.admit(&source(1), &v4_answer(0, 1_000), NOW);
    assert!(!r.dropped_whole, "exactly 1,000 is read");
    assert_eq!(r.admitted, MAX_ADMITTED_PER_ANSWER);
}

#[test]
fn at_most_500_new_addresses_are_admitted_per_answer() {
    let mut book = CrawlBook::default();
    let r = book.admit(&source(1), &v4_answer(0, 600), NOW);
    assert_eq!((r.admitted, r.over_source_cap), (500, 100));
    assert_eq!(book.len(), 500);
    // Addresses already known are named again without counting against it.
    let r = book.admit(&source(2), &v4_answer(0, 600), NOW);
    assert_eq!((r.named_again, r.admitted, r.over_source_cap), (500, 100, 0));
}

#[test]
fn entries_older_than_the_max_age_are_ignored() {
    let params = BookParams { max_age_secs: DAY, ..BookParams::default() };
    let mut book = CrawlBook::new(params);
    let mut answer = v4_answer(0, 2);
    answer[0].time = (NOW - DAY) as u32;
    answer[1].time = (NOW - DAY - 1) as u32;
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!((r.admitted, r.too_old), (1, 1), "exactly the max age is kept");
    assert_eq!(BookParams::default().max_age_secs, 5 * DAY);
}

#[test]
fn entries_more_than_ten_minutes_ahead_are_ignored() {
    let mut book = CrawlBook::default();
    let mut answer = v4_answer(0, 2);
    answer[0].time = (NOW + 600) as u32;
    answer[1].time = (NOW + 601) as u32;
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!((r.admitted, r.in_future), (1, 1));
}

/// The flood the frontier rules are for: 1,000 addresses from one IPv6
/// `/64` admit one, and later answers cannot add a second.
#[test]
fn an_addr_flood_from_one_ipv6_64_admits_one() {
    let mut book = CrawlBook::default();
    let flood: Vec<AddrV2Message> = (0..1_000u32)
        .map(|i| entry(AddrV2::Ipv6(Ipv6Addr::new(0x2a01, 0x4f8, 1, 2, 0, 0, (i >> 16) as u16, i as u16 + 1)), 8333, NOW))
        .collect();
    let r = book.admit(&source(1), &flood, NOW);
    assert_eq!((r.admitted, r.ipv6_prefix_full), (1, 999));
    let r = book.admit(&source(2), &flood[1..], NOW);
    assert_eq!(r.admitted, 0, "nor from another source");
    // The next /64 is its own prefix.
    let r = book.admit(&source(1), &[ip_entry("2a01:4f8:1:3::1", 8333)], NOW);
    assert_eq!(r.admitted, 1);
}

#[test]
fn ipv4_admits_a_bounded_number_per_24() {
    let mut book = CrawlBook::default();
    let answer: Vec<AddrV2Message> = (1..=20).map(|i| ip_entry(&format!("5.6.7.{i}"), 8333)).collect();
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!((r.admitted, r.ipv4_prefix_full), (8, 12), "default 8 per /24");

    let mut book = CrawlBook::new(BookParams { ipv4_per_24: 3, ..BookParams::default() });
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!(r.admitted, 3, "the bound is a parameter");
    let r = book.admit(&source(1), &[ip_entry("5.6.8.1", 8333)], NOW);
    assert_eq!(r.admitted, 1, "the next /24 is its own prefix");
}

#[test]
fn bogon_private_reserved_and_multicast_addresses_are_refused() {
    let mut book = CrawlBook::default();
    let refused = [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "0.0.0.1",
        "100.64.0.1",
        "169.254.0.1",
        "192.0.2.1",
        "192.0.0.8",
        "198.18.0.1",
        "224.0.0.1",
        "239.1.1.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::1.2.3.4",
        "::ffff:10.0.0.1",
    ];
    let answer: Vec<AddrV2Message> = refused.iter().map(|ip| ip_entry(ip, 8333)).collect();
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!((r.admitted, r.not_public), (0, refused.len()), "{r:?}");
    // A CJDNS entry outside fc00::/8 is not one.
    let r = book.admit(&source(1), &[entry(AddrV2::Cjdns("fd00::1".parse().unwrap()), 8333, NOW)], NOW);
    assert_eq!(r.not_public, 1);
    let r = book.admit(&source(1), &[ip_entry("1.2.3.4", 8333), ip_entry("2a01:4f8::1", 8333), ip_entry("::ffff:1.2.3.5", 8333)], NOW);
    assert_eq!(r.admitted, 3, "public unicast is admitted, a mapped address as IPv4");
    assert!(book.get(&CrawlAddr::Peer(PeerAddr::Socket("1.2.3.5:8333".parse().unwrap()))).is_some());
}

#[test]
fn cores_bad_ports_are_skipped() {
    let mut book = CrawlBook::default();
    let r = book.admit(&source(1), &[ip_entry("1.2.3.4", 22), ip_entry("1.2.3.5", 25), ip_entry("1.2.3.6", 8333)], NOW);
    assert_eq!((r.admitted, r.bad_port), (1, 2));
    assert!(!book.seed(PeerAddr::Socket("1.2.3.7:22".parse().unwrap()), 0, NOW), "seeds too");
}

#[test]
fn torv2_and_unknown_networks_are_refused() {
    let mut book = CrawlBook::default();
    let r = book.admit(&source(1), &[entry(AddrV2::TorV2([1; 10]), 8333, NOW), entry(AddrV2::Unknown(9, vec![1, 2]), 8333, NOW)], NOW);
    assert_eq!((r.admitted, r.unsupported), (0, 2));
}

#[test]
fn onion_v3_has_no_prefix_cap() {
    let mut book = CrawlBook::default();
    let answer: Vec<AddrV2Message> = (0..50u8)
        .map(|i| {
            let mut key = [7u8; 32];
            key[31] = i;
            entry(AddrV2::TorV3(key), 8333, NOW)
        })
        .collect();
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!(r.admitted, 50);
    assert_eq!(book.counts().learned[2], 50, "onion");
    let (addr, _) = book.rows().next().unwrap();
    assert!(matches!(addr, CrawlAddr::Peer(PeerAddr::Onion { host, .. }) if host.ends_with(".onion")));
    assert_eq!(book.next_due(NOW, usize::MAX).len(), 50, "and dialled");
}

#[test]
fn i2p_and_cjdns_are_counted_but_never_dialled() {
    let mut book = CrawlBook::default();
    let answer: Vec<AddrV2Message> = (0..5u8)
        .flat_map(|i| {
            [
                entry(AddrV2::I2p([i; 32]), 0, NOW),
                entry(AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, u16::from(i) + 1)), 8333, NOW),
            ]
        })
        .collect();
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!(r.admitted, 10, "no prefix cap on either");
    let c = book.counts();
    assert_eq!((c.learned[3], c.learned[4]), (5, 5), "i2p, cjdns");
    assert!(book.next_due(NOW + 365 * DAY, usize::MAX).is_empty(), "never due");
    assert!(book.rows().all(|(a, _)| !a.dialable()));
}

#[test]
fn distinct_sources_are_counted_and_single_source_addresses_go_last() {
    let mut book = CrawlBook::default();
    book.admit(&source(1), &v4_answer(0, 2), NOW);
    book.admit(&source(1), &v4_answer(0, 2), NOW);
    let key = |i| CrawlAddr::Peer(v4(i));
    assert_eq!(book.get(&key(0)).unwrap().source_count(), 1, "the same source twice is one");
    // A later-learned address that two sources named is dialled first.
    book.admit(&source(2), &v4_answer(1, 1), NOW + 10);
    assert_eq!(book.get(&key(1)).unwrap().source_count(), 2);
    let order: Vec<PeerAddr> = book.next_due(NOW + 20, usize::MAX).into_iter().map(|(a, _)| a).collect();
    assert_eq!(order, vec![v4(1), v4(0)]);
    // The count saturates.
    for s in 3..40 {
        book.admit(&source(s), &v4_answer(1, 1), NOW);
    }
    assert_eq!(book.get(&key(1)).unwrap().source_count(), MAX_SOURCES);
}

// ---- Timers ----

#[test]
fn first_contact_is_a_discovery_then_a_v1_recheck() {
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.admit(&source(1), &v4_answer(1, 1), NOW);
    assert_eq!(due_kind(&book, &a, NOW), Some(SessionKind::Discovery));
    book.record_result(&a, None, SessionKind::Discovery, v2_ok(NOW), NOW);
    assert_eq!(due_kind(&book, &a, NOW), Some(SessionKind::V1Recheck), "v1 recheck on first contact");
}

#[test]
fn liveness_is_due_every_interval() {
    let a = v4(1);
    let book = reached_book(&a, NOW);
    assert_eq!(due_kind(&book, &a, NOW + 2 * HOUR - 1), None);
    assert_eq!(due_kind(&book, &a, NOW + 2 * HOUR), Some(SessionKind::Liveness));
    let mut book = book;
    book.record_result(&a, None, SessionKind::Liveness, v2_ok(NOW + 2 * HOUR), NOW + 2 * HOUR);
    assert_eq!(due_kind(&book, &a, NOW + 4 * HOUR - 1), None);
    assert_eq!(due_kind(&book, &a, NOW + 4 * HOUR), Some(SessionKind::Liveness));

    let mut fast = CrawlBook::new(BookParams { liveness_secs: HOUR, ..BookParams::default() });
    fast.seed(a.clone(), 0, NOW);
    fast.record_result(&a, None, SessionKind::Discovery, SessionResult { v1: Attempt::Ok, v2: Attempt::Failed, observation: None }, NOW);
    assert_eq!(due_kind(&fast, &a, NOW + HOUR), Some(SessionKind::Liveness), "the interval is a parameter");
}

#[test]
fn discovery_is_due_once_per_day() {
    let a = v4(1);
    let mut book = reached_book(&a, NOW);
    for t in (1..12).map(|i| NOW + i * 2 * HOUR) {
        assert_eq!(due_kind(&book, &a, t), Some(SessionKind::Liveness), "at +{}h", (t - NOW) / HOUR);
        book.record_result(&a, None, SessionKind::Liveness, v2_ok(t), t);
    }
    assert_eq!(due_kind(&book, &a, NOW + DAY), Some(SessionKind::Discovery));
    book.record_result(&a, None, SessionKind::Discovery, v2_ok(NOW + DAY), NOW + DAY);
    assert_eq!(book.get(&CrawlAddr::Peer(a.clone())).unwrap().last_discovery, Some(NOW + DAY));
    assert_eq!(due_kind(&book, &a, NOW + 2 * DAY - 1), Some(SessionKind::Liveness));
}

#[test]
fn v1_recheck_is_on_first_contact_then_weekly_and_marks_v2_only() {
    let a = v4(1);
    let key = CrawlAddr::Peer(a.clone());
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    book.record_result(&a, None, SessionKind::Discovery, v2_ok(NOW), NOW);
    assert_eq!(due_kind(&book, &a, NOW), Some(SessionKind::V1Recheck));
    let v1_fail = SessionResult { v1: Attempt::Failed, ..Default::default() };
    book.record_result(&a, None, SessionKind::V1Recheck, v1_fail.clone(), NOW + 5);
    let e = book.get(&key).unwrap();
    assert!(e.v2_only, "v1 failed next to a v2 success");
    assert_eq!((e.failures, e.retry_at), (0, None), "a v1 refusal is not unreachability");
    // Daily discoveries and liveness checks in between, no recheck until
    // a week has passed.
    let mut t = NOW;
    while t + 2 * HOUR < NOW + 5 + V1_RECHECK_INTERVAL_SECS {
        t += 2 * HOUR;
        let kind = due_kind(&book, &a, t).expect("something is due");
        assert_ne!(kind, SessionKind::V1Recheck, "at +{}h", (t - NOW) / HOUR);
        book.record_result(&a, None, kind, v2_ok(t), t);
    }
    t = NOW + 5 + V1_RECHECK_INTERVAL_SECS;
    assert_eq!(due_kind(&book, &a, t), Some(SessionKind::V1Recheck), "weekly");
    // v1 works now: no longer v2-only.
    book.record_result(&a, None, SessionKind::V1Recheck, SessionResult { v1: Attempt::Ok, ..Default::default() }, t);
    assert!(!book.get(&key).unwrap().v2_only);

    // A target reached over v1 after v2 failed never gets a recheck.
    let b = v4(2);
    book.seed(b.clone(), 0, NOW);
    book.record_result(&b, None, SessionKind::Discovery, SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: None }, NOW);
    for t in [NOW, NOW + 2 * HOUR, NOW + 8 * DAY] {
        assert_ne!(due_kind(&book, &b, t), Some(SessionKind::V1Recheck));
    }
    assert!(!book.get(&CrawlAddr::Peer(b)).unwrap().v2_only);
}

#[test]
fn a_node_down_on_both_transports_is_not_v2_only() {
    let a = v4(1);
    let mut book = reached_book(&a, NOW);
    book.record_result(&a, None, SessionKind::Liveness, down(), NOW + 2 * HOUR);
    let e = book.get(&CrawlAddr::Peer(a)).unwrap();
    assert!(!e.v2_only);
    assert_eq!(e.failures, 1);
}

#[test]
fn unreachable_backs_off_one_four_and_24_hours_then_daily() {
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let mut t = NOW;
    for wait in [HOUR, 4 * HOUR, DAY, DAY, DAY] {
        assert!(due_kind(&book, &a, t).is_some());
        book.record_result(&a, None, SessionKind::Discovery, down(), t);
        assert_eq!(due_kind(&book, &a, t + wait - 1), None, "waits {}h", wait / HOUR);
        assert_eq!(due_kind(&book, &a, t + wait), Some(SessionKind::Discovery));
        t += wait;
    }
    // A success resets it.
    book.record_result(&a, None, SessionKind::Discovery, v2_ok(t), t);
    book.record_result(&a, None, SessionKind::Liveness, down(), t + 2 * HOUR);
    assert_eq!(book.get(&CrawlAddr::Peer(a.clone())).unwrap().retry_at, Some(t + 3 * HOUR));
}

#[test]
fn an_address_failing_for_30_days_that_no_source_names_is_dropped() {
    let a = v4(1);
    let b = v4(2);
    let mut book = CrawlBook::default();
    book.admit(&source(1), &v4_answer(1, 2), NOW);
    let mut t = NOW;
    while t < NOW + 31 * DAY {
        for x in [&a, &b] {
            if due_kind(&book, x, t).is_some() {
                book.record_result(x, None, SessionKind::Discovery, down(), t);
            }
        }
        // b keeps being named.
        if (NOW + 29 * DAY..NOW + 29 * DAY + HOUR).contains(&t) {
            let mut ans = v4_answer(2, 1);
            ans[0].time = t as u32;
            book.admit(&source(2), &ans, t);
        }
        t += HOUR;
    }
    assert!(book.get(&CrawlAddr::Peer(a)).is_none(), "dropped");
    assert!(book.get(&CrawlAddr::Peer(b)).is_some(), "named again within the 30 days");
}

#[test]
fn never_dialled_entries_go_after_30_days_unnamed() {
    let mut book = CrawlBook::default();
    book.admit(&source(1), &[entry(AddrV2::I2p([1; 32]), 0, NOW)], NOW);
    book.expire(NOW + DROP_AFTER_SECS - 1);
    assert_eq!(book.len(), 1);
    book.expire(NOW + DROP_AFTER_SECS);
    assert!(book.is_empty());
}

#[test]
fn one_session_at_a_time() {
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let session = book.mark_dialling(&a, NOW);
    assert!(session.is_some());
    assert!(book.mark_dialling(&a, NOW).is_none(), "already open");
    assert_eq!(due_kind(&book, &a, NOW), None);
    assert!(book.record_result(&a, session, SessionKind::Discovery, v2_ok(NOW), NOW));
    assert!(!book.get(&CrawlAddr::Peer(a.clone())).unwrap().in_flight(NOW));
    assert!(book.mark_dialling(&v4(99), NOW).is_none(), "not in the book");
}

#[test]
fn liveness_sessions_keep_the_last_discoverys_findings() {
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let mut obs = observation(NOW);
    obs.getaddr = Some(GetaddrResult::Answered { entries: 812, delay_ms: 21_000 });
    obs.chain_check = Some(ChainCheck::OnChain);
    obs.probes.set(Probe::Ping, ProbeOutcome::Answered(40));
    book.record_result(&a, None, SessionKind::Discovery, SessionResult { v2: Attempt::Ok, v1: Attempt::NotTried, observation: Some(obs) }, NOW);
    book.record_result(&a, None, SessionKind::Liveness, v2_ok(NOW + 2 * HOUR), NOW + 2 * HOUR);
    let o = book.get(&CrawlAddr::Peer(a)).unwrap().observation.clone().unwrap();
    assert_eq!(o.at, NOW + 2 * HOUR);
    assert_eq!(o.getaddr, Some(GetaddrResult::Answered { entries: 812, delay_ms: 21_000 }));
    assert_eq!(o.chain_check, Some(ChainCheck::OnChain));
    assert_eq!(o.probes.get(Probe::Ping), Some(ProbeOutcome::Answered(40)));
    assert_eq!(o.height_gap(), 2);
}

#[test]
fn the_snapshot_is_the_handshakes_within_the_liveness_window() {
    let mut book = CrawlBook::default();
    for i in 0..3 {
        book.seed(v4(i), 0, NOW);
    }
    book.record_result(&v4(0), None, SessionKind::Discovery, v2_ok(NOW), NOW);
    book.record_result(&v4(1), None, SessionKind::Discovery, v2_ok(NOW + HOUR), NOW + HOUR);
    book.record_result(&v4(2), None, SessionKind::Discovery, down(), NOW + HOUR);
    let at = |now| {
        let mut v: Vec<PeerAddr> = book.snapshot(now).map(|(a, _)| a.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(at(NOW + HOUR), vec![v4(0), v4(1)]);
    assert_eq!(at(NOW + 2 * HOUR), vec![v4(0), v4(1)], "the window's edge is in");
    assert_eq!(at(NOW + 2 * HOUR + 1), vec![v4(1)]);
}

#[test]
fn past_the_cap_the_least_recently_used_goes() {
    let mut book = CrawlBook::new(BookParams { max_entries: 3, ..BookParams::default() });
    for i in 0..3 {
        book.admit(&source(1), &v4_answer(i, 1), NOW + u64::from(i));
    }
    // Reaching the oldest makes it the most recent.
    book.record_result(&v4(0), None, SessionKind::Discovery, v2_ok(NOW + 10), NOW + 10);
    book.admit(&source(1), &v4_answer(3, 1), NOW + 11);
    assert_eq!(book.len(), 3);
    assert!(book.get(&CrawlAddr::Peer(v4(1))).is_none(), "the least recently used went");
    // Named again refreshes too.
    book.admit(&source(2), &v4_answer(2, 1), NOW + 12);
    book.admit(&source(1), &v4_answer(4, 1), NOW + 13);
    assert!(book.get(&CrawlAddr::Peer(v4(0))).is_none(), "v4(2) was named after v4(0) was reached");
    assert!(book.get(&CrawlAddr::Peer(v4(2))).is_some() && book.get(&CrawlAddr::Peer(v4(3))).is_some());
    // An evicted address frees its prefix.
    let mut small = CrawlBook::new(BookParams { max_entries: 1, ..BookParams::default() });
    small.admit(&source(1), &[ip_entry("2a01:4f8:1:2::1", 8333)], NOW);
    small.admit(&source(1), &v4_answer(0, 1), NOW + 1);
    let r = small.admit(&source(1), &[ip_entry("2a01:4f8:1:2::2", 8333)], NOW + 2);
    assert_eq!(r.admitted, 1);
    assert_eq!(BookParams::default().max_entries, 250_000);
}

// ---- The file ----

fn full_book() -> CrawlBook {
    let mut book = CrawlBook::default();
    let mut answer = v4_answer(0, 3);
    answer.push(ip_entry("2a01:4f8:1:2::1", 18333));
    answer.push(entry(AddrV2::TorV3([9; 32]), 8333, NOW));
    answer.push(entry(AddrV2::I2p([3; 32]), 0, NOW));
    answer.push(entry(AddrV2::Cjdns("fc00::5".parse().unwrap()), 8333, NOW));
    answer[0].services = ServiceFlags::NETWORK | ServiceFlags::P2P_V2;
    book.admit(&source(1), &answer, NOW);
    book.admit(&source(2), &answer[..1], NOW + 1);
    let mut obs = observation(NOW + 2);
    obs.getaddr = Some(GetaddrResult::Answered { entries: 1000, delay_ms: 70_000 });
    obs.chain_check = Some(ChainCheck::Fork);
    obs.asn = None;
    obs.clock_offset_secs = None;
    obs.probes.set(Probe::Unknown, ProbeOutcome::Disconnected);
    obs.probes.set(Probe::GetData, ProbeOutcome::Silent);
    book.record_result(&v4(0), None, SessionKind::Discovery, SessionResult { v2: Attempt::Ok, v1: Attempt::NotTried, observation: Some(obs) }, NOW + 2);
    book.record_result(&v4(0), None, SessionKind::V1Recheck, SessionResult { v1: Attempt::Failed, ..Default::default() }, NOW + 3);
    book.record_result(&v4(1), None, SessionKind::Discovery, down(), NOW + 4);
    let mut nogetaddr = observation(NOW + 5);
    nogetaddr.getaddr = Some(GetaddrResult::NoAnswer);
    nogetaddr.height = -1;
    nogetaddr.fingerprint = Fingerprint::Unknown;
    nogetaddr.shape = Some(shape());
    book.record_result(&v4(2), None, SessionKind::Discovery, SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(nogetaddr) }, NOW + 5);
    book
}

#[test]
fn the_book_round_trips_through_the_file() {
    let book = full_book();
    assert_eq!(book.len(), 7);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CRAWL_FILE);
    book.save(&path, MAGIC).unwrap();
    let back = CrawlBook::load(&path, MAGIC, NOW + 6, BookParams::default()).unwrap();
    assert_eq!(back.len(), book.len());
    for (addr, e) in book.rows() {
        assert_eq!(back.get(addr), Some(e), "{addr:?}");
    }
    let e = back.get(&CrawlAddr::Peer(v4(0))).unwrap();
    assert!(e.v2_only && e.v2_advertised() && e.source_count() == 2);
    // The timers survive: the same addresses are due, for the same reasons.
    for t in [NOW + 6, NOW + 3 * HOUR, NOW + 2 * DAY] {
        assert_eq!(back.next_due(t, usize::MAX), book.next_due(t, usize::MAX));
    }
    assert_eq!(back.encode(MAGIC), book.encode(MAGIC), "written the same again");
    // An absent file is an empty book.
    assert!(CrawlBook::load(&dir.path().join("absent.dat"), MAGIC, NOW, BookParams::default()).unwrap().is_empty());
}

/// Replace the checksum after editing a file's body.
fn reseal(mut body: Vec<u8>) -> Vec<u8> {
    let sum = sha256d::Hash::hash(&body);
    body.extend_from_slice(sum.as_byte_array());
    body
}

#[test]
fn a_bad_file_is_refused() {
    let bytes = full_book().encode(MAGIC);
    let p = BookParams::default();
    assert!(CrawlBook::decode(&bytes, MAGIC, NOW, p).is_ok());
    let err = |b: &[u8]| CrawlBook::decode(b, MAGIC, NOW, p).unwrap_err();
    assert!(CrawlBook::decode(&bytes, [0, 1, 2, 3], NOW, p).unwrap_err().contains("another network"));
    let mut flipped = bytes.clone();
    flipped[40] ^= 1;
    assert!(err(&flipped).contains("checksum"));
    let body = bytes[..bytes.len() - 32].to_vec();
    let mut wrong_magic = body.clone();
    wrong_magic[..8].copy_from_slice(b"satdsrv1");
    assert!(err(&reseal(wrong_magic)).contains("not a crawl book"));
    let mut wrong_version = body.clone();
    // Version 1 had no shapes: set aside, not misread.
    wrong_version[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert!(err(&reseal(wrong_version)).contains("version 1"));
    assert!(err(&reseal(body[..body.len() - 3].to_vec())).contains("truncated"));
    let mut trailing = body.clone();
    trailing.push(0);
    assert!(err(&reseal(trailing)).contains("trailing"));
    assert!(err(&bytes[..10]).contains("too short"));
    // A survey file is not a crawl book.
    let mut survey = crate::net::survey::SurveyStore::default();
    survey.insert(
        v4(0),
        crate::net::survey::SurveyRecord {
            fingerprint: Fingerprint::Unknown,
            user_agent: String::new(),
            protocol_version: 70016,
            services: 0,
            v2: false,
            asn: None,
            first_seen: NOW,
            last_seen: NOW,
            probes: ProbeResults::default(),
        },
        NOW,
    );
    assert!(CrawlBook::decode(&survey.encode(MAGIC), MAGIC, NOW, p).is_err());
}

/// An unknown shape is bounded on the way in: more commands than a
/// transcript holds, or a command longer than the wire's field, is a bad
/// file; and on the way out, a longer one is cut to the bound.
#[test]
fn an_unknown_shape_is_bounded() {
    let mut buf = Vec::new();
    encode_shape(&mut buf, &shape());
    assert_eq!(decode_shape(&mut Reader(&buf)).unwrap(), shape());
    let mut many = vec![17u8];
    many.extend(std::iter::repeat_n([1u8, b'a'], 17).flatten());
    assert!(decode_shape(&mut Reader(&many)).unwrap_err().contains("17 commands"));
    let mut long = vec![1u8, 13];
    long.extend([b'a'; 13]);
    assert!(decode_shape(&mut Reader(&long)).unwrap_err().contains("13 bytes"));
    let big = UnknownShape { commands: vec!["x".repeat(40); 40], ..shape() };
    let mut buf = Vec::new();
    encode_shape(&mut buf, &big);
    let back = decode_shape(&mut Reader(&buf)).unwrap();
    assert_eq!(back.commands, vec!["x".repeat(SHAPE_COMMAND_LEN); crate::net::behavior::HANDSHAKE_CAPTURE_MAX]);
}

#[test]
fn reading_the_file_obeys_the_bound_and_expiry() {
    let bytes = full_book().encode(MAGIC);
    let small = CrawlBook::decode(&bytes, MAGIC, NOW + 6, BookParams { max_entries: 2, ..BookParams::default() }).unwrap();
    assert_eq!(small.len(), 2);
    assert!(small.get(&CrawlAddr::Peer(v4(0))).is_some() && small.get(&CrawlAddr::Peer(v4(2))).is_some(), "the most recently used stay");
    let later = CrawlBook::decode(&bytes, MAGIC, NOW + DROP_AFTER_SECS + 5, BookParams::default()).unwrap();
    // The failing address and the never-dialled ones go; the dialable
    // ones that are not failing stay.
    assert!(later.get(&CrawlAddr::Peer(v4(1))).is_none());
    assert!(later.rows().all(|(a, _)| a.dialable()));
}

#[cfg(unix)]
#[test]
fn the_file_takes_the_directorys_permissions() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CRAWL_FILE);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    full_book().save(&path, MAGIC).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
}

#[test]
fn seeds_skip_the_answer_rules_but_not_the_address_rules() {
    let mut book = CrawlBook::default();
    for i in 1..=20 {
        assert!(book.seed(PeerAddr::Socket(format!("5.6.7.{i}:8333").parse().unwrap()), 0, NOW));
    }
    assert_eq!(book.len(), 20, "no /24 bound on seeds");
    assert!(!book.seed(PeerAddr::Socket("10.0.0.1:8333".parse().unwrap()), 0, NOW));
    let e = book.get(&CrawlAddr::Peer(PeerAddr::Socket("5.6.7.1:8333".parse().unwrap()))).unwrap();
    assert_eq!(e.source_count(), 1);
}

#[test]
fn a_mapped_seed_is_the_entry_its_gossip_names() {
    let mut book = CrawlBook::default();
    assert!(book.seed(PeerAddr::Socket("[::ffff:5.6.7.1]:8333".parse().unwrap()), 0, NOW));
    let r = book.admit(&source(1), &[ip_entry("5.6.7.1", 8333)], NOW);
    assert_eq!((r.admitted, r.named_again), (0, 1));
    assert_eq!(book.len(), 1);
    let e = book.get(&CrawlAddr::Peer(PeerAddr::Socket("5.6.7.1:8333".parse().unwrap()))).unwrap();
    assert_eq!(e.source_count(), 2);
}

#[test]
fn a_session_open_is_never_evicted_or_expired() {
    // Eviction: the least recently used entry has a session open.
    let a = v4(0);
    let mut book = CrawlBook::new(BookParams { max_entries: 2, ..BookParams::default() });
    book.seed(a.clone(), 0, NOW);
    let session = book.mark_dialling(&a, NOW);
    book.admit(&source(1), &v4_answer(1, 1), NOW + 1);
    book.admit(&source(1), &v4_answer(2, 1), NOW + 2);
    assert_eq!(book.len(), 2);
    assert!(book.get(&CrawlAddr::Peer(v4(1))).is_none(), "the oldest without a session went");
    book.record_result(&a, session, SessionKind::Discovery, v2_ok(NOW + 3), NOW + 3);
    assert_eq!(book.get(&CrawlAddr::Peer(a.clone())).unwrap().last_reachable(), Some(NOW + 3), "its result counts");

    // Expiry: failing and unnamed for 30 days, with a session open.
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    book.record_result(&a, None, SessionKind::Discovery, down(), NOW);
    let later = NOW + DROP_AFTER_SECS + DAY;
    let session = book.mark_dialling(&a, later);
    book.expire(later);
    assert!(book.get(&CrawlAddr::Peer(a.clone())).is_some(), "not expired mid-session");
    book.record_result(&a, session, SessionKind::Discovery, v2_ok(later), later);
    assert_eq!(book.get(&CrawlAddr::Peer(a)).unwrap().last_reachable(), Some(later));
}

#[test]
fn the_prefix_caps_count_ips_not_ports() {
    let mut book = CrawlBook::default();
    let ports: Vec<AddrV2Message> = (0..8).map(|p| ip_entry("5.6.7.1", 8333 + p)).collect();
    assert_eq!(book.admit(&source(1), &ports, NOW).admitted, 8);
    let others: Vec<AddrV2Message> = (2..=8).map(|i| ip_entry(&format!("5.6.7.{i}"), 8333)).collect();
    let r = book.admit(&source(1), &others, NOW);
    assert_eq!((r.admitted, r.ipv4_prefix_full), (7, 0), "one host on eight ports takes one slot");
    assert_eq!(book.admit(&source(1), &[ip_entry("5.6.7.9", 8333)], NOW).ipv4_prefix_full, 1);

    let r = book.admit(&source(1), &[ip_entry("2a01:4f8:1:2::1", 8333), ip_entry("2a01:4f8:1:2::1", 8334)], NOW);
    assert_eq!(r.admitted, 2, "another port of the /64's one IP");
    assert_eq!(book.admit(&source(1), &[ip_entry("2a01:4f8:1:2::2", 8333)], NOW).ipv6_prefix_full, 1);

    // The slot frees when the IP's last entry goes.
    let mut book = CrawlBook::new(BookParams { max_entries: 2, ipv4_per_24: 1, ..BookParams::default() });
    book.admit(&source(1), &[ip_entry("5.6.7.1", 8333)], NOW);
    book.admit(&source(1), &[ip_entry("5.6.7.1", 8334)], NOW + 1);
    book.admit(&source(1), &[ip_entry("9.9.9.1", 8333)], NOW + 2);
    assert_eq!(book.len(), 2);
    assert_eq!(book.admit(&source(1), &[ip_entry("5.6.7.2", 8333)], NOW + 3).ipv4_prefix_full, 1, "5.6.7.1:8334 holds it");
    book.admit(&source(1), &[ip_entry("9.9.10.1", 8333)], NOW + 4);
    assert!(book.get(&CrawlAddr::Peer(PeerAddr::Socket("5.6.7.1:8334".parse().unwrap()))).is_none());
    assert_eq!(book.admit(&source(1), &[ip_entry("5.6.7.2", 8333)], NOW + 5).admitted, 1);
}

#[test]
fn seeding_again_does_not_hold_off_the_drop() {
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let mut t = NOW;
    while t < NOW + 31 * DAY {
        // Seeded again every day until day 29: no source names it.
        if t < NOW + 29 * DAY && (t - NOW).is_multiple_of(DAY) {
            book.seed(a.clone(), 0, t);
        }
        if due_kind(&book, &a, t).is_some() {
            book.record_result(&a, None, SessionKind::Discovery, down(), t);
        }
        t += HOUR;
    }
    assert!(book.get(&CrawlAddr::Peer(a)).is_none(), "dropped after 30 days of failures");
}

#[test]
fn an_abandoned_session_ages_out() {
    // A session that never reports (its task cancelled) does not pin the
    // address: after ABANDONED_AFTER_SECS it is due, evictable and
    // droppable again.
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    assert!(book.mark_dialling(&a, NOW).is_some());
    let gone = NOW + ABANDONED_AFTER_SECS;
    assert_eq!(due_kind(&book, &a, gone - 1), None);
    assert!(book.mark_dialling(&a, gone - 1).is_none(), "still open");
    assert!(due_kind(&book, &a, gone).is_some(), "abandoned: due again");
    assert!(book.mark_dialling(&a, gone).is_some(), "and can be dialled again");

    // Eviction no longer skips it.
    let mut book = CrawlBook::new(BookParams { max_entries: 1, ..BookParams::default() });
    book.seed(a.clone(), 0, NOW);
    assert!(book.mark_dialling(&a, NOW).is_some());
    let r = book.admit(&source(1), &v4_answer(2, 1), gone);
    assert_eq!(r.admitted, 1, "{r:?}");
    assert!(book.get(&CrawlAddr::Peer(a)).is_none(), "the abandoned entry went");
}

#[test]
fn an_entry_evicted_at_once_is_not_reported_kept() {
    // Full, and every older entry has a session open: the new entry is the
    // one that goes, and neither admit nor seed says it was kept.
    let a = v4(0);
    let mut book = CrawlBook::new(BookParams { max_entries: 1, ..BookParams::default() });
    book.seed(a.clone(), 0, NOW);
    assert!(book.mark_dialling(&a, NOW).is_some());
    let r = book.admit(&source(1), &v4_answer(1, 1), NOW + 1);
    assert_eq!((r.admitted, r.not_kept), (0, 1));
    assert!(!book.seed(v4(2), 0, NOW + 1));
    assert_eq!(book.len(), 1);
    assert!(book.get(&CrawlAddr::Peer(a)).is_some());
}

#[test]
fn a_late_result_from_an_abandoned_session_is_ignored() {
    // Session A is abandoned, B opens; A reporting late neither clears
    // B's marker (a third session could open) nor counts as the outcome.
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let first = book.mark_dialling(&a, NOW);
    let later = NOW + ABANDONED_AFTER_SECS;
    let second = book.mark_dialling(&a, later);
    assert!(second.is_some() && second != first);
    assert!(!book.record_result(&a, first, SessionKind::Discovery, down(), later + 1), "stale");
    assert!(book.mark_dialling(&a, later + 1).is_none(), "B is still open");
    assert_eq!(book.get(&CrawlAddr::Peer(a.clone())).unwrap().last_reachable(), None);
    assert!(book.record_result(&a, second, SessionKind::Discovery, v2_ok(later + 2), later + 2));
    assert_eq!(book.get(&CrawlAddr::Peer(a.clone())).unwrap().last_reachable(), Some(later + 2));
    // And once B has reported, A's result is stale too.
    assert!(!book.record_result(&a, first, SessionKind::Discovery, down(), later + 3));
    assert_eq!(book.get(&CrawlAddr::Peer(a)).unwrap().last_reachable(), Some(later + 2));
}

#[test]
fn two_sessions_in_one_second_have_different_tokens() {
    // Discovery then a v1 recheck in the same second is the normal flow: a
    // duplicated report of the first must not match the second.
    let a = v4(1);
    let mut book = CrawlBook::default();
    book.seed(a.clone(), 0, NOW);
    let first = book.mark_dialling(&a, NOW);
    assert!(book.record_result(&a, first, SessionKind::Discovery, v2_ok(NOW), NOW));
    let second = book.mark_dialling(&a, NOW);
    assert!(second.is_some() && second != first);
    assert!(!book.record_result(&a, first, SessionKind::Discovery, v2_ok(NOW), NOW), "duplicate");
    assert!(book.mark_dialling(&a, NOW).is_none(), "the second is still open");
}

/// On regtest the book admits loopback and private addresses, so a crawl
/// can walk nodes on one host; on every other network it refuses them, as
/// [`BookParams::default`] does.
#[test]
fn local_addresses_are_admitted_on_regtest_only() {
    use bitcoin::Network as Net;
    let local = ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"];
    let answer: Vec<AddrV2Message> = local.iter().map(|ip| ip_entry(ip, 18444)).collect();
    for network in [Net::Bitcoin, Net::Testnet4, Net::Signet] {
        let params = BookParams::for_network(network);
        assert!(!params.allow_local, "{network}");
        let mut book = CrawlBook::new(params);
        let r = book.admit(&source(1), &answer, NOW);
        assert_eq!((r.admitted, r.not_public), (0, local.len()), "{network}: {r:?}");
        assert!(!book.seed(PeerAddr::Socket("127.0.0.1:18444".parse().unwrap()), 0, NOW), "{network}");
        assert!(book.is_empty(), "{network}");
    }
    let mut book = CrawlBook::new(BookParams::for_network(Net::Regtest));
    let r = book.admit(&source(1), &answer, NOW);
    assert_eq!(r.admitted, local.len(), "{r:?}");
    assert!(book.seed(PeerAddr::Socket("127.0.0.2:18444".parse().unwrap()), 0, NOW));
    // An address that names no host stays out even there.
    let r = book.admit(&source(1), &[ip_entry("0.0.0.0", 18444), ip_entry("::", 18444)], NOW);
    assert_eq!((r.admitted, r.not_public), (0, 2), "{r:?}");
}

/// The engine's filter leaves the addresses it cannot dial out of the
/// list before the limit is applied, so they cannot crowd out the rest.
#[test]
fn next_due_where_applies_the_filter_before_the_limit() {
    let mut book = CrawlBook::default();
    for i in 0..10 {
        assert!(book.seed(v4(i), 0, NOW));
    }
    let onion = PeerAddr::Onion { host: "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion".into(), port: 8333 };
    assert!(book.seed(onion.clone(), 0, NOW + 1));
    assert!(!book.next_due(NOW + 2, 3).iter().any(|(a, _)| *a == onion), "the onion is due last");
    let due = book.next_due_where(NOW + 2, 3, PeerAddr::is_onion);
    assert_eq!(due, vec![(onion, SessionKind::Discovery)]);
}
