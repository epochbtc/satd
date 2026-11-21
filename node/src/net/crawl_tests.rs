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
