//! The crawl's report: the aggregate over a constructed book, and the rows.

use super::*;
use crate::net::crawlbook::{Attempt, SessionKind, SessionResult};
use crate::net::fingerprint::Confidence;
use crate::net::peer::PeerAddr;
use crate::net::survey::{Probe, ProbeOutcome, ProbeResults, Verdict};
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const NOW: u64 = 1_790_000_000;
const HOUR: u64 = 60 * 60;
const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

fn v4(i: u8) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((Ipv4Addr::new(23, 1, i, 7), 8333)))
}

fn v6() -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((
        "2a01:4f8::1".parse::<Ipv6Addr>().unwrap(),
        8333,
    )))
}

fn onion() -> PeerAddr {
    PeerAddr::Onion {
        host: ONION.to_string(),
        port: 8333,
    }
}

fn observation(fingerprint: Fingerprint, v2: bool) -> Observation {
    let mut probes = ProbeResults::default();
    probes.set(Probe::Ping, ProbeOutcome::Answered(42));
    Observation {
        at: NOW,
        fingerprint,
        user_agent: "/Satoshi:32.1.0/".to_string(),
        protocol_version: 70016,
        services: 0xc09,
        asn: Some(64496),
        probes,
        v2,
        height: 900_000,
        our_height: 900_002,
        chain_check: None,
        shape: None,
        verdict: Default::default(),
        clock_offset_secs: Some(-3),
        handshake_rtt_ms: Some(120),
        getaddr: Some(GetaddrResult::Answered {
            entries: 812,
            delay_ms: 21_000,
        }),
    }
}

fn result(v2: Attempt, v1: Attempt, fp: Option<Fingerprint>) -> SessionResult {
    let over_v2 = v2 == Attempt::Ok;
    SessionResult {
        v2,
        v1,
        observation: fp.map(|f| observation(f, over_v2)),
    }
}

fn core() -> Fingerprint {
    Fingerprint::Known(Family::Core, Confidence::High)
}

/// A book with one address of every transport class, an address reached
/// before the liveness window, one never reached, and an I2P and a CJDNS
/// address learned from an answer:
///
/// | Address | Transport | Family |
/// |---|---|---|
/// | IPv4 `a` | v2 and v1 | core |
/// | IPv4 `b` | v1 only | btcd |
/// | IPv4 `c` | v2 only | satd, claiming core (a mismatch) |
/// | IPv6 `d` | v2, v1 not checked | unknown |
/// | onion `e` | v1, v2 never tried (not advertised) | core |
/// | IPv4 `f` | reached 3 h ago: not reachable | |
/// | IPv4 `g` | never reached | |
fn book() -> CrawlBook {
    let mut book = CrawlBook::new(crate::net::crawlbook::BookParams::for_network(
        bitcoin::Network::Bitcoin,
    ));
    let p2p_v2 = (ServiceFlags::NETWORK | ServiceFlags::P2P_V2).to_u64();
    for (addr, services) in [
        (v4(1), p2p_v2),
        (v4(2), 1),
        (v4(3), 1),
        (v6(), 1),
        (onion(), 1),
        (v4(4), 1),
        (v4(5), 1),
    ] {
        assert!(book.seed(addr, services, NOW - 4 * HOUR));
    }
    let d = SessionKind::Discovery;
    book.record_result(
        &v4(1),
        None,
        d,
        result(Attempt::Ok, Attempt::NotTried, Some(core())),
        NOW,
    );
    book.record_result(
        &v4(1),
        None,
        SessionKind::V1Recheck,
        result(Attempt::NotTried, Attempt::Ok, None),
        NOW,
    );
    let btcd = Fingerprint::Known(Family::Btcd, Confidence::High);
    book.record_result(
        &v4(2),
        None,
        d,
        result(Attempt::Failed, Attempt::Ok, Some(btcd)),
        NOW,
    );
    let mismatch = Fingerprint::Mismatch {
        claimed: Family::Core,
        observed: Family::Satd,
    };
    book.record_result(
        &v4(3),
        None,
        d,
        result(Attempt::Ok, Attempt::NotTried, Some(mismatch)),
        NOW,
    );
    book.record_result(
        &v4(3),
        None,
        SessionKind::V1Recheck,
        result(Attempt::NotTried, Attempt::Failed, None),
        NOW,
    );
    book.record_result(
        &v6(),
        None,
        d,
        result(Attempt::Ok, Attempt::NotTried, Some(Fingerprint::Unknown)),
        NOW,
    );
    book.record_result(
        &onion(),
        None,
        d,
        result(Attempt::NotTried, Attempt::Ok, Some(core())),
        NOW,
    );
    book.record_result(
        &v4(4),
        None,
        d,
        result(Attempt::Ok, Attempt::NotTried, Some(core())),
        NOW - 3 * HOUR,
    );
    book.record_result(
        &v4(5),
        None,
        d,
        result(Attempt::Failed, Attempt::Failed, None),
        NOW,
    );
    let learned = [
        AddrV2Message {
            time: NOW as u32,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::I2p([7; 32]),
            port: 0,
        },
        AddrV2Message {
            time: NOW as u32,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            port: 8333,
        },
    ];
    let r = book.admit(&v4(1), &learned, NOW);
    assert_eq!(r.admitted, 2, "{r:?}");
    book
}

fn family(agg: &Aggregate, f: Family) -> usize {
    agg.families[Family::ALL.iter().position(|x| *x == f).unwrap()]
}

/// The aggregate over the constructed book, exactly: the learned counts
/// over the whole book, everything else over the reachable set only.
#[test]
fn the_aggregate_counts_the_book_exactly() {
    let book = book();
    let agg = aggregate(&book, NOW);
    assert_eq!(agg.entries, 9);
    assert_eq!(
        agg.learned,
        [5, 1, 1, 1, 1],
        "ipv4, ipv6, onion, i2p, cjdns"
    );
    assert_eq!(agg.ever_reached, [4, 1, 1, 0, 0]);
    assert_eq!(
        agg.reachable,
        [3, 1, 1],
        "f's handshake is past the liveness window"
    );
    assert_eq!(agg.reachable_total(), 5);
    assert_eq!(
        agg.transport,
        [1, 1, 1, 1, 1],
        "v2 and v1, v1 only, v1 v2 untried, v2 only, v2 unconfirmed"
    );
    assert_eq!(
        agg.transport.iter().sum::<usize>(),
        agg.reachable_total(),
        "every reachable address in one class"
    );
    assert_eq!(agg.v2_advertised, 1);
    assert_eq!(family(&agg, Family::Core), 2);
    assert_eq!(family(&agg, Family::Btcd), 1);
    assert_eq!(
        family(&agg, Family::Satd),
        1,
        "a mismatch counts by the family observed"
    );
    assert_eq!(agg.unknown, 1);
    assert_eq!(agg.mismatches, 1);
    assert_eq!(
        agg.families.iter().sum::<usize>() + agg.unknown,
        agg.reachable_total()
    );

    // A day on, nothing is reachable and the learned counts stand.
    let later = aggregate(&book, NOW + 24 * HOUR);
    assert_eq!(later.reachable, [0, 0, 0]);
    assert_eq!(later.transport, [0; 5]);
    assert_eq!(later.learned, agg.learned);
}

/// A v1 handshake is "v1 only" only when a BIP 324 attempt failed; with no
/// v2 attempt at all (the node advertised none) it is a class of its own.
#[test]
fn v1_only_means_v2_was_tried_and_failed() {
    let mut book = CrawlBook::new(crate::net::crawlbook::BookParams::for_network(
        bitcoin::Network::Bitcoin,
    ));
    for a in [v4(1), v4(2)] {
        assert!(book.seed(a, 1, NOW - HOUR));
    }
    let d = SessionKind::Discovery;
    book.record_result(
        &v4(1),
        None,
        d,
        result(Attempt::Failed, Attempt::Ok, Some(core())),
        NOW,
    );
    book.record_result(
        &v4(2),
        None,
        d,
        result(Attempt::NotTried, Attempt::Ok, Some(core())),
        NOW,
    );
    let class = |a: PeerAddr| {
        Transport::of(
            book.get(&crate::net::crawlbook::CrawlAddr::Peer(a))
                .unwrap(),
        )
    };
    assert_eq!(class(v4(1)), Transport::V1Only);
    assert_eq!(class(v4(2)), Transport::V1V2Untried);
    assert_eq!(Transport::V1V2Untried.name(), "v1_v2_untried");
}

/// The JSON carries the aggregate, shares of the reachable addresses, and
/// no address or user agent at all.
#[test]
fn the_aggregate_json_is_counts_only() {
    let book = book();
    let json = aggregate_json(&aggregate(&book, NOW), 250_000);
    assert_eq!(json["book"]["entries"], 9);
    assert_eq!(json["book"]["max_entries"], 250_000);
    assert_eq!(json["book"]["learned"]["i2p"], 1);
    assert_eq!(json["book"]["learned"]["cjdns"], 1);
    assert_eq!(json["book"]["ever_reached"]["ipv4"], 4);
    assert_eq!(
        json["reachable"],
        serde_json::json!({ "total": 5, "ipv4": 3, "ipv6": 1, "onion": 1 })
    );
    assert!(
        json["reachable"].get("i2p").is_none(),
        "I2P and CJDNS are never reachable: never dialled"
    );
    assert_eq!(
        json["transport"]["v2_only"],
        serde_json::json!({ "count": 1, "share": 0.2 })
    );
    assert_eq!(json["transport"]["v1_only"]["count"], 1);
    assert_eq!(json["transport"]["v1_v2_untried"]["count"], 1);
    assert_eq!(json["transport"]["v2_and_v1"]["count"], 1);
    assert_eq!(json["transport"]["v2_unconfirmed"]["count"], 1);
    assert_eq!(json["transport"]["v2_advertised"]["count"], 1);
    assert_eq!(
        json["families"]["core"],
        serde_json::json!({ "count": 2, "share": 0.4 })
    );
    assert_eq!(json["families"]["unknown"]["count"], 1);
    assert_eq!(json["mismatches"], 1);

    let text = json.to_string();
    for (addr, _) in book.rows() {
        let a = addr_text(addr);
        let host = a
            .rsplit_once(':')
            .map(|(h, _)| h.trim_matches(['[', ']']))
            .unwrap_or(&a);
        assert!(!text.contains(host), "{host} in {text}");
    }
    for needle in [
        "23.1.", "2a01", "fc00", ".b32.i2p", "pg6mm", "Satoshi", "/satd:",
    ] {
        assert!(!text.contains(needle), "{needle} in {text}");
    }
}

/// An empty book: every count zero, every share zero (not NaN), every key
/// present.
#[test]
fn an_empty_book_reports_zeros() {
    let json = aggregate_json(&aggregate(&CrawlBook::default(), NOW), 250_000);
    assert_eq!(json["book"]["entries"], 0);
    assert_eq!(json["reachable"]["total"], 0);
    for t in Transport::ALL {
        assert_eq!(
            json["transport"][t.name()],
            serde_json::json!({ "count": 0, "share": 0.0 }),
            "{}",
            t.name()
        );
    }
    for f in Family::ALL {
        assert_eq!(json["families"][f.name()]["count"], 0);
        assert_eq!(
            json["claimed"][f.name()],
            serde_json::json!({ "count": 0, "share": 0.0 })
        );
        assert_eq!(
            json["fake"][f.name()],
            serde_json::json!({ "count": 0, "share": 0.0 })
        );
    }
    assert_eq!(json["families"]["unknown"]["share"], 0.0);
    assert_eq!(
        json["closed_early"],
        serde_json::json!({ "count": 0, "share": 0.0 })
    );
    assert_eq!(
        nodes_json(&CrawlBook::default(), NOW, true),
        serde_json::json!([])
    );
}

/// The rows: one per address, the most recently reached first; without
/// `verbose` the address, its network, whether it is reachable, its last
/// handshake, its transport class and its family; with `verbose` every
/// field, the observation included.
#[test]
fn rows_without_and_with_verbose() {
    let book = book();
    let rows = nodes_json(&book, NOW, false);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 9);
    let keys = |r: &serde_json::Value| {
        r.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    let short: BTreeSet<String> = [
        "addr",
        "network",
        "reachable",
        "last_success",
        "transport",
        "family",
        "fingerprint",
    ]
    .map(String::from)
    .into();
    for r in rows {
        assert_eq!(keys(r), short, "{r}");
    }
    let row = |rows: &[serde_json::Value], addr: &str| {
        rows.iter().find(|r| r["addr"] == addr).cloned().unwrap()
    };
    let a = row(rows, "23.1.1.7:8333");
    assert_eq!(a["network"], "ipv4");
    assert_eq!(
        (
            a["reachable"].clone(),
            a["transport"].clone(),
            a["family"].clone()
        ),
        (true.into(), "v2_and_v1".into(), "core".into())
    );
    assert_eq!(row(rows, "23.1.3.7:8333")["transport"], "v2_only");
    assert_eq!(
        row(rows, "[2a01:4f8::1]:8333")["transport"],
        "v2_unconfirmed"
    );
    assert_eq!(row(rows, &format!("{ONION}:8333"))["network"], "onion");
    let f = row(rows, "23.1.4.7:8333");
    assert_eq!(
        (f["reachable"].clone(), f["last_success"].clone()),
        (false.into(), (NOW - 3 * HOUR).into())
    );
    let g = row(rows, "23.1.5.7:8333");
    assert_eq!(
        (g["transport"].clone(), g["family"].clone()),
        (serde_json::Value::Null, serde_json::Value::Null)
    );
    let i2p = format!(
        "{}.b32.i2p:0",
        data_encoding::BASE32_NOPAD
            .encode(&[7; 32])
            .to_ascii_lowercase()
    );
    let r = row(rows, &i2p);
    assert_eq!(
        (r["network"].clone(), r["reachable"].clone()),
        ("i2p".into(), false.into())
    );
    assert_eq!(row(rows, "[fc00::1]:8333")["network"], "cjdns");
    // The most recently reached first; never reached last.
    let order: Vec<Option<u64>> = rows.iter().map(|r| r["last_success"].as_u64()).collect();
    let mut sorted = order.clone();
    sorted.sort_by(|x, y| y.cmp(x));
    assert_eq!(order, sorted);

    let rows = nodes_json(&book, NOW, true);
    let rows = rows.as_array().unwrap();
    for r in rows {
        assert!(keys(r).is_superset(&short));
        for k in [
            "sources",
            "attempts",
            "failures",
            "retry_at",
            "v2_ok",
            "v1_ok",
            "v2_only",
            "observation",
            "in_flight",
        ] {
            assert!(r.get(k).is_some(), "{k} in {r}");
        }
    }
    let c = row(rows, "23.1.3.7:8333");
    assert_eq!(
        (c["v2_ok"].clone(), c["v1_ok"].clone(), c["v2_only"].clone()),
        (true.into(), false.into(), true.into())
    );
    let obs = &c["observation"];
    assert_eq!(obs["family"], "satd");
    assert_eq!(obs["claimed"], "core");
    assert_eq!(obs["mismatch"], true);
    assert_eq!(obs["subver"], "/Satoshi:32.1.0/");
    assert_eq!(obs["services"], "0000000000000c09");
    assert_eq!(obs["height_gap"], 2);
    assert_eq!(
        obs["getaddr"],
        serde_json::json!({ "result": "answered", "entries": 812, "delay_ms": 21_000 })
    );
    assert_eq!(
        obs["probes"]["ping"],
        serde_json::json!({ "result": "answered", "value": 42 })
    );
    let a = row(rows, "23.1.1.7:8333");
    assert_eq!(
        (a["v2_advertised"].clone(), a["sources"].clone()),
        (true.into(), 1.into()),
        "seeded only"
    );
    assert_eq!(
        row(rows, "23.1.5.7:8333")["observation"],
        serde_json::Value::Null
    );
}

/// The reachable addresses in exactly one of the family, claimed, fake,
/// closed-early and unknown tallies.
fn counted_once(agg: &Aggregate) -> usize {
    agg.families.iter().sum::<usize>()
        + agg.unknown
        + agg.claimed.iter().sum::<usize>()
        + agg.fake.iter().sum::<usize>()
        + agg.closed_early
}

/// An observation with `verdict`, over v1.
fn judged(fingerprint: Fingerprint, verdict: Verdict, user_agent: &str) -> SessionResult {
    let mut o = observation(fingerprint, false);
    o.verdict = verdict;
    o.user_agent = user_agent.to_string();
    SessionResult {
        v2: Attempt::Failed,
        v1: Attempt::Ok,
        observation: Some(o),
    }
}

/// A claimed family (no row matched; the user agent names it) is never
/// counted as observed or as unknown: `claimed` alone carries the family.
/// A fake session and a closed-early one are counted apart again, fake by
/// its claimed family: `unknown` is only what names no family, and each
/// reachable address is counted once. A closed-early address is still
/// reachable, by network and transport like any other. The rows say so
/// too: no `family`, and the fingerprint `core/claimed`, `fake/core` or
/// `closed-early`, the claim kept.
#[test]
fn a_claimed_family_is_never_counted_as_observed() {
    let mut book = CrawlBook::new(crate::net::crawlbook::BookParams::for_network(
        bitcoin::Network::Bitcoin,
    ));
    for addr in [v4(1), v4(2), v4(3), v4(4), v4(5), v4(6)] {
        assert!(book.seed(addr, 1, NOW - HOUR));
    }
    let d = SessionKind::Discovery;
    let claimed = Fingerprint::Known(Family::Core, Confidence::Claimed);
    book.record_result(
        &v4(1),
        None,
        d,
        result(Attempt::Failed, Attempt::Ok, Some(claimed)),
        NOW,
    );
    let low = Fingerprint::Known(Family::Btcd, Confidence::Low);
    book.record_result(
        &v4(2),
        None,
        d,
        result(Attempt::Failed, Attempt::Ok, Some(low)),
        NOW,
    );
    book.record_result(
        &v4(3),
        None,
        d,
        result(Attempt::Failed, Attempt::Ok, Some(Fingerprint::Unknown)),
        NOW,
    );
    book.record_result(
        &v4(4),
        None,
        d,
        judged(claimed, Verdict::Fake(Family::Core), "/Satoshi:25.0.0/"),
        NOW,
    );
    // A fake whose transcript a row matched is still fake, and no
    // mismatch.
    let mismatch = Fingerprint::Mismatch {
        claimed: Family::Core,
        observed: Family::Btcd,
    };
    book.record_result(
        &v4(5),
        None,
        d,
        judged(mismatch, Verdict::Fake(Family::Core), "/Satoshi:25.1.0/"),
        NOW,
    );
    book.record_result(
        &v4(6),
        None,
        d,
        judged(
            Fingerprint::Unknown,
            Verdict::ClosedEarly,
            "/Satoshi:28.1.0/",
        ),
        NOW,
    );
    let agg = aggregate(&book, NOW);
    assert_eq!(
        agg.reachable_total(),
        6,
        "a closed-early address is reachable"
    );
    assert_eq!(
        agg.transport[Transport::ALL
            .iter()
            .position(|t| *t == Transport::V1Only)
            .unwrap()],
        6
    );
    assert_eq!(
        family(&agg, Family::Core),
        0,
        "claimed is not observed, nor fake"
    );
    assert_eq!(
        family(&agg, Family::Btcd),
        1,
        "low is observed; a fake's row is not"
    );
    assert_eq!(agg.unknown, 1, "only the one that names no family");
    let of =
        |counts: &[usize], f: Family| counts[Family::ALL.iter().position(|x| *x == f).unwrap()];
    assert_eq!(of(&agg.claimed, Family::Core), 1);
    assert_eq!(
        agg.claimed.iter().sum::<usize>(),
        1,
        "the fakes are not claimed"
    );
    assert_eq!(of(&agg.fake, Family::Core), 2);
    assert_eq!(agg.fake.iter().sum::<usize>(), 2);
    assert_eq!(agg.closed_early, 1);
    assert_eq!(agg.mismatches, 0, "a fake is no mismatch");
    assert_eq!(
        counted_once(&agg),
        agg.reachable_total(),
        "each reachable address in exactly one tally"
    );

    let json = aggregate_json(&agg, 250_000);
    assert_eq!(json["families"]["core"]["count"], 0);
    assert_eq!(json["families"]["unknown"]["count"], 1);
    assert_eq!(
        json["claimed"]["core"],
        serde_json::json!({ "count": 1, "share": 1.0 / 6.0 })
    );
    for f in Family::ALL.iter().filter(|f| **f != Family::Core) {
        assert_eq!(json["claimed"][f.name()]["count"], 0, "{}", f.name());
        assert_eq!(json["fake"][f.name()]["count"], 0, "{}", f.name());
    }
    assert!(json["claimed"].get("unknown").is_none());
    assert_eq!(
        json["fake"]["core"],
        serde_json::json!({ "count": 2, "share": 2.0 / 6.0 }),
        "shares are of the reachable"
    );
    assert!(json["fake"].get("unknown").is_none());
    assert_eq!(
        json["closed_early"],
        serde_json::json!({ "count": 1, "share": 1.0 / 6.0 })
    );
    assert!(!json.to_string().contains("Satoshi"), "counts only");

    let rows = nodes_json(&book, NOW, true);
    let rows = rows.as_array().unwrap();
    let at = |i: u8| {
        rows.iter()
            .find(|r| r["addr"] == format!("23.1.{i}.7:8333"))
            .unwrap()
    };
    for i in [4, 5] {
        let fake = at(i);
        assert_eq!(fake["fingerprint"], "fake/core", "{fake}");
        assert_eq!(fake["family"], serde_json::Value::Null);
        assert_eq!(fake["observation"]["fingerprint"], "fake/core");
        assert_eq!(fake["observation"]["family"], serde_json::Value::Null);
        assert_eq!(fake["observation"]["claimed"], "core");
        assert_eq!(fake["observation"]["mismatch"], false);
    }
    let early = at(6);
    assert_eq!(early["fingerprint"], "closed-early", "{early}");
    assert_eq!(
        (early["reachable"].clone(), early["transport"].clone()),
        (true.into(), "v1_only".into())
    );
    assert_eq!(early["observation"]["fingerprint"], "closed-early");
    assert_eq!(
        early["observation"]["claimed"], "core",
        "the user agent's claim is kept"
    );
    assert_eq!(early["observation"]["subver"], "/Satoshi:28.1.0/");
    assert_eq!(early["observation"]["version"], 70016);
    let short = nodes_json(&book, NOW, false);
    let short = short.as_array().unwrap();
    assert!(short.iter().any(|r| r["fingerprint"] == "closed-early"));
    assert_eq!(
        short
            .iter()
            .filter(|r| r["fingerprint"] == "fake/core")
            .count(),
        2
    );

    let row = at(1);
    assert_eq!(row["family"], serde_json::Value::Null);
    assert_eq!(row["fingerprint"], "core/claimed");
    assert_eq!(row["observation"]["family"], serde_json::Value::Null);
    assert_eq!(row["observation"]["claimed"], "core");
    assert_eq!(row["observation"]["mismatch"], false);
}
