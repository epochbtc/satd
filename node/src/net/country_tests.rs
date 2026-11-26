//! The country file: lookups in a written MaxMind DB file, the totals and
//! their fold, and the committed fixture.

use super::testing::{FIXTURE, mmdb};
use super::*;
use std::net::{Ipv4Addr, SocketAddr};

fn map() -> CountryMap {
    CountryMap::from_bytes(mmdb(FIXTURE)).expect("the writer's file reads")
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((Ipv4Addr::new(a, b, c, d), 8333)))
}

fn onion() -> PeerAddr {
    PeerAddr::Onion {
        host: "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion".to_string(),
        port: 8333,
    }
}

/// The file's networks give their countries, a lowercase code read in
/// uppercase; an IPv4-mapped IPv6 address is its IPv4 address; an address
/// outside every network, and one in a network whose record has no country,
/// have none.
#[test]
fn a_lookup_gives_the_iso_code_or_none() {
    let m = map();
    assert_eq!(m.database_type(), "satd-test-Country");
    assert_eq!(m.lookup(ip("192.0.2.1")).as_deref(), Some("DE"));
    assert_eq!(m.lookup(ip("192.0.2.200")).as_deref(), Some("JP"));
    assert_eq!(m.lookup(ip("198.51.100.9")).as_deref(), Some("BR"));
    assert_eq!(m.lookup(ip("::ffff:192.0.2.1")).as_deref(), Some("DE"));
    assert_eq!(m.lookup(ip("2001:db8::1")).as_deref(), Some("NZ"));
    assert_eq!(m.lookup(ip("2001:db8:8000::1")), None);
    assert_eq!(
        m.lookup(ip("203.0.113.5")),
        None,
        "a record with no country"
    );
    assert_eq!(m.lookup(ip("203.0.113.200")), None, "no record");
    assert_eq!(m.lookup(ip("127.0.0.1")), None);
}

/// A code that is not two letters is no country: a file cannot make a key
/// that reads as `other`, `unknown` or a network.
#[test]
fn a_code_that_is_not_two_letters_is_unknown() {
    let m = CountryMap::from_bytes(mmdb(&[
        ("192.0.2.0/26", Some("other")),
        ("192.0.2.64/26", Some("D1")),
        ("192.0.2.128/26", Some("")),
        ("192.0.2.192/26", Some("fr")),
    ]))
    .unwrap();
    for host in [1, 65, 129] {
        assert_eq!(m.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))), None);
    }
    assert_eq!(
        m.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 193)))
            .as_deref(),
        Some("FR")
    );
}

/// Each node's key: its country, `unknown` for an IP the file has no
/// country for, `onion` for an onion.
#[test]
fn the_key_of_a_node() {
    let m = map();
    assert_eq!(m.key_of(&v4(192, 0, 2, 1)), "DE");
    assert_eq!(m.key_of(&v4(203, 0, 113, 200)), UNKNOWN);
    assert_eq!(m.key_of(&v4(203, 0, 113, 5)), UNKNOWN);
    assert_eq!(m.key_of(&onion()), "onion");
}

/// The totals: a country under the minimum is folded into `other`, one at
/// it is kept; `unknown` and `onion` are never folded however few; the
/// three are present at zero.
#[test]
fn the_totals_fold_a_country_below_the_minimum_into_other() {
    let m = map();
    let mut nodes = Vec::new();
    for i in 0..3 {
        nodes.push(v4(192, 0, 2, i + 1)); // DE
    }
    for i in 0..2 {
        nodes.push(v4(192, 0, 2, 129 + i)); // JP
    }
    nodes.push(v4(198, 51, 100, 1)); // BR
    nodes.push(v4(203, 0, 113, 200)); // unknown
    nodes.push(onion());
    let t = totals(&nodes, &m, 3);
    let want: BTreeMap<String, usize> = [("DE", 3), ("other", 3), ("unknown", 1), ("onion", 1)]
        .into_iter()
        .map(|(k, n)| (k.to_string(), n))
        .collect();
    assert_eq!(t, want);
    assert_eq!(t.values().sum::<usize>(), nodes.len(), "every node once");

    let t = totals(&nodes, &m, 1);
    assert_eq!(t["JP"], 2, "nothing folded at a minimum of one");
    assert_eq!(t["BR"], 1);
    assert_eq!(t["other"], 0);

    let empty = totals(std::iter::empty(), &m, 10);
    assert_eq!(
        empty.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["onion", "other", "unknown"]
    );
    assert!(empty.values().all(|n| *n == 0));
}

/// A file that is not a MaxMind DB, a truncated one and a missing one are
/// refused, each with an error naming the file.
#[test]
fn a_bad_country_file_is_refused() {
    assert!(CountryMap::from_bytes(b"not a database".to_vec()).is_err());
    assert!(CountryMap::from_bytes(Vec::new()).is_err());
    let good = mmdb(FIXTURE);
    assert!(CountryMap::from_bytes(good[..good.len() - 20].to_vec()).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.mmdb");
    std::fs::write(&path, b"garbage").unwrap();
    let e = CountryMap::load(&path).unwrap_err();
    assert!(e.contains("garbage.mmdb") && e.contains("MaxMind"), "{e}");
    let e = CountryMap::load(&dir.path().join("missing.mmdb")).unwrap_err();
    assert!(e.contains("missing.mmdb"), "{e}");
}

/// The committed fixture the integration tests load is the writer's file
/// for [`FIXTURE`]. `SATD_WRITE_COUNTRY_FIXTURE=1` rewrites it.
#[test]
fn the_committed_fixture_is_the_writers_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../satd/tests/data/country-test.mmdb");
    let bytes = mmdb(FIXTURE);
    if std::env::var_os("SATD_WRITE_COUNTRY_FIXTURE").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(
        std::fs::read(&path).expect("the fixture is committed"),
        bytes,
        "rewrite it with SATD_WRITE_COUNTRY_FIXTURE=1"
    );
    assert_eq!(
        CountryMap::load(&path)
            .unwrap()
            .lookup(ip("192.0.2.1"))
            .as_deref(),
        Some("DE")
    );
}
