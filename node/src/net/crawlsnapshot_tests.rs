//! The crawl's snapshots: node IDs, the key file, the export's shape and
//! what it leaves out, the gzip framing, and the hourly files' schedule and
//! retention under an injected clock.

use super::*;
use crate::net::crawlbook::{Attempt, BookParams, GetaddrResult, Observation, SessionKind, SessionResult};
use crate::net::fingerprint::Confidence;
use crate::net::survey::ProbeResults;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// A day-aligned time, so UTC days and hours fall on round offsets.
const NOW: u64 = 20_717 * DAY;
const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
const MAINNET_PORT: u16 = 8333;

fn key() -> ExportKey {
    let mut k = [0u8; EXPORT_KEY_BYTES];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    ExportKey(k)
}

fn v4(i: u8, port: u16) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from((Ipv4Addr::new(23, 1, i, 7), port)))
}

fn v6() -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from(("2a01:4f8::1".parse::<Ipv6Addr>().unwrap(), MAINNET_PORT)))
}

fn onion() -> PeerAddr {
    PeerAddr::Onion { host: ONION.to_string(), port: MAINNET_PORT }
}

fn observation(asn: Option<u32>) -> Observation {
    Observation {
        at: NOW,
        fingerprint: Fingerprint::Known(Family::Core, Confidence::High),
        user_agent: "/Satoshi:32.1.0/".to_string(),
        protocol_version: 70016,
        services: 0xc09,
        asn,
        probes: ProbeResults::default(),
        v2: false,
        height: 900_000,
        our_height: 900_002,
        chain_check: None,
        shape: None,
        verdict: Default::default(),
        clock_offset_secs: Some(-3),
        handshake_rtt_ms: Some(120),
        getaddr: Some(GetaddrResult::Answered { entries: 812, delay_ms: 21_000 }),
    }
}

/// A mainnet book:
///
/// | Address | Port | ASN | Reachable |
/// |---|---|---|---|
/// | IPv4 `23.1.1.7` .. `23.1.3.7` | 8333 | 64496 | yes |
/// | IPv4 `23.1.4.7` | 8334 | 64497 | yes |
/// | IPv6 `2a01:4f8::1` | 8333 | none | yes |
/// | onion | 8333 | none | yes |
/// | IPv4 `23.1.5.7` | 8333 | 64496 | reached 3 h ago: no |
///
/// and an I2P and a CJDNS address learned from an answer.
fn book() -> CrawlBook {
    let mut book = CrawlBook::new(BookParams::for_network(bitcoin::Network::Bitcoin));
    let reached = [
        (v4(1, 8333), Some(64496)),
        (v4(2, 8333), Some(64496)),
        (v4(3, 8333), Some(64496)),
        (v4(4, 8334), Some(64497)),
        (v6(), None),
        (onion(), None),
    ];
    for (addr, asn) in reached.iter().cloned().chain([(v4(5, 8333), Some(64496))]) {
        assert!(book.seed(addr.clone(), ServiceFlags::NETWORK.to_u64(), NOW - 4 * HOUR));
        let at = if addr == v4(5, 8333) { NOW - 3 * HOUR } else { NOW };
        let result = SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(observation(asn)) };
        book.record_result(&addr, None, SessionKind::Discovery, result, at);
    }
    let learned = [
        AddrV2Message { time: NOW as u32, services: ServiceFlags::NETWORK, addr: AddrV2::I2p([7; 32]), port: 0 },
        AddrV2Message {
            time: NOW as u32,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            port: 8333,
        },
    ];
    assert_eq!(book.admit(&v4(1, 8333), &learned, NOW).admitted, 2);
    book
}

fn ctx() -> ExportContext<'static> {
    ExportContext { now: NOW, latest_height: 900_002, default_port: MAINNET_PORT, chain: "main" }
}

fn keyed(min_k: u32) -> Mode {
    Mode::Keyed { key: key(), min_k }
}

/// Every string (keys included) and every number in `v`.
fn leaves(v: &serde_json::Value, strings: &mut Vec<String>, numbers: &mut Vec<u64>) {
    match v {
        serde_json::Value::String(s) => strings.push(s.clone()),
        serde_json::Value::Number(n) => numbers.extend(n.as_u64()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| leaves(x, strings, numbers)),
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                strings.push(k.clone());
                leaves(x, strings, numbers);
            }
        }
        _ => {}
    }
}

const CLEARNET: [&str; 6] = ["23.1.1.7", "23.1.2.7", "23.1.3.7", "23.1.4.7", "23.1.5.7", "2a01:4f8"];

// ---- node IDs and the key ----

/// HMAC-SHA256 under the key 00 01 .. 1f of `ip:port`, truncated to 16
/// bytes, against values computed independently (Python's `hmac`). An
/// IPv4-mapped IPv6 address is its IPv4 address.
#[test]
fn node_id_known_answer() {
    let id = node_id(&key(), &"203.0.113.7:8333".parse().unwrap());
    assert_eq!(id, "adccb55f12feb805aab99ac4145f6109");
    assert_eq!(id.len(), NODE_ID_BYTES * 2);
    assert_eq!(node_id(&key(), &"[2001:db8::7]:8333".parse().unwrap()), "011f0155bfaba661bb93df463c4205b0");
    assert_eq!(node_id(&key(), &"[::ffff:203.0.113.7]:8333".parse().unwrap()), id);
    assert_eq!(id_message(&"[2001:db8::7]:8333".parse().unwrap()), "[2001:db8::7]:8333");
    assert_ne!(node_id(&key(), &"203.0.113.7:8334".parse().unwrap()), id, "the port is in the message");
    assert_ne!(node_id(&ExportKey([9; 32]), &"203.0.113.7:8333".parse().unwrap()), id, "and the key");
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The default key file is created by the first load, 32 bytes, mode
/// 0600, and read as it stands by every load after: the IDs stay the same.
#[test]
fn the_default_key_is_created_0600_once_and_reused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(EXPORT_KEY_FILE);
    let source = KeySource::Default(path.clone());
    let first = load_key(&source).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), EXPORT_KEY_BYTES);
    assert_eq!(bytes, first.0);
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    assert_ne!(first.0, [0; 32]);
    let again = load_key(&source).unwrap();
    assert_eq!(again, first, "reused, not regenerated");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|d| d.unwrap().file_name()).collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from(EXPORT_KEY_FILE)], "no temporary file left");
    // Replacing the file is the operator's rotation: the next load reads it.
    std::fs::write(&path, [5u8; 32]).unwrap();
    assert_eq!(load_key(&source).unwrap(), ExportKey([5; 32]));
}

/// Creating the key never replaces one that is there: a second creation
/// leaves the first key, so two first exports at once agree on one.
#[test]
fn creating_the_key_never_replaces_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(EXPORT_KEY_FILE);
    create_key_file(&path, &[1; 32]).unwrap();
    create_key_file(&path, &[2; 32]).unwrap();
    assert_eq!(read_key(&path).unwrap(), ExportKey([1; 32]));
    let other = dir.path().join("race.key");
    let keys: Vec<ExportKey> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8).map(|_| s.spawn(|| load_key(&KeySource::Default(other.clone())).unwrap())).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(keys.windows(2).all(|w| w[0] == w[1]), "every racing first export reads one key");
}

/// A `-crawlexportkeyfile` key is read and never created: missing, or not
/// 32 bytes, the export is refused.
#[test]
fn a_supplied_key_is_read_and_never_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("census.key");
    let source = KeySource::Supplied(path.clone());
    let err = load_key(&source).unwrap_err();
    assert!(err.contains("census.key"), "{err}");
    assert!(!path.exists(), "satd never creates a supplied key");
    std::fs::write(&path, [3u8; 31]).unwrap();
    assert!(load_key(&source).unwrap_err().contains("must be 32 bytes, not 31"));
    std::fs::write(&path, [3u8; 32]).unwrap();
    assert_eq!(load_key(&source).unwrap(), ExportKey([3; 32]));
    // A short default file is refused too, not replaced.
    let default = dir.path().join(EXPORT_KEY_FILE);
    std::fs::write(&default, [4u8; 8]).unwrap();
    assert!(load_key(&KeySource::Default(default.clone())).is_err());
    assert_eq!(std::fs::read(&default).unwrap(), vec![4u8; 8]);
}

// ---- the export ----

/// The export is shaped as a Bitnodes snapshot: `timestamp`,
/// `total_nodes`, `latest_height` and `nodes`, each node Bitnodes' thirteen
/// fields (the geographic ones, hostname, organization and connected-since
/// null) and then our `satd` object.
#[test]
fn the_export_is_bitnodes_shaped() {
    for mode in [keyed(1), Mode::Raw] {
        let out = export_json(&book(), &ctx(), &mode);
        assert_eq!(out["timestamp"], NOW);
        assert_eq!(out["latest_height"], 900_002);
        assert_eq!(out["total_nodes"], 6, "the past-window address is not reachable");
        let nodes = out["nodes"].as_object().unwrap();
        assert_eq!(nodes.len(), 6);
        for (k, n) in nodes {
            let a = n.as_array().unwrap_or_else(|| panic!("{k}: {n}"));
            assert_eq!(a.len(), 14, "{k}");
            assert_eq!(a[0], 70016, "protocol version");
            assert_eq!(a[1], "/Satoshi:32.1.0/", "user agent");
            assert_eq!(a[2], serde_json::Value::Null, "connected since");
            assert_eq!(a[3], 0xc09, "services");
            assert_eq!(a[4], 900_000, "height");
            for (i, what) in [(5, "hostname"), (6, "city"), (7, "country"), (8, "latitude"), (9, "longitude"), (10, "timezone"), (12, "organization")] {
                assert_eq!(a[i], serde_json::Value::Null, "{k}: {what}");
            }
            let satd = a[13].as_object().unwrap();
            for f in ["network", "port", "transport", "v2_advertised", "family", "fingerprint", "confidence", "claimed", "mismatch", "chain_check", "last_seen"] {
                assert!(satd.contains_key(f), "{k}: satd.{f}");
            }
            assert_eq!(satd["transport"], "v1_only");
            assert_eq!(satd["family"], "core");
            assert_eq!(satd["fingerprint"], "core/high");
            assert_eq!(satd["confidence"], "high");
            assert_eq!(satd["claimed"], "core", "the family its user agent names");
            assert_eq!(satd["last_seen"], NOW);
        }
        assert_eq!(out["satd"]["chain"], "main");
        assert_eq!(out["satd"]["liveness"], crate::net::crawlbook::DEFAULT_LIVENESS_SECS);
    }
}

/// A node only its user agent names the family of is exported with no
/// family: `confidence` says `claimed`, `claimed` names the family.
#[test]
fn a_claimed_family_is_exported_as_no_family() {
    let mut book = CrawlBook::new(BookParams::for_network(bitcoin::Network::Bitcoin));
    assert!(book.seed(v4(1, 8333), ServiceFlags::NETWORK.to_u64(), NOW - HOUR));
    let mut o = observation(None);
    o.fingerprint = Fingerprint::Known(Family::Core, Confidence::Claimed);
    let result = SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(o) };
    book.record_result(&v4(1, 8333), None, SessionKind::Discovery, result, NOW);
    let out = export_json(&book, &ctx(), &Mode::Raw);
    let node = out["nodes"]["23.1.1.7:8333"].as_array().unwrap();
    let satd = &node[13];
    assert_eq!(satd["family"], serde_json::Value::Null);
    assert_eq!(satd["fingerprint"], "core/claimed");
    assert_eq!(satd["confidence"], "claimed");
    assert_eq!(satd["claimed"], "core");
    assert_eq!(satd["mismatch"], false);
}

/// A fake node and a closed-early one are exported as no family and no
/// confidence, their `fingerprint` reading `fake/core` and `closed-early`
/// and `claimed` kept; the closed-early one is in the reachable set with
/// its `version`'s fields. Keyed, neither carries its address.
#[test]
fn fake_and_closed_early_nodes_are_exported_apart() {
    let mut book = CrawlBook::new(BookParams::for_network(bitcoin::Network::Bitcoin));
    let (fake_at, early_at) = (v4(1, 8333), v4(2, 8333));
    for a in [&fake_at, &early_at] {
        assert!(book.seed(a.clone(), ServiceFlags::NETWORK.to_u64(), NOW - HOUR));
    }
    let mut fake = observation(None);
    // A fake whose transcript a row matched is still no family.
    fake.fingerprint = Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd };
    fake.user_agent = "/Satoshi:25.0.0/".to_string();
    fake.verdict = Verdict::Fake(Family::Core);
    let mut early = observation(None);
    early.fingerprint = Fingerprint::Unknown;
    early.verdict = Verdict::ClosedEarly;
    for (a, o) in [(&fake_at, fake), (&early_at, early)] {
        let result = SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(o) };
        book.record_result(a, None, SessionKind::Discovery, result, NOW);
    }
    let raw = export_json(&book, &ctx(), &Mode::Raw);
    assert_eq!(raw["total_nodes"], 2, "both reachable");
    let satd = |key: &str| raw["nodes"][key][13].clone();
    let f = satd("23.1.1.7:8333");
    assert_eq!(f["fingerprint"], "fake/core", "{f}");
    assert_eq!((f["family"].clone(), f["confidence"].clone()), (serde_json::Value::Null, serde_json::Value::Null));
    assert_eq!(f["claimed"], "core");
    assert_eq!(f["mismatch"], false);
    let e = satd("23.1.2.7:8333");
    assert_eq!(e["fingerprint"], "closed-early", "{e}");
    assert_eq!((e["family"].clone(), e["confidence"].clone()), (serde_json::Value::Null, serde_json::Value::Null));
    assert_eq!(e["claimed"], "core");
    assert_eq!(e["transport"], "v1_only");
    assert_eq!(raw["nodes"]["23.1.2.7:8333"][1], "/Satoshi:32.1.0/", "the version's user agent is kept");

    // A fake whose fingerprint is the usual claim: still no confidence.
    let claimed_at = v4(3, 8333);
    assert!(book.seed(claimed_at.clone(), ServiceFlags::NETWORK.to_u64(), NOW - HOUR));
    let mut claimed_fake = observation(None);
    claimed_fake.fingerprint = Fingerprint::Known(Family::Core, Confidence::Claimed);
    claimed_fake.verdict = Verdict::Fake(Family::Core);
    let result = SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(claimed_fake) };
    book.record_result(&claimed_at, None, SessionKind::Discovery, result, NOW);
    let raw = export_json(&book, &ctx(), &Mode::Raw);
    let c = &raw["nodes"]["23.1.3.7:8333"][13];
    assert_eq!((c["fingerprint"].clone(), c["confidence"].clone()), ("fake/core".into(), serde_json::Value::Null), "{c}");

    let keyed = export_json(&book, &ctx(), &keyed(1));
    let text = keyed.to_string();
    assert!(!text.contains("23.1.1.7") && !text.contains("23.1.2.7") && !text.contains("23.1.3.7"), "{text}");
    let fingerprints: BTreeSet<String> = keyed["nodes"]
        .as_object()
        .unwrap()
        .values()
        .map(|n| n[13]["fingerprint"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(fingerprints, ["closed-early", "fake/core"].map(String::from).into(), "two fakes, one closed early");
    assert_eq!(keyed["total_nodes"], 3);
    // The hourly lines are the raw export's nodes.
    let lines = String::from_utf8(snapshot_lines(&book, &ctx())).unwrap();
    assert!(lines.contains("\"fingerprint\":\"fake/core\"") && lines.contains("\"fingerprint\":\"closed-early\""), "{lines}");
}

/// Keyed, no clearnet address and no port is anywhere in the export: not
/// in a key, not in a value, not as a number. Clearnet nodes are keyed by
/// their 32-digit ID, the port is `default` or `other`. Raw, the addresses
/// and ports are there.
#[test]
fn a_keyed_export_carries_no_clearnet_address_and_no_port() {
    let out = export_json(&book(), &ctx(), &keyed(1));
    let (mut strings, mut numbers) = (Vec::new(), Vec::new());
    leaves(&out, &mut strings, &mut numbers);
    let text = out.to_string();
    for ip in CLEARNET {
        assert!(!text.contains(ip), "{ip} in {text}");
    }
    for s in &strings {
        assert!(!s.contains(":8333") && !s.contains(":8334"), "a port in {s:?}");
    }
    assert!(!numbers.contains(&8333) && !numbers.contains(&8334), "a port as a number: {numbers:?}");
    let nodes = out["nodes"].as_object().unwrap();
    let ids: Vec<&String> = nodes.keys().filter(|k| !k.ends_with(".onion")).collect();
    assert_eq!(ids.len(), 5);
    for id in &ids {
        assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
    }
    let SocketAddr::V4(a) = SocketAddr::from((Ipv4Addr::new(23, 1, 4, 7), 8334)) else { unreachable!() };
    let other = &nodes[&node_id(&key(), &SocketAddr::V4(a))];
    assert_eq!(other[13]["port"], "other");
    assert_eq!(nodes[&node_id(&key(), &"23.1.1.7:8333".parse().unwrap())][13]["port"], "default");
    assert_eq!(out["satd"]["export"], "keyed");
    assert_eq!(out["satd"]["node_id"], "hmac-sha256-128");

    let raw = export_json(&book(), &ctx(), &Mode::Raw);
    let text = raw.to_string();
    for ip in &CLEARNET[..4] {
        assert!(text.contains(ip), "{ip} raw");
    }
    assert!(raw["nodes"].get("23.1.4.7:8334").is_some() && raw["nodes"].get("[2a01:4f8::1]:8333").is_some());
    assert_eq!(raw["satd"]["export"], "raw");
    assert!(raw["satd"].get("node_id").is_none());
}

/// Keyed, an ASN is given only when at least `-crawlexportmink` nodes of
/// the export are in it; the others are `"other"`; a node without `-asmap`
/// data has none. Raw, every ASN is exact.
#[test]
fn asns_under_the_minimum_are_folded_into_other() {
    let asns = |out: &serde_json::Value| {
        let mut v: Vec<String> =
            out["nodes"].as_object().unwrap().values().map(|n| n[11].as_str().unwrap_or("-").to_string()).collect();
        v.sort();
        v
    };
    let out = export_json(&book(), &ctx(), &keyed(3));
    assert_eq!(asns(&out), ["-", "-", "AS64496", "AS64496", "AS64496", "other"], "AS64497 has one node");
    assert_eq!(out["satd"]["asn_min_count"], 3);
    let out = export_json(&book(), &ctx(), &keyed(DEFAULT_EXPORT_MIN_K));
    assert_eq!(asns(&out), ["-", "-", "other", "other", "other", "other"]);
    assert!(!out.to_string().contains("6449"), "no small ASN by number anywhere");
    let raw = export_json(&book(), &ctx(), &Mode::Raw);
    assert_eq!(asns(&raw), ["-", "-", "AS64496", "AS64496", "AS64496", "AS64497"]);
}

/// Keyed, an onion is listed by its address, raw (on the network's port
/// without the port: its class says `default`); I2P and CJDNS addresses
/// appear only as counts.
#[test]
fn onions_raw_i2p_and_cjdns_as_counts() {
    for mode in [keyed(1), Mode::Raw] {
        let out = export_json(&book(), &ctx(), &mode);
        let text = out.to_string();
        assert!(!text.contains(".b32.i2p") && !text.contains("fc00"), "{text}");
        assert_eq!(out["satd"]["learned_not_dialled"], serde_json::json!({ "i2p": 1, "cjdns": 1 }));
    }
    let out = export_json(&book(), &ctx(), &keyed(1));
    let n = &out["nodes"][ONION];
    assert_eq!(n[13]["network"], "onion", "{out}");
    assert_eq!(n[13]["port"], "default");
    let raw = export_json(&book(), &ctx(), &Mode::Raw);
    assert!(raw["nodes"].get(format!("{ONION}:8333")).is_some(), "raw keeps the port");
}

// ---- gzip ----

/// The framing is RFC 1952's: the CRC-32 check value, the header, a
/// member Python's `gzip` wrote reads back, and every output round-trips.
#[test]
fn gzip_is_standard() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc32(b""), 0);
    let gz = gzip(b"hello\n", 0x1234_5678);
    assert_eq!(&gz[..10], &[0x1f, 0x8b, 8, 0, 0x78, 0x56, 0x34, 0x12, 0, 0xff]);
    assert_eq!(gunzip(&gz).unwrap(), b"hello\n");
    // gzip.compress(b"hello\n", mtime=0)
    let python = hex::decode("1f8b08000000000002ffcb48cdc9c9e7020020303a3606000000").unwrap();
    assert_eq!(gunzip(&python).unwrap(), b"hello\n");
    assert_eq!(&gz[gz.len() - 8..], &python[python.len() - 8..], "the same trailer");
    let big: Vec<u8> = (0..200_000u32).flat_map(|i| (i % 251).to_le_bytes()).collect();
    assert_eq!(gunzip(&gzip(&big, 0)).unwrap(), big);
}

// ---- the hourly files ----

/// An hourly snapshot's lines: one per reachable node, raw, as the raw
/// export lists it.
#[test]
fn snapshot_lines_are_one_per_reachable_node() {
    let lines = snapshot_lines(&book(), &ctx());
    let text = String::from_utf8(lines).unwrap();
    let rows: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(rows.len(), 6);
    let raw = export_json(&book(), &ctx(), &Mode::Raw);
    for r in &rows {
        assert_eq!((r["timestamp"].clone(), r["latest_height"].clone()), (NOW.into(), 900_002.into()));
        let addr = r["addr"].as_str().unwrap();
        assert_eq!(r["node"], raw["nodes"][addr], "{addr}");
    }
    assert!(text.contains("23.1.4.7:8334") && !text.contains("23.1.5.7"));
}

/// The retention rule at its edges: younger than 7 days kept; from 7 to 90
/// days the first of each UTC day; 90 days and older gone; a snapshot dated
/// ahead of the clock kept.
#[test]
fn prune_plan_edges() {
    let times = [
        NOW + HOUR,                         // ahead
        NOW - HOURLY_KEEP_SECS + 1,         // young
        NOW - HOURLY_KEEP_SECS,             // first of its day (NOW is day-aligned)
        NOW - HOURLY_KEEP_SECS + 2 * HOUR,  // young: same day, kept hourly
        NOW - HOURLY_KEEP_SECS - HOUR,      // the day before: first of it
        NOW - HOURLY_KEEP_SECS - 2 * HOUR,  // the day before: earlier, so this one is the first
        NOW - DAILY_KEEP_SECS + 1,          // daily
        NOW - DAILY_KEEP_SECS,              // gone
        NOW - DAILY_KEEP_SECS - DAY,        // gone
    ];
    let mut del = prune_plan(&times, NOW);
    del.sort_unstable();
    assert_eq!(del, vec![NOW - DAILY_KEEP_SECS - DAY, NOW - DAILY_KEEP_SECS, NOW - HOURLY_KEEP_SECS - HOUR]);
}

/// 100 days of a crawl under an injected clock, checking every 10
/// minutes: a snapshot each UTC hour, and once the pruning has run, every
/// hourly snapshot of the last 7 days (168) and one a day, the first, for
/// the 83 days before back to 90 days.
#[test]
fn hourly_snapshots_kept_7_days_then_one_a_day_to_90() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = SnapshotStore::open(dir.path().join(SNAPSHOT_DIR));
    let start = NOW - 100 * DAY;
    let mut written = 0;
    let mut t = start;
    while t <= NOW {
        if store.due(t) {
            store.write(t, b"{}\n").unwrap();
            written += 1;
        }
        t += 10 * 60;
    }
    assert_eq!(written, 100 * 24 + 1, "one an hour");
    let kept = list_snapshots(store.dir()).unwrap();
    let hourly: Vec<u64> = kept.iter().copied().filter(|t| NOW - t < HOURLY_KEEP_SECS).collect();
    let daily: Vec<u64> = kept.iter().copied().filter(|t| NOW - t >= HOURLY_KEEP_SECS).collect();
    assert_eq!(hourly.len(), 168, "every hour of the last 7 days");
    assert!(hourly.windows(2).all(|w| w[1] - w[0] == HOUR));
    assert_eq!(daily.len(), 83, "{daily:?}");
    assert!(daily.iter().all(|t| t % DAY == 0), "the first of each day");
    assert!(daily.windows(2).all(|w| w[1] - w[0] == DAY), "one a day");
    assert!(NOW - daily[0] < DAILY_KEEP_SECS, "none 90 days old");
    assert_eq!(NOW - daily[0], DAILY_KEEP_SECS - DAY);
}

/// A snapshot is due once per UTC hour; a store reopened after a restart
/// counts the newest file as its last write; other files in the directory
/// are left alone.
#[test]
fn a_snapshot_is_due_once_an_hour_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let snaps = dir.path().join(SNAPSHOT_DIR);
    let mut store = SnapshotStore::open(snaps.clone());
    assert!(store.due(NOW + 10));
    store.write(NOW + 10, b"").unwrap();
    assert!(!store.due(NOW + HOUR - 1));
    let store = SnapshotStore::open(snaps.clone());
    assert!(!store.due(NOW + 30 * 60), "a restart within the hour writes none");
    assert!(store.due(NOW + HOUR));
    std::fs::write(snaps.join("notes.txt"), "x").unwrap();
    std::fs::write(snaps.join("1.jsonl.gz.bak"), "x").unwrap();
    let mut store = SnapshotStore::open(snaps.clone());
    store.write(NOW + 200 * DAY, b"").unwrap();
    assert_eq!(list_snapshots(&snaps).unwrap(), vec![NOW + 200 * DAY], "the old snapshot pruned");
    assert!(snaps.join("notes.txt").exists() && snaps.join("1.jsonl.gz.bak").exists());
    assert_eq!(parse_snapshot_name("1790000000.jsonl.gz"), Some(1_790_000_000));
    for bad in ["x.jsonl.gz", ".jsonl.gz", "1.jsonl", "-1.jsonl.gz", "1.jsonl.dat.tmp"] {
        assert_eq!(parse_snapshot_name(bad), None, "{bad}");
    }
}

/// The directory takes the data directory's permissions and each file
/// those, execute bits dropped, as `crawlbook.dat`: under a 0700 data
/// directory, 0700 and 0600. The file is the gzip of the lines.
#[cfg(unix)]
#[test]
fn snapshot_files_are_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("regtest");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = SnapshotStore::open(data.join(SNAPSHOT_DIR));
    let lines = snapshot_lines(&book(), &ctx());
    let w = store.write(NOW, &lines).unwrap();
    assert_eq!(mode(&data.join(SNAPSHOT_DIR)), 0o700);
    assert_eq!(mode(&w.path), 0o600);
    assert_eq!(w.path, data.join(SNAPSHOT_DIR).join(format!("{NOW}.jsonl.gz")));
    assert_eq!(gunzip(&std::fs::read(&w.path).unwrap()).unwrap(), lines);
    let leftovers = std::fs::read_dir(data.join(SNAPSHOT_DIR)).unwrap().count();
    assert_eq!(leftovers, 1, "no temporary file left");
}

/// Keyed, one onion's services on two ports are two nodes: the one on the
/// network's port by host alone, the other with its port.
#[test]
fn one_onion_on_two_ports_is_two_nodes_keyed() {
    let mut book = book();
    let other = PeerAddr::Onion { host: ONION.to_string(), port: 9050 };
    assert!(book.seed(other.clone(), ServiceFlags::NETWORK.to_u64(), NOW - 4 * HOUR));
    let result = SessionResult { v2: Attempt::Failed, v1: Attempt::Ok, observation: Some(observation(None)) };
    book.record_result(&other, None, SessionKind::Discovery, result, NOW);
    let out = export_json(&book, &ctx(), &keyed(1));
    let nodes = out["nodes"].as_object().unwrap();
    assert!(nodes.contains_key(ONION), "{out}");
    assert!(nodes.contains_key(&format!("{ONION}:9050")), "{out}");
    assert_eq!(out["total_nodes"], nodes.len());
}

/// A failed write is not retried on every tick: the store waits
/// SNAPSHOT_RETRY_SECS, then a write that works clears it.
#[test]
fn a_failed_snapshot_write_waits_before_the_next_try() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = SnapshotStore::open(dir.path().join(SNAPSHOT_DIR));
    assert!(store.due(NOW));
    store.failed(NOW);
    assert!(!store.due(NOW + 1));
    assert!(!store.due(NOW + SNAPSHOT_RETRY_SECS - 1));
    assert!(store.due(NOW + SNAPSHOT_RETRY_SECS));
    store.write(NOW + SNAPSHOT_RETRY_SECS, b"{}\n").unwrap();
    assert!(store.due(NOW + SNAPSHOT_RETRY_SECS + HOUR), "the next hour");
}
