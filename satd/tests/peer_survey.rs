//! The network survey (`-peersurvey`, #1353) against a running regtest
//! node: a small cluster of peers whose families are known (scripted peers
//! with the shapes the fingerprint captures show for Core, btcd and
//! libbitcoin, and a real satd), surveyed until each has a record; the
//! aggregate must say so. Then the store survives a restart, and with the
//! survey off the node dials nothing. A peer claiming Core that sends only
//! `version` and `verack` and stays silent is counted fake, and one that
//! closes straight after the handshake closed early, neither as a family.
//! A closed-early address is given retries until a session settles, and a
//! settled one keeps its fingerprint when a later session closes early.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, find_available_port, poll_until_json, test_timeout};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// What a scripted peer sends when dialled.
#[derive(Clone)]
struct Shape {
    user_agent: &'static str,
    protocol_version: u32,
    relay: bool,
    /// Between the dialler's `version` and our `verack`.
    negotiation: Vec<NetworkMessage>,
    /// Once the dialler's `verack` arrives.
    after_verack: Vec<NetworkMessage>,
    /// Answer `ping`, `getheaders` and `getdata`.
    answers: bool,
    /// Hang up once the dialler's `verack` arrives, as a node with full
    /// inbound slots evicting its newest connection does.
    close_after_verack: bool,
    /// Hang up so while this is set, whatever `close_after_verack` says.
    evicting: Option<Arc<AtomicBool>>,
}

/// `core-31.2-outbound`: Core when dialled.
fn core() -> Shape {
    Shape {
        user_agent: "/Satoshi:32.1.0/",
        protocol_version: 70016,
        relay: true,
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            }),
            NetworkMessage::Ping(7),
        ],
        answers: true,
        close_after_verack: false,
        evicting: None,
    }
}

/// `btcd-0.27.0-outbound`: btcd when dialled sends nothing after `verack`.
fn btcd() -> Shape {
    Shape {
        user_agent: "/btcwire:0.5.0/btcd:0.27.0/",
        protocol_version: 70016,
        relay: true,
        negotiation: vec![NetworkMessage::SendAddrV2],
        after_verack: vec![],
        answers: true,
        close_after_verack: false,
        evicting: None,
    }
}

/// `libbitcoin-3.8.0-outbound`: protocol 70013, relay off, nothing more.
fn libbitcoin() -> Shape {
    Shape {
        user_agent: "/libbitcoin:3.8.0/",
        protocol_version: 70013,
        relay: false,
        negotiation: vec![],
        after_verack: vec![],
        answers: true,
        close_after_verack: false,
        evicting: None,
    }
}

/// A peer claiming Core 25 at protocol 70016 that sends `version` and
/// `verack` and nothing else, answering nothing, not even a `ping`: no
/// Core release since 0.21 does that.
fn fake_core() -> Shape {
    Shape {
        user_agent: "/Satoshi:25.0.0/",
        protocol_version: 70016,
        relay: true,
        negotiation: vec![],
        after_verack: vec![],
        answers: false,
        close_after_verack: false,
        evicting: None,
    }
}

/// Core with its inbound slots full: it completes the handshake, then
/// evicts the new connection before sending anything more.
fn evicting_core() -> Shape {
    Shape {
        after_verack: vec![],
        close_after_verack: true,
        ..core()
    }
}

fn send(stream: &mut TcpStream, msg: NetworkMessage) -> io::Result<()> {
    stream.write_all(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)))
}

fn recv(stream: &mut TcpStream) -> io::Result<NetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    if header[..4] != Magic::REGTEST.to_bytes() {
        // A v2 handshake, or anything else: a v1-only peer hangs up.
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not v1"));
    }
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let mut buf = header.to_vec();
    buf.resize(24 + len, 0);
    stream.read_exact(&mut buf[24..])?;
    let raw: RawNetworkMessage =
        deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(raw.into_payload())
}

/// One dialled connection, served by `shape` until the dialler hangs up.
fn serve(mut stream: TcpStream, shape: &Shape) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    loop {
        match recv(&mut stream)? {
            NetworkMessage::Version(_) => {
                let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                send(
                    &mut stream,
                    NetworkMessage::Version(VersionMessage {
                        version: shape.protocol_version,
                        services,
                        timestamp: 1_790_000_000,
                        receiver: Address::new(&zero, ServiceFlags::NONE),
                        sender: Address::new(&zero, services),
                        nonce: rand::random(),
                        user_agent: shape.user_agent.into(),
                        start_height: 0,
                        relay: shape.relay,
                    }),
                )?;
                for m in &shape.negotiation {
                    send(&mut stream, m.clone())?;
                }
                send(&mut stream, NetworkMessage::Verack)?;
            }
            NetworkMessage::Verack => {
                if shape.close_after_verack
                    || shape
                        .evicting
                        .as_ref()
                        .is_some_and(|e| e.load(Ordering::SeqCst))
                {
                    // A clean close: our end first, then read to the
                    // dialler's, so no reset discards what it has not read.
                    stream.shutdown(std::net::Shutdown::Write)?;
                    while recv(&mut stream).is_ok() {}
                    return Ok(());
                }
                for m in &shape.after_verack {
                    send(&mut stream, m.clone())?;
                }
            }
            _ if !shape.answers => {}
            NetworkMessage::Ping(n) => send(&mut stream, NetworkMessage::Pong(n))?,
            NetworkMessage::GetHeaders(_) => send(&mut stream, NetworkMessage::Headers(vec![]))?,
            NetworkMessage::GetData(inv) => send(&mut stream, NetworkMessage::NotFound(inv))?,
            _ => {}
        }
    }
}

/// A scripted peer listening on loopback: its port and how many
/// connections it has taken.
fn scripted(shape: Shape) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let shape = shape.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, &shape);
            });
        }
    });
    (port, accepts)
}

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// Mine a block, so the node is out of initial block download: during it
/// the automatic outbound target is 64 whatever `-maxconnections` says, and
/// the node would dial the cluster itself.
fn leave_ibd(node: &TestNode) {
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
}

fn add_address(node: &TestNode, port: u16) {
    let r = node.rpc_ok("addpeeraddress", vec![json!("127.0.0.1"), json!(port)]);
    assert_eq!(r["success"], true, "{r}");
}

/// The node surveys each peer of the cluster and the aggregate counts one
/// of each family. `-maxconnections=0`, out of initial block download,
/// leaves the node no automatic connection of its own, so every dial is the
/// survey's: the survey takes no slot.
#[test]
fn the_survey_aggregate_matches_the_families_it_reached() {
    let metrics_port = find_available_port();
    let mut target = TestNode::start(&[]);
    let satd_port = target.p2p_port.expect("p2p port");
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=1",
        &format!("--metricsport={metrics_port}"),
    ]);
    leave_ibd(&node);
    let ports: Vec<u16> = [core(), btcd(), libbitcoin()]
        .into_iter()
        .map(|s| scripted(s).0)
        .collect();
    for port in ports.iter().chain([&satd_port]) {
        add_address(&node, *port);
    }

    let survey = poll_until_json(
        || node.rpc_ok("getpeersurvey", vec![]),
        |v| v["addresses"] == 4,
        test_timeout(240).as_secs(),
    );
    assert_eq!(survey["enabled"], true);
    for (family, n) in [
        ("core", 1),
        ("btcd", 1),
        ("libbitcoin", 1),
        ("satd", 1),
        ("unknown", 0),
    ] {
        assert_eq!(survey["families"][family]["count"], n, "{family}: {survey}");
    }
    assert_eq!(survey["families"]["core"]["share"], 0.25);
    assert_eq!(survey["mismatches"], 0);
    assert!(
        survey["v2"]["count"].as_u64().unwrap() <= 1,
        "only the satd peer speaks v2"
    );
    assert!(
        survey.get("peers").is_none(),
        "no address without verbose: {survey}"
    );

    let verbose = node.rpc_ok("getpeersurvey", vec![json!(true)]);
    let rows = verbose["peers"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let row = rows
        .iter()
        .find(|r| r["addr"] == format!("127.0.0.1:{}", ports[0]))
        .expect("the Core peer's row");
    assert_eq!(row["family"], "core");
    assert_eq!(row["subver"], "/Satoshi:32.1.0/");
    assert_eq!(row["network"], "ipv4");
    let named = node
        .rpc_call_with_named_params("getpeersurvey", json!({"verbose": true}))
        .unwrap();
    assert_eq!(
        named["result"]["peers"].as_array().unwrap().len(),
        4,
        "{named}"
    );

    // No survey connection is a peer.
    assert_eq!(node.rpc_ok("getconnectioncount", vec![]), 0);
    assert!(
        node.rpc_ok("help", vec![])
            .as_str()
            .unwrap()
            .contains("getpeersurvey")
    );

    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    for line in [
        "satd_peer_survey_enabled 1",
        "satd_peer_survey_records 4",
        "satd_peer_survey_family{family=\"core\"} 1",
        "satd_peer_survey_family{family=\"btcd\"} 1",
    ] {
        assert!(body.lines().any(|l| l == line), "missing `{line}`");
    }
    assert!(!body.contains("127.0.0.1"), "no address in the metrics");

    // The store is written at shutdown with the data directory's
    // permissions, and read back at startup.
    node.stop();
    let net_dir = node.datadir.join("regtest");
    let file = net_dir.join("peersurvey.dat");
    assert!(file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let dir_mode = std::fs::metadata(&net_dir).unwrap().permissions().mode() & 0o777;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, dir_mode & 0o666);
    }
    node.restart_preserving_datadir(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=3600",
    ]);
    assert_eq!(node.rpc_ok("getpeersurvey", vec![])["addresses"], 4);
    node.stop();
    target.stop();
}

/// A peer claiming Core that sends `version` and `verack` and then nothing,
/// the connection open through the passive wait, is fake; one that closes
/// the connection straight after the handshake is closed early. Each is
/// counted on its own tally, in no family, claim or unknown, and shown so
/// in the verbose rows and the metrics.
#[test]
fn the_survey_counts_fake_and_closed_early_apart() {
    let metrics_port = find_available_port();
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=1",
        &format!("--metricsport={metrics_port}"),
    ]);
    leave_ibd(&node);
    let fake_port = scripted(fake_core()).0;
    let early_port = scripted(evicting_core()).0;
    add_address(&node, fake_port);
    add_address(&node, early_port);

    let survey = poll_until_json(
        || node.rpc_ok("getpeersurvey", vec![]),
        |v| v["addresses"] == 2,
        test_timeout(240).as_secs(),
    );
    assert_eq!(survey["fake"]["core"]["count"], 1, "{survey}");
    assert_eq!(
        survey["fake"]["core"]["share"], 0.5,
        "of all records: {survey}"
    );
    assert_eq!(survey["closed_early"]["count"], 1, "{survey}");
    assert_eq!(survey["closed_early"]["share"], 0.5, "{survey}");
    assert_eq!(survey["families"]["core"]["count"], 0, "{survey}");
    assert_eq!(survey["families"]["unknown"]["count"], 0, "{survey}");
    assert_eq!(survey["claimed"]["core"]["count"], 0, "{survey}");
    assert_eq!(survey["mismatches"], 0);
    assert_eq!(
        survey["connections"]["completed"].as_u64().map(|n| n >= 2),
        Some(true),
        "both completed: {survey}"
    );

    let verbose = node.rpc_ok("getpeersurvey", vec![json!(true)]);
    let rows = verbose["peers"].as_array().unwrap();
    let row = |port: u16| {
        rows.iter()
            .find(|r| r["addr"] == format!("127.0.0.1:{port}"))
            .expect("a row")
    };
    let fake = row(fake_port);
    assert_eq!(fake["fingerprint"], "fake/core", "{fake}");
    assert_eq!(fake["family"], serde_json::Value::Null);
    assert_eq!(fake["claimed"], "core");
    assert_eq!(fake["handshake"], json!(["version", "verack"]));
    let early = row(early_port);
    assert_eq!(early["fingerprint"], "closed-early", "{early}");
    assert_eq!(early["family"], serde_json::Value::Null);
    assert_eq!(early["claimed"], "core");
    assert_eq!(early["subver"], "/Satoshi:32.1.0/");
    assert_eq!(early["version"], 70016);

    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    for line in [
        "satd_peer_survey_records 2",
        "satd_peer_survey_fake{family=\"core\"} 1",
        "satd_peer_survey_closed_early 1",
        "satd_peer_survey_family{family=\"core\"} 0",
        "satd_peer_survey_family{family=\"unknown\"} 0",
        "satd_peer_survey_claimed{family=\"core\"} 0",
    ] {
        assert!(body.lines().any(|l| l == line), "missing `{line}`");
    }

    // The verdicts survive a restart.
    node.stop();
    node.restart_preserving_datadir(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=3600",
    ]);
    let again = node.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(
        (
            again["fake"]["core"]["count"].clone(),
            again["closed_early"]["count"].clone()
        ),
        (json!(1), json!(1)),
        "{again}"
    );
    node.stop();
}

/// With the survey off (the default), a node with an address in its book
/// and no automatic slots (out of initial block download) dials nothing, and `getpeersurvey` reports the
/// survey off.
#[test]
fn with_the_survey_off_the_node_dials_nothing() {
    let mut node = TestNode::start(&["--maxconnections=0"]);
    leave_ibd(&node);
    let (port, accepts) = scripted(core());
    add_address(&node, port);
    std::thread::sleep(test_timeout(15));
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "no connection");
    let survey = node.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(survey["enabled"], false);
    assert_eq!(survey["addresses"], 0);
    assert!(!node.datadir.join("regtest").join("peersurvey.dat").exists());
    node.stop();
    assert!(
        !node.datadir.join("regtest").join("peersurvey.dat").exists(),
        "nothing written"
    );
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The verbose row of the peer on `port`, once there is one.
fn survey_row(node: &TestNode, port: u16) -> Option<serde_json::Value> {
    let verbose = node.rpc_ok("getpeersurvey", vec![json!(true)]);
    verbose["peers"]
        .as_array()?
        .iter()
        .find(|r| r["addr"] == format!("127.0.0.1:{port}"))
        .cloned()
}

/// A peer that closes straight after the handshake (a Core node with its
/// inbound slots full) is recorded closed early and given a retry after
/// each such session: due 15 min, 30 min, 1 h, 2 h, then 4 h after it, each
/// spread by a fifth, ten in all, then none. The node's clock is mocked
/// and frozen, so every session happens at one instant and each due time
/// is checked against it; with one address in the book every survey turn
/// reaches it. Once the peer has room, its session settles: the record is
/// Core and the schedule is cleared.
#[test]
fn a_closed_early_address_is_retried_until_it_settles() {
    let metrics_port = find_available_port();
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=1",
        &format!("--metricsport={metrics_port}"),
    ]);
    leave_ibd(&node);
    let t0 = now_secs();
    node.rpc_ok("setmocktime", vec![json!(t0)]);
    let evicting = Arc::new(AtomicBool::new(true));
    let (port, accepts) = scripted(Shape {
        evicting: Some(evicting.clone()),
        ..core()
    });
    add_address(&node, port);

    let delays = [900u64, 1_800, 3_600, 7_200, 14_400];
    let row = poll_until_json(
        || survey_row(&node, port).unwrap_or(json!(null)),
        |r| r["fingerprint"] == "closed-early",
        test_timeout(120).as_secs(),
    );
    let count = row["retry"]["count"].as_u64().unwrap();
    assert!(count >= 1, "{row}");
    if let Some(due) = row["retry"]["next_due"].as_u64() {
        let wait = delays[(count as usize).min(delays.len()) - 1];
        assert!(
            (t0 + wait * 4 / 5..=t0 + wait * 6 / 5).contains(&due),
            "retry {count} due {}: {row}",
            due - t0
        );
    }

    // Every survey turn reaches the one address, so the ten retries are
    // scheduled, and then none.
    let survey = poll_until_json(
        || node.rpc_ok("getpeersurvey", vec![]),
        |v| v["retries"]["exhausted"] == 1,
        test_timeout(120).as_secs(),
    );
    assert_eq!(
        survey["retries"],
        json!({ "pending": 0, "exhausted": 1 }),
        "{survey}"
    );
    assert_eq!(survey["closed_early"]["count"], 1);
    let row = survey_row(&node, port).unwrap();
    assert_eq!(
        row["retry"],
        json!({ "count": 10, "next_due": null }),
        "{row}"
    );
    assert!(
        accepts.load(Ordering::SeqCst) >= 11,
        "the first session and ten more"
    );

    // The peer has room now: the next session settles, and clears it.
    evicting.store(false, Ordering::SeqCst);
    let row = poll_until_json(
        || survey_row(&node, port).unwrap_or(json!(null)),
        |r| r["fingerprint"] != "closed-early",
        test_timeout(120).as_secs(),
    );
    assert_eq!(row["family"], "core", "{row}");
    assert!(row.get("retry").is_none(), "settled: no retry: {row}");
    let survey = node.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(
        survey["retries"],
        json!({ "pending": 0, "exhausted": 0 }),
        "{survey}"
    );
    assert_eq!(
        (
            survey["closed_early"]["count"].clone(),
            survey["families"]["core"]["count"].clone()
        ),
        (json!(0), json!(1))
    );
    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    assert!(
        body.lines()
            .any(|l| l == "satd_peer_survey_closed_early_retries 0"),
        "{body}"
    );
    node.stop();
}

/// A closed-early address with a retry pending keeps it across a restart,
/// and the metric counts it.
#[test]
fn a_pending_retry_survives_a_restart() {
    let metrics_port = find_available_port();
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=1",
        &format!("--metricsport={metrics_port}"),
    ]);
    leave_ibd(&node);
    let port = scripted(evicting_core()).0;
    add_address(&node, port);
    let row = poll_until_json(
        || survey_row(&node, port).unwrap_or(json!(null)),
        |r| r["fingerprint"] == "closed-early",
        test_timeout(120).as_secs(),
    );
    assert!(row["retry"]["count"].as_u64().unwrap() >= 1, "{row}");
    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    assert!(
        body.lines()
            .any(|l| l.starts_with("satd_peer_survey_closed_early_retries ")),
        "{body}"
    );
    node.stop();
    // Read back with the survey connecting no more, so the schedule stands.
    node.restart_preserving_datadir(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=3600",
    ]);
    let back = survey_row(&node, port).unwrap();
    assert_eq!(back["fingerprint"], "closed-early");
    assert!(back["retry"]["count"].as_u64().unwrap() >= 1, "{back}");
    let survey = node.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(
        survey["retries"]["pending"].as_u64().unwrap()
            + survey["retries"]["exhausted"].as_u64().unwrap(),
        1,
        "{survey}"
    );
    node.stop();
}

/// A settled address whose later survey sessions close early keeps its
/// fingerprint and transcript; only its last sighting moves on, and it gets
/// no retry.
#[test]
fn a_settled_address_keeps_its_fingerprint_when_it_later_closes_early() {
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--peersurvey=1",
        "--peersurveyinterval=1",
    ]);
    leave_ibd(&node);
    let t0 = now_secs();
    node.rpc_ok("setmocktime", vec![json!(t0)]);
    let evicting = Arc::new(AtomicBool::new(false));
    let (port, accepts) = scripted(Shape {
        evicting: Some(evicting.clone()),
        ..core()
    });
    add_address(&node, port);
    poll_until_json(
        || survey_row(&node, port).unwrap_or(json!(null)),
        |r| r["family"] == "core",
        test_timeout(120).as_secs(),
    );
    let wait_accepts = |n: usize| {
        let deadline = std::time::Instant::now() + test_timeout(60);
        while accepts.load(Ordering::SeqCst) < n {
            assert!(std::time::Instant::now() < deadline, "no more sessions");
            std::thread::sleep(Duration::from_millis(100));
        }
        // The session before it is recorded just after its connection
        // leaves the peer table, which lets the next one be dialled.
        std::thread::sleep(Duration::from_millis(500));
    };

    // From now on the peer closes straight after the handshake. A
    // connection accepted after the change is one; one survey connection
    // at a time, so by then the last settled session has been recorded.
    evicting.store(true, Ordering::SeqCst);
    wait_accepts(accepts.load(Ordering::SeqCst) + 1);
    let settled = survey_row(&node, port).unwrap();
    assert_eq!(settled["family"], "core", "{settled}");
    node.rpc_ok("setmocktime", vec![json!(t0 + 100)]);
    // Two more connections: the one before them, closed early at the new
    // time, has been recorded.
    wait_accepts(accepts.load(Ordering::SeqCst) + 2);
    let mut row = survey_row(&node, port).unwrap();
    assert_eq!(
        row["last_seen"],
        t0 + 100,
        "the last sighting moves on: {row}"
    );
    row["last_seen"] = settled["last_seen"].clone();
    assert_eq!(row, settled, "all else is the settled record's");
    assert!(row.get("retry").is_none(), "no retry: {row}");
    let survey = node.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(survey["closed_early"]["count"], 0, "{survey}");
    assert_eq!(survey["families"]["core"]["count"], 1, "{survey}");
    assert_eq!(survey["retries"], json!({ "pending": 0, "exhausted": 0 }));
    node.stop();
}
