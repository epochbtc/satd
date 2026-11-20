//! The network survey (`-peersurvey`, #1353) against a running regtest
//! node: a small cluster of peers whose families are known (scripted peers
//! with the shapes the fingerprint captures show for Core, btcd and
//! libbitcoin, and a real satd), surveyed until each has a record; the
//! aggregate must say so. Then the store survives a restart, and with the
//! survey off the node dials nothing.

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
use std::sync::atomic::{AtomicUsize, Ordering};
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
}

/// `core-31.2-outbound`: Core when dialled.
fn core() -> Shape {
    Shape {
        user_agent: "/Satoshi:32.1.0/",
        protocol_version: 70016,
        relay: true,
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: 2 }), NetworkMessage::Ping(7)],
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
    let raw: RawNetworkMessage = deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
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
                for m in &shape.after_verack {
                    send(&mut stream, m.clone())?;
                }
            }
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
    let ports: Vec<u16> = [core(), btcd(), libbitcoin()].into_iter().map(|s| scripted(s).0).collect();
    for port in ports.iter().chain([&satd_port]) {
        add_address(&node, *port);
    }

    let survey = poll_until_json(
        || node.rpc_ok("getpeersurvey", vec![]),
        |v| v["addresses"] == 4,
        test_timeout(240).as_secs(),
    );
    assert_eq!(survey["enabled"], true);
    for (family, n) in [("core", 1), ("btcd", 1), ("libbitcoin", 1), ("satd", 1), ("unknown", 0)] {
        assert_eq!(survey["families"][family]["count"], n, "{family}: {survey}");
    }
    assert_eq!(survey["families"]["core"]["share"], 0.25);
    assert_eq!(survey["mismatches"], 0);
    assert!(survey["v2"]["count"].as_u64().unwrap() <= 1, "only the satd peer speaks v2");
    assert!(survey.get("peers").is_none(), "no address without verbose: {survey}");

    let verbose = node.rpc_ok("getpeersurvey", vec![json!(true)]);
    let rows = verbose["peers"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let row = rows.iter().find(|r| r["addr"] == format!("127.0.0.1:{}", ports[0])).expect("the Core peer's row");
    assert_eq!(row["family"], "core");
    assert_eq!(row["subver"], "/Satoshi:32.1.0/");
    assert_eq!(row["network"], "ipv4");
    let named = node.rpc_call_with_named_params("getpeersurvey", json!({"verbose": true})).unwrap();
    assert_eq!(named["result"]["peers"].as_array().unwrap().len(), 4, "{named}");

    // No survey connection is a peer.
    assert_eq!(node.rpc_ok("getconnectioncount", vec![]), 0);
    assert!(node.rpc_ok("help", vec![]).as_str().unwrap().contains("getpeersurvey"));

    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics")).unwrap().text().unwrap();
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
    node.restart_preserving_datadir(&["--maxconnections=0", "--peersurvey=1", "--peersurveyinterval=3600"]);
    assert_eq!(node.rpc_ok("getpeersurvey", vec![])["addresses"], 4);
    node.stop();
    target.stop();
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
    assert!(!node.datadir.join("regtest").join("peersurvey.dat").exists(), "nothing written");
}
