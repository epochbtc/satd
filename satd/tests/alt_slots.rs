//! Alt-slots (`-altslots`, #1355) against a running regtest node: scripted
//! peers with the handshake shapes the fingerprint captures show for Core
//! and btcd. The one full-relay slot, set aside for `family:btcd` by a
//! SIGHUP reload, fills with the btcd peer; a reload past the limits is
//! refused; lowering `-altslots` keeps the peer as an ordinary outbound.
//! With no matching peer reachable, a fallback takes the slot.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, find_available_port, poll_until_json, test_timeout};
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

#[derive(Clone)]
struct Shape {
    user_agent: &'static str,
    negotiation: Vec<NetworkMessage>,
    after_verack: Vec<NetworkMessage>,
}

/// `core-31.2-outbound`.
fn core() -> Shape {
    Shape {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: 2,
            }),
            NetworkMessage::Ping(7),
        ],
    }
}

/// `btcd-0.27.0-outbound`: nothing after `verack`.
fn btcd() -> Shape {
    Shape {
        user_agent: "/btcwire:0.5.0/btcd:0.27.0/",
        negotiation: vec![NetworkMessage::SendAddrV2],
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

fn serve(mut stream: TcpStream, shape: &Shape) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    loop {
        match recv(&mut stream)? {
            NetworkMessage::Version(_) => {
                let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                send(
                    &mut stream,
                    NetworkMessage::Version(VersionMessage {
                        version: 70016,
                        services,
                        timestamp: 1_790_000_000,
                        receiver: Address::new(&zero, ServiceFlags::NONE),
                        sender: Address::new(&zero, services),
                        nonce: rand::random(),
                        user_agent: shape.user_agent.into(),
                        start_height: 0,
                        relay: true,
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
            _ => {}
        }
    }
}

fn scripted(shape: Shape) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shape = shape.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, &shape);
            });
        }
    });
    port
}

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

fn sighup(node: &TestNode) {
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(node.process.id().to_string())
        .status()
        .expect("kill -HUP");
    assert!(status.success());
}

/// Rewrite the config file and reload it.
fn reload(node: &TestNode, conf: &str) {
    std::fs::write(
        node.datadir.join("bitcoin.conf"),
        format!("[regtest]\n{conf}"),
    )
    .unwrap();
    sighup(node);
}

fn alt_slots(node: &TestNode) -> Value {
    node.rpc_ok("getpeersurvey", vec![])["alt_slots"].clone()
}

/// A node out of IBD with one full-relay slot (`-maxconnections=1` leaves
/// no block-relay-only one), whose only slot is then set aside by a reload
/// with `conf`, before any address is in its book.
fn node_with_one_alt_slot(conf: &str, extra: &[&str]) -> TestNode {
    let mut args = vec!["--maxconnections=1"];
    args.extend_from_slice(extra);
    let node = TestNode::start(&args);
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    reload(&node, conf);
    poll_until_json(
        || alt_slots(&node),
        |v| v["configured"] == 1,
        test_timeout(30).as_secs(),
    );
    node
}

fn add_address(node: &TestNode, port: u16) {
    let r = node.rpc_ok("addpeeraddress", vec![json!("127.0.0.1"), json!(port)]);
    assert_eq!(r["success"], true, "{r}");
}

#[test]
fn the_alt_slot_fills_with_the_matching_peer() {
    let metrics_port = find_available_port();
    let conf = "maxoutboundfullrelay=1\naltslots=1\naltprefer=family:btcd\n";
    let mut node = node_with_one_alt_slot(conf, &[&format!("--metricsport={metrics_port}")]);
    let btcd_port = scripted(btcd());
    add_address(&node, scripted(core()));
    add_address(&node, btcd_port);

    let behavior = poll_until_json(
        || node.rpc_ok("getpeerbehavior", vec![]),
        |v| {
            v.as_array()
                .is_some_and(|a| a.iter().any(|p| p["alt_slot"]["rule"] == "family:btcd"))
        },
        test_timeout(240).as_secs(),
    );
    let peer = behavior
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["alt_slot"].is_object())
        .unwrap()
        .clone();
    assert_eq!(
        peer["alt_slot"],
        json!({"rule": "family:btcd", "trust": "verified", "fallback": false})
    );
    let id = peer["id"].clone();
    let info = node.rpc_ok("getpeerinfo", vec![]);
    let row = info
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .expect("in getpeerinfo")
        .clone();
    assert_eq!(row["connection_type"], "outbound-full-relay");
    assert_eq!(row["addr"], format!("127.0.0.1:{btcd_port}"));
    assert_eq!(
        alt_slots(&node),
        json!({"configured": 1, "matched": 1, "fallback": 0, "empty": 0})
    );
    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    assert!(
        body.lines()
            .any(|l| l == "satd_peer_alt_slots{state=\"matched\"} 1"),
        "{body}"
    );
    assert!(!body.contains("127.0.0.1:"), "no address in the metrics");

    // Past the limits: the reload is refused and the running values kept.
    reload(
        &node,
        "maxoutboundfullrelay=1\naltslots=2\naltprefer=family:btcd\n",
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        alt_slots(&node)["configured"],
        1,
        "a reload past the limits is refused"
    );
    reload(&node, "maxoutboundfullrelay=17\n");
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(alt_slots(&node)["configured"], 1, "17 needs the override");

    // Lowered to none: the peer stays, as an ordinary outbound.
    reload(&node, "maxoutboundfullrelay=1\naltslots=0\n");
    poll_until_json(
        || alt_slots(&node),
        |v| v["configured"] == 0,
        test_timeout(30).as_secs(),
    );
    let behavior = node.rpc_ok("getpeerbehavior", vec![]);
    let same = behavior
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .expect("still connected");
    assert!(same.get("alt_slot").is_none(), "{same}");
    node.stop();
}

/// No peer matches: once the slot has been empty for `-altfillwait`, an
/// ordinary fallback peer takes it.
#[test]
fn a_fallback_takes_the_slot_when_nothing_matches() {
    let conf = "maxoutboundfullrelay=1\naltslots=1\naltprefer=family:floresta\naltfillwait=1\n";
    let mut node = node_with_one_alt_slot(conf, &[]);
    for _ in 0..3 {
        add_address(&node, scripted(core()));
    }
    poll_until_json(
        || alt_slots(&node),
        |v| v["fallback"] == 1,
        test_timeout(240).as_secs(),
    );
    let behavior = node.rpc_ok("getpeerbehavior", vec![]);
    assert!(
        behavior
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["alt_slot"] == json!({"rule": null, "trust": null, "fallback": true})),
        "{behavior}"
    );
    node.stop();
}
