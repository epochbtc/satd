//! `getpeerbehavior` and the peer-flag metrics against a running regtest
//! node, with a raw peer that sends btcd's handshake under Core's user
//! agent and asks for addresses twice.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, find_available_port, poll_until_json, test_timeout};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

struct Peer {
    stream: TcpStream,
}

impl Peer {
    fn send(&mut self, msg: NetworkMessage) {
        let _ = self.stream.write_all(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)));
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<NetworkMessage> {
        self.stream.set_read_timeout(Some(timeout)).unwrap();
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut buf = header.to_vec();
        buf.resize(24 + len, 0);
        self.stream.read_exact(&mut buf[24..])?;
        let raw: RawNetworkMessage =
            deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(raw.into_payload())
    }

    /// Dial the node and handshake as the btcd capture does
    /// (`version sendaddrv2 verack`), under `user_agent`.
    fn btcd_shaped(port: u16, user_agent: &str) -> Self {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + test_timeout(30);
        let stream = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("connect: {e}"),
            }
        };
        stream.set_nodelay(true).unwrap();
        let mut peer = Peer { stream };
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        peer.send(NetworkMessage::Version(VersionMessage {
            version: 70016,
            services,
            timestamp: 1_760_000_000,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, services),
            nonce: 0x5eed_beef,
            user_agent: user_agent.into(),
            start_height: 0,
            relay: true,
        }));
        let (mut got_version, mut got_verack) = (false, false);
        while !(got_version && got_verack) {
            match peer.recv(test_timeout(30)).expect("handshake") {
                NetworkMessage::Version(_) => {
                    got_version = true;
                    peer.send(NetworkMessage::SendAddrV2);
                    peer.send(NetworkMessage::Verack);
                }
                NetworkMessage::Verack => got_verack = true,
                _ => {}
            }
        }
        peer
    }
}

#[test]
fn getpeerbehavior_reports_a_borrowed_user_agent_and_repeated_getaddr() {
    let metrics_port = find_available_port();
    let mut node = TestNode::start(&[&format!("--metricsport={metrics_port}")]);
    let port = node.p2p_port.expect("p2p port");

    assert_eq!(node.rpc_ok("getpeerbehavior", vec![]), json!([]));
    let unknown = node.rpc_call_with_params("getpeerbehavior", vec![json!(99)]).unwrap();
    assert_eq!(unknown["error"]["code"], -8, "{unknown}");

    let mut peer = Peer::btcd_shaped(port, "/Satoshi:31.2.0/");
    peer.send(NetworkMessage::GetAddr);
    peer.send(NetworkMessage::GetAddr);

    // The node judges peers every 5 seconds.
    let all = poll_until_json(
        || node.rpc_ok("getpeerbehavior", vec![]),
        |v| v[0]["flag_codes"] == "FA",
        test_timeout(30).as_secs(),
    );
    let p = &all[0];
    let id = p["id"].as_u64().unwrap();
    assert_eq!(p["connection_type"], "inbound");
    assert_eq!(p["subver"], "/Satoshi:31.2.0/");
    assert_eq!(
        p["fingerprint"],
        json!({
            "result": "mismatch", "claimed": "core", "observed": "btcd", "settled": true,
            "handshake": ["version", "sendaddrv2", "verack", "getaddr"],
        })
    );
    assert_eq!(p["flags"][0]["evidence"], json!({"claimed": "core", "observed": "btcd"}));
    assert_eq!(p["flags"][1]["evidence"]["getaddr_in"], 2);
    assert_eq!(p["counters"]["getaddr_in"], 2);
    assert!(!p.to_string().contains("127.0.0.1"), "no address: {p}");

    // By id, and by name.
    assert_eq!(node.rpc_ok("getpeerbehavior", vec![json!(id)]), json!([p]));
    let named = node.rpc_call_with_named_params("getpeerbehavior", json!({"peer_id": id})).unwrap();
    assert_eq!(named["result"], json!([p]), "{named}");

    // Help lists it with the Network RPCs.
    let help = node.rpc_ok("help", vec![]);
    assert!(help.as_str().unwrap().contains("getpeerbehavior"));

    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics")).unwrap().text().unwrap();
    for line in [
        "satd_peer_flagged{flag=\"F\"} 1",
        "satd_peer_flagged{flag=\"A\"} 1",
        "satd_peer_flagged{flag=\"S\"} 0",
        "satd_peer_fingerprint{family=\"btcd\"} 1",
        "satd_peer_fingerprint{family=\"core\"} 0",
    ] {
        assert!(body.lines().any(|l| l == line), "missing `{line}` in\n{body}");
    }
    drop(peer);
    node.stop();
}
