//! The crawl's whole session against a live Bitcoin Core: a regtest satd
//! with `-crawl` learns Core's address, advertised with `NODE_P2P_V2`, from
//! the `getaddr` answer of a scripted v1 peer (its only seed; a seed
//! carries no services, so it alone would be dialled over v1), and runs
//! its discovery session to Core
//! (BIP 324, the crawler's `version`, `wtxidrelay`, `sendaddrv2`, `verack`,
//! one `getaddr`, the four probes, the `getheaders` one being the chain
//! check) and then its v1 recheck (the handshake over v1). Core, which does
//! not whitelist anyone here, must raise no misbehaviour against either
//! connection, close neither itself (each ends with Core reading our close:
//! "socket closed"), and ban nothing; and the crawl's book must record Core
//! reached over both transports, its `getaddr` answered, every probe
//! answered or silent, none disconnected, the chain check on chain (Core is
//! given satd's block first), and the fingerprint Core's, with high
//! confidence, from the crawl rows.
//!
//! Core's address book holds 1,000 routable addresses on a port Core's
//! `IsBadPort` lists (22), so its answer is a full one while the crawl,
//! which skips bad ports, dials none of them: nothing here leaves the host.
//!
//! The oracle is `$BITCOIND` if set (the Core version pinned by CORE_IMAGE
//! in scripts/canary/PINS, v32.1), else the `bitcoind` copied out of that
//! image with Docker:
//!
//! ```text
//! cargo test -p satd --test core_crawl_session --features core-p2p-differential
//! ```

#[path = "../../fuzz/src/p2p_diff.rs"]
mod p2p_diff;

mod common;

use common::{TestNode, test_timeout};
use node::net::crawlbook::{BookParams, ChainCheck, CrawlAddr, CrawlBook, GetaddrResult, CRAWL_FILE};
use node::net::fingerprint::{Confidence, Family, Fingerprint};
use node::net::survey::{Probe, ProbeOutcome};
use p2p_diff::CoreOracle;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// Core's id for each crawl connection, from its `version` line, in order.
fn crawl_ids(log: &[String]) -> Vec<String> {
    log.iter()
        .filter(|l| l.contains("receive version message: /satd:") && l.contains("(crawler)/"))
        .filter_map(|l| l.rsplit("peer=").next().map(|id| id.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").to_string()))
        .collect()
}

fn names_peer(line: &str, id: &str) -> bool {
    line.split(|c: char| !c.is_ascii_alphanumeric() && c != '=').any(|w| w == format!("peer={id}"))
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
    let raw: RawNetworkMessage = deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(raw.into_payload())
}

/// A scripted v1 peer whose `getaddr` answer names Core with
/// `NODE_P2P_V2`, next to a bad-port address the crawl skips (a one-entry
/// answer reads as the peer's own announcement). Returns its port.
fn referrer(core_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let answer = vec![
        AddrV2Message {
            time: now - 60,
            services: services | ServiceFlags::P2P_V2,
            addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
            port: core_port,
        },
        AddrV2Message { time: now - 60, services, addr: AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), port: 22 },
    ];
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let answer = answer.clone();
            std::thread::spawn(move || -> io::Result<()> {
                let mut stream = stream;
                stream.set_read_timeout(Some(Duration::from_secs(120)))?;
                loop {
                    match recv(&mut stream)? {
                        NetworkMessage::Version(_) => {
                            let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                            let v = VersionMessage {
                                version: 70016,
                                services,
                                timestamp: now as i64,
                                receiver: Address::new(&zero, ServiceFlags::NONE),
                                sender: Address::new(&zero, services),
                                nonce: 0x5eed,
                                user_agent: "/Satoshi:32.1.0/".into(),
                                start_height: 0,
                                relay: true,
                            };
                            send(&mut stream, NetworkMessage::Version(v))?;
                            send(&mut stream, NetworkMessage::WtxidRelay)?;
                            send(&mut stream, NetworkMessage::SendAddrV2)?;
                            send(&mut stream, NetworkMessage::Verack)?;
                        }
                        NetworkMessage::GetAddr => send(&mut stream, NetworkMessage::AddrV2(answer.clone()))?,
                        NetworkMessage::Ping(n) => send(&mut stream, NetworkMessage::Pong(n))?,
                        NetworkMessage::GetHeaders(_) => send(&mut stream, NetworkMessage::Headers(vec![]))?,
                        NetworkMessage::GetData(inv) => send(&mut stream, NetworkMessage::NotFound(inv))?,
                        _ => {}
                    }
                }
            });
        }
    });
    port
}

#[test]
fn the_crawl_session_is_handled_by_core_without_punishment() {
    let mut oracle = CoreOracle::start_without_whitelist().expect("start Bitcoin Core");
    for i in 0..1000u32 {
        let ip = format!("{}.{}.{}.1", 1 + i / 250, 1 + i % 250, 7);
        let _ = oracle.call("addpeeraddress", &[json!(ip), json!(22)]);
    }
    let core_port = oracle.p2p_port();
    let mut log = oracle.new_log_lines();

    let seed = format!("--crawlseed=127.0.0.1:{}", referrer(core_port));
    let mut node = TestNode::start(&["--maxconnections=0", "--crawl=1", &seed, "--loglevel=debug"]);
    // satd on Core's chain, one block past it, and Core given that block:
    // the chain check then finds our tip. The crawl's first probe comes
    // after its 10 s passive wait.
    let core_height = oracle.call("getblockcount", &[]).expect("getblockcount").as_u64().unwrap();
    for h in 1..=core_height {
        let hash = oracle.call("getblockhash", &[json!(h)]).expect("getblockhash");
        let raw = oracle.call("getblock", &[hash, json!(0)]).expect("getblock");
        node.rpc_ok("submitblock", vec![raw]);
    }
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    let tip = node.rpc_ok("getbestblockhash", vec![]);
    let raw = node.rpc_ok("getblock", vec![tip.clone(), json!(0)]);
    let took = oracle.call("submitblock", &[raw]).expect("submitblock");
    assert!(took.is_null(), "Core takes satd's block: {took}");
    assert_eq!(oracle.call("getbestblockhash", &[]).expect("getbestblockhash"), tip, "Core is on satd's chain");

    // Both sessions: Core logs each crawl version, then our close.
    let deadline = Instant::now() + test_timeout(240);
    loop {
        log.extend(oracle.new_log_lines());
        let ids = crawl_ids(&log);
        let closed = ids
            .iter()
            .filter(|id| log.iter().any(|l| names_peer(l, id) && l.contains("socket closed")))
            .count();
        if ids.len() >= 2 && closed >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "two crawl sessions, each closed by us: {:#?}", log);
        std::thread::sleep(Duration::from_millis(500));
    }
    std::thread::sleep(Duration::from_millis(500));
    log.extend(oracle.new_log_lines());
    node.stop();

    let ids = crawl_ids(&log);
    for id in &ids[..2] {
        let about: Vec<&String> = log.iter().filter(|l| names_peer(l, id)).collect();
        let punished: Vec<&&String> = about
            .iter()
            .filter(|l| l.contains("Misbehaving") || (l.contains("disconnecting") && !l.contains("socket closed")))
            .collect();
        assert!(punished.is_empty(), "Core punished or dropped crawl peer={id}: {punished:#?}\n{about:#?}");
    }
    // The discovery session: Core read the getaddr and every probe.
    let first: Vec<&String> = log.iter().filter(|l| names_peer(l, &ids[0])).collect();
    for cmd in ["getaddr", "ping", "getheaders", "getdata"] {
        assert!(
            first.iter().any(|l| l.contains(&format!("received: {cmd} "))),
            "Core received {cmd} on the discovery session: {first:#?}"
        );
    }
    assert!(first.iter().any(|l| l.contains("Unknown message type")), "the unknown-message probe: {first:#?}");
    let banned = oracle.call("listbanned", &[]).expect("listbanned");
    assert_eq!(banned.as_array().map_or(0, Vec::len), 0, "Core banned nothing");

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let book = CrawlBook::load(
        &node.datadir.join("regtest").join(CRAWL_FILE),
        bitcoin::p2p::Magic::REGTEST.to_bytes(),
        now,
        BookParams::for_network(bitcoin::Network::Regtest),
    )
    .unwrap();
    let core = node::net::peer::PeerAddr::Socket(([127, 0, 0, 1], core_port).into());
    let e = book.get(&CrawlAddr::Peer(core)).expect("Core in the book");
    assert_eq!((e.v2_ok, e.v1_ok, e.v2_only), (Some(true), Some(true), false));
    let obs = e.observation.as_ref().unwrap();
    assert!(obs.user_agent.starts_with("/Satoshi:32.1"), "{obs:?}");
    assert!(matches!(obs.getaddr, Some(GetaddrResult::Answered { entries, .. }) if entries > 1), "{obs:?}");
    for p in Probe::ALL {
        assert!(
            matches!(obs.probes.get(p), Some(ProbeOutcome::Answered(_) | ProbeOutcome::Silent)),
            "{}: {:?}",
            p.name(),
            obs.probes.get(p)
        );
    }
    assert_eq!(obs.chain_check, Some(ChainCheck::OnChain), "{obs:?}");
    assert_eq!(obs.fingerprint, Fingerprint::Known(Family::Core, Confidence::High), "{obs:?}");
    assert_eq!(obs.shape, None);
    assert_eq!(book.len(), 2, "Core and the referrer: no bad-port address entered the book");
}
