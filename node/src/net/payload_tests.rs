//! `net::payload` against Bitcoin Core's message handlers. Every input is
//! built by hand, byte by byte, as a peer would send it.

use super::*;
use bitcoin::consensus::deserialize;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;

/// A v1 frame (regtest magic) with `command` and `payload` as given.
fn frame(command: &[u8], payload: &[u8]) -> Vec<u8> {
    assert!(command.len() <= 12);
    let mut v = vec![0xfa, 0xbf, 0xb5, 0xda];
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command);
    v.extend_from_slice(&cmd);
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&sha256d::Hash::hash(payload)[..4]);
    v.extend_from_slice(payload);
    v
}

fn cmd(s: &'static str) -> CommandString {
    CommandString::try_from_static(s).unwrap()
}

/// A network address as `version` carries it: services, IPv4-mapped IPv6,
/// big-endian port.
fn net_addr(services: u64, ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut v = services.to_le_bytes().to_vec();
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    v.extend_from_slice(&ip);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

/// The fields Core requires: version, services, time, receiver address.
fn version_required() -> Vec<u8> {
    let mut v = 70016u32.to_le_bytes().to_vec();
    v.extend_from_slice(&0x409u64.to_le_bytes());
    v.extend_from_slice(&1_700_000_000i64.to_le_bytes());
    v.extend(net_addr(0, [10, 0, 0, 1], 18444));
    v
}

/// A full `version` up to and including the start height, with no relay
/// byte: the shape a BIP 37-less peer sends.
fn version_without_relay() -> Vec<u8> {
    let mut v = version_required();
    v.extend(net_addr(0x409, [10, 0, 0, 2], 18444));
    v.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    v.push(11);
    v.extend_from_slice(b"/Gocoin:1./");
    v.extend_from_slice(&120_000i32.to_le_bytes());
    v
}

fn version(payload: &[u8]) -> Result<VersionMessage, encode::Error> {
    match decode_v1_frame(&frame(b"version", payload))? {
        NetworkMessage::Version(v) => Ok(v),
        other => panic!("not a version: {other:?}"),
    }
}

/// A `version` that ends after the start height is read with relay true,
/// Core's default (`net_processing.cpp:3594`, `3642`). rust-bitcoin refuses
/// it, and the handshake never completed.
#[test]
fn a_version_without_a_relay_byte_reads_with_relay_true() {
    let payload = version_without_relay();
    assert!(deserialize::<RawNetworkMessage>(&frame(b"version", &payload)).is_err(), "rust-bitcoin refuses it");
    let v = version(&payload).unwrap();
    assert_eq!(v.version, 70016);
    assert_eq!(v.services.to_u64(), 0x409);
    assert_eq!(v.timestamp, 1_700_000_000);
    assert_eq!(v.receiver.port, 18444);
    assert_eq!(v.sender.services.to_u64(), 0x409);
    assert_eq!(v.nonce, 0x0102_0304_0506_0708);
    assert_eq!(v.user_agent, "/Gocoin:1./");
    assert_eq!(v.start_height, 120_000);
    assert!(v.relay);

    let mut with_relay = payload.clone();
    with_relay.push(0);
    assert!(!version(&with_relay).unwrap().relay);
    *with_relay.last_mut().unwrap() = 2;
    assert!(version(&with_relay).unwrap().relay, "any non-zero byte is true");
}

/// Only the first four fields are required; each later one missing takes
/// Core's default: nonce 1, empty user agent, start height -1, relay true.
#[test]
fn a_version_with_only_its_required_fields_takes_cores_defaults() {
    let v = version(&version_required()).unwrap();
    assert_eq!((v.nonce, v.user_agent.as_str(), v.start_height, v.relay), (1, "", -1, true));
    assert_eq!(v.sender.port, 0);

    // A field cut short is refused, as Core's read throws.
    let required = version_required();
    assert!(version(&required[..required.len() - 1]).is_err());
    let mut half_sender = required.clone();
    half_sender.extend(&net_addr(1, [1, 2, 3, 4], 1)[..10]);
    assert!(version(&half_sender).is_err());
    let mut truncated_agent = version_without_relay();
    truncated_agent.truncate(required.len() + 26 + 8 + 5);
    assert!(version(&truncated_agent).is_err());
}

/// Core's `LIMITED_STRING(strSubVer, 256)` refuses a longer user agent; one
/// that is not UTF-8 is read (Core sanitizes it), where rust-bitcoin
/// refuses it.
#[test]
fn a_version_user_agent_is_read_as_core_reads_it() {
    let with_agent = |agent: &[u8]| {
        let mut v = version_required();
        v.extend(net_addr(0, [0; 4], 0));
        v.extend_from_slice(&7u64.to_le_bytes());
        v.extend(encode::serialize(&encode::VarInt(agent.len() as u64)));
        v.extend_from_slice(agent);
        v.extend_from_slice(&5i32.to_le_bytes());
        v.push(1);
        v
    };
    assert_eq!(version(&with_agent(&[b'a'; 256])).unwrap().user_agent.len(), 256);
    assert!(version(&with_agent(&[b'a'; 257])).is_err());

    let latin1 = with_agent(b"/caf\xe9/");
    assert!(deserialize::<RawNetworkMessage>(&frame(b"version", &latin1)).is_err(), "rust-bitcoin refuses it");
    let v = version(&latin1).unwrap();
    assert_eq!(v.user_agent, "/caf\u{fffd}/");
    assert_eq!(v.start_height, 5);
}

/// Bytes after the last field are ignored, as every Core handler ignores
/// them. rust-bitcoin 0.32.10+ refuses each of these frames.
#[test]
fn bytes_after_the_last_field_are_ignored() {
    let tail = [0xde, 0xad, 0xbe, 0xef];
    let with_tail = |payload: &[u8]| {
        let mut v = payload.to_vec();
        v.extend_from_slice(&tail);
        v
    };
    let mut full_version = version_without_relay();
    full_version.push(1);
    let mut inv = vec![1u8];
    inv.extend_from_slice(&1u32.to_le_bytes());
    inv.extend_from_slice(&[0x11; 32]);
    // A one-input, one-output legacy transaction.
    let mut tx = 1u32.to_le_bytes().to_vec();
    tx.push(1);
    tx.extend_from_slice(&[0x22; 32]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&1000u64.to_le_bytes());
    tx.extend_from_slice(&[1, 0x51]);
    tx.extend_from_slice(&0u32.to_le_bytes());

    let cases: Vec<(&[u8], Vec<u8>)> = vec![
        (b"version", full_version),
        (b"verack", vec![]),
        (b"sendheaders", vec![]),
        (b"wtxidrelay", vec![]),
        (b"sendaddrv2", vec![]),
        (b"getaddr", vec![]),
        (b"mempool", vec![]),
        (b"ping", 9u64.to_le_bytes().to_vec()),
        (b"pong", 9u64.to_le_bytes().to_vec()),
        (b"inv", inv),
        (b"tx", tx),
        (b"feefilter", 1000i64.to_le_bytes().to_vec()),
        (b"sendcmpct", [&[1u8][..], &2u64.to_le_bytes()].concat()),
    ];
    for (command, payload) in cases {
        let name = String::from_utf8_lossy(command).into_owned();
        let exact = decode_v1_frame(&frame(command, &payload)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let tailed = frame(command, &with_tail(&payload));
        assert!(deserialize::<RawNetworkMessage>(&tailed).is_err(), "{name}: rust-bitcoin refuses it");
        assert_eq!(decode_v1_frame(&tailed).unwrap(), exact, "{name}");
        assert_eq!(exact.cmd(), name);
    }
}

/// `sendcmpct`'s flag is a `bool`: Core reads any non-zero byte as true
/// (`src/serialize.h:279`). rust-bitcoin refuses a byte other than 0 or 1.
#[test]
fn a_sendcmpct_flag_is_any_non_zero_byte() {
    for (flag, expected) in [(0u8, false), (1, true), (2, true), (0xff, true)] {
        let payload = [&[flag][..], &2u64.to_le_bytes()].concat();
        let f = frame(b"sendcmpct", &payload);
        assert_eq!(deserialize::<RawNetworkMessage>(&f).is_ok(), flag <= 1, "rust-bitcoin, flag {flag}");
        assert_eq!(
            decode_v1_frame(&f).unwrap(),
            NetworkMessage::SendCmpct(SendCmpct { send_compact: expected, version: 2 }),
            "flag {flag}"
        );
    }
}

/// `feefilter` is read whatever its value; Core reads the `CAmount` and the
/// handler ignores one outside `MoneyRange` (`PeerManager::set_peer_fee_filter`).
#[test]
fn a_feefilter_is_read_whatever_its_value() {
    for rate in [-1i64, i64::MIN, 2_100_000_000_000_001, i64::MAX, 0, 1000] {
        let f = frame(b"feefilter", &rate.to_le_bytes());
        assert_eq!(decode_v1_frame(&f).unwrap(), NetworkMessage::FeeFilter(rate));
    }
    assert!(decode_v1_frame(&frame(b"feefilter", &[0; 7])).is_err(), "too short for an i64");
}

/// An inventory entry of type 0 (`MSG_ERROR`) carries a hash like any
/// other, and the entries after it are read in step, as Core's `CInv` reads
/// them. rust-bitcoin before 0.32.10 read no hash for it and misread the
/// rest of the list.
#[test]
fn an_inventory_entry_of_type_zero_keeps_the_list_in_step() {
    let mut inv = vec![2u8];
    inv.extend_from_slice(&0u32.to_le_bytes());
    inv.extend_from_slice(&[0x33; 32]);
    inv.extend_from_slice(&1u32.to_le_bytes());
    inv.extend_from_slice(&[0x44; 32]);
    let NetworkMessage::Inv(entries) = decode_v1_frame(&frame(b"inv", &inv)).unwrap() else { panic!("not inv") };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], Inventory::Unknown { inv_type: 0, hash: [0x33; 32] });
    assert!(entries[0].is_error());
    assert!(matches!(entries[1], Inventory::Transaction(t) if t.to_byte_array() == [0x44; 32]));
}

/// A message type with an embedded NUL is one Core drops
/// (`IsMessageTypeValid`). It must not be read as the type the bytes before
/// the NUL spell; rust-bitcoin before 0.32.10 dropped the NULs and read
/// `pi\0ng` as `ping`. A non-ASCII type is refused, as Core refuses it.
#[test]
fn message_types_core_drops_are_not_acted_on() {
    let nonce = 9u64.to_le_bytes();
    let got = decode_v1_frame(&frame(b"pi\0ng", &nonce)).unwrap();
    assert!(matches!(got, NetworkMessage::Unknown { ref command, .. } if command.as_ref() == "pi\0ng"), "{got:?}");
    let got = decode_v1_frame(&frame(b"ping\0\0\0\0\0\0\0x", &nonce)).unwrap();
    assert!(matches!(got, NetworkMessage::Unknown { .. }), "{got:?}");
    assert!(decode_v1_frame(&frame(b"p\xe9ng", &nonce)).is_err());
    // Trailing NULs are padding.
    assert_eq!(decode_v1_frame(&frame(b"ping", &nonce)).unwrap(), NetworkMessage::Ping(9));
}

/// An unknown type is passed on whole; a bad checksum or a short frame is
/// refused.
#[test]
fn unknown_types_pass_and_corrupt_frames_are_refused() {
    let got = decode_v1_frame(&frame(b"napatt", &[1, 2, 3])).unwrap();
    assert_eq!(got, NetworkMessage::Unknown { command: cmd("napatt"), payload: vec![1, 2, 3] });

    let mut bad = frame(b"ping", &9u64.to_le_bytes());
    bad[20] ^= 1;
    assert!(matches!(decode_v1_frame(&bad), Err(encode::Error::InvalidChecksum { .. })));
    let good = frame(b"ping", &9u64.to_le_bytes());
    assert!(decode_v1_frame(&good[..good.len() - 1]).is_err());
    assert!(decode_v1_frame(&good[..20]).is_err());
}

/// What rust-bitcoin writes reads back the same, for every message satd
/// sends during a handshake and relay.
#[test]
fn what_rust_bitcoin_writes_reads_back() {
    let v = version(&{
        let mut p = version_without_relay();
        p.push(1);
        p
    })
    .unwrap();
    for msg in [
        NetworkMessage::Version(v),
        NetworkMessage::Verack,
        NetworkMessage::Ping(3),
        NetworkMessage::FeeFilter(1000),
        NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }),
        NetworkMessage::Headers(vec![bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header]),
        NetworkMessage::Block(bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)),
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(bitcoin::BlockHash::all_zeros())]),
    ] {
        let wire = encode::serialize(&RawNetworkMessage::new(bitcoin::p2p::Magic::REGTEST, msg.clone()));
        assert_eq!(decode_v1_frame(&wire).unwrap(), msg);
    }
}
