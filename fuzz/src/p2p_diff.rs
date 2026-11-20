//! P2P message decoding differential against Bitcoin Core (#1135).
//!
//! satd reads P2P messages with its own readers (`node::net::payload`,
//! `node::net::addrv2`) on top of rust-bitcoin's decoders. Where those are
//! stricter than Core, satd drops messages that Core and every Core peer
//! treat as valid, and a test whose inputs come from the same libraries
//! never notices. This module replays one message at a time against a real
//! regtest `bitcoind` over a P2P connection and compares what each side made
//! of it.
//!
//! It is used by two drivers, which share this file:
//!
//!   * the `p2p_differential` fuzz target (`fuzz/fuzz_targets/`), run nightly
//!     by `scripts/fuzz/run-standalone-targets.sh`; and
//!   * the `core_p2p_differential` integration test (`satd/tests/`), which
//!     replays the seed cases below on pull requests that touch the decoders.
//!
//! ## The oracle
//!
//! Core is driven as a peer, not linked. Each message goes over a v1 or a v2
//! (BIP 324) connection that has completed the handshake, followed by a
//! `ping`. Core handles a peer's messages in order, so once the `pong` is
//! back the message has been handled, and the lines Core wrote to
//! `debug.log` (`-debug=net`, unbuffered) say what it made of it:
//!
//!   * **ignore** -- dropped before any handler: a v1 header error
//!     (`V1Transport::GetReceivedMessage`, `src/net.cpp:826-840`), a v2
//!     message type that does not parse (`V2Transport::GetReceivedMessage`,
//!     `src/net.cpp:1477`), or a type no handler knows
//!     (`net_processing.cpp:5360`);
//!   * **reject** -- the handler's read threw, which `ProcessMessages`
//!     catches and logs (`net_processing.cpp:5493`);
//!   * **accept** -- the handler was entered (`received: <type>`,
//!     `net_processing.cpp:3834`) and nothing threw.
//!
//! `version` is handled on a connection of its own: it is only read as the
//! first message. A second, valid `version` follows it; Core calls that one
//! redundant if it accepted the first, and reads it if it did not.
//!
//! ## What counts as a divergence
//!
//! The verdicts differ (satd's verdict comes from the same readers its
//! connection loop uses), or both accept and a decoded field Core exposes
//! differs. Core exposes few:
//!
//!   * `version`: version, start height, relay flag and user agent
//!     (`receive version message`, `net_processing.cpp:3950`), and the
//!     service bits (`getpeerinfo`);
//!   * `addr`, `addrv2`: the entry count (`Received addr`,
//!     `net_processing.cpp:6046`, or the `MAX_ADDR_TO_SEND` refusal);
//!   * `getdata`: the entry count (`net_processing.cpp:4452`); `inv` only
//!     past `MAX_INV_SZ`;
//!   * `tx`: txid and wtxid (`AcceptToMemoryPool`, accepted or not);
//!   * `block`: the block hash (`received block`).
//!
//! Every other command (`headers`, `cmpctblock`, `blocktxn`, `getblocktxn`,
//! `feefilter`, `sendcmpct`) is compared on the verdict only.
//!
//! Message-handling policy is out of scope: count caps, `MoneyRange`, and
//! misbehaviour. Core runs with `-whitelist=noban@127.0.0.1`, so a
//! misbehaving message does not cost the connection. Where a cap stops Core
//! before it reads the message (`headers` over 2000), or Core stops for a
//! policy reason before the read is complete (`version` below
//! `MIN_PEER_PROTO_VERSION`), the case is skipped: Core gave no verdict on
//! the decoding. [`ALLOWED`] lists deliberate differences; it is empty.

#![allow(dead_code)]

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{self, serialize, Decodable, Encodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use node::net::addrv2::{AddrV2DecodeError, ADDRV2_COMMAND};
use node::net::v2transport::V2CodecError;

/// The commands satd reads that this differential covers (#1135).
pub const COMMANDS: [&str; 13] = [
    "version",
    "addr",
    "addrv2",
    "inv",
    "getdata",
    "headers",
    "cmpctblock",
    "blocktxn",
    "getblocktxn",
    "feefilter",
    "sendcmpct",
    "tx",
    "block",
];

/// Message types Core or satd knows that are not covered here. A case that
/// names one is skipped: neither side would call it unknown, and their
/// handlers are not what this differential compares.
const OTHER_KNOWN: [&str; 26] = [
    "verack", "getaddr", "mempool", "ping", "pong", "notfound", "filterload", "filteradd",
    "filterclear", "getblocks", "getheaders", "sendheaders", "merkleblock", "getcfilters",
    "cfilter", "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "wtxidrelay",
    "sendtxrcncl", "sendaddrv2", "feature", "alert", "reject", "checkorder",
];

/// Core's `V2_MESSAGE_IDS` (`src/net.cpp:925`, v32.1): the type each BIP 324
/// short id stands for. An empty name is an unimplemented id, which Core
/// reads as the empty message type and its handler drops as unknown.
const CORE_V2_MESSAGE_IDS: [&str; 38] = [
    "", "addr", "block", "blocktxn", "cmpctblock", "feefilter", "filteradd", "filterclear",
    "filterload", "getblocks", "getblocktxn", "getdata", "getheaders", "headers", "inv",
    "mempool", "merkleblock", "notfound", "ping", "pong", "sendcmpct", "tx", "getcfilters",
    "cfilter", "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "addrv2", "", "", "",
    "", "", "", "", "", "feature",
];

/// Largest payload a case carries. Far below Core's 4 MB message limit,
/// which ends the connection rather than giving a verdict.
pub const MAX_CASE_PAYLOAD: usize = 1 << 20;

/// User agent of the `version` sent after a fuzzed one. Core logs it when it
/// reads it, which is how a refused fuzzed `version` is told apart from an
/// accepted one.
const PROBE_USER_AGENT: &str = "/p2pdiff-probe:0.1/";

/// How a case's message type is put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// A v1 frame with this 12-byte command field, and a correct checksum
    /// unless `bad_checksum`.
    V1 { command: [u8; 12], bad_checksum: bool },
    /// v2 contents starting with this BIP 324 short id (never 0).
    V2Short(u8),
    /// v2 contents in the long form: a zero byte, then these 12 bytes.
    V2Long([u8; 12]),
}

/// One message to compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

/// What a case's message type is, as Core reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeName {
    /// One of [`COMMANDS`].
    Named(&'static str),
    /// A type no handler knows, or one that does not parse.
    Unknown,
    /// One of [`OTHER_KNOWN`]: not compared.
    OtherKnown,
}

fn command_bytes(name: &str) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

fn short_id(name: &str) -> Option<u8> {
    CORE_V2_MESSAGE_IDS.iter().position(|n| !n.is_empty() && *n == name).map(|i| i as u8)
}

/// Core's reading of a 12-byte message type field: printable ASCII up to the
/// first NUL and only NULs after it (`CMessageHeader::IsMessageTypeValid`,
/// `src/protocol.cpp`; the same rule in `V2Transport::GetMessageType`).
fn core_message_type(field: &[u8; 12]) -> Option<String> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(12);
    if field[..end].iter().any(|&b| !(b' '..=0x7e).contains(&b)) {
        return None;
    }
    if field[end..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(String::from_utf8(field[..end].to_vec()).expect("printable ASCII"))
}

fn classify_name(name: &str) -> TypeName {
    if let Some(n) = COMMANDS.iter().find(|n| **n == name) {
        TypeName::Named(n)
    } else if OTHER_KNOWN.contains(&name) {
        TypeName::OtherKnown
    } else {
        TypeName::Unknown
    }
}

impl Case {
    pub fn v1(name: &str, payload: Vec<u8>) -> Self {
        Case { msg_type: MsgType::V1 { command: command_bytes(name), bad_checksum: false }, payload }
    }

    pub fn v2_short(name: &str, payload: Vec<u8>) -> Self {
        Case { msg_type: MsgType::V2Short(short_id(name).expect("has a short id")), payload }
    }

    pub fn v2_long(name: &str, payload: Vec<u8>) -> Self {
        Case { msg_type: MsgType::V2Long(command_bytes(name)), payload }
    }

    /// Read a case from fuzzer bytes: a transport byte (v1, v2 short id, v2
    /// long form), a command byte (an index into [`COMMANDS`], or the last
    /// value for a raw type: 12 bytes, or one short id byte, from the
    /// front of the rest), a flags byte (bit 0: a wrong v1 checksum), then
    /// the payload.
    pub fn from_bytes(data: &[u8]) -> Option<Case> {
        let (&transport, rest) = data.split_first()?;
        let (&sel, rest) = rest.split_first()?;
        let (&flags, rest) = rest.split_first()?;
        let transport = transport % 3;
        let sel = (sel as usize) % (COMMANDS.len() + 1);
        let bad_checksum = flags & 1 == 1;
        let (msg_type, payload) = if sel < COMMANDS.len() {
            let name = COMMANDS[sel];
            let mt = match (transport, short_id(name)) {
                (0, _) => MsgType::V1 { command: command_bytes(name), bad_checksum },
                (1, Some(id)) => MsgType::V2Short(id),
                _ => MsgType::V2Long(command_bytes(name)),
            };
            (mt, rest)
        } else if transport == 1 {
            let (&id, rest) = rest.split_first()?;
            if id == 0 {
                return None;
            }
            (MsgType::V2Short(id), rest)
        } else {
            if rest.len() < 12 {
                return None;
            }
            let (field, rest) = rest.split_at(12);
            let field: [u8; 12] = field.try_into().expect("12 bytes");
            if transport == 0 {
                (MsgType::V1 { command: field, bad_checksum }, rest)
            } else {
                (MsgType::V2Long(field), rest)
            }
        };
        if payload.len() > MAX_CASE_PAYLOAD {
            return None;
        }
        Some(Case { msg_type, payload: payload.to_vec() })
    }

    /// The fuzzer bytes [`Case::from_bytes`] reads back as this case.
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw = COMMANDS.len() as u8;
        let mut out = Vec::new();
        match &self.msg_type {
            MsgType::V1 { command, bad_checksum } => {
                let flags = u8::from(*bad_checksum);
                match COMMANDS.iter().position(|n| command_bytes(n) == *command) {
                    Some(i) => out.extend([0, i as u8, flags]),
                    None => {
                        out.extend([0, raw, flags]);
                        out.extend(command);
                    }
                }
            }
            MsgType::V2Short(id) => {
                let name = CORE_V2_MESSAGE_IDS.get(*id as usize).copied().unwrap_or("");
                match COMMANDS.iter().position(|n| *n == name && !name.is_empty()) {
                    Some(i) => out.extend([1, i as u8, 0]),
                    None => out.extend([1, raw, 0, *id]),
                }
            }
            MsgType::V2Long(field) => {
                // A named type with a short id would read back as the short
                // form, so the long form of a named type is written raw.
                match COMMANDS.iter().position(|n| command_bytes(n) == *field && short_id(n).is_none()) {
                    Some(i) => out.extend([2, i as u8, 0]),
                    None => {
                        out.extend([2, raw, 0]);
                        out.extend(field);
                    }
                }
            }
        }
        out.extend(&self.payload);
        out
    }

    /// The message type as Core reads it.
    pub fn type_name(&self) -> TypeName {
        match &self.msg_type {
            MsgType::V1 { command, .. } | MsgType::V2Long(command) => match core_message_type(command) {
                Some(name) => classify_name(&name),
                None => TypeName::Unknown,
            },
            MsgType::V2Short(id) => match CORE_V2_MESSAGE_IDS.get(*id as usize) {
                Some(name) if !name.is_empty() => classify_name(name),
                _ => TypeName::Unknown,
            },
        }
    }

    fn is_v2(&self) -> bool {
        !matches!(self.msg_type, MsgType::V1 { .. })
    }

    /// The v1 frame, magic through payload.
    fn v1_frame(&self) -> Vec<u8> {
        let MsgType::V1 { command, bad_checksum } = &self.msg_type else { panic!("not a v1 case") };
        let mut frame = Vec::with_capacity(24 + self.payload.len());
        frame.extend(Magic::from(Network::Regtest).to_bytes());
        frame.extend(command);
        frame.extend((self.payload.len() as u32).to_le_bytes());
        let mut checksum: [u8; 4] = sha256d::Hash::hash(&self.payload)[..4].try_into().expect("4 bytes");
        if *bad_checksum {
            checksum[0] ^= 0xff;
        }
        frame.extend(checksum);
        frame.extend(&self.payload);
        frame
    }

    /// The v2 contents: message type, then payload.
    fn v2_contents(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.payload.len());
        match &self.msg_type {
            MsgType::V2Short(id) => out.push(*id),
            MsgType::V2Long(field) => {
                out.push(0);
                out.extend(field);
            }
            MsgType::V1 { .. } => panic!("not a v2 case"),
        }
        out.extend(&self.payload);
        out
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.msg_type {
            MsgType::V1 { command, bad_checksum } => {
                write!(f, "v1 command={}", hex::encode(command))?;
                if *bad_checksum {
                    write!(f, " (bad checksum)")?;
                }
            }
            MsgType::V2Short(id) => write!(f, "v2 short id {id}")?,
            MsgType::V2Long(field) => write!(f, "v2 long type={}", hex::encode(field))?,
        }
        write!(f, " [{:?}] payload ({} bytes)={}", self.type_name(), self.payload.len(), hex::encode(&self.payload))
    }
}

// ---------------------------------------------------------------------------
// satd's verdict
// ---------------------------------------------------------------------------

/// What satd made of a case.
#[derive(Debug)]
pub enum SatdVerdict {
    Accept(Box<NetworkMessage>),
    Reject(String),
    Ignore(String),
}

/// Decode a case with the readers satd's connection loops use. The v1 path
/// is `recv_message`'s dispatch (`node/src/net/connection.rs`): `addrv2`
/// through `net::addrv2`, every other frame through
/// `net::payload::decode_v1_frame`. The v2 path is
/// `net::v2transport::decode_message`. Either loop skips a message that does
/// not decode and hands on what does; an `Unknown` message reaches no
/// handler.
pub fn satd_decode(case: &Case) -> SatdVerdict {
    match &case.msg_type {
        MsgType::V1 { command, .. } => {
            let frame = case.v1_frame();
            if *command == ADDRV2_COMMAND {
                return match node::net::addrv2::decode_v1_payload(&frame[..24], &case.payload) {
                    Ok(addrs) => SatdVerdict::Accept(Box::new(NetworkMessage::AddrV2(addrs))),
                    Err(AddrV2DecodeError::BadChecksum) => SatdVerdict::Ignore("bad checksum".into()),
                    Err(e) => SatdVerdict::Reject(e.to_string()),
                };
            }
            match node::net::payload::decode_v1_frame(&frame) {
                Ok(NetworkMessage::Unknown { .. }) => SatdVerdict::Ignore("unknown message type".into()),
                Ok(msg) => SatdVerdict::Accept(Box::new(msg)),
                Err(encode::Error::InvalidChecksum { .. }) => SatdVerdict::Ignore("bad checksum".into()),
                Err(e) => {
                    if CommandString::consensus_decode(&mut &command[..]).is_err() {
                        SatdVerdict::Ignore(format!("message type: {e}"))
                    } else {
                        SatdVerdict::Reject(e.to_string())
                    }
                }
            }
        }
        MsgType::V2Short(_) | MsgType::V2Long(_) => {
            let contents = case.v2_contents();
            match node::net::v2transport::decode_message(&contents) {
                Ok(NetworkMessage::Unknown { .. }) => SatdVerdict::Ignore("unknown message type".into()),
                Ok(msg) => SatdVerdict::Accept(Box::new(msg)),
                Err(V2CodecError::Truncated) => SatdVerdict::Ignore("truncated message type".into()),
                Err(e) => {
                    let type_failed = match &case.msg_type {
                        MsgType::V2Short(id) => e.to_string().contains(&format!("unknown short message id {id}")),
                        MsgType::V2Long(field) => CommandString::consensus_decode(&mut &field[..]).is_err(),
                        MsgType::V1 { .. } => unreachable!(),
                    };
                    if type_failed {
                        SatdVerdict::Ignore(format!("message type: {e}"))
                    } else {
                        SatdVerdict::Reject(e.to_string())
                    }
                }
            }
        }
    }
}

/// Decoded fields of a `version`, as Core reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionFields {
    pub version: i32,
    pub start_height: i32,
    pub relay: bool,
    /// Sanitized as Core's `SanitizeString`, `<no user agent>` when empty.
    pub user_agent: String,
    /// `None` on the Core side when `getpeerinfo` could not be read.
    pub services: Option<u64>,
}

/// The decoded content a side reports. Core reports a subset; each field it
/// reports is compared.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    pub version: Option<VersionFields>,
    pub count: Option<usize>,
    /// (txid, wtxid)
    pub tx: Option<(String, String)>,
    pub block: Option<String>,
}

fn user_agent_as_core_logs(raw: &str) -> String {
    let clean = node::net::limits::sanitize_string(raw);
    if clean.is_empty() { "<no user agent>".to_string() } else { clean }
}

/// The fields of satd's decoded message that Core can report.
pub fn satd_observed(msg: &NetworkMessage) -> Observed {
    let mut o = Observed::default();
    match msg {
        NetworkMessage::Version(v) => {
            o.version = Some(VersionFields {
                version: v.version as i32,
                start_height: v.start_height,
                relay: v.relay,
                user_agent: user_agent_as_core_logs(&v.user_agent),
                services: Some(v.services.to_u64()),
            })
        }
        NetworkMessage::Addr(a) => o.count = Some(a.len()),
        NetworkMessage::AddrV2(a) => o.count = Some(a.len()),
        NetworkMessage::Inv(i) | NetworkMessage::GetData(i) => o.count = Some(i.len()),
        NetworkMessage::Headers(h) => o.count = Some(h.len()),
        NetworkMessage::Tx(tx) => o.tx = Some((tx.compute_txid().to_string(), tx.compute_wtxid().to_string())),
        NetworkMessage::Block(b) => o.block = Some(b.block_hash().to_string()),
        _ => {}
    }
    o
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/// What Core made of a case.
#[derive(Clone, Debug)]
pub enum CoreVerdict {
    Accept(Observed),
    Reject(String),
    Ignore(String),
    /// Core gave no verdict on the decoding (a policy stop, a dropped
    /// connection). The case is skipped.
    Unobservable(String),
}

/// The result of comparing one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Agree,
    Skipped(String),
    Allowed(&'static str),
    Diverge(String),
}

/// A deliberate difference: a matcher over the case and both verdicts, and
/// why it is deliberate. Add an entry only for a difference satd keeps on
/// purpose, with its reason; a bug is fixed, not listed.
pub struct Allowed {
    pub matches: fn(&Case, &SatdVerdict, &CoreVerdict) -> bool,
    pub why: &'static str,
}

/// Deliberate differences. None so far.
pub const ALLOWED: &[Allowed] = &[];

fn verdict_word(s: &SatdVerdict) -> &'static str {
    match s {
        SatdVerdict::Accept(_) => "accept",
        SatdVerdict::Reject(_) => "reject",
        SatdVerdict::Ignore(_) => "ignore",
    }
}

/// Compare satd's and Core's verdicts on one case.
pub fn compare(case: &Case, satd: &SatdVerdict, core: &CoreVerdict) -> Outcome {
    let diverge = match (satd, core) {
        (_, CoreVerdict::Unobservable(why)) => return Outcome::Skipped(why.clone()),
        (SatdVerdict::Accept(msg), CoreVerdict::Accept(core_seen)) => {
            let ours = satd_observed(msg);
            let mut diffs = Vec::new();
            if let Some(cv) = &core_seen.version {
                match &ours.version {
                    None => diffs.push(format!("Core read a version, satd read {}", msg.cmd())),
                    Some(sv) => {
                        let mut sv = sv.clone();
                        if cv.services.is_none() {
                            sv.services = None;
                        }
                        if sv != *cv {
                            diffs.push(format!("version fields: satd {sv:?}, Core {cv:?}"));
                        }
                    }
                }
            }
            if let Some(n) = core_seen.count
                && ours.count != Some(n)
            {
                diffs.push(format!("entry count: satd {:?}, Core {n}", ours.count));
            }
            if let Some(t) = &core_seen.tx
                && ours.tx.as_ref() != Some(t)
            {
                diffs.push(format!("tx ids: satd {:?}, Core {t:?}", ours.tx));
            }
            if let Some(b) = &core_seen.block
                && ours.block.as_ref() != Some(b)
            {
                diffs.push(format!("block hash: satd {:?}, Core {b}", ours.block));
            }
            if diffs.is_empty() {
                return Outcome::Agree;
            }
            diffs.join("; ")
        }
        (SatdVerdict::Reject(_), CoreVerdict::Reject(_)) | (SatdVerdict::Ignore(_), CoreVerdict::Ignore(_)) => {
            return Outcome::Agree;
        }
        (s, c) => format!("satd {} ({}), Core {c:?}", verdict_word(s), match s {
            SatdVerdict::Accept(m) => m.cmd().to_string(),
            SatdVerdict::Reject(e) | SatdVerdict::Ignore(e) => e.clone(),
        }),
    };
    if let Some(a) = ALLOWED.iter().find(|a| (a.matches)(case, satd, core)) {
        return Outcome::Allowed(a.why);
    }
    Outcome::Diverge(diverge)
}

// ---------------------------------------------------------------------------
// The Core oracle
// ---------------------------------------------------------------------------

/// The canary manifest's Core image, so this differential, the block
/// differential and the canaries run the same reference node.
pub fn core_image() -> &'static str {
    include_str!("../../scripts/canary/PINS")
        .lines()
        .find_map(|line| line.strip_prefix("CORE_IMAGE="))
        .expect("scripts/canary/PINS has a CORE_IMAGE line")
}

/// The Core version in the pinned image's tag (`bitcoin/bitcoin:32.1@...`).
pub fn core_version() -> &'static str {
    let image = core_image();
    let tag = image.split_once(':').map(|(_, t)| t).unwrap_or(image);
    tag.split('@').next().unwrap_or(tag)
}

fn free_port() -> io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn scratch_root() -> PathBuf {
    std::env::var_os("P2P_DIFF_TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

/// The `bitcoind` to run: `$BITCOIND` if set, else the binary copied out of
/// the pinned image (`docker create` + `docker cp`; nothing runs in Docker).
/// Its version must be the pinned one.
fn bitcoind_binary(work: &Path) -> Result<PathBuf, String> {
    let path = match std::env::var_os("BITCOIND") {
        Some(p) => PathBuf::from(p),
        None => {
            let image = core_image();
            let name = format!("satd-p2pdiff-extract-{}", std::process::id());
            let _ = Command::new("docker").args(["rm", "-f", &name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            let out = Command::new("docker")
                .args(["create", "--name", &name, image])
                .output()
                .map_err(|e| format!("could not run docker (set BITCOIND to a bitcoind {}): {e}", core_version()))?;
            if !out.status.success() {
                return Err(format!("docker create {image} failed: {}", String::from_utf8_lossy(&out.stderr)));
            }
            let dest = work.join("bitcoind");
            let src = format!("{name}:/opt/bitcoin-{}/bin/bitcoind", core_version());
            let cp = Command::new("docker").args(["cp", &src]).arg(&dest).output();
            let _ = Command::new("docker").args(["rm", "-f", &name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
            match cp {
                Ok(o) if o.status.success() => dest,
                Ok(o) => return Err(format!("docker cp {src} failed: {}", String::from_utf8_lossy(&o.stderr))),
                Err(e) => return Err(format!("docker cp failed: {e}")),
            }
        }
    };
    let out = Command::new(&path)
        .arg("-version")
        .output()
        .map_err(|e| format!("could not run {}: {e}", path.display()))?;
    let first = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").to_string();
    let want = format!("v{}.", core_version());
    if !first.contains(&want) {
        return Err(format!(
            "{} reports {first:?}; the oracle must be Bitcoin Core {} (CORE_IMAGE in scripts/canary/PINS)",
            path.display(),
            core_version()
        ));
    }
    Ok(path)
}

enum Conn {
    V1(TcpStream),
    V2(Box<bip324::io::Protocol<TcpStream, TcpStream>>),
}

/// One P2P connection to Core.
struct Peer {
    conn: Conn,
    stream: TcpStream,
    local_port: u16,
}

const MAGIC: Magic = Magic::REGTEST;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

impl Peer {
    fn connect(port: u16, v2: bool) -> Result<Peer, String> {
        let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
        let local_port = stream.local_addr().map_err(|e| e.to_string())?.port();
        let clone = || stream.try_clone().map_err(|e| e.to_string());
        let conn = if v2 {
            let proto = bip324::io::Protocol::new(
                Network::Regtest,
                bip324::Role::Initiator,
                None,
                None,
                clone()?,
                clone()?,
            )
            .map_err(|e| format!("v2 handshake: {e:?}"))?;
            Conn::V2(Box::new(proto))
        } else {
            Conn::V1(clone()?)
        };
        Ok(Peer { conn, stream, local_port })
    }

    /// Whether Core has closed the connection: a non-blocking peek that
    /// reads end of stream. Bytes waiting to be read are not a close.
    fn closed_by_core(&self) -> bool {
        if self.stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut b = [0u8; 1];
        let closed = matches!(self.stream.peek(&mut b), Ok(0))
            || matches!(self.stream.peek(&mut b), Err(e) if e.kind() != io::ErrorKind::WouldBlock);
        let _ = self.stream.set_nonblocking(false);
        closed
    }

    fn send_raw(&mut self, case: &Case) -> Result<(), String> {
        match &mut self.conn {
            Conn::V1(s) => s.write_all(&case.v1_frame()).map_err(|e| e.to_string()),
            Conn::V2(p) => p.write(&bip324::io::Payload::genuine(case.v2_contents())).map_err(|e| format!("{e:?}")),
        }
    }

    fn send(&mut self, msg: NetworkMessage) -> Result<(), String> {
        match &mut self.conn {
            Conn::V1(s) => s.write_all(&serialize(&RawNetworkMessage::new(MAGIC, msg))).map_err(|e| e.to_string()),
            Conn::V2(p) => p
                .write(&bip324::io::Payload::genuine(node::net::v2transport::encode_message(msg)))
                .map_err(|e| format!("{e:?}")),
        }
    }

    /// The next message from Core: its type and payload.
    fn recv(&mut self) -> Result<(String, Vec<u8>), String> {
        match &mut self.conn {
            Conn::V1(s) => {
                let mut header = [0u8; 24];
                s.read_exact(&mut header).map_err(|e| e.to_string())?;
                let len = u32::from_le_bytes(header[16..20].try_into().expect("4 bytes")) as usize;
                let mut payload = vec![0u8; len];
                s.read_exact(&mut payload).map_err(|e| e.to_string())?;
                let field: [u8; 12] = header[4..16].try_into().expect("12 bytes");
                Ok((core_message_type(&field).unwrap_or_default(), payload))
            }
            Conn::V2(p) => loop {
                let packet = p.read().map_err(|e| format!("{e:?}"))?;
                if packet.packet_type() == bip324::PacketType::Decoy {
                    continue;
                }
                let c = packet.contents();
                let Some((&first, rest)) = c.split_first() else { continue };
                if first == 0 {
                    if rest.len() < 12 {
                        continue;
                    }
                    let field: [u8; 12] = rest[..12].try_into().expect("12 bytes");
                    return Ok((core_message_type(&field).unwrap_or_default(), rest[12..].to_vec()));
                }
                let name = CORE_V2_MESSAGE_IDS.get(first as usize).copied().unwrap_or("");
                return Ok((name.to_string(), rest.to_vec()));
            },
        }
    }

    /// Send a `ping` and read until its `pong`, answering Core's pings.
    fn sync(&mut self, nonce: u64) -> Result<(), String> {
        self.send(NetworkMessage::Ping(nonce))?;
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                return Err("no pong".into());
            }
            let (cmd, payload) = self.recv()?;
            match cmd.as_str() {
                "ping" if payload.len() >= 8 => {
                    let n = u64::from_le_bytes(payload[..8].try_into().expect("8 bytes"));
                    self.send(NetworkMessage::Pong(n))?;
                }
                "pong" if payload.len() >= 8 && u64::from_le_bytes(payload[..8].try_into().expect("8 bytes")) == nonce => {
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    /// Complete the handshake: our `version`, Core's `verack`, ours, and a
    /// `sendcmpct` (version 2) so Core reads the `cmpctblock`s it is sent
    /// (`net_processing.cpp:4795`).
    fn handshake(&mut self, nonce: u64) -> Result<(), String> {
        self.send(NetworkMessage::Version(our_version(nonce, "/p2pdiff:0.1/")))?;
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                return Err("no verack".into());
            }
            let (cmd, _) = self.recv()?;
            if cmd == "verack" {
                break;
            }
        }
        self.send(NetworkMessage::Verack)?;
        self.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: 2 }))?;
        self.sync(nonce ^ 0x5a5a)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

fn our_version(nonce: u64, user_agent: &str) -> VersionMessage {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    version_at(now, nonce, user_agent)
}

fn version_at(timestamp: i64, nonce: u64, user_agent: &str) -> VersionMessage {
    let local = Address::new(&"127.0.0.1:0".parse().expect("addr"), ServiceFlags::NONE);
    let mut v = VersionMessage::new(
        ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp,
        local.clone(),
        local,
        nonce,
        user_agent.to_string(),
        0,
    );
    v.version = 70016;
    v.relay = true;
    v
}

/// A resident regtest `bitcoind` and a v1 and a v2 connection to it.
pub struct CoreOracle {
    daemon: Daemon,
    work: WorkDir,
    log: std::fs::File,
    /// Bytes of a line Core has not finished writing.
    log_partial: Vec<u8>,
    rpc: Client,
    p2p_port: u16,
    v1: Option<Peer>,
    v2: Option<Peer>,
    nonce: u64,
    /// Cases compared, skipped (by reason) -- for the run's summary.
    pub stats: Stats,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub compared: u64,
    pub skipped: std::collections::BTreeMap<String, u64>,
    pub reconnects: u64,
}

impl CoreOracle {
    /// Start `bitcoind`, mine one block so it leaves initial block download
    /// (Core drops a `tx` unread during IBD, `net_processing.cpp:4718`), and
    /// connect.
    ///
    /// The ports are picked free and then handed to `bitcoind`, so another
    /// process can take one in between; startup is tried three times.
    pub fn start() -> Result<CoreOracle, String> {
        let mut last = String::new();
        for attempt in 1..=3 {
            match Self::start_once() {
                Ok(oracle) => return Ok(oracle),
                Err(e) => {
                    eprintln!("p2p-differential: starting Bitcoin Core, attempt {attempt}: {e}");
                    last = e;
                }
            }
        }
        Err(last)
    }

    fn start_once() -> Result<CoreOracle, String> {
        let work = scratch_root().join(format!("satd-p2pdiff-{}-{}", std::process::id(), free_port().map_err(|e| e.to_string())?));
        std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
        // Removed on every early return below, and with the oracle.
        let work = WorkDir(work);
        let bitcoind = bitcoind_binary(&work.0)?;
        let datadir = work.0.join("data");
        std::fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;
        let rpc_port = free_port().map_err(|e| e.to_string())?;
        let p2p_port = free_port().map_err(|e| e.to_string())?;
        let (user, pass) = ("p2pdiff", format!("pw{rpc_port}"));
        let mut args: Vec<String> = vec![
            "-regtest".into(),
            format!("-datadir={}", datadir.display()),
            "-server=1".into(),
            "-rpcbind=127.0.0.1".into(),
            "-rpcallowip=127.0.0.1".into(),
            format!("-rpcport={rpc_port}"),
            format!("-rpcuser={user}"),
            format!("-rpcpassword={pass}"),
            format!("-bind=127.0.0.1:{p2p_port}"),
        ];
        args.extend(
            [
                "-listen=1", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-listenonion=0",
                "-natpmp=0", "-v2transport=1", "-whitelist=noban@127.0.0.1", "-debug=net", "-debug=mempool",
                "-debug=mempoolrej", "-debug=cmpctblock", "-printtoconsole=0", "-shrinkdebugfile=0",
                "-logthreadnames=0", "-logtimestamps=0",
            ]
            .map(String::from),
        );
        let mut daemon = Daemon::spawn(&bitcoind, &args, &work.0)?;
        let rpc = Client::new(&format!("http://127.0.0.1:{rpc_port}"), Auth::UserPass(user.into(), pass))
            .map_err(|e| format!("rpc client: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = daemon.exited() {
                return Err(format!("bitcoind exited during startup: {status}"));
            }
            if rpc.get_blockchain_info().is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                return Err("bitcoind RPC did not come up within 90 s".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let log_path = datadir.join("regtest").join("debug.log");
        let log = std::fs::File::open(&log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
        let mut oracle = CoreOracle {
            daemon,
            work,
            log,
            log_partial: Vec::new(),
            rpc,
            p2p_port,
            v1: None,
            v2: None,
            nonce: 1,
            stats: Stats::default(),
        };
        let desc: serde_json::Value = oracle
            .rpc
            .call("getdescriptorinfo", &[serde_json::json!("raw(51)")])
            .map_err(|e| format!("getdescriptorinfo: {e}"))?;
        let desc = desc["descriptor"].as_str().ok_or("getdescriptorinfo: no descriptor")?.to_string();
        let _: serde_json::Value = oracle
            .rpc
            .call("generatetodescriptor", &[serde_json::json!(1), serde_json::json!(desc)])
            .map_err(|e| format!("generatetodescriptor: {e}"))?;
        let info = oracle.rpc.get_blockchain_info().map_err(|e| format!("getblockchaininfo: {e}"))?;
        if info.initial_block_download {
            return Err("Core is still in initial block download after mining a block".into());
        }
        // Prove the connections work before any case is judged by them.
        oracle.peer(false)?;
        oracle.peer(true)?;
        Ok(oracle)
    }

    /// The oracle's scratch directory (datadir, and the copied `bitcoind`).
    pub fn work_dir(&self) -> &Path {
        &self.work.0
    }

    fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.wrapping_add(1);
        self.nonce ^ 0x7032_7064_6966_6600
    }

    fn peer(&mut self, v2: bool) -> Result<&mut Peer, String> {
        let slot_empty = if v2 { self.v2.is_none() } else { self.v1.is_none() };
        if slot_empty {
            let nonce = self.next_nonce();
            let mut p = Peer::connect(self.p2p_port, v2)?;
            p.handshake(nonce)?;
            if v2 {
                self.v2 = Some(p);
            } else {
                self.v1 = Some(p);
            }
        }
        Ok(if v2 { self.v2.as_mut().expect("v2 peer") } else { self.v1.as_mut().expect("v1 peer") })
    }

    fn drop_peer(&mut self, v2: bool) {
        self.stats.reconnects += 1;
        if v2 {
            self.v2 = None;
        } else {
            self.v1 = None;
        }
    }

    fn skip_log(&mut self) {
        let _ = self.log.seek(SeekFrom::End(0));
        self.log_partial.clear();
    }

    /// The complete lines Core has written since the last read. A line still
    /// being written is held back until its newline arrives, so a marker is
    /// never split across two reads.
    fn read_log(&mut self) -> Vec<String> {
        let _ = self.log.read_to_end(&mut self.log_partial);
        let Some(end) = self.log_partial.iter().rposition(|&b| b == b'\n') else {
            return Vec::new();
        };
        let rest = self.log_partial.split_off(end + 1);
        let done = std::mem::replace(&mut self.log_partial, rest);
        String::from_utf8_lossy(&done).lines().map(str::to_string).collect()
    }

    /// Core's verdict on one case.
    pub fn verdict(&mut self, case: &Case) -> Result<CoreVerdict, String> {
        match case.type_name() {
            TypeName::OtherKnown => return Ok(CoreVerdict::Unobservable("not a covered command".into())),
            TypeName::Named("version") => return self.version_verdict(case),
            _ => {}
        }
        let v2 = case.is_v2();
        // A connection that cannot be made or handshaken is the harness's
        // failure, not a verdict.
        self.peer(v2)?;
        self.skip_log();
        let nonce = self.next_nonce();
        let peer = self.peer(v2)?;
        let sent = peer.send_raw(case).and_then(|()| peer.sync(nonce));
        let lines = self.read_log();
        if sent.is_err() {
            self.drop_peer(v2);
        }
        Ok(classify(case, &lines, sent.err()))
    }

    /// `version` on a fresh connection, followed by a valid one.
    fn version_verdict(&mut self, case: &Case) -> Result<CoreVerdict, String> {
        self.skip_log();
        let mut peer = Peer::connect(self.p2p_port, case.is_v2())?;
        let local_port = peer.local_port;
        let probe_nonce = self.next_nonce();
        let sent = peer
            .send_raw(case)
            .and_then(|()| peer.send(NetworkMessage::Version(our_version(probe_nonce, PROBE_USER_AGENT))));
        let mut lines = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        // Polled even when a send failed: Core may have logged its verdict
        // on the fuzzed version and closed the connection before the probe
        // went out.
        let mut closed = false;
        while Instant::now() < deadline {
            lines.extend(self.read_log());
            if version_settled(&lines) || closed {
                // Settled, or Core closed the connection and has logged all
                // it will.
                break;
            }
            closed = peer.closed_by_core();
            std::thread::sleep(Duration::from_millis(1));
        }
        lines.extend(self.read_log());
        // Read while the connection is still up: Core drops the peer from
        // getpeerinfo once it is closed.
        let services = if sent.is_ok() { self.peer_services(local_port) } else { None };
        drop(peer);
        if let Err(e) = sent {
            return Ok(classify_drop(&lines).unwrap_or_else(|| CoreVerdict::Unobservable(format!("send failed: {e}"))));
        }
        let messages: Vec<&str> = lines.iter().map(|l| core_message(l)).collect();
        if messages.iter().any(|m| m.starts_with("peer using obsolete version") || m.starts_with("connected to self")) {
            return Ok(CoreVerdict::Unobservable("version refused by policy before its read completed".into()));
        }
        // Core reads the fuzzed version before the probe, so when the probe
        // is redundant the first version Core logged is the fuzzed one.
        // Lines are matched at their start: the user agent is the peer's
        // text and can contain any of these markers.
        if messages.iter().any(|m| m.starts_with("redundant version message")) {
            let Some(line) = messages.iter().find(|m| m.starts_with("receive version message: ")) else {
                return Ok(CoreVerdict::Unobservable("accepted version not logged".into()));
            };
            let Some(mut fields) = parse_version_line(line) else {
                return Err(format!("could not parse Core's version line: {line}"));
            };
            fields.services = services;
            return Ok(CoreVerdict::Accept(Observed { version: Some(fields), ..Observed::default() }));
        }
        Ok(classify_drop(&lines).unwrap_or_else(|| {
            CoreVerdict::Unobservable(if closed {
                "Core closed the connection after the version".into()
            } else {
                "version neither read nor refused".into()
            })
        }))
    }

    fn peer_services(&self, local_port: u16) -> Option<u64> {
        let peers: serde_json::Value = self.rpc.call("getpeerinfo", &[]).ok()?;
        let want = format!("127.0.0.1:{local_port}");
        let p = peers.as_array()?.iter().find(|p| p["addr"].as_str() == Some(want.as_str()))?;
        u64::from_str_radix(p["services"].as_str()?, 16).ok()
    }

    /// Note one compared or skipped case in [`CoreOracle::stats`].
    pub fn note(&mut self, outcome: &Outcome) {
        match outcome {
            Outcome::Skipped(why) => *self.stats.skipped.entry(why.clone()).or_default() += 1,
            _ => self.stats.compared += 1,
        }
    }
}

impl Drop for CoreOracle {
    fn drop(&mut self) {
        // Close the connections before Core goes away; the fields then drop
        // in order: the daemon, then its work dir.
        self.v1 = None;
        self.v2 = None;
    }
}

/// Keeps `P2P_DIFF_KEEP` set to leave the work dir for inspection.
fn keep_work() -> bool {
    std::env::var_os("P2P_DIFF_KEEP").is_some()
}

/// The oracle's scratch directory, removed on drop.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        if !keep_work() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Runs `bitcoind` and stops it when this process lets go of the shim's
/// stdin: on drop, and also when the process ends without dropping it. The
/// fuzz target keeps the oracle in a static, which is never dropped, and
/// libFuzzer leaves by `exit`, so a `Drop` alone would leave `bitcoind`
/// running and its datadir behind after every run. The shim then removes the
/// work dir.
const SHIM: &str = r#"exec 3<&0
"$@" </dev/null &
pid=$!
( cat <&3 >/dev/null; kill "$pid" 2>/dev/null ) &
exec 3<&-
wait "$pid"
status=$?
[ -n "$P2P_DIFF_KEEP" ] || rm -rf -- "$P2P_DIFF_WORK"
exit "$status"
"#;

struct Daemon {
    shim: Child,
}

impl Daemon {
    fn spawn(bitcoind: &Path, args: &[String], work: &Path) -> Result<Daemon, String> {
        let shim = Command::new("sh")
            .arg("-c")
            .arg(SHIM)
            .arg("p2pdiff-bitcoind")
            .arg(bitcoind)
            .args(args)
            .env("P2P_DIFF_WORK", work)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("could not start {} under sh: {e}", bitcoind.display()))?;
        Ok(Daemon { shim })
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.shim.try_wait().ok().flatten()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // End of input tells the shim to stop bitcoind; Core shuts down on
        // SIGTERM in a few seconds.
        drop(self.shim.stdin.take());
        let _ = self.shim.wait();
    }
}

/// A log line without Core's `[category] ` prefix (`LogDebug` lines carry
/// one; `LogInfo` lines do not). The start of what is left is Core's own text.
fn core_message(line: &str) -> &str {
    if line.starts_with('[')
        && let Some(i) = line.find("] ")
    {
        return &line[i + 2..];
    }
    line
}

/// Core has finished with the fuzzed `version`: the probe after it was
/// redundant (the fuzzed one was read), Core stopped on a policy check, or
/// the fuzzed one was dropped and the probe was read after it.
fn version_settled(lines: &[String]) -> bool {
    let mut dropped = false;
    for l in lines {
        let m = core_message(l);
        if m.starts_with("redundant version message")
            || m.starts_with("peer using obsolete version")
            || m.starts_with("connected to self")
        {
            return true;
        }
        if classify_drop(std::slice::from_ref(l)).is_some() {
            dropped = true;
        } else if dropped && m.starts_with("receive version message: ") {
            return true;
        }
    }
    false
}

/// Parse `receive version message: <ua>: version V, blocks=H, us=A, txrelay=R, peer=N`.
fn parse_version_line(line: &str) -> Option<VersionFields> {
    let rest = core_message(line).strip_prefix("receive version message: ")?;
    let split = rest.rfind(": version ")?;
    let user_agent = rest[..split].to_string();
    let mut version = None;
    let mut start_height = None;
    let mut relay = None;
    for part in rest[split + 2..].split(", ") {
        if let Some(v) = part.strip_prefix("version ") {
            version = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("blocks=") {
            start_height = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("txrelay=") {
            relay = Some(v == "1");
        }
    }
    Some(VersionFields { version: version?, start_height: start_height?, relay: relay?, user_agent, services: None })
}

/// The number after `prefix` in `line`.
fn number_after(line: &str, prefix: &str) -> Option<usize> {
    let start = line.find(prefix)? + prefix.len();
    let digits: String = line[start..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Core dropped the message: before any handler, or in its read.
fn classify_drop(lines: &[String]) -> Option<CoreVerdict> {
    for l in lines {
        let m = core_message(l);
        if m.starts_with("Header error: Wrong checksum")
            || m.starts_with("Header error: Invalid message type")
            || m.starts_with("V2 transport error: invalid message type")
        {
            return Some(CoreVerdict::Ignore(l.clone()));
        }
        if m.starts_with("ProcessMessages(") && m.contains("): Exception '") {
            return Some(CoreVerdict::Reject(l.clone()));
        }
        if m.starts_with("Unknown message type") {
            return Some(CoreVerdict::Ignore(l.clone()));
        }
    }
    None
}

/// Core's verdict on a non-`version` case from the lines it logged while
/// handling it.
fn classify(case: &Case, lines: &[String], sync_error: Option<String>) -> CoreVerdict {
    if let Some(v) = classify_drop(lines) {
        return v;
    }
    let TypeName::Named(name) = case.type_name() else {
        return CoreVerdict::Unobservable(match sync_error {
            Some(e) => format!("connection lost: {e}"),
            None => "unknown type, but no drop logged".into(),
        });
    };
    const POLICY_STOPS: [&str; 5] = [
        "headers message size = ",
        "sent us a compact block despite never having sent us a SENDCMPCT",
        "sent us a compact block even though we are",
        "transaction sent in violation of protocol",
        "while still loading blocks",
    ];
    if let Some(stop) = POLICY_STOPS.iter().find(|s| lines.iter().any(|l| l.contains(*s))) {
        return CoreVerdict::Unobservable(format!("{name}: policy stop before the read ({stop})"));
    }
    let reached = format!("received: {name} (");
    if !lines.iter().any(|l| core_message(l).starts_with(&reached)) {
        return CoreVerdict::Unobservable(match sync_error {
            Some(e) => format!("{name}: connection lost: {e}"),
            None => format!("{name}: handler not entered"),
        });
    }
    let mut o = Observed::default();
    for l in lines {
        match name {
            "addr" | "addrv2" => {
                if let Some(n) = number_after(l, "Received addr: ") {
                    o.count = Some(n);
                }
                if let Some(n) = number_after(l, &format!(": {name} message size = ")) {
                    o.count = Some(n);
                }
            }
            "getdata" => {
                if let Some(n) = number_after(l, "received getdata (") {
                    o.count = Some(n);
                }
                if let Some(n) = number_after(l, "getdata message size = ") {
                    o.count = Some(n);
                }
            }
            "inv" => {
                if let Some(n) = number_after(l, "inv message size = ") {
                    o.count = Some(n);
                }
            }
            "tx" => {
                // "accepted <txid> (wtxid=<wtxid>)" or
                // "<txid> (wtxid=<wtxid>) from peer=N was not accepted".
                if let Some(i) = l.find(" (wtxid=") {
                    let txid = l[..i].rsplit(' ').next().unwrap_or("");
                    let wtxid: String = l[i + 8..].chars().take_while(char::is_ascii_hexdigit).collect();
                    if txid.len() == 64 && wtxid.len() == 64 {
                        o.tx = Some((txid.to_string(), wtxid));
                    }
                }
            }
            "block" => {
                if let Some(i) = l.find("received block ") {
                    let hash: String = l[i + 15..].chars().take_while(char::is_ascii_hexdigit).collect();
                    if hash.len() == 64 {
                        o.block = Some(hash);
                    }
                }
            }
            _ => {}
        }
    }
    CoreVerdict::Accept(o)
}

// ---------------------------------------------------------------------------
// Seed cases
// ---------------------------------------------------------------------------

fn enc<T: Encodable>(v: &T) -> Vec<u8> {
    serialize(v)
}

fn compact_size(n: u64) -> Vec<u8> {
    enc(&encode::VarInt(n))
}

/// An `addrv2` payload: IPv4, IPv6, TorV3, I2P, CJDNS, an unknown network,
/// and an IPv4 entry whose services set bit 26 (Core reads services with no
/// range check, `src/protocol.h:441-446`).
fn addrv2_payload() -> Vec<u8> {
    let mut p = compact_size(7);
    let mut entry = |services: u64, net: u8, addr: &[u8], port: u16| {
        p.extend(1_700_000_000u32.to_le_bytes());
        p.extend(compact_size(services));
        p.push(net);
        p.extend(compact_size(addr.len() as u64));
        p.extend(addr);
        p.extend(port.to_be_bytes());
    };
    entry(0x409, 1, &[8, 8, 8, 8], 8333);
    entry(1 << 26 | 0x409, 1, &[1, 2, 3, 4], 8333);
    entry(0x9, 2, &[0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88], 8333);
    entry(0x1, 4, &[0x11; 32], 8333);
    entry(0x1, 5, &[0x22; 32], 0);
    entry(0x1, 6, &[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8333);
    entry(0x1, 42, &[1, 2, 3], 9);
    p
}

fn sample_tx(witness: bool) -> bitcoin::Transaction {
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    let mut w = Witness::new();
    if witness {
        w.push([0x51]);
    }
    bitcoin::Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: bitcoin::Txid::from_byte_array([0x42; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w,
        }],
        output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from(vec![0x51]) }],
    }
}

/// Synthetic seeds, one well-formed (or deliberately edge-case) payload per
/// covered command, before the transport is chosen. No address in them was
/// captured from a peer.
pub fn seed_payloads() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    use bitcoin::p2p::message_blockdata::Inventory;
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let gh = genesis.block_hash();
    let mut seeds: Vec<(&'static str, &'static str, Vec<u8>)> = Vec::new();

    // A fixed timestamp keeps the committed seeds equal to this generator.
    let full = version_at(1_700_000_000, 7, "/Satoshi:32.1.0/");
    seeds.push(("version", "version-full", enc(&full)));
    let mut no_relay = enc(&full);
    no_relay.pop();
    seeds.push(("version", "version-no-relay", no_relay));
    seeds.push(("version", "version-four-fields", enc(&full)[..4 + 8 + 8 + 26].to_vec()));
    let mut odd_ua = full.clone();
    odd_ua.user_agent = String::new();
    let mut odd = enc(&odd_ua);
    // Replace the empty user agent with four bytes that are not UTF-8.
    let ua_at = 4 + 8 + 8 + 26 + 26 + 8;
    odd.splice(ua_at..ua_at + 1, [4u8, b'/', 0xff, 0xfe, b'/']);
    seeds.push(("version", "version-non-utf8-agent", odd));
    let mut long_ua = full.clone();
    long_ua.user_agent = "x".repeat(257);
    seeds.push(("version", "version-agent-over-256", enc(&long_ua)));

    let addr = vec![(1_700_000_000u32, Address::new(&"8.8.4.4:8333".parse().expect("addr"), ServiceFlags::NETWORK))];
    seeds.push(("addr", "addr-one", enc(&addr)));
    seeds.push(("addrv2", "addrv2-mixed-high-service-bit", addrv2_payload()));

    let inv = vec![Inventory::Block(gh), Inventory::WTx(bitcoin::Wtxid::from_byte_array([7; 32]))];
    seeds.push(("inv", "inv-block-wtx", enc(&inv)));
    let mut inv_unknown = compact_size(1);
    inv_unknown.extend(0x7u32.to_le_bytes());
    inv_unknown.extend([9u8; 32]);
    seeds.push(("inv", "inv-unknown-type", inv_unknown));
    seeds.push(("getdata", "getdata-genesis", enc(&vec![Inventory::Block(gh)])));

    let mut headers = compact_size(1);
    headers.extend(enc(&genesis.header));
    headers.push(0);
    seeds.push(("headers", "headers-one", headers));
    seeds.push(("headers", "headers-none", compact_size(0)));
    // Core reads each header's tx count as a CompactSize and ignores it.
    let mut headers = compact_size(1);
    headers.extend(enc(&genesis.header));
    headers.push(1);
    seeds.push(("headers", "headers-tx-count-one", headers));
    let mut headers = compact_size(1);
    headers.extend(enc(&genesis.header));
    headers.extend(compact_size(256));
    seeds.push(("headers", "headers-tx-count-3-byte", headers));


    // cmpctblock: header, nonce, one short id, the coinbase prefilled.
    let mut cmpct = enc(&genesis.header);
    cmpct.extend(42u64.to_le_bytes());
    cmpct.extend(compact_size(1));
    cmpct.extend([1, 2, 3, 4, 5, 6]);
    cmpct.extend(compact_size(1));
    cmpct.extend(compact_size(0));
    cmpct.extend(enc(&genesis.txdata[0]));
    seeds.push(("cmpctblock", "cmpctblock-one-prefilled", cmpct));

    let mut blocktxn = enc(&gh);
    blocktxn.extend(compact_size(1));
    blocktxn.extend(enc(&sample_tx(true)));
    seeds.push(("blocktxn", "blocktxn-one", blocktxn));

    // getblocktxn: differentially encoded indexes 0 and 2.
    let mut getblocktxn = enc(&gh);
    getblocktxn.extend(compact_size(2));
    getblocktxn.extend(compact_size(0));
    getblocktxn.extend(compact_size(1));
    seeds.push(("getblocktxn", "getblocktxn-two", getblocktxn));
    // Core's indexes are 16-bit: 65535 is read, 65536 is refused.
    for (name, diff) in [("getblocktxn-index-65535", 65535), ("getblocktxn-index-65536", 65536)] {
        let mut getblocktxn = enc(&gh);
        getblocktxn.extend(compact_size(1));
        getblocktxn.extend(compact_size(diff));
        seeds.push(("getblocktxn", name, getblocktxn));
    }


    seeds.push(("feefilter", "feefilter-1000", 1000i64.to_le_bytes().to_vec()));
    seeds.push(("feefilter", "feefilter-negative", (-1i64).to_le_bytes().to_vec()));
    let mut sendcmpct = vec![0u8];
    sendcmpct.extend(2u64.to_le_bytes());
    seeds.push(("sendcmpct", "sendcmpct-v2", sendcmpct));
    let mut sendcmpct_hb2 = vec![2u8];
    sendcmpct_hb2.extend(2u64.to_le_bytes());
    seeds.push(("sendcmpct", "sendcmpct-flag-2", sendcmpct_hb2));

    seeds.push(("tx", "tx-witness", enc(&sample_tx(true))));
    seeds.push(("tx", "tx-legacy", enc(&sample_tx(false))));
    seeds.push(("block", "block-genesis", enc(&genesis)));
    seeds
}

/// Every seed payload on each transport its command has, plus an unknown
/// command, an unimplemented short id, and a v1 frame with a bad checksum.
pub fn seed_cases() -> Vec<(String, Case)> {
    let mut out = Vec::new();
    for (cmd, name, payload) in seed_payloads() {
        out.push((format!("{name}-v1"), Case::v1(cmd, payload.clone())));
        if short_id(cmd).is_some() {
            out.push((format!("{name}-v2short"), Case::v2_short(cmd, payload.clone())));
        }
        out.push((format!("{name}-v2long"), Case::v2_long(cmd, payload)));
    }
    out.push(("unknown-command-v1".into(), Case::v1("zzzz", vec![1, 2, 3])));
    out.push(("unknown-command-v2long".into(), Case::v2_long("zzzz", vec![1, 2, 3])));
    out.push(("unimplemented-short-id-v2".into(), Case { msg_type: MsgType::V2Short(30), payload: vec![0] }));
    let mut bad = Case::v1("tx", enc(&sample_tx(true)));
    bad.msg_type = MsgType::V1 { command: command_bytes("tx"), bad_checksum: true };
    out.push(("tx-bad-checksum-v1".into(), bad));
    out
}
