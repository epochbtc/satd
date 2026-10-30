//! P2P message payloads, read the way Bitcoin Core reads them.
//!
//! Core reads a message's fields off the front of its payload and ignores
//! whatever follows: no message handler in `src/net_processing.cpp` checks
//! that the payload was used up, and `version` reads its later fields only
//! `if (!vRecv.empty())` (`net_processing.cpp:3626-3642`). rust-bitcoin
//! 0.32.10 and later refuse a v1 message with bytes left after the last
//! field ("extra bytes after network message payload"), and one refused
//! `version` or `verack` would stall the handshake.
//!
//! These are also read as Core reads them, not as rust-bitcoin does:
//!
//! - `version` needs only its first four fields (version, services, time,
//!   the receiver's address); each later field is read only if bytes remain,
//!   and a missing one takes Core's default: nonce 1, an empty user agent,
//!   start height -1, relay true (`net_processing.cpp:3587-3643`). Peers on
//!   the network end a `version` after the start height, with no relay byte
//!   (BIP 37's optional field); rust-bitcoin refuses it, and the handshake
//!   never completes. A user agent over 256 bytes is refused, as Core's
//!   `LIMITED_STRING` refuses it; one that is not UTF-8 is read lossily,
//!   where rust-bitcoin refuses it (Core sanitizes it for display).
//! - `sendcmpct`'s high-bandwidth flag is a `bool`, which Core reads as any
//!   byte, non-zero meaning true (`src/serialize.h:279`). rust-bitcoin
//!   refuses a byte other than 0 or 1.
//! - `feefilter`'s value is read whole, whatever it is. Core reads the
//!   `CAmount` and then ignores a value outside `MoneyRange`
//!   (`net_processing.cpp:5035-5045`); the handler does the same
//!   (`PeerManager::set_peer_fee_filter`). rust-bitcoin refuses the message.
//!
//! Each payload is otherwise decoded by rust-bitcoin's decoder for its
//! type, so a malformed field is refused as before. The message type is
//! parsed by rust-bitcoin's `CommandString`: ASCII, trailing NULs trimmed,
//! an embedded NUL kept. An embedded NUL or a non-ASCII byte makes a type
//! Core drops (`CMessageHeader::IsMessageTypeValid`, `src/protocol.cpp:26`;
//! `V2Transport::GetMessageType`, `src/net.cpp:1413`); here it is refused or
//! comes back as `NetworkMessage::Unknown`, which no handler acts on.
//!
//! `addrv2` is read by [`crate::net::addrv2`] before a payload gets here.

use bitcoin::consensus::encode::{self, Decodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::message::{CommandString, NetworkMessage};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message_compact_blocks::SendCmpct;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;

/// Size of a v1 message header: magic 4, command 12, length 4, checksum 4.
const V1_HEADER_SIZE: usize = 24;

/// Read a `T` off the front of `payload`, ignoring any bytes after it.
fn read<T: Decodable>(payload: &[u8]) -> Result<T, encode::Error> {
    let mut r = payload;
    T::consensus_decode_from_finite_reader(&mut r)
}

/// Core's `MAX_SUBVERSION_LENGTH` (`src/net.h`).
const MAX_SUBVERSION_LENGTH: u64 = 256;

/// `version`, as Core's handler reads it (`net_processing.cpp:3587-3643`).
fn read_version(payload: &[u8]) -> Result<VersionMessage, encode::Error> {
    let mut r = payload;
    let version = u32::consensus_decode(&mut r)?;
    let services = ServiceFlags::from(u64::consensus_decode(&mut r)?);
    let timestamp = i64::consensus_decode(&mut r)?;
    let receiver = Address::consensus_decode(&mut r)?;
    let mut msg = VersionMessage {
        version,
        services,
        timestamp,
        receiver,
        sender: Address { services: ServiceFlags::NONE, address: [0; 8], port: 0 },
        nonce: 1,
        user_agent: String::new(),
        start_height: -1,
        relay: true,
    };
    // Each `if` is one of Core's `if (!vRecv.empty())`: once a field has
    // begun, all of it must be there.
    if !r.is_empty() {
        msg.sender = Address::consensus_decode(&mut r)?;
        msg.nonce = u64::consensus_decode(&mut r)?;
    }
    if !r.is_empty() {
        let len = encode::VarInt::consensus_decode(&mut r)?.0;
        if len > MAX_SUBVERSION_LENGTH {
            return Err(encode::Error::ParseFailed("version user agent over 256 bytes"));
        }
        let len = len as usize;
        if r.len() < len {
            return Err(encode::Error::ParseFailed("version user agent truncated"));
        }
        let (agent, rest) = r.split_at(len);
        msg.user_agent = String::from_utf8_lossy(agent).into_owned();
        r = rest;
    }
    if !r.is_empty() {
        msg.start_height = i32::consensus_decode(&mut r)?;
    }
    if !r.is_empty() {
        msg.relay = u8::consensus_decode(&mut r)? != 0;
    }
    Ok(msg)
}

/// `headers`: a count, then each header followed by a one-byte tx count
/// that must be zero, as rust-bitcoin reads it.
fn read_headers(payload: &[u8]) -> Result<Vec<bitcoin::block::Header>, encode::Error> {
    let mut r = payload;
    let count = encode::VarInt::consensus_decode(&mut r)?.0;
    let mut out = Vec::with_capacity((count as usize).min(payload.len() / 81));
    for _ in 0..count {
        out.push(bitcoin::block::Header::consensus_decode(&mut r)?);
        if u8::consensus_decode(&mut r)? != 0 {
            return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
        }
    }
    Ok(out)
}

/// Decode the payload of a message of type `command`, as Core reads it.
/// A type no handler knows comes back as [`NetworkMessage::Unknown`].
pub fn decode_payload(command: CommandString, payload: &[u8]) -> Result<NetworkMessage, encode::Error> {
    use NetworkMessage as M;
    Ok(match command.as_ref() {
        "version" => M::Version(read_version(payload)?),
        "verack" => M::Verack,
        "addr" => M::Addr(read(payload)?),
        "inv" => M::Inv(read(payload)?),
        "getdata" => M::GetData(read(payload)?),
        "notfound" => M::NotFound(read(payload)?),
        "getblocks" => M::GetBlocks(read(payload)?),
        "getheaders" => M::GetHeaders(read(payload)?),
        "mempool" => M::MemPool,
        "block" => M::Block(read(payload)?),
        "headers" => M::Headers(read_headers(payload)?),
        "sendheaders" => M::SendHeaders,
        "getaddr" => M::GetAddr,
        "ping" => M::Ping(read(payload)?),
        "pong" => M::Pong(read(payload)?),
        "merkleblock" => M::MerkleBlock(read(payload)?),
        "filterload" => M::FilterLoad(read(payload)?),
        "filteradd" => M::FilterAdd(read(payload)?),
        "filterclear" => M::FilterClear,
        "tx" => M::Tx(read(payload)?),
        "getcfilters" => M::GetCFilters(read(payload)?),
        "cfilter" => M::CFilter(read(payload)?),
        "getcfheaders" => M::GetCFHeaders(read(payload)?),
        "cfheaders" => M::CFHeaders(read(payload)?),
        "getcfcheckpt" => M::GetCFCheckpt(read(payload)?),
        "cfcheckpt" => M::CFCheckpt(read(payload)?),
        "reject" => M::Reject(read(payload)?),
        "alert" => M::Alert(read(payload)?),
        "feefilter" => M::FeeFilter(read(payload)?),
        "sendcmpct" => {
            let mut r = payload;
            let high_bandwidth = u8::consensus_decode(&mut r)?;
            let version = u64::consensus_decode(&mut r)?;
            M::SendCmpct(SendCmpct { send_compact: high_bandwidth != 0, version })
        }
        "cmpctblock" => M::CmpctBlock(read(payload)?),
        "getblocktxn" => M::GetBlockTxn(read(payload)?),
        "blocktxn" => M::BlockTxn(read(payload)?),
        "wtxidrelay" => M::WtxidRelay,
        "addrv2" => M::AddrV2(read(payload)?),
        "sendaddrv2" => M::SendAddrV2,
        _ => M::Unknown { command, payload: payload.to_vec() },
    })
}

/// Decode a whole v1 frame (header and payload). A frame whose checksum
/// does not match is refused, as Core drops it (`src/net.cpp:821`). The
/// caller has checked the magic and that the payload length matches the
/// header.
pub fn decode_v1_frame(frame: &[u8]) -> Result<NetworkMessage, encode::Error> {
    if frame.len() < V1_HEADER_SIZE {
        return Err(encode::Error::ParseFailed("v1 frame shorter than its header"));
    }
    let (header, payload) = frame.split_at(V1_HEADER_SIZE);
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if payload.len() != len {
        return Err(encode::Error::ParseFailed("v1 payload length does not match its header"));
    }
    let hash = sha256d::Hash::hash(payload);
    if hash[..4] != header[20..24] {
        return Err(encode::Error::InvalidChecksum {
            expected: [header[20], header[21], header[22], header[23]],
            actual: [hash[0], hash[1], hash[2], hash[3]],
        });
    }
    let command = CommandString::consensus_decode(&mut &header[4..16])?;
    decode_payload(command, payload)
}

#[cfg(test)]
#[path = "payload_tests.rs"]
mod tests;
