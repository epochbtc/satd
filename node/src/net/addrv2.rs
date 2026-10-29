//! BIP 155 `addrv2` payloads, read the way Bitcoin Core reads them.
//!
//! rust-bitcoin's `AddrV2Message` decoder refuses things Core accepts, and
//! one refused entry loses the whole message:
//!
//! - Up to 0.32.9 it read `services` as a size-checked CompactSize, so any
//!   value above `MAX_SIZE` (0x0200_0000, i.e. any service bit at or above
//!   25) failed. Core reads it with `CompactSizeFormatter<false>`, no range
//!   check (`src/protocol.h:446`). Nodes that set bit 26 are on the
//!   network, and a `getaddr` reply of 1000 entries nearly always lists one.
//!   0.32.10 dropped the check; this reader keeps Core's rule either way.
//! - It fails an IPv6 entry that carries an embedded IPv4 or TORv2 address,
//!   a TORv2 entry of the wrong length, and a CJDNS entry without the `fc`
//!   prefix. Core reads each of these as an invalid address that is never
//!   gossiped and moves on to the next entry (`src/netaddress.h:440-475`,
//!   `src/netaddress.cpp:49-98`).
//!
//! [`decode_payload`] mirrors Core's `CAddress` / `CNetAddr` network
//! unserialization. An entry Core reads as invalid comes back as
//! [`AddrV2::Unknown`] with its network id and bytes, which no consumer
//! dials or relays. What Core refuses, it refuses: a non-canonical
//! CompactSize anywhere, an entry count or address length above `MAX_SIZE`,
//! an address longer than 512 bytes, a founding network (other than TORv2)
//! with the wrong address length, and a truncated payload.

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::ServiceFlags;
use std::net::Ipv6Addr;

/// The `addrv2` command as it sits in a v1 header and in a v2 long-form
/// message type: ASCII, NUL-padded to 12 bytes.
pub const ADDRV2_COMMAND: [u8; 12] = *b"addrv2\0\0\0\0\0\0";

/// Core's `MAX_SIZE` (`src/serialize.h`): the range check on a CompactSize
/// read as a size or count.
const MAX_SIZE: u64 = 0x0200_0000;

/// Core's `CNetAddr::MAX_ADDRV2_SIZE`.
const MAX_ADDRV2_SIZE: u64 = 512;

/// The smallest encoded entry: time 4, services 1, network 1, length 1,
/// port 2. Bounds the up-front allocation by the bytes actually present.
const MIN_ENTRY_LEN: usize = 9;

/// Core's `INTERNAL_IN_IPV6_PREFIX`, `IPV4_IN_IPV6_PREFIX` and
/// `TORV2_IN_IPV6_PREFIX` (`src/netaddress.h`).
const INTERNAL_IN_IPV6_PREFIX: [u8; 6] = [0xfd, 0x6b, 0x88, 0xc0, 0x87, 0x24];
const IPV4_IN_IPV6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
const TORV2_IN_IPV6_PREFIX: [u8; 6] = [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43];

/// Why an `addrv2` payload could not be read.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddrV2DecodeError {
    #[error("addrv2 payload truncated")]
    Truncated,
    #[error("non-canonical CompactSize")]
    NonCanonicalCompactSize,
    #[error("CompactSize {0} exceeds MAX_SIZE")]
    SizeTooLarge(u64),
    #[error("address too long: {0} > 512")]
    AddressTooLong(u64),
    #[error("BIP155 network {network} address with length {len}")]
    BadAddressLength { network: u8, len: u64 },
    #[error("v1 checksum mismatch")]
    BadChecksum,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AddrV2DecodeError> {
        if self.buf.len() < n {
            return Err(AddrV2DecodeError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, AddrV2DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Core's `ReadCompactSize(is, range_check)` (`src/serialize.h:332`):
    /// non-canonical encodings are always refused; `MAX_SIZE` only when
    /// `range_check` is set.
    fn compact_size(&mut self, range_check: bool) -> Result<u64, AddrV2DecodeError> {
        let first = self.u8()?;
        let (value, min) = match first {
            0..=0xfc => (u64::from(first), 0),
            0xfd => (u64::from(u16::from_le_bytes(self.take(2)?.try_into().unwrap())), 0xfd),
            0xfe => (u64::from(u32::from_le_bytes(self.take(4)?.try_into().unwrap())), 0x1_0000),
            0xff => (u64::from_le_bytes(self.take(8)?.try_into().unwrap()), 0x1_0000_0000),
        };
        if value < min {
            return Err(AddrV2DecodeError::NonCanonicalCompactSize);
        }
        if range_check && value > MAX_SIZE {
            return Err(AddrV2DecodeError::SizeTooLarge(value));
        }
        Ok(value)
    }
}

/// Decode an `addrv2` message payload (the bytes after the v1 header or the
/// v2 message type). Bytes past the last entry are ignored, as Core ignores
/// them.
///
/// The entry count is not capped here: the message handler refuses more
/// than `MAX_ADDR_TO_SEND` with a misbehavior score, as Core does, and the
/// transport's message size limit bounds the work.
pub fn decode_payload(payload: &[u8]) -> Result<Vec<AddrV2Message>, AddrV2DecodeError> {
    let mut r = Reader { buf: payload };
    let count = r.compact_size(true)?;
    let mut out = Vec::with_capacity((count as usize).min(payload.len() / MIN_ENTRY_LEN));
    for _ in 0..count {
        out.push(decode_entry(&mut r)?);
    }
    Ok(out)
}

/// Check a v1 frame's checksum (`header[20..24]`) and decode its payload.
/// Core drops a frame whose checksum does not match (`V1Transport`,
/// `src/net.cpp:826`).
pub fn decode_v1_payload(
    header: &[u8],
    payload: &[u8],
) -> Result<Vec<AddrV2Message>, AddrV2DecodeError> {
    if sha256d::Hash::hash(payload)[..4] != header[20..24] {
        return Err(AddrV2DecodeError::BadChecksum);
    }
    decode_payload(payload)
}

fn decode_entry(r: &mut Reader<'_>) -> Result<AddrV2Message, AddrV2DecodeError> {
    let time = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
    // `CompactSizeFormatter<false>`: no range check on the service bits.
    let services = ServiceFlags::from(r.compact_size(false)?);
    let network = r.u8()?;
    let len = r.compact_size(true)?;
    if len > MAX_ADDRV2_SIZE {
        return Err(AddrV2DecodeError::AddressTooLong(len));
    }
    let want = match network {
        1 => Some(4),
        2 | 6 => Some(16),
        4 | 5 => Some(32),
        // TORv2 (3) is no longer a network Core knows, so like an id from
        // the future it is skipped at any length.
        _ => None,
    };
    if let Some(want) = want
        && len != want
    {
        return Err(AddrV2DecodeError::BadAddressLength { network, len });
    }
    let bytes = r.take(len as usize)?;
    let addr = match network {
        1 => AddrV2::Ipv4(<[u8; 4]>::try_from(bytes).unwrap().into()),
        2 => {
            let octets = <[u8; 16]>::try_from(bytes).unwrap();
            // Core reads these as invalid (internal names, and IPv4 or TORv2
            // embedded in IPv6, which BIP 155 sends under their own ids).
            if octets.starts_with(&INTERNAL_IN_IPV6_PREFIX)
                || octets.starts_with(&IPV4_IN_IPV6_PREFIX)
                || octets.starts_with(&TORV2_IN_IPV6_PREFIX)
            {
                AddrV2::Unknown(network, bytes.to_vec())
            } else {
                AddrV2::Ipv6(Ipv6Addr::from(octets))
            }
        }
        4 => AddrV2::TorV3(bytes.try_into().unwrap()),
        5 => AddrV2::I2p(bytes.try_into().unwrap()),
        // Core reads any 16 bytes here and calls the address invalid
        // without the `fc` prefix (`CNetAddr::IsValid`).
        6 if bytes[0] == 0xfc => AddrV2::Cjdns(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => AddrV2::Unknown(network, bytes.to_vec()),
    };
    let port = u16::from_be_bytes(r.take(2)?.try_into().unwrap());
    Ok(AddrV2Message { time, services, addr, port })
}

/// An `addrv2` payload of three IPv4 entries (1.2.3.4, 5.6.7.8, 9.9.9.9,
/// port 8333) whose middle entry advertises service bit 26, which
/// rust-bitcoin's decoder refuses. For the transport tests.
#[cfg(test)]
pub(crate) fn payload_with_service_bit_26() -> Vec<u8> {
    let mut v = vec![3u8];
    for (ip, services) in [([1, 2, 3, 4], 0x409u64), ([5, 6, 7, 8], 1 << 26 | 0x409), ([9, 9, 9, 9], 0x409)] {
        v.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        v.extend(bitcoin::consensus::encode::serialize(&bitcoin::consensus::encode::VarInt(services)));
        v.extend_from_slice(&[1, 4]);
        v.extend_from_slice(&ip);
        v.extend_from_slice(&8333u16.to_be_bytes());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::{serialize, VarInt};

    fn entry(time: u32, services: u64, network: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut v = time.to_le_bytes().to_vec();
        v.extend(serialize(&VarInt(services)));
        v.push(network);
        v.extend(serialize(&VarInt(addr.len() as u64)));
        v.extend_from_slice(addr);
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    fn payload(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut v = serialize(&VarInt(entries.len() as u64));
        for e in entries {
            v.extend_from_slice(e);
        }
        v
    }

    /// The defect: one entry advertising service bit 26 made rust-bitcoin
    /// refuse the whole message. Core reads it, and so must we, with the
    /// entries around it.
    #[test]
    fn services_above_max_size_decode_with_their_neighbours() {
        let p = payload(&[
            entry(1, 0x409, 1, &[1, 2, 3, 4], 8333),
            entry(2, 1 << 26 | 0x409, 1, &[5, 6, 7, 8], 8333),
            entry(3, u64::MAX, 1, &[9, 9, 9, 9], 18333),
        ]);
        // rust-bitcoin 0.32.9 refused this payload; 0.32.10 dropped the
        // range check (#6182) and reads it. The module stays for the
        // entries Core reads as invalid, which rust-bitcoin still refuses.
        assert!(bitcoin::consensus::deserialize::<Vec<AddrV2Message>>(&p).is_ok());
        let got = decode_payload(&p).expect("Core reads this payload");
        assert_eq!(got.len(), 3);
        assert_eq!(got[1].services.to_u64(), 1 << 26 | 0x409);
        assert_eq!(got[1].addr, AddrV2::Ipv4([5, 6, 7, 8].into()));
        assert_eq!(got[2].services.to_u64(), u64::MAX);
        assert_eq!(got[2].port, 18333);
    }

    /// Whatever rust-bitcoin can read, we read the same.
    #[test]
    fn agrees_with_rust_bitcoin_on_ordinary_entries() {
        let msgs = vec![
            AddrV2Message { time: 7, services: ServiceFlags::NETWORK, addr: AddrV2::Ipv4([8, 8, 4, 4].into()), port: 8333 },
            AddrV2Message { time: 8, services: ServiceFlags::WITNESS, addr: AddrV2::Ipv6("2001:4860::8888".parse().unwrap()), port: 1 },
            AddrV2Message { time: 9, services: ServiceFlags::NONE, addr: AddrV2::TorV3([0x11; 32]), port: 0 },
            AddrV2Message { time: 10, services: ServiceFlags::NONE, addr: AddrV2::I2p([0x22; 32]), port: 0 },
            AddrV2Message { time: 11, services: ServiceFlags::NONE, addr: AddrV2::Cjdns("fc00::1".parse().unwrap()), port: 8333 },
            AddrV2Message { time: 12, services: ServiceFlags::NONE, addr: AddrV2::Unknown(42, vec![1, 2, 3]), port: 9 },
        ];
        let p = serialize(&msgs);
        assert_eq!(decode_payload(&p).unwrap(), msgs);
    }

    /// Entries Core reads as invalid are kept as `Unknown` and the rest of
    /// the message is still read.
    #[test]
    fn entries_core_reads_as_invalid_do_not_lose_the_message() {
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&[1, 2, 3, 4]);
        let mut onioncat = [0u8; 16];
        onioncat[..6].copy_from_slice(&TORV2_IN_IPV6_PREFIX);
        let mut cjdns = [0u8; 16];
        cjdns[0] = 0xfd;
        let p = payload(&[
            entry(1, 1, 2, &mapped, 1),
            entry(1, 1, 2, &onioncat, 1),
            entry(1, 1, 3, &[0; 7], 1),
            entry(1, 1, 6, &cjdns, 1),
            entry(1, 1, 1, &[1, 1, 1, 1], 2),
        ]);
        let got = decode_payload(&p).unwrap();
        assert_eq!(got.len(), 5);
        assert!(got[..4].iter().all(|m| matches!(m.addr, AddrV2::Unknown(..))));
        assert!(got[..4].iter().all(|m| m.socket_addr().is_err()));
        assert_eq!(got[4].addr, AddrV2::Ipv4([1, 1, 1, 1].into()));
    }

    /// What Core refuses, we refuse.
    #[test]
    fn refuses_what_core_refuses() {
        // Non-canonical services (Core checks canonical form even without
        // the range check).
        let mut e = 1u32.to_le_bytes().to_vec();
        e.extend_from_slice(&[0xfd, 0x01, 0x00]);
        e.extend_from_slice(&[1, 4, 1, 2, 3, 4, 0, 1]);
        assert_eq!(decode_payload(&payload(&[e])), Err(AddrV2DecodeError::NonCanonicalCompactSize));
        // Wrong length for a founding network.
        assert_eq!(
            decode_payload(&payload(&[entry(1, 1, 1, &[1, 2, 3], 1)])),
            Err(AddrV2DecodeError::BadAddressLength { network: 1, len: 3 })
        );
        // Too long an address, even for an unknown network.
        assert_eq!(
            decode_payload(&payload(&[entry(1, 1, 99, &[0; 513], 1)])),
            Err(AddrV2DecodeError::AddressTooLong(513))
        );
        // A count past MAX_SIZE.
        assert_eq!(
            decode_payload(&serialize(&VarInt(MAX_SIZE + 1))),
            Err(AddrV2DecodeError::SizeTooLarge(MAX_SIZE + 1))
        );
        // Truncated.
        let mut p = payload(&[entry(1, 1, 1, &[1, 2, 3, 4], 1)]);
        p.pop();
        assert_eq!(decode_payload(&p), Err(AddrV2DecodeError::Truncated));
    }

    #[test]
    fn v1_payload_needs_its_checksum() {
        let p = payload(&[entry(1, 1 << 26, 1, &[1, 2, 3, 4], 1)]);
        let mut header = [0u8; 24];
        header[20..24].copy_from_slice(&sha256d::Hash::hash(&p)[..4]);
        assert_eq!(decode_v1_payload(&header, &p).unwrap().len(), 1);
        header[20] ^= 1;
        assert_eq!(decode_v1_payload(&header, &p), Err(AddrV2DecodeError::BadChecksum));
    }
}
