//! `anchors.dat`: the block-relay-only peers the node held when it last
//! shut down cleanly, dialled first when it starts again (#1150).
//!
//! Anchors are an eclipse defence. An attacker who fills the address book
//! while the node is down still has to displace the block-relay-only peers
//! the node held before the restart. Core writes the file only on a clean
//! shutdown (`CConnman::StopNodes`, v31.1 `src/net.cpp:3675`), and reads and
//! deletes it at startup (`ReadAnchors`, `src/addrdb.cpp:234`), so a bad
//! anchor is tried at most once. Neither happens under `-connect`.
//!
//! The file is byte-compatible with Core's: the network magic, the
//! addresses as `CAddress::V2_DISK` serializes a vector of them, then the
//! hash256 of everything before it (`SerializeDB`, `src/addrdb.cpp:38`). A
//! datadir moved between Core and satd keeps its anchors, and Core's
//! `feature_anchors.py` reads and edits the file.

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::ServiceFlags;

use crate::net::addrv2::{decode_disk_vector, encode_disk_vector};
use crate::net::peer::{onion_host_to_torv3_pubkey, torv3_to_onion_host, PeerAddr};

/// The file's name in the network data directory (Core's
/// `ANCHORS_DATABASE_FILENAME`).
pub const ANCHORS_FILE: &str = "anchors.dat";

/// Core's `MAX_BLOCK_RELAY_ONLY_ANCHORS` (v31.1 `src/net.cpp:57`): at most
/// this many anchors are written, and at most this many read are used.
pub const MAX_BLOCK_RELAY_ONLY_ANCHORS: usize = 2;

/// One anchor: a block-relay-only peer's address and the services it
/// offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub addr: PeerAddr,
    pub services: ServiceFlags,
}

impl Anchor {
    fn to_addrv2(&self, time: u32) -> Option<AddrV2Message> {
        let (addr, port) = match &self.addr {
            PeerAddr::Socket(sa) => (
                match sa.ip().to_canonical() {
                    IpAddr::V4(ip) => AddrV2::Ipv4(ip),
                    IpAddr::V6(ip) => AddrV2::Ipv6(ip),
                },
                sa.port(),
            ),
            PeerAddr::Onion { host, port } => (AddrV2::TorV3(onion_host_to_torv3_pubkey(host)?), *port),
        };
        Some(AddrV2Message { time, services: self.services, addr, port })
    }

    /// `None` for a network satd cannot dial (I2P, CJDNS): Core would keep
    /// the entry and pass over it as unreachable when it dials.
    fn from_addrv2(m: &AddrV2Message) -> Option<Anchor> {
        let addr = match &m.addr {
            AddrV2::Ipv4(ip) => PeerAddr::Socket(SocketAddr::new(IpAddr::V4(*ip), m.port)),
            AddrV2::Ipv6(ip) => PeerAddr::Socket(SocketAddr::new(IpAddr::V6(*ip), m.port)),
            AddrV2::TorV3(key) => PeerAddr::Onion { host: torv3_to_onion_host(key), port: m.port },
            _ => return None,
        };
        Some(Anchor { addr, services: m.services })
    }
}

/// Read the anchors in `path` and delete the file, whether it could be
/// read or not, as Core's `ReadAnchors` does. A missing file is no
/// anchors. A file that fails its magic or checksum, or does not parse, is
/// an error, and leaves no anchors either.
pub fn read(path: &Path, magic: [u8; 4]) -> Result<Vec<Anchor>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            let _ = std::fs::remove_file(path);
            return Err(format!("reading {}: {e}", path.display()));
        }
    };
    let _ = std::fs::remove_file(path);
    decode(&bytes, magic).map_err(|e| format!("{}: {e}", path.display()))
}

fn decode(bytes: &[u8], magic: [u8; 4]) -> Result<Vec<Anchor>, String> {
    if bytes.len() < 4 || bytes[..4] != magic {
        return Err("invalid network magic number".to_string());
    }
    let (entries, used) = decode_disk_vector(&bytes[4..]).map_err(|e| e.to_string())?;
    let end = 4 + used;
    let Some(checksum) = bytes.get(end..end + 32) else {
        return Err("truncated before its checksum".to_string());
    };
    if sha256d::Hash::hash(&bytes[..end]).as_byte_array()[..] != *checksum {
        return Err("checksum mismatch, data corrupted".to_string());
    }
    Ok(entries.iter().filter_map(Anchor::from_addrv2).collect())
}

/// Write `anchors` to `path` atomically (temp file, fsync, rename), as
/// `peers.dat` is written.
pub fn write(path: &Path, magic: [u8; 4], anchors: &[Anchor]) -> Result<(), String> {
    let time = u32::try_from(crate::time::now_secs()).unwrap_or(u32::MAX);
    let entries: Vec<AddrV2Message> = anchors.iter().filter_map(|a| a.to_addrv2(time)).collect();
    let mut buf = magic.to_vec();
    buf.extend(encode_disk_vector(&entries));
    let checksum = sha256d::Hash::hash(&buf);
    buf.extend_from_slice(checksum.as_byte_array());
    let tmp = path.with_extension("dat.tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).map_err(|e| format!("creating {}: {e}", tmp.display()))?;
        f.write_all(&buf).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("renaming {} -> {}: {e}", tmp.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    fn anchors() -> Vec<Anchor> {
        vec![
            Anchor { addr: PeerAddr::Socket("127.0.0.1:18444".parse().unwrap()), services: ServiceFlags::from(9) },
            Anchor { addr: PeerAddr::Socket("[2001:4860::1]:8333".parse().unwrap()), services: ServiceFlags::from(0x409) },
            Anchor { addr: PeerAddr::Onion { host: ONION.to_string(), port: 8333 }, services: ServiceFlags::NONE },
        ]
    }

    #[test]
    fn anchors_round_trip_and_the_file_is_deleted_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        write(&path, MAGIC, &anchors()).unwrap();
        assert_eq!(read(&path, MAGIC).unwrap(), anchors());
        assert!(!path.exists());
        assert_eq!(read(&path, MAGIC).unwrap(), Vec::new());
    }

    /// The bytes `feature_anchors.py` looks for: the magic, the count, then
    /// per entry the disk version, the time and the services, and an IPv4
    /// address as BIP 155 network 1 with its port big-endian.
    #[test]
    fn the_layout_is_cores() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        write(&path, MAGIC, &anchors()[..1]).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes[..4], MAGIC);
        assert_eq!(bytes[4], 1);
        assert_eq!(u32::from_le_bytes(bytes[5..9].try_into().unwrap()), 220_000 | 1 << 29);
        // services_index = 4 + 1 + 4 + 4 in the test.
        assert_eq!(bytes[13], 9);
        assert_eq!(bytes[14..20], [1, 4, 0x7f, 0, 0, 1]);
        assert_eq!(bytes[20..22], 18444u16.to_be_bytes());
        assert_eq!(bytes.len(), 22 + 32);
        assert_eq!(bytes[22..], sha256d::Hash::hash(&bytes[..22]).to_byte_array());
    }

    /// `feature_anchors.py` inserts a byte at offset 20 and expects no
    /// anchors, and the node to start; the file goes all the same.
    #[test]
    fn a_damaged_file_gives_no_anchors_and_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        write(&path, MAGIC, &anchors()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.insert(20, b'1');
        std::fs::write(&path, &bytes).unwrap();
        assert!(read(&path, MAGIC).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn another_networks_file_gives_no_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        write(&path, [0xf9, 0xbe, 0xb4, 0xd9], &anchors()).unwrap();
        assert!(read(&path, MAGIC).unwrap_err().contains("magic"));
        assert!(!path.exists());
    }

    /// A file cut short of its checksum is refused, and so is one whose
    /// last byte changed.
    #[test]
    fn a_truncated_or_altered_checksum_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        write(&path, MAGIC, &anchors()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(decode(&bytes[..bytes.len() - 1], MAGIC).unwrap_err().contains("truncated"));
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(decode(&altered, MAGIC).unwrap_err().contains("checksum"));
        assert!(decode(&bytes, MAGIC).is_ok());
    }

    /// An entry in the pre-BIP 155 disk form (version 0), which neither
    /// Core nor satd writes to `anchors.dat`, is refused.
    #[test]
    fn an_entry_not_in_the_bip155_form_is_refused() {
        let mut buf = MAGIC.to_vec();
        let mut body = encode_disk_vector(&[anchors()[0].to_addrv2(0).unwrap()]);
        body[1..5].copy_from_slice(&220_000u32.to_le_bytes());
        buf.extend(body);
        let checksum = sha256d::Hash::hash(&buf);
        buf.extend_from_slice(checksum.as_byte_array());
        assert!(decode(&buf, MAGIC).unwrap_err().contains("version"));
    }

    /// An I2P or CJDNS anchor, which Core can write, is read past.
    #[test]
    fn an_anchor_on_a_network_satd_cannot_dial_is_dropped() {
        let entries = [
            AddrV2Message { time: 0, services: ServiceFlags::NONE, addr: AddrV2::I2p([7; 32]), port: 0 },
            anchors()[0].to_addrv2(0).unwrap(),
        ];
        let mut buf = MAGIC.to_vec();
        buf.extend(encode_disk_vector(&entries));
        let checksum = sha256d::Hash::hash(&buf);
        buf.extend_from_slice(checksum.as_byte_array());
        assert_eq!(decode(&buf, MAGIC).unwrap(), anchors()[..1]);
    }
}
