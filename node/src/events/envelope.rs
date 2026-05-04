//! [`NodeEvent`] — the wire-level envelope external transports emit.
//!
//! Wraps the existing internal events ([`MempoolEvent`], [`ChainEvent`])
//! in a versioned, edge-stamped record. Adapters (gRPC, ZMQ, …) consume
//! the envelope; internal Rust subscribers continue using the raw
//! broadcasts directly.

use std::fs;
use std::path::{Path, PathBuf};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::chain::events::ChainEvent;
use crate::mempool::events::MempoolEvent;

use super::schema::SCHEMA_VERSION;

/// Filename inside `<datadir>` that holds the auto-generated UUIDv4 if
/// the operator did not pin one via `--node-id`. Created on first start
/// and read verbatim afterwards so the identifier is stable across
/// restarts (downstream consumers can deduplicate when a node briefly
/// flaps).
pub const NODE_ID_FILENAME: &str = "node_id";

/// Maximum length of the packed `region` tag. Eight ASCII bytes covers
/// common AWS / GCP region codes (`us-east-1`, `eu-west2`, etc.) without
/// inflating the wire envelope. Longer values are an error at parse
/// time — operators should use a shorter alias.
pub const REGION_BYTES: usize = 8;

/// Identity stamped on every [`NodeEvent`]. Constructed once at daemon
/// start and threaded into the [`super::EventPublisher`].
#[derive(Debug, Clone, Copy)]
pub struct EdgeIdentity {
    pub node_id: [u8; 16],
    pub region: Option<[u8; REGION_BYTES]>,
}

/// Errors loading or persisting the node-id / region.
#[derive(Debug, thiserror::Error)]
pub enum EdgeIdentityError {
    #[error("node-id must be a 32-character hex string ({0} chars given)")]
    NodeIdLength(usize),
    #[error("node-id is not valid hex: {0}")]
    NodeIdHex(#[from] hex::FromHexError),
    #[error("region tag is empty or whitespace-only")]
    RegionEmpty,
    #[error("region tag must be ASCII and at most {max} bytes ('{tag}' is {len} bytes)")]
    RegionTooLong { tag: String, len: usize, max: usize },
    #[error("region tag must be printable ASCII, got byte 0x{0:02x}")]
    RegionNotAscii(u8),
    #[error("failed to read node-id file at {path}: {source}")]
    NodeIdRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write node-id file at {path}: {source}")]
    NodeIdWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl EdgeIdentity {
    /// Construct from explicit values. `region` is parsed via
    /// [`Self::parse_region`].
    pub fn new(
        node_id: [u8; 16],
        region: Option<&str>,
    ) -> Result<Self, EdgeIdentityError> {
        let region = match region {
            Some(s) => Some(Self::parse_region(s)?),
            None => None,
        };
        Ok(Self { node_id, region })
    }

    /// Resolve the node-id from operator-provided value, the persisted
    /// file at `<datadir>/node_id`, or by generating a fresh UUIDv4.
    ///
    /// `explicit_node_id` (when `Some`) is parsed as a 32-char hex
    /// string and used verbatim — it is **not** persisted, so changing
    /// the flag does not corrupt the stored identifier.
    ///
    /// When `explicit_node_id` is `None`:
    /// - if `<datadir>/node_id` exists, parse it.
    /// - otherwise generate a fresh UUIDv4 and persist it.
    pub fn resolve(
        datadir: &Path,
        explicit_node_id: Option<&str>,
        region: Option<&str>,
    ) -> Result<Self, EdgeIdentityError> {
        let node_id = match explicit_node_id {
            Some(s) => parse_node_id(s)?,
            None => load_or_generate_node_id(datadir)?,
        };
        Self::new(node_id, region)
    }

    /// Parse a region tag into its packed-ASCII representation. Empty,
    /// non-ASCII, or too-long inputs are rejected.
    pub fn parse_region(raw: &str) -> Result<[u8; REGION_BYTES], EdgeIdentityError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EdgeIdentityError::RegionEmpty);
        }
        if trimmed.len() > REGION_BYTES {
            return Err(EdgeIdentityError::RegionTooLong {
                tag: trimmed.to_string(),
                len: trimmed.len(),
                max: REGION_BYTES,
            });
        }
        for b in trimmed.as_bytes() {
            if !(0x20..0x7f).contains(b) {
                return Err(EdgeIdentityError::RegionNotAscii(*b));
            }
        }
        let mut out = [0u8; REGION_BYTES];
        out[..trimmed.len()].copy_from_slice(trimmed.as_bytes());
        Ok(out)
    }

    /// Render the node-id as a 32-character lowercase hex string.
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }

    /// Render the region as a `&str` if present, trimming trailing
    /// padding zeroes.
    pub fn region_str(&self) -> Option<&str> {
        self.region.as_ref().map(|raw| {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(REGION_BYTES);
            std::str::from_utf8(&raw[..end]).unwrap_or("")
        })
    }
}

#[cfg(test)]
mod stamp_serde_tests {
    use super::*;

    fn stamp() -> EdgeStamp {
        EdgeStamp {
            node_id: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef,
            ],
            region: Some(*b"us-east1"),
            edge_seen_at_ns: 12_345_678,
            edge_wall_ns: 1_700_000_000_000_000_000,
            seq: 42,
        }
    }

    #[test]
    fn stamp_json_renders_node_id_as_hex() {
        let v = serde_json::to_value(stamp()).unwrap();
        assert_eq!(v["node_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(v["node_id"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn stamp_json_renders_region_as_trimmed_string() {
        let v = serde_json::to_value(stamp()).unwrap();
        assert_eq!(v["region"], "us-east1");
    }

    #[test]
    fn stamp_json_region_padded_short_value_is_trimmed() {
        let s = EdgeStamp {
            region: Some(*b"eu-w\0\0\0\0"),
            ..stamp()
        };
        let v = serde_json::to_value(s).unwrap();
        assert_eq!(v["region"], "eu-w");
    }

    #[test]
    fn stamp_json_region_none_serializes_as_null() {
        let s = EdgeStamp {
            region: None,
            ..stamp()
        };
        let v = serde_json::to_value(s).unwrap();
        assert!(v["region"].is_null());
    }

    #[test]
    fn stamp_json_preserves_numeric_fields() {
        let v = serde_json::to_value(stamp()).unwrap();
        assert_eq!(v["edge_seen_at_ns"], 12_345_678);
        assert_eq!(v["edge_wall_ns"], 1_700_000_000_000_000_000_u64);
        assert_eq!(v["seq"], 42);
    }
}

fn parse_node_id(s: &str) -> Result<[u8; 16], EdgeIdentityError> {
    let s = s.trim();
    if s.len() != 32 {
        return Err(EdgeIdentityError::NodeIdLength(s.len()));
    }
    let mut out = [0u8; 16];
    hex::decode_to_slice(s, &mut out)?;
    Ok(out)
}

fn load_or_generate_node_id(datadir: &Path) -> Result<[u8; 16], EdgeIdentityError> {
    let path = datadir.join(NODE_ID_FILENAME);
    match fs::read_to_string(&path) {
        Ok(contents) => parse_node_id(&contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = *uuid::Uuid::new_v4().as_bytes();
            // Best-effort persist. If the datadir does not yet exist
            // (first start before chain init), bubble that up so the
            // operator sees a clear error rather than a silently
            // regenerated id on every restart.
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                fs::create_dir_all(parent).map_err(|source| {
                    EdgeIdentityError::NodeIdWrite {
                        path: path.clone(),
                        source,
                    }
                })?;
            }
            fs::write(&path, hex::encode(id)).map_err(|source| {
                EdgeIdentityError::NodeIdWrite {
                    path: path.clone(),
                    source,
                }
            })?;
            Ok(id)
        }
        Err(source) => Err(EdgeIdentityError::NodeIdRead { path, source }),
    }
}

/// Per-event stamp applied at the bridge layer of the
/// [`super::EventPublisher`]. All sinks see identical stamps for the
/// same source event, so downstream pipelines can correlate observations
/// across transports.
///
/// JSON shape (custom serialization via [`Serialize`]):
/// ```json
/// {
///   "node_id": "0123456789abcdef0123456789abcdef",
///   "region": "us-east1",
///   "edge_seen_at_ns": 12345678,
///   "edge_wall_ns": 1700000000000000000,
///   "seq": 42
/// }
/// ```
/// `node_id` is the 32-character lowercase hex render of the 16-byte
/// identifier; `region` is the trimmed ASCII tag (or `null` if unset).
/// Sinks that need raw bytes (e.g. the gRPC adapter mapping into a
/// `bytes` field) read the public fields directly.
#[derive(Debug, Clone, Copy)]
pub struct EdgeStamp {
    /// Stable per-node identifier. UUIDv4 by default.
    pub node_id: [u8; 16],
    /// Operator-provided geo / topology tag, packed ASCII.
    pub region: Option<[u8; REGION_BYTES]>,
    /// Monotonic-clock time at the moment the bridge converted the
    /// internal event to a [`NodeEvent`]. Nanoseconds since publisher
    /// construction (so the value is monotonic and cheap to capture).
    pub edge_seen_at_ns: u64,
    /// Wall-clock realtime nanoseconds since the Unix epoch, captured
    /// at the same instant as `edge_seen_at_ns`. Subject to clock
    /// adjustments (NTP, manual `date -s`) and therefore not monotonic.
    /// Use [`Self::edge_seen_at_ns`] for ordering on a single node and
    /// `edge_wall_ns` for cross-node correlation (with awareness of
    /// inter-node clock skew).
    pub edge_wall_ns: u64,
    /// Per-`EventPublisher` monotonic sequence number, starting at 1.
    /// Restarts at 1 on daemon restart — pair with `node_id` for global
    /// uniqueness or with `edge_wall_ns` for ordering across restarts.
    pub seq: u64,
}

impl EdgeStamp {
    /// Render the trimmed region tag as a borrowed `&str`, or `None` if
    /// no region was configured.
    pub fn region_str(&self) -> Option<&str> {
        self.region.as_ref().map(|raw| {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(REGION_BYTES);
            std::str::from_utf8(&raw[..end]).unwrap_or("")
        })
    }
}

impl Serialize for EdgeStamp {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let node_id_hex = hex::encode(self.node_id);
        let region = self.region_str();
        let mut s = ser.serialize_struct("EdgeStamp", 5)?;
        s.serialize_field("node_id", &node_id_hex)?;
        s.serialize_field("region", &region)?;
        s.serialize_field("edge_seen_at_ns", &self.edge_seen_at_ns)?;
        s.serialize_field("edge_wall_ns", &self.edge_wall_ns)?;
        s.serialize_field("seq", &self.seq)?;
        s.end()
    }
}

/// Body variants carried by [`NodeEvent`]. The discriminator field is
/// `category` (rendered snake_case: `mempool`, `chain`, `heartbeat`) —
/// distinct from the inner `MempoolEvent`'s and `ChainEvent`'s own
/// `kind` field so the outer tag does not collide with the inner one.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum NodeEventBody {
    Mempool(MempoolEvent),
    Chain(ChainEvent),
    Heartbeat {
        /// Nanoseconds since the [`super::EventPublisher`] was
        /// constructed. Lets downstream consumers measure end-to-end
        /// pipeline latency without an out-of-band clock.
        uptime_ns: u64,
    },
}

/// Versioned, edge-stamped event envelope. External transports emit
/// these; internal Rust subscribers continue using the raw broadcasts.
#[derive(Debug, Clone, Serialize)]
pub struct NodeEvent {
    pub schema_version: u32,
    pub stamp: EdgeStamp,
    pub body: NodeEventBody,
}

impl NodeEvent {
    /// Construct an envelope with [`SCHEMA_VERSION`] and the given stamp
    /// + body.
    pub fn new(stamp: EdgeStamp, body: NodeEventBody) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            stamp,
            body,
        }
    }

    /// Categorize this envelope for subscriber filters. Bitfield values
    /// match the gRPC `SubscribeRequest.categories` semantics: `mempool=1`,
    /// `chain=2`, `heartbeat=4`. A subscriber requesting `0` receives all
    /// categories (the conservative default).
    pub fn category_bit(&self) -> u32 {
        match &self.body {
            NodeEventBody::Mempool(_) => 1,
            NodeEventBody::Chain(_) => 2,
            NodeEventBody::Heartbeat { .. } => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};
    use tempfile::tempdir;

    fn stamp() -> EdgeStamp {
        EdgeStamp {
            node_id: [0xab; 16],
            region: Some(*b"us-east1"),
            edge_seen_at_ns: 100,
            edge_wall_ns: 1_700_000_000_000_000_000,
            seq: 1,
        }
    }

    #[test]
    fn parse_region_packs_ascii() {
        let r = EdgeIdentity::parse_region("us-east1").unwrap();
        assert_eq!(&r, b"us-east1");
        let r = EdgeIdentity::parse_region("eu-w").unwrap();
        assert_eq!(&r[..4], b"eu-w");
        assert_eq!(&r[4..], &[0u8; 4]);
    }

    #[test]
    fn parse_region_rejects_long() {
        assert!(matches!(
            EdgeIdentity::parse_region("too-long-region"),
            Err(EdgeIdentityError::RegionTooLong { .. })
        ));
    }

    #[test]
    fn parse_region_rejects_non_ascii() {
        assert!(matches!(
            EdgeIdentity::parse_region("café"),
            Err(EdgeIdentityError::RegionNotAscii(_))
        ));
    }

    #[test]
    fn parse_region_rejects_empty() {
        assert!(matches!(
            EdgeIdentity::parse_region("   "),
            Err(EdgeIdentityError::RegionEmpty)
        ));
    }

    #[test]
    fn region_str_round_trip() {
        let id = EdgeIdentity::new([0; 16], Some("eu-w")).unwrap();
        assert_eq!(id.region_str(), Some("eu-w"));
    }

    #[test]
    fn node_id_persisted_then_reloaded() {
        let dir = tempdir().unwrap();
        let id1 = EdgeIdentity::resolve(dir.path(), None, None).unwrap();
        let id2 = EdgeIdentity::resolve(dir.path(), None, None).unwrap();
        assert_eq!(id1.node_id, id2.node_id);
        // Persisted file is plain hex, no whitespace.
        let raw = std::fs::read_to_string(dir.path().join(NODE_ID_FILENAME)).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(raw, id1.node_id_hex());
    }

    #[test]
    fn explicit_node_id_overrides_file() {
        let dir = tempdir().unwrap();
        // Pre-seed file with id A
        let id_a = EdgeIdentity::resolve(dir.path(), None, None).unwrap();
        // Operator passes id B explicitly
        let id_b_hex = "11223344556677889900aabbccddeeff";
        let id_b = EdgeIdentity::resolve(dir.path(), Some(id_b_hex), None).unwrap();
        assert_ne!(id_a.node_id, id_b.node_id);
        assert_eq!(id_b.node_id_hex(), id_b_hex);
        // File is untouched — flag is volatile.
        let raw = std::fs::read_to_string(dir.path().join(NODE_ID_FILENAME)).unwrap();
        assert_eq!(raw, id_a.node_id_hex());
    }

    #[test]
    fn explicit_node_id_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            EdgeIdentity::resolve(dir.path(), Some("abc"), None),
            Err(EdgeIdentityError::NodeIdLength(3))
        ));
    }

    #[test]
    fn envelope_serializes_with_schema_version() {
        let body = NodeEventBody::Mempool(MempoolEvent::Enter {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [1u8; 32],
            )),
            fee: 100,
            vsize: 250,
            fee_rate_sat_per_kvb: 400,
            time: 1_700_000_000,
        });
        let env = NodeEvent::new(stamp(), body);
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        // Outer discriminator is `category`; inner `kind` is preserved.
        assert_eq!(v["body"]["category"], "mempool");
        assert_eq!(v["body"]["kind"], "enter");
        assert_eq!(v["body"]["fee"], 100);
    }

    #[test]
    fn category_bits_are_disjoint() {
        let env_m = NodeEvent::new(
            stamp(),
            NodeEventBody::Mempool(MempoolEvent::LeaveReplaced {
                txid: Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                ),
                replacing_txid: Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]),
                ),
            }),
        );
        let env_c = NodeEvent::new(
            stamp(),
            NodeEventBody::Chain(ChainEvent::BlockConnected {
                hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]),
                ),
                height: 42,
            }),
        );
        let env_h = NodeEvent::new(stamp(), NodeEventBody::Heartbeat { uptime_ns: 7 });
        assert_eq!(env_m.category_bit(), 1);
        assert_eq!(env_c.category_bit(), 2);
        assert_eq!(env_h.category_bit(), 4);
    }
}
