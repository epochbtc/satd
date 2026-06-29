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
    /// Fresh per-process epoch nonce, generated at construction and
    /// **never persisted**. `node_id` is stable across restarts, but the
    /// per-publisher `seq` space (and therefore a [`Cursor`]'s
    /// `mempool_seq` high-water mark) resets to zero on every daemon
    /// start. A reconnecting client compares the `instance_id` carried in
    /// its saved cursor against the live stream's: a mismatch means the
    /// daemon restarted since the cursor was issued, so the stale
    /// `mempool_seq` must be discarded (treated as epoch start) rather
    /// than trusted. Durable confirmed `(height, tx_index)` replay is
    /// instance-independent and unaffected.
    pub instance_id: u64,
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
        // A fresh nonce per construction. In production `EdgeIdentity` is
        // built exactly once per daemon start (via `resolve`) and Copy-
        // threaded, so every event in a process shares one `instance_id`;
        // a restart yields a new one. Randomness (not a counter or the
        // start clock) keeps it collision-resistant across nodes and
        // robust to wall-clock adjustments.
        let instance_id = rand::random::<u64>();
        Ok(Self {
            node_id,
            region,
            instance_id,
        })
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
    /// In-band notice that the carrier dropped events for this subscriber
    /// (slow-consumer lag); the stream then continues live. Synthesized by
    /// the transport adapter on a `Lagged` broadcast error — never bridged
    /// from an internal event. `resume_cursor` is the position of the last
    /// event delivered before the gap, for a `from_cursor` reconnect.
    Lagged {
        dropped_count: u64,
        resume_cursor: Cursor,
    },
    /// Deterministic outcome of a mid-stream re-anchor (`SetCursor`). Like
    /// [`Lagged`](NodeEventBody::Lagged), this is synthesized by the carrier
    /// and emitted in-band — never bridged from an internal event. Emitted
    /// exactly once per actionable `SetCursor`, ahead of any confirmed history
    /// the re-anchor admits, so a client can distinguish "accepted, replaying"
    /// from "ignored, still live from the old position".
    SetCursorResult(SetCursorOutcome),
}

/// Why a mid-stream re-anchor was not admitted (see [`SetCursorOutcome`]).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CursorRejectReason {
    /// Per-principal re-anchor rate limit exceeded.
    RateLimited,
    /// Another re-anchor is already draining (only one runs at a time).
    ConcurrentReanchor,
    /// The `SetCursor` carried no cursor.
    EmptyCursor,
    /// The server has no block source to replay from.
    NoSource,
}

/// Deterministic result of a `SetCursor` re-anchor, carried in-band by
/// [`NodeEventBody::SetCursorResult`].
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SetCursorOutcome {
    /// The re-anchor was admitted; confirmed-history replay follows this event
    /// in height order before the live tail resumes. `clamped` is true when the
    /// requested cursor predated the replay window and the lower end was
    /// dropped — replay still runs, but only from `earliest_replayed`, and the
    /// client must full-resync history below it.
    Accepted {
        from: Cursor,
        clamped: bool,
        earliest_replayed: u32,
    },
    /// The re-anchor was not admitted; the live stream is unchanged.
    /// `current_head` is the server's present resume position.
    Rejected {
        reason: CursorRejectReason,
        current_head: Cursor,
    },
}

/// Durable resume position carried alongside confirmed-side events.
///
/// Confirmed cursors are `(height, tx_index)` — per-transaction, so a
/// reconnecting client can resume mid-block. `mempool_seq` is a
/// best-effort high-water mark for the mempool side (advisory; it tracks
/// the per-publisher `seq`, which resets on restart). A client persists
/// the `cursor` from the last [`NodeEvent`] it durably processed and
/// presents it to resume; the confirmed `(height, tx_index)` half is
/// reconstructable from the durable block store, the mempool half is not.
///
/// `instance_id` is the per-process epoch nonce of the publisher that
/// issued the cursor (see [`EdgeIdentity::instance_id`]). On resume the
/// server compares it against the live publisher's: a mismatch means the
/// daemon restarted since the cursor was issued, so the `mempool_seq`
/// watermark is from a dead `seq` space and is discarded (full mempool
/// window replay) rather than trusted. The confirmed half is unaffected.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Cursor {
    /// Block height of the last delivered confirmed item.
    pub height: u32,
    /// Index within that block of the last delivered transaction.
    pub tx_index: u32,
    /// Best-effort mempool high-water mark (advisory; resets on restart).
    pub mempool_seq: u64,
    /// Per-process epoch nonce of the issuing publisher. Rendered as a
    /// decimal **string** in JSON so JS/JSON consumers (WS/SSE) preserve
    /// the full 64-bit value without `Number` precision loss.
    #[serde(serialize_with = "serialize_u64_as_str")]
    pub instance_id: u64,
}

/// Serialize a `u64` as a decimal string — used for cursor fields whose
/// full 64-bit range must survive a round-trip through JSON `Number`
/// (which only preserves 53 bits of integer precision).
fn serialize_u64_as_str<S: Serializer>(v: &u64, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&v.to_string())
}

impl NodeEventBody {
    /// Derive the durable [`Cursor`] this body advances to, if any.
    ///
    /// A connected block advances the confirmed cursor to `(height, 0)`
    /// (block-level today; per-tx `tx_index` is populated once per-tx
    /// confirmed events exist). Other bodies do not advance the durable
    /// confirmed position, so they carry no cursor. `mempool_seq` is the
    /// current per-publisher sequence, stamped so a reconnecting client
    /// has a best-effort mempool high-water mark; `instance_id` is the
    /// issuing publisher's per-process epoch nonce (see [`Cursor`]).
    pub fn derive_cursor(&self, instance_id: u64, mempool_seq: u64) -> Option<Cursor> {
        match self {
            NodeEventBody::Chain(ChainEvent::BlockConnected { height, .. }) => Some(Cursor {
                height: *height,
                tx_index: 0,
                mempool_seq,
                instance_id,
            }),
            _ => None,
        }
    }
}

/// Versioned, edge-stamped event envelope. External transports emit
/// these; internal Rust subscribers continue using the raw broadcasts.
#[derive(Debug, Clone, Serialize)]
pub struct NodeEvent {
    pub schema_version: u32,
    pub stamp: EdgeStamp,
    /// Durable resume position as of this event. `Some` on confirmed-side
    /// bodies (a connected block); `None` on events that do not advance
    /// the durable cursor (mempool-only transitions, heartbeats).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    pub body: NodeEventBody,
}

impl NodeEvent {
    /// Construct an envelope with [`SCHEMA_VERSION`] and the given stamp
    /// + body, with no durable cursor.
    pub fn new(stamp: EdgeStamp, body: NodeEventBody) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            stamp,
            cursor: None,
            body,
        }
    }

    /// Construct an envelope carrying a durable [`Cursor`].
    pub fn with_cursor(stamp: EdgeStamp, cursor: Option<Cursor>, body: NodeEventBody) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            stamp,
            cursor,
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
            // A lag notice is a control signal, not a content category: it
            // must reach every subscriber regardless of the category mask, so
            // it sets all bits (and carriers emit it directly, bypassing the
            // filter, anyway).
            NodeEventBody::Lagged { .. } => u32::MAX,
            // A re-anchor ack is a control signal addressed to the requesting
            // subscriber, not a content category: it must reach the client
            // regardless of the category mask (and carriers emit it directly,
            // bypassing the filter, anyway).
            NodeEventBody::SetCursorResult(_) => u32::MAX,
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

    #[test]
    fn block_connected_derives_cursor_with_instance_id() {
        let body = NodeEventBody::Chain(ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [9u8; 32],
            )),
            height: 808_080,
        });
        let cur = body.derive_cursor(0xdead_beef_cafe_f00d, 42).expect("cursor");
        assert_eq!(cur.height, 808_080);
        assert_eq!(cur.tx_index, 0);
        assert_eq!(cur.mempool_seq, 42);
        assert_eq!(cur.instance_id, 0xdead_beef_cafe_f00d);
        // Non-confirmed bodies advance no durable cursor.
        assert!(NodeEventBody::Heartbeat { uptime_ns: 1 }
            .derive_cursor(1, 2)
            .is_none());
    }

    #[test]
    fn lagged_body_serializes_with_category_and_resume_cursor() {
        let resume = Cursor {
            height: 700,
            tx_index: 0,
            mempool_seq: 1234,
            instance_id: 0xABCD,
        };
        let env = NodeEvent::with_cursor(
            stamp(),
            Some(resume),
            NodeEventBody::Lagged {
                dropped_count: 42,
                resume_cursor: resume,
            },
        );
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["body"]["category"], "lagged");
        assert_eq!(v["body"]["dropped_count"], 42);
        assert_eq!(v["body"]["resume_cursor"]["height"], 700);
        // instance_id is a JS-safe string in every cursor, including the
        // resume cursor nested in a Lagged body.
        assert_eq!(
            v["body"]["resume_cursor"]["instance_id"],
            serde_json::Value::String("43981".to_string()),
        );
        // A lag notice must never be category-filtered out.
        assert_eq!(env.category_bit(), u32::MAX);
    }

    #[test]
    fn cursor_serializes_instance_id_as_string() {
        // A full-range u64 must survive JSON as a string — a JS `Number`
        // would silently lose precision above 2^53, breaking the client's
        // epoch comparison.
        let cur = Cursor {
            height: 5,
            tx_index: 0,
            mempool_seq: 7,
            instance_id: 0xFFFF_FFFF_FFFF_FFFF,
        };
        let v = serde_json::to_value(cur).unwrap();
        assert_eq!(v["height"], 5);
        assert_eq!(v["mempool_seq"], 7);
        assert_eq!(
            v["instance_id"],
            serde_json::Value::String("18446744073709551615".to_string()),
            "instance_id must serialize as a decimal string, not a JSON number",
        );
    }
}
