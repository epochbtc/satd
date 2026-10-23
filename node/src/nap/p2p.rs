//! The P2P messages, their paging, and the serving limits.
//!
//! ```text
//! getnapatt { anchor_height_min u32, keys varstr[] (<= 32), cursor optional outpoint }
//! napatt    { attestations attestation[], next_cursor optional outpoint }
//! ```
//!
//! An optional outpoint is a `u8` (0 absent, 1 present) followed, when
//! present, by the outpoint. The fields decode strictly, as the attestation
//! does, but bytes after the last field are ignored, so a later version can
//! append fields without this one treating its messages as malformed. A
//! change older nodes cannot skip takes a new command.
//!
//! A publisher answers a `getnapatt` from any peer, whether or not it
//! advertises [`NODE_NAP`]; it never sends a `napatt` unasked. Results are
//! ordered by outpoint, then key, and a page never splits an outpoint.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bitcoin::OutPoint;
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::p2p::ServiceFlags;

use super::{Attestation, FormatError, MAX_KEYS_PER_OUTPOINT, message};

/// `NODE_NAP`: the node publishes attestations. Bit 30, from the range
/// Bitcoin Core reserves for temporary experiments (`protocol.h`).
pub const NODE_NAP_BIT: u64 = 1 << 30;
/// The `getnapatt` command.
pub const GETNAPATT: &str = "getnapatt";
/// The `napatt` command.
pub const NAPATT: &str = "napatt";
/// The largest serialized `napatt`, in bytes.
pub const MAX_NAPATT_SIZE: usize = 1_000_000;
/// The most keys a `getnapatt` filters on.
pub const MAX_GETNAPATT_KEYS: usize = 32;

/// How often one connection may start a new pull.
pub const PULL_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// The window both byte budgets are counted over.
pub const BUDGET_WINDOW: Duration = Duration::from_secs(60 * 60);
/// The bytes one connection is served per [`BUDGET_WINDOW`].
pub const CONN_BUDGET_BYTES: u64 = 200_000_000;
/// How many times the per-connection limits a network group gets: new pulls
/// per [`PULL_INTERVAL`], and bytes per [`BUDGET_WINDOW`].
pub const GROUP_MULTIPLE: u64 = 8;

/// [`NODE_NAP_BIT`] as service flags.
pub fn node_nap() -> ServiceFlags {
    ServiceFlags::from(NODE_NAP_BIT)
}

/// A request for the attestations a peer publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNapAtt {
    /// Only attestations anchored at or above this height.
    pub anchor_height_min: u32,
    /// Only these keys; empty is every key.
    pub keys: Vec<String>,
    /// Resume after this outpoint; `None` starts a pull.
    pub cursor: Option<OutPoint>,
}

/// One page of attestations, answering one [`GetNapAtt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapAtt {
    pub attestations: Vec<Attestation>,
    /// The last outpoint in this page, when more follow.
    pub next_cursor: Option<OutPoint>,
}

fn encode_cursor<W: bitcoin::io::Write + ?Sized>(
    cursor: &Option<OutPoint>,
    w: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    match cursor {
        None => 0u8.consensus_encode(w),
        Some(op) => Ok(1u8.consensus_encode(w)? + op.consensus_encode(w)?),
    }
}

fn decode_cursor(r: &mut &[u8]) -> Result<Option<OutPoint>, FormatError> {
    match u8::consensus_decode(r)? {
        0 => Ok(None),
        1 => Ok(Some(OutPoint::consensus_decode(r)?)),
        b => Err(FormatError::Decode(format!("cursor flag {b}"))),
    }
}

/// A compact size, refused if it is over `max`.
fn count(r: &mut &[u8], max: usize, what: &str) -> Result<usize, FormatError> {
    let n = encode::VarInt::consensus_decode(r)?.0;
    if n > max as u64 {
        return Err(FormatError::Decode(format!("{n} {what}, over the limit of {max}")));
    }
    Ok(n as usize)
}

impl Encodable for GetNapAtt {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = self.anchor_height_min.consensus_encode(w)?;
        len += encode::VarInt(self.keys.len() as u64).consensus_encode(w)?;
        for key in &self.keys {
            len += key.as_bytes().to_vec().consensus_encode(w)?;
        }
        len += encode_cursor(&self.cursor, w)?;
        Ok(len)
    }
}

impl GetNapAtt {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode::serialize(self)
    }

    /// Decode a `getnapatt` payload, ignoring bytes after its fields. Each
    /// key must be one an attestation could carry.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = bytes;
        let anchor_height_min = u32::consensus_decode(&mut r)?;
        let n = count(&mut r, MAX_GETNAPATT_KEYS, "keys")?;
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            let len = count(&mut r, super::MAX_KEY_LEN, "key bytes")?;
            if r.len() < len {
                return Err(FormatError::Decode("truncated".into()));
            }
            let (key, rest) = r.split_at(len);
            r = rest;
            message::check_key(key)?;
            keys.push(String::from_utf8(key.to_vec()).expect("checked printable"));
        }
        let cursor = decode_cursor(&mut r)?;
        Ok(GetNapAtt { anchor_height_min, keys, cursor })
    }

    fn wants(&self, att: &Attestation) -> bool {
        att.anchor_height() >= self.anchor_height_min
            && (self.keys.is_empty() || self.keys.iter().any(|k| k == att.key()))
    }
}

impl Encodable for NapAtt {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = encode::VarInt(self.attestations.len() as u64).consensus_encode(w)?;
        for att in &self.attestations {
            len += att.consensus_encode(w)?;
        }
        len += encode_cursor(&self.next_cursor, w)?;
        Ok(len)
    }
}

impl NapAtt {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode::serialize(self)
    }

    /// Decode a `napatt` payload, ignoring bytes after its fields, and
    /// refusing one over [`MAX_NAPATT_SIZE`] before reading it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_NAPATT_SIZE {
            return Err(FormatError::Decode(format!(
                "napatt is {} bytes, over the {MAX_NAPATT_SIZE}-byte limit",
                bytes.len()
            )));
        }
        let mut r = bytes;
        // Every attestation is well over a byte, so the count is bounded by
        // the payload before any is read.
        let n = count(&mut r, bytes.len(), "attestations")?;
        let mut attestations = Vec::new();
        for _ in 0..n {
            attestations.push(Attestation::decode_from(&mut r)?);
        }
        let next_cursor = decode_cursor(&mut r)?;
        Ok(NapAtt { attestations, next_cursor })
    }
}

/// The page answering `req`, from `atts` ordered by outpoint then key: the
/// wanted attestations of each outpoint after the cursor, whole outpoints
/// only, while the serialized page stays within `max_size`. The first
/// outpoint is always included; at most [`MAX_KEYS_PER_OUTPOINT`]
/// attestations of [`super::MAX_ATTESTATION_SIZE`] bytes, it is well within
/// [`MAX_NAPATT_SIZE`]. Ends with a cursor when wanted attestations remain
/// past the page.
pub fn page<'a>(atts: impl IntoIterator<Item = &'a Attestation>, req: &GetNapAtt, max_size: usize) -> NapAtt {
    // The count's compact size and a present cursor, at their largest.
    const OVERHEAD: usize = 9 + 1 + 36;
    let mut out: Vec<Attestation> = Vec::new();
    let mut size = OVERHEAD;
    let mut group: Vec<&Attestation> = Vec::with_capacity(MAX_KEYS_PER_OUTPOINT);
    let mut group_size = 0;
    let mut more = false;
    let wanted = atts
        .into_iter()
        .filter(|a| req.cursor.is_none_or(|c| a.outpoint() > c))
        .filter(|a| req.wants(a));
    for att in wanted {
        if group.first().is_some_and(|g| g.outpoint() != att.outpoint()) {
            if !out.is_empty() && size + group_size > max_size {
                more = true;
                group.clear();
                break;
            }
            size += group_size;
            out.extend(group.drain(..).cloned());
            group_size = 0;
        }
        group_size += super::wire::serialized_size(att);
        group.push(att);
    }
    if !group.is_empty() {
        if out.is_empty() || size + group_size <= max_size {
            out.extend(group.drain(..).cloned());
        } else {
            more = true;
        }
    }
    let next_cursor = if more { out.last().map(|a| a.outpoint()) } else { None };
    NapAtt { attestations: out, next_cursor }
}

/// Why a request was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The connection started a pull less than [`PULL_INTERVAL`] ago.
    ConnPull,
    /// The network group started [`GROUP_MULTIPLE`] pulls in the last
    /// [`PULL_INTERVAL`].
    GroupPull,
    /// The connection's byte budget for the window is spent.
    ConnBytes,
    /// The network group's byte budget for the window is spent.
    GroupBytes,
}

/// Bytes served in a window that starts with the first byte served in it.
#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    used: u64,
}

impl Window {
    fn used(&self, now: Instant) -> u64 {
        if now.saturating_duration_since(self.start) >= BUDGET_WINDOW { 0 } else { self.used }
    }

    fn add(window: &mut Option<Window>, bytes: u64, now: Instant) {
        match window {
            Some(w) if now.saturating_duration_since(w.start) < BUDGET_WINDOW => w.used += bytes,
            _ => *window = Some(Window { start: now, used: bytes }),
        }
    }
}

struct Conn {
    group: Vec<u8>,
    last_pull: Option<Instant>,
    bytes: Option<Window>,
    /// The cursor last sent, which a continuation must quote.
    expected: Option<OutPoint>,
}

#[derive(Default)]
struct Group {
    pulls: VecDeque<Instant>,
    bytes: Option<Window>,
}

impl Group {
    fn idle(&self, now: Instant) -> bool {
        self.pulls.is_empty() && self.bytes.is_none_or(|w| w.used(now) == 0)
    }
}

/// The serving limits, per connection and per network group (the design's
/// Serving limits). A connection's limits end with it; a group's outlive
/// its connections, so reconnecting resets only the connection's own.
///
/// A request with a cursor continues a pull only when the cursor is the one
/// this connection was last sent; any other request starts a pull.
#[derive(Default)]
pub struct ServeLimits {
    conns: HashMap<u64, Conn>,
    groups: HashMap<Vec<u8>, Group>,
    last_prune: Option<Instant>,
}

/// An admitted request, to be [`ServeLimits::commit`]ted once its page is
/// built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pull: bool,
}

impl ServeLimits {
    /// Whether `peer`, in network group `group`, may be served a request
    /// with `cursor` at `now`, before its page is built, so a refused
    /// request costs no page. A budget with less than a whole page
    /// ([`MAX_NAPATT_SIZE`]) left is treated as spent: pages never split an
    /// outpoint, so a smaller remainder would otherwise admit request after
    /// request whose page [`Self::commit`] then refuses.
    pub fn admit(
        &mut self,
        peer: u64,
        group: &[u8],
        cursor: Option<OutPoint>,
        now: Instant,
    ) -> Result<Admitted, Refused> {
        self.prune(now);
        let conn = self.conns.entry(peer).or_insert_with(|| Conn {
            group: group.to_vec(),
            last_pull: None,
            bytes: None,
            expected: None,
        });
        let grp = self.groups.entry(group.to_vec()).or_default();
        while grp.pulls.front().is_some_and(|t| now.saturating_duration_since(*t) >= PULL_INTERVAL) {
            grp.pulls.pop_front();
        }
        let pull = cursor.is_none() || cursor != conn.expected;
        if pull {
            if conn.last_pull.is_some_and(|t| now.saturating_duration_since(t) < PULL_INTERVAL) {
                return Err(Refused::ConnPull);
            }
            if grp.pulls.len() as u64 >= GROUP_MULTIPLE {
                return Err(Refused::GroupPull);
            }
        }
        let page = MAX_NAPATT_SIZE as u64;
        if conn.bytes.map_or(0, |w| w.used(now)) + page > CONN_BUDGET_BYTES {
            return Err(Refused::ConnBytes);
        }
        if grp.bytes.map_or(0, |w| w.used(now)) + page > CONN_BUDGET_BYTES * GROUP_MULTIPLE {
            return Err(Refused::GroupBytes);
        }
        Ok(Admitted { pull })
    }

    /// Charge a page of `size` bytes, ending at `next_cursor`, to an
    /// admitted request, or refuse it if either byte budget cannot cover it
    /// (which [`Self::admit`] already rules out for a page within
    /// [`MAX_NAPATT_SIZE`]).
    pub fn commit(
        &mut self,
        peer: u64,
        admitted: Admitted,
        size: usize,
        next_cursor: Option<OutPoint>,
        now: Instant,
    ) -> Result<(), Refused> {
        let size = size as u64;
        let conn = self.conns.get_mut(&peer).expect("admitted");
        let grp = self.groups.entry(conn.group.clone()).or_default();
        if conn.bytes.map_or(0, |w| w.used(now)) + size > CONN_BUDGET_BYTES {
            return Err(Refused::ConnBytes);
        }
        if grp.bytes.map_or(0, |w| w.used(now)) + size > CONN_BUDGET_BYTES * GROUP_MULTIPLE {
            return Err(Refused::GroupBytes);
        }
        if admitted.pull {
            conn.last_pull = Some(now);
            grp.pulls.push_back(now);
        }
        Window::add(&mut conn.bytes, size, now);
        Window::add(&mut grp.bytes, size, now);
        conn.expected = next_cursor;
        Ok(())
    }

    /// Drop a connection's limits when it closes. Its group's stay.
    pub fn forget(&mut self, peer: u64) {
        self.conns.remove(&peer);
    }

    /// Drop the groups with nothing left to count, once a minute.
    fn prune(&mut self, now: Instant) {
        if self.last_prune.is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(60)) {
            return;
        }
        self.last_prune = Some(now);
        for grp in self.groups.values_mut() {
            while grp.pulls.front().is_some_and(|t| now.saturating_duration_since(*t) >= PULL_INTERVAL) {
                grp.pulls.pop_front();
            }
        }
        let live: std::collections::HashSet<&Vec<u8>> = self.conns.values().map(|c| &c.group).collect();
        self.groups.retain(|g, grp| live.contains(g) || !grp.idle(now));
    }

    #[cfg(test)]
    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }
}
