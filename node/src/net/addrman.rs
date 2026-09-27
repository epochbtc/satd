//! A persistent address manager (`peers.dat`).
//!
//! satd previously held learned peer addresses in a plain in-memory
//! `Vec` that was lost on restart. This module adds a bounded, persisted
//! address book modeled on Bitcoin Core's addrman: addresses are split
//! into a *new* table (gossiped/seeded, unverified) and a *tried* table
//! (we have connected successfully), and both are bucketed by network
//! *group* (the `/16` for IPv4, or — once `-asmap` is wired — the ASN) so
//! that no single network group can dominate the table and eclipse the
//! node. Selection is biased ~50/50 between tried and new.
//!
//! The on-disk format is satd-native and versioned (magic `SADR`); it is
//! NOT byte-compatible with Core's `peers.dat`, and is treated as
//! untrusted on load (capped, malformed records skipped). Version 2 adds
//! each entry's advertised service bits and the address of the peer that
//! told us about it; a version 1 file still loads, with Core's defaults for
//! the two fields.
//!
//! Core's addrman stores every entry at a fixed `bucket/position` slot, and
//! `getrawaddrman` reports those slots. satd keeps a flat map instead, so
//! [`AddrMan::positions`] *derives* a slot for each entry with Core's own
//! bucket formulas, keyed by a per-process random key. The slots are stable
//! for the life of the process and spread entries the way Core's do, but
//! they are not where anything is stored, and two processes disagree.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// Hard cap on total stored addresses (new + tried). Keeps `peers.dat`
/// and memory bounded; well above what a single node needs to bootstrap.
const MAX_ENTRIES: usize = 16_384;
/// Per-network-group cap in the *new* table (eclipse resistance: stop one
/// `/16`/ASN from flooding the book with addresses).
const MAX_NEW_PER_GROUP: usize = 64;

/// The service bits an entry carries when nothing better is known:
/// `NODE_NETWORK | NODE_WITNESS`, which is what Core's `addpeeraddress`
/// records and what a version 1 `peers.dat` entry is loaded with.
pub const DEFAULT_SERVICES: u64 = 1 | 8;

/// Current `peers.dat` format version (see the module docs).
const FORMAT_VERSION: u32 = 2;

// Core's table geometry (`src/addrman_impl.h`), used to derive the
// `bucket/position` slots `getrawaddrman` reports.
const TRIED_BUCKET_COUNT: u64 = 256;
const NEW_BUCKET_COUNT: u64 = 1024;
const BUCKET_SIZE: u64 = 64;
const TRIED_BUCKETS_PER_GROUP: u64 = 8;
const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;

#[derive(Clone, Debug)]
pub struct AddrEntry {
    pub addr: SocketAddr,
    /// We have completed a handshake with this address at least once.
    pub tried: bool,
    /// Unix seconds of last successful connect (0 if never).
    pub last_success: u64,
    /// Consecutive failed attempts since the last success.
    pub attempts: u32,
    /// Unix seconds this address was last seen (gossiped or connected).
    pub last_seen: u64,
    /// Service bits the address was announced with (Core's `nServices`).
    pub services: u64,
    /// The peer that told us about this address (Core's `source`). An
    /// address we learned by connecting to it, or that was added by hand,
    /// is its own source, as in Core's `addpeeraddress`.
    pub source: IpAddr,
    /// Cached network-group key (`group_fn(ip)`), computed once when the
    /// entry is inserted. Cached so the per-group cap check does not have
    /// to re-run `group_fn` for every entry on every `add` — that recompute
    /// is O(n) per gossiped address, and under `-asmap` each call is a trie
    /// walk, which an address flood could amplify into a CPU sink. Not
    /// persisted: it depends on the active `group_fn` (`-asmap`), so it is
    /// recomputed on load.
    group: Vec<u8>,
}

/// Network group key used for bucketing. IPv4 → the `/16`; IPv6 → the
/// `/32`. A custom grouping (e.g. `-asmap` ASN) can be installed via
/// [`AddrMan::set_group_fn`].
fn default_group(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets()[..2].to_vec(),
        IpAddr::V6(v6) => {
            // IPv4-mapped → group by the embedded v4 /16.
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.octets()[..2].to_vec()
            } else {
                v6.octets()[..4].to_vec()
            }
        }
    }
}

type GroupFn = Box<dyn Fn(IpAddr) -> Vec<u8> + Send + Sync>;

pub struct AddrMan {
    entries: HashMap<SocketAddr, AddrEntry>,
    /// Pluggable network-group function (replaced by `-asmap`).
    group_fn: GroupFn,
    /// SipHash key for the derived `bucket/position` slots (Core's
    /// `nKey`). Random per process, so slots are stable within a run.
    slot_key: (u64, u64),
}

/// Where [`AddrMan::positions`] places an entry: its table and its derived
/// `bucket/position` slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrSlot {
    pub tried: bool,
    pub bucket: u64,
    pub position: u64,
}

/// Per-table counts for one network, as `getaddrmaninfo` reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableCounts {
    pub new: usize,
    pub tried: usize,
}

impl TableCounts {
    pub fn total(&self) -> usize {
        self.new + self.tried
    }
}

/// Network of an address, spelled as Core's `GetNetworkName` spells it. An
/// IPv4-mapped IPv6 address is IPv4. The address book holds only socket
/// addresses, so the answer is always `ipv4` or `ipv6`.
pub fn network_name(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

/// An address as Core's `ToStringAddr` prints it: the bare IP, with an
/// IPv4-mapped IPv6 address shown as the IPv4 it carries.
pub fn addr_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// Core's `CService::GetKey`-equivalent input for the slot hashes: the IP in
/// its 16-byte form followed by the big-endian port.
fn addr_key(addr: &SocketAddr) -> Vec<u8> {
    let mut k = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    k.extend_from_slice(&addr.port().to_be_bytes());
    k
}

impl Default for AddrMan {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrMan {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            group_fn: Box::new(default_group),
            slot_key: (rand::random(), rand::random()),
        }
    }

    /// Install a custom network-group function (e.g. ASN-based via
    /// `-asmap`). Must be called before addresses are added for bucketing
    /// to use it consistently.
    pub fn set_group_fn(&mut self, f: GroupFn) {
        self.group_fn = f;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn group_of(&self, addr: &SocketAddr) -> Vec<u8> {
        (self.group_fn)(addr.ip())
    }

    fn new_count_in_group(&self, group: &[u8]) -> usize {
        // Uses the cached `e.group` rather than re-running `group_fn`, so
        // this stays a cheap byte-slice comparison even under `-asmap`.
        self.entries
            .values()
            .filter(|e| !e.tried && e.group == group)
            .count()
    }

    /// Add (or refresh) a gossiped/seeded address. Honors the total and
    /// per-group caps. Returns true if a new entry was inserted. The entry
    /// gets the default service bits and is its own source; use
    /// [`add_from`](Self::add_from) when the announcement carried both.
    pub fn add(&mut self, addr: SocketAddr, now: u64) -> bool {
        self.add_from(addr, now, DEFAULT_SERVICES, addr.ip())
    }

    /// [`add`](Self::add) with the announced service bits and the address
    /// of the peer that announced it. A refresh of a known address updates
    /// its last-seen time only, as before.
    pub fn add_from(&mut self, addr: SocketAddr, now: u64, services: u64, source: IpAddr) -> bool {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.last_seen = now;
            return false;
        }
        if self.entries.len() >= MAX_ENTRIES {
            return false;
        }
        let group = self.group_of(&addr);
        if self.new_count_in_group(&group) >= MAX_NEW_PER_GROUP {
            return false;
        }
        self.entries.insert(
            addr,
            AddrEntry {
                addr,
                tried: false,
                last_success: 0,
                attempts: 0,
                last_seen: now,
                services,
                source,
                group,
            },
        );
        true
    }

    /// Promote an address to the *tried* table after a successful connect.
    ///
    /// Only the addresses we successfully *dialed* (outbound) should be
    /// passed here — an inbound peer's socket address is its ephemeral
    /// source port, which is not re-dialable and would only pollute the
    /// table. The total cap is enforced even on this path: a brand-new
    /// address is not inserted once the table is full, so inbound churn (or
    /// any future caller) cannot grow the table without bound. An address
    /// already present is always refreshed/promoted.
    pub fn mark_good(&mut self, addr: SocketAddr, now: u64) {
        if !self.entries.contains_key(&addr) && self.entries.len() >= MAX_ENTRIES {
            return;
        }
        let group = self.group_of(&addr);
        let entry = self.entries.entry(addr).or_insert_with(|| AddrEntry {
            addr,
            tried: false,
            last_success: 0,
            attempts: 0,
            last_seen: now,
            services: DEFAULT_SERVICES,
            source: addr.ip(),
            group,
        });
        entry.tried = true;
        entry.last_success = now;
        entry.last_seen = now;
        entry.attempts = 0;
    }

    /// Record a failed connection attempt.
    pub fn mark_attempt(&mut self, addr: SocketAddr) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.attempts = e.attempts.saturating_add(1);
        }
    }

    /// Pick an address to dial, biased ~50/50 between tried and new.
    pub fn select(&self) -> Option<SocketAddr> {
        let (tried, new): (Vec<&AddrEntry>, Vec<&AddrEntry>) =
            self.entries.values().partition(|e| e.tried);
        let prefer_tried = !tried.is_empty() && (new.is_empty() || rand::random::<bool>());
        let pool = if prefer_tried { &tried } else { &new };
        if pool.is_empty() {
            return None;
        }
        let idx = (rand::random::<u64>() as usize) % pool.len();
        Some(pool[idx].addr)
    }

    /// Return up to `n` distinct addresses for seeding the dial pool at
    /// startup (tried first, then new).
    pub fn select_n(&self, n: usize) -> Vec<SocketAddr> {
        let mut tried: Vec<&AddrEntry> = self.entries.values().filter(|e| e.tried).collect();
        let mut new: Vec<&AddrEntry> = self.entries.values().filter(|e| !e.tried).collect();
        // Most-recently-successful tried first; most-recently-seen new.
        tried.sort_by(|a, b| b.last_success.cmp(&a.last_success));
        new.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        tried
            .into_iter()
            .chain(new)
            .take(n)
            .map(|e| e.addr)
            .collect()
    }

    /// Every entry, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &AddrEntry> {
        self.entries.values()
    }

    /// Core's `addpeeraddress`: add `addr` to the new table and, when
    /// `tried`, promote it to the tried table. The error strings are Core's.
    ///
    /// Adding an address that is already present fails with
    /// `failed-adding-to-new` whichever table was asked for, because Core's
    /// `Add` refuses a duplicate before `Good` is ever reached. The caps
    /// that bound gossip bound this path too.
    pub fn add_manual(&mut self, addr: SocketAddr, tried: bool, now: u64) -> Result<(), &'static str> {
        if !self.add_from(addr, now, DEFAULT_SERVICES, addr.ip()) {
            return Err("failed-adding-to-new");
        }
        if tried {
            self.mark_good(addr, now);
        }
        Ok(())
    }

    /// New/tried counts per network, keyed by Core's network name (`ipv4`,
    /// `ipv6`). Networks with no entries are absent.
    pub fn counts_by_network(&self) -> std::collections::BTreeMap<&'static str, TableCounts> {
        let mut out: std::collections::BTreeMap<&'static str, TableCounts> = Default::default();
        for e in self.entries.values() {
            let c = out.entry(network_name(e.addr.ip())).or_default();
            if e.tried {
                c.tried += 1;
            } else {
                c.new += 1;
            }
        }
        out
    }

    fn slot_hash(&self, parts: &[&[u8]]) -> u64 {
        let mut data = Vec::new();
        for p in parts {
            data.extend_from_slice(p);
        }
        bitcoin::hashes::siphash24::Hash::hash_to_u64_with_keys(self.slot_key.0, self.slot_key.1, &data)
    }

    /// The slot Core's formulas give `e` (`AddrInfo::GetTriedBucket`,
    /// `GetNewBucket` and `GetBucketPosition` in `src/addrman.cpp`), with
    /// SipHash under this process's key in place of Core's `HashWriter`.
    fn derived_slot(&self, e: &AddrEntry) -> AddrSlot {
        let key = addr_key(&e.addr);
        let group = &e.group;
        let bucket = if e.tried {
            let h1 = self.slot_hash(&[&key]) % TRIED_BUCKETS_PER_GROUP;
            self.slot_hash(&[group, &h1.to_le_bytes()]) % TRIED_BUCKET_COUNT
        } else {
            let src_group = (self.group_fn)(e.source);
            let h1 = self.slot_hash(&[group, &src_group]) % NEW_BUCKETS_PER_SOURCE_GROUP;
            self.slot_hash(&[&src_group, &h1.to_le_bytes()]) % NEW_BUCKET_COUNT
        };
        let tag: &[u8] = if e.tried { b"K" } else { b"N" };
        let position = self.slot_hash(&[tag, &bucket.to_le_bytes(), &key]) % BUCKET_SIZE;
        AddrSlot { tried: e.tried, bucket, position }
    }

    /// Every entry with a derived `bucket/position` slot, unique within its
    /// table. See the module docs: the slots are computed, not stored.
    ///
    /// Core never has two entries in one slot (a collision evicts or is
    /// refused), and `getrawaddrman` keys its JSON objects by slot, so a
    /// collision here must not be reported twice under one key. Entries are
    /// placed in address order and a taken slot moves on to the next free
    /// one, which keeps the result deterministic for a given key.
    pub fn positions(&self) -> Vec<(AddrSlot, &AddrEntry)> {
        let mut entries: Vec<&AddrEntry> = self.entries.values().collect();
        entries.sort_by_key(|e| e.addr);
        let mut taken: std::collections::HashSet<(bool, u64)> = Default::default();
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let mut slot = self.derived_slot(e);
            let buckets = if e.tried { TRIED_BUCKET_COUNT } else { NEW_BUCKET_COUNT };
            let capacity = buckets * BUCKET_SIZE;
            let mut index = slot.bucket * BUCKET_SIZE + slot.position;
            // MAX_ENTRIES is well below either table's capacity, so a free
            // slot always exists.
            while !taken.insert((e.tried, index)) {
                index = (index + 1) % capacity;
            }
            slot.bucket = index / BUCKET_SIZE;
            slot.position = index % BUCKET_SIZE;
            out.push((slot, e));
        }
        out
    }

    // ---- persistence (peers.dat) ----------------------------------------

    /// Load addresses from `path` (no-op if the file is absent). The file
    /// is untrusted: a bad header is an error, but the record count is
    /// capped and malformed records stop the read without failing.
    pub fn load(&mut self, path: &Path) -> Result<(), String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let mut cur = io::Cursor::new(&bytes);
        let mut magic = [0u8; 4];
        if cur.read_exact(&mut magic).is_err() || &magic != b"SADR" {
            return Err(format!("{}: bad peers.dat magic", path.display()));
        }
        let version = read_u32(&mut cur).map_err(|_| "peers.dat: truncated header")?;
        if version != 1 && version != FORMAT_VERSION {
            return Err(format!("peers.dat: unsupported version {version}"));
        }
        let count = read_u32(&mut cur).unwrap_or(0).min(MAX_ENTRIES as u32);
        for _ in 0..count {
            match read_entry(&mut cur, version) {
                Some(mut e) => {
                    // Recompute the cached group under the active group_fn
                    // (the on-disk format does not store it, since `-asmap`
                    // can change the grouping between runs).
                    e.group = self.group_of(&e.addr);
                    self.entries.insert(e.addr, e);
                }
                None => break, // truncated/garbage tail — keep what we have
            }
        }
        Ok(())
    }

    /// Atomically write the address book to `path` (temp file + fsync +
    /// rename), mirroring the mempool.dat durability path.
    pub fn dump(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("dat.tmp");
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"SADR");
        buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in self.entries.values() {
            write_entry(&mut buf, e);
        }
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
            f.write_all(&buf)
                .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("renaming {} -> {}: {e}", tmp.display(), path.display()))?;
        Ok(())
    }
}

fn read_u32(cur: &mut io::Cursor<&Vec<u8>>) -> io::Result<u32> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(cur: &mut io::Cursor<&Vec<u8>>) -> io::Result<u64> {
    let mut b = [0u8; 8];
    cur.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_ip(cur: &mut io::Cursor<&Vec<u8>>) -> Option<IpAddr> {
    let mut tag = [0u8; 1];
    cur.read_exact(&mut tag).ok()?;
    match tag[0] {
        0 => {
            let mut o = [0u8; 4];
            cur.read_exact(&mut o).ok()?;
            Some(IpAddr::from(o))
        }
        1 => {
            let mut o = [0u8; 16];
            cur.read_exact(&mut o).ok()?;
            Some(IpAddr::from(o))
        }
        _ => None,
    }
}

fn write_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            buf.push(0);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(1);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

fn read_entry(cur: &mut io::Cursor<&Vec<u8>>, version: u32) -> Option<AddrEntry> {
    let ip = read_ip(cur)?;
    let port = {
        let mut b = [0u8; 2];
        cur.read_exact(&mut b).ok()?;
        u16::from_le_bytes(b)
    };
    let mut tried = [0u8; 1];
    cur.read_exact(&mut tried).ok()?;
    let last_success = read_u64(cur).ok()?;
    let attempts = read_u32(cur).ok()?;
    let last_seen = read_u64(cur).ok()?;
    let addr = SocketAddr::new(ip, port);
    // Version 1 carried neither field: load Core's defaults (the entry is
    // its own source, with NODE_NETWORK | NODE_WITNESS).
    let (services, source) = if version >= 2 {
        (read_u64(cur).ok()?, read_ip(cur)?)
    } else {
        (DEFAULT_SERVICES, ip)
    };
    Some(AddrEntry {
        addr,
        tried: tried[0] != 0,
        last_success,
        attempts,
        last_seen,
        services,
        source,
        // Filled in by `load` under the active group_fn; the group is not
        // part of the on-disk format.
        group: Vec::new(),
    })
}

fn write_entry(buf: &mut Vec<u8>, e: &AddrEntry) {
    write_ip(buf, e.addr.ip());
    buf.extend_from_slice(&e.addr.port().to_le_bytes());
    buf.push(if e.tried { 1 } else { 0 });
    buf.extend_from_slice(&e.last_success.to_le_bytes());
    buf.extend_from_slice(&e.attempts.to_le_bytes());
    buf.extend_from_slice(&e.last_seen.to_le_bytes());
    buf.extend_from_slice(&e.services.to_le_bytes());
    write_ip(buf, e.source);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn add_dedups_and_marks_good_promotes() {
        let mut a = AddrMan::new();
        assert!(a.add(sa("1.2.3.4:8333"), 100));
        assert!(!a.add(sa("1.2.3.4:8333"), 200)); // dup refresh
        assert_eq!(a.len(), 1);
        a.mark_good(sa("1.2.3.4:8333"), 300);
        let e = &a.entries[&sa("1.2.3.4:8333")];
        assert!(e.tried && e.last_success == 300 && e.attempts == 0);
    }

    #[test]
    fn per_group_cap_enforced() {
        let mut a = AddrMan::new();
        // All in 10.0.x.x → same /16 group.
        for i in 0..(MAX_NEW_PER_GROUP + 10) {
            a.add(sa(&format!("10.0.{}.{}:8333", i / 256, i % 256)), 1);
        }
        assert_eq!(a.len(), MAX_NEW_PER_GROUP);
        // A different group is still accepted.
        assert!(a.add(sa("11.0.0.1:8333"), 1));
    }

    #[test]
    fn select_prefers_available_pool() {
        let mut a = AddrMan::new();
        assert_eq!(a.select(), None);
        a.add(sa("1.2.3.4:8333"), 1);
        assert_eq!(a.select(), Some(sa("1.2.3.4:8333")));
        a.mark_good(sa("5.6.7.8:8333"), 2);
        // With both pools non-empty, select returns one of them.
        for _ in 0..20 {
            let s = a.select().unwrap();
            assert!(s == sa("1.2.3.4:8333") || s == sa("5.6.7.8:8333"));
        }
    }

    #[test]
    fn peers_dat_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");
        let mut a = AddrMan::new();
        a.add(sa("1.2.3.4:8333"), 111);
        a.add(sa("[2001:db8::1]:8333"), 222);
        a.mark_good(sa("1.2.3.4:8333"), 333);
        a.dump(&path).unwrap();

        let mut b = AddrMan::new();
        b.load(&path).unwrap();
        assert_eq!(b.len(), 2);
        assert!(b.entries[&sa("1.2.3.4:8333")].tried);
        assert_eq!(b.entries[&sa("1.2.3.4:8333")].last_success, 333);
        assert!(!b.entries[&sa("[2001:db8::1]:8333")].tried);
    }

    #[test]
    fn load_missing_is_ok_and_bad_magic_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = AddrMan::new();
        assert!(a.load(&dir.path().join("absent.dat")).is_ok());
        let bad = dir.path().join("bad.dat");
        std::fs::write(&bad, b"XXXXnonsense").unwrap();
        assert!(a.load(&bad).is_err());
    }

    #[test]
    fn mark_good_does_not_insert_past_the_total_cap() {
        // mark_good must honor MAX_ENTRIES for brand-new addresses, so a
        // flood of (e.g. inbound) successful handshakes can't grow the
        // table without bound. An already-present address is still promoted.
        let mut a = AddrMan::new();
        // Fill the table to the cap with tried entries from distinct groups
        // (so the per-group new cap doesn't interfere).
        for i in 0..MAX_ENTRIES {
            let octet_b = (i / 256) as u8;
            let octet_c = (i % 256) as u8;
            a.mark_good(sa(&format!("10.{octet_b}.{octet_c}.1:8333")), 1);
        }
        assert_eq!(a.len(), MAX_ENTRIES);
        // A brand-new address at capacity is rejected (not inserted).
        a.mark_good(sa("203.0.113.7:8333"), 2);
        assert_eq!(a.len(), MAX_ENTRIES);
        assert!(!a.entries.contains_key(&sa("203.0.113.7:8333")));
        // But an address already present is still refreshed/promoted.
        a.mark_good(sa("10.0.0.1:8333"), 99);
        assert_eq!(a.entries[&sa("10.0.0.1:8333")].last_success, 99);
    }

    #[test]
    fn add_caches_the_group_key() {
        // The per-group cap reads a cached group rather than re-running
        // group_fn per entry; confirm the cache is populated with the
        // active grouping (default: v4 /16, v6 /32).
        let mut a = AddrMan::new();
        a.add(sa("203.0.113.9:8333"), 1);
        assert_eq!(a.entries[&sa("203.0.113.9:8333")].group, vec![203, 0]);
        a.add(sa("[2001:db8::1]:8333"), 1);
        assert_eq!(
            a.entries[&sa("[2001:db8::1]:8333")].group,
            vec![0x20, 0x01, 0x0d, 0xb8]
        );
        // The cached group is what the per-group cap counts against.
        assert_eq!(a.new_count_in_group(&[203, 0]), 1);
    }

    #[test]
    fn load_recomputes_group_key() {
        // peers.dat does not store the group; it must be recomputed on load
        // (the grouping can change between runs, e.g. when -asmap is added).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");
        let mut a = AddrMan::new();
        a.add(sa("1.2.3.4:8333"), 1);
        a.dump(&path).unwrap();

        let mut b = AddrMan::new();
        b.load(&path).unwrap();
        assert_eq!(b.entries[&sa("1.2.3.4:8333")].group, vec![1, 2]);
    }

    #[test]
    fn services_and_source_survive_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");
        let mut a = AddrMan::new();
        let source: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(a.add_from(sa("1.2.3.4:8333"), 5, 1 | 8 | 1024, source));
        a.add_from(sa("[2001:db8::5]:18444"), 6, 1, "2001:db8::9".parse().unwrap());
        a.dump(&path).unwrap();

        let mut b = AddrMan::new();
        b.load(&path).unwrap();
        let e = &b.entries[&sa("1.2.3.4:8333")];
        assert_eq!(e.services, 1 | 8 | 1024);
        assert_eq!(e.source, source);
        let e6 = &b.entries[&sa("[2001:db8::5]:18444")];
        assert_eq!(e6.services, 1);
        assert_eq!(e6.source, "2001:db8::9".parse::<IpAddr>().unwrap());
    }

    /// A `peers.dat` written by the version 1 writer (no services, no
    /// source): the bytes below are exactly what that writer produced for
    /// one tried IPv4 entry and one new IPv6 entry. It must still load, with
    /// Core's defaults for the two missing fields.
    #[test]
    fn a_version_1_peers_dat_still_loads() {
        let mut v1: Vec<u8> = Vec::new();
        v1.extend_from_slice(b"SADR");
        v1.extend_from_slice(&1u32.to_le_bytes()); // version 1
        v1.extend_from_slice(&2u32.to_le_bytes()); // count
        // 1.2.3.4:8333, tried, last_success 333, attempts 0, last_seen 333
        v1.push(0);
        v1.extend_from_slice(&[1, 2, 3, 4]);
        v1.extend_from_slice(&8333u16.to_le_bytes());
        v1.push(1);
        v1.extend_from_slice(&333u64.to_le_bytes());
        v1.extend_from_slice(&0u32.to_le_bytes());
        v1.extend_from_slice(&333u64.to_le_bytes());
        // [2001:db8::1]:8333, new, never connected, 2 attempts, last_seen 222
        v1.push(1);
        v1.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v1.extend_from_slice(&8333u16.to_le_bytes());
        v1.push(0);
        v1.extend_from_slice(&0u64.to_le_bytes());
        v1.extend_from_slice(&2u32.to_le_bytes());
        v1.extend_from_slice(&222u64.to_le_bytes());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");
        std::fs::write(&path, &v1).unwrap();
        let mut a = AddrMan::new();
        a.load(&path).unwrap();
        assert_eq!(a.len(), 2);
        let e = &a.entries[&sa("1.2.3.4:8333")];
        assert!(e.tried);
        assert_eq!((e.last_success, e.last_seen), (333, 333));
        assert_eq!(e.services, DEFAULT_SERVICES);
        assert_eq!(e.source, "1.2.3.4".parse::<IpAddr>().unwrap());
        let e6 = &a.entries[&sa("[2001:db8::1]:8333")];
        assert!(!e6.tried);
        assert_eq!((e6.attempts, e6.last_seen), (2, 222));
        assert_eq!(e6.services, DEFAULT_SERVICES);

        // Re-dumped, it is a version 2 file that keeps what it had.
        a.dump(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[4..8], &FORMAT_VERSION.to_le_bytes());
        let mut b = AddrMan::new();
        b.load(&path).unwrap();
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn an_unknown_peers_dat_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.dat");
        let mut bytes = b"SADR".to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(AddrMan::new().load(&path).is_err());
    }

    /// Warnet's address-manager check reads `getrawaddrman` and wants more
    /// than one distinct bucket in a table. Fifty addresses over three /16s
    /// must spread across buckets in both tables, the way Core's do.
    #[test]
    fn derived_slots_spread_across_buckets() {
        let mut a = AddrMan::new();
        for i in 0..50u8 {
            let net = [10u8, 172, 192][(i % 3) as usize];
            let src: IpAddr = format!("{}.{}.0.1", 100 + (i % 7), i).parse().unwrap();
            a.add_from(sa(&format!("{net}.{}.{}.1:8333", i % 3, i)), 1, DEFAULT_SERVICES, src);
        }
        // Promote a third of them (all inside the three /16s).
        let tried: Vec<SocketAddr> = a.iter().map(|e| e.addr).step_by(3).collect();
        for addr in &tried {
            a.mark_good(*addr, 2);
        }
        let slots = a.positions();
        assert_eq!(slots.len(), 50);
        for table in [false, true] {
            let buckets: std::collections::HashSet<u64> = slots
                .iter()
                .filter(|(s, _)| s.tried == table)
                .map(|(s, _)| s.bucket)
                .collect();
            assert!(buckets.len() > 1, "tried={table}: one bucket for every entry");
        }
        // Slots are unique per table and inside Core's geometry.
        let mut seen = std::collections::HashSet::new();
        for (s, _) in &slots {
            assert!(seen.insert((s.tried, s.bucket, s.position)), "duplicate slot {s:?}");
            assert!(s.position < BUCKET_SIZE);
            assert!(s.bucket < if s.tried { TRIED_BUCKET_COUNT } else { NEW_BUCKET_COUNT });
        }
    }

    /// Warnet's tanks all sit in one /16. Core spreads one group's tried
    /// entries across up to eight buckets (`TRIED_BUCKETS_PER_GROUP`); a
    /// derivation that hashed the group alone would put them all in one.
    #[test]
    fn one_group_still_spans_several_tried_buckets() {
        let mut a = AddrMan::new();
        for i in 0..32u8 {
            a.mark_good(sa(&format!("10.244.{i}.5:18444")), 1);
        }
        let buckets: std::collections::HashSet<u64> =
            a.positions().iter().map(|(s, _)| s.bucket).collect();
        assert!(buckets.len() > 1, "{buckets:?}");
        assert!(buckets.len() <= TRIED_BUCKETS_PER_GROUP as usize, "{buckets:?}");
    }

    /// One /16's tried entries share at most eight buckets of 64 slots,
    /// so 300 of them must collide; each still gets its own slot, or
    /// `getrawaddrman` would report two entries under one key and drop one.
    #[test]
    fn colliding_slots_are_moved_not_shared() {
        let mut a = AddrMan::new();
        for i in 0..300u16 {
            a.mark_good(sa(&format!("10.244.{}.{}:18444", i / 256, i % 256)), 1);
        }
        let slots = a.positions();
        let unique: std::collections::HashSet<(u64, u64)> =
            slots.iter().map(|(s, _)| (s.bucket, s.position)).collect();
        assert_eq!(unique.len(), 300);
    }

    #[test]
    fn derived_slots_are_stable_within_a_process() {
        let mut a = AddrMan::new();
        for i in 0..20u8 {
            a.add(sa(&format!("{}.1.1.1:8333", 20 + i)), 1);
        }
        let first: Vec<(AddrSlot, SocketAddr)> =
            a.positions().into_iter().map(|(s, e)| (s, e.addr)).collect();
        let again: Vec<(AddrSlot, SocketAddr)> =
            a.positions().into_iter().map(|(s, e)| (s, e.addr)).collect();
        assert_eq!(first, again);
    }

    #[test]
    fn add_manual_reports_core_errors() {
        let mut a = AddrMan::new();
        assert_eq!(a.add_manual(sa("1.0.0.0:8333"), false, 1), Ok(()));
        // Already present: fails at the new table whichever table was asked.
        assert_eq!(a.add_manual(sa("1.0.0.0:8333"), false, 1), Err("failed-adding-to-new"));
        assert_eq!(a.add_manual(sa("1.0.0.0:8333"), true, 1), Err("failed-adding-to-new"));
        assert!(!a.entries[&sa("1.0.0.0:8333")].tried);
        assert_eq!(a.add_manual(sa("1.2.3.4:8333"), true, 1), Ok(()));
        let e = &a.entries[&sa("1.2.3.4:8333")];
        assert!(e.tried);
        assert_eq!(e.source, e.addr.ip());
        assert_eq!(e.services, DEFAULT_SERVICES);
        let counts = a.counts_by_network();
        assert_eq!(counts["ipv4"], TableCounts { new: 1, tried: 1 });
        assert!(!counts.contains_key("ipv6"));
    }

    #[test]
    fn network_names_follow_core() {
        assert_eq!(network_name("1.2.3.4".parse().unwrap()), "ipv4");
        assert_eq!(network_name("::ffff:1.2.3.4".parse().unwrap()), "ipv4");
        assert_eq!(network_name("2001:db8::1".parse().unwrap()), "ipv6");
        assert_eq!(addr_string("::ffff:1.2.3.4".parse().unwrap()), "1.2.3.4");
        assert_eq!(addr_string("2001:db8::1".parse().unwrap()), "2001:db8::1");
    }
}
