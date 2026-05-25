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
//! untrusted on load (capped, malformed records skipped).

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

pub struct AddrMan {
    entries: HashMap<SocketAddr, AddrEntry>,
    /// Pluggable network-group function (replaced by `-asmap`).
    group_fn: fn(IpAddr) -> Vec<u8>,
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
            group_fn: default_group,
        }
    }

    /// Install a custom network-group function (e.g. ASN-based via
    /// `-asmap`). Must be called before addresses are added for bucketing
    /// to use it consistently.
    pub fn set_group_fn(&mut self, f: fn(IpAddr) -> Vec<u8>) {
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
    /// per-group caps. Returns true if a new entry was inserted.
    pub fn add(&mut self, addr: SocketAddr, now: u64) -> bool {
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
        if version != 1 {
            return Err(format!("peers.dat: unsupported version {version}"));
        }
        let count = read_u32(&mut cur).unwrap_or(0).min(MAX_ENTRIES as u32);
        for _ in 0..count {
            match read_entry(&mut cur) {
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
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
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

fn read_entry(cur: &mut io::Cursor<&Vec<u8>>) -> Option<AddrEntry> {
    let mut tag = [0u8; 1];
    cur.read_exact(&mut tag).ok()?;
    let ip: IpAddr = match tag[0] {
        0 => {
            let mut o = [0u8; 4];
            cur.read_exact(&mut o).ok()?;
            IpAddr::from(o)
        }
        1 => {
            let mut o = [0u8; 16];
            cur.read_exact(&mut o).ok()?;
            IpAddr::from(o)
        }
        _ => return None,
    };
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
    Some(AddrEntry {
        addr,
        tried: tried[0] != 0,
        last_success,
        attempts,
        last_seen,
        // Filled in by `load` under the active group_fn; the group is not
        // part of the on-disk format.
        group: Vec::new(),
    })
}

fn write_entry(buf: &mut Vec<u8>, e: &AddrEntry) {
    match e.addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(0);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(1);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&e.addr.port().to_le_bytes());
    buf.push(if e.tried { 1 } else { 0 });
    buf.extend_from_slice(&e.last_success.to_le_bytes());
    buf.extend_from_slice(&e.attempts.to_le_bytes());
    buf.extend_from_slice(&e.last_seen.to_le_bytes());
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
}
