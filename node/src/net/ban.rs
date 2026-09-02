//! Subnet-level ban list with wall-clock times and JSON persistence.
//!
//! Bitcoin Core bans at the subnet level, stores ban entries as wall-clock
//! Unix timestamps (so they survive restarts and respond to `setmocktime`),
//! and persists the list to `banlist.json` in the chain data directory.
//!
//! The key type is a normalised address string — a CIDR subnet like
//! `"127.0.0.0/24"`, a bare IP normalised to `/32` or `/128`, or a `.onion`
//! hostname. SocketAddr ports are irrelevant: a ban on `127.0.0.1` bans
//! every port on that IP.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// A single ban entry, mirroring Core's `banlist.json` wire format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanEntry {
    /// Normalised subnet string, e.g. `"127.0.0.0/24"`, `"<onion>"`.
    pub address: String,
    /// Unix seconds when the ban was created.
    pub ban_created: u64,
    /// Unix seconds when the ban expires.
    pub banned_until: u64,
}

impl BanEntry {
    /// Original ban duration in seconds.
    pub fn ban_duration(&self) -> u64 {
        self.banned_until.saturating_sub(self.ban_created)
    }

    /// Seconds remaining until expiry, relative to `now` (Unix seconds).
    pub fn time_remaining(&self, now: u64) -> u64 {
        self.banned_until.saturating_sub(now)
    }

    /// Whether this ban has expired as of `now` (Unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.banned_until
    }
}

/// The parsed form of a `setban` subnet argument.
#[derive(Clone, Debug)]
pub enum BanTarget {
    /// An IPv4 or IPv6 subnet.
    Net(IpNet),
    /// A `.onion` hostname (verbatim, no CIDR).
    Onion(String),
}

impl BanTarget {
    /// The normalised string that becomes the map key and the `address`
    /// field in `banlist.json`.
    pub fn normalised(&self) -> String {
        match self {
            Self::Net(net) => net.trunc().to_string(),
            Self::Onion(s) => s.clone(),
        }
    }

    /// Whether `addr` falls within this ban target.
    pub fn contains_addr(&self, addr: &IpAddr) -> bool {
        match self {
            Self::Net(net) => net.contains(addr),
            Self::Onion(_) => false,
        }
    }
}

/// Parse a `setban` subnet argument into a `BanTarget`.
///
/// Accepts:
/// - Bare IPv4 (`"127.0.0.1"`) → `/32`
/// - Bare IPv6 (`"::1"`) → `/128`
/// - CIDR notation (`"127.0.0.0/24"`, `"2001:db8::/19"`)
/// - `.onion` hostnames (verbatim)
///
/// Returns `Err` with a human message on failure.
pub fn parse_ban_target(s: &str) -> Result<BanTarget, String> {
    // .onion addresses
    if s.ends_with(".onion") {
        return Ok(BanTarget::Onion(s.to_string()));
    }

    // Try CIDR first
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(BanTarget::Net(net));
    }

    // Try bare IP
    if let Ok(ip) = s.parse::<IpAddr>() {
        let net = IpNet::from(ip);
        return Ok(BanTarget::Net(net));
    }

    Err(format!("Error: Invalid IP/Subnet"))
}

/// The ban list: a map from normalised address string to ban entry.
///
/// `BTreeMap` gives sorted iteration, which Core's `listbanned` relies on
/// (the test asserts a specific order after restart).
#[derive(Clone, Debug, Default)]
pub struct BanList {
    entries: BTreeMap<String, BanEntry>,
    /// Path to `banlist.json`, set once at load time.
    persist_path: Option<PathBuf>,
}

impl BanList {
    /// Create an empty ban list that will persist to `path`.
    pub fn new(persist_path: PathBuf) -> Self {
        Self {
            entries: BTreeMap::new(),
            persist_path: Some(persist_path),
        }
    }

    /// Load from `banlist.json` at `path`. If the file does not exist,
    /// creates an empty list and returns `true` (caller should log
    /// "Recreating the banlist database"). If the file exists but is
    /// malformed, returns an error.
    pub fn load(path: &Path) -> Result<(Self, bool), String> {
        let mut list = Self {
            entries: BTreeMap::new(),
            persist_path: Some(path.to_path_buf()),
        };

        if !path.exists() {
            // Write an empty file so the test can find it.
            list.dump().map_err(|e| format!("failed to write banlist: {e}"))?;
            return Ok((list, true));
        }

        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let entries: Vec<BanEntry> = serde_json::from_str(&data)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

        for entry in entries {
            list.entries.insert(entry.address.clone(), entry);
        }

        Ok((list, false))
    }

    /// Write the current ban list to `banlist.json`.
    pub fn dump(&self) -> Result<(), std::io::Error> {
        let Some(path) = &self.persist_path else {
            return Ok(());
        };
        let entries: Vec<&BanEntry> = self.entries.values().collect();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Insert a ban entry. Returns `Err` if the address is already banned
    /// (either exactly, or the IP falls within an existing subnet).
    pub fn add(
        &mut self,
        target: &BanTarget,
        ban_created: u64,
        banned_until: u64,
    ) -> Result<(), String> {
        let key = target.normalised();

        // Check if already banned: exact match, or (for Net targets) IP is
        // contained in an existing banned subnet.
        if self.entries.contains_key(&key) {
            return Err("IP/Subnet already banned".to_string());
        }

        // For single-host bans (/32 or /128): check if the IP falls
        // within an existing banned subnet. Core only does this
        // containment check for single hosts, not for subnet-to-subnet
        // overlap, so banning both 127.0.0.0/32 and 127.0.0.0/24 is
        // allowed.
        if let BanTarget::Net(net) = target {
            if net.prefix_len() == net.max_prefix_len() {
                let addr = net.addr();
                for existing in self.entries.values() {
                    if let Ok(existing_net) = existing.address.parse::<IpNet>() {
                        if existing_net.contains(&addr) {
                            return Err("IP/Subnet already banned".to_string());
                        }
                    }
                }
            }
        }

        self.entries.insert(
            key.clone(),
            BanEntry {
                address: key,
                ban_created,
                banned_until,
            },
        );

        self.dump().map_err(|e| format!("failed to persist ban: {e}"))?;
        Ok(())
    }

    /// Remove a ban entry by exact key match. Returns `Err` if no such
    /// entry exists.
    pub fn remove(&mut self, target: &BanTarget) -> Result<(), String> {
        let key = target.normalised();
        if self.entries.remove(&key).is_none() {
            return Err("Error: Unban failed. Requested address/subnet was not previously manually banned.".to_string());
        }
        let _ = self.dump();
        Ok(())
    }

    /// Clear all bans.
    pub fn clear(&mut self) {
        self.entries.clear();
        let _ = self.dump();
    }

    /// Remove expired entries, using `now` as the current time (Unix secs).
    pub fn prune_expired(&mut self, now: u64) {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired(now));
        if self.entries.len() != before {
            let _ = self.dump();
        }
    }

    /// All non-expired entries, sorted by key.
    pub fn list(&self, now: u64) -> Vec<&BanEntry> {
        self.entries
            .values()
            .filter(|e| !e.is_expired(now))
            .collect()
    }

    /// Whether `addr` is currently banned (falls within any non-expired
    /// subnet), given `now` in Unix seconds.
    pub fn is_banned(&self, addr: &IpAddr, now: u64) -> bool {
        for entry in self.entries.values() {
            if entry.is_expired(now) {
                continue;
            }
            // .onion entries only match by exact key, never by IP.
            if entry.address.ends_with(".onion") {
                continue;
            }
            if let Ok(net) = entry.address.parse::<IpNet>() {
                if net.contains(addr) {
                    return true;
                }
            }
        }
        false
    }

    /// Whether the given .onion hostname is currently banned.
    pub fn is_onion_banned(&self, host: &str, now: u64) -> bool {
        self.entries
            .get(host)
            .map(|e| !e.is_expired(now))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_ipv4() {
        let target = parse_ban_target("127.0.0.1").unwrap();
        assert_eq!(target.normalised(), "127.0.0.1/32");
    }

    #[test]
    fn parse_cidr_v4() {
        let target = parse_ban_target("127.0.0.0/24").unwrap();
        assert_eq!(target.normalised(), "127.0.0.0/24");
    }

    #[test]
    fn parse_onion() {
        let target = parse_ban_target(
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
        )
        .unwrap();
        assert!(matches!(target, BanTarget::Onion(_)));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let target =
            parse_ban_target("2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/19").unwrap();
        assert!(target.normalised().contains("/19"));
    }

    #[test]
    fn parse_invalid_cidr() {
        assert!(parse_ban_target("127.0.0.1/42").is_err());
    }

    #[test]
    fn subnet_contains_ip() {
        let target = parse_ban_target("127.0.0.0/24").unwrap();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(target.contains_addr(&ip));
    }

    #[test]
    fn already_banned_within_subnet() {
        let mut list = BanList::default();
        let subnet = parse_ban_target("127.0.0.0/24").unwrap();
        list.add(&subnet, 1000, 2000).unwrap();

        // Banning a specific IP within the subnet should fail.
        let ip = parse_ban_target("127.0.0.1").unwrap();
        assert!(list.add(&ip, 1000, 2000).is_err());
    }

    #[test]
    fn is_banned_by_subnet() {
        let mut list = BanList::default();
        let subnet = parse_ban_target("127.0.0.0/24").unwrap();
        list.add(&subnet, 1000, 2000).unwrap();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(list.is_banned(&ip, 1500));
        assert!(!list.is_banned(&ip, 2500));
    }
}
