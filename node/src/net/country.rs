//! Per-country node totals from an operator-supplied country file
//! (`-countryfile`), in the MaxMind DB (`.mmdb`) format: DB-IP's "IP to
//! Country Lite" or MaxMind's GeoLite2 Country. Both carry the
//! GeoLite2-Country schema.
//!
//! The file is read once, at startup, into memory. A lookup reads one field
//! of the record, `country.iso_code`, and nothing else: a city file works,
//! and its city, subdivision and coordinates are never read.
//!
//! What comes out is totals only ([`totals`]): a count per country over a
//! set of nodes, every country with fewer than the minimum folded into
//! [`OTHER`]. No per-node record ever carries a country: next to the AS,
//! the user agent and the services it could single out a node in a small
//! country.
//!
//! The keys of a total:
//!
//! - a country's ISO 3166-1 alpha-2 code, two uppercase letters (`DE`);
//! - [`UNKNOWN`]: an IPv4 or IPv6 node the file has no country for;
//! - [`OTHER`]: every country with fewer nodes than the minimum;
//! - a network's name for a node not on IPv4 or IPv6 (`onion`): its address
//!   says nothing about where it is, so it is given no country.
//!
//! `unknown` and the network keys are never folded: they name no country.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::net::crawl::network_of;
use crate::net::crawlbook::Network;
use crate::net::peer::PeerAddr;

/// The key of an IP node the file gives no country.
pub const UNKNOWN: &str = "unknown";

/// The key every country with fewer nodes than the minimum is folded into.
pub const OTHER: &str = "other";

/// The country file, read into memory.
pub struct CountryMap {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl std::fmt::Debug for CountryMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountryMap")
            .field("database_type", &self.database_type())
            .finish()
    }
}

impl CountryMap {
    /// Read the file at `path`: an error when it does not read or is not a
    /// MaxMind DB file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("reading the country file {}: {e}", path.display()))?;
        Self::from_bytes(bytes).map_err(|e| format!("the country file {}: {e}", path.display()))
    }

    /// A map from a MaxMind DB file's bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|e| format!("not a MaxMind DB (.mmdb) file: {e}"))?;
        Ok(CountryMap { reader })
    }

    /// The file's `database_type`, as its metadata states it.
    pub fn database_type(&self) -> &str {
        &self.reader.metadata().database_type
    }

    /// When the file was built, Unix seconds, as its metadata states it.
    pub fn build_epoch(&self) -> u64 {
        self.reader.metadata().build_epoch
    }

    /// The country of `ip`: its ISO code in uppercase, or `None` when the
    /// file has no record for it, the record has no `country.iso_code`, or
    /// the code is not two letters. An IPv4-mapped IPv6 address is looked
    /// up as the IPv4 address it carries.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip.to_canonical()).ok()?;
        let code: String = result
            .decode_path(&[
                maxminddb::PathElement::Key("country"),
                maxminddb::PathElement::Key("iso_code"),
            ])
            .ok()
            .flatten()?;
        (code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()))
            .then(|| code.to_ascii_uppercase())
    }

    /// The key `peer` is counted under, before folding: its country,
    /// [`UNKNOWN`], or its network's name when it is not on IPv4 or IPv6.
    pub fn key_of(&self, peer: &PeerAddr) -> String {
        match peer {
            PeerAddr::Socket(sa) => self.lookup(sa.ip()).unwrap_or_else(|| UNKNOWN.to_string()),
            PeerAddr::Onion { .. } => network_of(peer).name().to_string(),
        }
    }
}

/// Whether `key` names a country, and so may be folded.
fn is_country(key: &str) -> bool {
    key != UNKNOWN && key != OTHER && !Network::ALL.iter().any(|n| n.name() == key)
}

/// The totals of `nodes` under `map`: a count per key, every country with
/// fewer than `min_k` nodes added to [`OTHER`]. [`UNKNOWN`], [`OTHER`] and
/// the key of each network that can carry no country (`onion`) are always
/// present, zero or not; a country only when it has `min_k` nodes or more.
pub fn totals<'a>(
    nodes: impl IntoIterator<Item = &'a PeerAddr>,
    map: &CountryMap,
    min_k: u32,
) -> BTreeMap<String, usize> {
    let mut raw: BTreeMap<String, usize> = BTreeMap::new();
    for peer in nodes {
        *raw.entry(map.key_of(peer)).or_default() += 1;
    }
    fold(raw, min_k)
}

/// `raw` with every country under `min_k` folded into [`OTHER`].
pub fn fold(raw: BTreeMap<String, usize>, min_k: u32) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    out.insert(UNKNOWN.to_string(), 0);
    out.insert(OTHER.to_string(), 0);
    out.insert(Network::Onion.name().to_string(), 0);
    for (key, n) in raw {
        let key = if is_country(&key) && (n as u64) < u64::from(min_k) {
            OTHER.to_string()
        } else {
            key
        };
        *out.entry(key).or_default() += n;
    }
    out
}

/// A MaxMind DB file writer, for tests: an IPv6 tree with IPv4 under
/// `::/96`, as both real files lay it out, 24-bit records, and per network
/// a record `{"country": {"iso_code": <code>}}`, or a record without a
/// country when the code is `None`.
#[cfg(test)]
pub(crate) mod testing {
    use std::net::IpAddr;

    enum Rec {
        Empty,
        Node(usize),
        Data(usize),
    }

    fn put_ctrl(out: &mut Vec<u8>, ty: u8, size: usize) {
        assert!(size < 29, "the writer keeps every size under 29");
        if ty <= 7 {
            out.push((ty << 5) | size as u8);
        } else {
            out.push(size as u8);
            out.push(ty - 7);
        }
    }

    fn put_str(out: &mut Vec<u8>, s: &str) {
        put_ctrl(out, 2, s.len());
        out.extend_from_slice(s.as_bytes());
    }

    fn put_uint(out: &mut Vec<u8>, ty: u8, v: u64) {
        let bytes = v.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        put_ctrl(out, ty, 8 - skip);
        out.extend_from_slice(&bytes[skip..]);
    }

    fn put_map_header(out: &mut Vec<u8>, n: usize) {
        put_ctrl(out, 7, n);
    }

    /// The bits of `net` (`a.b.c.d/len` or `v6/len`) in the IPv6 tree.
    fn prefix_bits(net: &str) -> Vec<bool> {
        let (ip, len) = net.split_once('/').expect("a network has a length");
        let len: usize = len.parse().expect("a length");
        let ip: IpAddr = ip.parse().expect("an IP");
        let (bits, offset) = match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 96),
            IpAddr::V6(v6) => (u128::from(v6), 0),
        };
        let total = offset + len;
        (0..total).map(|i| (bits >> (127 - i)) & 1 == 1).collect()
    }

    /// The file for `networks`: each a network and its country code.
    pub(crate) fn mmdb(networks: &[(&str, Option<&str>)]) -> Vec<u8> {
        // The data section: one record per network, in order.
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for (_, code) in networks {
            offsets.push(data.len());
            match code {
                Some(code) => {
                    put_map_header(&mut data, 1);
                    put_str(&mut data, "country");
                    put_map_header(&mut data, 1);
                    put_str(&mut data, "iso_code");
                    put_str(&mut data, code);
                }
                None => {
                    put_map_header(&mut data, 1);
                    put_str(&mut data, "continent");
                    put_map_header(&mut data, 1);
                    put_str(&mut data, "code");
                    put_str(&mut data, "EU");
                }
            }
        }
        // The tree: node 0 the root, a node per bit of every prefix.
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
        for ((net, _), off) in networks.iter().zip(&offsets) {
            let bits = prefix_bits(net);
            let mut node = 0;
            for (i, bit) in bits.iter().enumerate() {
                let side = usize::from(*bit);
                if i + 1 == bits.len() {
                    nodes[node][side] = Rec::Data(*off);
                } else {
                    node = match nodes[node][side] {
                        Rec::Node(n) => n,
                        _ => {
                            nodes.push([Rec::Empty, Rec::Empty]);
                            let n = nodes.len() - 1;
                            nodes[node][side] = Rec::Node(n);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let mut out = Vec::new();
        for node in &nodes {
            for rec in node {
                let v = match rec {
                    Rec::Empty => count,
                    Rec::Node(n) => *n,
                    Rec::Data(off) => count + 16 + off,
                };
                assert!(v < 1 << 24);
                out.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        put_map_header(&mut out, 9);
        put_str(&mut out, "binary_format_major_version");
        put_uint(&mut out, 5, 2);
        put_str(&mut out, "binary_format_minor_version");
        put_uint(&mut out, 5, 0);
        put_str(&mut out, "build_epoch");
        put_uint(&mut out, 9, 1_790_000_000);
        put_str(&mut out, "database_type");
        put_str(&mut out, "satd-test-Country");
        put_str(&mut out, "description");
        put_map_header(&mut out, 1);
        put_str(&mut out, "en");
        put_str(&mut out, "satd test fixture");
        put_str(&mut out, "ip_version");
        put_uint(&mut out, 5, 6);
        put_str(&mut out, "languages");
        put_ctrl(&mut out, 11, 1);
        put_str(&mut out, "en");
        put_str(&mut out, "node_count");
        put_uint(&mut out, 6, count as u64);
        put_str(&mut out, "record_size");
        put_uint(&mut out, 5, 24);
        out
    }

    /// The networks of the committed fixture,
    /// `satd/tests/data/country-test.mmdb`: documentation ranges only.
    pub(crate) const FIXTURE: &[(&str, Option<&str>)] = &[
        ("192.0.2.0/25", Some("DE")),
        ("192.0.2.128/25", Some("JP")),
        ("198.51.100.0/24", Some("br")),
        ("203.0.113.0/26", None),
        ("2001:db8::/33", Some("NZ")),
    ];
}

#[cfg(test)]
#[path = "country_tests.rs"]
mod tests;
