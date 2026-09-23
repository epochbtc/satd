//! Source-IP allowlist for the JSON-RPC HTTP listener.
//!
//! Bitcoin Core's `-rpcallowip=<ip|cidr>` model: the RPC server refuses
//! any non-loopback request whose source IP is not on the operator's
//! allowlist. Loopback (127.0.0.0/8, ::1) is always implicitly
//! allowed — the config-load check in satd already enforces "no
//! non-loopback bind without an allowlist", and once an allowlist is
//! configured the loopback exemption keeps `sat-cli` working from the
//! same host without forcing the operator to redundantly list
//! `127.0.0.1` in `rpcallowip=`.
//!
//! Enforcement happens at the TCP accept boundary: the plain-HTTP and
//! startup RPC listeners run a manual accept loop (see
//! `rpc::server::spawn_plain_surface`) that calls [`is_allowed`] on the
//! peer's source IP for each connection and answers `403 Forbidden` to
//! any non-allowlisted, non-loopback source — jsonrpsee's high-level
//! `Server::start` never exposes the peer address to HTTP middleware, so
//! a tower layer couldn't do this. The static "must allowlist before
//! exposing" validation in `Config::load` is a complementary guard that
//! refuses to start a non-loopback bind without an allowlist.
//!
//! The TLS listeners accept on their own loop too, and apply the
//! allowlist through [`tls_listener_denies`] — same rule, except that an
//! empty allowlist leaves the TLS bind reachable from wherever it is
//! bound rather than collapsing to loopback-only. Neither that startup
//! guard nor this module has ever covered a TLS bind, so an empty list
//! there means "the operator never expressed a rule", not "loopback
//! only". See that function for why.

use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single `-rpcallowip` entry, retained alongside its parsed form.
/// The `raw` field is kept so error messages and `getconfig` echo can
/// show what the operator typed (e.g. `192.168.1.5`) instead of the
/// normalised CIDR form (`192.168.1.5/32`).
#[derive(Debug, Clone)]
pub struct IpAllowEntry {
    pub raw: String,
    pub net: IpNet,
}

impl IpAllowEntry {
    pub fn parse(s: &str) -> Result<Self, String> {
        let raw = s.trim().to_string();
        if raw.is_empty() {
            return Err("empty allowlist entry".to_string());
        }
        // Core's `LookupHost` accepts an IPv6 literal in brackets, `[::1]`
        // or `[fd00::]/8`, the spelling `-rpcbind` requires.
        let unbracketed = match raw.split_once('/') {
            Some((host, prefix)) => format!("{}/{prefix}", strip_brackets(host)),
            None => strip_brackets(&raw).to_string(),
        };
        let net: IpNet = if let Ok(n) = unbracketed.parse::<IpNet>() {
            n
        } else if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
            }
        } else {
            return Err(format!(
                "invalid -rpcallowip entry {raw:?}: expected IP address or CIDR \
                (e.g. 127.0.0.1, 192.168.0.0/16, ::1, fd00::/8)"
            ));
        };
        Ok(Self { raw, net })
    }

    /// Whether the entry's network is Core's CJDNS range under
    /// `-cjdnsreachable`: fc00::/8, the half of RFC4193 with the L bit clear.
    pub fn is_cjdns_range(&self) -> bool {
        matches!(self.net, IpNet::V6(n) if n.network().octets()[0] == 0xfc)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.net.contains(&ip)
    }
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// Does `ip` satisfy the allowlist? Loopback is always allowed (matches
/// Bitcoin Core's `IsLocal()` exemption); otherwise the IP must fall in
/// at least one configured CIDR. An empty list means loopback-only.
pub fn is_allowed(ip: IpAddr, allow: &[IpAllowEntry]) -> bool {
    // A dual-stack `[::]` bind reports an IPv4 peer as `::ffff:a.b.c.d`;
    // judge it as the IPv4 address it is, or 127.0.0.1 would miss the
    // loopback exemption and no IPv4 entry could ever match.
    let ip = ip.to_canonical();
    if ip_is_loopback(ip) {
        return true;
    }
    allow.iter().any(|e| e.contains(ip))
}

/// Does a TLS JSON-RPC listener (`-rpctlsbind`, `-rpcreadonlytlsbind`)
/// have to refuse `ip`?
///
/// The TLS binds honour the allowlist only when the operator configured
/// one. An empty list does NOT collapse to loopback-only here, the way
/// it does for a plain-HTTP bind: the startup guard that refuses a
/// non-loopback `-rpcbind` without an allowlist has never covered a TLS
/// bind, so a TLS listener on a public interface with no `-rpcallowip`
/// is a configuration operators are already running. Reading it as
/// loopback-only would lock every one of those clients out on upgrade.
/// Once an allowlist exists the operator has said who may reach
/// JSON-RPC, and that answer covers both transports.
///
/// A denied peer is refused before the TLS handshake, so it never takes
/// a connection-cap permit and never sees a certificate — unlike the
/// plain-HTTP path, which is already speaking HTTP and can answer
/// `403 Forbidden`.
pub fn tls_listener_denies(ip: IpAddr, allow: &[IpAllowEntry]) -> bool {
    !allow.is_empty() && !is_allowed(ip, allow)
}

fn ip_is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST || v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a dual-stack `[::]` bind an IPv4 peer arrives IPv4-mapped. It is
    /// judged as IPv4: loopback stays exempt and IPv4 entries match.
    #[test]
    fn ipv4_mapped_peers_are_judged_as_ipv4() {
        let mapped = |v4: Ipv4Addr| IpAddr::V6(v4.to_ipv6_mapped());
        let allow = vec![IpAllowEntry::parse("10.0.0.0/8").unwrap()];
        assert!(is_allowed(mapped(Ipv4Addr::LOCALHOST), &allow));
        assert!(is_allowed(mapped(Ipv4Addr::new(10, 1, 2, 3)), &allow));
        assert!(!is_allowed(mapped(Ipv4Addr::new(192, 0, 2, 1)), &allow));
        assert!(!tls_listener_denies(mapped(Ipv4Addr::LOCALHOST), &allow));
        assert!(!tls_listener_denies(mapped(Ipv4Addr::new(10, 1, 2, 3)), &allow));
        assert!(tls_listener_denies(mapped(Ipv4Addr::new(192, 0, 2, 1)), &allow));
    }

    #[test]
    fn parse_bare_ipv4() {
        let e = IpAllowEntry::parse("192.168.1.5").unwrap();
        assert_eq!(e.raw, "192.168.1.5");
        assert!(e.contains("192.168.1.5".parse().unwrap()));
        assert!(!e.contains("192.168.1.6".parse().unwrap()));
    }

    #[test]
    fn parse_ipv4_cidr() {
        let e = IpAllowEntry::parse("10.0.0.0/8").unwrap();
        assert!(e.contains("10.5.5.5".parse().unwrap()));
        assert!(!e.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6() {
        let e = IpAllowEntry::parse("::1").unwrap();
        assert!(e.contains("::1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let e = IpAllowEntry::parse("fd00::/8").unwrap();
        assert!(e.contains("fd00:1234::5".parse().unwrap()));
        assert!(!e.contains("fe00::1".parse().unwrap()));
    }

    #[test]
    fn parse_bracketed_ipv6() {
        let e = IpAllowEntry::parse("[::1]").unwrap();
        assert!(e.contains("::1".parse().unwrap()));
        let e = IpAllowEntry::parse("[fd00::]/8").unwrap();
        assert!(e.contains("fd00:1234::5".parse().unwrap()));
        assert!(IpAllowEntry::parse("[::1").is_err());
    }

    #[test]
    fn parse_garbage() {
        assert!(IpAllowEntry::parse("nope").is_err());
        assert!(IpAllowEntry::parse("").is_err());
        assert!(IpAllowEntry::parse("999.0.0.1").is_err());
    }

    #[test]
    fn loopback_always_allowed() {
        let allow: Vec<IpAllowEntry> = vec![IpAllowEntry::parse("10.0.0.0/8").unwrap()];
        assert!(is_allowed("127.0.0.1".parse().unwrap(), &allow));
        assert!(is_allowed("127.5.5.5".parse().unwrap(), &allow));
        assert!(is_allowed("::1".parse().unwrap(), &allow));
        assert!(is_allowed("10.0.0.5".parse().unwrap(), &allow));
        assert!(!is_allowed("8.8.8.8".parse().unwrap(), &allow));
    }

    #[test]
    fn empty_allowlist_means_loopback_only() {
        let allow: Vec<IpAllowEntry> = Vec::new();
        assert!(is_allowed("127.0.0.1".parse().unwrap(), &allow));
        assert!(is_allowed("::1".parse().unwrap(), &allow));
        assert!(!is_allowed("8.8.8.8".parse().unwrap(), &allow));
    }

    #[test]
    fn a_tls_listener_without_an_allowlist_denies_nobody() {
        let allow: Vec<IpAllowEntry> = Vec::new();
        assert!(!tls_listener_denies("8.8.8.8".parse().unwrap(), &allow));
        assert!(!tls_listener_denies("fd00::1".parse().unwrap(), &allow));
        assert!(!tls_listener_denies("127.0.0.1".parse().unwrap(), &allow));
        // The same address IS refused on a plain-HTTP bind, where an empty
        // list means loopback-only. The two rules differ on purpose.
        assert!(!is_allowed("8.8.8.8".parse().unwrap(), &allow));
    }

    #[test]
    fn a_tls_listener_with_an_allowlist_enforces_it() {
        let allow: Vec<IpAllowEntry> = vec![IpAllowEntry::parse("10.0.0.0/8").unwrap()];
        assert!(tls_listener_denies("8.8.8.8".parse().unwrap(), &allow));
        assert!(!tls_listener_denies("10.1.2.3".parse().unwrap(), &allow));
        // Loopback keeps its exemption, so `sat-cli` over TLS on the same
        // host works without listing 127.0.0.1.
        assert!(!tls_listener_denies("127.0.0.1".parse().unwrap(), &allow));
        assert!(!tls_listener_denies("::1".parse().unwrap(), &allow));
    }
}
