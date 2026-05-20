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
//! Per-request enforcement is wired in PR-1b (it depends on a manual
//! accept-loop refactor of the plain-HTTP path so the source IP can be
//! injected into request extensions before the AuthLayer runs). For
//! PR-1 the allowlist is parsed and surfaced via `getconfig` for
//! visibility, and the static "must allowlist before exposing"
//! validation in `Config::load` already prevents the misconfigured-
//! exposure case.

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
        let net: IpNet = if let Ok(n) = raw.parse::<IpNet>() {
            n
        } else if let Ok(ip) = raw.parse::<IpAddr>() {
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

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.net.contains(&ip)
    }
}

/// Does `ip` satisfy the allowlist? Loopback is always allowed (matches
/// Bitcoin Core's `IsLocal()` exemption); otherwise the IP must fall in
/// at least one configured CIDR. An empty list means loopback-only.
pub fn is_allowed(ip: IpAddr, allow: &[IpAllowEntry]) -> bool {
    if ip_is_loopback(ip) {
        return true;
    }
    allow.iter().any(|e| e.contains(ip))
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
}
