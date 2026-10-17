//! The networks automatic outbound connections may use: Core's
//! `g_reachable_nets`, set from `-onlynet` (`src/init.cpp`).
//!
//! `-onlynet=<net>` restricts *automatic* outbound connections, and the
//! addresses the node keeps from gossip, to the named networks. Inbound and
//! manual connections (`-connect`, `-addnode`, `-seednode`) are not affected,
//! as in Core. Without `-onlynet` every network the node can reach is
//! reachable.

use std::net::{IpAddr, SocketAddr};

/// A network `-onlynet` can name: Core's `ParseNetwork`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Ipv4,
    Ipv6,
    Onion,
    I2p,
    Cjdns,
}

/// Core's `ParseNetwork`: case-insensitive; `None` for anything else, which
/// Core reports as "Unknown network specified in -onlynet".
pub fn parse_network(name: &str) -> Option<Network> {
    match name.to_ascii_lowercase().as_str() {
        "ipv4" => Some(Network::Ipv4),
        "ipv6" => Some(Network::Ipv6),
        "onion" => Some(Network::Onion),
        "i2p" => Some(Network::I2p),
        "cjdns" => Some(Network::Cjdns),
        _ => None,
    }
}

/// The reachable networks. satd has no I2P transport, so I2P is never
/// reachable. CJDNS addresses are IPv6 addresses in `fc00::/8` that
/// `-cjdnsreachable` says to read as CJDNS (Core's `MaybeFlipIPv6toCJDNS`);
/// satd has no CJDNS transport either, so it never dials one automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachableNets {
    pub ipv4: bool,
    pub ipv6: bool,
    pub onion: bool,
    pub cjdns: bool,
    /// `-cjdnsreachable`: read `fc00::/8` as CJDNS rather than IPv6.
    pub cjdns_flip: bool,
}

impl Default for ReachableNets {
    /// No `-onlynet`: everything satd can reach.
    fn default() -> Self {
        Self { ipv4: true, ipv6: true, onion: true, cjdns: false, cjdns_flip: false }
    }
}

impl ReachableNets {
    /// The network of a socket address, as Core classifies it once
    /// `MaybeFlipIPv6toCJDNS` has run. IPv4-mapped IPv6 is IPv4.
    pub fn network_of(&self, addr: &SocketAddr) -> Network {
        match addr.ip() {
            IpAddr::V4(_) => Network::Ipv4,
            IpAddr::V6(v6) => {
                if v6.to_ipv4_mapped().is_some() {
                    Network::Ipv4
                } else if self.cjdns_flip && v6.octets()[0] == 0xfc {
                    Network::Cjdns
                } else {
                    Network::Ipv6
                }
            }
        }
    }

    /// Whether `net` is reachable.
    pub fn contains(&self, net: Network) -> bool {
        match net {
            Network::Ipv4 => self.ipv4,
            Network::Ipv6 => self.ipv6,
            Network::Onion => self.onion,
            Network::Cjdns => self.cjdns,
            Network::I2p => false,
        }
    }

    /// Whether an automatic outbound connection may go to `addr`.
    pub fn contains_socket(&self, addr: &SocketAddr) -> bool {
        self.contains(self.network_of(addr))
    }

    /// Whether IPv4 or IPv6 is reachable: DNS seeds answer only with those.
    pub fn clearnet(&self) -> bool {
        self.ipv4 || self.ipv6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_names_are_cores() {
        assert_eq!(parse_network("IPv4"), Some(Network::Ipv4));
        assert_eq!(parse_network("ipv6"), Some(Network::Ipv6));
        assert_eq!(parse_network("Onion"), Some(Network::Onion));
        assert_eq!(parse_network("i2p"), Some(Network::I2p));
        assert_eq!(parse_network("cjdns"), Some(Network::Cjdns));
        assert_eq!(parse_network("tor"), None, "Core does not accept tor");
        assert_eq!(parse_network(""), None);
    }

    #[test]
    fn addresses_are_classified_as_core_classifies_them() {
        let all = ReachableNets::default();
        let v4: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:8333".parse().unwrap();
        let v6: SocketAddr = "[2001:4860::1]:8333".parse().unwrap();
        let fc: SocketAddr = "[fc00::1]:8333".parse().unwrap();
        assert_eq!(all.network_of(&v4), Network::Ipv4);
        assert_eq!(all.network_of(&mapped), Network::Ipv4);
        assert_eq!(all.network_of(&v6), Network::Ipv6);
        assert_eq!(all.network_of(&fc), Network::Ipv6, "fc00::/8 is IPv6 without -cjdnsreachable");
        let flip = ReachableNets { cjdns_flip: true, ..all };
        assert_eq!(flip.network_of(&fc), Network::Cjdns);

        let onion_only = ReachableNets { ipv4: false, ipv6: false, onion: true, cjdns: false, cjdns_flip: false };
        assert!(!onion_only.contains_socket(&v4));
        assert!(!onion_only.contains_socket(&v6));
        assert!(!onion_only.clearnet());
        assert!(onion_only.contains(Network::Onion));
    }
}
