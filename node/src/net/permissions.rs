//! Peer permission flags (Bitcoin Core's `NetPermissionFlags`), driven by
//! `-whitelist` (by source subnet) and `-whitebind` (by local bind
//! address). A whitelisted peer can be exempted from banning and the
//! inbound connection caps, and granted transaction-relay even while the
//! node runs `-blocksonly`.

use ipnet::IpNet;
use std::net::IpAddr;

/// The subset of Bitcoin Core's net permissions satd acts on. Stored per
/// peer. `Addr`/`Mempool`/`Download` are tracked for parity/`getpeerinfo`
/// even where satd does not yet special-case them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetPermissions {
    /// Never ban/disconnect this peer for misbehavior; exempt from the
    /// inbound connection caps.
    pub noban: bool,
    /// Relay transactions to/from this peer even under `-blocksonly`.
    pub relay: bool,
    /// Relay even transactions/blocks that fail standardness/policy
    /// (implies `relay`). Core's `forcerelay`.
    pub force_relay: bool,
    /// Accept `mempool` requests from this peer.
    pub mempool: bool,
    /// Serve historical blocks ignoring `-maxuploadtarget`.
    pub download: bool,
    /// Process `addr` messages from this peer without rate limiting.
    pub addr: bool,
}

impl NetPermissions {
    pub const NONE: NetPermissions = NetPermissions {
        noban: false,
        relay: false,
        force_relay: false,
        mempool: false,
        download: false,
        addr: false,
    };

    /// The implicit permission set Bitcoin Core grants a `-whitelist` /
    /// `-whitebind` entry written without an explicit permission list.
    pub fn implicit() -> Self {
        Self {
            noban: true,
            relay: true,
            force_relay: false,
            mempool: true,
            download: true,
            addr: true,
        }
    }

    pub fn all() -> Self {
        Self {
            noban: true,
            relay: true,
            force_relay: true,
            mempool: true,
            download: true,
            addr: true,
        }
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            noban: self.noban || other.noban,
            relay: self.relay || other.relay,
            force_relay: self.force_relay || other.force_relay,
            mempool: self.mempool || other.mempool,
            download: self.download || other.download,
            addr: self.addr || other.addr,
        }
    }

    pub fn any(&self) -> bool {
        self.noban || self.relay || self.force_relay || self.mempool || self.download || self.addr
    }

    /// Whether tx relay is allowed with this peer (relay or forcerelay).
    pub fn relays_txes(&self) -> bool {
        self.relay || self.force_relay
    }

    /// Parse a comma-separated permission list (`noban,relay,...` or
    /// `all`). An empty string yields the implicit default set.
    pub fn parse_list(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::implicit());
        }
        let mut p = Self::NONE;
        for tok in s.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "" => {}
                "all" => p = p.union(Self::all()),
                "noban" => p.noban = true,
                "relay" => p.relay = true,
                "forcerelay" => {
                    p.force_relay = true;
                    p.relay = true;
                }
                "mempool" => p.mempool = true,
                "download" => p.download = true,
                "addr" => p.addr = true,
                // Recognised Core permission names satd doesn't act on yet
                // (kept permissive rather than erroring).
                "bloomfilter" | "in" | "out" => {}
                other => {
                    return Err(format!(
                        "unknown net permission {other:?}; valid: noban, relay, forcerelay, \
                         mempool, download, addr, all"
                    ));
                }
            }
        }
        Ok(p)
    }
}

/// A `-whitelist` entry: a permission set applied to peers whose address
/// falls within `net`.
#[derive(Clone, Debug)]
pub struct WhitelistEntry {
    pub net: IpNet,
    pub perms: NetPermissions,
    pub raw: String,
    /// True when the entry was written without an explicit `perms@` prefix
    /// and therefore took the implicit permission set. The global
    /// `-whitelistrelay` / `-whitelistforcerelay` defaults apply only to
    /// these entries (Core applies them to peers "with default permissions").
    pub implicit: bool,
}

impl WhitelistEntry {
    /// Parse a `-whitelist` value: `[<perms>@]<ip-or-cidr>`. The optional
    /// `perms@` prefix is a comma-separated permission list; without it,
    /// the implicit default set applies.
    pub fn parse(s: &str) -> Result<Self, String> {
        let raw = s.trim().to_string();
        if raw.is_empty() {
            return Err("empty -whitelist entry".to_string());
        }
        let (perms, subnet, implicit) = match raw.split_once('@') {
            Some((p, net)) => (NetPermissions::parse_list(p)?, net.trim(), false),
            None => (NetPermissions::implicit(), raw.as_str(), true),
        };
        let net: IpNet = if let Ok(n) = subnet.parse::<IpNet>() {
            n
        } else if let Ok(ip) = subnet.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
            }
        } else {
            return Err(format!(
                "invalid -whitelist subnet {subnet:?}: expected IP or CIDR (e.g. \
                 127.0.0.1, 10.0.0.0/8, noban@192.168.0.0/16)"
            ));
        };
        Ok(Self {
            net,
            perms,
            raw,
            implicit,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.net.contains(&ip)
    }

    /// Apply the global `-whitelistrelay` (default on) and
    /// `-whitelistforcerelay` (default off) modifiers. They affect only
    /// entries that took the implicit permission set (no explicit `perms@`
    /// prefix), matching Bitcoin Core, which applies them to whitelisted
    /// peers "with default permissions". An explicit `relay`/`forcerelay`
    /// in a `perms@` prefix is left untouched.
    pub fn apply_global_relay_defaults(
        &mut self,
        whitelist_relay: bool,
        whitelist_force_relay: bool,
    ) {
        if !self.implicit {
            return;
        }
        self.perms.relay = whitelist_relay;
        if whitelist_force_relay {
            self.perms.force_relay = true;
            self.perms.relay = true;
        }
    }
}

/// Compute the union of permissions granted to `ip` by the whitelist.
pub fn permissions_for_ip(whitelist: &[WhitelistEntry], ip: IpAddr) -> NetPermissions {
    whitelist
        .iter()
        .filter(|e| e.contains(ip))
        .fold(NetPermissions::NONE, |acc, e| acc.union(e.perms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_subnet_gets_implicit_perms() {
        let e = WhitelistEntry::parse("192.168.0.0/16").unwrap();
        assert_eq!(e.perms, NetPermissions::implicit());
        assert!(e.contains("192.168.1.5".parse().unwrap()));
        assert!(!e.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn explicit_perms_prefix() {
        let e = WhitelistEntry::parse("noban,relay@10.0.0.0/8").unwrap();
        assert!(e.perms.noban && e.perms.relay);
        assert!(!e.perms.mempool);
        assert!(e.contains("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn forcerelay_implies_relay() {
        let p = NetPermissions::parse_list("forcerelay").unwrap();
        assert!(p.force_relay && p.relay && p.relays_txes());
    }

    #[test]
    fn unknown_permission_errors() {
        assert!(NetPermissions::parse_list("nonsense").is_err());
        assert!(WhitelistEntry::parse("relay@not-an-ip").is_err());
    }

    #[test]
    fn global_relay_defaults_only_touch_implicit_entries() {
        // Implicit entry: -whitelistrelay=0 strips relay.
        let mut e = WhitelistEntry::parse("127.0.0.1").unwrap();
        assert!(e.implicit && e.perms.relay);
        e.apply_global_relay_defaults(false, false);
        assert!(!e.perms.relay);

        // Implicit entry: -whitelistforcerelay=1 grants forcerelay + relay.
        let mut e = WhitelistEntry::parse("10.0.0.0/8").unwrap();
        e.apply_global_relay_defaults(true, true);
        assert!(e.perms.force_relay && e.perms.relay);

        // Explicit perms@ entry: untouched by the global defaults.
        let mut e = WhitelistEntry::parse("noban@192.168.0.0/16").unwrap();
        assert!(!e.implicit && !e.perms.relay);
        e.apply_global_relay_defaults(true, true);
        assert!(!e.perms.relay && !e.perms.force_relay, "explicit entry must be untouched");
        assert!(e.perms.noban);
    }

    #[test]
    fn union_over_multiple_entries() {
        let wl = vec![
            WhitelistEntry::parse("noban@10.0.0.0/8").unwrap(),
            WhitelistEntry::parse("relay@10.0.0.5").unwrap(),
        ];
        let p = permissions_for_ip(&wl, "10.0.0.5".parse().unwrap());
        assert!(p.noban && p.relay);
        let p2 = permissions_for_ip(&wl, "10.9.9.9".parse().unwrap());
        assert!(p2.noban && !p2.relay);
    }
}
