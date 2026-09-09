//! Peer permission flags (Bitcoin Core's `NetPermissionFlags`), driven by
//! `-whitelist` (by source subnet) and `-whitebind` (by local bind
//! address). A whitelisted peer can be exempted from banning and the
//! inbound connection caps, and granted transaction-relay even while the
//! node runs `-blocksonly`.

use ipnet::IpNet;
use std::net::IpAddr;

/// Which connection directions a `-whitelist` entry applies to
/// (Core's `ConnectionDirection`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Direction {
    pub inbound: bool,
    pub outbound: bool,
}

impl Direction {
    pub const NONE: Self = Self {
        inbound: false,
        outbound: false,
    };
    /// Core's default for an entry carrying neither token.
    pub const IN: Self = Self {
        inbound: true,
        outbound: false,
    };
    pub const OUT: Self = Self {
        inbound: false,
        outbound: true,
    };
}

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
    ///
    /// Core's expansion (`src/net.cpp`, `CConnman::CreateNodeFromAcceptedSocket`)
    /// is exactly `ForceRelay?` + `Relay?` + `Mempool` + `NoBan` — and `NoBan`
    /// carries `Download` in its flag value. **No `Addr`.**
    /// `p2p_permissions.py` asserts the list literally:
    ///
    /// ```text
    /// ["-whitelist=127.0.0.1"] -> ["relay", "noban", "mempool", "download"]
    /// ```
    ///
    /// satd granted `addr` here as well, which meant a bare `-whitelist`
    /// entry exempted the peer from address-relay rate limiting. That was
    /// invisible while `getpeerinfo.permissions` was hardcoded `[]`.
    pub fn implicit() -> Self {
        Self {
            noban: true,
            relay: true,
            force_relay: false,
            mempool: true,
            download: true,
            addr: false,
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

    /// Core's `NetPermissions::ToStrings` (`src/net_permissions.cpp`), which
    /// is what `getpeerinfo.permissions` reports. The order is Core's, not
    /// alphabetical, and `rpc_setban.py` reads the array by membership.
    ///
    /// `bloomfilter` is absent because satd has no flag for it: `parse_list`
    /// accepts the name and drops it, so reporting it would claim a grant that
    /// was never recorded.
    pub fn to_strings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.noban {
            out.push("noban");
        }
        if self.force_relay {
            out.push("forcerelay");
        }
        if self.relay {
            out.push("relay");
        }
        if self.mempool {
            out.push("mempool");
        }
        if self.download {
            out.push("download");
        }
        if self.addr {
            out.push("addr");
        }
        out
    }

    /// Parse a comma-separated permission list, returning the permissions and
    /// the connection direction its `in` / `out` tokens select.
    pub fn parse_list_with_direction(s: &str) -> Result<(Self, Direction), String> {
        let mut direction = Direction::NONE;
        for tok in s.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "in" => direction.inbound = true,
                "out" => direction.outbound = true,
                _ => {}
            }
        }
        let perms = Self::parse_list(s)?;
        // Core's `TryParsePermissionFlags` (`src/net_permissions.cpp`):
        //
        //     if (connection_direction == ConnectionDirection::None) {
        //         connection_direction = ConnectionDirection::In;
        //     } else if (flags == NetPermissionFlags::None) {
        //         error = "Only direction was set, no permissions: '<str>'";
        //         return false;
        //     }
        //
        // The second branch matters: `-whitelist=out@10.0.0.0/8` grants
        // nothing, so accepting it started a node whose operator believed a
        // grant was in place. Core refuses to start and names the entry.
        if direction == Direction::NONE {
            direction = Direction::IN;
        } else if perms == Self::NONE {
            return Err(format!(
                "only direction was set, no permissions: {s:?}"
            ));
        }
        Ok((perms, direction))
    }

    /// `-whitebind`'s parse: as [`Self::parse_list_with_direction`], but `out`
    /// is refused.
    ///
    /// Core passes a null `output_connection_direction` for a `-whitebind`
    /// entry, and `TryParsePermissionFlags` uses exactly that to reject the
    /// token: a bind address describes where connections *arrive*, so an
    /// outbound qualifier on one is meaningless. satd swallowed it, so
    /// `-whitebind=out@127.0.0.1:8333` started a node where Core refuses.
    pub fn parse_list_for_bind(s: &str) -> Result<Self, String> {
        if s.split(',').any(|t| t.trim().eq_ignore_ascii_case("out")) {
            return Err(
                "whitebind may only be used for incoming connections (\"out\" was passed)"
                    .to_string(),
            );
        }
        let (perms, _) = Self::parse_list_with_direction(s)?;
        Ok(perms)
    }

    /// Parse a comma-separated permission list (`noban,relay,...` or `all`).
    ///
    /// An empty list grants **nothing**. This is only reachable as the
    /// `@`-prefixed form — `-whitelist=@1.2.3.4`, Core's idiom for "match this
    /// range and grant it nothing" — because a bare subnet never comes through
    /// here at all; [`WhitelistEntry::parse`] hands it [`Self::implicit`]
    /// directly. Core takes the `else` branch in `TryParsePermissionFlags`
    /// for an `@` entry, never setting `Implicit`, so no expansion follows;
    /// `p2p_permissions.py` asserts `["-whitelist=@127.0.0.1", …] -> []`.
    ///
    /// Returning the implicit set here instead silently granted `noban` —
    /// which exempts a peer from banning *and* from the inbound connection
    /// caps — to every peer in a range the operator had asked to grant
    /// nothing.
    pub fn parse_list(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let mut p = Self::NONE;
        if s.is_empty() {
            return Ok(p);
        }
        for tok in s.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "" => {}
                "all" => p = p.union(Self::all()),
                // Core's `NetPermissionFlags::NoBan` is `(1U << 4) | Download`
                // -- the grant *is* the pair, not two names that happen to be
                // given together, so `noban` alone also lifts the
                // `-maxuploadtarget` block-serving limit.
                "noban" => {
                    p.noban = true;
                    p.download = true;
                }
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
    /// Which connection directions this entry applies to. Core keeps two
    /// lists (`vWhitelistedRangeIncoming` / `Outgoing`) and consults the
    /// outgoing one *only* for manual connections; satd records the direction
    /// on the entry and applies the same rule in [`permissions_for`].
    ///
    /// The default is inbound-only, as in Core, whose
    /// `TryParsePermissionFlags` resolves an unqualified entry to
    /// `ConnectionDirection::In`. satd used to swallow the `in` / `out`
    /// tokens as no-ops and apply every entry in both directions, so
    /// `-whitelist=noban@127.0.0.1` made an *outbound* peer un-bannable and
    /// exempt from the upload budget — a grant with no `out` token asking
    /// for it.
    pub direction: Direction,
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
        let (perms, direction, subnet, implicit) = match raw.split_once('@') {
            Some((p, net)) => {
                let (perms, direction) = NetPermissions::parse_list_with_direction(p)?;
                (perms, direction, net.trim(), false)
            }
            // No `perms@` prefix: the implicit set, inbound only, as in Core.
            None => (
                NetPermissions::implicit(),
                Direction::IN,
                raw.as_str(),
                true,
            ),
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
            direction,
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
    permissions_for(whitelist, ip, Direction::IN)
}

/// The permissions granted to a peer at `ip` reached in `direction`.
///
/// Core keeps two lists and picks between them at the call site
/// (`CConnman::ConnectNode`):
///
/// ```text
/// whitelist_permissions = conn_type == ConnectionType::MANUAL
///     ? vWhitelistedRangeOutgoing : {};
/// ```
///
/// so an *automatic* outbound connection gets nothing from `-whitelist` at
/// all, and a manual one gets only the entries carrying an `out` token. satd
/// applies the same rule by filtering on the entry's recorded direction; the
/// caller passes [`Direction::NONE`] for an outbound connection that is not
/// manual.
pub fn permissions_for(
    whitelist: &[WhitelistEntry],
    ip: IpAddr,
    direction: Direction,
) -> NetPermissions {
    if direction == Direction::NONE {
        return NetPermissions::NONE;
    }
    whitelist
        .iter()
        .filter(|e| {
            (direction.inbound && e.direction.inbound)
                || (direction.outbound && e.direction.outbound)
        })
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

    /// Core's `NetPermissionFlags::NoBan` is `(1U << 4) | Download`: the two
    /// are one grant, so `noban` also lifts the block-serving limit.
    #[test]
    fn noban_implies_download() {
        let p = NetPermissions::parse_list("noban").unwrap();
        assert!(p.noban && p.download);
    }

    /// The array `getpeerinfo.permissions` reports. The order is Core's
    /// `ToStrings` order, not alphabetical.
    #[test]
    fn to_strings_matches_cores_order() {
        assert_eq!(NetPermissions::NONE.to_strings(), Vec::<&str>::new());
        assert_eq!(
            NetPermissions::all().to_strings(),
            ["noban", "forcerelay", "relay", "mempool", "download", "addr"]
        );
        // Core's `p2p_permissions.py` asserts this list literally, as the
        // documented default for a bare `-whitelist=<subnet>`.
        assert_eq!(
            NetPermissions::implicit().to_strings(),
            ["noban", "relay", "mempool", "download"]
        );
        // The one `rpc_setban.py` reads.
        assert!(
            NetPermissions::parse_list("noban")
                .unwrap()
                .to_strings()
                .contains(&"noban")
        );
    }

    /// Core's idiom for "match this range and grant it nothing" is an `@`
    /// entry with an empty permission list. satd expanded it to the implicit
    /// set, silently granting `noban` — exemption from banning *and* from the
    /// inbound connection caps — to a range the operator asked to grant
    /// nothing.
    #[test]
    fn an_empty_permission_list_grants_nothing() {
        assert_eq!(NetPermissions::parse_list("").unwrap(), NetPermissions::NONE);
        let e = WhitelistEntry::parse("@127.0.0.1").unwrap();
        assert_eq!(e.perms, NetPermissions::NONE, "@<subnet> grants nothing");
        assert!(e.perms.to_strings().is_empty());
        assert!(e.contains("127.0.0.1".parse().unwrap()), "it still matches the range");

        // A bare subnet never reaches `parse_list`, so it is unaffected.
        let e = WhitelistEntry::parse("127.0.0.1").unwrap();
        assert_eq!(e.perms, NetPermissions::implicit());
    }

    /// Core's `-whitelist` is inbound-only unless the entry says otherwise,
    /// and its outgoing list is consulted only for manual connections.
    /// `p2p_permissions.py` pins the difference:
    ///
    /// ```text
    /// -whitelist=noban,out@127.0.0.1  -> ["noban", "download"]
    /// -whitelist=noban@127.0.0.1      -> []
    /// ```
    ///
    /// satd swallowed the `in` / `out` tokens as no-ops and applied every
    /// entry in both directions, so the second line granted `noban` — making
    /// an outbound peer un-bannable and exempt from the upload budget with no
    /// `out` token asking for it.
    #[test]
    fn whitelist_entries_are_inbound_only_by_default() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let inbound_only = vec![WhitelistEntry::parse("noban@127.0.0.1").unwrap()];
        assert_eq!(inbound_only[0].direction, Direction::IN);
        assert!(permissions_for(&inbound_only, ip, Direction::IN).noban);
        assert_eq!(
            permissions_for(&inbound_only, ip, Direction::OUT),
            NetPermissions::NONE,
            "an entry with no `out` token grants nothing outbound"
        );

        let outbound = vec![WhitelistEntry::parse("noban,out@127.0.0.1").unwrap()];
        assert_eq!(outbound[0].direction, Direction::OUT);
        assert!(permissions_for(&outbound, ip, Direction::OUT).noban);
        assert!(
            permissions_for(&outbound, ip, Direction::OUT).download,
            "noban carries download"
        );
        assert_eq!(
            permissions_for(&outbound, ip, Direction::IN),
            NetPermissions::NONE,
            "`out` alone grants nothing inbound"
        );

        // Both tokens grant in both directions.
        let both = vec![WhitelistEntry::parse("noban,in,out@127.0.0.1").unwrap()];
        assert!(permissions_for(&both, ip, Direction::IN).noban);
        assert!(permissions_for(&both, ip, Direction::OUT).noban);

        // A bare subnet is the implicit set, inbound only.
        let bare = vec![WhitelistEntry::parse("127.0.0.1").unwrap()];
        assert_eq!(bare[0].direction, Direction::IN);
        assert_eq!(permissions_for(&bare, ip, Direction::OUT), NetPermissions::NONE);

        // An automatic outbound connection asks for nothing and gets nothing,
        // whatever the entries say.
        assert_eq!(
            permissions_for(&both, ip, Direction::NONE),
            NetPermissions::NONE
        );

        // `permissions_for_ip` is the inbound spelling, unchanged.
        assert!(permissions_for_ip(&inbound_only, ip).noban);
    }

    /// Core refuses an entry that sets only a direction, because such an entry
    /// grants nothing:
    ///
    /// ```cpp
    /// } else if (flags == NetPermissionFlags::None) {
    ///     error = strprintf(_("Only direction was set, no permissions: '%s'"), str);
    ///     return false;
    /// }
    /// ```
    ///
    /// Accepting it started a node whose operator believed a grant was in
    /// place. And `-whitebind` refuses `out` outright — Core passes a null
    /// `output_connection_direction` for a bind entry, since a bind address
    /// describes where connections *arrive*.
    #[test]
    fn a_direction_without_permissions_is_refused() {
        for entry in ["out", "in", "in,out", " out "] {
            let err = NetPermissions::parse_list_with_direction(entry)
                .expect_err("{entry:?} grants nothing and must be refused");
            assert!(err.contains("no permissions"), "{entry:?}: {err}");
        }

        // A direction *with* a permission is fine, and so is a bare list.
        assert!(NetPermissions::parse_list_with_direction("noban,out").is_ok());
        assert!(NetPermissions::parse_list_with_direction("noban").is_ok());
        // The `@`-form's empty list is Core's "grant nothing" idiom and stays
        // legal: no direction was set, so the refusal does not apply.
        assert!(NetPermissions::parse_list_with_direction("").is_ok());

        // `-whitebind` rejects `out` whatever else it carries.
        let err = NetPermissions::parse_list_for_bind("noban,out")
            .expect_err("out is meaningless on a bind address");
        assert!(err.contains("only be used for incoming"), "{err}");
        assert!(NetPermissions::parse_list_for_bind("noban,in").is_ok());
        assert!(NetPermissions::parse_list_for_bind("noban").is_ok());
        // ...and inherits the direction-only refusal.
        assert!(NetPermissions::parse_list_for_bind("in").is_err());
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
