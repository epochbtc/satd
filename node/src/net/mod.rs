pub mod addrman;
pub mod ban;
pub mod asmap;
pub mod bg_catchup;
pub mod compact;
pub mod connection;
pub mod dns;
pub mod flow;
pub mod ibd;
pub mod manager;
pub mod orphan_blocks;
pub mod peer;
pub mod permissions;
pub mod proxy;
pub mod stats;
pub mod tor;
pub mod sync;
pub mod v2transport;

/// Bitcoin Core's `CNetAddr::IsValid` for an IP address: whether it can name
/// a host at all (v31.1 `src/netaddress.cpp:424`).
///
/// False for the IPv4 `INADDR_ANY` (`0.0.0.0`) and `INADDR_NONE`
/// (`255.255.255.255`), the IPv6 unspecified address `::`, RFC 3849
/// documentation space (`2001:db8::/32`), and the two IPv6 prefixes Core
/// never reads as a host: its internal name encoding (`fd6b:88c0:8724::/48`)
/// and the retired TORv2 OnionCat range (`fd87:d87e:eb43::/48`), both of
/// which it unserializes as invalid (`netaddress.cpp:148`, `:155`). Core
/// never dials an invalid address (`ConnectNode`, `src/net.cpp:443`) and
/// its address book never holds one.
///
/// A peer can still announce one. On Linux a connect to `0.0.0.0` reaches
/// the local host, so a gossiped `0.0.0.0:<our port>` that is dialled is a
/// connection to ourselves.
pub fn is_valid(ip: std::net::IpAddr) -> bool {
    // An IPv4-mapped address is judged as the IPv4 address it carries, as
    // Core reads a legacy `addr` entry.
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_broadcast()),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_unspecified()
                // RFC 3849 documentation, 2001:db8::/32.
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                // Core's internal (name) addresses.
                || (s[0] == 0xfd6b && s[1] == 0x88c0 && s[2] == 0x8724)
                // TORv2 OnionCat.
                || (s[0] == 0xfd87 && s[1] == 0xd87e && s[2] == 0xeb43))
        }
    }
}

/// Bitcoin Core's `CNetAddr::IsRoutable`: whether an address can appear on
/// the public internet.
///
/// Everything Core calls unroutable — RFC 1918 private space, RFC 2544
/// benchmarking, RFC 3927 link-local, RFC 5737 documentation, RFC 6598
/// shared address space, RFC 4193 unique-local, RFC 4843 ORCHID, RFC 7343
/// ORCHIDv2, loopback, and every address [`is_valid`] refuses — is false
/// here.
///
/// Two places need the same answer and used to disagree: `getpeerinfo`'s
/// `network` field, which called only loopback and unspecified
/// `not_publicly_routable`, and the proxy-dial decision, which bypassed the
/// proxy for loopback alone.
pub fn is_routable(ip: std::net::IpAddr) -> bool {
    // Core's `IsRoutable` is `IsValid() && !(...)` (`netaddress.cpp:462`).
    if !is_valid(ip) {
        return false;
    }
    // Core folds an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) into the
    // IPv4 address it carries when the `CNetAddr` is built, so an RFC 1918
    // peer that arrived on a dual-stack `[::]` listener is judged as the
    // IPv4 address it is, not as a routable IPv6 one.
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                // Core's `IsLocal` is 127.0.0.0/8 *and* 0.0.0.0/8.
                || o[0] == 0
                || v4.is_private()
                || v4.is_link_local()
                // RFC 6598 shared address space, 100.64.0.0/10.
                || (o[0] == 100 && (64..128).contains(&o[1]))
                // RFC 5737 documentation ranges.
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                // RFC 2544 benchmarking, 198.18.0.0/15.
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                // RFC 4193 unique-local, fc00::/7.
                || (s[0] & 0xfe00) == 0xfc00
                // Link-local, fe80::/10.
                || (s[0] & 0xffc0) == 0xfe80
                // RFC 4843 ORCHID, 2001:10::/28, and RFC 7343 ORCHIDv2,
                // 2001:20::/28.
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Core's `IsValid` cases (`netaddress.cpp:424`): the addresses that
    /// name no host, and a spread of ones that do, including the private
    /// and loopback ranges that are valid but not routable.
    #[test]
    fn is_valid_follows_core() {
        for bad in [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "::ffff:0.0.0.0",
            "::ffff:255.255.255.255",
            "2001:db8::1",
            "fd6b:88c0:8724::1",
            "fd87:d87e:eb43::1",
        ] {
            assert!(!is_valid(ip(bad)), "{bad} names no host");
            assert!(!is_routable(ip(bad)), "{bad} cannot be routable either");
        }
        for good in [
            "1.2.3.4",
            "0.0.0.1",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "255.255.255.254",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:470::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_valid(ip(good)), "{good} is a host");
        }
        // Valid is wider than routable.
        assert!(is_routable(ip("1.2.3.4")));
        assert!(is_routable(ip("2001:470::1")));
        for private in ["0.0.0.1", "127.0.0.1", "10.0.0.1", "::1", "fc00::1", "::ffff:10.0.0.1"] {
            assert!(!is_routable(ip(private)), "{private} is valid but not routable");
        }
    }
}
