pub mod addrman;
pub mod ban;
pub mod asmap;
pub mod bg_catchup;
pub mod compact;
pub mod connection;
pub mod dns;
pub mod ibd;
pub mod manager;
pub mod peer;
pub mod permissions;
pub mod proxy;
pub mod stats;
pub mod tor;
pub mod sync;
pub mod v2transport;

/// Bitcoin Core's `CNetAddr::IsRoutable`: whether an address can appear on
/// the public internet.
///
/// Everything Core calls unroutable — RFC 1918 private space, RFC 2544
/// benchmarking, RFC 3927 link-local, RFC 5737 documentation, RFC 6598
/// shared address space, RFC 4193 unique-local, RFC 4843 ORCHID, RFC 7343
/// ORCHIDv2, and loopback / unspecified — is false here.
///
/// Two places need the same answer and used to disagree: `getpeerinfo`'s
/// `network` field, which called only loopback and unspecified
/// `not_publicly_routable`, and the proxy-dial decision, which bypassed the
/// proxy for loopback alone.
pub fn is_routable(ip: std::net::IpAddr) -> bool {
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
                || v4.is_broadcast()
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
                || v6.is_unspecified()
                // RFC 4193 unique-local, fc00::/7.
                || (s[0] & 0xfe00) == 0xfc00
                // Link-local, fe80::/10.
                || (s[0] & 0xffc0) == 0xfe80
                // RFC 4843 ORCHID, 2001:10::/28, and RFC 7343 ORCHIDv2,
                // 2001:20::/28.
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020)
                // RFC 3849 documentation, 2001:db8::/32 — refused by Core's
                // `IsValid`, which `IsRoutable` requires.
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}
