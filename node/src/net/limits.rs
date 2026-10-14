//! Bitcoin Core's limits on what one P2P message may carry, and its
//! sanitizing of peer-supplied text.
//!
//! rust-bitcoin decodes a vector of any length the frame can hold
//! (`MAX_INV_SIZE` is documented as "not currently enforced"), so these are
//! applied to the decoded message, with Core's reaction to each.

/// Core's `MAX_HEADERS_RESULTS` (`net_processing.h`): the most headers a
/// `headers` message may carry. More is `Misbehaving` ("headers message
/// size = N").
pub const MAX_HEADERS_RESULTS: usize = 2000;

/// Core's `MAX_ADDR_TO_SEND` (`net_processing.cpp`): the most entries an
/// `addr` or `addrv2` message may carry. More is `Misbehaving` ("addr
/// message size = N", `ProcessAddrs`).
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// The most entries of a `notfound` Core looks at: `MAX_PEER_TX_ANNOUNCEMENTS
/// + MAX_BLOCKS_IN_TRANSIT_PER_PEER` (5000 + 16, `net_processing.cpp`
/// `NOTFOUND`). A longer one is ignored whole, with no penalty.
pub const MAX_NOTFOUND_SZ: usize = 5000 + 16;

/// Characters Core's `SanitizeString` keeps under `SAFE_CHARS_DEFAULT`
/// (`util/strencodings.cpp`): alphanumerics plus ` .,;-_/:?@()`.
fn is_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " .,;-_/:?@()".contains(c)
}

/// Core's `SanitizeString(str)`: drop every character outside
/// `SAFE_CHARS_DEFAULT`. Core applies it to a peer's user agent before it
/// stores or logs it (`cleanSubVer`), and to message types in log lines, so
/// nothing a peer sends can put a line break, a control character or an
/// escape sequence into the log or into `getpeerinfo`.
pub fn sanitize_string(s: &str) -> String {
    s.chars().filter(|c| is_safe_char(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core's `SAFE_CHARS_DEFAULT`, character for character: everything it
    /// lists survives, and nothing else in the byte range does.
    #[test]
    fn sanitize_string_keeps_exactly_cores_safe_chars() {
        let core_safe: String = ('a'..='z')
            .chain('A'..='Z')
            .chain('0'..='9')
            .chain(" .,;-_/:?@()".chars())
            .collect();
        assert_eq!(sanitize_string(&core_safe), core_safe);
        for b in 0u8..=255 {
            let c = char::from(b);
            let kept = sanitize_string(&c.to_string());
            assert_eq!(kept.is_empty(), !core_safe.contains(c), "byte {b:#04x}");
        }
        assert_eq!(sanitize_string("/Satoshi:27.0.0/\nfake log line\x1b[31m"), "/Satoshi:27.0.0/fake log line31m");
        assert_eq!(sanitize_string("caf\u{e9}"), "caf");
    }
}
