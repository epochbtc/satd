//! The wire-neutral credential a surface extracts from its transport.
//!
//! Each surface's carrier adapter turns its native transport into one of these
//! and hands it to [`Verifier::resolve`](crate::Verifier::resolve). HTTP
//! surfaces (JSON-RPC, Esplora, MCP) parse an `Authorization` header; gRPC reads
//! the `authorization` metadata key; Electrum (phase 3) supplies an
//! already-validated mTLS leaf subject.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// A credential presented by a client, borrowing from a caller-owned buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Credential<'a> {
    /// `Authorization: Bearer <token>` — an opaque, high-entropy token whose
    /// SHA-256 is looked up in the token store.
    Bearer { token: &'a str },
    /// `Authorization: Basic <base64(user:pass)>` — the Core-compatible
    /// cookie/userpass/rpcauth path, resolving to the operator principal.
    Basic { user: &'a str, pass: &'a str },
    /// An already-validated mTLS client-certificate subject (CN / first
    /// DNS-SAN). Produced by the transport layer, not parsed from a header.
    ClientCert { subject: &'a str },
}

impl<'a> Credential<'a> {
    /// Parse an HTTP `Authorization` header value.
    ///
    /// The scheme token is matched case-insensitively per RFC 7235. For the
    /// `Basic` scheme the base64 payload is decoded into `scratch` (which the
    /// caller owns) so the returned `&str`s can borrow from it. Returns `None`
    /// for a missing scheme, an unknown scheme, invalid base64, non-UTF-8
    /// Basic payload, or a Basic payload with no `:` separator.
    pub fn from_authorization(hdr: &'a str, scratch: &'a mut String) -> Option<Credential<'a>> {
        let hdr = hdr.trim();
        let (scheme, rest) = hdr.split_once(' ')?;
        let rest = rest.trim();

        if scheme.eq_ignore_ascii_case("bearer") {
            if rest.is_empty() {
                return None;
            }
            return Some(Credential::Bearer { token: rest });
        }

        if scheme.eq_ignore_ascii_case("basic") {
            let decoded = BASE64.decode(rest).ok()?;
            *scratch = String::from_utf8(decoded).ok()?;
            let (user, pass) = scratch.split_once(':')?;
            return Some(Credential::Basic { user, pass });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer() {
        let mut s = String::new();
        assert_eq!(
            Credential::from_authorization("Bearer abc.def", &mut s),
            Some(Credential::Bearer { token: "abc.def" })
        );
        // case-insensitive scheme
        let mut s = String::new();
        assert_eq!(
            Credential::from_authorization("bEaReR xyz", &mut s),
            Some(Credential::Bearer { token: "xyz" })
        );
        let mut s = String::new();
        assert_eq!(Credential::from_authorization("Bearer ", &mut s), None); // empty token
    }

    #[test]
    fn basic() {
        let mut scratch = String::new();
        let hdr = format!("Basic {}", BASE64.encode("alice:s3cr3t"));
        let cred = Credential::from_authorization(&hdr, &mut scratch);
        assert_eq!(
            cred,
            Some(Credential::Basic {
                user: "alice",
                pass: "s3cr3t"
            })
        );
    }

    #[test]
    fn basic_password_may_contain_colon() {
        let mut scratch = String::new();
        let hdr = format!("Basic {}", BASE64.encode("__cookie__:de:ad:be:ef"));
        let cred = Credential::from_authorization(&hdr, &mut scratch);
        assert_eq!(
            cred,
            Some(Credential::Basic {
                user: "__cookie__",
                pass: "de:ad:be:ef"
            })
        );
    }

    #[test]
    fn rejects_garbage() {
        for h in ["", "Basic", "Digest abc"] {
            let mut s = String::new();
            assert_eq!(Credential::from_authorization(h, &mut s), None, "{h:?}");
        }
        let mut scratch = String::new();
        assert_eq!(
            Credential::from_authorization("Basic !!!notbase64!!!", &mut scratch),
            None
        );
        let mut scratch2 = String::new();
        let no_colon = BASE64.encode("nocolon");
        assert_eq!(
            Credential::from_authorization(&format!("Basic {no_colon}"), &mut scratch2),
            None
        );
    }
}
