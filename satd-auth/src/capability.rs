//! The capability vocabulary and the compact set type tokens carry.
//!
//! Coarse to start, designed to extend (SATD_AUTH_PLAN.md §6). A bearer token
//! carries a [`CapabilitySet`]; the operator principal (cookie/userpass/rpcauth)
//! carries [`CapabilitySet::ALL`]. The string forms are the stable wire/file
//! vocabulary — an attenuable token format (biscuit/macaroon) could reuse them
//! verbatim later.

use std::fmt;

/// A single capability. The `str` forms are what appear in `auth.toml`
/// `capabilities = [...]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Capability {
    /// Read-only JSON-RPC methods.
    RpcRead,
    /// Mutating JSON-RPC (`sendrawtransaction`, node/index control, mining).
    RpcWrite,
    /// Esplora REST / SSE.
    EsploraRead,
    /// Open a streaming subscription (gRPC events).
    StreamSubscribe,
    /// Register outpoint/script/descriptor watches (gated by `watch_quota`).
    StreamWatch,
    /// MCP tool access (serialized as the wildcard `mcp:*`).
    McpAll,
}

/// Every capability, in bit order. The single source of truth used to derive
/// [`CapabilitySet::ALL`] and to render a set for logging.
const ALL_CAPS: [Capability; 6] = [
    Capability::RpcRead,
    Capability::RpcWrite,
    Capability::EsploraRead,
    Capability::StreamSubscribe,
    Capability::StreamWatch,
    Capability::McpAll,
];

impl Capability {
    /// The stable string form used in `auth.toml`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::RpcRead => "rpc:read",
            Capability::RpcWrite => "rpc:write",
            Capability::EsploraRead => "esplora:read",
            Capability::StreamSubscribe => "stream:subscribe",
            Capability::StreamWatch => "stream:watch",
            Capability::McpAll => "mcp:*",
        }
    }

    /// Parse a capability string. Total over the vocabulary; returns `None` for
    /// anything unknown so the store loader can recognize-reject (mirroring
    /// `bitcoin.conf`'s hard-error on unknown keys).
    pub fn parse(s: &str) -> Option<Capability> {
        ALL_CAPS.into_iter().find(|c| c.as_str() == s)
    }

    /// The bit this capability occupies in a [`CapabilitySet`].
    const fn bit(self) -> u16 {
        1u16 << (self as u16)
    }
}

// `CapabilitySet` is a `u16`, so the vocabulary must stay ≤ 16 entries — a 17th
// would make `1u16 << 16` over-shift (debug panic / release wrap → two
// capabilities aliasing one bit → silent privilege grant). This fails the build
// the moment that ceiling is crossed; widen `CapabilitySet` to `u32` then.
const _: () = assert!(
    ALL_CAPS.len() <= 16,
    "CapabilitySet is u16: widen it before adding a 17th capability"
);

/// A compact, `Copy`, cheap-to-clone set of capabilities (bitflags over the
/// fixed vocabulary). The operator principal is [`Self::ALL`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    /// The empty set (a token with no capabilities can authenticate but is
    /// denied every operation).
    pub const EMPTY: CapabilitySet = CapabilitySet(0);

    /// Every capability — the operator/loopback principal.
    pub const ALL: CapabilitySet = {
        // const fold of all bits; kept in lockstep with ALL_CAPS by the
        // `all_set_covers_every_capability` test.
        CapabilitySet(
            Capability::RpcRead.bit()
                | Capability::RpcWrite.bit()
                | Capability::EsploraRead.bit()
                | Capability::StreamSubscribe.bit()
                | Capability::StreamWatch.bit()
                | Capability::McpAll.bit(),
        )
    };

    /// Insert a capability, returning the new set (builder form).
    pub const fn with(self, c: Capability) -> Self {
        CapabilitySet(self.0 | c.bit())
    }

    /// Insert a capability in place.
    pub fn insert(&mut self, c: Capability) {
        self.0 |= c.bit();
    }

    /// Does the set grant `c`?
    pub const fn contains(self, c: Capability) -> bool {
        self.0 & c.bit() != 0
    }

    /// Is the set empty?
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Build a set from capability strings, rejecting any unknown string
    /// (recognize-reject). Returns the offending string on failure.
    pub fn from_strs<'a, I>(it: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut set = CapabilitySet::EMPTY;
        for s in it {
            let c = Capability::parse(s).ok_or_else(|| s.to_string())?;
            set.insert(c);
        }
        Ok(set)
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for c in ALL_CAPS {
            if self.contains(c) {
                list.entry(&c.as_str());
            }
        }
        list.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_strings() {
        for c in ALL_CAPS {
            assert_eq!(Capability::parse(c.as_str()), Some(c));
        }
        assert_eq!(Capability::parse("rpc:admin"), None);
        assert_eq!(Capability::parse(""), None);
        assert_eq!(Capability::parse("mcp"), None); // must be the wildcard form
    }

    #[test]
    fn all_set_covers_every_capability() {
        for c in ALL_CAPS {
            assert!(CapabilitySet::ALL.contains(c), "{} missing from ALL", c.as_str());
        }
        assert!(CapabilitySet::EMPTY.is_empty());
        assert!(!CapabilitySet::ALL.is_empty());
    }

    #[test]
    fn distinct_bits() {
        // No two capabilities collide on a bit (would silently grant extra access).
        for (i, a) in ALL_CAPS.iter().enumerate() {
            for b in &ALL_CAPS[i + 1..] {
                assert_ne!(a.bit(), b.bit(), "{} and {} share a bit", a.as_str(), b.as_str());
            }
        }
    }

    #[test]
    fn from_strs_recognize_reject() {
        let set = CapabilitySet::from_strs(["rpc:read", "stream:subscribe"]).unwrap();
        assert!(set.contains(Capability::RpcRead));
        assert!(set.contains(Capability::StreamSubscribe));
        assert!(!set.contains(Capability::RpcWrite));

        let err = CapabilitySet::from_strs(["rpc:read", "bogus:cap"]).unwrap_err();
        assert_eq!(err, "bogus:cap");
    }
}
