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
    /// Mutating JSON-RPC (node/index control, mining, and everything
    /// [`Capability::RpcSubmit`] grants).
    ///
    /// Implies [`Capability::RpcSubmit`]: a set holding `rpc:write` satisfies
    /// a check for `rpc:submit`, so a token minted before the submit
    /// capability existed keeps broadcasting. The converse does not hold.
    RpcWrite,
    /// Mempool submission only: `sendrawtransaction`, `submitpackage`, and
    /// the other methods the read-only listener classes as mempool-submit.
    ///
    /// The read-only listener already tells "hand a transaction to the
    /// mempool" apart from "control the node"; this carries that distinction
    /// into bearer tokens, so a broadcaster (a payment processor, a wallet
    /// backend) can hold `rpc:read` + `rpc:submit` and never `stop`,
    /// `addnode`, or `invalidateblock`. Implied by [`Capability::RpcWrite`].
    RpcSubmit,
    /// Esplora REST / SSE.
    EsploraRead,
    /// Open a streaming subscription (gRPC events).
    StreamSubscribe,
    /// Register outpoint/script/descriptor watches (gated by `watch_quota`).
    StreamWatch,
    /// MCP tool access (serialized as the wildcard `mcp:*`).
    McpAll,
    /// Move the node clock via `setmocktime` (regtest only).
    ///
    /// Deliberately *not* implied by [`Capability::RpcWrite`]: shifting the
    /// clock reaches the future-block check, mempool expiry and block-template
    /// timestamps, so a token handed out for ordinary writes should not carry
    /// it. Must be granted explicitly in `auth.toml`.
    TestClock,
    /// Open an outbound connection of a chosen type via `addconnection`
    /// (regtest only).
    ///
    /// Like [`Capability::TestClock`], deliberately *not* implied by
    /// [`Capability::RpcWrite`]: `addconnection` dials an address of the
    /// caller's choosing and picks the connection's type, which decides
    /// whether that peer is asked for transactions and whether it takes part
    /// in address relay. A token handed out for ordinary writes should not be
    /// able to reshape the node's peer set. Must be granted explicitly in
    /// `auth.toml`.
    TestNet,
}

/// Every capability, in bit order. The single source of truth used to derive
/// [`CapabilitySet::ALL`] and to render a set for logging.
const ALL_CAPS: [Capability; 9] = [
    Capability::RpcRead,
    Capability::RpcWrite,
    Capability::RpcSubmit,
    Capability::EsploraRead,
    Capability::StreamSubscribe,
    Capability::StreamWatch,
    Capability::McpAll,
    Capability::TestClock,
    Capability::TestNet,
];

impl Capability {
    /// The stable string form used in `auth.toml`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::RpcRead => "rpc:read",
            Capability::RpcWrite => "rpc:write",
            Capability::RpcSubmit => "rpc:submit",
            Capability::EsploraRead => "esplora:read",
            Capability::StreamSubscribe => "stream:subscribe",
            Capability::StreamWatch => "stream:watch",
            Capability::McpAll => "mcp:*",
            Capability::TestClock => "test:clock",
            Capability::TestNet => "test:net",
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
                | Capability::RpcSubmit.bit()
                | Capability::EsploraRead.bit()
                | Capability::StreamSubscribe.bit()
                | Capability::StreamWatch.bit()
                | Capability::McpAll.bit()
                | Capability::TestClock.bit()
                | Capability::TestNet.bit(),
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
    ///
    /// This is the single check every surface reaches through
    /// `Principal::has`, so the one implication in the vocabulary lives here:
    /// [`Capability::RpcWrite`] grants [`Capability::RpcSubmit`]. A set that
    /// holds only `rpc:submit` does **not** satisfy `rpc:write`.
    pub const fn contains(self, c: Capability) -> bool {
        if self.0 & c.bit() != 0 {
            return true;
        }
        matches!(c, Capability::RpcSubmit) && self.0 & Capability::RpcWrite.bit() != 0
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
        // Render the bits actually granted, not the implied view
        // (`contains`), so a log line shows what the file said.
        for c in ALL_CAPS {
            if self.0 & c.bit() != 0 {
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
    fn submit_roundtrips_and_parses() {
        assert_eq!(Capability::parse("rpc:submit"), Some(Capability::RpcSubmit));
        assert_eq!(Capability::RpcSubmit.as_str(), "rpc:submit");
        let set = CapabilitySet::from_strs(["rpc:submit"]).unwrap();
        assert!(set.contains(Capability::RpcSubmit));
    }

    #[test]
    fn write_implies_submit_but_not_the_converse() {
        // A pre-existing write token keeps its broadcast ability.
        let write_only = CapabilitySet::from_strs(["rpc:write"]).unwrap();
        assert!(write_only.contains(Capability::RpcWrite));
        assert!(write_only.contains(Capability::RpcSubmit));
        assert!(!write_only.contains(Capability::RpcRead));

        // A submit token cannot control the node.
        let submit_only = CapabilitySet::from_strs(["rpc:submit"]).unwrap();
        assert!(submit_only.contains(Capability::RpcSubmit));
        assert!(!submit_only.contains(Capability::RpcWrite));
        assert!(!submit_only.contains(Capability::RpcRead));

        // The implication is a view over the bits, not a stored bit: the
        // set's emptiness and rendering report only what was granted.
        assert!(!write_only.is_empty());
        assert_eq!(format!("{write_only:?}"), r#"["rpc:write"]"#);
        assert_eq!(format!("{submit_only:?}"), r#"["rpc:submit"]"#);
        assert!(CapabilitySet::EMPTY.is_empty());
        assert!(!CapabilitySet::EMPTY.contains(Capability::RpcSubmit));
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
