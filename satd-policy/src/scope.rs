//! Quarantine scopes (§3, §5).
//!
//! A `quarantine` rule withholds a transaction along one or both of two axes:
//! `relay` (don't announce/serve/rebroadcast) and `template` (don't select into
//! blocks this node builds). `allow` rules carry no scope. A bare `quarantine`
//! defaults to the full `relay, template` scope.

use std::fmt;

/// The set of axes along which a transaction is withheld.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeSet {
    pub relay: bool,
    pub template: bool,
}

impl ScopeSet {
    /// Both axes — the default for a bare `quarantine`.
    pub const fn all() -> Self {
        ScopeSet {
            relay: true,
            template: true,
        }
    }
    pub const fn relay_only() -> Self {
        ScopeSet {
            relay: true,
            template: false,
        }
    }
    pub const fn template_only() -> Self {
        ScopeSet {
            relay: false,
            template: true,
        }
    }
    pub const fn empty() -> Self {
        ScopeSet {
            relay: false,
            template: false,
        }
    }

    pub fn is_empty(self) -> bool {
        !self.relay && !self.template
    }

    /// Union of two scope sets (used for infectious-descendant propagation, §7).
    pub fn union(self, other: ScopeSet) -> ScopeSet {
        ScopeSet {
            relay: self.relay || other.relay,
            template: self.template || other.template,
        }
    }
}

impl Default for ScopeSet {
    fn default() -> Self {
        ScopeSet::all()
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.relay, self.template) {
            (true, true) => f.write_str("relay,template"),
            (true, false) => f.write_str("relay"),
            (false, true) => f.write_str("template"),
            (false, false) => f.write_str("(none)"),
        }
    }
}
