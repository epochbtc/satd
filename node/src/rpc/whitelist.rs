//! Per-user JSON-RPC method allowlists: Bitcoin Core's `-rpcwhitelist` and
//! `-rpcwhitelistdefault`.
//!
//! The semantics are Core's, taken from v31.1 `src/httprpc.cpp`:
//!
//! - `rpcwhitelist=<user>:<m1>,<m2>,...` is repeatable. The method list is
//!   split on `,` **or** space (`SplitString(s, ", ")`), and empty tokens are
//!   kept, as Core keeps them; no method is named `""`, so an empty token
//!   allows nothing. The username is everything before the first `:` and is
//!   not trimmed.
//! - An entry with no `:` names the user and gives no list. For a user seen
//!   for the first time that is an empty list (deny everything); for a user
//!   already listed it changes nothing (lines 311-313: the set is created on
//!   first sight and only replaced when a list is present).
//! - The same user listed twice keeps the **intersection** of the lists.
//! - `rpcwhitelistdefault` defaults to true exactly when any `rpcwhitelist`
//!   is set (line 306). When it is true, a user with no entry may call
//!   nothing.
//! - Method names compare case-sensitively.
//!
//! This module is the pure data model. The decision about a request body, and
//! the HTTP 403 it produces, live in [`crate::rpc::compat`], the one layer
//! that reads request bodies; [`crate::rpc::auth`] attaches the authenticated
//! user's [`MethodScope`] to the request.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The parsed `-rpcwhitelist` / `-rpcwhitelistdefault` configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcWhitelist {
    users: BTreeMap<String, Arc<BTreeSet<String>>>,
    default_deny: bool,
}

/// What an authenticated RPC user may call, when that is less than
/// everything. A user with no restriction carries no scope at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodScope {
    /// `rpcwhitelistdefault` is on and the user has no `rpcwhitelist` entry:
    /// every request is refused, whatever it asks for.
    DenyAll,
    /// The user's `rpcwhitelist` entry: only these methods.
    Only(Arc<BTreeSet<String>>),
}

impl MethodScope {
    /// May a request naming `method` run under this scope?
    pub fn allows(&self, method: &str) -> bool {
        match self {
            MethodScope::DenyAll => false,
            MethodScope::Only(set) => set.contains(method),
        }
    }
}

impl RpcWhitelist {
    /// Build from the raw `rpcwhitelist` values (command line first, then the
    /// config file, as Core's `GetArgs` orders them) and the resolved
    /// `rpcwhitelistdefault`.
    pub fn new(entries: &[String], default: Option<bool>) -> Self {
        let users = parse_entries(entries);
        RpcWhitelist {
            default_deny: default.unwrap_or(!entries.is_empty()),
            users: users.into_iter().map(|(u, s)| (u, Arc::new(s))).collect(),
        }
    }

    /// True when the configuration restricts nobody: no entries and the
    /// default is allow. The server then attaches no scope to any request.
    pub fn is_inert(&self) -> bool {
        self.users.is_empty() && !self.default_deny
    }

    /// Whether users without an entry are refused everything.
    pub fn default_deny(&self) -> bool {
        self.default_deny
    }

    /// The users with an entry and their allowed methods.
    pub fn users(&self) -> impl Iterator<Item = (&str, &BTreeSet<String>)> {
        self.users.iter().map(|(u, s)| (u.as_str(), s.as_ref()))
    }

    /// The scope for an authenticated user, or `None` when the user is
    /// unrestricted.
    pub fn scope_for(&self, user: &str) -> Option<MethodScope> {
        match self.users.get(user) {
            Some(set) => Some(MethodScope::Only(set.clone())),
            None if self.default_deny => Some(MethodScope::DenyAll),
            None => None,
        }
    }
}

/// Core's `InitRPCAuthentication` whitelist loop (v31.1
/// `src/httprpc.cpp:307-326`), over the raw values in order.
pub fn parse_entries(entries: &[String]) -> BTreeMap<String, BTreeSet<String>> {
    let mut users: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in entries {
        let (user, list) = match entry.split_once(':') {
            Some((u, l)) => (u, Some(l)),
            None => (entry.as_str(), None),
        };
        let seen = users.contains_key(user);
        let current = users.entry(user.to_string()).or_default();
        if let Some(list) = list {
            let new: BTreeSet<String> = list.split([',', ' ']).map(str::to_string).collect();
            *current = if seen {
                current.intersection(&new).cloned().collect()
            } else {
                new
            };
        }
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(entries: &[&str], default: Option<bool>) -> RpcWhitelist {
        let v: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        RpcWhitelist::new(&v, default)
    }

    fn allowed(w: &RpcWhitelist, user: &str, method: &str) -> bool {
        w.scope_for(user).is_none_or(|s| s.allows(method))
    }

    // The rows below are the users of Core's `rpc_whitelist.py`.

    #[test]
    fn a_trailing_comma_allows_the_listed_method() {
        // user1 `getbestblockhash,getblockcount,` and strangedude3 `:getblockcount,`
        let w = wl(&["user1:getbestblockhash,getblockcount,", "s3:getblockcount,"], None);
        assert!(allowed(&w, "user1", "getbestblockhash"));
        assert!(allowed(&w, "user1", "getblockcount"));
        assert!(!allowed(&w, "user1", "getnetworkinfo"));
        assert!(allowed(&w, "s3", "getblockcount"));
        assert!(!allowed(&w, "s3", "getnetworkinfo"));
    }

    #[test]
    fn a_bare_user_or_an_empty_list_allows_nothing() {
        // strangedude `strangedude:` and strangedude2 `strangedude2`
        let w = wl(&["s1:", "s2"], Some(false));
        assert_eq!(w.scope_for("s1"), Some(MethodScope::Only(Arc::new(BTreeSet::from([String::new()])))));
        assert!(!allowed(&w, "s1", "getnetworkinfo"));
        assert!(!allowed(&w, "s2", "getnetworkinfo"));
        assert_eq!(w.scope_for("s2"), Some(MethodScope::Only(Arc::new(BTreeSet::new()))));
    }

    #[test]
    fn the_same_user_twice_keeps_the_intersection() {
        // strangedude4 `:getblockcount, getbestblockhash` then `:getblockcount`
        let w = wl(&["s4:getblockcount, getbestblockhash", "s4:getblockcount"], None);
        assert!(allowed(&w, "s4", "getblockcount"));
        assert!(!allowed(&w, "s4", "getbestblockhash"));
    }

    #[test]
    fn a_repeated_method_is_one_permission() {
        // strangedude5 `:getblockcount,getblockcount`
        let w = wl(&["s5:getblockcount,getblockcount"], None);
        assert!(allowed(&w, "s5", "getblockcount"));
    }

    #[test]
    fn a_space_separates_methods_like_a_comma() {
        let w = wl(&["u:getblockcount getbestblockhash"], None);
        assert!(allowed(&w, "u", "getblockcount"));
        assert!(allowed(&w, "u", "getbestblockhash"));
        assert!(!allowed(&w, "u", "getblockcount getbestblockhash"));
    }

    #[test]
    fn a_bare_user_after_a_list_leaves_the_list_alone() {
        // Core only replaces the set when the entry has a `:`.
        let w = wl(&["u:getblockcount", "u"], None);
        assert!(allowed(&w, "u", "getblockcount"));
    }

    #[test]
    fn method_names_are_case_sensitive() {
        let w = wl(&["u:getblockcount"], None);
        assert!(!allowed(&w, "u", "GetBlockCount"));
    }

    #[test]
    fn the_username_is_not_trimmed() {
        let w = wl(&[" u:getblockcount"], Some(false));
        assert!(allowed(&w, "u", "getnetworkinfo"), "`u` has no entry; ` u` does");
        assert!(!allowed(&w, " u", "getnetworkinfo"));
    }

    #[test]
    fn the_default_flips_on_when_any_whitelist_is_set() {
        // strangedude6 has no entry.
        assert!(!allowed(&wl(&["u:getblockcount"], None), "s6", "getbestblockhash"));
        assert!(allowed(&wl(&["u:getblockcount"], Some(false)), "s6", "getbestblockhash"));
        assert!(allowed(&wl(&[], None), "s6", "getbestblockhash"));
        assert_eq!(wl(&[], Some(true)).scope_for("s6"), Some(MethodScope::DenyAll));
    }

    #[test]
    fn inert_only_when_it_restricts_nobody() {
        assert!(wl(&[], None).is_inert());
        assert!(wl(&[], Some(false)).is_inert());
        assert!(!wl(&[], Some(true)).is_inert());
        assert!(!wl(&["u:getblockcount"], Some(false)).is_inert());
    }
}
