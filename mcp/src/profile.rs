//! Which tools a bearer token may see and call.
//!
//! A token holding `mcp:*` gets every tool. A token holding only
//! `mcp:read` gets the read-only profile: the tools that answer questions
//! about the chain, the mempool and fees. It is meant for a token handed to
//! the public, so it leaves out every tool that
//!
//! - acts: signs, broadcasts, mines or changes the peer set
//!   (`sign_transaction`, `send_transaction`, `generate_blocks`,
//!   `manage_peer`);
//! - reveals other people's addresses: `get_peer_info`, `get_ban_list`;
//! - reveals the operator's machine or setup: `get_config`,
//!   `get_policy_info` (the ruleset's file path), `get_system_info` (memory
//!   use), `get_metrics_snapshot` (the full metrics dump).
//!
//! The lists are allowlists in both directions: every tool the server
//! registers must be in exactly one of them, or the
//! `every_tool_is_in_exactly_one_profile_list` test fails. A new tool is
//! therefore classified on purpose, never by default.
//!
//! A tool the profile leaves out is invisible to the token: `tools/list`
//! omits it and `tools/call` answers "tool not found", exactly as for a
//! name no tool has.

use satd_auth::{Capability, Principal};

/// The tools a principal may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpProfile {
    /// Every tool (`mcp:*`, and the loopback default without `-mcpauth`).
    Full,
    /// The read-only tools ([`READ_TOOLS`]), for `mcp:read`.
    Read,
}

/// The tools an `mcp:read` token may use.
pub const READ_TOOLS: &[&str] = &[
    "get_node_status",
    "get_opreturn_prune_info",
    "get_block",
    "get_block_header",
    "get_block_stats",
    "get_chain_info",
    "search_block_range",
    "get_transaction",
    "decode_raw_transaction",
    "decode_script",
    "get_mempool_overview",
    "list_mempool_transactions",
    "get_mempool_entry",
    "get_quarantine_info",
    "list_quarantine",
    "get_quarantine_entry",
    "estimate_fee",
    // Builds an unsigned transaction from the caller's inputs and outputs.
    "create_transaction",
    // satd holds no keys: every action decodes, combines, updates or
    // finalizes what the caller supplies. None signs.
    "psbt_workflow",
    "get_mining_info",
    "get_block_template",
    "get_utxo",
    "get_utxo_set_stats",
    "validate_address",
    "get_mempool_entries_bulk",
    "get_mempool_history",
    "subscribe_mempool_snapshot",
    "get_reorg_history",
    "get_health",
    "get_readiness",
];

/// The tools only an `mcp:*` token may use.
pub const FULL_ONLY_TOOLS: &[&str] = &[
    "sign_transaction",
    "send_transaction",
    "generate_blocks",
    "manage_peer",
    "get_peer_info",
    "get_ban_list",
    "get_config",
    "get_policy_info",
    "get_system_info",
    "get_metrics_snapshot",
];

impl McpProfile {
    /// The profile a principal's capabilities give it, or `None` if it may
    /// not use MCP at all.
    pub fn of(principal: &Principal) -> Option<Self> {
        if principal.has(Capability::McpAll) {
            Some(McpProfile::Full)
        } else if principal.has(Capability::McpRead) {
            Some(McpProfile::Read)
        } else {
            None
        }
    }

    /// The profile for a request: the one the HTTP layer tagged it with, or,
    /// untagged, every tool for the loopback operator when tokens are not
    /// required and nothing when they are (fail closed: such a request was
    /// never authorized).
    pub fn resolve(tagged: Option<McpProfile>, auth_required: bool) -> Option<McpProfile> {
        match tagged {
            Some(profile) => Some(profile),
            None if auth_required => None,
            None => Some(McpProfile::Full),
        }
    }

    /// May this profile see and call `tool`?
    pub fn allows(self, tool: &str) -> bool {
        match self {
            McpProfile::Full => true,
            McpProfile::Read => READ_TOOLS.contains(&tool),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_is_in_exactly_one_profile_list() {
        let (ctx, _dir) = crate::test_ctx();
        let registered: Vec<String> = crate::SatdMcpServer::new(ctx, false)
            .list_tools_from_router()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        for name in &registered {
            let read = READ_TOOLS.contains(&name.as_str());
            let full = FULL_ONLY_TOOLS.contains(&name.as_str());
            assert!(
                read ^ full,
                "tool {name} must be in exactly one of READ_TOOLS and FULL_ONLY_TOOLS \
                 (read: {read}, full-only: {full})"
            );
        }
        for name in READ_TOOLS.iter().chain(FULL_ONLY_TOOLS) {
            assert!(
                registered.iter().any(|r| r == name),
                "{name} is listed but no such tool is registered"
            );
        }
    }

    #[test]
    fn an_untagged_request_gets_nothing_when_tokens_are_required() {
        assert_eq!(McpProfile::resolve(None, true), None);
        assert_eq!(McpProfile::resolve(None, false), Some(McpProfile::Full));
        assert_eq!(
            McpProfile::resolve(Some(McpProfile::Read), true),
            Some(McpProfile::Read)
        );
        assert_eq!(
            McpProfile::resolve(Some(McpProfile::Read), false),
            Some(McpProfile::Read)
        );
    }

    #[test]
    fn read_allows_only_its_list_and_full_allows_all() {
        for t in READ_TOOLS {
            assert!(McpProfile::Read.allows(t), "{t}");
            assert!(McpProfile::Full.allows(t), "{t}");
        }
        for t in FULL_ONLY_TOOLS {
            assert!(!McpProfile::Read.allows(t), "{t}");
            assert!(McpProfile::Full.allows(t), "{t}");
        }
        assert!(!McpProfile::Read.allows("no_such_tool"));
    }
}
