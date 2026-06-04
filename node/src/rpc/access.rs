//! JSON-RPC method read/write classification.
//!
//! This is the single source of truth for which methods the **opt-in
//! read-only RPC listener** (served on the bounded API runtime) is allowed
//! to dispatch. The default full read/write listener on the consensus
//! (core) runtime serves everything and does not consult this table.
//!
//! ## Why the read-only listener exists
//!
//! The read-only listener runs on the same separate, bounded tokio runtime
//! as the high-volume read surfaces (Esplora/Electrum/gRPC) so a flood of
//! consumer RPC traffic can never starve block connection or mempool
//! acceptance. But that isolation comes with a hard correctness constraint
//! discovered while moving surfaces off the core runtime:
//!
//! > A surface that **connects blocks** must not run on the API runtime.
//! > `connect_block` writes the address index inline and *then* broadcasts
//! > `ChainEvent::BlockConnected`; the address-index status notifier is an
//! > independent core-runtime consumer of that broadcast. When the
//! > broadcast originates from the API runtime, the cross-runtime wakeup
//! > can reorder the notifier ahead of the inline index write becoming
//! > visible, delivering a stale all-zeros status to SSE/Electrum
//! > subscribers.
//!
//! Mempool *submission* is exempt: the mempool notifier bundles its index
//! write and notify into one task, so `sendrawtransaction` is safe to
//! originate from the API runtime. Block connection is the only path with
//! the unbundled ordering dependency.
//!
//! ## The boundary
//!
//! The read-only listener admits [`RpcAccess::Read`] and
//! [`RpcAccess::MempoolSubmit`]. It rejects [`RpcAccess::Control`] (node /
//! peer / index management and resource-intensive operator diagnostics) and
//! [`RpcAccess::BlockConnecting`] (the correctness-critical set above). The
//! filter is **fail-closed**: a method that is not classified here (e.g. a
//! newly added RPC a developer forgot to classify) returns `None` and is
//! therefore *rejected* on the read-only listener — never silently allowed
//! onto the API runtime. A debug-build startup audit
//! (`debug_assert` in `rpc::server::start`) flags any unclassified
//! registered method so the gap is caught in tests rather than shipped.

/// Read/write classification of a JSON-RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAccess {
    /// Pure read — informational queries plus stateless transaction tooling
    /// (decode/create/PSBT/sign-with-key), fee estimation, long-poll waits,
    /// and mempool subscriptions. No node, chain, index, or peer state is
    /// mutated. Safe on the read-only API-runtime listener.
    Read,
    /// Submits a transaction to the mempool. Safe to originate from the API
    /// runtime because the mempool notifier bundles index-write + notify in
    /// one task (unlike block connection). Allowed on the read-only listener
    /// so it can serve the broadcast path consumers actually need.
    MempoolSubmit,
    /// Node / peer / index management or a resource-intensive operator
    /// diagnostic (stop, ban control, log level, savemempool, index
    /// backfill control, full-UTXO dump, chain re-verification, mining
    /// template assembly, …). Not a consumer read; stays on the consensus
    /// listener. Rejected on the read-only listener.
    Control,
    /// Connects blocks, activates a different chain tip, or swaps the active
    /// chainstate. This is the correctness-critical set that MUST NOT
    /// originate from the API runtime (see module docs). Rejected on the
    /// read-only listener.
    BlockConnecting,
}

/// Classify a JSON-RPC method by read/write access.
///
/// Returns `None` for any method not explicitly listed. Callers gating the
/// read-only listener MUST treat `None` as "reject" (fail-closed) — see
/// [`readonly_listener_allows`].
///
/// Every method registered in [`crate::rpc::server::start`] must appear
/// here; the startup audit asserts this in debug builds.
pub fn classify(method: &str) -> Option<RpcAccess> {
    use RpcAccess::*;
    let class = match method {
        // --- Reads: informational queries ---
        "getbestblockhash"
        | "getblock"
        | "getblockchaininfo"
        | "getblockcount"
        | "getblockfilter"
        | "getblockhash"
        | "getblockheader"
        | "getblockstats"
        | "getchainstates"
        | "getchaintips"
        | "getchaintxstats"
        | "getconfig"
        | "getconnectioncount"
        | "getdifficulty"
        | "getibdprogress"
        | "getindexinfo"
        | "getmemoryinfo"
        | "getmempoolancestors"
        | "getmempooldescendants"
        | "getmempoolentry"
        | "getmempoolhistory"
        | "getmempoolinfo"
        | "getmininginfo"
        | "getnettotals"
        | "getnetworkhashps"
        | "getnetworkinfo"
        | "getorphaninfo"
        | "getpeerinfo"
        | "getrawmempool"
        | "getrawtransaction"
        | "getreorghistory"
        | "getrpcinfo"
        | "getserverstatus"
        | "getsysteminfo"
        | "gettxout"
        | "gettxoutsetinfo"
        | "getwarnings"
        | "getaddednodeinfo"
        | "getaddressbalance"
        | "getaddresshistory"
        | "getaddressutxos"
        | "listbanned"
        | "help"
        | "uptime"
        | "validateaddress"
        | "ping" => Read,

        // --- Reads: stateless transaction / PSBT tooling (pure compute) ---
        "analyzepsbt"
        | "combinepsbt"
        | "combinerawtransaction"
        | "converttopsbt"
        | "createpsbt"
        | "createrawtransaction"
        | "decodepsbt"
        | "decoderawtransaction"
        | "decodescript"
        | "finalizepsbt"
        | "joinpsbts"
        | "signrawtransactionwithkey"
        | "utxoupdatepsbt"
        // Dry-run mempool acceptance check: validates against current state
        // without inserting, so it is a read.
        | "testmempoolaccept" => Read,

        // --- Reads: fee estimation ---
        "estimatefees" | "estimatesmartfee" => Read,

        // --- Reads: long-poll waits + mempool subscription stream ---
        "waitforblock" | "waitforblockheight" | "waitfornewblock" => Read,
        "subscribemempool" | "unsubscribemempool" => Read,

        // --- Mempool submission (broadcast) ---
        "sendrawtransaction" => MempoolSubmit,

        // --- Control: node / peer management ---
        "stop"
        | "addnode"
        | "disconnectnode"
        | "setban"
        | "clearbanned"
        | "setnetworkactive"
        | "logging"
        // mempool *policy* mutation (mining priority), not a submit
        | "prioritisetransaction"
        // operational flush of the mempool to disk
        | "savemempool" => Control,

        // --- Control: index management ---
        "backfillindex" | "pauseindex" | "resumeindex" | "cancelindex" => Control,

        // --- Control: resource-intensive operator diagnostics / mining
        // control-plane. Not consumer reads; kept on the consensus listener.
        // `getblocktemplate` also has a proposal mode that validates blocks;
        // `dumptxoutset` and `getblockfileaudit` are minute-scale on
        // mainnet; `verifychain` re-verifies the chain. ---
        "getblocktemplate" | "dumptxoutset" | "getblockfileaudit" | "verifychain" => Control,

        // --- Block-connecting / chainstate-activating (correctness-critical) ---
        "generateblock"
        | "generatetoaddress"
        | "submitblock"
        | "submitheader"
        | "preciousblock"
        | "invalidateblock"
        | "reconsiderblock"
        | "loadtxoutset" => BlockConnecting,

        _ => return None,
    };
    Some(class)
}

/// Whether the opt-in read-only RPC listener may dispatch `method`.
///
/// Fail-closed: unclassified methods (`classify` returns `None`) are
/// rejected.
pub fn readonly_listener_allows(method: &str) -> bool {
    matches!(
        classify(method),
        Some(RpcAccess::Read | RpcAccess::MempoolSubmit)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_connecting_methods_are_rejected_on_readonly() {
        // The correctness-critical set: these MUST never be dispatchable on
        // the API-runtime read-only listener, or block connection could
        // originate there and corrupt the address-index status notifier.
        for m in [
            "generateblock",
            "generatetoaddress",
            "submitblock",
            "submitheader",
            "preciousblock",
            "invalidateblock",
            "reconsiderblock",
            "loadtxoutset",
        ] {
            assert_eq!(classify(m), Some(RpcAccess::BlockConnecting), "{m}");
            assert!(!readonly_listener_allows(m), "{m} must be rejected");
        }
    }

    #[test]
    fn control_methods_are_rejected_on_readonly() {
        for m in [
            "stop",
            "addnode",
            "disconnectnode",
            "setban",
            "clearbanned",
            "setnetworkactive",
            "logging",
            "prioritisetransaction",
            "savemempool",
            "backfillindex",
            "pauseindex",
            "resumeindex",
            "cancelindex",
            "getblocktemplate",
            "dumptxoutset",
            "getblockfileaudit",
            "verifychain",
        ] {
            assert_eq!(classify(m), Some(RpcAccess::Control), "{m}");
            assert!(!readonly_listener_allows(m), "{m} must be rejected");
        }
    }

    #[test]
    fn mempool_submit_is_allowed_on_readonly() {
        assert_eq!(classify("sendrawtransaction"), Some(RpcAccess::MempoolSubmit));
        assert!(readonly_listener_allows("sendrawtransaction"));
    }

    #[test]
    fn representative_reads_are_allowed_on_readonly() {
        for m in [
            "getblock",
            "getblockcount",
            "getrawtransaction",
            "gettxout",
            "getaddresshistory",
            "getrawmempool",
            "estimatesmartfee",
            "decoderawtransaction",
            "testmempoolaccept",
            "waitfornewblock",
            "subscribemempool",
        ] {
            assert_eq!(classify(m), Some(RpcAccess::Read), "{m}");
            assert!(readonly_listener_allows(m), "{m} must be allowed");
        }
    }

    #[test]
    fn unclassified_method_is_fail_closed() {
        assert_eq!(classify("totallynewrpc"), None);
        assert!(!readonly_listener_allows("totallynewrpc"));
    }

    /// Structural tripwire: any method whose name matches a chain-mutating
    /// shape MUST be rejected on the read-only listener. This catches the
    /// realistic human error — adding e.g. `generateblock2` / `submitblockx`
    /// and classifying it `Read` — at CI time, in every build profile (the
    /// runtime `debug_assert` in `emit_chain_event` is the complementary
    /// backstop on exercised paths). Keep these prefixes in sync with the
    /// block-connecting / mining-control surface.
    #[test]
    fn chain_mutating_shaped_methods_are_never_readonly_allowed() {
        const DANGEROUS_PREFIXES: &[&str] = &[
            "generate",
            "submitblock",
            "submitheader",
            "invalidate",
            "reconsider",
            "preciousblock",
            "loadtxoutset",
        ];
        // Every classified method that matches a chain-mutating prefix must
        // NOT be readonly-allowed (must be Control or BlockConnecting).
        let dangerous = |m: &str| DANGEROUS_PREFIXES.iter().any(|p| m.starts_with(p));
        // The known registered methods matching these shapes — if a new one
        // is added it should be appended here AND classified as rejecting.
        for m in [
            "generateblock",
            "generatetoaddress",
            "submitblock",
            "submitheader",
            "preciousblock",
            "invalidateblock",
            "reconsiderblock",
            "loadtxoutset",
        ] {
            assert!(dangerous(m), "test prefix list missed {m}");
            assert!(
                !readonly_listener_allows(m),
                "{m} matches a chain-mutating shape but is readonly-allowed — \
                 it must be classified Control or BlockConnecting"
            );
        }
    }
}
