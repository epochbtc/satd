use crate::chain::state::ChainState;
use crate::net::manager::PeerManager;
use crate::net::peer::PeerId;
use bitcoin::BlockHash;
use serde_json::{json, Value};

/// Bitcoin Core's `RPC_MISC_ERROR`, the code Core's own `getblockfrompeer`
/// uses for every one of its rejections.
const RPC_MISC_ERROR: i32 = -1;
/// Bitcoin Core's `RPC_INVALID_PARAMETER`.
const RPC_INVALID_PARAMETER: i32 = -8;

/// `getblockfrompeer "blockhash" ( peer_id )` — ask one peer for one block.
///
/// Core-compatible in name, positional arguments and its empty-object result.
/// It differs from Core in three ways, and the differences are not all in the
/// permissive direction:
///
/// 1. `peer_id` is optional. Core requires the operator to pick a peer; when
///    it is omitted satd picks a connected `NODE_NETWORK` + `NODE_WITNESS`
///    peer itself, which is what the repair use case wants. A *malformed*
///    peer_id is still an error rather than an auto-select.
/// 2. "Block already downloaded" is decided by whether the block's bytes can
///    actually be *read back*, not by the `block_index` status flag. Core
///    tests the flag, which would refuse exactly the case this exists for: an
///    entry that claims to hold data whose record was lost to a crash before
///    it reached disk.
/// 3. **More restrictive than Core:** satd refuses pruned blocks. Core allows
///    re-fetching them (noting the block may be re-pruned immediately and
///    carries no undo data); satd's repair path will not repopulate data the
///    prune accounting no longer tracks, so refusing here is better than
///    accepting the call and failing after the download.
///
/// Error message strings are close to Core's but not identical, and named
/// arguments are not supported (a satd-wide limitation, not specific to this
/// method). Clients matching on exact Core error text should not rely on them.
///
/// The reply is routed to `ChainState::repair_block_data`, not the normal
/// accept path — see `PeerManager::request_block_from_peer`. Delivery is
/// best-effort and asynchronous: like Core, a successful return means the
/// request was sent, not that the block arrived.
pub fn get_block_from_peer(
    chain_state: &ChainState,
    peer_manager: &PeerManager,
    hash_str: &str,
    peer_id: Option<PeerId>,
) -> Result<Value, (i32, String)> {
    let hash: BlockHash = hash_str.parse().map_err(|_| {
        (
            RPC_INVALID_PARAMETER,
            format!(
                "hash must be of length 64 (not {}, for '{}')",
                hash_str.len(),
                hash_str
            ),
        )
    })?;

    // We must already hold the header: it is what authenticates whatever the
    // peer sends back (see `repair_block_data`).
    let entry = chain_state
        .get_block_index(&hash)
        .ok_or((RPC_MISC_ERROR, "Block header missing".to_string()))?;

    if chain_state.block_data_readable(&hash) {
        return Err((RPC_MISC_ERROR, "Block already downloaded".to_string()));
    }

    // In prune mode, refuse to fetch blocks we haven't synced past yet.
    // Core rejects these because the node can't verify the block without
    // the preceding UTXO state, and it would be pruned immediately anyway.
    if peer_manager.is_pruning() && entry.height > chain_state.tip_height() {
        return Err((
            RPC_MISC_ERROR,
            "In prune mode, only blocks that the node has already synced \
             previously can be fetched from a peer"
                .to_string(),
        ));
    }

    // Refuse statuses the arrival path will refuse anyway, *before* spending a
    // round trip and a block download on them. Without this the operator gets
    // an empty-object success, the block is fetched, and the repair is then
    // rejected with nothing but a log line to show for it.
    match entry.status {
        crate::storage::blockindex::BlockStatus::Pruned => {
            // Match Bitcoin Core's pruned-block error for pruneblockchain'd blocks
            // that were already synced past.
            return Err((
                RPC_MISC_ERROR,
                "Block not available (pruned data)".to_string(),
            ));
        }
        crate::storage::blockindex::BlockStatus::Invalid => {
            return Err((
                RPC_MISC_ERROR,
                "Block is marked invalid".to_string(),
            ));
        }
        _ => {}
    }

    let peer_id = match peer_id {
        Some(id) => id,
        None => *peer_manager
            .block_serving_peer_ids()
            .first()
            .ok_or_else(|| {
                (
                    RPC_MISC_ERROR,
                    "No connected peer advertises NODE_NETWORK; \
                     connect one or name a peer explicitly"
                        .to_string(),
                )
            })?,
    };

    peer_manager
        .request_block_from_peer(hash, peer_id)
        .map_err(|e| (RPC_MISC_ERROR, e))?;

    Ok(json!({}))
}


/// Build the `getnetworkinfo` response with live connection data.
pub fn get_network_info(peer_manager: &PeerManager) -> Value {
    let connections = peer_manager.connection_count();
    let connections_in = peer_manager.inbound_count();
    let connections_out = peer_manager.outbound_count();
    let onion_reachable = peer_manager.onion_routing_available();
    let randomize = peer_manager.proxy_randomize();
    let clearnet_proxy = peer_manager.proxy_addr().unwrap_or_default();
    let onion_proxy = peer_manager.onion_proxy_addr().unwrap_or_default();
    // proxy_randomize_credentials is only meaningful for a network that
    // actually routes through a proxy.
    let clearnet_randomize = randomize && !clearnet_proxy.is_empty();
    let onion_randomize = randomize && !onion_proxy.is_empty();
    let local_addresses: Vec<Value> = peer_manager
        .local_addresses()
        .into_iter()
        .map(|(address, port, score)| {
            json!({ "address": address, "port": port, "score": score })
        })
        .collect();

    json!({
        // Advertises Bitcoin Core wire-protocol vintage (Core v28).
        // Distinct from `subversion`, which carries satd's own
        // implementation version. Clients use `version` to gate
        // legacy compatibility adapters — `bitcoincore-rpc`
        // pre-`getblockchaininfo` switches softfork shape on
        // `version < 190000`, so anything advertising sub-0.19 here
        // breaks every Core-compat client.
        "version": 280000,
        "subversion": crate::user_agent(),
        "protocolversion": 70016,
        "localservices": "0000000000000409",
        "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": peer_manager.is_network_active(),
        "connections": connections,
        "connections_in": connections_in,
        "connections_out": connections_out,
        "networks": [
            {
                "name": "ipv4",
                "limited": false,
                "reachable": true,
                "proxy": clearnet_proxy.clone(),
                "proxy_randomize_credentials": clearnet_randomize
            },
            {
                "name": "ipv6",
                "limited": false,
                "reachable": true,
                "proxy": clearnet_proxy,
                "proxy_randomize_credentials": clearnet_randomize
            },
            {
                "name": "onion",
                "limited": !onion_reachable,
                "reachable": onion_reachable,
                "proxy": onion_proxy,
                "proxy_randomize_credentials": onion_randomize
            }
        ],
        "relayfee": 0.00001000,
        "incrementalfee": 0.00001000,
        "localaddresses": local_addresses,
        "warnings": ""
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::tests::{build_test_block, make_chain_state};
    use crate::mempool::fee::FeeEstimator;
    use crate::mempool::pool::Mempool;
    use crate::net::manager::PeerManager;
    use bitcoin::Network;
    use std::sync::Arc;

    /// A chain state with `n` connected regtest blocks, plus a peer manager
    /// wired to it. No peers are connected, which is what the tests below
    /// want: every assertion here is about the checks that run *before* a
    /// peer is chosen.
    fn fixture(n: u32) -> (Arc<ChainState>, Arc<PeerManager>, Vec<bitcoin::Block>, std::path::PathBuf) {
        let (cs, dir) = make_chain_state();
        let cs = Arc::new(cs);
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        let mut blocks = Vec::new();
        for h in 1..=n {
            let b = build_test_block(parent, h, 1_300_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            cs.store_block(&b).unwrap();
            cs.connect_stored_block(&b.block_hash()).unwrap();
            parent = b.block_hash();
            blocks.push(b);
        }
        let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let pm = PeerManager::new(
            cs.clone(),
            Arc::new(Mempool::new(1_000_000, 0)),
            Arc::new(FeeEstimator::new()),
            Network::Regtest,
            shutdown_rx,
        );
        (cs, pm, blocks, dir)
    }

    #[test]
    fn rejects_a_malformed_block_hash() {
        let (cs, pm, _b, dir) = fixture(1);
        let (code, msg) = get_block_from_peer(&cs, &pm, "not-a-hash", None).unwrap_err();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(msg.contains("length 64"), "got {msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Core's wording and code, for a block whose header we never accepted.
    /// The header is what authenticates the peer's reply, so without it there
    /// is nothing to check the block against.
    #[test]
    fn rejects_a_block_we_have_no_header_for() {
        let (cs, pm, _b, dir) = fixture(1);
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let unknown = build_test_block(genesis.block_hash(), 1, 1_999_999_999).block_hash();

        let (code, msg) = get_block_from_peer(&cs, &pm, &unknown.to_string(), None).unwrap_err();
        assert_eq!(code, RPC_MISC_ERROR);
        assert_eq!(msg, "Block header missing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_block_whose_data_reads_back_fine() {
        let (cs, pm, blocks, dir) = fixture(2);
        let hash = blocks[0].block_hash();
        let (code, msg) = get_block_from_peer(&cs, &pm, &hash.to_string(), None).unwrap_err();
        assert_eq!(code, RPC_MISC_ERROR);
        assert_eq!(msg, "Block already downloaded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The deviation from Core that makes this RPC useful for repair: an entry
    /// that still claims `DataStored`/`Valid` but whose record is unreadable
    /// must get *past* the "already downloaded" gate. Core tests the status
    /// flag and would refuse here.
    ///
    /// With no peers connected the call then fails at peer selection — which
    /// is exactly the evidence wanted: reaching that error proves the gate
    /// was cleared.
    #[test]
    fn a_block_with_an_unreadable_record_gets_past_the_already_downloaded_gate() {
        let (cs, pm, blocks, dir) = fixture(2);
        let hash = blocks[0].block_hash();

        // Truncate the record away, then resync the append offset as a
        // restart after a crash would.
        let entry = cs.get_block_index(&hash).unwrap();
        let path = dir
            .join("blocks")
            .join(format!("blk{:05}.dat", entry.file_number));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(entry.data_pos as u64 + 8)
            .unwrap();
        cs.resync_block_append_pos().unwrap();

        assert!(!cs.block_data_readable(&hash));
        assert_eq!(
            cs.get_block_index(&hash).unwrap().status,
            crate::storage::blockindex::BlockStatus::Valid,
            "the entry must still claim to hold data — that is the whole point"
        );

        let (code, msg) = get_block_from_peer(&cs, &pm, &hash.to_string(), None).unwrap_err();
        assert_eq!(code, RPC_MISC_ERROR);
        assert!(
            msg.contains("NODE_NETWORK"),
            "expected to fail at peer selection, not at the download gate; got {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_an_unknown_peer_id() {
        let (cs, pm, blocks, dir) = fixture(2);
        let hash = blocks[0].block_hash();
        let entry = cs.get_block_index(&hash).unwrap();
        let path = dir
            .join("blocks")
            .join(format!("blk{:05}.dat", entry.file_number));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(entry.data_pos as u64 + 8)
            .unwrap();
        cs.resync_block_append_pos().unwrap();

        let (code, msg) =
            get_block_from_peer(&cs, &pm, &hash.to_string(), Some(4242)).unwrap_err();
        assert_eq!(code, RPC_MISC_ERROR);
        // Core's exact wording, so a Core-derived client's assertion holds.
        assert_eq!(msg, "Peer does not exist");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
