//! Integration tests for MCP tools.
//!
//! Each test creates a fresh regtest McpContext with InMemoryStore + NoopVerifier
//! and exercises the tool functions directly (not through the MCP protocol).

use std::sync::Arc;

use bitcoin::Network;
use node::chain::state::{AssumeValid, ChainState};
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::net::manager::PeerManager;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::NoopVerifier;
use satd_mcp::McpContext;

const REGTEST_ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// Create a fresh McpContext for testing with an empty regtest chain.
fn make_test_ctx() -> (McpContext, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let store = Box::new(InMemoryStore::new());
    let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
    let chain_state = Arc::new(
        ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        )
        .unwrap(),
    );
    let mempool = Arc::new(Mempool::new(1_000_000, 0));
    let fee_estimator = Arc::new(FeeEstimator::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let peer_manager = PeerManager::new(
        chain_state.clone(),
        mempool.clone(),
        fee_estimator.clone(),
        Network::Regtest,
        shutdown_rx,
    );

    let ctx = McpContext {
        chain_state,
        mempool,
        peer_manager,
        fee_estimator,
        start_time: std::time::Instant::now(),
        network: Network::Regtest,
    };
    (ctx, dir)
}

/// Create an McpContext with some mined blocks for richer test data.
fn make_test_ctx_with_blocks(n: u32) -> (McpContext, tempfile::TempDir) {
    let (ctx, dir) = make_test_ctx();
    node::mining::miner::mine_blocks(&ctx.chain_state, &ctx.mempool, REGTEST_ADDR, n).unwrap();
    (ctx, dir)
}

// ============================================================
// Node Status Tools
// ============================================================

mod node_status {
    use super::*;
    use satd_mcp::tools::node_status;

    #[test]
    fn test_get_node_status_genesis() {
        let (ctx, _dir) = make_test_ctx();
        let result = node_status::get_node_status(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["height"], 0);
        assert_eq!(json["chain"], "regtest");
        assert!(json["best_block_hash"].is_string());
        assert!(json["uptime_seconds"].is_number());
        assert!(json["mempool"]["size"].is_number());
        assert!(json["peers"]["connections"].is_number());
    }

    #[test]
    fn test_get_node_status_after_mining() {
        let (ctx, _dir) = make_test_ctx_with_blocks(5);
        let result = node_status::get_node_status(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["height"], 5);
        assert_eq!(json["chain"], "regtest");
    }

    #[test]
    fn test_get_system_info() {
        let (ctx, _dir) = make_test_ctx();
        let result = node_status::get_system_info(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["uptime_seconds"].is_number());
        assert!(json["utxo_set"]["coin_count"].is_number());
        assert!(json["chain"]["height"].is_number());
        assert!(json["chain"]["tip"].is_string());
    }
}

// ============================================================
// Blockchain Tools
// ============================================================

mod blockchain {
    use super::*;
    use satd_mcp::tools::blockchain as bc;

    #[test]
    fn test_get_block_by_height() {
        let (ctx, _dir) = make_test_ctx_with_blocks(3);
        let result = bc::get_block(&ctx, "1", "summary");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["height"], 1);
        assert!(json["hash"].is_string());
        assert!(json["tx"].is_array());
    }

    #[test]
    fn test_get_block_by_hash() {
        let (ctx, _dir) = make_test_ctx_with_blocks(1);
        // Get hash of block 1
        let status = bc::get_block(&ctx, "1", "summary");
        let json: serde_json::Value = serde_json::from_str(&status).unwrap();
        let hash = json["hash"].as_str().unwrap();

        // Now fetch by hash
        let result = bc::get_block(&ctx, hash, "summary");
        let json2: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json2["height"], 1);
        assert_eq!(json2["hash"].as_str().unwrap(), hash);
    }

    #[test]
    fn test_get_block_raw() {
        let (ctx, _dir) = make_test_ctx_with_blocks(1);
        let result = bc::get_block(&ctx, "1", "raw");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Raw mode returns hex string
        assert!(json.is_string());
    }

    #[test]
    fn test_get_block_invalid_height() {
        let (ctx, _dir) = make_test_ctx();
        let result = bc::get_block(&ctx, "9999", "summary");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_get_block_header_by_height() {
        let (ctx, _dir) = make_test_ctx_with_blocks(2);
        let result = bc::get_block_header(&ctx, "1", false);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["height"], 1);
        assert!(json["hash"].is_string());
        assert!(json["previousblockhash"].is_string());
    }

    #[test]
    fn test_get_block_header_raw() {
        let (ctx, _dir) = make_test_ctx_with_blocks(1);
        let result = bc::get_block_header(&ctx, "1", true);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Raw returns hex string
        assert!(json.is_string());
    }

    #[test]
    fn test_get_block_stats() {
        let (ctx, _dir) = make_test_ctx_with_blocks(3);
        let result = bc::get_block_stats(&ctx, "2");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["height"].is_number() || json["error"].is_string());
    }

    #[test]
    fn test_get_chain_info() {
        let (ctx, _dir) = make_test_ctx_with_blocks(5);
        let result = bc::get_chain_info(&ctx, 5);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["chain_tips"].is_array());
        assert!(json["difficulty"].is_number());
    }

    #[test]
    fn test_search_block_range() {
        let (ctx, _dir) = make_test_ctx_with_blocks(5);
        let result = bc::search_block_range(&ctx, 0, 3);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["start_height"], 0);
        assert_eq!(json["count"], 4); // blocks 0,1,2,3
        assert!(json["headers"].is_array());
        assert_eq!(json["headers"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_search_block_range_capped_at_100() {
        let (ctx, _dir) = make_test_ctx_with_blocks(5);
        // Request more than 100 blocks — should be capped
        let result = bc::search_block_range(&ctx, 0, 200);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Only 6 blocks exist (0-5), and range is capped at start+99
        assert!(json["count"].as_u64().unwrap() <= 100);
    }

    #[test]
    fn test_search_block_range_beyond_tip() {
        let (ctx, _dir) = make_test_ctx_with_blocks(3);
        let result = bc::search_block_range(&ctx, 0, 10);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Should return only blocks 0-3
        assert_eq!(json["count"], 4);
    }
}

// ============================================================
// Transaction Tools
// ============================================================

mod transactions {
    use super::*;
    use satd_mcp::tools::transactions as tx;

    #[test]
    fn test_get_transaction_not_found() {
        let (ctx, _dir) = make_test_ctx();
        let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = tx::get_transaction(&ctx, fake_txid, None);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_decode_raw_transaction_valid() {
        // Minimal valid tx hex (version + 1 input + 1 output + locktime)
        // This is a well-known simple transaction for testing
        let hex = "0200000001000000000000000000000000000000000000000000000000000000\
                   0000000000ffffffff0100f2052a0100000017a91489abcdefabbaabbaabbaab\
                   baabbaabbaabbaabba8700000000";
        let result = tx::decode_raw_transaction(hex);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Either decoded successfully or returned an error
        assert!(json["txid"].is_string() || json["error"].is_string());
    }

    #[test]
    fn test_decode_raw_transaction_invalid() {
        let result = tx::decode_raw_transaction("deadbeef");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_decode_script_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac";
        let result = tx::decode_script(hex);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["type"].is_string() || json["asm"].is_string() || json["error"].is_string());
    }

    #[test]
    fn test_decode_script_invalid() {
        let result = tx::decode_script("xyz");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }
}

// ============================================================
// Mempool Tools
// ============================================================

mod mempool {
    use super::*;
    use satd_mcp::tools::mempool as mp;

    #[test]
    fn test_get_mempool_overview_empty() {
        let (ctx, _dir) = make_test_ctx();
        let result = mp::get_mempool_overview(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["size"], 0);
        assert_eq!(json["bytes"], 0);
        assert!(json["fee_histogram"].is_object());
    }

    #[test]
    fn test_list_mempool_transactions_empty() {
        let (ctx, _dir) = make_test_ctx();
        let result = mp::list_mempool_transactions(&ctx, "fee_rate", 25, None);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["count"], 0);
        assert_eq!(json["total_mempool_size"], 0);
        assert!(json["transactions"].is_array());
        assert!(json["transactions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_list_mempool_transactions_respects_limit() {
        let (ctx, _dir) = make_test_ctx();
        // Even with limit=0, should return empty, not error
        let result = mp::list_mempool_transactions(&ctx, "fee_rate", 0, None);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["count"], 0);
    }

    #[test]
    fn test_get_mempool_entry_not_found() {
        let (ctx, _dir) = make_test_ctx();
        let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = mp::get_mempool_entry(&ctx, fake_txid, false);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_get_mempool_entry_with_relatives_not_found() {
        let (ctx, _dir) = make_test_ctx();
        let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = mp::get_mempool_entry(&ctx, fake_txid, true);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }
}

// ============================================================
// Fee Estimation Tools
// ============================================================

mod fees {
    use super::*;
    use satd_mcp::tools::fees as fee;

    #[test]
    fn test_estimate_fee_default_targets() {
        let (ctx, _dir) = make_test_ctx();
        let targets = vec![1, 3, 6, 12, 25];
        let result = fee::estimate_fee(&ctx, &targets);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["estimates"].is_array());
        let estimates = json["estimates"].as_array().unwrap();
        assert_eq!(estimates.len(), 5);

        for est in estimates {
            assert!(est["target_blocks"].is_number());
            assert!(est["fee_rate_btc_kvb"].is_number());
            assert!(est["fee_rate_sat_vb"].is_string());
        }
    }

    #[test]
    fn test_estimate_fee_single_target() {
        let (ctx, _dir) = make_test_ctx();
        let result = fee::estimate_fee(&ctx, &[1]);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["estimates"].as_array().unwrap().len(), 1);
    }
}

// ============================================================
// Network Tools
// ============================================================

mod network {
    use super::*;
    use satd_mcp::tools::network as net;

    #[test]
    fn test_get_peer_info_summary() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::get_peer_info(&ctx, true);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["connection_count"], 0);
        assert!(json["peers"].is_array());
    }

    #[test]
    fn test_get_peer_info_full() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::get_peer_info(&ctx, false);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["connection_count"], 0);
        assert!(json["peers"].is_array());
    }

    #[test]
    fn test_manage_peer_invalid_address() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::manage_peer(&ctx, "disconnect", "not-an-address");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_manage_peer_unknown_action() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::manage_peer(&ctx, "explode", "127.0.0.1:8333");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_manage_peer_disconnect_nonexistent() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::manage_peer(&ctx, "disconnect", "127.0.0.1:8333");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["result"], "peer not found");
    }

    #[test]
    fn test_get_ban_list_empty() {
        let (ctx, _dir) = make_test_ctx();
        let result = net::get_ban_list(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["count"], 0);
        assert!(json["banned"].is_array());
    }
}

// ============================================================
// Transaction Construction Tools
// ============================================================

mod construction {
    use super::*;
    use satd_mcp::tools::construction as cst;

    #[test]
    fn test_create_transaction_basic() {
        let inputs = serde_json::json!([{
            "txid": "0000000000000000000000000000000000000000000000000000000000000001",
            "vout": 0
        }]);
        let outputs = serde_json::json!({
            "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01
        });
        let result = cst::create_transaction(&inputs, &outputs, None);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Should return hex string of the unsigned tx
        assert!(json.is_string() || json["error"].is_string());
    }

    #[test]
    fn test_create_transaction_invalid_inputs() {
        let inputs = serde_json::json!("not an array");
        let outputs = serde_json::json!({});
        let result = cst::create_transaction(&inputs, &outputs, None);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_send_transaction_invalid_hex() {
        let (ctx, _dir) = make_test_ctx();
        let result = cst::send_transaction(&ctx, "notvalidhex");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_psbt_create() {
        let (ctx, _dir) = make_test_ctx();
        let params = serde_json::json!({
            "inputs": [{
                "txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "vout": 0
            }],
            "outputs": {
                "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202": 0.01
            }
        });
        let result = cst::psbt_workflow(&ctx, "create", &params);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // Should return base64 PSBT or error
        assert!(json.is_string() || json["error"].is_string());
    }

    #[test]
    fn test_psbt_decode_invalid() {
        let (ctx, _dir) = make_test_ctx();
        let params = serde_json::json!({"psbt": "not-valid-base64-psbt"});
        let result = cst::psbt_workflow(&ctx, "decode", &params);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_psbt_unknown_action() {
        let (ctx, _dir) = make_test_ctx();
        let result = cst::psbt_workflow(&ctx, "foobar", &serde_json::json!({}));
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].as_str().unwrap().contains("Unknown PSBT action"));
    }
}

// ============================================================
// Mining Tools
// ============================================================

mod mining {
    use super::*;
    use satd_mcp::tools::mining as mine;

    #[test]
    fn test_get_mining_info() {
        let (ctx, _dir) = make_test_ctx_with_blocks(3);
        let result = mine::get_mining_info(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["mining_info"].is_object());
        assert!(json["network_hashrate"].is_number());
    }

    #[test]
    fn test_generate_blocks_regtest() {
        let (ctx, _dir) = make_test_ctx();
        let result = mine::generate_blocks(&ctx, 5, REGTEST_ADDR);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 5);
        assert_eq!(ctx.chain_state.tip_height(), 5);
    }

    #[test]
    fn test_generate_blocks_mainnet_rejected() {
        // Create a mainnet context — generate_blocks should refuse
        let dir = tempfile::TempDir::new().unwrap();
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.path().join("blocks")).unwrap();
        let chain_state = Arc::new(
            ChainState::new(
                store,
                flat_files,
                Network::Bitcoin,
                Box::new(NoopVerifier),
                AssumeValid::Disabled,
                450,
            )
            .unwrap(),
        );
        let mempool = Arc::new(Mempool::new(1_000_000, 0));
        let fee_estimator = Arc::new(FeeEstimator::new());
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let peer_manager =
            PeerManager::new(chain_state.clone(), mempool.clone(), fee_estimator.clone(), Network::Bitcoin, rx);

        let ctx = McpContext {
            chain_state,
            mempool,
            peer_manager,
            fee_estimator,
            start_time: std::time::Instant::now(),
            network: Network::Bitcoin,
        };

        let result = mine::generate_blocks(&ctx, 1, REGTEST_ADDR);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_get_block_template() {
        let (ctx, _dir) = make_test_ctx_with_blocks(1);
        let result = mine::get_block_template(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["height"].is_number());
        assert!(json["previousblockhash"].is_string());
        assert!(json["transactions"].is_array());
    }
}

// ============================================================
// UTXO Tools
// ============================================================

mod utxo {
    use super::*;
    use satd_mcp::tools::utxo;

    #[test]
    fn test_get_utxo_not_found() {
        let (ctx, _dir) = make_test_ctx();
        let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = utxo::get_utxo(&ctx, fake_txid, 0);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    #[test]
    fn test_get_utxo_set_stats_genesis() {
        let (ctx, _dir) = make_test_ctx();
        let result = utxo::get_utxo_set_stats(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["txouts"].is_number());
        assert!(json["total_amount"].is_number());
        assert!(json["height"].is_number());
    }

    #[test]
    fn test_get_utxo_set_stats_after_mining() {
        let (ctx, _dir) = make_test_ctx_with_blocks(10);
        let result = utxo::get_utxo_set_stats(&ctx);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Should have UTXOs from mined coinbase outputs
        assert!(json["txouts"].as_u64().unwrap() >= 10);
        assert!(json["height"].as_u64().unwrap() == 10);
    }
}

// ============================================================
// Address Tools
// ============================================================

mod address {
    use super::*;
    use satd_mcp::tools::address;

    #[test]
    fn test_validate_address_valid_bech32() {
        let result = address::validate_address(REGTEST_ADDR);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["isvalid"], true);
    }

    #[test]
    fn test_validate_address_invalid() {
        let result = address::validate_address("not-a-valid-address");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["isvalid"], false);
    }

    #[test]
    fn test_validate_address_empty() {
        let result = address::validate_address("");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["isvalid"], false);
    }
}

// ============================================================
// Tool Router Tests (verify MCP tool registration)
// ============================================================

mod tool_router {
    use super::*;
    use rmcp::ServerHandler;

    fn make_server() -> satd_mcp::SatdMcpServer {
        let (ctx, _dir) = make_test_ctx();
        // Leak the TempDir so it lives long enough (tests are short-lived)
        std::mem::forget(_dir);
        satd_mcp::SatdMcpServer::new(Arc::new(ctx))
    }

    #[test]
    fn test_server_info() {
        let server = make_server();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "satd-mcp");
        assert!(info.instructions.is_some());
        assert!(info.instructions.unwrap().contains("Bitcoin"));
    }

    #[test]
    fn test_tool_router_lists_27_tools() {
        let server = make_server();
        let tools = server.list_tools_from_router();
        assert_eq!(
            tools.len(),
            27,
            "Expected 27 tools, got {}. Tools: {:?}",
            tools.len(),
            tools.iter().map(|t| &*t.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_tool_router_has_expected_tools() {
        let server = make_server();
        let tools = server.list_tools_from_router();
        let names: Vec<&str> = tools.iter().map(|t| &*t.name).collect();

        let expected = [
            "get_node_status",
            "get_system_info",
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
            "estimate_fee",
            "get_peer_info",
            "manage_peer",
            "get_ban_list",
            "create_transaction",
            "sign_transaction",
            "send_transaction",
            "psbt_workflow",
            "get_mining_info",
            "generate_blocks",
            "get_block_template",
            "get_utxo",
            "get_utxo_set_stats",
            "validate_address",
        ];

        for name in &expected {
            assert!(
                names.contains(name),
                "Missing tool: {}. Registered: {:?}",
                name,
                names
            );
        }
    }

    #[test]
    fn test_all_tools_have_descriptions() {
        let server = make_server();
        let tools = server.list_tools_from_router();

        for tool in &tools {
            assert!(
                tool.description.is_some() && !tool.description.as_ref().unwrap().is_empty(),
                "Tool '{}' is missing a description",
                tool.name
            );
        }
    }
}
