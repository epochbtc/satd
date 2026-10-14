//! RPC answers checked against Bitcoin Core's source: how a double is printed
//! (`UniValue::setFloat`, src/univalue/lib/univalue.cpp), amounts
//! (`ValueFromAmount`), `submitblock` and `getnetworkhashps`
//! (src/rpc/mining.cpp), `getblockfilter` (src/rpc/blockchain.cpp) and the
//! genesis coinbase refusal in `getrawtransaction`
//! (src/rpc/rawtransaction.cpp).

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, TxOut, Txid};
use serde_json::{json, Value};

use crate::chain::state::tests::{
    build_test_block, build_test_block_spending, grind_test_pow, make_chain_state,
};
use crate::chain::state::{ChainError, ChainState};
use crate::mempool::pool::Mempool;
use crate::rpc::blockchain::{self, PruneMode};
use crate::rpc::util::univalue_double;
use crate::rpc::{mining, network, psbt, rawtx};

/// What Core prints for the regtest difficulty (nBits `0x207fffff`).
/// The shortest round-trip form is `4.6565423739069247e-10`.
const REGTEST_DIFFICULTY: &str = "4.656542373906925e-10";

fn genesis_hash() -> BlockHash {
    bitcoin::constants::genesis_block(Network::Regtest).block_hash()
}

/// A regtest chain of `n` blocks on genesis, each connected through
/// `accept_block`, block `h` timestamped `time(h)`.
fn chain(n: u32, time: impl Fn(u32) -> u32) -> (ChainState, std::path::PathBuf, Vec<Block>) {
    let (cs, dir) = make_chain_state();
    let mut parent = genesis_hash();
    let mut blocks = Vec::new();
    for h in 1..=n {
        let b = build_test_block(parent, h, time(h));
        cs.accept_block(&b).expect("the test block connects");
        parent = b.block_hash();
        blocks.push(b);
    }
    (cs, dir, blocks)
}

fn spaced(h: u32) -> u32 {
    1_300_000_000 + h * 600
}

fn pool() -> Mempool {
    Mempool::new(1_000_000, 0)
}

fn hex_of(block: &Block) -> String {
    hex::encode(bitcoin::consensus::serialize(block))
}

// ---------------------------------------------------------------------------
// Doubles: `std::ostringstream << std::setprecision(16)`
// ---------------------------------------------------------------------------

/// Every expected string below is what `std::ostringstream` prints with
/// `std::setprecision(16)` (libstdc++), the formatting `UniValue::setFloat`
/// uses for every double Core puts in an RPC answer.
#[test]
fn doubles_print_as_cores_univalue_does() {
    let cases: &[(f64, &str)] = &[
        (1.0, "1"),
        (0.5, "0.5"),
        (0.0, "0"),
        (4.6565423739069247e-10, REGTEST_DIFFICULTY),
        // Mainnet nBits 0x1701f303.
        (144398401518100.94, "144398401518100.9"),
        (1e15, "1000000000000000"),
        (1e16, "1e+16"),
        (9999999999999999.0, "1e+16"),
        (0.0001, "0.0001"),
        (0.00001, "1e-05"),
        (9.5e-5, "9.500000000000001e-05"),
        (123456789012345678.0, "1.234567890123457e+17"),
        (0.6360546080260824, "0.6360546080260824"),
        (1.0 / 3.0, "0.3333333333333333"),
        (2.0 / 3.0, "0.6666666666666666"),
    ];
    for &(v, core) in cases {
        assert_eq!(univalue_double(v).to_string(), core, "{v:e}");
    }
    // Not a JSON number at all; never produced by a real difficulty.
    assert_eq!(univalue_double(f64::NAN), Value::Null);
    assert_eq!(univalue_double(f64::INFINITY), Value::Null);
}

#[test]
fn difficulty_has_cores_sixteen_significant_digits_everywhere() {
    let (cs, dir, blocks) = chain(1, spaced);
    let tip = blocks[0].block_hash().to_string();

    assert_eq!(blockchain::get_difficulty(&cs).to_string(), REGTEST_DIFFICULTY);
    let info = blockchain::get_blockchain_info(&cs, PruneMode::Off);
    assert_eq!(info["difficulty"].to_string(), REGTEST_DIFFICULTY, "{info}");
    let header = blockchain::get_block_header(&cs, &tip, true).unwrap();
    assert_eq!(header["difficulty"].to_string(), REGTEST_DIFFICULTY, "{header}");
    let block = blockchain::get_block(&cs, &tip, 1).unwrap();
    assert_eq!(block["difficulty"].to_string(), REGTEST_DIFFICULTY);
    let states = blockchain::get_chain_states(&cs);
    assert_eq!(
        states["chainstates"][0]["difficulty"].to_string(),
        REGTEST_DIFFICULTY,
        "{states}"
    );
    let mining = mining::get_mining_info(&cs, &pool());
    assert_eq!(mining["difficulty"].to_string(), REGTEST_DIFFICULTY, "{mining}");
    assert_eq!(mining["next"]["difficulty"].to_string(), REGTEST_DIFFICULTY, "{mining}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `getmininginfo.networkhashps` and `verificationprogress` are doubles too.
/// `GetNetworkHashPS` answers a bare `0` on a chain with nothing to measure.
#[test]
fn other_doubles_use_cores_formatting() {
    let (cs, dir, _) = chain(0, spaced);
    let mining = mining::get_mining_info(&cs, &pool());
    assert_eq!(mining["networkhashps"].to_string(), "0", "{mining}");

    let info = blockchain::get_blockchain_info(&cs, PruneMode::Off);
    let progress = &info["verificationprogress"];
    let as_core = univalue_double(progress.as_f64().expect("a number"));
    assert_eq!(progress.to_string(), as_core.to_string(), "{info}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Amounts: `ValueFromAmount`, eight decimal places
// ---------------------------------------------------------------------------

#[test]
fn getnetworkinfo_fee_floors_are_amounts() {
    let (cs, dir) = make_chain_state();
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pm = crate::net::manager::PeerManager::new(
        Arc::new(cs),
        Arc::new(pool()),
        Arc::new(crate::mempool::fee::FeeEstimator::new()),
        Network::Regtest,
        shutdown_rx,
    );
    // Core: `ValueFromAmount(min_relay_feerate.GetFeePerK())` (src/rpc/net.cpp).
    let info = network::get_network_info(&pm, 100, 1_000, Vec::new());
    assert_eq!(info["relayfee"].to_string(), "0.00000100", "{info}");
    assert_eq!(info["incrementalfee"].to_string(), "0.00001000", "{info}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The version 2 PSBT path reports `fee` the way the version 0 path does:
/// `ValueFromAmount` in `decodepsbt` and `analyzepsbt` (src/rpc/rawtransaction.cpp).
#[test]
fn psbt_v2_fee_is_an_amount() {
    use base64::Engine as _;
    let doc: Value =
        serde_json::from_str(satd_psbt::testing::BIP370_VECTORS).expect("vectors parse");
    let mut fees = 0;
    for v in doc["valid"].as_array().expect("valid vectors") {
        let b64 = v["psbt"].as_str().expect("base64");
        assert!(base64::engine::general_purpose::STANDARD.decode(b64).is_ok());
        for out in [psbt::decode_psbt(b64, None), psbt::analyze_psbt(b64, None)] {
            let out = out.unwrap_or_else(|e| panic!("{}: {e:?}", v["description"]));
            if out["fee"].is_null() {
                continue;
            }
            let text = out["fee"].to_string();
            let frac = text.split_once('.').map(|(_, f)| f.len());
            assert_eq!(frac, Some(8), "{}: fee {text}", v["description"]);
            fees += 1;
        }
    }
    assert!(fees > 0, "no vector carried every input's UTXO, so nothing was checked");
}

// ---------------------------------------------------------------------------
// getnetworkhashps
// ---------------------------------------------------------------------------

/// `nblocks = -1` is "since the last difficulty change": Core takes
/// `height % DifficultyAdjustmentInterval() + 1` blocks, and the interval is
/// 144 on regtest (one day of ten-minute blocks, `chainparams.cpp`), not 2016.
#[test]
fn networkhashps_since_the_last_retarget_uses_regtests_interval() {
    // Ten-minute blocks to height 143, then one second apart, so windows of
    // different lengths measure different rates.
    let time = |h: u32| {
        if h <= 143 {
            spaced(h)
        } else {
            spaced(143) + (h - 143)
        }
    };
    let (cs, dir, _) = chain(150, time);
    let since_retarget = mining::get_network_hash_ps(&cs, -1, -1).unwrap();
    let seven = mining::get_network_hash_ps(&cs, 150 % 144 + 1, -1).unwrap();
    let whole_chain = mining::get_network_hash_ps(&cs, 150, -1).unwrap();
    assert_ne!(seven, whole_chain, "the fixture must tell the windows apart");
    assert_eq!(since_retarget, seven);

    // At an explicit height the window is that height's, still mod 144.
    assert_eq!(
        mining::get_network_hash_ps(&cs, -1, 145).unwrap(),
        mining::get_network_hash_ps(&cs, 145 % 144 + 1, 145).unwrap(),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// submitblock
// ---------------------------------------------------------------------------

/// Core throws `RPC_DESERIALIZATION_ERROR` "Block decode failed" for hex it
/// cannot decode into a block (`mining_basic.py` submits a block with its last
/// 15 bytes cut off). It is not a BIP 22 result string.
#[test]
fn submitblock_decode_failure_is_an_rpc_error() {
    let (cs, dir, _) = chain(0, spaced);
    let block = build_test_block(genesis_hash(), 1, spaced(1));
    let hex = hex_of(&block);
    let decode_failed = Err((-22, "Block decode failed".to_string()));

    assert_eq!(mining::submit_block(&cs, &pool(), "not hex"), decode_failed);
    assert_eq!(mining::submit_block(&cs, &pool(), &hex[..hex.len() - 30]), decode_failed);
    // The whole block connects.
    assert_eq!(mining::submit_block(&cs, &pool(), &hex), Ok(Value::Null));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core answers a block whose index entry is marked failed with
/// `duplicate-invalid` (`AcceptBlockHeader`, src/validation.cpp; asserted in
/// `mining_basic.py`), and one it already holds as valid with `duplicate`.
#[test]
fn submitblock_answers_duplicate_invalid_for_a_block_marked_invalid() {
    let (cs, dir, blocks) = chain(1, spaced);
    let tip = blocks[0].block_hash();

    // A known header whose body fails at connect: it spends a coin that does
    // not exist. The failure marks the header's index entry.
    let missing = OutPoint { txid: Txid::from_byte_array([0xab; 32]), vout: 0 };
    let bad = build_test_block_spending(tip, 2, spaced(2), missing);
    cs.accept_header(&bad.header).unwrap();
    assert_eq!(
        mining::submit_block(&cs, &pool(), &hex_of(&bad)),
        Ok(json!("bad-txns-inputs-missingorspent"))
    );
    assert_eq!(mining::submit_block(&cs, &pool(), &hex_of(&bad)), Ok(json!("duplicate-invalid")));

    // A block already held as valid.
    assert_eq!(mining::submit_block(&cs, &pool(), &hex_of(&blocks[0])), Ok(json!("duplicate")));

    // `invalidateblock` marks it too.
    cs.invalidate_block(tip).unwrap();
    assert_eq!(
        mining::submit_block(&cs, &pool(), &hex_of(&blocks[0])),
        Ok(json!("duplicate-invalid"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failure that is about this node rather than the block is Core's
/// `state.IsError()`: `RPC_VERIFY_ERROR` (-25), not a reject reason
/// (`BIP22ValidationResult`, src/rpc/mining.cpp). Verdicts stay reasons.
#[test]
fn submitblock_reports_a_node_failure_as_an_rpc_error() {
    use crate::chain::connect::ConnectError;
    use crate::storage::StoreError;

    let (cs, dir, _) = chain(0, spaced);
    let hash = build_test_block(genesis_hash(), 1, spaced(1)).block_hash();
    let answer = |e: ChainError| mining::rejection_answer(&cs, &hash, e);

    for e in [
        ChainError::Storage(StoreError::Database("disk gone".into())),
        ChainError::FlatFile("short write".into()),
        ChainError::BlockDataUnreadable("no record".into()),
        ChainError::SnapshotLoadInProgress,
        ChainError::ParentNeverConnected,
        ChainError::Connect(ConnectError::Interrupted),
        ChainError::Connect(ConnectError::ChainTxGap { parent: hash }),
    ] {
        let text = e.to_string();
        assert_eq!(answer(e), Err((-25, text)));
    }

    for (e, reason) in [
        (ChainError::PrevBlockNotFound, "prev-blk-not-found"),
        (ChainError::BadPrevBlock, "bad-prevblk"),
        (
            ChainError::Validation(crate::validation::ValidationError::BadMerkleRoot),
            "bad-txnmrklroot",
        ),
        (
            ChainError::Connect(ConnectError::BadCoinbaseValue),
            "bad-cb-amount",
        ),
    ] {
        assert_eq!(answer(e), Ok(json!(reason)));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The BIP 141 commitment output for a coinbase-only block: its witness root
/// is the coinbase wtxid, which is all zeros, and the reserved value is zero.
fn coinbase_only_commitment() -> TxOut {
    let commitment = bitcoin::hashes::sha256d::Hash::hash(&[0u8; 64]).to_byte_array();
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&commitment);
    TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) }
}

/// Core's `submitblock` runs `UpdateUncommittedBlockStructures` first: a
/// coinbase that has a witness commitment but no witness at all gets the
/// 32-byte zero reserved value, which is what a pool working from
/// `getblocktemplate` leaves out (src/validation.cpp).
#[test]
fn submitblock_fills_in_the_witness_reserved_value() {
    let (cs, dir, _) = chain(0, spaced);
    let mut block = build_test_block(genesis_hash(), 1, spaced(1));
    block.txdata[0].output.push(coinbase_only_commitment());
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    grind_test_pow(&mut block);
    assert!(block.txdata[0].input[0].witness.is_empty());

    assert_eq!(mining::submit_block(&cs, &pool(), &hex_of(&block)), Ok(Value::Null));
    assert_eq!(cs.tip_hash(), block.block_hash());
    // The block stored is the completed one.
    let stored = blockchain::get_block(&cs, &block.block_hash().to_string(), 0).unwrap();
    let stored: Block =
        bitcoin::consensus::deserialize(&hex::decode(stored.as_str().unwrap()).unwrap()).unwrap();
    let witness: Vec<&[u8]> = stored.txdata[0].input[0].witness.iter().collect();
    assert_eq!(witness, vec![&[0u8; 32][..]]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A coinbase that already carries witness data is left as it is, so a wrong
/// reserved value is still rejected.
#[test]
fn submitblock_leaves_a_coinbase_witness_alone() {
    let (cs, dir, _) = chain(0, spaced);
    let mut block = build_test_block(genesis_hash(), 1, spaced(1));
    block.txdata[0].output.push(coinbase_only_commitment());
    block.txdata[0].input[0].witness.push([0x11; 7]);
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    grind_test_pow(&mut block);

    assert_eq!(
        mining::submit_block(&cs, &pool(), &hex_of(&block)),
        Ok(json!("bad-witness-nonce-size"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// getblockfilter
// ---------------------------------------------------------------------------

/// Core's order and answers: `ParseHashV` (-8), then the filter type (-5
/// "Unknown filtertype"), then whether the index exists (-1 "Index is not
/// enabled for filtertype basic"), then the block (-5 "Block not found").
/// `rpc_getblockfilter.py` asserts the last three.
#[cfg(feature = "block-filter-index")]
#[test]
fn getblockfilter_refusals_match_core() {
    use crate::rpc::indexes::get_block_filter;
    use node_filter_index::{FilterIndex, FilterIndexConfig};

    let (cs, dir) = make_chain_state();
    let cs = Arc::new(cs);
    let index = |enabled: bool| -> Arc<dyn FilterIndex> {
        Arc::new(crate::index::filter::RocksFilterIndex::new(
            cs.store_ref().clone(),
            FilterIndexConfig { enabled, peer_serve: false },
        ))
    };
    let (on, off) = (index(true), index(false));
    let genesis = genesis_hash().to_string();
    let unknown = "0123456789abcdef".repeat(4);
    let err = |code: i32, msg: &str| Err::<Value, _>((code, msg.to_string()));

    assert_eq!(
        get_block_filter(&cs, Some(&on), true, "abc", None),
        err(-8, "blockhash must be of length 64 (not 3, for 'abc')")
    );
    assert_eq!(
        get_block_filter(&cs, Some(&on), true, &genesis, Some("unknown")),
        err(-5, "Unknown filtertype")
    );
    assert_eq!(
        get_block_filter(&cs, Some(&on), true, &unknown, Some("basic")),
        err(-5, "Block not found")
    );
    let not_enabled = err(-1, "Index is not enabled for filtertype basic");
    assert_eq!(get_block_filter(&cs, Some(&off), false, &genesis, Some("basic")), not_enabled);
    assert_eq!(get_block_filter(&cs, Some(&off), false, &genesis, None), not_enabled);
    // The index is checked before the block is looked up.
    assert_eq!(get_block_filter(&cs, Some(&off), false, &unknown, None), not_enabled);
    assert_eq!(get_block_filter(&cs, None, false, &genesis, None), not_enabled);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// getrawtransaction
// ---------------------------------------------------------------------------

#[test]
fn getrawtransaction_refuses_the_genesis_coinbase_in_cores_words() {
    let (cs, dir, blocks) = chain(1, spaced);
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let txid = genesis.txdata[0].compute_txid().to_string();
    assert_eq!(
        rawtx::get_raw_transaction(&cs, &pool(), &txid, false, 0, None),
        Err((
            -5,
            "The genesis block coinbase is not considered an ordinary transaction and cannot be \
             retrieved"
                .to_string()
        ))
    );
    // Any other coinbase is served.
    let coinbase = blocks[0].txdata[0].compute_txid().to_string();
    let hash = blocks[0].block_hash().to_string();
    assert_eq!(
        rawtx::get_raw_transaction(&cs, &pool(), &coinbase, false, 0, Some(&hash)),
        Ok(json!(hex::encode(bitcoin::consensus::serialize(&blocks[0].txdata[0]))))
    );
    let _ = std::fs::remove_dir_all(&dir);
}
