//! Phase C Layer 2 — in-process consensus fuzzer with a live Bitcoin Core
//! oracle.
//!
//! libFuzzer mutates raw bytes; we deserialize them as a `Block`, fix the
//! header connectivity fields so the block builds on the shared genesis tip
//! with valid PoW/time/difficulty (the fuzzer owns the transaction list and
//! header *version*; the harness owns prev/bits/time/merkle/nonce), then:
//!
//!   * run satd's REAL validation IN-PROCESS — `check_block` +
//!     `check_block_version` + `connect_block` (with the bitcoinconsensus
//!     script verifier, matching Core) — so libFuzzer's coverage feedback is
//!     driven by satd's actual consensus code, and a satd panic / UB is caught
//!     directly; and
//!   * submit the identical bytes to a resident `bitcoind` (the oracle).
//!
//! ## What counts as a divergence
//!
//! ONLY an accept-vs-reject disagreement. A randomly-mutated block typically
//! violates *several* rules at once, and satd and Core legitimately report
//! *different* first-fault reject reasons depending on internal check order —
//! that is NOT a consensus bug. Verdict (accept/reject) agreement is the
//! consensus invariant; reason-string parity is asserted only by the curated
//! single-fault cases in Layer 1 (`phase_c_differential.rs`).
//!
//! Connectivity / duplicate verdicts from Core (a valid mutant already
//! accepted as a side block, or a `submitblock` RPC pre-check error) are
//! skipped — they are not consensus signals.
//!
//! Build/run via `scripts/fuzz/run-block-differential.sh` (needs nightly +
//! cargo-fuzz + Docker). Genesis is the shared base, so candidates are
//! height-1 blocks and no chain is mined; contextual *spend* paths
//! (maturity/amounts on real coins, BIP30, sequence locks) are Layer 1's
//! domain.

#![no_main]

use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::pow::CompactTarget;
use bitcoin::{Block, BlockHash, Network, TxMerkleNode};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use libfuzzer_sys::fuzz_target;

use node::chain::connect::{check_block_version, connect_block, ConnectParams};
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFilePos;
use node::validation::block::check_block;
use node::validation::script::ConsensusVerifier;

use satd_fuzz::{genesis_hash, grind, BLOCK_SPACING, GENESIS_TIME, POWLIMIT_BITS};

const CORE_IMAGE: &str = "lncm/bitcoind:v27.0";
const CORE_CONTAINER: &str = "satd-fuzz-core";
const CORE_RPC_PORT: u16 = 28443;
const CORE_USER: &str = "fuzz";
const CORE_PASS: &str = "fuzzpw";

/// Resident shared base: a Core node at regtest genesis and an empty
/// in-process UTXO store. Built once, reused for every fuzz iteration.
struct Base {
    rpc: Client,
    store: InMemoryStore,
    tip: BlockHash,
    height: u32,
    tip_time: u32,
    mtp: u32,
}

// Safety: Client + InMemoryStore are Send/Sync; the OnceLock is initialised
// once and only shared by reference thereafter. libFuzzer runs the target
// single-threaded by default.
static BASE: OnceLock<Base> = OnceLock::new();

fn base() -> &'static Base {
    BASE.get_or_init(spawn_base)
}

fn spawn_base() -> Base {
    // Best-effort cleanup of a stale container, then pull + run.
    let _ = Command::new("docker")
        .args(["rm", "-f", CORE_CONTAINER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for attempt in 1..=3u64 {
        let ok = Command::new("docker")
            .args(["pull", CORE_IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            break;
        }
        std::thread::sleep(Duration::from_secs(attempt * 2));
    }
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            CORE_CONTAINER,
            "--network=host",
            CORE_IMAGE,
            "-regtest",
            "-server",
            "-listen=0",
            &format!("-rpcport={CORE_RPC_PORT}"),
            "-port=28444",
            &format!("-rpcuser={CORE_USER}"),
            &format!("-rpcpassword={CORE_PASS}"),
            "-rpcallowip=127.0.0.1",
        ])
        .output()
        .expect("docker run bitcoind (is Docker installed?)");
    assert!(
        run.status.success(),
        "docker run for Bitcoin Core failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let rpc = Client::new(
        &format!("http://127.0.0.1:{CORE_RPC_PORT}"),
        Auth::UserPass(CORE_USER.to_string(), CORE_PASS.to_string()),
    )
    .expect("Core RPC client");

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if rpc.get_blockchain_info().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "Bitcoin Core RPC never came up");
        std::thread::sleep(Duration::from_millis(200));
    }

    let genesis = genesis_hash();
    let best = rpc
        .call::<String>("getbestblockhash", &[])
        .expect("Core getbestblockhash");
    assert_eq!(best, genesis.to_string(), "Core not at regtest genesis");

    Base {
        rpc,
        store: InMemoryStore::new(),
        tip: genesis,
        height: 0,
        tip_time: GENESIS_TIME,
        mtp: GENESIS_TIME,
    }
}

/// satd's in-process verdict, mirroring `accept_block`'s consensus checks for a
/// block whose PoW / timestamp / difficulty are already valid (the harness
/// fixed those): structure (`check_block`), the mandatory version gate
/// (`check_block_version`), then the contextual checks + real script
/// verification (`connect_block`). `true` = accept.
fn satd_accepts(b: &Block, base: &Base) -> bool {
    if check_block(b).is_err() {
        return false;
    }
    if check_block_version(&b.header, base.height + 1, Network::Regtest).is_err() {
        return false;
    }
    connect_block(&ConnectParams {
        store: &base.store,
        block: b,
        height: base.height + 1,
        parent_chainwork: &[0u8; 32],
        flat_pos: FlatFilePos { file_number: 0, data_pos: 0 },
        script_verifier: &ConsensusVerifier::new(Network::Regtest),
        median_time_past: base.mtp,
        network: Network::Regtest,
        pre_verified_txs: None,
        num_threads: 1,
        precomputed_txids: None,
        address_index: &Default::default(),
        phase_tracker: None,
    })
    .is_ok()
}

/// Core's verdict via `submitblock`. `Some(true)` = accept (null result),
/// `Some(false)` = a consensus reject, `None` = a connectivity/duplicate
/// verdict or RPC-level error → skip (not a consensus signal).
fn core_accepts(rpc: &Client, hex: &str) -> Option<bool> {
    match rpc.call::<Option<String>>("submitblock", &[serde_json::Value::String(hex.to_string())]) {
        Ok(None) => Some(true),
        Ok(Some(reason)) => {
            if is_connectivity(&reason) {
                None
            } else {
                Some(false)
            }
        }
        // RPC error (e.g. the submitblock "doesn't start with a coinbase"
        // pre-check, or a decode error) — not a comparable consensus verdict.
        Err(_) => None,
    }
}

fn is_connectivity(reason: &str) -> bool {
    matches!(
        reason,
        "bad-prevblk"
            | "prev-blk-not-found"
            | "inconclusive"
            | "duplicate"
            | "duplicate-invalid"
            | "duplicate-inconclusive"
    )
}

fuzz_target!(|data: &[u8]| {
    // Deserialize the fuzzer bytes as a block; most random inputs fail here and
    // are cheaply discarded.
    let Ok(mut block) = deserialize::<Block>(data) else {
        return;
    };
    if block.txdata.is_empty() {
        return; // need at least a coinbase slot for a meaningful candidate
    }

    let base = base();

    // Fix header connectivity so the block builds on the shared genesis tip
    // with valid PoW/time/difficulty. The fuzzer keeps ownership of the tx list
    // and the header version (so the version gate is exercised).
    block.header.prev_blockhash = base.tip;
    block.header.bits = CompactTarget::from_consensus(POWLIMIT_BITS);
    block.header.time = base.tip_time + BLOCK_SPACING;
    block.header.merkle_root =
        block.compute_merkle_root().unwrap_or(TxMerkleNode::all_zeros());
    grind(&mut block.header);

    let satd = satd_accepts(&block, base);

    let hex = hex::encode(serialize(&block));
    let Some(core) = core_accepts(&base.rpc, &hex) else {
        return; // connectivity/dup/RPC-error — skip
    };

    if satd != core {
        eprintln!("=== PHASE C FUZZ CONSENSUS DIVERGENCE ===");
        eprintln!("satd_accept={satd} core_accept={core}");
        eprintln!("block_hex={hex}");
        panic!("phase-c fuzz: satd and Core disagree on block acceptance (satd={satd}, core={core})");
    }
});
